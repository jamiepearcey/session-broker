/**
 * `POST /session/refresh`: an in-tab single-flight promise, plus the
 * leader-only timer and the every-tab lazy checks that decide when to call
 * it (§8).
 *
 * Single-flight lives here (not per-caller) because it is what makes the
 * timer, the lazy checks, and `fetch.ts`'s 401 recovery all safe to trigger
 * a refresh independently without turning into a request storm in one tab:
 * whichever fires first wins, everyone else in this tab awaits the same
 * promise. Redundant refreshes *between* tabs are the server's job
 * (coalescing) — this module only needs to be cheap, not exclusive.
 */
import type { ErrorCode, SessionMeta } from './types.js';

/** What a successful refresh call measured, for the demo's refresh log. */
export interface RefreshOutcome {
  meta: SessionMeta;
  /** Round-trip measured with `performance.now()`, wall-clock from this tab's perspective. */
  rttMs: number;
  /** `X-Broker-Handler-Us`: server-reported time spent inside the handler, or `null` if the header was absent. */
  serverHandlerUs: number | null;
}

/** A non-2xx response from `/session/refresh`, carrying the parsed error body when one was sent. */
export class RefreshDeniedError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly loginUrl: string | undefined;

  constructor(code: ErrorCode, detail: string, status: number, loginUrl?: string) {
    super(detail);
    this.name = 'RefreshDeniedError';
    this.code = code;
    this.status = status;
    this.loginUrl = loginUrl;
  }
}

/**
 * Build a single-flight refresh function bound to one fetch implementation.
 * Concurrent callers within the same tab, no matter what triggered them,
 * observe the very same in-flight promise and therefore the very same
 * network call.
 */
export function singleFlightRefresh(fetchImpl: typeof fetch = fetch): () => Promise<RefreshOutcome> {
  let inFlight: Promise<RefreshOutcome> | null = null;

  return function refresh(): Promise<RefreshOutcome> {
    if (!inFlight) {
      inFlight = performRefresh(fetchImpl).finally(() => {
        inFlight = null;
      });
    }
    return inFlight;
  };
}

async function performRefresh(fetchImpl: typeof fetch): Promise<RefreshOutcome> {
  const started = performance.now();
  const response = await fetchImpl('/session/refresh', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { accept: 'application/json' },
  });
  const rttMs = performance.now() - started;

  if (!response.ok) {
    const body = await safeParseError(response);
    throw new RefreshDeniedError(
      body?.error ?? 'bad_request',
      body?.detail ?? response.statusText,
      response.status,
      body?.login_url,
    );
  }

  const meta = (await response.json()) as SessionMeta;
  const headerValue = response.headers.get('x-broker-handler-us');
  let serverHandlerUs: number | null = null;
  if (headerValue !== null && headerValue !== '') {
    const parsed = Number(headerValue);
    serverHandlerUs = Number.isFinite(parsed) ? parsed : null;
  }
  return { meta, rttMs, serverHandlerUs };
}

async function safeParseError(
  response: Response,
): Promise<{ error: ErrorCode; detail: string; login_url?: string } | null> {
  try {
    return (await response.json()) as { error: ErrorCode; detail: string; login_url?: string };
  } catch {
    return null;
  }
}

/**
 * Denial codes that no amount of retrying can fix: the session is beyond local
 * recovery and only an interactive login will help. The timer *halts* on these
 * rather than re-arming, because `active_until` is by then in the past, so
 * every reschedule would compute a zero delay and spin — one dead tab left
 * open would hammer the broker forever.
 */
const TERMINAL_CODES: ReadonlySet<ErrorCode> = new Set<ErrorCode>([
  'invalid_session',
  'session_expired',
  'login_required',
  'upstream_revoked',
  'csrf_rejected',
]);

/** Floor between attempts, so even an unforeseen error code cannot spin. */
const MIN_INTERVAL_MS = 1_000;
const MAX_BACKOFF_MS = 60_000;

export interface RefreshTimerOptions {
  /** Whether *this* tab currently owns the timer (leader.ts). Re-read on every schedule/reschedule. */
  isLeader: () => boolean;
  /** Latest known meta hint, or `null` if there is none to schedule against. */
  getMeta: () => SessionMeta | null;
  /** The single-flight refresh to invoke. */
  refresh: () => Promise<RefreshOutcome>;
  /** How far ahead of `active_until` to fire. Default 30s per §8. */
  skewMs?: number;
  onError?: (error: unknown) => void;
  /** Injectable clock for tests. Default `Date.now`. */
  now?: () => number;
}

export interface RefreshTimerHandle {
  /** Recompute the leader timer's fire time from the latest leader/meta state. Call after either changes. */
  reschedule(): void;
  /**
   * Whether the timer has stopped because the session is beyond local
   * recovery. Cleared by a successful refresh or by [`resume`].
   */
  isHalted(): boolean;
  /** Re-arm after a halt — for a fresh login in a tab that never navigated. */
  resume(): void;
  /**
   * Stop the timer immediately without a denial round-trip — for an
   * out-of-band terminal signal (SSE `session.killed`, events.ts) that
   * already tells us the session is gone, so spending a refresh call to
   * find that out again would just 401. Symmetric with [`resume`]; unlike
   * [`dispose`] the DOM lazy-check listeners stay attached, so a same-tab
   * relogin can still [`resume`] later.
   */
  halt(): void;
  dispose(): void;
}

/**
 * Own the leader-only refresh timer and the every-tab lazy checks
 * (`visibilitychange`, `focus`, `online`). Lazy checks run regardless of
 * leadership — they exist for background-tab timer throttling and for a
 * non-leader tab that wakes before the cookie jar has caught up.
 */
export function startRefreshTimers(options: RefreshTimerOptions): RefreshTimerHandle {
  const skewMs = options.skewMs ?? 30_000;
  const now = options.now ?? (() => Date.now());
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  let halted = false;
  let backoffMs = 0;
  let lastAttemptAt = 0;

  function clearTimer() {
    if (timeoutId !== null) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
  }

  function fire() {
    lastAttemptAt = now();
    options.refresh().then(
      () => {
        halted = false;
        backoffMs = 0;
      },
      (error: unknown) => {
        if (error instanceof RefreshDeniedError && TERMINAL_CODES.has(error.code)) {
          halted = true;
          clearTimer();
        } else {
          // Anything else (rate limiting, a transient network failure) is worth
          // retrying, but only ever slower — never in a tight loop.
          backoffMs = Math.min(Math.max(backoffMs * 2, MIN_INTERVAL_MS), MAX_BACKOFF_MS);
        }
        options.onError?.(error);
      },
    );
  }

  /** Earliest instant another attempt may be made, independent of `active_until`. */
  function attemptFloor(): number {
    if (lastAttemptAt === 0) return 0;
    return lastAttemptAt + Math.max(MIN_INTERVAL_MS, backoffMs);
  }

  function reschedule() {
    clearTimer();
    if (halted) return;
    if (!options.isLeader()) return;
    const meta = options.getMeta();
    if (!meta) return;
    const fireAt = meta.active_until * 1000 - skewMs;
    const delay = Math.max(0, Math.max(fireAt, attemptFloor()) - now());
    timeoutId = setTimeout(fire, delay);
  }

  function lazyCheck() {
    if (halted) return;
    const meta = options.getMeta();
    if (!meta) return;
    if (now() < attemptFloor()) return;
    if (now() >= meta.active_until * 1000 - skewMs) {
      fire();
    }
  }

  const hasDom = typeof document !== 'undefined' && typeof window !== 'undefined';
  const onVisibility = () => {
    if (document.visibilityState === 'visible') lazyCheck();
  };
  const onFocus = () => lazyCheck();
  const onOnline = () => lazyCheck();

  if (hasDom) {
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('focus', onFocus);
    window.addEventListener('online', onOnline);
  }

  reschedule();

  return {
    reschedule,
    isHalted: () => halted,
    resume() {
      halted = false;
      backoffMs = 0;
      lastAttemptAt = 0;
      reschedule();
    },
    halt() {
      halted = true;
      clearTimer();
    },
    dispose() {
      clearTimer();
      if (hasDom) {
        document.removeEventListener('visibilitychange', onVisibility);
        window.removeEventListener('focus', onFocus);
        window.removeEventListener('online', onOnline);
      }
    },
  };
}
