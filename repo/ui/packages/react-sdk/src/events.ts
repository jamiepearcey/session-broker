/**
 * `GET /session/events`: a cookie-authenticated `text/event-stream` of
 * session lifecycle hints (`session.killed`, `custody.changed`). Per INV-9
 * these are hints that prompt the client to act, never ground truth — the
 * server's own responses (`/session/refresh`, `brokerFetch`) remain
 * authoritative; this module only ever *reacts faster* to what a lazy check
 * would eventually have discovered anyway.
 *
 * Hard safety rule (the reason this file exists as its own module, mirroring
 * refresh.ts's `TERMINAL_CODES` halt): `EventSource` reconnects forever by
 * default and cannot see the HTTP status code of a failed connection
 * attempt. The endpoint 401s on every attempt once the session is dead, so a
 * naive `new EventSource(url)` left to its own devices turns into an
 * infinite reconnect loop against a dead session — indistinguishable, from
 * inside the browser, from a healthy stream that is merely slow to open.
 *
 * So this module never leans on the platform's own reconnect behaviour:
 * every `error` closes the underlying source itself (stopping whatever the
 * browser might otherwise have done next) and hands the next attempt to our
 * own capped, backed-off loop — the same shape as `startRefreshTimers`, one
 * layer down where there is even less information to work with. `error`
 * with no intervening `open` is the *only* terminal signal available (no
 * status code to read), so consecutive `error`-without-`open` is what trips
 * the halt: a stream that opens even once resets the counter, because that
 * proves the endpoint is reachable and the session was live at least then.
 *
 * The server's `retry:` field is intentionally not consulted — we always
 * close and re-create rather than let a held-open `EventSource` retry on its
 * own timer, because that native path is exactly the one with no status
 * visibility and no cap. The `: keepalive` comment line needs no handling
 * here at all: `EventSource` never surfaces SSE comment lines as events: - it
 * exists purely to stop intermediary proxies from timing the connection out.
 */
import type { CustodyStatus } from './types.js';

/** `session.killed` payload, the `data` field of the named SSE event. */
export interface SessionKilledPayload {
  sid: string;
  reason: 'logged_out' | 'upstream_revoked' | 'admin_revoked';
}

/** `custody.changed` payload, the `data` field of the named SSE event. */
export interface CustodyChangedPayload {
  sid: string;
  custody: CustodyStatus;
}

/** One decoded event off the stream, tagged with when *this tab* received it — the server sends no timestamp of its own. */
export type SessionStreamEvent =
  | { name: 'session.killed'; data: SessionKilledPayload; receivedAt: number }
  | { name: 'custody.changed'; data: CustodyChangedPayload; receivedAt: number };

export type SessionStreamEventListener = (event: SessionStreamEvent) => void;

/** Connection lifecycle of one stream instance, for the demo's connection indicator. */
export type StreamState = 'connecting' | 'open' | 'closed';

/**
 * The subset of `EventSource` this module needs, so tests can supply a fake.
 * That fake must model the platform faithfully — auto-reconnecting
 * internally with no way for us to read *why* an attempt failed — not a
 * convenient version of it. See `__tests__/events.test.ts`'s `FakeEventSource`
 * for the two platform rules that matter here: an `error` event carries no
 * status, and a source that has been `close()`d fires nothing further no
 * matter what the network does next.
 */
export interface EventSourceLike {
  close(): void;
  addEventListener(type: string, listener: (event: Event) => void): void;
  removeEventListener(type: string, listener: (event: Event) => void): void;
}

export type EventSourceFactory = (url: string) => EventSourceLike;

function defaultFactory(url: string): EventSourceLike {
  return new EventSource(url, { withCredentials: true }) as unknown as EventSourceLike;
}

export interface SessionEventStreamOptions {
  /** Default `/session/events`. */
  url?: string;
  /** Default: a real `EventSource` against `url`, or `null` if `EventSource` doesn't exist in this environment (SSR, ancient browser) — tests inject a fake here. */
  factory?: EventSourceFactory;
  /**
   * Consecutive `error`-without-an-intervening-`open` attempts before the
   * stream halts permanently and stops reconnecting. Default 3: enough to
   * ride out one blip (a proxy restart between keepalives) without
   * tolerating what looks like a dead/401ing session for long — the same
   * "never spin, but don't give up on the first hiccup either" trade-off
   * `startRefreshTimers` makes with its backoff floor.
   */
  maxConsecutiveFailures?: number;
  /** Delay before the first reconnect after a failure. Default 1s, doubling with each further consecutive failure. */
  baseBackoffMs?: number;
  /** Ceiling for the doubling backoff. Default 30s. */
  maxBackoffMs?: number;
  /** Called with each raw connection failure (the native `error` event), for callers that want to log/report — never called for the routine keepalive traffic, and never spammed once halted. */
  onError?: (error: unknown) => void;
}

export interface SessionEventStream {
  /**
   * Add a listener for decoded events. Multiple subscribers share the one
   * connection this stream opened — subscribing never opens a second
   * `EventSource` (single-flight, the same collapsing idea as
   * `singleFlightRefresh`, just for a long-lived stream instead of a single
   * request). Returns an unsubscribe function.
   */
  subscribe(listener: SessionStreamEventListener): () => void;
  /** Subscribe to connection-state changes (for the demo's connection indicator). */
  onStateChange(listener: (state: StreamState) => void): () => void;
  getState(): StreamState;
  /** Whether the stream has stopped reconnecting for good. Cleared only by creating a new stream — there is no `resume()` here, unlike the refresh timer: a dead stream means a dead session, and only a fresh page load (fresh cookie, fresh provider mount) makes that worth retrying. */
  isHalted(): boolean;
  /** Tear down: close the connection and cancel any pending reconnect. Idempotent. */
  close(): void;
}

const DEFAULT_MAX_CONSECUTIVE_FAILURES = 3;
const DEFAULT_BASE_BACKOFF_MS = 1_000;
const DEFAULT_MAX_BACKOFF_MS = 30_000;

/**
 * Open (or begin opening) `/session/events` and own its whole reconnect
 * lifecycle. Call once per tab that wants the stream — *whether* to call
 * this at all (the `events` option × leader status) is the provider's
 * decision, not this module's; this module only ever makes one open
 * connection safe.
 */
export function startSessionEventStream(options: SessionEventStreamOptions = {}): SessionEventStream {
  const url = options.url ?? '/session/events';
  const resolvedFactory: EventSourceFactory | null =
    options.factory ?? (typeof EventSource !== 'undefined' ? defaultFactory : null);
  const maxConsecutiveFailures = options.maxConsecutiveFailures ?? DEFAULT_MAX_CONSECUTIVE_FAILURES;
  const baseBackoffMs = options.baseBackoffMs ?? DEFAULT_BASE_BACKOFF_MS;
  const maxBackoffMs = options.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS;

  const listeners = new Set<SessionStreamEventListener>();
  const stateListeners = new Set<(state: StreamState) => void>();
  let state: StreamState = resolvedFactory ? 'connecting' : 'closed';
  let halted = resolvedFactory === null;
  let closed = false;
  let consecutiveFailures = 0;
  let current: EventSourceLike | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  function setState(next: StreamState) {
    if (state === next) return;
    state = next;
    for (const listener of stateListeners) listener(next);
  }

  function clearReconnectTimer() {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  }

  function decode(name: SessionStreamEvent['name'], raw: Event): void {
    const data = (raw as MessageEvent).data as unknown;
    let parsed: unknown;
    try {
      parsed = typeof data === 'string' ? JSON.parse(data) : null;
    } catch {
      return;
    }
    const event = toStreamEvent(name, parsed);
    if (!event) return;
    for (const listener of listeners) listener(event);
  }

  function connect(): void {
    reconnectTimer = null;
    if (closed || halted || !resolvedFactory) return;
    setState('connecting');
    const source = resolvedFactory(url);
    current = source;

    const onOpen = () => {
      if (current !== source) return;
      consecutiveFailures = 0;
      setState('open');
    };

    const onError = (event: Event) => {
      if (current !== source) return;
      source.close();
      current = null;
      options.onError?.(event);
      if (closed) return;

      consecutiveFailures += 1;
      if (consecutiveFailures >= maxConsecutiveFailures) {
        halted = true;
        setState('closed');
        return;
      }
      setState('connecting');
      const delay = Math.min(baseBackoffMs * 2 ** (consecutiveFailures - 1), maxBackoffMs);
      reconnectTimer = setTimeout(connect, delay);
    };

    source.addEventListener('open', onOpen);
    source.addEventListener('error', onError);
    source.addEventListener('session.killed', (event) => decode('session.killed', event));
    source.addEventListener('custody.changed', (event) => decode('custody.changed', event));
  }

  connect();

  return {
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    onStateChange(listener) {
      stateListeners.add(listener);
      return () => stateListeners.delete(listener);
    },
    getState: () => state,
    isHalted: () => halted,
    close() {
      if (closed) return;
      closed = true;
      clearReconnectTimer();
      current?.close();
      current = null;
      setState('closed');
    },
  };
}

function toStreamEvent(name: SessionStreamEvent['name'], parsed: unknown): SessionStreamEvent | null {
  if (typeof parsed !== 'object' || parsed === null) return null;
  const value = parsed as Record<string, unknown>;
  const sid = value['sid'];
  if (typeof sid !== 'string') return null;
  const receivedAt = Date.now();

  if (name === 'session.killed') {
    const reason = value['reason'];
    if (reason !== 'logged_out' && reason !== 'upstream_revoked' && reason !== 'admin_revoked') return null;
    return { name, data: { sid, reason }, receivedAt };
  }

  const custody = value['custody'];
  if (custody !== 'ok' && custody !== 'degraded' && custody !== 'dead') return null;
  return { name, data: { sid, custody }, receivedAt };
}
