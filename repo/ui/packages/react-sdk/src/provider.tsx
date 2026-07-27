/**
 * `<SessionProvider>` + `useSession()` (§8): the one place the four modules
 * get wired together. Mounts leader election and the refresh timers exactly
 * once for the app; every other hook here just projects a slice of the same
 * shared state so the demo can observe leadership, the refresh log, and a
 * provider-bound `brokerFetch` without re-deriving any of it.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactElement,
  type ReactNode,
} from 'react';
import { getSessionMeta } from './meta.js';
import { electLeader } from './leader.js';
import { singleFlightRefresh, startRefreshTimers, RefreshDeniedError } from './refresh.js';
import type { RefreshOutcome, RefreshTimerHandle } from './refresh.js';
import { createBrokerFetch } from './fetch.js';
import type { BrokerFetch } from './fetch.js';
import { startSessionEventStream } from './events.js';
import type { EventSourceFactory, SessionEventStream, SessionStreamEvent, StreamState } from './events.js';
import type { SessionMeta, SessionStatus } from './types.js';

const REFRESH_LOG_LIMIT = 50;
const EVENTS_LOG_LIMIT = 50;

/**
 * When (if ever) this tab opens `GET /session/events`. Default
 * `'leader-only'` is the conservative choice: under HTTP/1.1 a browser
 * allows only ~6 connections per origin, and a permanently-open SSE stream
 * held by every tab would starve that pool for the tab's other requests.
 * Only the Web Lock leader (leader.ts, ADR-0008) opens the stream; every
 * other tab still gets `session.killed`/`custody.changed` eventually via the
 * next lazy check or refresh, just not the sub-second push. Set `'per-tab'`
 * once the app is known to be served over HTTP/2 (or HTTP/3), where ~100
 * multiplexed streams share one connection and per-tab streams cost nothing
 * extra. `'off'` disables the stream entirely — the SDK still works, just
 * back to lazy-check latency for everything this endpoint would have told
 * it sooner.
 */
export type SessionEventsMode = 'leader-only' | 'per-tab' | 'off';

/** Connection state as seen from outside a tab: `'disabled'` means this tab never opened a stream at all (mode `'off'`, or `'leader-only'` and this tab isn't leader) — distinct from `'closed'`, which means a stream was opened and then stopped. */
export type SessionStreamProviderState = 'disabled' | StreamState;

/** One measured refresh, for the demo's refresh log (§8 item 4). */
export interface RefreshLogEntry {
  at: number;
  gen: number;
  rttMs: number;
  serverHandlerUs: number | null;
}

export interface LogoutResult {
  loggedOut: boolean;
  idpLogoutUrl?: string;
}

interface SessionContextValue {
  status: SessionStatus;
  meta: SessionMeta | null;
  isLeader: boolean;
  refreshLog: RefreshLogEntry[];
  login: (returnTo?: string) => void;
  logout: () => Promise<LogoutResult>;
  refreshNow: () => Promise<RefreshOutcome>;
  brokerFetch: BrokerFetch;
  eventsMode: SessionEventsMode;
  streamState: SessionStreamProviderState;
  streamActive: boolean;
  streamEvents: SessionStreamEvent[];
}

const SessionContext = createContext<SessionContextValue | null>(null);

export interface SessionProviderProps {
  children: ReactNode;
  /**
   * Fetch implementation to use for `/session/refresh` and `/logout`, and
   * the default bound into `brokerFetch`. Read once at mount — stable
   * across the provider's lifetime; pass a fixed reference (tests only,
   * normally omit this and let it default to the ambient `fetch`).
   */
  fetchImpl?: typeof fetch;
  /** Whether/when this tab opens `GET /session/events` — see {@link SessionEventsMode}. Default `'leader-only'`. Read once at mount. */
  events?: SessionEventsMode;
  /** `EventSource` factory for `/session/events`. Read once at mount; tests only, normally omit and let it default to the ambient `EventSource`. */
  eventSourceFactory?: EventSourceFactory;
}

/**
 * Derive a *hint* status from the meta cookie's timestamps. Per INV-9 this
 * is never ground truth: `active_until` passing on its own just means "due
 * for refresh" — the timer/lazy checks handle that — so the UI keeps
 * showing 'active' until either a refresh or a 401 proves otherwise. Only
 * `refresh_until`/`absolute_until` passing is something the hint can say
 * with real confidence, because past that point the server does not even
 * attempt a local refresh.
 */
function statusFromMeta(meta: SessionMeta | null, nowMs: number): SessionStatus {
  if (!meta) return 'anonymous';
  if (nowMs >= meta.absolute_until * 1000 || nowMs >= meta.refresh_until * 1000) {
    return 'expired';
  }
  return 'active';
}

export function SessionProvider(props: SessionProviderProps): ReactElement {
  const { children } = props;
  const fetchImplRef = useRef(props.fetchImpl ?? fetch);
  const eventsModeRef = useRef<SessionEventsMode>(props.events ?? 'leader-only');
  const eventSourceFactoryRef = useRef(props.eventSourceFactory);

  const [meta, setMeta] = useState<SessionMeta | null>(() => getSessionMeta());
  const [status, setStatus] = useState<SessionStatus>(() => statusFromMeta(meta, Date.now()));
  const [isLeader, setIsLeader] = useState(false);
  const [refreshLog, setRefreshLog] = useState<RefreshLogEntry[]>([]);
  const [streamState, setStreamState] = useState<SessionStreamProviderState>('disabled');
  const [streamActive, setStreamActive] = useState(false);
  const [streamEvents, setStreamEvents] = useState<SessionStreamEvent[]>([]);

  const metaRef = useRef(meta);
  metaRef.current = meta;
  const timerRef = useRef<RefreshTimerHandle | null>(null);
  const refreshOnceRef = useRef(singleFlightRefresh(fetchImplRef.current));

  const doRefresh = useCallback((): Promise<RefreshOutcome> => {
    setStatus('refreshing');
    return refreshOnceRef.current().then(
      (outcome) => {
        setMeta(outcome.meta);
        setStatus('active');
        setRefreshLog((prev) =>
          [
            ...prev,
            {
              at: Date.now(),
              gen: outcome.meta.gen,
              rttMs: outcome.rttMs,
              serverHandlerUs: outcome.serverHandlerUs,
            },
          ].slice(-REFRESH_LOG_LIMIT),
        );
        timerRef.current?.reschedule();
        return outcome;
      },
      (error: unknown) => {
        // invalid_session means there was never a recoverable session here
        // (ANONYMOUS); every other denial (session_expired, upstream_revoked,
        // login_required, csrf_rejected, ...) means there *was* one and it
        // now needs interactive login, i.e. 'expired'.
        if (error instanceof RefreshDeniedError && error.code === 'invalid_session') {
          setMeta(null);
          setStatus('anonymous');
        } else {
          setStatus('expired');
        }
        timerRef.current?.reschedule();
        throw error;
      },
    );
  }, []);

  const brokerFetch = useMemo<BrokerFetch>(
    () => createBrokerFetch(doRefresh, fetchImplRef.current),
    [doRefresh],
  );

  useEffect(() => {
    const election = electLeader();
    setIsLeader(election.isLeader());

    const timers = startRefreshTimers({
      isLeader: () => election.isLeader(),
      getMeta: () => metaRef.current,
      refresh: doRefresh,
      onError: () => {
        /* already reflected in `status` by doRefresh's rejection handler */
      },
    });
    timerRef.current = timers;

    // The event stream's lifecycle is driven by the same leadership signal
    // as the refresh timer, so it lives in this same effect rather than a
    // second one — one election, one place that reacts to it.
    const eventsMode = eventsModeRef.current;
    let stream: SessionEventStream | null = null;
    let unsubStreamEvents: (() => void) | null = null;
    let unsubStreamState: (() => void) | null = null;

    function teardownStream() {
      unsubStreamEvents?.();
      unsubStreamState?.();
      unsubStreamEvents = null;
      unsubStreamState = null;
      stream?.close();
      stream = null;
      setStreamActive(false);
      setStreamState('disabled');
    }

    function setupStream() {
      if (stream) return; // already open — leadership churn must not reopen a live stream
      const opened = startSessionEventStream({
        ...(eventSourceFactoryRef.current ? { factory: eventSourceFactoryRef.current } : {}),
        onError: () => {
          /* consumers observe this via streamState; no console spam by default */
        },
      });
      stream = opened;
      setStreamActive(true);
      setStreamState(opened.getState());
      unsubStreamState = opened.onStateChange((next) => setStreamState(next));
      unsubStreamEvents = opened.subscribe((event) => {
        setStreamEvents((prev) => [...prev, event].slice(-EVENTS_LOG_LIMIT));
        if (event.name === 'session.killed') {
          // A stronger signal than any lazy check could give: the session is
          // gone, so move straight to 'expired' and stop the timer without
          // spending a refresh call to rediscover the same fact via a 401
          // (INV-9: this is still a hint prompting local cleanup, not a
          // truth the server didn't already establish). Nothing left to
          // stream for this session either, so close it.
          setStatus('expired');
          timerRef.current?.halt();
          teardownStream();
        } else {
          setMeta((prev) => (prev ? { ...prev, custody: event.data.custody } : prev));
        }
      });
    }

    function syncStream(leading: boolean) {
      if (eventsMode === 'off') {
        teardownStream();
        return;
      }
      if (eventsMode === 'per-tab' || leading) {
        setupStream();
      } else {
        teardownStream();
      }
    }

    syncStream(election.isLeader());

    const unsubscribe = election.onChange((leading) => {
      setIsLeader(leading);
      timers.reschedule();
      syncStream(leading);
    });

    return () => {
      unsubscribe();
      election.release();
      timers.dispose();
      timerRef.current = null;
      teardownStream();
    };
  }, [doRefresh]);

  const login = useCallback((returnTo?: string) => {
    const url = new URL('/session/refresh', window.location.origin);
    url.searchParams.set('interactive', '1');
    if (returnTo) url.searchParams.set('return_to', returnTo);
    window.location.assign(url.toString());
  }, []);

  const logout = useCallback(async (): Promise<LogoutResult> => {
    const response = await fetchImplRef.current('/logout', {
      method: 'POST',
      credentials: 'same-origin',
    });
    let body: { logged_out?: boolean; idp_logout_url?: string } = {};
    try {
      body = (await response.json()) as typeof body;
    } catch {
      body = {};
    }
    setMeta(null);
    setStatus('anonymous');
    timerRef.current?.reschedule();
    const idpLogoutUrl = body.idp_logout_url;
    return idpLogoutUrl !== undefined
      ? { loggedOut: body.logged_out ?? response.ok, idpLogoutUrl }
      : { loggedOut: body.logged_out ?? response.ok };
  }, []);

  const value = useMemo<SessionContextValue>(
    () => ({
      status,
      meta,
      isLeader,
      refreshLog,
      login,
      logout,
      refreshNow: doRefresh,
      brokerFetch,
      eventsMode: eventsModeRef.current,
      streamState,
      streamActive,
      streamEvents,
    }),
    [status, meta, isLeader, refreshLog, login, logout, doRefresh, brokerFetch, streamState, streamActive, streamEvents],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

function useSessionContext(hookName: string): SessionContextValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error(`${hookName}() must be used within <SessionProvider>`);
  return ctx;
}

/** The core hook (§8): `{ status, meta, login, logout }`. */
export function useSession(): Pick<SessionContextValue, 'status' | 'meta' | 'login' | 'logout'> {
  const { status, meta, login, logout } = useSessionContext('useSession');
  return { status, meta, login, logout };
}

/** Whether this tab currently holds the refresh-leader Web Lock (demo's leader badge). */
export function useLeader(): boolean {
  return useSessionContext('useLeader').isLeader;
}

/** The measured refresh log, plus a manual trigger — feeds the demo's refresh log and race button. */
export function useRefreshLog(): { entries: RefreshLogEntry[]; refreshNow: () => Promise<RefreshOutcome> } {
  const { refreshLog, refreshNow } = useSessionContext('useRefreshLog');
  return { entries: refreshLog, refreshNow };
}

/** The provider-bound `brokerFetch`, wired to the shared single-flight refresh. */
export function useBrokerFetch(): BrokerFetch {
  return useSessionContext('useBrokerFetch').brokerFetch;
}

/** The recent `/session/events` feed plus this tab's stream connection state — feeds the demo's live event feed and its connection indicator. */
export interface SessionEventsInfo {
  /** Recent decoded events, oldest first, capped at 50 (like the refresh log). */
  entries: SessionStreamEvent[];
  /** This tab's own stream state: `'disabled'` if it never opened one (mode `'off'`, or `'leader-only'` and not leader). */
  connectionState: SessionStreamProviderState;
  /** Whether *this* tab currently has a stream open at all. */
  active: boolean;
  /** Whether `active` is true specifically *because* this tab is the Web Lock leader — false in `'per-tab'` mode, where every tab is active regardless of leadership. */
  activeBecauseLeader: boolean;
}

export function useSessionEvents(): SessionEventsInfo {
  const ctx = useSessionContext('useSessionEvents');
  return {
    entries: ctx.streamEvents,
    connectionState: ctx.streamState,
    active: ctx.streamActive,
    activeBecauseLeader: ctx.streamActive && ctx.eventsMode === 'leader-only' && ctx.isLeader,
  };
}
