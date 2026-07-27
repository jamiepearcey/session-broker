export type { SessionMeta, CustodyStatus, ErrorCode, ApiErrorBody, SessionStatus } from './types.js';

export { parseMetaCookie, getSessionMeta } from './meta.js';

export { electLeader } from './leader.js';
export type { LocksLike, LeaderElection, LeaderChangeListener } from './leader.js';

export { singleFlightRefresh, startRefreshTimers, RefreshDeniedError } from './refresh.js';
export type { RefreshOutcome, RefreshTimerOptions, RefreshTimerHandle } from './refresh.js';

export { createBrokerFetch } from './fetch.js';
export type { BrokerFetch } from './fetch.js';

export { startSessionEventStream } from './events.js';
export type {
  EventSourceLike,
  EventSourceFactory,
  SessionEventStream,
  SessionEventStreamOptions,
  SessionStreamEvent,
  SessionStreamEventListener,
  SessionKilledPayload,
  CustodyChangedPayload,
  StreamState,
} from './events.js';

export {
  SessionProvider,
  useSession,
  useLeader,
  useRefreshLog,
  useBrokerFetch,
  useSessionEvents,
} from './provider.js';
export type {
  SessionProviderProps,
  RefreshLogEntry,
  LogoutResult,
  SessionEventsMode,
  SessionStreamProviderState,
  SessionEventsInfo,
} from './provider.js';
