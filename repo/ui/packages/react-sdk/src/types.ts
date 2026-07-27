/**
 * Contract types shared across the SDK. These mirror
 * `docs/architecture/implementation-strategy.md` §4 exactly — do not add
 * fields the server does not send, and do not infer semantics the server
 * does not document.
 */

/** `custody` field of the meta payload: local view of upstream token health. */
export type CustodyStatus = 'ok' | 'degraded' | 'dead';

/**
 * The exact shape of `broker_meta` (and the JSON body of a successful
 * `POST /session/refresh`) per §4. All `*_until` fields are epoch seconds,
 * as minted by the server — never re-derive them client-side.
 */
export interface SessionMeta {
  v: number;
  sub: string;
  sid: string;
  gen: number;
  active_until: number;
  refresh_until: number;
  absolute_until: number;
  custody: CustodyStatus;
}

/** The error taxonomy from §4's shared JSON error shape. */
export type ErrorCode =
  | 'invalid_session'
  | 'session_stale'
  | 'session_expired'
  | 'login_required'
  | 'upstream_revoked'
  | 'csrf_rejected'
  | 'oauth_error'
  | 'bad_request'
  | 'rate_limited';

/** `{ "error": "<code>", "detail": "...", "login_url": "..."? }` verbatim. */
export interface ApiErrorBody {
  error: ErrorCode;
  detail: string;
  login_url?: string;
}

/**
 * Client-facing session status. This is a UI convenience derived from the
 * meta hint and observed request outcomes — per INV-9 it is never ground
 * truth; a 401 from the server always wins over what this says.
 */
export type SessionStatus = 'anonymous' | 'active' | 'refreshing' | 'expired';
