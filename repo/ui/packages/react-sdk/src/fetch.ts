/**
 * `brokerFetch`: pass-through fetch that recovers from exactly one 401
 * shape and otherwise gets out of the way.
 *
 * Per the resource-auth column of the session state machine (§3), a 401
 * from a cookie-authenticated endpoint can mean three different things:
 * `invalid_session` (ANONYMOUS — refresh would fail too), `session_stale`
 * (STALE-REFRESHABLE — refresh succeeds locally and resolves it) or
 * `session_expired` / `upstream_revoked` (HARD-EXPIRED — needs interactive
 * login). Only `session_stale` is worth spending a refresh-and-retry on;
 * the others are surfaced to the caller untouched; `brokerFetch` never
 * redirects on any of them — navigation is the app's decision via
 * `login()`.
 */
import type { RefreshOutcome } from './refresh.js';
import type { ApiErrorBody } from './types.js';

const REFRESHABLE: ReadonlySet<ApiErrorBody['error']> = new Set(['session_stale']);

export type BrokerFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/**
 * Bind a `brokerFetch` to a single-flight refresh function (typically the
 * one shared by the provider, so a 401-triggered refresh coalesces with any
 * timer- or lazy-check-triggered one already in flight).
 */
export function createBrokerFetch(
  refresh: () => Promise<RefreshOutcome>,
  fetchImpl: typeof fetch = fetch,
): BrokerFetch {
  return async function brokerFetch(input, init) {
    const send = () => fetchImpl(input, { ...init, credentials: 'same-origin' });

    const first = await send();
    if (first.status !== 401) return first;

    const body = await safeParseBody(first);
    if (!body || !REFRESHABLE.has(body.error)) {
      // invalid_session / session_expired / login_required / anything else:
      // not recoverable by refreshing. Surface as-is, retry nothing.
      return first;
    }

    try {
      await refresh();
    } catch {
      // The refresh itself was denied — the original 401 already carries the
      // right signal, so hand that back rather than the refresh's error.
      return first;
    }

    // Exactly one retry, no matter what it returns.
    return send();
  };
}

async function safeParseBody(response: Response): Promise<ApiErrorBody | null> {
  try {
    return (await response.clone().json()) as ApiErrorBody;
  } catch {
    return null;
  }
}
