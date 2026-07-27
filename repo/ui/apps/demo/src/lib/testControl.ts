/**
 * Thin client for `mock-idp`'s `/__test__/*` control surface
 * (`crates/mock-idp/src/routes/test_control.rs`), proxied same-origin by
 * the Vite dev server. This is what drives the demo's failure-path
 * controls: forced upstream expiry, refresh-token revocation, and
 * injected `/token` failures.
 *
 * Every call is wrapped so a control action failing (wrong subject, mock
 * IdP not running, etc.) surfaces as data the UI can render rather than an
 * unhandled rejection — these buttons are meant to be pressed against a
 * partially-wired dev stack.
 */

export interface ControlResult<T> {
  ok: boolean;
  status: number;
  body: T | null;
  error?: string;
}

async function call<T>(method: 'GET' | 'POST', path: string, payload?: unknown): Promise<ControlResult<T>> {
  try {
    const init: RequestInit =
      payload !== undefined
        ? {
            method,
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload),
          }
        : { method, credentials: 'same-origin' };
    const response = await fetch(`/__test__${path}`, init);
    let body: T | null = null;
    try {
      body = (await response.json()) as T;
    } catch {
      body = null;
    }
    return { ok: response.ok, status: response.status, body };
  } catch (err) {
    return { ok: false, status: 0, body: null, error: err instanceof Error ? err.message : String(err) };
  }
}

/** `POST /__test__/expire` — force every live token belonging to `subject` into the past. */
export function expireSubject(subject: string): Promise<ControlResult<{ expired: number }>> {
  return call('POST', '/expire', { subject });
}

/** `POST /__test__/revoke-refresh` — the next upstream refresh for `subject` fails `invalid_grant`. */
export function revokeRefreshFor(subject: string): Promise<ControlResult<{ revoked: number }>> {
  return call('POST', '/revoke-refresh', { subject });
}

/** `POST /__test__/fail-next` — the next `count` calls to the IdP's `/token` fail with the given status/error. */
export function failNextUpstreamCalls(
  count: number,
  status: number,
  error: string,
): Promise<ControlResult<Record<string, never>>> {
  return call('POST', '/fail-next', { count, status, error });
}

/** `GET /__test__/state` — full dump of issued tokens, subjects, and call counters. */
export function dumpMockIdpState(): Promise<ControlResult<unknown>> {
  return call('GET', '/state');
}
