/**
 * Parse the `broker_meta` cookie into a typed {@link SessionMeta}.
 *
 * Pure: every function here takes its input explicitly and only touches
 * `document.cookie` in the zero-argument default of {@link getSessionMeta}.
 * INV-9: this is an unsigned, unsigned-by-design *hint* — never validated,
 * never trusted over a server response. A corrupt or missing cookie is a
 * normal case, not an error: every parse path returns `null` and never
 * throws.
 */
import type { SessionMeta } from './types.js';

const META_COOKIE_NAME = 'broker_meta';

/**
 * Read and decode `broker_meta` out of a raw `Cookie`-header-shaped string
 * (`"a=1; b=2"`). Fully pure — no ambient reads — which is what makes it
 * unit-testable without a DOM.
 */
export function parseMetaCookie(cookieHeader: string): SessionMeta | null {
  const raw = extractCookieValue(cookieHeader, META_COOKIE_NAME);
  if (raw === null) return null;
  return decodeMeta(raw);
}

/**
 * Read `broker_meta` from `document.cookie` (or an injected cookie string,
 * for tests that don't want to mock `document`). Never throws.
 */
export function getSessionMeta(cookieHeader?: string): SessionMeta | null {
  const source = cookieHeader ?? (typeof document !== 'undefined' ? document.cookie : '');
  return parseMetaCookie(source);
}

function extractCookieValue(cookieHeader: string, name: string): string | null {
  for (const pair of cookieHeader.split(';')) {
    const eq = pair.indexOf('=');
    if (eq === -1) continue;
    const key = pair.slice(0, eq).trim();
    if (key === name) {
      return pair.slice(eq + 1).trim();
    }
  }
  return null;
}

function decodeMeta(value: string): SessionMeta | null {
  let json: string;
  try {
    json = base64UrlDecode(value);
  } catch {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }

  return isSessionMeta(parsed) ? parsed : null;
}

/** base64url (no padding), the exact encoding `encode_meta` on the server uses. */
function base64UrlDecode(value: string): string {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const withPadding = padded + '='.repeat((4 - (padded.length % 4)) % 4);
  const binary = atob(withPadding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

const CUSTODY_VALUES = new Set(['ok', 'degraded', 'dead']);

/** Runtime shape guard so a structurally-wrong-but-valid-JSON cookie is `null`, not a crash later. */
function isSessionMeta(value: unknown): value is SessionMeta {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v['v'] === 'number' &&
    typeof v['sub'] === 'string' &&
    typeof v['sid'] === 'string' &&
    typeof v['gen'] === 'number' &&
    typeof v['active_until'] === 'number' &&
    typeof v['refresh_until'] === 'number' &&
    typeof v['absolute_until'] === 'number' &&
    typeof v['custody'] === 'string' &&
    CUSTODY_VALUES.has(v['custody'])
  );
}
