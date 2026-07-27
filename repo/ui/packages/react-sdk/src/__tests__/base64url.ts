/**
 * base64url (no padding) — the exact encoding the broker's `encode_meta` emits
 * and `meta.ts`'s `base64UrlDecode` reverses.
 *
 * Written against `btoa`/`TextEncoder` rather than Node's `Buffer` on purpose.
 * This is a **browser** SDK: reaching for a Node global here typechecks on a
 * developer machine that happens to have `@types/node` hoisted into its store
 * and then fails on a clean install, which is exactly how it was found. Using
 * the same primitives the SDK itself uses also means the test encodes the way a
 * browser would, rather than the way a server would.
 */
export function base64UrlEncode(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The common case: a meta object as it arrives in the `broker_meta` cookie. */
export function encodeMeta(value: unknown): string {
  return base64UrlEncode(JSON.stringify(value));
}
