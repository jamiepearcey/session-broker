# Verifying session-broker tokens

For the product that receives a token (log-less is the first): how to decide, offline,
whether a token the broker issued is good. The broker signs; you verify against the
public keys it publishes. There is no introspection endpoint and no per-request call
back to the broker (ADR-0017).

Two kinds of token share one format. Machine tokens come from `POST /auth/token`, user
tokens from `POST /session/token`. Both are compact JWS: header `{"alg":"EdDSA","typ":"JWT","kid":"…"}`,
Ed25519 signature, claims below. Test tokens with the verdict each must get are in
[`vectors.json`](vectors.json).

## Claims

| Claim | Machine token | User token |
|---|---|---|
| `iss` | the broker's configured `token_issuer` | same |
| `sub` | principal id (`sp_…`) | the identity provider's `sub` |
| `aud` | one string, the principal's audience | one string, the audience requested |
| `exp`, `iat` | seconds; `exp - iat` is 86400 by default | seconds; 3600 by default, cut at the session's idle expiry |
| `jti` | 22 characters, unique per token | same |
| `tenant` | the principal's tenant | the grant's tenant |
| `kind` | `ingest`, `node`, `replica`, `reader` or `admin` | `user` |
| `name` | the principal's name | absent |
| `scopes` | array of strings | absent |
| `roles` | absent | array of strings |
| `sid` | absent | the broker session id |
| `indexes` | array of strings; `["*"]` means every index of the tenant | same |

There is no `nbf`. The broker never backdates `iat`.

## The checks, in order

Fail closed: the first failing check rejects the token, and the reason is the one named.
Do not read a claim before the signature has verified.

1. **Shape and header.** Exactly three base64url (no padding) segments. Parse the header.
   Reject unless `alg` is exactly `EdDSA`, and do it before looking at any key: never let
   the token choose the algorithm, and never accept `none` or an HMAC `alg` (`alg`).
   `typ` must be absent or `JWT`; there must be no `crit`; `kid` must be present (`malformed`).
2. **Find the key.** Look `kid` up in your cached key set. If it is missing and your
   last refresh was more than 60 s ago, refresh once. Still missing: reject (`unknown_kid`).
3. **Verify the signature.** Ed25519 over the ASCII bytes of `header.payload` exactly as
   received (`signature`).
4. **Check the claims.**
   - `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `tenant`, `kind` must all be present (`claims`).
   - `iss` equals your configured issuer string exactly (`issuer`).
   - `aud` is a string equal to your own configured audience, and nothing else (`audience`).
     A token for another product, or another component of yours with its own audience, is
     refused.
   - `exp > now - 300` (`expired`).
   - `iat <= now + 300` (`not_yet_valid`).
5. **Enforce, from the token and nowhere else.** The tenant comes from the `tenant` claim,
   never from the request path or a header. Check that `kind` is allowed at this endpoint,
   that `scopes` holds the scope the operation needs, and that `indexes` is `["*"]` or
   names the index being touched. For a node token, `name` is the node id. The broker
   stamps these attributes and does not interpret them; deciding what they permit is yours.

**Clock allowance: 300 seconds**, either way, on `exp` and `iat`. A token whose `exp` is
200 s in the past is still accepted; one 301 s past is not. This is the figure Auth0, AWS
and Google use. The vectors cover both edges.

## Getting and caching the keys

The key set is at `GET <issuer>/auth/jwks.json` (the broker's `jwks_uri`, also named in
`GET <issuer>/.well-known/oauth-authorization-server`). It lists every **published** key:
the one signing now, older ones whose tokens may still be in flight, and pending ones
that start signing later, so you learn a key before any token carries it. Each entry is
`{"kty":"OKP","crv":"Ed25519","kid","x","use":"sig","alg":"EdDSA"}`.

Cache policy:

- **Fetch at start** if the broker is reachable. Persist the cache to disk with its fetch
  time, so a restart while the broker is down still works.
- **Refresh hourly** (add jitter). Send `If-None-Match` with the last `ETag`; a `304`
  means nothing changed. The broker sends `Cache-Control: public, max-age=300,
  stale-if-error=2592000`; treat `max-age` as a floor on how often you ask.
- **Refresh at once on an unknown `kid`**, at most once per 60 s.
- **Keep serving the cache while the broker is unreachable, with no time limit.** An edge
  that cannot reach the broker must not stop verifying, and so must not stop ingesting.
  `stale-if-error` says the same. Expose how stale the cache is as a metric and warn on
  it, but do not stop verifying because of it.
- **Never drop a key on a failed refresh.** Replace the cached set atomically, and only
  after a refresh succeeds and parses.
- The `Date` response header is the broker's clock. If it differs from yours by more than
  30 s, log a warning: the 300 s allowance is the budget, and drift eats it.

## What rotation means for you

Rotation is an operator action, not a schedule. A normal rotation publishes the new key
a day (by default) before it signs, and keeps the old key published until the longest
token it signed has expired plus the allowance, so an hourly refresh never misses a key.

An **emergency** rotation (`activate_in_secs: 0`) is different on purpose: the new key
signs now and every older key stops being published now. Tokens signed by the old key
stop verifying as soon as you refresh, and new tokens fail with `unknown_kid` until you do,
which is why step 2 refreshes on an unknown `kid`.

## What a token cannot tell you

An issued token cannot be revoked before it expires. If a principal, secret or grant is
revoked, you learn nothing until the token's `exp`. If that is not acceptable for an
operation (a destructive admin call, say), do not rely on the token alone for it; there
is deliberately no introspection endpoint to ask.

## The test vectors

[`vectors.json`](vectors.json) holds the key set, the issuer and audience to configure,
the allowance, and a list of cases. Each case is a token, a `verify_at` (the instant to
treat as "now"), and the expected result: `accept`, or `reject` with the reason above.

| Id | What it tests | Result |
|---|---|---|
| `V1.accept` | A valid machine token at `iat + 10` | accept |
| `V1.accept-inside-allowance-after-exp` | 200 s past `exp` | accept |
| `V1.accept-inside-allowance-before-iat` | 200 s before `iat` | accept |
| `V1.expired` | 301 s past `exp` | reject `expired` |
| `V1.issued-in-the-future` | 301 s before `iat` | reject `not_yet_valid` |
| `V2.audience` | Correctly signed, wrong `aud` | reject `audience` |
| `V2.alg-hs256` | V1's claims signed HS256 with the public key as the secret | reject `alg` |
| `V2.tampered-payload` | V1's signature around a different payload | reject `signature` |
| `V3.accept` | A valid user token at `iat + 30` | accept |
| `V3.expired` | The user token 301 s past `exp` | reject `expired` |
| `V3.unknown-kid` | Right key, a `kid` the set does not contain | reject `unknown_kid` |

A verifier passes when every case gets its verdict. If it rejects a case for a different
reason than the one listed it still fails safe, but it is checking in a different order
from the one above, and that is worth knowing.

The file is generated by `repo/crates/session-broker/src/issuer/vectors.rs` from a fixed
**test-only** seed, and that test fails if the committed file differs from what the
signer produces, so the vectors cannot drift from the broker. The seed is in that source
file and public: never load it into a broker. Regenerate with
`UPDATE_VECTORS=1 cargo test -p session-broker vectors` from `repo/`.
