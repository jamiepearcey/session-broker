# ADR-0006: Opaque Hashed Cookie Tokens; No JWT Sessions; Upstream Tokens Encrypted at Rest

## Status

Accepted (2026-07-26)

## Context

The session cookie is the credential the entire rotation/grace/logout model
(ADR-0002, ADR-0010) is built on. That model requires the server to hold
authoritative, mutable state per token — generation number, supersession time,
parent session liveness — and to be able to kill a whole family of tokens in
one write. Upstream access/refresh tokens are a separate, higher-value secret
that must survive at-rest theft of the store file.

## Decision

- **Session/txn cookie values are 256-bit CSPRNG opaque tokens.** The store
  holds only `SHA-256(token)` (INV-5) — never the raw value.
- **No JWT for session state.** The session cookie carries no claims; it is a
  lookup key into server-side state.
- **Upstream access and refresh tokens are encrypted at rest** with
  XChaCha20-Poly1305, key from a keyfile beside the DB (env-overridable) —
  resolved question 7. Store-file theft alone yields no usable session
  cookies (hashes are one-way) and no plaintext upstream tokens (encrypted,
  separate key).

## Alternatives considered

- **JWT session cookie**, self-contained and statelessly verifiable. Rejected:
  a JWT cannot be revoked or rotated through server-side bookkeeping without a
  blocklist, which reintroduces the server-side state this format is chosen
  to avoid and would defeat INV-7's atomic single-write logout (there'd be no
  single row to tombstone — validity would depend on checking a growing
  blocklist on every request). The generation/grace model in ADR-0002 requires
  server-authoritative per-token state that a self-contained token can't hold.
- **Encrypt the session token instead of hashing it.** Rejected: hashing is
  simpler (no key management on the hot lookup path), one-way (a compromised
  hash reveals nothing usable), and lookup is by equality on the hash — no
  decryption step needed on every resource check.
- **Store upstream tokens in plaintext**, relying on filesystem permissions
  alone. Rejected: filesystem permissions are a single control; encryption at
  rest is a second, independent one, and upstream tokens are the one asset in
  this system whose theft has consequences reaching outside the broker
  (the upstream IdP grant itself).

## Consequences

- Session state cannot be verified offline — every resource check requires a
  store/map lookup by hash. This is the trade this project explicitly makes
  (contrast `iam`'s JWT access tokens, ADR-0004 there, chosen for a different
  problem — stateless verification by many resource servers): here, the
  server-side lookup is what *enables* rotation, grace, and atomic logout, not
  a cost paid despite them.
- Encryption key/keyfile lifecycle (generation on first boot, rotation,
  backup) becomes an operational responsibility; keyfile-and-DB theft
  together still yields plaintext tokens, but that is accepted because both
  live in the same trust zone (one box) per resolved question 7.
- No JWKS/introspection surface is needed for session tokens, simplifying the
  broker's public contract relative to a JWT-based design — this is the one
  place where doing less is a direct consequence of doing less trust-remote
  verification, not an oversight.
