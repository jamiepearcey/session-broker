# ADR-0016: Production hardening — rate limits, transport limits, graceful drain, readiness, and a rotatable custody keyring

## Status

Accepted (2026-10-03). Closes the "POC" gaps left after M0–M10: nothing here
changes the session model (ADR-0002/0003) or the lane topology (ADR-0007/0012).

## Context

The broker did what its ADRs said, but a deployment would have found five
things missing, each of which fails silently until something hostile or
operational happens:

1. Nothing bounded guessing against the shared secrets (admin key, backend
   key) or the per-call cost of `/auth/login` (a durable transaction each).
2. No request-size ceiling, no handler deadline, no response headers.
3. SIGTERM killed the process mid-flush; the write-behind queue was lost.
4. `/healthz` said the process was up, not that it could persist anything.
5. The custody key was a single raw 32-byte file: no way to rotate it, and the
   "refuse a world-readable keyfile" claim in the module docs was not enforced.

## Decision

**Rate limiting (`ratelimit.rs`, `http::guards::RateLimit`).** Two limiters:
wrong-key attempts on the internal and admin lanes (keyed on the peer — callers
connect directly), and `/auth/login` on the public lane. The public limiter is
**off unless `rate_limit_client_ip_header` names the header a trusted edge
appends**: behind an edge every request shares one peer, so a peer-keyed limiter
would put the whole user base in one bucket and the first trip would lock
everyone out. Each limiter is bounded in memory (`rate_limit_max_tracked`) and
fails closed when full.

**Transport hardening (`http::hardening`).** Outermost layer on both listeners:
64 KiB body ceiling, 30 s handler deadline (the SSE stream is exempt by path —
it is long-lived by design, ADR-0013), and `no-store`, `nosniff`,
`no-referrer`, a deny-all CSP, `X-Frame-Options: DENY`, CORP `same-origin`;
HSTS only when `base_url` is https.

**Graceful drain.** SIGTERM/Ctrl-C flips `/readyz` to 503, stops accepting,
waits up to `shutdown_grace_secs` (default 15) for in-flight requests — bounded,
because open SSE streams never finish — then drops the writer, which flushes and
joins. An orchestrator grace period must exceed this.

**Readiness vs liveness.** `/healthz` (public) stays liveness. `GET /readyz`
(internal listener) is 200 only if not draining, the writer thread still
receives, and the read connection answers `SELECT 1`. A broker with a dead
writer accepts logins it cannot persist; it must leave the load balancer.

**Custody keyring and rotation (`store::crypto`).**
- Sealed value = `0x01 || key_id || nonce || ciphertext`; the header and a
  **context naming the custody row and column** are authenticated, so a
  ciphertext cannot be moved between rows and the key id cannot be flipped.
- The keyfile is a keyring (highest id encrypts, all decrypt). A bare 32-byte
  file is read as key 1, so existing deployments rotate in place.
- `session-broker rotate-key` appends a key atomically (temp file `0600` from
  creation, fsync, rename). On the next boot `Command::Reseal` moves every row
  onto the active key inside the writer's transaction — it cannot interleave
  with a keepalive rotation, which matters because a regressed refresh token is
  an unrecoverable loss of the grant. Unreadable rows are counted and left
  untouched, never rewritten.
- A keyfile with any group/other permission bits is refused at startup.

**Container.** `repo/Dockerfile`: distroless/cc, non-root, state in `/data`
(store and keyfile together — back them up together).

## Consequences

- **Breaking storage format.** Sealed values written before this ADR have no
  header and will not open. There are no production deployments (and the
  project rule is no legacy shims), so existing development databases should be
  deleted. The keyfile itself is compatible.
- Postgres/HA remains unbuilt (ADR-0005): `/readyz` and the drain are per-node
  and make a single node well-behaved, not the service highly available.
- The `/proxy/*` lane (M5b) is still deliberately absent.
