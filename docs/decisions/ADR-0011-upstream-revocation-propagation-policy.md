# ADR-0011: Upstream-Revocation Propagation Policy (`kill` Default) and Custody Health via the Meta Cookie

## Status

Accepted (2026-07-26)

## Context

The keepalive worker (ADR-0003) can hit a **permanent** upstream failure
(`invalid_grant` — the refresh token was revoked, expired, or already
consumed). This is qualitatively different from a transient failure: it means
the upstream IdP has ended the grant, often as an administrative action (an
admin disabled the user, the user revoked consent, a security team forced
reauth). One custody record can back several sessions — same user, multiple
device logins are one custody per login (resolved question 4), but nothing
stops several sessions sharing a custody in other flows. A decision is needed
on what a dead custody does to the sessions riding on it, and how that state
becomes visible.

## Decision

`on_upstream_revoked` is a static, deployment-wide policy, **default
`kill`**: on permanent upstream failure, all sessions referencing that
custody are tombstoned, reusing the ADR-0010/INV-7 atomic-tombstone
machinery. Rationale: upstream revocation is an administrative security
action and must be able to propagate — a broker that let sessions outlive an
IdP-side ban would be a way around that ban, not a caching layer in front of
it.

`degrade` is available as an opt-in alternative: sessions stay alive for
broker-local auth, with `custody: "dead"` surfaced in the meta cookie
(ADR-0009 — a hint only). This exists for deployments where the broker
session is the product in its own right and upstream calls are incidental to
it.

Custody health (`ok | degraded | dead`) is exposed in `broker_meta.custody`
for UI purposes; it carries no authority — the actual behavioral gate is
server-side (`/proxy` and `/internal/token` return `upstream_revoked`-flavored
errors once custody is dead or degraded past `access_exp`, independent of
session `status`).

## Alternatives considered

- **Always `degrade`, never force logout on upstream revocation.** Rejected
  as the default: it would let a broker-local session survive an
  administrative IdP-side revocation indefinitely, defeating the purpose of
  the upstream provider being the identity authority.
- **Always `kill`, no `degrade` option.** Rejected as too rigid: some
  deployments genuinely want the broker session to be authoritative on its
  own (e.g. upstream is used only for initial identity, not ongoing
  authorization) and forcing a hard logout on any upstream hiccup would be
  the wrong trade for them.
- **Per-session policy** rather than deployment-wide. Rejected: adds
  configuration surface and a place for inconsistent behavior within one
  deployment for no demonstrated need; an operator wanting mixed policies can
  run two broker instances instead.

## Consequences

- Because one custody can back multiple sessions, `kill` affects all of them
  simultaneously — a single upstream revocation can end several device
  sessions for a user at once. This is documented behavior, not a bug, but is
  surprising if an operator hasn't internalized the custody/session
  relationship.
- Under `degrade`, a session can sit `ACTIVE` (local auth fine) while every
  upstream-dependent surface (`/proxy`, `/internal/token`) fails with
  `upstream_revoked` — a split-brain-looking state that must be documented
  for downstream consumers, not just for operators.
- The policy is static config, not runtime-adjustable per session — changing
  posture requires a config change and restart (or reload, if supported),
  not an API call.
- Custody-health-in-meta (ADR-0009) means the client can show "reconnecting"
  UX proactively, but a compromised or stale client value must never be
  trusted for the actual gating decision — that stays server-side.
