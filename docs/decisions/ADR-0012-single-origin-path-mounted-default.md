# ADR-0012: Single-Origin Path-Mounted Deployment as the Default Topology; CORS/Subdomain Mode Deferred

## Status

Accepted (2026-07-26)

## Context

The broker can be deployed either path-mounted on the SPA's own origin behind
a reverse proxy (`/auth/*`, `/session/*`, `/proxy/*`), or as a separate
subdomain (`auth.example.com`) — the pattern many IdPs default to. A subdomain
deployment requires CORS with `credentials: true`, which is a materially
different — and larger — attack surface than same-origin: a misconfigured
allowlist there grants cross-origin credentialed access, whereas same-origin
deployment has no CORS surface to misconfigure at all. The CSRF model
(INV-2/ADR-0004) is also simplest and strongest when everything is same-origin.

## Decision

**Default topology: single-origin, path-mounted** (INV-10). No CORS surface
exists in this mode. Subdomain mode is a **documented, explicitly opt-in**
option requiring an explicit CORS allowlist with `credentials: true` —
off by default (resolved question 5: deferred, not built into v1).

## Alternatives considered

- **Subdomain-first, matching common IdP convention.** Rejected as the
  default: it forces CORS-with-credentials on by default for every
  deployment, trading a class of misconfiguration risk (broken or overly
  broad allowlist exposing credentialed cross-origin access) for topology
  convenience that path-mounting behind a reverse proxy provides without that
  risk.
- **Support both with no stated default.** Rejected: every deployment would
  then have to make an explicit, informed topology decision with no safe
  starting point; a stated default that is also the more conservative option
  is strictly better guidance.
- **CORS mode always on, allowlist-empty-by-default (fail closed).**
  Considered as a middle ground but rejected as unnecessary complexity: if
  subdomain mode isn't the default, there's no benefit to building its CORS
  machinery into the always-on request path; it can be a mode the config
  enables, not infrastructure carried by every deployment regardless of use.

## Consequences

- Deployments needing the broker shared across multiple, genuinely distinct
  app origins must explicitly opt into subdomain mode and take on CORS
  allowlist configuration and its risks — this is a deliberate friction, not
  an oversight; INV-10 is designed to make the safe path the easy path and
  the riskier path a conscious choice.
- The default deployment story has a hard dependency on reverse-proxy
  path-mount configuration (`/auth/*`, `/session/*`, `/proxy/*` routed to the
  broker on the app's own origin) — this becomes required documentation and
  a first-class part of the "getting started" story, not an afterthought.
- A fully separate, shared-broker-across-many-unrelated-origins architecture
  is explicitly not the default-supported shape (consistent with ADR-0001's
  single-trust-zone, non-multi-tenant scope) — such deployments need the
  deferred subdomain mode and accept its larger CORS surface knowingly.
