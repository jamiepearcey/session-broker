# ADR-0001: Session Broker, Not IdP — Scope Boundary and Non-Goals

## Status

Accepted (2026-07-26)

## Context

The field splits into IdPs (Ory Kratos, Keycloak, Authentik, Zitadel, Pocket ID)
and auth proxies (oauth2-proxy, Authelia, Tinyauth). Neither group ships the
specific triple this project needs: rotation that is deliberately
non-invalidating, stateful background keepalive decoupling session TTL from
upstream token TTL, and sub-millisecond local refresh. Building all of IdP
functionality (users, passwords, consent, credential stores) or a general
authorization engine would dwarf that triple and duplicate mature software.

## Decision

`session-broker` is a self-hosted token custodian between a browser SPA and an
upstream OIDC provider. It owns exactly three problems:

1. Session continuity without races (non-invalidating generation rotation,
   ADR-0002).
2. Local-only fast refresh, decoupled from upstream token lifetime (ADR-0003).
3. Upstream token custody as a product surface — backends and a minimal proxy
   lane get the token, the browser never does (ADR-0007).

It is explicitly **not**: an IdP (no users, passwords, consent, or credential
storage — it delegates identity entirely to an upstream OIDC provider); an
authorization engine (no RBAC, no policy evaluation — `sub` and upstream scopes
pass through, nothing more); a general reverse proxy (the proxy lane injects one
header and forwards; no path rewriting, no response caching, no protocol
translation); and not multi-tenant (one broker instance serves one upstream
IdP configuration and one set of proxy targets).

## Alternatives considered

- **Build a minimal IdP** (own user store, password/passkey login). Rejected:
  duplicates functionality mature open-source IdPs already provide well, and
  every hour spent there is not spent on the rotation/keepalive triple that is
  the actual gap.
- **Extend an existing auth proxy** (oauth2-proxy, Authelia) rather than build
  new. Rejected: the coupling of cookie refresh to synchronous upstream token
  refresh is architectural in those projects, not a config option — fixing it
  means rewriting their session core, at which point starting fresh with the
  non-invalidating model as the foundation is cleaner.
- **Add an authorization layer** (RBAC/policy) so the broker is a one-stop auth
  service. Rejected: conflates two different lifecycles (authentication session
  vs. authorization policy) and turns a ~1.6k-line focused service into a
  general platform; policy belongs upstream or in the resource servers.
- **Multi-tenant broker** (many upstream IdPs / many apps behind one instance).
  Rejected for v1: every invariant and the storage model (§5) assume a single
  trust zone; multi-tenancy is a different product with different isolation
  requirements, not a flag.

## Consequences

- Every deployment needs a working upstream OIDC provider; the broker cannot
  function standalone. This is a hard dependency, not a fallback path.
- No authorization decisions can be made in the broker — consumers needing
  RBAC/ABAC must implement it downstream of `sub`/scope claims.
- The proxy lane (ADR-0007) is deliberately weak as a proxy — consumers needing
  request rewriting, caching, or multi-backend routing need a real reverse
  proxy in front of or behind the broker.
- Running the same upstream IdP behind several unrelated apps means several
  broker instances, each with its own store — this is intentional (ADR-0012)
  but is an operational cost some deployments will find unwelcome.
- Scope discipline must be maintained under feature pressure: every future
  ADR that proposes new functionality should be checked against this boundary
  before being accepted.
