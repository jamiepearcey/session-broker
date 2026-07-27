# Project Brief

## What this project is

`session-broker` is a small (~1-2k line) self-hosted Rust service that brokers
browser sessions against an upstream OAuth2/OIDC identity provider, and takes
custody of the upstream tokens on the user's behalf.

It is deliberately **not** an identity provider: it has no user store, no
credential handling, no admin console, no SAML/LDAP. It federates to whatever
IdP the deployment already has and owns exactly one thing — the browser session
and the OAuth tokens behind it.

## What problem it solves

Front-end auth today forces a bad choice: either deploy a full identity platform
(Keycloak, Ory, Zitadel) to get session management, or bolt a proxy
(oauth2-proxy, Authelia) in front of the app and inherit its session model. The
proxies handle login simply but get the *refresh* path wrong: cookie lifetime is
coupled to upstream token lifetime, refresh hits the IdP on the hot path, and
concurrent requests race during rotation.

## What is innovative or distinctive

Three properties, in priority order:

1. **Non-invalidating rotation.** Issuing a new session cookie does not
   invalidate the old one; generations overlap for a grace period. This removes
   the refresh race class outright rather than coordinating around it.
2. **Local-only fast refresh.** Session lifetime is decoupled from upstream token
   lifetime. A stateful background worker keeps provisioned upstream tokens warm,
   so the refresh endpoint never calls the IdP and answers in microseconds.
3. **Server-side guarantees, dumb client.** Because the server tolerates races,
   the React SDK needs no BroadcastChannel, no SharedWorker, no heartbeats — just
   a single-flight interceptor, a meta cookie, and one Web Lock for leader election.

## Who it is for

Teams running an SPA against an existing IdP who want correct session handling
without operating an identity platform.

## Boundaries

- Upstream IdP: any OAuth2/OIDC provider supporting authorization-code + PKCE.
- Downstream: the broker exposes the current upstream access token to the app's
  own backend; it is not a general API gateway.
- Related internal projects: `security/iam` (the full IdP platform — a possible
  *upstream* for this broker, not a competitor) and `security/secrets-keeper`
  (secrets custody; shares the dependency posture set out in its ADR-0002).
