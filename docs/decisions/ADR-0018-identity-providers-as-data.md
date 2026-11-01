# ADR-0018: Identity providers are data, managed from the admin lane

## Status

Accepted (2026-11-01). **Amends ADR-0001** only in that one upstream provider becomes
several. ADR-0002, 0003, 0007, 0010, 0011 and 0017 stand as written. The rule they share
stays: the broker owns login and upstream tokens, and nothing else holds a client secret
after handing it over.

## Context

An operator should be able to add Entra, Okta or any OpenID Connect provider from a
console without editing config and restarting. Until now the broker built one
`OidcClient` from config at boot, and refused to start without one.

## Decision

**A table and a registry.** `identity_provider` (schema v6) holds id, preset, display name,
issuer, client id, sealed client secret, scopes and enabled. `ProviderRegistry` maps id to
client and is what `/auth/*`, keepalive and the admin lane read. A change installs a new
immutable map. The config-file provider, if configured, is the read-only id `default`.

**Boot.** `default` is discovered at boot, and a failure there still stops the process: that
is a config error, and it is what the deployment already relies on. Store providers connect
on first use, so one IdP being down costs that provider's logins and nothing else. No provider
at all is a valid boot; `/auth/login` answers `503 no_providers`.

**Admin lane.** `GET/POST /admin/providers`, `GET/PUT/DELETE /admin/providers/{id}`,
`POST /admin/providers/test` (discovery only, unsaved), `GET /admin/providers/{id}/people`.
Mutations are Tier A (`provider.created`, `provider.updated`, `provider.deleted`), recording
whether the secret changed and nothing else about it. PUT is a merge: an absent field stays,
so an unchanged secret is an absent field. An empty secret is refused rather than read as
"unchanged". Saving with `enabled: true` runs discovery first, and a failure saves nothing.

**Issuer rules.** https, or http on loopback only, with no credentials, query or fragment.
Discovery must return an `issuer` equal to the configured one byte for byte. This is what
refuses Entra's `common` and `organizations`, whose issuer is a template. Discovery follows no
redirect. Endpoints it advertises are held to the same transport rule, including `jwks_uri`.

**Login.** `GET /auth/providers` lists enabled providers, publicly, for a chooser.
`/auth/login?provider=<id>`; with exactly one enabled the parameter is optional, otherwise
`400 provider_required`. There is one callback. The login transaction records the provider,
server-side, and the callback completes on that provider's client: the browser has no say. An
RFC 9207 `iss`, if present, must match. Transactions live in one store shared by every client,
so replacing a client does not strand a login in flight.

**Disabling and deleting.** A disabled provider starts no login and completes none in flight:
someone disabling a provider because it is compromised does not want one more session from it.
Its existing grants keep renewing, and the ordinary upstream-revoked policy applies if the IdP
refuses (ADR-0011). Deleting destroys the sealed secret and leaves a tombstone; its grants fail
permanently at their next refresh and the same policy applies. A missing `default` is retried
rather than treated as revoked, because a config change can be undone and a kill cannot.

**Client authentication** at the token endpoint, code exchange and refresh alike, comes from
discovery's `token_endpoint_auth_methods_supported`: `client_secret_basic` when listed, and when
the field is absent, which RFC 8414 defines as the same thing; otherwise `client_secret_post`.
This applies to `default` too, which until now always sent post, so a config provider that lists
basic switches to it.

**Key rotation.** An `id_token` naming a key the client does not hold sends it back to `jwks_uri`
and verification is retried on the same token, since the code is already spent. The `kid` is the
caller's to choose, so this happens at most once per five minutes per provider, whether or not
the fetch worked, and is only reachable once issuer and audience have passed. A failed or empty
fetch keeps the keys held. A token still unmatched afterwards is refused.

### Subject collision

Two issuers can both say `sub: 123`, and those are two people. The broker's name for a person
is `<provider_id>|<upstream sub>`. It is decided in one function, `oauth::person_subject`, and
is what the session, custody row, issued token and `user_grant` all carry. `default` keeps the
upstream spelling, so adding a provider changes nobody who already exists.

That spelling makes an id a set of people, and three further rules follow from it, each beyond
what the brief asked for and each closing a way for grants to move to a stranger:

1. **An issuer is fixed once people exist under it.** PUT changing `issuer_url` is
   `409 issuer_locked` once any custody row or grant carries the id. Correcting a typo before
   anyone has signed in still works.
2. **An id cannot come back on another issuer.** DELETE leaves a tombstone. POST of that id is
   allowed on the same issuer and otherwise `409 provider_id_retired`. The same answer applies
   when grants were written ahead of time for an id nobody has registered.
3. **`default` cannot speak for a provider.** Because it keeps the upstream spelling, its
   subject `entra|123` would be provider `entra`'s person 123. Auth0 really does issue subjects
   of this shape. If the part before the first `|` names a provider, that login is refused
   (`subject_collision`).

`default` and `test` are reserved ids. `test` would otherwise be shadowed by the test route.

## Consequences

- Moving people between providers is an explicit act: new grants under the new id.
- Discovery runs on the login path the first time a provider is used after boot. INV-8 is
  untouched: `/session/refresh` still reaches no provider.
- The upstream HTTP client now has a 30-second timeout. With several providers, one hung IdP
  must not hold a keepalive batch containing everyone else's grants.
- `/admin/providers/test` makes the broker fetch a URL of the caller's choosing. It sits behind
  the admin key on the internal listener, like everything else that can mint credentials.
- `user_grant.sub` allows 320 characters: a 63-character id, the separator, OIDC's 255.

## Known limits

- **A rotation inside the five-minute floor waits for it.** If a refetch already ran just before
  an IdP publishes a new key, logins signed with that key fail `invalid_id_token` until the floor
  passes, or the provider is edited or re-enabled, or the broker restarts.
- **The method is chosen per provider, not per client.** An IdP that lists both methods but holds
  this client to post will fail at the code exchange. `private_key_jwt` is not offered.
- **Not run against a real Entra, Okta, Auth0, Google or Keycloak tenant.** The proof is
  `mock-idp` as two providers.
