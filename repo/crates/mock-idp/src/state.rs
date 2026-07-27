//! In-memory state shared across every route: registered clients/users, the
//! signing key, every issued code/token, and the runtime-tunable knobs the
//! `/__test__` control surface flips.
//!
//! Everything lives behind one `std::sync::Mutex<Inner>`. Handlers never
//! `.await` while holding the guard, so a plain (non-async) mutex is the
//! simplest correct choice — there is no lock-order or contention story to
//! manage for a single-process test fixture.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{config::MockIdpConfig, keys::SigningKey};

#[derive(Debug, Clone)]
pub struct ClientRecord {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserRecord {
    pub subject: String,
    pub email: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub subject: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub expires_at: i64,
    pub used: bool,
}

/// Why `redeem_auth_code` refused a code — mapped 1:1 onto an
/// `invalid_grant` description by the `/token` handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCodeError {
    NotFound,
    AlreadyUsed,
    Expired,
    ClientMismatch,
    RedirectUriMismatch,
    PkceMismatch,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessTokenRecord {
    pub subject: String,
    pub client_id: String,
    pub scope: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefreshTokenRecord {
    pub subject: String,
    pub client_id: String,
    pub scope: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

/// Outcome of a successful refresh grant: the caller-facing refresh token
/// value, which may or may not be the one that was presented depending on
/// `rotate_refresh_tokens`.
pub struct RefreshGrant {
    pub subject: String,
    pub scope: String,
    pub refresh_token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshError {
    NotFound,
    Revoked,
    Expired,
}

/// Runtime-tunable behaviour, mutated only through `POST /__test__/config`.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeConfig {
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub rotate_refresh_tokens: bool,
    pub token_latency_ms: u64,
}

/// Partial update accepted by `POST /__test__/config`; any field left out
/// keeps its current value.
#[derive(Debug, Deserialize, Default)]
pub struct RuntimeConfigPatch {
    pub access_token_ttl_secs: Option<u64>,
    pub refresh_token_ttl_secs: Option<u64>,
    pub rotate_refresh_tokens: Option<bool>,
    pub token_latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Counters {
    pub authorize_calls: u64,
    pub token_calls_total: u64,
    pub token_calls_by_grant: HashMap<String, u64>,
    pub userinfo_calls: u64,
    pub revoke_calls: u64,
}

/// A queued instruction to make the next N `/token` calls fail, for
/// exercising the broker's retry/backoff behaviour against a flaky/down
/// upstream without needing a real one.
#[derive(Debug, Clone)]
pub struct FailNext {
    pub remaining: u32,
    pub status: u16,
    pub error: String,
    pub error_description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientSummary {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenSummary {
    pub token: String,
    pub subject: String,
    pub client_id: String,
    pub scope: String,
    pub issued_at: i64,
    pub expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
}

/// Full state dump served at `GET /__test__/state`, including the counters
/// a broker's tests assert on to prove the fast refresh path never calls
/// out to `/token`.
#[derive(Debug, Serialize)]
pub struct StateSnapshot {
    pub base_url: String,
    pub runtime: RuntimeConfig,
    pub users: Vec<UserRecord>,
    pub clients: Vec<ClientSummary>,
    pub issued_access_tokens: Vec<TokenSummary>,
    pub issued_refresh_tokens: Vec<TokenSummary>,
    pub counters: Counters,
    pub pending_fail_next: Option<u32>,
}

pub struct AppState {
    pub base_url: String,
    pub signing_key: SigningKey,
    pub authorization_code_ttl_secs: u64,
    pub clients: HashMap<String, ClientRecord>,
    pub users: Vec<UserRecord>,
    inner: Mutex<Inner>,
}

struct Inner {
    runtime: RuntimeConfig,
    auth_codes: HashMap<String, AuthCode>,
    access_tokens: HashMap<String, AccessTokenRecord>,
    refresh_tokens: HashMap<String, RefreshTokenRecord>,
    counters: Counters,
    fail_next: Option<FailNext>,
}

impl AppState {
    pub fn new(config: MockIdpConfig, base_url: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !config.clients.is_empty(),
            "mock-idp needs at least one registered client"
        );
        anyhow::ensure!(
            !config.users.is_empty(),
            "mock-idp needs at least one canned user"
        );

        let clients = config
            .clients
            .iter()
            .map(|c| {
                (
                    c.client_id.clone(),
                    ClientRecord {
                        client_id: c.client_id.clone(),
                        client_secret: c.client_secret.clone(),
                        redirect_uris: c.redirect_uris.clone(),
                    },
                )
            })
            .collect();
        let users = config
            .users
            .iter()
            .map(|u| UserRecord {
                subject: u.subject.clone(),
                email: u.email.clone(),
                name: u.name.clone(),
            })
            .collect();

        Ok(Self {
            base_url,
            signing_key: SigningKey::generate(config.rsa_seed)?,
            authorization_code_ttl_secs: config.authorization_code_ttl_secs,
            clients,
            users,
            inner: Mutex::new(Inner {
                runtime: RuntimeConfig {
                    access_token_ttl_secs: config.access_token_ttl_secs,
                    refresh_token_ttl_secs: config.refresh_token_ttl_secs,
                    rotate_refresh_tokens: config.rotate_refresh_tokens,
                    token_latency_ms: 0,
                },
                auth_codes: HashMap::new(),
                access_tokens: HashMap::new(),
                refresh_tokens: HashMap::new(),
                counters: Counters::default(),
                fail_next: None,
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // Recover from poisoning rather than panicking the next request: a
        // panic inside one handler shouldn't wedge every other test using
        // the same fixture instance.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn find_user(&self, subject: &str) -> Option<UserRecord> {
        self.users.iter().find(|u| u.subject == subject).cloned()
    }

    /// The user `/authorize` logs in as when `login_as` is omitted.
    pub fn default_user(&self) -> &UserRecord {
        &self.users[0] // non-empty is an invariant enforced in `new`
    }

    pub fn find_client(&self, client_id: &str) -> Option<&ClientRecord> {
        self.clients.get(client_id)
    }

    pub fn runtime_config(&self) -> RuntimeConfig {
        self.lock().runtime.clone()
    }

    pub fn patch_runtime_config(&self, patch: RuntimeConfigPatch) -> RuntimeConfig {
        let mut inner = self.lock();
        if let Some(v) = patch.access_token_ttl_secs {
            inner.runtime.access_token_ttl_secs = v;
        }
        if let Some(v) = patch.refresh_token_ttl_secs {
            inner.runtime.refresh_token_ttl_secs = v;
        }
        if let Some(v) = patch.rotate_refresh_tokens {
            inner.runtime.rotate_refresh_tokens = v;
        }
        if let Some(v) = patch.token_latency_ms {
            inner.runtime.token_latency_ms = v;
        }
        inner.runtime.clone()
    }

    pub fn store_auth_code(&self, code: String, record: AuthCode) {
        self.lock().auth_codes.insert(code, record);
    }

    /// Validate and, on success, consume an authorization code in one
    /// atomic step (including the PKCE check) so a racing double-redeem
    /// can never observe the code as still-unused twice.
    ///
    /// A code that fails validation is deliberately left unconsumed: only
    /// a *complete, successful* redemption marks it single-use, so a client
    /// that retries after fixing a transient mistake (e.g. the wrong
    /// `code_verifier` typo) isn't punished for the failed attempt.
    pub fn redeem_auth_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: &str,
        now: i64,
    ) -> Result<AuthCode, AuthCodeError> {
        let mut inner = self.lock();
        let record = inner.auth_codes.get(code).ok_or(AuthCodeError::NotFound)?;
        if record.used {
            return Err(AuthCodeError::AlreadyUsed);
        }
        // `<=`, not `<`: TTLs are second-granularity here, so an equal
        // timestamp means "at or past expiry", not "still has this whole
        // second left".
        if record.expires_at <= now {
            return Err(AuthCodeError::Expired);
        }
        if record.client_id != client_id {
            return Err(AuthCodeError::ClientMismatch);
        }
        if record.redirect_uri != redirect_uri {
            return Err(AuthCodeError::RedirectUriMismatch);
        }
        if !pkce_s256_matches(code_verifier, &record.code_challenge) {
            return Err(AuthCodeError::PkceMismatch);
        }
        let record = record.clone();
        inner
            .auth_codes
            .get_mut(code)
            .expect("just looked up under the same lock")
            .used = true;
        Ok(record)
    }

    pub fn issue_access_token(
        &self,
        subject: &str,
        client_id: &str,
        scope: &str,
        now: i64,
    ) -> (String, i64) {
        let mut inner = self.lock();
        let ttl = inner.runtime.access_token_ttl_secs as i64;
        let token = new_opaque_token("at");
        let expires_at = now + ttl;
        inner.access_tokens.insert(
            token.clone(),
            AccessTokenRecord {
                subject: subject.to_owned(),
                client_id: client_id.to_owned(),
                scope: scope.to_owned(),
                issued_at: now,
                expires_at,
            },
        );
        (token, ttl)
    }

    pub fn issue_refresh_token(
        &self,
        subject: &str,
        client_id: &str,
        scope: &str,
        now: i64,
    ) -> String {
        let mut inner = self.lock();
        let ttl = inner.runtime.refresh_token_ttl_secs as i64;
        let token = new_opaque_token("rt");
        inner.refresh_tokens.insert(
            token.clone(),
            RefreshTokenRecord {
                subject: subject.to_owned(),
                client_id: client_id.to_owned(),
                scope: scope.to_owned(),
                issued_at: now,
                expires_at: now + ttl,
                revoked: false,
            },
        );
        token
    }

    pub fn lookup_access_token(&self, token: &str) -> Option<AccessTokenRecord> {
        self.lock().access_tokens.get(token).cloned()
    }

    /// Validate a presented refresh token and issue a fresh access token
    /// grant, atomically applying the configured rotation policy: when
    /// `rotate_refresh_tokens` is set the old token is invalidated and a
    /// new one minted, otherwise the same token remains valid and is
    /// echoed back unchanged.
    pub fn refresh_grant(
        &self,
        presented_token: &str,
        client_id: &str,
        now: i64,
    ) -> Result<RefreshGrant, RefreshError> {
        let mut inner = self.lock();
        let record = inner
            .refresh_tokens
            .get(presented_token)
            .ok_or(RefreshError::NotFound)?
            .clone();
        if record.revoked {
            return Err(RefreshError::Revoked);
        }
        if record.expires_at <= now {
            return Err(RefreshError::Expired);
        }
        if record.client_id != client_id {
            // Don't distinguish "wrong client" from "unknown token" in the
            // error shape — both are `invalid_grant` to the caller.
            return Err(RefreshError::NotFound);
        }

        let refresh_token = if inner.runtime.rotate_refresh_tokens {
            inner.refresh_tokens.remove(presented_token);
            let ttl = inner.runtime.refresh_token_ttl_secs as i64;
            let new_token = new_opaque_token("rt");
            inner.refresh_tokens.insert(
                new_token.clone(),
                RefreshTokenRecord {
                    subject: record.subject.clone(),
                    client_id: record.client_id.clone(),
                    scope: record.scope.clone(),
                    issued_at: now,
                    expires_at: now + ttl,
                    revoked: false,
                },
            );
            new_token
        } else {
            presented_token.to_owned()
        };

        Ok(RefreshGrant {
            subject: record.subject,
            scope: record.scope,
            refresh_token,
        })
    }

    /// `POST /__test__/expire`: force every live access/refresh token
    /// belonging to `subject` into the past. Returns how many were
    /// affected.
    pub fn force_expire_subject(&self, subject: &str, now: i64) -> usize {
        let mut inner = self.lock();
        let mut count = 0;
        for record in inner.access_tokens.values_mut() {
            if record.subject == subject && record.expires_at > now {
                record.expires_at = now - 1;
                count += 1;
            }
        }
        for record in inner.refresh_tokens.values_mut() {
            if record.subject == subject && record.expires_at > now {
                record.expires_at = now - 1;
                count += 1;
            }
        }
        count
    }

    /// `POST /__test__/revoke-refresh`: revoke every live refresh token
    /// belonging to `subject`. Returns how many were affected.
    pub fn revoke_refresh_for_subject(&self, subject: &str) -> usize {
        let mut inner = self.lock();
        let mut count = 0;
        for record in inner.refresh_tokens.values_mut() {
            if record.subject == subject && !record.revoked {
                record.revoked = true;
                count += 1;
            }
        }
        count
    }

    /// `POST /revoke` (RFC 7009): revoke a token by its literal value,
    /// whichever kind it turns out to be. Unknown values are a no-op —
    /// callers get 200 either way, per the RFC's guidance not to leak
    /// whether a token exists.
    pub fn revoke_token_value(&self, token: &str) {
        let mut inner = self.lock();
        if let Some(record) = inner.refresh_tokens.get_mut(token) {
            record.revoked = true;
        }
        if let Some(record) = inner.access_tokens.get_mut(token) {
            record.expires_at = 0;
        }
    }

    pub fn queue_fail_next(&self, fail: FailNext) {
        self.lock().fail_next = Some(fail);
    }

    /// Consume one unit of a pending `/__test__/fail-next` instruction, if
    /// any is queued.
    pub fn take_fail_next(&self) -> Option<(u16, String, Option<String>)> {
        let mut inner = self.lock();
        let fail = inner.fail_next.as_mut()?;
        let outcome = (
            fail.status,
            fail.error.clone(),
            fail.error_description.clone(),
        );
        fail.remaining -= 1;
        if fail.remaining == 0 {
            inner.fail_next = None;
        }
        Some(outcome)
    }

    pub fn record_authorize_call(&self) {
        self.lock().counters.authorize_calls += 1;
    }

    pub fn record_token_call(&self, grant_type: &str) {
        let mut inner = self.lock();
        inner.counters.token_calls_total += 1;
        *inner
            .counters
            .token_calls_by_grant
            .entry(grant_type.to_owned())
            .or_insert(0) += 1;
    }

    pub fn record_userinfo_call(&self) {
        self.lock().counters.userinfo_calls += 1;
    }

    pub fn record_revoke_call(&self) {
        self.lock().counters.revoke_calls += 1;
    }

    pub fn snapshot(&self) -> StateSnapshot {
        let inner = self.lock();
        StateSnapshot {
            base_url: self.base_url.clone(),
            runtime: inner.runtime.clone(),
            users: self.users.clone(),
            clients: self
                .clients
                .values()
                .map(|c| ClientSummary {
                    client_id: c.client_id.clone(),
                    redirect_uris: c.redirect_uris.clone(),
                })
                .collect(),
            issued_access_tokens: inner
                .access_tokens
                .iter()
                .map(|(token, r)| TokenSummary {
                    token: token.clone(),
                    subject: r.subject.clone(),
                    client_id: r.client_id.clone(),
                    scope: r.scope.clone(),
                    issued_at: r.issued_at,
                    expires_at: r.expires_at,
                    revoked: None,
                })
                .collect(),
            issued_refresh_tokens: inner
                .refresh_tokens
                .iter()
                .map(|(token, r)| TokenSummary {
                    token: token.clone(),
                    subject: r.subject.clone(),
                    client_id: r.client_id.clone(),
                    scope: r.scope.clone(),
                    issued_at: r.issued_at,
                    expires_at: r.expires_at,
                    revoked: Some(r.revoked),
                })
                .collect(),
            counters: inner.counters.clone(),
            pending_fail_next: inner.fail_next.as_ref().map(|f| f.remaining),
        }
    }
}

/// Wall-clock seconds since the epoch, used for all TTL bookkeeping. A mock
/// fixture has no need for a mockable clock beyond `/__test__/expire`,
/// which sidesteps time entirely by rewriting `expires_at` directly.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64
}

/// A random opaque token value. Deliberately not a JWT: access and refresh
/// tokens are server-tracked strings so `/__test__` can expire/revoke them
/// by simple lookup, without needing to mint and verify signed tokens for
/// pure bookkeeping.
pub(crate) fn new_opaque_token(prefix: &str) -> String {
    format!("{prefix}_{}", uuid::Uuid::new_v4().simple())
}

fn pkce_s256_matches(code_verifier: &str, code_challenge: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest) == code_challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_known_rfc7636_vector() {
        // From RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(pkce_s256_matches(verifier, challenge));
        assert!(!pkce_s256_matches("wrong-verifier", challenge));
    }
}
