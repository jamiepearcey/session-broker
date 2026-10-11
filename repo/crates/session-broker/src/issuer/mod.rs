//! The token issuer's signing core (docs/design/token-issuer.md §1–2, as scoped
//! by token-issuer-scope.md): Ed25519 keys kept in the store, a compact-JWS
//! signer, and the key lifecycle — created at first boot, rotated when an
//! operator asks, removed once nothing signed by them can still be valid.
//!
//! ## Where the keys live
//!
//! In the `signing_key` table, the 32-byte seed sealed under the custody
//! keyring exactly as upstream tokens are (INV-5). So the backup unit is still
//! "database + keyfile", and losing the keyfile loses the signing keys together
//! with the upstream tokens — one recovery story, not two.
//!
//! ## Rotation is an operation, not a schedule
//!
//! Nothing rotates a key by itself. [`Issuer::rotate`] adds a key that starts
//! signing after a publish lead, so verifiers that refresh their key set hourly
//! have it long before a token carries it. A lead of zero is the emergency
//! form: the new key signs at once and every older key stops being published
//! at once, which invalidates outstanding tokens and makes verifiers reject new
//! ones until their next key refresh.
//!
//! ## What does not happen here
//!
//! No verification, no introspection, no revocation list. The broker signs;
//! resource servers verify offline against the published keys.

pub mod jwt;
pub mod keys;

use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Serialize;

use crate::audit::{action, ActorKind, AuditSink, Event, Outcome};
use crate::clock::{Clock, Timestamp};
use crate::store::repo;
use crate::store::writer::{AdminWrite, WriterHandle};
use crate::store::Reader;

use keys::KeyCache;

/// How stale the in-memory keys may get before the next use re-reads the
/// store. This is what lets `session-broker rotate-signing-key`, a separate
/// process, take effect on a running broker without a signal or a restart.
const RELOAD_INTERVAL_SECS: u64 = 60;

/// Added to the longest token lifetime when dating a superseded key, to cover
/// the clock allowance verifiers apply to `exp`.
const RETIRE_MARGIN_SECS: u64 = 300;

/// The two durations key rotation depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPolicy {
    /// How long a new key is published before it signs, unless the rotation
    /// says otherwise.
    pub publish_lead_secs: u64,
    /// The longest lifetime any issued token can have. A superseded key stays
    /// published this long (plus a margin) after its successor takes over.
    pub max_ttl_secs: u64,
}

impl Default for KeyPolicy {
    fn default() -> KeyPolicy {
        KeyPolicy {
            publish_lead_secs: 86_400,
            max_ttl_secs: 86_400,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("signing-key store: {0}")]
    Store(String),
    #[error(
        "no usable signing key: none has activated, or its seed cannot be opened with the \
         keyfile. `session-broker rotate-signing-key --now` creates one."
    )]
    NoSigningKey,
    #[error("claims could not be serialised: {0}")]
    Claims(#[from] serde_json::Error),
}

/// What [`Issuer::rotate`] did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rotation {
    /// The new key.
    pub kid: String,
    /// When it starts signing.
    pub activate_at: i64,
    /// When the keys before it stop being published.
    pub previous_retire_at: i64,
    /// True for a zero-lead rotation: outstanding tokens are already invalid
    /// and verifiers reject new ones until they next refresh their key set.
    pub immediate: bool,
}

/// What the public listener holds of the issuer: the signer and the settings
/// it was configured with.
#[derive(Clone)]
pub struct IssuerHandle {
    pub signer: Arc<Issuer>,
    pub config: Arc<crate::config::IssuerConfig>,
}

pub struct Issuer {
    reader: Arc<Reader>,
    writer: WriterHandle,
    /// `None` only in tests with no audit sink. Production always supplies one:
    /// a signing key is a credential, and INV-13 wants its row.
    audit: Option<AuditSink>,
    clock: Arc<dyn Clock>,
    policy: KeyPolicy,
    cache: RwLock<KeyCache>,
}

impl std::fmt::Debug for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Load the signing keys, creating the first one if the store has none.
///
/// Called once at boot. The key and its `signing_key.created` row commit in one
/// transaction; a second boot finds the key and creates nothing.
pub fn bootstrap(
    reader: Arc<Reader>,
    writer: WriterHandle,
    audit: Option<AuditSink>,
    clock: Arc<dyn Clock>,
    policy: KeyPolicy,
) -> Result<Arc<Issuer>, IssuerError> {
    let issuer = Issuer::open(reader, writer, audit, clock, policy)?;
    let existing = issuer
        .reader
        .with(repo::list_signing_keys)
        .map_err(|e| IssuerError::Store(e.to_string()))?;
    if existing.is_empty() {
        let now = issuer.clock.now();
        let key = keys::generate();
        let kid = key.kid.clone();
        let event = Event::new(
            action::SIGNING_KEY_CREATED,
            Outcome::Success,
            ActorKind::System,
            now,
        )
        .key_id(kid.clone())
        .detail(serde_json::json!({ "activate_at": now.secs() }));
        issuer.write(AdminWrite::InsertSigningKey { key, now }, event)?;
        tracing::info!(target: "broker::keys", kid = %kid, "created the first signing key");
        issuer.reload()?;
    }
    Ok(issuer)
}

impl Issuer {
    /// Load whatever keys the store holds, creating none. [`bootstrap`] is the
    /// boot path; this is for a caller that must not create a key as a side
    /// effect.
    pub fn open(
        reader: Arc<Reader>,
        writer: WriterHandle,
        audit: Option<AuditSink>,
        clock: Arc<dyn Clock>,
        policy: KeyPolicy,
    ) -> Result<Arc<Issuer>, IssuerError> {
        let issuer = Issuer {
            reader,
            writer,
            audit,
            clock,
            policy,
            cache: RwLock::new(KeyCache::default()),
        };
        issuer.reload()?;
        Ok(Arc::new(issuer))
    }

    /// Re-read the keys from the store.
    pub fn reload(&self) -> Result<(), IssuerError> {
        let rows = self
            .reader
            .with(repo::load_signing_keys)
            .map_err(|e| IssuerError::Store(e.to_string()))?;
        let (cache, unusable) = KeyCache::build(rows, self.clock.now());
        for kid in unusable {
            tracing::error!(
                target: "broker::keys",
                kid = %kid,
                "signing key cannot be used: its seed does not open with the keyfile. \
                 It stays published; it cannot sign."
            );
        }
        *self.cache.write().unwrap_or_else(|e| e.into_inner()) = cache;
        Ok(())
    }

    /// Run `f` against keys no older than [`RELOAD_INTERVAL_SECS`].
    fn with_keys<T>(&self, f: impl FnOnce(&KeyCache, Timestamp) -> T) -> T {
        let now = self.clock.now();
        let loaded_at = self
            .cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .loaded_at;
        if loaded_at.is_none_or(|at| now.since(at) >= RELOAD_INTERVAL_SECS) {
            // On failure the keys already in memory keep serving: a store that
            // cannot be read for a moment must not stop tokens being signed.
            if let Err(e) = self.reload() {
                tracing::error!(target: "broker::keys", error = %e, "signing-key reload failed");
            }
        }
        f(&self.cache.read().unwrap_or_else(|e| e.into_inner()), now)
    }

    /// Sign `claims` with the current signing key as a compact JWS.
    ///
    /// The claims are the caller's. This adds only the header
    /// (`alg=EdDSA`, `typ=JWT`, `kid`).
    pub fn sign<C: Serialize>(&self, claims: &C) -> Result<String, IssuerError> {
        self.with_keys(|keys, now| {
            let (kid, key) = keys.signing(now).ok_or(IssuerError::NoSigningKey)?;
            Ok(jwt::encode(kid, key, claims)?)
        })
    }

    /// The `kid` tokens are being signed with right now.
    pub fn signing_kid(&self) -> Option<String> {
        self.with_keys(|keys, now| keys.signing(now).map(|(kid, _)| kid.to_owned()))
    }

    /// The JWK Set (RFC 7517) of every published key, newest first.
    pub fn jwks(&self) -> serde_json::Value {
        self.with_keys(|keys, now| {
            let keys: Vec<serde_json::Value> = keys
                .published(now)
                .map(|row| {
                    serde_json::json!({
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "kid": row.kid,
                        "x": URL_SAFE_NO_PAD.encode(row.public_key),
                        "use": "sig",
                        "alg": jwt::ALG,
                    })
                })
                .collect();
            serde_json::json!({ "keys": keys })
        })
    }

    /// Add a signing key that takes over in `activate_in_secs` (default: the
    /// policy's publish lead).
    ///
    /// Keys before it stay published until the new key has been signing for the
    /// longest token lifetime, so nothing they signed is orphaned. With a lead
    /// of `0` they stop being published now instead — see the module docs.
    ///
    /// `actor_id` is recorded on the `signing_key.rotated` row, which commits
    /// with the key or not at all.
    pub fn rotate(
        &self,
        activate_in_secs: Option<u64>,
        actor_id: &str,
    ) -> Result<Rotation, IssuerError> {
        let now = self.clock.now();
        let lead = activate_in_secs.unwrap_or(self.policy.publish_lead_secs);
        let immediate = lead == 0;
        let activate_at = now.plus_secs(lead);
        let retire_at = if immediate {
            now
        } else {
            activate_at.plus_secs(self.policy.max_ttl_secs.saturating_add(RETIRE_MARGIN_SECS))
        };

        let key = keys::generate();
        let rotation = Rotation {
            kid: key.kid.clone(),
            activate_at: activate_at.secs(),
            previous_retire_at: retire_at.secs(),
            immediate,
        };
        let event = Event::new(
            action::SIGNING_KEY_ROTATED,
            Outcome::Success,
            ActorKind::Admin,
            now,
        )
        .actor_id(actor_id)
        .key_id(rotation.kid.clone())
        .detail(serde_json::json!({
            "activate_at": rotation.activate_at,
            "previous_retire_at": rotation.previous_retire_at,
            "immediate": immediate,
        }));
        self.write(
            AdminWrite::RotateSigningKey {
                key,
                now,
                activate_at,
                retire_at,
            },
            event,
        )?;
        tracing::info!(
            target: "broker::keys",
            kid = %rotation.kid,
            activate_at = rotation.activate_at,
            immediate,
            "signing key rotated"
        );
        self.reload()?;
        Ok(rotation)
    }

    /// Mark every key past its `retire_at` removed. Returns how many.
    ///
    /// Rides the hourly audit-prune timer. A removed key is already unpublished
    /// (publication stops at `retire_at`, by the clock); this only records that
    /// and drops it from memory.
    pub fn prune_retired(&self) -> usize {
        let now = self.clock.now();
        let due = match self
            .reader
            .with(|conn| repo::retired_signing_keys_due(conn, now))
        {
            Ok(due) => due,
            Err(e) => {
                tracing::error!(target: "broker::keys", error = %e, "signing-key prune could not read");
                return 0;
            }
        };
        let mut removed = 0;
        for kid in due {
            let event = Event::new(
                action::SIGNING_KEY_REMOVED,
                Outcome::Success,
                ActorKind::System,
                now,
            )
            .key_id(kid.clone());
            match self.write(
                AdminWrite::RemoveRetiredSigningKey {
                    kid: kid.clone(),
                    now,
                },
                event,
            ) {
                Ok(true) => {
                    removed += 1;
                    tracing::info!(target: "broker::keys", kid = %kid, "retired signing key removed");
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::error!(target: "broker::keys", kid = %kid, error = %e, "signing-key prune failed");
                }
            }
        }
        if removed > 0 {
            if let Err(e) = self.reload() {
                tracing::error!(target: "broker::keys", error = %e, "signing-key reload failed");
            }
        }
        removed
    }

    /// One signing-key mutation with its Tier A row, in one transaction.
    fn write(&self, write: AdminWrite, event: Event) -> Result<bool, IssuerError> {
        let row = self.audit.as_ref().map(|sink| sink.transactional(event));
        self.writer.write_admin_audited(write, row).map_err(|e| {
            if let Some(sink) = &self.audit {
                sink.note_transactional_failure();
            }
            IssuerError::Store(e)
        })
    }
}

#[cfg(test)]
mod tests;
