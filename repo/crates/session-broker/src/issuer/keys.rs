//! Signing-key material and the in-memory view of the `signing_key` table.
//!
//! A key has no stored state. Where the clock stands against its three
//! timestamps is the state:
//!
//! * **pending** — `activate_at` is still ahead. Published, not signing. This is
//!   the publish lead: verifiers learn the key before any token carries it.
//! * **signing** — the newest key that has activated and has not reached its
//!   `retire_at`.
//! * **published** — not removed and not past `retire_at`. Pending keys, the
//!   signing key, and superseded keys whose tokens may still be in flight.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::clock::Timestamp;
use crate::store::repo::{self, NewSigningKey, SigningKeyRow};

/// `base64url(SHA-256(public_key)[..8])`: derived from the key itself, so two
/// different keys cannot be given the same id and a kid cannot be chosen.
pub fn kid_of(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(&Sha256::digest(public_key)[..8])
}

/// A fresh Ed25519 key. The seed comes from the same OS CSPRNG as every other
/// secret in the broker (`token::fill_random`).
pub(crate) fn generate() -> NewSigningKey {
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    crate::token::fill_random(seed.as_mut_slice());
    let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    NewSigningKey {
        kid: kid_of(&public_key),
        public_key,
        seed,
    }
}

pub(crate) struct CachedKey {
    pub(crate) row: SigningKeyRow,
    /// `None` when the seed would not open under any key in the keyfile, or did
    /// not match the stored public key. Such a key is still published; it just
    /// cannot sign.
    pub(crate) signing: Option<SigningKey>,
}

impl CachedKey {
    fn published(&self, now: Timestamp) -> bool {
        self.row.removed_at.is_none() && self.row.retire_at.is_none_or(|at| at > now)
    }
}

/// Every key not yet removed, newest first (the order `load_signing_keys`
/// returns them in).
#[derive(Default)]
pub(crate) struct KeyCache {
    keys: Vec<CachedKey>,
    /// When the store was last read. `None` before the first load.
    pub(crate) loaded_at: Option<Timestamp>,
}

impl KeyCache {
    /// Returns the cache and the kids whose seeds were unusable.
    pub(crate) fn build(
        rows: Vec<(SigningKeyRow, repo::OpenedSeed)>,
        now: Timestamp,
    ) -> (KeyCache, Vec<String>) {
        let mut unusable = Vec::new();
        let keys = rows
            .into_iter()
            .map(|(row, seed)| {
                let signing = seed
                    .map(|seed| SigningKey::from_bytes(&seed))
                    // A seed that opens but belongs to a different public key
                    // would sign tokens no verifier accepts.
                    .filter(|key| key.verifying_key().to_bytes() == row.public_key);
                if signing.is_none() {
                    unusable.push(row.kid.clone());
                }
                CachedKey { row, signing }
            })
            .collect();
        (
            KeyCache {
                keys,
                loaded_at: Some(now),
            },
            unusable,
        )
    }

    /// The key that signs at `now`.
    pub(crate) fn signing(&self, now: Timestamp) -> Option<(&str, &SigningKey)> {
        self.keys
            .iter()
            .filter(|k| k.row.activate_at <= now && k.published(now))
            .find_map(|k| Some((k.row.kid.as_str(), k.signing.as_ref()?)))
    }

    /// Test seam: the seeds held in memory, to prove they are nowhere else.
    #[cfg(test)]
    pub(crate) fn seeds(&self) -> Vec<[u8; 32]> {
        self.keys
            .iter()
            .filter_map(|k| Some(k.signing.as_ref()?.to_bytes()))
            .collect()
    }

    /// What a verifier should be able to fetch at `now`.
    pub(crate) fn published(&self, now: Timestamp) -> impl Iterator<Item = &SigningKeyRow> {
        self.keys
            .iter()
            .filter(move |k| k.published(now))
            .map(|k| &k.row)
    }
}
