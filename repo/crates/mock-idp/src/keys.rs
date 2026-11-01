//! RSA signing key for `id_token`s, generated in-process at startup.
//!
//! A real IdP rotates keys and publishes several JWKS entries; this fixture
//! holds one at a time, optionally seeded so a broker's test suite can pin
//! `jwks.json` — and therefore golden `id_token`s — across runs. A test can
//! replace it through `POST /__test__/rotate-keys`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand::{rngs::StdRng, SeedableRng};
use rsa::{pkcs1::EncodeRsaPrivateKey as _, traits::PublicKeyParts as _, RsaPrivateKey};
use serde::Serialize;
use serde_json::{json, Value};

const RSA_BITS: usize = 2048;

/// Key id published in `jwks.json` and every signed `id_token`'s header.
pub const KEY_ID: &str = "mock-idp-rsa-1";

pub struct SigningKey {
    kid: String,
    encoding_key: EncodingKey,
    jwk: Value,
}

impl SigningKey {
    /// Generate a fresh RSA-2048 keypair. `seed` makes the keypair (and
    /// hence every signature) fully reproducible across runs; without it
    /// each process start draws a new key from OS entropy.
    pub fn generate(seed: Option<u64>) -> anyhow::Result<Self> {
        Self::generate_with_kid(seed, KEY_ID)
    }

    /// As [`SigningKey::generate`], under a key id of the caller's choosing.
    pub fn generate_with_kid(seed: Option<u64>, kid: &str) -> anyhow::Result<Self> {
        let private_key = match seed {
            Some(seed) => RsaPrivateKey::new(&mut StdRng::seed_from_u64(seed), RSA_BITS)?,
            None => RsaPrivateKey::new(&mut rand::rngs::OsRng, RSA_BITS)?,
        };
        let public_key = private_key.to_public_key();
        let der = private_key.to_pkcs1_der()?;
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());

        let n = b64(&public_key.n().to_bytes_be());
        let e = b64(&public_key.e().to_bytes_be());
        let jwk = json!({
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": n,
            "e": e,
        });

        Ok(Self {
            kid: kid.to_owned(),
            encoding_key,
            jwk,
        })
    }

    /// Sign `claims` as a compact RS256 JWT.
    pub fn sign<T: Serialize>(&self, claims: &T) -> anyhow::Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        Ok(jsonwebtoken::encode(&header, claims, &self.encoding_key)?)
    }

    /// The `{"keys": [...]}` document served at `/jwks.json`.
    pub fn jwks_document(&self) -> Value {
        json!({ "keys": [self.jwk.clone()] })
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
