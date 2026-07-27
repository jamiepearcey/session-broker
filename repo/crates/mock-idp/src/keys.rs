//! RSA signing key for `id_token`s, generated in-process at startup.
//!
//! A real IdP rotates keys and publishes several JWKS entries; this fixture
//! needs exactly one, generated once per process and optionally seeded so a
//! broker's test suite can pin `jwks.json` — and therefore golden
//! `id_token`s — across runs.

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
    encoding_key: EncodingKey,
    jwk: Value,
}

impl SigningKey {
    /// Generate a fresh RSA-2048 keypair. `seed` makes the keypair (and
    /// hence every signature) fully reproducible across runs; without it
    /// each process start draws a new key from OS entropy.
    pub fn generate(seed: Option<u64>) -> anyhow::Result<Self> {
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
            "kid": KEY_ID,
            "use": "sig",
            "alg": "RS256",
            "n": n,
            "e": e,
        });

        Ok(Self { encoding_key, jwk })
    }

    /// Sign `claims` as a compact RS256 JWT.
    pub fn sign<T: Serialize>(&self, claims: &T) -> anyhow::Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KEY_ID.to_owned());
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
