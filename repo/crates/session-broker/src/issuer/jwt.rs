//! Compact JWS (RFC 7515 §3.1) with `alg=EdDSA`, and nothing else.
//!
//! Hand-written because it is three base64url segments and one signature, and
//! because an encoder that can only emit one algorithm cannot be talked into
//! emitting another. Verification is deliberately absent: the broker issues
//! tokens, resource servers verify them. The tests check this encoder against
//! an independent decoder rather than against itself.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;

/// The only algorithm the broker signs with.
pub const ALG: &str = "EdDSA";
/// Plain `JWT`, as the scope addendum settles it: what every verifier library
/// expects without being told.
pub const TYP: &str = "JWT";

// A struct, not a `json!` map, so the field order on the wire is fixed.
#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    typ: &'static str,
    kid: &'a str,
}

/// `base64url(header) . base64url(claims) . base64url(signature)`, the
/// signature being Ed25519 over the ASCII bytes of the first two segments.
pub fn encode<C: Serialize>(
    kid: &str,
    key: &SigningKey,
    claims: &C,
) -> Result<String, serde_json::Error> {
    let header = serde_json::to_vec(&Header {
        alg: ALG,
        typ: TYP,
        kid,
    })?;
    let mut token = URL_SAFE_NO_PAD.encode(header);
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?));
    let signature = key.sign(token.as_bytes());
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    Ok(token)
}
