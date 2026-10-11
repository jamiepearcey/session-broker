//! `docs/verifier/vectors.json`: tokens a verifier can be tested against, and
//! the verdict each one must get.
//!
//! The file is generated here, from a fixed TEST-ONLY seed, and this test fails
//! if the committed copy differs from what the code produces. Ed25519 signing
//! is deterministic, so a diff means a claim, a header or the signer changed,
//! which is exactly when verifier authors need to hear about it.
//!
//! Regenerate with `UPDATE_VECTORS=1 cargo test -p session-broker vectors`.
//!
//! The vectors are also run through a small reference verifier written from
//! `docs/verifier/README.md`, so the verdicts in the file are checked against
//! the rules the README states rather than asserted by hand.

use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
use serde::Serialize;
use serde_json::{json, Value};

use super::jwt;
use super::keys::kid_of;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// Exactly 32 bytes of ASCII. A test key: it signs nothing but these vectors,
/// and anyone can read it here, so it must never be loaded into a broker.
const TEST_SEED: &[u8; 32] = b"session-broker/test-vectors/seed";

const ISSUER: &str = "https://broker.example.test";
const AUDIENCE: &str = "logless";
/// How far either side of `exp`/`iat` a verifier forgives.
const ALLOWANCE: i64 = 300;
/// Every vector token is issued at this instant.
const IAT: i64 = 1_790_000_000;
const MACHINE_TTL: i64 = 86_400;
const USER_TTL: i64 = 3_600;

/// Field order is the wire order, as in `http::token`.
#[derive(Serialize, Clone)]
struct MachineClaims {
    iss: &'static str,
    sub: &'static str,
    aud: &'static str,
    exp: i64,
    iat: i64,
    jti: &'static str,
    tenant: &'static str,
    kind: &'static str,
    name: &'static str,
    scopes: Vec<&'static str>,
    indexes: Vec<&'static str>,
}

/// Field order is the wire order, as in `http::user_token`.
#[derive(Serialize, Clone)]
struct UserClaims {
    iss: &'static str,
    sub: &'static str,
    sid: &'static str,
    aud: &'static str,
    exp: i64,
    iat: i64,
    jti: &'static str,
    kind: &'static str,
    tenant: &'static str,
    roles: Vec<&'static str>,
    indexes: Vec<&'static str>,
}

fn machine() -> MachineClaims {
    MachineClaims {
        iss: ISSUER,
        sub: "sp_a1b2c3d4e5f6g7h8",
        aud: AUDIENCE,
        exp: IAT + MACHINE_TTL,
        iat: IAT,
        jti: "AAAAAAAAAAAAAAAAAAAAAA",
        tenant: "acme",
        kind: "ingest",
        name: "edge-1",
        scopes: vec!["ingest"],
        indexes: vec!["default"],
    }
}

fn user() -> UserClaims {
    UserClaims {
        iss: ISSUER,
        sub: "auth0|user-42",
        sid: "sid_0123456789abcdef",
        aud: AUDIENCE,
        exp: IAT + USER_TTL,
        iat: IAT,
        jti: "BBBBBBBBBBBBBBBBBBBBBB",
        kind: "user",
        tenant: "acme",
        roles: vec!["viewer"],
        indexes: vec!["*"],
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(TEST_SEED)
}

struct Case {
    id: &'static str,
    description: &'static str,
    token: String,
    verify_at: i64,
    /// `None` is accept; `Some(reason)` is the rejection reason.
    expect: Option<&'static str>,
}

fn case(
    id: &'static str,
    description: &'static str,
    token: String,
    verify_at: i64,
    expect: Option<&'static str>,
) -> Case {
    Case {
        id,
        description,
        token,
        verify_at,
        expect,
    }
}

fn cases() -> Vec<Case> {
    let key = signing_key();
    let public = key.verifying_key().to_bytes();
    let kid = kid_of(&public);
    let sign = |claims: &dyn ErasedClaims| claims.encode(&kid, &key);

    let v1 = sign(&machine());
    let mut wrong_audience = machine();
    wrong_audience.aud = "other-product";
    let mut other_tenant = machine();
    other_tenant.tenant = "someone-else";
    let tampered = {
        // V1's header and signature around a different payload.
        let parts: Vec<&str> = v1.split('.').collect();
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&other_tenant).unwrap());
        format!("{}.{payload}.{}", parts[0], parts[2])
    };
    let hs256 = {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.typ = Some("JWT".to_owned());
        header.kid = Some(kid.clone());
        jsonwebtoken::encode(
            &header,
            &machine(),
            &jsonwebtoken::EncodingKey::from_secret(&public),
        )
        .unwrap()
    };
    let v3 = sign(&user());
    let unknown_kid = jwt::encode("AAAAAAAAAAA", &key, &user()).unwrap();

    let exp1 = IAT + MACHINE_TTL;
    let exp3 = IAT + USER_TTL;
    vec![
        case(
            "V1.accept",
            "A valid machine token, checked ten seconds after issue.",
            v1.clone(),
            IAT + 10,
            None,
        ),
        case(
            "V1.accept-inside-allowance-after-exp",
            "The same token 200 s past exp: inside the 300 s allowance, so still accepted.",
            v1.clone(),
            exp1 + 200,
            None,
        ),
        case(
            "V1.accept-inside-allowance-before-iat",
            "The same token checked 200 s before iat, as a verifier with a slow clock would: accepted.",
            v1.clone(),
            IAT - 200,
            None,
        ),
        case(
            "V1.expired",
            "The same token 301 s past exp: outside the allowance.",
            v1.clone(),
            exp1 + 301,
            Some("expired"),
        ),
        case(
            "V1.issued-in-the-future",
            "The same token checked 301 s before iat: outside the allowance.",
            v1.clone(),
            IAT - 301,
            Some("not_yet_valid"),
        ),
        case(
            "V2.audience",
            "Correctly signed, but aud names another product.",
            sign(&wrong_audience),
            IAT + 10,
            Some("audience"),
        ),
        case(
            "V2.alg-hs256",
            "V1's claims re-signed as HS256 with the public key bytes as the HMAC secret, under the real kid.",
            hs256,
            IAT + 10,
            Some("alg"),
        ),
        case(
            "V2.tampered-payload",
            "V1's header and signature around a payload that names another tenant.",
            tampered,
            IAT + 10,
            Some("signature"),
        ),
        case(
            "V3.accept",
            "A valid user token, checked 30 s after issue.",
            v3.clone(),
            IAT + 30,
            None,
        ),
        case(
            "V3.expired",
            "The same user token 301 s past exp.",
            v3,
            exp3 + 301,
            Some("expired"),
        ),
        case(
            "V3.unknown-kid",
            "A user token signed by the right key but naming a kid the key set does not contain.",
            unknown_kid,
            IAT + 30,
            Some("unknown_kid"),
        ),
    ]
}

/// Lets one closure sign either claims struct.
trait ErasedClaims {
    fn encode(&self, kid: &str, key: &SigningKey) -> String;
}
impl<T: Serialize> ErasedClaims for T {
    fn encode(&self, kid: &str, key: &SigningKey) -> String {
        jwt::encode(kid, key, self).unwrap()
    }
}

/// The verifier of `docs/verifier/README.md`, step for step. `Ok(())` accepts;
/// `Err(reason)` is the rejection reason the README names.
fn reference_verify(jwks: &Value, token: &str, now: i64) -> Result<(), &'static str> {
    // 1. Shape and header.
    let parts: Vec<&str> = token.split('.').collect();
    let [header, payload, signature] = parts[..] else {
        return Err("malformed");
    };
    let decode = |s: &str| URL_SAFE_NO_PAD.decode(s).map_err(|_| "malformed");
    let header: Value = serde_json::from_slice(&decode(header)?).map_err(|_| "malformed")?;
    if header["alg"] != "EdDSA" {
        return Err("alg");
    }
    if header.get("typ").is_some_and(|t| t != "JWT") || header.get("crit").is_some() {
        return Err("malformed");
    }
    let Some(kid) = header["kid"].as_str() else {
        return Err("malformed");
    };

    // 2. Find the key. (A real verifier refreshes the key set once here.)
    let jwk = jwks["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|k| k["kid"] == kid))
        .ok_or("unknown_kid")?;
    let x = decode(jwk["x"].as_str().ok_or("malformed")?)?;
    let verifying = VerifyingKey::from_bytes(&x.try_into().map_err(|_| "malformed")?)
        .map_err(|_| "malformed")?;

    // 3. Signature over the first two segments, as sent.
    let signed = &token[..token.len() - signature.len() - 1];
    let signature = Signature::from_slice(&decode(signature)?).map_err(|_| "signature")?;
    verifying
        .verify(signed.as_bytes(), &signature)
        .map_err(|_| "signature")?;

    // 4. Claims.
    let claims: Value = serde_json::from_slice(&decode(payload)?).map_err(|_| "malformed")?;
    for name in ["iss", "sub", "aud", "exp", "iat", "jti", "tenant", "kind"] {
        if claims.get(name).is_none() {
            return Err("claims");
        }
    }
    if claims["iss"] != ISSUER {
        return Err("issuer");
    }
    if claims["aud"] != AUDIENCE {
        return Err("audience");
    }
    let (Some(exp), Some(iat)) = (claims["exp"].as_i64(), claims["iat"].as_i64()) else {
        return Err("claims");
    };
    if exp <= now - ALLOWANCE {
        return Err("expired");
    }
    if iat > now + ALLOWANCE {
        return Err("not_yet_valid");
    }
    Ok(())
}

fn document() -> Value {
    let key = signing_key();
    let public = key.verifying_key().to_bytes();
    let jwks = json!({ "keys": [{
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid_of(&public),
        "x": URL_SAFE_NO_PAD.encode(public),
        "use": "sig",
        "alg": "EdDSA",
    }]});
    let cases = cases();
    for c in &cases {
        let verdict = reference_verify(&jwks, &c.token, c.verify_at);
        assert_eq!(verdict.err(), c.expect, "{}: {}", c.id, c.description);
    }
    json!({
        "description": "Test vectors for verifying tokens issued by session-broker. \
            See docs/verifier/README.md for the checks, in order. Generated by \
            repo/crates/session-broker/src/issuer/vectors.rs from a fixed test-only seed; do not edit by hand.",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "clock_allowance_secs": ALLOWANCE,
        "jwks": jwks,
        "cases": cases.iter().map(|c| {
            let payload = c.token.split('.').nth(1).unwrap();
            json!({
                "id": c.id,
                "description": c.description,
                "token": c.token,
                "payload": serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap(),
                "verify_at": c.verify_at,
                "expect": match c.expect {
                    None => json!({ "result": "accept" }),
                    Some(reason) => json!({ "result": "reject", "reason": reason }),
                },
            })
        }).collect::<Vec<_>>(),
    })
}

/// The committed file is what the code produces now.
#[test]
fn the_published_vectors_are_what_the_signer_produces() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../docs/verifier/vectors.json");
    let generated = serde_json::to_string_pretty(&document()).unwrap() + "\n";
    if std::env::var_os("UPDATE_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(&path)
        .expect("docs/verifier/vectors.json exists; UPDATE_VECTORS=1 writes it");
    assert_eq!(
        committed, generated,
        "docs/verifier/vectors.json is stale; run UPDATE_VECTORS=1 cargo test -p session-broker vectors"
    );
}

/// The vectors are not hollow: the accepting ones really verify with an
/// independent decoder, and the tokens are what the broker would issue (same
/// header, same claim names, same order as the routes).
#[test]
fn the_accepted_vectors_verify_with_an_independent_decoder() {
    let doc = document();
    let set: jsonwebtoken::jwk::JwkSet = serde_json::from_value(doc["jwks"].clone()).unwrap();
    let mut accepted = 0;
    for c in doc["cases"].as_array().unwrap() {
        if c["expect"]["result"] != "accept" {
            continue;
        }
        let token = c["token"].as_str().unwrap();
        let header = jsonwebtoken::decode_header(token).unwrap();
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        let key = jsonwebtoken::DecodingKey::from_jwk(
            set.find(&header.kid.clone().unwrap()).expect("kid in set"),
        )
        .unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_audience(&[AUDIENCE]);
        validation.set_issuer(&[ISSUER]);
        // Time is the vector's, not the wall clock's.
        validation.validate_exp = false;
        jsonwebtoken::decode::<Value>(token, &key, &validation).unwrap();
        accepted += 1;
    }
    assert!(accepted >= 3);
}
