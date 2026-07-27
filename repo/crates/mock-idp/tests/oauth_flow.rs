//! Integration tests driving a real, in-process `mock-idp` instance (via
//! `spawn_mock_idp`) through the same HTTP surface `session-broker` will
//! use: authorize -> token -> refresh -> revoke -> `/__test__` controls.

use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use mock_idp::{spawn_mock_idp, MockIdpConfig};
use rand::RngCore;
use sha2::{Digest, Sha256};
use url::Url;

const CLIENT_ID: &str = "session-broker-dev";
const CLIENT_SECRET: &str = "dev-secret";
const REDIRECT_URI: &str = "http://localhost:8080/auth/callback";
const SUBJECT: &str = "user-1";

fn pkce_pair() -> (String, String) {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn no_redirect_client() -> reqwest::Client {
    // /authorize's success response IS the thing under test (a 302 to a
    // redirect_uri that doesn't really exist) — following it would just 404.
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client builds")
}

/// Drive `/authorize` and pull the issued `code` out of the redirect's
/// `Location` header. Helper-internal `expect`s are fine here: a failure
/// means the fixture itself is broken, not the thing a given test asserts.
async fn get_authorization_code(client: &reqwest::Client, base: &str, challenge: &str) -> String {
    let response = client
        .get(format!("{base}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("state", "xyz"),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .expect("authorize request succeeds");
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("redirect has a Location header")
        .to_str()
        .expect("Location is valid UTF-8");
    let url = Url::parse(location).expect("Location is a valid URL");
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(
        params.get("state").map(String::as_str),
        Some("xyz"),
        "state must be echoed back"
    );
    params.get("code").expect("redirect carries a code").clone()
}

async fn exchange_code(
    client: &reqwest::Client,
    base: &str,
    code: &str,
    verifier: &str,
) -> reqwest::Response {
    client
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .expect("token request succeeds")
}

async fn refresh(client: &reqwest::Client, base: &str, refresh_token: &str) -> reqwest::Response {
    client
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
        ])
        .send()
        .await
        .expect("token request succeeds")
}

#[tokio::test]
async fn pkce_wrong_verifier_is_rejected() {
    let handle = spawn_mock_idp(MockIdpConfig::default())
        .await
        .expect("spawns");
    let client = no_redirect_client();
    let (_verifier, challenge) = pkce_pair();
    let code = get_authorization_code(&client, handle.base_url(), &challenge).await;

    let response = exchange_code(&client, handle.base_url(), &code, "not-the-right-verifier").await;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.expect("json body");
    assert_eq!(body["error"], "invalid_grant");

    handle.shutdown().await;
}

#[tokio::test]
async fn code_cannot_be_exchanged_twice() {
    let handle = spawn_mock_idp(MockIdpConfig::default())
        .await
        .expect("spawns");
    let client = no_redirect_client();
    let (verifier, challenge) = pkce_pair();
    let code = get_authorization_code(&client, handle.base_url(), &challenge).await;

    let first = exchange_code(&client, handle.base_url(), &code, &verifier).await;
    assert_eq!(
        first.status(),
        reqwest::StatusCode::OK,
        "first exchange must succeed"
    );

    let second = exchange_code(&client, handle.base_url(), &code, &verifier).await;
    assert_eq!(second.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = second.json().await.expect("json body");
    assert_eq!(body["error"], "invalid_grant");

    handle.shutdown().await;
}

#[tokio::test]
async fn expired_code_is_rejected() {
    let config = MockIdpConfig {
        authorization_code_ttl_secs: 1,
        ..MockIdpConfig::default()
    };
    let handle = spawn_mock_idp(config).await.expect("spawns");
    let client = no_redirect_client();
    let (verifier, challenge) = pkce_pair();
    let code = get_authorization_code(&client, handle.base_url(), &challenge).await;

    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    let response = exchange_code(&client, handle.base_url(), &code, &verifier).await;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.expect("json body");
    assert_eq!(body["error"], "invalid_grant");
    assert!(body["error_description"]
        .as_str()
        .unwrap_or_default()
        .contains("expired"));

    handle.shutdown().await;
}

#[tokio::test]
async fn refresh_grant_without_rotation_keeps_the_same_token() {
    let config = MockIdpConfig {
        rotate_refresh_tokens: false,
        ..MockIdpConfig::default()
    };
    let handle = spawn_mock_idp(config).await.expect("spawns");
    let client = no_redirect_client();
    let (verifier, challenge) = pkce_pair();
    let code = get_authorization_code(&client, handle.base_url(), &challenge).await;
    let tokens: serde_json::Value = exchange_code(&client, handle.base_url(), &code, &verifier)
        .await
        .json()
        .await
        .expect("json body");
    let original_refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    let original_access = tokens["access_token"].as_str().unwrap().to_owned();

    let refreshed = refresh(&client, handle.base_url(), &original_refresh).await;
    assert_eq!(refreshed.status(), reqwest::StatusCode::OK);
    let refreshed_body: serde_json::Value = refreshed.json().await.expect("json body");

    assert_eq!(
        refreshed_body["refresh_token"].as_str().unwrap(),
        original_refresh,
        "non-rotating config must echo the same refresh token"
    );
    assert_ne!(
        refreshed_body["access_token"].as_str().unwrap(),
        original_access,
        "a fresh access token is still issued"
    );

    // The unchanged refresh token still works a second time.
    let refreshed_again = refresh(&client, handle.base_url(), &original_refresh).await;
    assert_eq!(refreshed_again.status(), reqwest::StatusCode::OK);

    handle.shutdown().await;
}

#[tokio::test]
async fn refresh_grant_with_rotation_issues_a_new_token_and_invalidates_the_old_one() {
    let config = MockIdpConfig {
        rotate_refresh_tokens: true,
        ..MockIdpConfig::default()
    };
    let handle = spawn_mock_idp(config).await.expect("spawns");
    let client = no_redirect_client();
    let (verifier, challenge) = pkce_pair();
    let code = get_authorization_code(&client, handle.base_url(), &challenge).await;
    let tokens: serde_json::Value = exchange_code(&client, handle.base_url(), &code, &verifier)
        .await
        .json()
        .await
        .expect("json body");
    let original_refresh = tokens["refresh_token"].as_str().unwrap().to_owned();

    let refreshed = refresh(&client, handle.base_url(), &original_refresh).await;
    assert_eq!(refreshed.status(), reqwest::StatusCode::OK);
    let refreshed_body: serde_json::Value = refreshed.json().await.expect("json body");
    let rotated_refresh = refreshed_body["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(
        rotated_refresh, original_refresh,
        "rotating config must issue a new refresh token"
    );

    // The old, rotated-away token no longer works.
    let reused_old = refresh(&client, handle.base_url(), &original_refresh).await;
    assert_eq!(reused_old.status(), reqwest::StatusCode::BAD_REQUEST);

    // The new one does.
    let uses_new = refresh(&client, handle.base_url(), &rotated_refresh).await;
    assert_eq!(uses_new.status(), reqwest::StatusCode::OK);

    handle.shutdown().await;
}

#[tokio::test]
async fn revoked_refresh_token_fails_invalid_grant() {
    let handle = spawn_mock_idp(MockIdpConfig::default())
        .await
        .expect("spawns");
    let client = no_redirect_client();
    let (verifier, challenge) = pkce_pair();
    let code = get_authorization_code(&client, handle.base_url(), &challenge).await;
    let tokens: serde_json::Value = exchange_code(&client, handle.base_url(), &code, &verifier)
        .await
        .json()
        .await
        .expect("json body");
    let refresh_token = tokens["refresh_token"].as_str().unwrap().to_owned();

    let revoke_response = client
        .post(format!("{}/__test__/revoke-refresh", handle.base_url()))
        .json(&serde_json::json!({ "subject": SUBJECT }))
        .send()
        .await
        .expect("revoke-refresh request succeeds");
    assert_eq!(revoke_response.status(), reqwest::StatusCode::OK);

    let response = refresh(&client, handle.base_url(), &refresh_token).await;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.expect("json body");
    assert_eq!(body["error"], "invalid_grant");

    handle.shutdown().await;
}

#[tokio::test]
async fn token_call_counter_tracks_every_call_by_grant_type() {
    let handle = spawn_mock_idp(MockIdpConfig::default())
        .await
        .expect("spawns");
    let client = no_redirect_client();
    let (verifier, challenge) = pkce_pair();
    let code = get_authorization_code(&client, handle.base_url(), &challenge).await;
    let tokens: serde_json::Value = exchange_code(&client, handle.base_url(), &code, &verifier)
        .await
        .json()
        .await
        .expect("json body");
    let refresh_token = tokens["refresh_token"].as_str().unwrap().to_owned();

    refresh(&client, handle.base_url(), &refresh_token).await;
    refresh(&client, handle.base_url(), &refresh_token).await;

    let state: serde_json::Value = client
        .get(format!("{}/__test__/state", handle.base_url()))
        .send()
        .await
        .expect("state request succeeds")
        .json()
        .await
        .expect("json body");

    assert_eq!(
        state["counters"]["token_calls_total"], 3,
        "1 code exchange + 2 refreshes"
    );
    assert_eq!(
        state["counters"]["token_calls_by_grant"]["authorization_code"],
        1
    );
    assert_eq!(
        state["counters"]["token_calls_by_grant"]["refresh_token"],
        2
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn discovery_document_and_jwks_are_self_consistent() {
    let handle = spawn_mock_idp(MockIdpConfig::default())
        .await
        .expect("spawns");
    let client = reqwest::Client::new();

    let discovery: serde_json::Value = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            handle.base_url()
        ))
        .send()
        .await
        .expect("discovery request succeeds")
        .json()
        .await
        .expect("json body");
    assert_eq!(discovery["issuer"], handle.base_url());
    assert_eq!(
        discovery["jwks_uri"],
        format!("{}/jwks.json", handle.base_url())
    );

    let jwks: serde_json::Value = client
        .get(discovery["jwks_uri"].as_str().unwrap())
        .send()
        .await
        .expect("jwks request succeeds")
        .json()
        .await
        .expect("json body");
    assert_eq!(jwks["keys"][0]["kty"], "RSA");
    assert_eq!(jwks["keys"][0]["alg"], "RS256");

    handle.shutdown().await;
}

#[tokio::test]
async fn userinfo_requires_a_valid_bearer_token() {
    let handle = spawn_mock_idp(MockIdpConfig::default())
        .await
        .expect("spawns");
    let client = reqwest::Client::new();

    let unauthenticated = client
        .get(format!("{}/userinfo", handle.base_url()))
        .send()
        .await
        .expect("userinfo request succeeds");
    assert_eq!(unauthenticated.status(), reqwest::StatusCode::UNAUTHORIZED);

    let redirect_client = no_redirect_client();
    let (verifier, challenge) = pkce_pair();
    let code = get_authorization_code(&redirect_client, handle.base_url(), &challenge).await;
    let tokens: serde_json::Value =
        exchange_code(&redirect_client, handle.base_url(), &code, &verifier)
            .await
            .json()
            .await
            .expect("json body");
    let access_token = tokens["access_token"].as_str().unwrap();

    let authenticated = client
        .get(format!("{}/userinfo", handle.base_url()))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("userinfo request succeeds");
    assert_eq!(authenticated.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = authenticated.json().await.expect("json body");
    assert_eq!(body["sub"], SUBJECT);

    handle.shutdown().await;
}
