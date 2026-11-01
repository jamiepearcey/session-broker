//! The real binary: boots with no provider at all, takes one from the admin lane,
//! logs someone in through it over real HTTP, keeps it across a restart, and
//! never writes its secret to its log.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use mock_idp::config::ClientConfig;
use mock_idp::{spawn_mock_idp, MockIdpConfig};
use serde_json::{json, Value};

const ADMIN_KEY: &str = "an-admin-key-that-is-at-least-32-chars";
const SECRET: &str = "binary-test-secret-5d2e";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Broker {
    child: Child,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Ports {
    public: u16,
    internal: u16,
}

impl Ports {
    fn public(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.public)
    }
    fn internal(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.internal)
    }
}

async fn start(dir: &Path, ports: &Ports, run: u32) -> Broker {
    let log = std::fs::File::create(dir.join(format!("broker-{run}.log"))).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_session-broker"))
        .current_dir(dir)
        .env_clear()
        .env("BROKER_BIND_ADDR", format!("127.0.0.1:{}", ports.public))
        .env(
            "BROKER_INTERNAL_BIND_ADDR",
            format!("127.0.0.1:{}", ports.internal),
        )
        .env("BROKER_BASE_URL", ports.public(""))
        .env("BROKER_DB_PATH", dir.join("broker.db"))
        .env("BROKER_KEYFILE_PATH", dir.join("broker.key"))
        .env("BROKER_ADMIN_API_KEY", ADMIN_KEY)
        .env("BROKER_SHUTDOWN_DRAIN_DELAY_SECS", "0")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let broker = Broker { child };
    for _ in 0..200 {
        if let Ok(response) = reqwest::get(ports.public("/healthz")).await {
            if response.status().is_success() {
                return broker;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "the broker did not come up: {}",
        std::fs::read_to_string(dir.join(format!("broker-{run}.log"))).unwrap()
    );
}

fn no_redirects() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn set_cookie(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap().to_owned())
}

fn location(response: &reqwest::Response) -> String {
    response.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned()
}

/// A full sign-in. Answers the person's `sub`.
async fn sign_in(ports: &Ports) -> String {
    let http = no_redirects();
    let login = http
        .get(ports.public("/auth/login?provider=mock"))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 303);
    let txn = set_cookie(&login, "broker_txn").expect("a txn cookie");
    let idp = http.get(location(&login)).send().await.unwrap();
    assert_eq!(idp.status(), 302);
    let callback = http
        .get(location(&idp))
        .header(reqwest::header::COOKIE, txn)
        .send()
        .await
        .unwrap();
    assert_eq!(callback.status(), 303);
    let session = set_cookie(&callback, "broker_session").expect("a session cookie");
    let meta: Value = http
        .get(ports.public("/session"))
        .header(reqwest::header::COOKIE, session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    meta["sub"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn the_binary_boots_with_no_provider_then_takes_one_from_the_admin_lane() {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "session-broker-providers-boot-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ports = Ports {
        public: free_port(),
        internal: free_port(),
    };
    let idp = spawn_mock_idp(MockIdpConfig {
        clients: vec![ClientConfig {
            client_id: "client".to_owned(),
            client_secret: Some(SECRET.to_owned()),
            redirect_uris: vec![ports.public("/auth/callback")],
        }],
        ..MockIdpConfig::default()
    })
    .await
    .unwrap();
    let http = no_redirects();

    let broker = start(&dir, &ports, 1).await;

    let choices: Value = reqwest::get(ports.public("/auth/providers"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(choices, json!({ "providers": [] }));
    let refused = http.get(ports.public("/auth/login")).send().await.unwrap();
    assert_eq!(refused.status(), 503);
    let refused: Value = refused.json().await.unwrap();
    assert_eq!(refused["error"], "no_providers");

    let created = http
        .post(ports.internal("/admin/providers"))
        .bearer_auth(ADMIN_KEY)
        .json(&json!({
            "id": "mock", "preset": "generic", "display_name": "Mock",
            "issuer_url": idp.base_url(), "client_id": "client", "client_secret": SECRET,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created = created.text().await.unwrap();
    assert!(!created.contains(SECRET));
    let created: Value = serde_json::from_str(&created).unwrap();
    assert_eq!(created["redirect_uri"], ports.public("/auth/callback"));

    assert_eq!(sign_in(&ports).await, "mock|user-1");

    // Across a restart, from the sealed row. A kill is the honest restart.
    drop(broker);
    let broker = start(&dir, &ports, 2).await;
    let list: Value = http
        .get(ports.internal("/admin/providers"))
        .bearer_auth(ADMIN_KEY)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["providers"][0]["id"], "mock");
    assert_eq!(list["providers"][0]["has_secret"], true);
    assert_eq!(sign_in(&ports).await, "mock|user-1");
    drop(broker);

    for run in [1, 2] {
        let log = std::fs::read_to_string(dir.join(format!("broker-{run}.log"))).unwrap();
        assert!(
            !log.is_empty(),
            "run {run} logged nothing, so this proves nothing"
        );
        assert!(
            !log.contains(SECRET),
            "the secret reached the log of run {run}"
        );
    }
    let database = std::fs::read(dir.join("broker.db")).unwrap();
    assert!(!database
        .windows(SECRET.len())
        .any(|window| window == SECRET.as_bytes()));

    idp.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
