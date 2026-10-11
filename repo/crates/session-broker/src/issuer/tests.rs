//! Tests for the signing core.
//!
//! Two rules shape them. Tokens are checked by `jsonwebtoken`, an independent
//! implementation, never by this crate's own encoder run backwards. And every
//! claim about a row is read through a separate connection to the database
//! file, after going through `bootstrap` / `rotate` / `prune_retired` — the
//! functions production calls — so a writer command nobody sends, or a
//! predicate that can never match, fails here rather than in a deployment.

use super::*;
use crate::audit::AuditConfig;
use crate::clock::TestClock;
use crate::store::repo::{AuditQuery, SigningKeyRow, StoredAuditRow};
use crate::store::writer::Writer;
use crate::telemetry::Metrics;

const T0: Timestamp = Timestamp(1_700_000_000);
const DAY: u64 = 86_400;

struct Store {
    path: std::path::PathBuf,
    writer: Writer,
    clock: TestClock,
}

fn store(tag: &str) -> Store {
    let path = std::env::temp_dir().join(format!(
        "session-broker-issuer-{tag}-{}-{}.sqlite3",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let conn = crate::store::open(&path, &path.with_extension("key")).unwrap();
    Store {
        path,
        writer: Writer::spawn(conn),
        clock: TestClock::new(T0),
    }
}

impl Store {
    fn connect(&self) -> rusqlite::Connection {
        crate::store::open(&self.path, &self.path.with_extension("key")).unwrap()
    }

    fn parts(&self) -> (Arc<Reader>, WriterHandle, Option<AuditSink>, Arc<dyn Clock>) {
        let writer = self.writer.handle();
        let audit = AuditSink::new(writer.clone(), Metrics::new(), AuditConfig::default());
        (
            Arc::new(Reader::new(self.connect())),
            writer,
            Some(audit),
            Arc::new(self.clock.clone()),
        )
    }

    /// What `main` does at start.
    fn boot(&self) -> Arc<Issuer> {
        let (reader, writer, audit, clock) = self.parts();
        bootstrap(reader, writer, audit, clock, KeyPolicy::default()).unwrap()
    }

    /// The `signing_key` table through a connection of its own, newest first.
    fn rows(&self) -> Vec<SigningKeyRow> {
        repo::list_signing_keys(&self.connect()).unwrap()
    }

    fn audit(&self, action: &str) -> Vec<StoredAuditRow> {
        repo::list_audit(
            &self.connect(),
            &AuditQuery {
                limit: 1000,
                ..AuditQuery::default()
            },
        )
        .unwrap()
        .into_iter()
        .filter(|r| r.row.action == action)
        .collect()
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(format!("{}-wal", self.path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", self.path.display()));
        let _ = std::fs::remove_file(self.path.with_extension("key"));
    }
}

fn jwks_kids(issuer: &Issuer) -> Vec<String> {
    issuer.jwks()["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_owned())
        .collect()
}

/// Claims with a real-clock `exp`, because the independent decoder checks it
/// against the system time.
fn claims() -> serde_json::Value {
    let now = crate::clock::SystemClock.now().secs();
    serde_json::json!({
        "iss": "https://broker.example",
        "sub": "sp_test",
        "aud": "logless:test:agent",
        "iat": now,
        "exp": now + 3600,
        "jti": "AAAAAAAAAAAAAAAAAAAAAA",
        "tenant": "default",
        "kind": "ingest",
    })
}

/// A verifier as a resource server would build it: keys from the published
/// JWKS, the algorithm fixed to EdDSA, issuer and audience pinned.
fn verify(
    issuer: &Issuer,
    token: &str,
) -> jsonwebtoken::errors::Result<jsonwebtoken::TokenData<serde_json::Value>> {
    let set: jsonwebtoken::jwk::JwkSet = serde_json::from_value(issuer.jwks()).unwrap();
    let kid = jsonwebtoken::decode_header(token)?.kid.unwrap();
    let key = jsonwebtoken::DecodingKey::from_jwk(set.find(&kid).expect("kid is published"))?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_audience(&["logless:test:agent"]);
    validation.set_issuer(&["https://broker.example"]);
    jsonwebtoken::decode(token, &key, &validation)
}

/// The slice's exit condition: a token signed by a fresh store verifies with a
/// decoder that shares no code with `issuer::jwt`.
#[test]
fn a_signed_token_verifies_with_an_independent_decoder() {
    let s = store("verify");
    let issuer = s.boot();
    let token = issuer.sign(&claims()).unwrap();

    let decoded = verify(&issuer, &token).expect("an independent decoder accepts the token");
    assert_eq!(decoded.claims, claims());
    assert_eq!(decoded.header.alg, jsonwebtoken::Algorithm::EdDSA);
    assert_eq!(decoded.header.typ.as_deref(), Some("JWT"));
    assert_eq!(decoded.header.kid, issuer.signing_kid());

    // The control: the same decoder refuses the token once a claim is altered,
    // so the acceptance above is a signature check and not a parse.
    let mut parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let mut altered = claims();
    altered["tenant"] = "someone-else".into();
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&altered).unwrap());
    parts[1] = &payload;
    assert!(verify(&issuer, &parts.join(".")).is_err());
}

/// Algorithm confusion: take a real token's claims, sign them HS256 using the
/// PUBLIC key as the HMAC secret, and present that under the real `kid`. A
/// verifier that let the token choose its algorithm would accept it.
#[test]
fn a_token_re_signed_as_hs256_with_the_public_key_is_rejected() {
    let s = store("confusion");
    let issuer = s.boot();
    let kid = issuer.signing_kid().unwrap();
    let x = issuer.jwks()["keys"][0]["x"].as_str().unwrap().to_owned();
    let public = URL_SAFE_NO_PAD.decode(&x).unwrap();

    // Both things an attacker could plausibly feed in as "the key": the raw
    // public bytes, and the base64url text the JWKS publishes.
    for secret in [public.as_slice(), x.as_bytes()] {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.typ = Some("JWT".to_owned());
        header.kid = Some(kid.clone());
        let forged = jsonwebtoken::encode(
            &header,
            &claims(),
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .unwrap();

        // The forgery is well formed: under HS256 with that secret it verifies.
        let mut hs = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        hs.set_audience(&["logless:test:agent"]);
        jsonwebtoken::decode::<serde_json::Value>(
            &forged,
            &jsonwebtoken::DecodingKey::from_secret(secret),
            &hs,
        )
        .expect("the forged token is a valid HS256 token");

        let refused = verify(&issuer, &forged).expect_err("an EdDSA-only verifier refuses it");
        assert!(
            matches!(
                refused.kind(),
                jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
            ),
            "refused for the algorithm, not by accident: {refused:?}"
        );
    }
}

#[test]
fn the_jwks_document_has_exactly_the_published_shape() {
    let s = store("jwks");
    let issuer = s.boot();
    let row = &s.rows()[0];
    assert_eq!(
        issuer.jwks(),
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": row.kid,
                "x": URL_SAFE_NO_PAD.encode(row.public_key),
                "use": "sig",
                "alg": "EdDSA",
            }]
        })
    );
    // Nothing private: an OKP private key would be a `d` member.
    assert!(issuer.jwks()["keys"][0].get("d").is_none());
}

/// RFC 8032 §7.1 test 1 pins what "seed" and "public key" mean; the expected
/// kid was computed outside this crate (`sha256(public)[..8]`, base64url).
#[test]
fn the_kid_is_derived_from_the_public_key() {
    let seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(public),
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    );
    assert_eq!(keys::kid_of(&public), "If4x36FUomE");

    // A generated key carries the kid of its own public half, and two
    // generated keys differ.
    let a = keys::generate();
    let b = keys::generate();
    assert_eq!(a.kid, keys::kid_of(&a.public_key));
    assert_ne!(a.kid, b.kid);
    assert!(!format!("{a:?}").contains(&format!("{:?}", a.seed.as_slice())));
}

/// INV-5 for the seed: it is in process memory and nowhere on disk, in any of
/// the encodings it could have leaked in. INV-12: nor in the audit rows.
#[test]
fn the_seed_bytes_are_absent_from_the_database_file() {
    let s = store("seed");
    let issuer = s.boot();
    issuer.rotate(Some(0), "test").unwrap();
    let seeds = issuer.cache.read().unwrap().seeds();
    assert_eq!(seeds.len(), 2, "both keys' seeds are held in memory");

    // Checkpoint so the main file holds every page, then read it and the WAL.
    s.connect()
        .execute_batch("PRAGMA wal_checkpoint(FULL)")
        .unwrap();
    let mut disk = std::fs::read(&s.path).unwrap();
    disk.extend(std::fs::read(format!("{}-wal", s.path.display())).unwrap_or_default());
    let contains = |needle: &[u8]| disk.windows(needle.len()).any(|w| w == needle);

    for row in s.rows() {
        assert!(
            contains(&row.public_key),
            "positive control: the public key IS in the file, so the search works"
        );
    }
    for seed in &seeds {
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!contains(seed), "raw seed bytes on disk");
        assert!(!contains(URL_SAFE_NO_PAD.encode(seed).as_bytes()));
        assert!(!contains(hex.as_bytes()));
    }
}

#[test]
fn bootstrap_creates_exactly_one_key_and_one_audit_row_and_a_second_boot_none() {
    let s = store("bootstrap");
    assert!(s.rows().is_empty());

    let first = s.boot();
    let rows = s.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].created_at, T0);
    assert_eq!(rows[0].activate_at, T0, "the first key signs at once");
    assert_eq!((rows[0].retire_at, rows[0].removed_at), (None, None));
    assert_eq!(first.signing_kid().as_deref(), Some(rows[0].kid.as_str()));

    let created = s.audit(action::SIGNING_KEY_CREATED);
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].row.key_id.as_deref(), Some(rows[0].kid.as_str()));
    assert_eq!(created[0].row.actor_kind, "system");
    assert_eq!(created[0].row.outcome, "success");

    // A restart, later: same key, no new row of either kind.
    drop(first);
    s.clock.advance(3 * DAY);
    let second = s.boot();
    assert_eq!(s.rows(), rows);
    assert_eq!(s.audit(action::SIGNING_KEY_CREATED).len(), 1);
    assert_eq!(second.signing_kid().as_deref(), Some(rows[0].kid.as_str()));
    // And it can still sign with the key it found, i.e. the seed opened.
    verify(&second, &second.sign(&claims()).unwrap()).unwrap();
}

/// The whole life of a key under a rotation with the default lead, driven by
/// the clock: pending → signing, and for the key it replaces: signing →
/// published-only → unpublished → removed.
#[test]
fn a_rotation_with_a_lead_runs_its_course_by_the_clock() {
    let s = store("lead");
    let issuer = s.boot();
    let old = issuer.signing_kid().unwrap();

    let rotation = issuer.rotate(None, "test").unwrap();
    let new = rotation.kid.clone();
    let activate = T0.plus_secs(DAY);
    let retire = T0.plus_secs(DAY + DAY + 300);
    assert_eq!(rotation.activate_at, activate.secs());
    assert_eq!(rotation.previous_retire_at, retire.secs());
    assert!(!rotation.immediate);

    // Through a second connection: the new key is pending and open-ended, the
    // old one has its end date.
    let rows = s.rows();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[0].kid.as_str(), rows[0].activate_at),
        (&*new, activate)
    );
    assert_eq!(rows[0].retire_at, None);
    assert_eq!(
        (rows[1].kid.as_str(), rows[1].retire_at),
        (&*old, Some(retire))
    );
    let recorded = s.audit(action::SIGNING_KEY_ROTATED);
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].row.key_id.as_deref(), Some(new.as_str()));
    assert_eq!(recorded[0].row.actor_id.as_deref(), Some("test"));

    // During the lead: the old key signs, both are published.
    assert_eq!(issuer.signing_kid().as_deref(), Some(old.as_str()));
    assert_eq!(jwks_kids(&issuer), [new.clone(), old.clone()]);
    s.clock.set(Timestamp(activate.secs() - 1));
    assert_eq!(issuer.signing_kid().as_deref(), Some(old.as_str()));

    // At `activate_at` the new key takes over; the old one is still published.
    s.clock.set(activate);
    assert_eq!(issuer.signing_kid().as_deref(), Some(new.as_str()));
    assert_eq!(jwks_kids(&issuer), [new.clone(), old.clone()]);

    // One second before `retire_at`: still published, and the prune's
    // predicate does not match it.
    s.clock.set(Timestamp(retire.secs() - 1));
    assert_eq!(jwks_kids(&issuer), [new.clone(), old.clone()]);
    assert_eq!(issuer.prune_retired(), 0);
    assert_eq!(s.rows()[1].removed_at, None);
    assert!(s.audit(action::SIGNING_KEY_REMOVED).is_empty());

    // At `retire_at`: unpublished by the clock alone, before any prune runs.
    s.clock.set(retire);
    assert_eq!(jwks_kids(&issuer), [new.as_str()]);
    assert_eq!(s.rows()[1].removed_at, None);

    // The prune now matches it, once.
    assert_eq!(issuer.prune_retired(), 1);
    let rows = s.rows();
    assert_eq!(
        (rows[1].kid.as_str(), rows[1].removed_at),
        (&*old, Some(retire))
    );
    assert_eq!(rows[0].removed_at, None, "the signing key is never pruned");
    let removed = s.audit(action::SIGNING_KEY_REMOVED);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].row.key_id.as_deref(), Some(old.as_str()));
    assert_eq!(removed[0].row.actor_kind, "system");

    assert_eq!(issuer.prune_retired(), 0);
    assert_eq!(s.audit(action::SIGNING_KEY_REMOVED).len(), 1);
    assert_eq!(issuer.signing_kid().as_deref(), Some(new.as_str()));
    assert_eq!(jwks_kids(&issuer), [new]);
}

#[test]
fn an_immediate_rotation_switches_now_and_unpublishes_the_old_key() {
    let s = store("immediate");
    let issuer = s.boot();
    let old = issuer.signing_kid().unwrap();
    let before = issuer.sign(&claims()).unwrap();

    // Same second as the bootstrap, so `activate_at` and `created_at` tie and
    // only insertion order says which key is newer.
    let rotation = issuer.rotate(Some(0), "test").unwrap();
    assert!(rotation.immediate);
    assert_eq!(rotation.activate_at, T0.secs());
    assert_eq!(rotation.previous_retire_at, T0.secs());

    let rows = s.rows();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[0].kid.as_str(), rows[0].retire_at),
        (&*rotation.kid, None)
    );
    assert_eq!((rows[1].kid.as_str(), rows[1].retire_at), (&*old, Some(T0)));

    assert_eq!(issuer.signing_kid(), Some(rotation.kid.clone()));
    assert_eq!(jwks_kids(&issuer), [rotation.kid.as_str()]);
    verify(&issuer, &issuer.sign(&claims()).unwrap()).unwrap();

    // A token from the old key names a kid that is no longer published.
    let old_kid = jsonwebtoken::decode_header(&before).unwrap().kid.unwrap();
    assert_eq!(old_kid, old);
    assert!(!jwks_kids(&issuer).contains(&old_kid));
}

/// Found by running it: a key that an earlier rotation had dated a day out
/// stayed published straight through an emergency rotation. An immediate
/// rotation must unpublish EVERY older key, including one already dated later
/// and one still pending.
#[test]
fn an_immediate_rotation_also_cuts_short_keys_dated_by_an_earlier_rotation() {
    let s = store("cut-short");
    let issuer = s.boot();
    let first = issuer.signing_kid().unwrap();
    let pending = issuer.rotate(None, "test").unwrap();
    assert_eq!(jwks_kids(&issuer).len(), 2);

    s.clock.advance(10);
    let now = T0.plus_secs(10);
    let emergency = issuer.rotate(Some(0), "test").unwrap();

    for row in s.rows() {
        let expected = (row.kid != emergency.kid).then_some(now);
        assert_eq!(row.retire_at, expected, "{}", row.kid);
    }
    assert_eq!(jwks_kids(&issuer), [emergency.kid.as_str()]);
    assert_eq!(issuer.signing_kid(), Some(emergency.kid.clone()));

    // The key that was pending never gets its turn, even once its
    // `activate_at` arrives.
    s.clock.set(Timestamp(pending.activate_at + 1));
    assert_eq!(issuer.signing_kid(), Some(emergency.kid.clone()));
    assert_eq!(jwks_kids(&issuer), [emergency.kid.as_str()]);
    assert!(!jwks_kids(&issuer).contains(&first));
}

/// The other half of the rotation's UPDATE predicate: a key already dated
/// EARLIER than the new end date keeps its date. Rotating never extends how
/// long an old key stays published.
#[test]
fn a_second_rotation_does_not_extend_an_already_dated_key() {
    let s = store("twice");
    let issuer = s.boot();
    let first = issuer.signing_kid().unwrap();
    let second = issuer.rotate(Some(100), "test").unwrap();

    s.clock.advance(1000);
    let third = issuer.rotate(Some(100), "test").unwrap();

    let retire_at = |kid: &str| {
        s.rows()
            .into_iter()
            .find(|r| r.kid == kid)
            .unwrap()
            .retire_at
    };
    assert_eq!(
        retire_at(&first),
        Some(T0.plus_secs(100 + DAY + 300)),
        "dated by the first rotation and not moved by the second"
    );
    assert_eq!(
        retire_at(&second.kid),
        Some(T0.plus_secs(1000 + 100 + DAY + 300)),
        "open-ended until the second rotation dated it"
    );
    assert_eq!(retire_at(&third.kid), None);
    // Exactly one key is open-ended, so there is always one to sign with.
    assert_eq!(s.rows().iter().filter(|r| r.retire_at.is_none()).count(), 1);
}

/// `rotate-signing-key` is another process writing the same file. The running
/// broker converges on it at its next reload, with no signal — and not before.
#[test]
fn a_rotation_made_by_another_process_is_picked_up_at_the_next_reload() {
    let s = store("converge");
    let broker = s.boot();
    let old = broker.signing_kid().unwrap();

    // The CLI: its own connections, its own writer thread, no bootstrap.
    let cli_writer = Writer::spawn(s.connect());
    let cli = Issuer::open(
        Arc::new(Reader::new(s.connect())),
        cli_writer.handle(),
        None,
        Arc::new(s.clock.clone()),
        KeyPolicy::default(),
    )
    .unwrap();
    let rotation = cli.rotate(Some(0), "cli").unwrap();
    assert_eq!(s.rows().len(), 2);

    assert_eq!(broker.signing_kid().as_deref(), Some(old.as_str()));
    s.clock.advance(RELOAD_INTERVAL_SECS - 1);
    assert_eq!(broker.signing_kid().as_deref(), Some(old.as_str()));
    s.clock.advance(1);
    assert_eq!(broker.signing_kid(), Some(rotation.kid.clone()));
    assert_eq!(jwks_kids(&broker), [rotation.kid]);
}

/// `Issuer::open` creates nothing, and with nothing to sign with it says so.
#[test]
fn with_no_key_signing_fails_plainly_and_nothing_is_published() {
    let s = store("empty");
    let (reader, writer, audit, clock) = s.parts();
    let issuer = Issuer::open(reader, writer, audit, clock, KeyPolicy::default()).unwrap();
    assert!(s.rows().is_empty());
    assert!(matches!(
        issuer.sign(&claims()),
        Err(IssuerError::NoSigningKey)
    ));
    assert_eq!(issuer.jwks(), serde_json::json!({ "keys": [] }));
}
