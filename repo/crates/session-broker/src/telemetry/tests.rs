//! Tests for the diagnostics plane.
//!
//! `telemetry::init` installs a process-global subscriber, so it can only
//! succeed once per test binary. Everything here therefore exercises the parts
//! that are testable without installing one — the config parsing, the
//! redaction helper, and the override bookkeeping — and the one test that does
//! install a subscriber tolerates having lost the race.

use super::*;

#[test]
fn ip_prefixes_are_prefixes_and_nothing_more() {
    // INV-12: a full client address is never logged or stored. A /24 answers
    // the only question the record asks of it — "plausibly somewhere else" for
    // INV-6a — without identifying anyone.
    let v4: std::net::IpAddr = "203.0.113.42".parse().unwrap();
    assert_eq!(ip_prefix(&v4), "203.0.113.0/24");
    assert!(
        !ip_prefix(&v4).contains("42"),
        "the host octet must not survive"
    );

    let v6: std::net::IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
    assert_eq!(ip_prefix(&v6), "2001:db8:1234::/48");
    assert!(!ip_prefix(&v6).contains("5678"));
}

#[test]
fn log_format_and_rotation_reject_typos_rather_than_defaulting() {
    // A silent fallback to `text` in a deployment that asked for `json` means
    // the collector parses nothing and nobody finds out until an incident.
    assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
    assert_eq!("TEXT".parse::<LogFormat>().unwrap(), LogFormat::Text);
    assert!("jsonl".parse::<LogFormat>().is_err());

    assert_eq!(
        "daily".parse::<FileRotation>().unwrap(),
        FileRotation::Daily
    );
    assert_eq!(
        "never".parse::<FileRotation>().unwrap(),
        FileRotation::Never
    );
    assert!("weekly".parse::<FileRotation>().is_err());
}

/// The one test that installs a subscriber. It exercises the override
/// lifecycle, which is the part with real consequences: a raised level that
/// never comes down is the failure the deadline exists to prevent.
#[test]
fn a_verbosity_override_is_bounded_and_expires_on_its_own() {
    let control = match init(LogConfig {
        default_filter: "session_broker=info".to_owned(),
        override_max_secs: 60,
        ..LogConfig::default()
    }) {
        Ok(control) => control,
        // Another test in this binary installed one first. Nothing here is
        // worth failing a build over.
        Err(_) => return,
    };

    assert!(!control.override_active());
    assert_eq!(control.effective_filter(), "session_broker=info");

    // Beyond the ceiling: refused, not silently clamped. Clamping would make
    // the console show a duration the broker did not agree to.
    assert!(matches!(
        control.set_override("session_broker=trace", 3_600, 1_000, None),
        Err(LogControlError::TooLong { .. })
    ));
    // Zero is not "forever".
    assert!(control
        .set_override("session_broker=trace", 0, 1_000, None)
        .is_err());
    // A directive that would not parse must be rejected BEFORE it is applied:
    // a filter that fails open logs everything, which on this service is the
    // loudest possible failure.
    assert!(matches!(
        control.set_override("=========", 30, 1_000, None),
        Err(LogControlError::BadFilter(_))
    ));
    assert!(!control.override_active(), "a refusal must change nothing");

    let entry = control
        .set_override("session_broker=trace", 30, 1_000, Some("admin".to_owned()))
        .expect("a valid, in-range override is accepted");
    assert_eq!(entry.expires_at, 1_030);
    assert!(control.override_active());
    assert_eq!(control.effective_filter(), "session_broker=trace");

    // Not yet due.
    assert!(!control.expire_due_override(1_029));
    assert!(control.override_active());

    // Due: restored without anyone asking.
    assert!(control.expire_due_override(1_030));
    assert!(!control.override_active());
    assert_eq!(control.effective_filter(), "session_broker=info");

    // Restoring when nothing is overridden is a no-op, not an error — two
    // operators pressing "restore now" must not produce a failure.
    assert!(!control.restore().unwrap());
}

/// INV-12, enforced against the LOG STREAM rather than by inspection.
///
/// The audit-row half of this invariant already has a test
/// (`audit::tests::no_builder_method_can_put_secret_material_in_a_row`). This is
/// the half that was still resting on a hand check: audit events are *also*
/// emitted to `broker::audit` (ADR-0014's fail-open archive path), and that path
/// formats every field itself. A row can be clean while the line beside it is
/// not.
///
/// It works by installing a scoped subscriber over an in-memory writer rather
/// than calling `init`, which is process-global and single-shot.
#[test]
fn no_secret_material_reaches_the_log_stream() {
    use crate::audit::{ActorKind, AuditConfig, AuditSink, Event, Outcome};
    use crate::clock::Timestamp;
    use crate::store::writer::Writer;
    use std::sync::{Arc, Mutex};

    /// A `MakeWriter` over a shared buffer, so the test can read back exactly
    /// the bytes a real sink would have received.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Captured {
            self.clone()
        }
    }

    // Fixtures shaped like the real thing, so a substring match is meaningful.
    const COOKIE: &str = "S3cr3tCookieValue_aaaaaaaaaaaaaaaaaaaaaaaa";
    const ACCESS_TOKEN: &str = "at_S3cr3tAccessToken_bbbbbbbbbbbbbbbbbbbb";
    const REFRESH_TOKEN: &str = "rt_S3cr3tRefreshToken_cccccccccccccccccc";
    const API_KEY: &str = "sk_S3cr3tApiKeySecret_dddddddddddddddddddd";
    const PKCE_VERIFIER: &str = "pkce_S3cr3tVerifier_eeeeeeeeeeeeeeeeeeee";

    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(captured.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let conn = crate::store::open_in_memory().unwrap();
        let writer = Writer::spawn(conn);
        let sink = AuditSink::new(writer.handle(), Metrics::new(), AuditConfig::default());

        // Drive both tiers, with every builder field populated. If a future
        // field ever forwards raw material into the log line, one of these
        // assertions is what catches it.
        let event = || {
            Event::new(
                crate::audit::action::TOKEN_EXCHANGED,
                Outcome::Success,
                ActorKind::Backend,
                Timestamp(1_700_000_000),
            )
            .actor_id("bk_visible")
            .key_id("bk_visible")
            .subject("user-1")
            .sid("sid-visible")
            .custody_id("cust-visible")
            .reason("ok")
            .client_ip_prefix("203.0.113.0/24")
            .detail(serde_json::json!({ "name": "envoy-edge" }))
        };
        sink.record(event());
        let _ = sink.transactional(event());

        // And the ordinary log paths that sit closest to credential material.
        tracing::info!(target: "broker::http", lane = "public", route = "/session/refresh", status = 200, "request");
        tracing::warn!(target: "broker::authz", reason = "session_not_active", "denied");

        drop(writer);
    });

    let bytes = captured.0.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.is_empty(), "the capture harness itself must work");

    for (label, secret) in [
        ("session cookie", COOKIE),
        ("upstream access token", ACCESS_TOKEN),
        ("upstream refresh token", REFRESH_TOKEN),
        ("api key secret", API_KEY),
        ("pkce verifier", PKCE_VERIFIER),
    ] {
        assert!(
            !text.contains(secret),
            "INV-12: {label} reached the log stream:\n{text}"
        );
    }

    // A full client address must not survive either — only the prefix.
    assert!(
        !text.contains("203.0.113.42"),
        "INV-12: a full client IP was logged"
    );

    // The identifiers that ARE permitted must be present, or this test would
    // pass just as well against a subscriber that emitted nothing at all.
    assert!(
        text.contains("sid-visible"),
        "permitted identifiers must still be logged"
    );
    assert!(text.contains("bk_visible"));
    assert!(text.contains("203.0.113.0/24"));
}

/// The default filter must actually pass the broker's own event targets.
///
/// This existed as a bug and nothing caught it. Events here carry explicit
/// targets — `broker::audit`, `broker::http`, `broker::authz`,
/// `broker::telemetry` — and an `EnvFilter` directive matches the TARGET, not
/// the crate that emitted it. So `session_broker=info` matched every
/// module-path event and silently dropped every named one, including the audit
/// stream ADR-0014 calls the long-term archive: a deployment shipping logs to a
/// SIEM for seven-year retention would have archived nothing at all.
///
/// The redaction test next door did not catch it because it installs a
/// subscriber with `max_level(TRACE)` and no `EnvFilter`, so it exercises the
/// formatter rather than the filter.
#[test]
fn the_default_filter_passes_every_broker_event_target() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let filter = LogConfig::default().default_filter;

    for target in [
        "broker::audit",
        "broker::http",
        "broker::authz",
        "broker::telemetry",
    ] {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));

        #[derive(Clone)]
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let mut g = self.0.lock().unwrap();
                g.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Sink;
            fn make_writer(&'a self) -> Sink {
                self.clone()
            }
        }

        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::try_new(&filter).expect("the shipped default must parse"))
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(Sink(captured.clone())),
            );

        tracing::subscriber::with_default(subscriber, || match target {
            "broker::audit" => tracing::info!(target: "broker::audit", action = "probe", "audit"),
            "broker::http" => {
                tracing::warn!(target: "broker::http", route = "/probe", "request failed")
            }
            "broker::authz" => tracing::warn!(target: "broker::authz", reason = "probe", "denied"),
            _ => tracing::warn!(target: "broker::telemetry", "probe"),
        });

        let out = String::from_utf8_lossy(&captured.lock().unwrap().clone()).to_string();
        assert!(
            out.contains(target),
            "the default filter {filter:?} drops target {target:?} — anything logged \
             under it reaches no sink at all"
        );
    }
}
