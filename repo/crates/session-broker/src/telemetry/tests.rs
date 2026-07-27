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

    assert_eq!("daily".parse::<FileRotation>().unwrap(), FileRotation::Daily);
    assert_eq!("never".parse::<FileRotation>().unwrap(), FileRotation::Never);
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
    assert_eq!(control.restore().unwrap(), false);
}
