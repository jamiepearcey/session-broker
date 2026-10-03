use super::*;

fn quota() -> Quota {
    // 3 requests per minute: small enough to exhaust in a test, shaped like a
    // real brute-force budget.
    Quota::new(3, 60)
}

#[test]
fn a_burst_is_allowed_then_refused() {
    let l = Limiter::new(quota(), 100);
    let t0 = Instant::now();

    for i in 0..3 {
        assert!(
            l.check_at("k", t0).is_allowed(),
            "request {i} is within the burst"
        );
    }
    let Decision::Deny { retry_after } = l.check_at("k", t0) else {
        panic!("the fourth must be refused");
    };
    assert!(
        retry_after > Duration::ZERO && retry_after <= Duration::from_secs(60),
        "Retry-After must be actionable, got {retry_after:?}"
    );
}

#[test]
fn the_budget_refills_gradually_not_all_at_once() {
    let l = Limiter::new(quota(), 100);
    let t0 = Instant::now();
    for _ in 0..3 {
        assert!(l.check_at("k", t0).is_allowed());
    }

    // A third of the window restores roughly one of three tokens.
    let t1 = t0 + Duration::from_secs(20);
    assert!(l.check_at("k", t1).is_allowed(), "one token has come back");
    assert!(
        !l.check_at("k", t1).is_allowed(),
        "but only one — a fixed window would have handed back the whole budget \
         at the boundary, which is the burst this shape exists to avoid"
    );

    // A full window restores everything.
    let t2 = t0 + Duration::from_secs(120);
    for _ in 0..3 {
        assert!(l.check_at("k", t2).is_allowed());
    }
}

#[test]
fn keys_are_independent_so_one_caller_cannot_lock_out_another() {
    let l = Limiter::new(quota(), 100);
    let t0 = Instant::now();
    for _ in 0..3 {
        assert!(l.check_at("attacker", t0).is_allowed());
    }
    assert!(!l.check_at("attacker", t0).is_allowed());
    assert!(
        l.check_at("bystander", t0).is_allowed(),
        "an exhausted key must not affect anyone else"
    );
}

/// The bound must not be an escape hatch. Filling the table with keys that are
/// mid-spend and then presenting a fresh one has to be refused, not served —
/// otherwise "make up a new key each time" bypasses the limiter entirely, and
/// growing instead turns that into memory exhaustion.
#[test]
fn a_full_table_of_active_keys_fails_closed() {
    let l = Limiter::new(quota(), 4);
    let t0 = Instant::now();

    // Four distinct keys, each having spent one token, so none is refillable.
    for i in 0..4 {
        assert!(l.check_at(&format!("k{i}"), t0).is_allowed());
    }
    assert_eq!(l.tracked(), 4);

    assert!(
        !l.check_at("k-new", t0).is_allowed(),
        "a new key at capacity must be refused rather than admitted or grown into"
    );
    assert_eq!(l.tracked(), 4, "and the table must not have grown");
}

/// The other half: buckets that have fully refilled carry no information, so
/// evicting them is free and keeps the table from wedging permanently.
#[test]
fn fully_refilled_buckets_are_evicted_to_make_room() {
    let l = Limiter::new(quota(), 4);
    let t0 = Instant::now();
    for i in 0..4 {
        assert!(l.check_at(&format!("k{i}"), t0).is_allowed());
    }

    // Well past a full window: every existing bucket is back to full.
    let later = t0 + Duration::from_secs(600);
    assert!(
        l.check_at("k-new", later).is_allowed(),
        "a new key must be admitted once old buckets have nothing left to say"
    );
    assert!(l.tracked() <= 4, "and the bound must still hold");
}

#[test]
fn a_client_ip_header_takes_the_last_value_not_the_first() {
    let src = ClientSource::Header("x-forwarded-for".to_owned());
    let mut headers = axum::http::HeaderMap::new();
    // The first entry is whatever the CLIENT sent. Keying on it would let an
    // attacker mint a fresh budget per request by varying a header they control.
    headers.insert(
        "x-forwarded-for",
        "203.0.113.9, 198.51.100.7".parse().unwrap(),
    );

    assert_eq!(
        src.key(None, &headers).as_deref(),
        Some("198.51.100.7"),
        "the last entry is what the nearest trusted proxy observed"
    );
}

#[test]
fn a_missing_configured_header_yields_no_key_rather_than_the_peer() {
    let src = ClientSource::Header("x-forwarded-for".to_owned());
    let headers = axum::http::HeaderMap::new();
    let peer: std::net::SocketAddr = "203.0.113.1:1234".parse().unwrap();

    assert_eq!(
        src.key(Some(&peer), &headers),
        None,
        "falling back to the peer is how a limiter configured for a proxied \
         deployment quietly starts bucketing every user together"
    );
}

#[test]
fn the_peer_source_keys_on_the_address_without_the_port() {
    let src = ClientSource::Peer;
    let peer: std::net::SocketAddr = "203.0.113.1:54321".parse().unwrap();
    assert_eq!(
        src.key(Some(&peer), &axum::http::HeaderMap::new())
            .as_deref(),
        Some("203.0.113.1"),
        "the port changes per connection; keying on it would give every new \
         connection a fresh budget"
    );
}
