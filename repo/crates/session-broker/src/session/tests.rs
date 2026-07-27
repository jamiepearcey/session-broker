//! Tests for the session state machine.
//!
//! Everything here is deterministic: time is an argument, never a sleep. The
//! cases map directly onto the state table in
//! `docs/architecture/implementation-strategy.md` §3 and the invariants in
//! `.context/invariants.md`.

use super::*;
use crate::clock::Timestamp;

const T0: Timestamp = Timestamp(1_700_000_000);

fn map() -> SessionMap {
    SessionMap::new(SessionPolicy::default())
}

fn new_session(m: &SessionMap, now: Timestamp) -> (Sid, SessionToken) {
    let sid = Sid("s1".into());
    let issued = m.create(sid.clone(), CustodyId("c1".into()), "user-42".into(), now);
    (sid, issued.token)
}

fn at(offset: u64) -> Timestamp {
    T0.plus_secs(offset)
}

// --- the state table ------------------------------------------------------

#[test]
fn a_fresh_session_is_active() {
    let m = map();
    let (sid, token) = new_session(&m, T0);
    assert_eq!(
        m.resolve(&token.hash(), T0),
        Resolution::Active {
            sid,
            gen_no: 1,
            newest: true
        }
    );
}

#[test]
fn an_unknown_token_is_unknown() {
    let m = map();
    new_session(&m, T0);
    let stranger = SessionToken::generate();
    assert_eq!(m.resolve(&stranger.hash(), T0), Resolution::Unknown);
}

#[test]
fn the_current_generation_goes_stale_but_stays_refreshable() {
    let m = map();
    let (sid, token) = new_session(&m, T0);

    // One second before gen_ttl: still authenticating resource access.
    assert!(m.resolve(&token.hash(), at(599)).authenticates());

    // Past gen_ttl the tab wakes into STALE-REFRESHABLE: no resource access,
    // but refresh must still work. This is the sleeping-tab path.
    assert_eq!(
        m.resolve(&token.hash(), at(601)),
        Resolution::StaleRefreshable { sid, gen_no: 1 }
    );
    let issued = m.refresh(&token.hash(), at(601)).expect("stale refreshes");
    assert!(issued.rotated);
    assert_eq!(issued.meta.gen, 2);
}

#[test]
fn idle_expiry_hard_expires_the_session() {
    let m = map();
    let (sid, token) = new_session(&m, T0);
    let idle = SessionPolicy::default().idle_ttl_secs;

    assert_eq!(
        m.resolve(&token.hash(), at(idle + 1)),
        Resolution::HardExpired {
            sid: sid.clone(),
            reason: ExpiredReason::Idle
        }
    );
    assert_eq!(
        m.refresh(&token.hash(), at(idle + 1)).unwrap_err(),
        RefreshDenied::Expired {
            sid,
            reason: ExpiredReason::Idle
        }
    );
}

#[test]
fn refreshing_slides_idle_expiry_but_never_past_the_absolute_ceiling() {
    let policy = SessionPolicy {
        idle_ttl_secs: 100,
        absolute_ttl_secs: 150,
        gen_ttl_secs: 10,
        coalesce_secs: 5,
        ..SessionPolicy::default()
    };
    let m = SessionMap::new(policy);
    let (_, token) = new_session(&m, T0);

    let issued = m.refresh(&token.hash(), at(50)).unwrap();
    // now + idle_ttl would be 150, and the absolute ceiling is also 150.
    assert_eq!(issued.meta.refresh_until, at(150).secs());
    assert_eq!(issued.meta.absolute_until, at(150).secs());

    let issued = m.refresh(&issued.token.hash(), at(120)).unwrap();
    // now + idle_ttl would be 220; the ceiling wins.
    assert_eq!(issued.meta.refresh_until, at(150).secs());
}

#[test]
fn absolute_expiry_cannot_be_slid_away() {
    let policy = SessionPolicy {
        idle_ttl_secs: 100,
        absolute_ttl_secs: 150,
        gen_ttl_secs: 10,
        coalesce_secs: 5,
        ..SessionPolicy::default()
    };
    let m = SessionMap::new(policy);
    let (sid, token) = new_session(&m, T0);

    // Keep the session alive across the idle window so that the *absolute*
    // ceiling is what finally stops it.
    let issued = m.refresh(&token.hash(), at(50)).unwrap();
    let issued = m.refresh(&issued.token.hash(), at(120)).unwrap();
    assert_eq!(
        m.resolve(&issued.token.hash(), at(151)),
        Resolution::HardExpired {
            sid,
            reason: ExpiredReason::Absolute
        }
    );
}

// --- INV-6: non-invalidating rotation ------------------------------------

#[test]
fn rotation_keeps_the_previous_generation_valid_for_the_grace_window() {
    let m = map();
    let (_, gen1) = new_session(&m, T0);

    // Past the coalesce window so this genuinely rotates.
    let gen2 = m.refresh(&gen1.hash(), at(31)).unwrap();
    assert!(gen2.rotated);
    assert_eq!(gen2.meta.gen, 2);

    // The old cookie still authenticates for `grace` seconds. This is the whole
    // point of the design.
    assert!(m.resolve(&gen1.hash(), at(31)).authenticates());
    assert!(m.resolve(&gen1.hash(), at(90)).authenticates());
    assert!(matches!(
        m.resolve(&gen1.hash(), at(31)),
        Resolution::Active { newest: false, .. }
    ));

    // Once grace closes it is retired — denied, and reported precisely enough
    // for an anomaly event (INV-6a) rather than as an unknown token.
    assert!(matches!(
        m.resolve(&gen1.hash(), at(92)),
        Resolution::Retired { gen_no: 1, .. }
    ));
    assert!(matches!(
        m.refresh(&gen1.hash(), at(92)),
        Err(RefreshDenied::Retired { gen_no: 1, .. })
    ));

    // ...while the new generation carries on regardless.
    assert!(m.resolve(&gen2.token.hash(), at(92)).authenticates());
}

/// The oauth2-proxy failure mode, as a named regression test: two concurrent
/// refreshes both carrying the pre-rotation cookie. Both must succeed. Under
/// rotation-with-invalidation the second would be logged out.
#[test]
fn concurrent_refreshes_with_the_old_cookie_both_succeed() {
    let m = map();
    let (_, gen1) = new_session(&m, T0);

    let first = m.refresh(&gen1.hash(), at(31)).expect("first refresh");
    let second = m.refresh(&gen1.hash(), at(31)).expect("second refresh");

    // Both callers get a usable cookie...
    assert!(m.resolve(&first.token.hash(), at(31)).authenticates());
    assert!(m.resolve(&second.token.hash(), at(31)).authenticates());
    // ...and the second coalesced onto the generation the first minted rather
    // than starting a rotation storm.
    assert!(!second.rotated);
    assert_eq!(first.meta.gen, second.meta.gen);
    assert_eq!(
        first.token.expose_for_cookie(),
        second.token.expose_for_cookie()
    );
}

#[test]
fn many_concurrent_refreshes_mint_exactly_once() {
    let m = map();
    let (_, gen1) = new_session(&m, T0);

    // 20 tabs waking together, all presenting the same cookie at the same
    // instant, as the demo app's forced-race button does.
    let issued: Vec<_> = (0..20)
        .map(|_| m.refresh(&gen1.hash(), at(31)).expect("refresh succeeds"))
        .collect();

    assert_eq!(issued.iter().filter(|i| i.rotated).count(), 1);
    assert!(issued.iter().all(|i| i.meta.gen == 2));
    for i in &issued {
        assert!(m.resolve(&i.token.hash(), at(31)).authenticates());
    }
}

#[test]
fn coalescing_stops_once_the_window_closes() {
    let policy = SessionPolicy {
        coalesce_secs: 30,
        gen_ttl_secs: 600,
        ..SessionPolicy::default()
    };
    let m = SessionMap::new(policy);
    let (_, gen1) = new_session(&m, T0);

    // Inside the window of gen 1's own birth: no new generation at all.
    let a = m.refresh(&gen1.hash(), at(29)).unwrap();
    assert!(!a.rotated);
    assert_eq!(a.meta.gen, 1);

    // Outside it: rotate.
    let b = m.refresh(&gen1.hash(), at(31)).unwrap();
    assert!(b.rotated);
    assert_eq!(b.meta.gen, 2);
}

#[test]
fn live_generations_are_capped() {
    let policy = SessionPolicy {
        coalesce_secs: 0,
        grace_secs: 3_600,
        gen_ttl_secs: 3_600,
        max_live_gens: 4,
        ..SessionPolicy::default()
    };
    let m = SessionMap::new(policy);
    let (sid, first) = new_session(&m, T0);

    // Rotate pathologically. With a grace window longer than the whole test,
    // only the cap can bound the live set.
    let mut token = first;
    let mut history = vec![token.hash()];
    for step in 1..=12 {
        token = m.refresh(&token.hash(), at(step)).unwrap().token;
        history.push(token.hash());
    }

    let live = history
        .iter()
        .filter(|h| m.resolve(h, at(13)).authenticates())
        .count();
    assert!(live <= 4, "live generations {live} exceeded the cap");

    // Capped-out generations are retired rather than forgotten, so a client
    // presenting one gets a precise answer — but only for as long as the
    // bounded retirement memory holds it. Beyond that the token is simply
    // unknown, which is the intended and documented end state.
    let recently_retired = history[history.len() - 5];
    assert!(matches!(
        m.resolve(&recently_retired, at(13)),
        Resolution::Retired { .. }
    ));
    assert_eq!(m.resolve(&history[0], at(13)), Resolution::Unknown);
    assert_eq!(m.len(), 1);
    assert!(m.resolve(&token.hash(), at(13)).authenticates());
    let _ = sid;
}

// --- INV-7: logout ---------------------------------------------------------

#[test]
fn logout_kills_every_generation_at_once() {
    let m = map();
    let (sid, gen1) = new_session(&m, T0);
    let gen2 = m.refresh(&gen1.hash(), at(31)).unwrap();
    let gen3 = m.refresh(&gen2.token.hash(), at(62)).unwrap();

    assert!(m.tombstone_session(&sid, at(70)));

    for hash in [gen1.hash(), gen2.token.hash(), gen3.token.hash()] {
        assert_eq!(
            m.resolve(&hash, at(70)),
            Resolution::HardExpired {
                sid: sid.clone(),
                reason: ExpiredReason::LoggedOut
            }
        );
        assert!(m.refresh(&hash, at(70)).is_err());
    }

    // Idempotent: logging out twice is not an error, it simply changes nothing.
    assert!(!m.tombstone_session(&sid, at(71)));
}

#[test]
fn a_tombstoned_session_is_collected_after_grace_then_forgotten() {
    let m = map();
    let (sid, token) = new_session(&m, T0);
    m.tombstone_session(&sid, at(10));

    // Within grace it still answers precisely, so late requests get a clean
    // "logged out" rather than an ambiguous "unknown".
    let (removed, _) = m.sweep(at(30));
    assert_eq!(removed, 0);
    assert!(matches!(
        m.resolve(&token.hash(), at(30)),
        Resolution::HardExpired { .. }
    ));

    let (removed, _) = m.sweep(at(200));
    assert_eq!(removed, 1);
    assert_eq!(m.resolve(&token.hash(), at(200)), Resolution::Unknown);
    assert!(m.is_empty());
}

// --- custody ---------------------------------------------------------------

#[test]
fn a_dead_custody_kills_sessions_under_the_default_policy() {
    let m = map();
    let (sid, token) = new_session(&m, T0);
    let custody = CustodyId("c1".into());

    assert_eq!(m.set_custody_status(&custody, CustodyStatus::Degraded), 1);
    // Degraded is not fatal: session auth does not depend on upstream liveness.
    assert!(m.resolve(&token.hash(), at(5)).authenticates());
    assert_eq!(
        m.meta_for(&token.hash()).unwrap().custody,
        CustodyStatus::Degraded
    );

    m.set_custody_status(&custody, CustodyStatus::Dead);
    assert_eq!(
        m.resolve(&token.hash(), at(6)),
        Resolution::HardExpired {
            sid: sid.clone(),
            reason: ExpiredReason::UpstreamRevoked
        }
    );

    assert_eq!(m.tombstone_by_custody(&custody, at(6)), 1);
    assert_eq!(
        m.resolve(&token.hash(), at(6)),
        Resolution::HardExpired {
            sid,
            reason: ExpiredReason::LoggedOut
        }
    );
}

#[test]
fn degrade_policy_keeps_sessions_alive_with_dead_custody() {
    let m = SessionMap::new(SessionPolicy {
        on_upstream_revoked: RevocationPolicy::Degrade,
        ..SessionPolicy::default()
    });
    let (_, token) = new_session(&m, T0);
    m.set_custody_status(&CustodyId("c1".into()), CustodyStatus::Dead);

    assert!(m.resolve(&token.hash(), at(5)).authenticates());
    let meta = m.refresh(&token.hash(), at(31)).unwrap().meta;
    assert_eq!(meta.custody, CustodyStatus::Dead);
}

#[test]
fn tombstone_by_custody_covers_every_session_it_backs() {
    let m = map();
    let custody = CustodyId("shared".into());
    for n in 0..3 {
        m.create(Sid(format!("s{n}")), custody.clone(), "user-42".into(), T0);
    }
    assert_eq!(m.tombstone_by_custody(&custody, at(1)), 3);
    assert_eq!(m.tombstone_by_custody(&custody, at(2)), 0);
}

// --- meta cookie -----------------------------------------------------------

#[test]
fn meta_payload_matches_the_documented_contract() {
    let m = map();
    let (_, token) = new_session(&m, T0);
    let meta = m.meta_for(&token.hash()).unwrap();

    // Asserted on the wire form, since that is what the cookie carries.
    let wire = serde_json::to_string(&meta).unwrap();
    assert_eq!(
        wire,
        format!(
            r#"{{"v":1,"sub":"user-42","sid":"s1","gen":1,"active_until":{},"refresh_until":{},"absolute_until":{},"custody":"ok"}}"#,
            at(600).secs(),
            at(SessionPolicy::default().idle_ttl_secs).secs(),
            at(SessionPolicy::default().absolute_ttl_secs).secs(),
        )
    );

    // And it round-trips, because the client SDK parses exactly this.
    let parsed: SessionMeta = serde_json::from_str(&wire).unwrap();
    assert_eq!(parsed, meta);
}

#[test]
fn coalesced_refresh_does_not_extend_the_generation() {
    let m = map();
    let (_, token) = new_session(&m, T0);
    let issued = m.refresh(&token.hash(), at(10)).unwrap();

    // The client is told the truth: coalescing hands back the same cookie with
    // the same deadline, so its timer stays anchored to the real expiry.
    assert!(!issued.rotated);
    assert_eq!(issued.meta.active_until, at(600).secs());
}

// --- sweep -----------------------------------------------------------------

#[test]
fn sweep_retires_dead_generations_without_touching_the_current_one() {
    let m = map();
    let (_, gen1) = new_session(&m, T0);
    let gen2 = m.refresh(&gen1.hash(), at(31)).unwrap();

    let (removed, retired) = m.sweep(at(200));
    assert_eq!(removed, 0);
    assert_eq!(retired, 1);
    assert!(m.resolve(&gen2.token.hash(), at(200)).authenticates());
    assert!(matches!(
        m.resolve(&gen1.hash(), at(200)),
        Resolution::Retired { .. }
    ));
}

// --- property test ---------------------------------------------------------

use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Action {
    Refresh,
    Advance(u64),
    Resolve,
    Logout,
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        4 => Just(Action::Refresh),
        4 => (1u64..400).prop_map(Action::Advance),
        3 => Just(Action::Resolve),
        1 => Just(Action::Logout),
    ]
}

proptest! {
    /// Random interleavings of refresh, time advance, resolve and logout. The
    /// invariants asserted here are the ones the whole design rests on.
    #[test]
    fn interleavings_preserve_the_core_invariants(actions in prop::collection::vec(action(), 1..60)) {
        let m = map();
        let (sid, first) = new_session(&m, T0);
        let mut now = T0;
        let mut held = first.hash();
        let mut issued_hashes = vec![held];
        let mut logged_out = false;

        for act in actions {
            match act {
                Action::Advance(secs) => now = now.plus_secs(secs),
                Action::Resolve => {
                    let r = m.resolve(&held, now);
                    if logged_out {
                        // INV-7: nothing survives a logout.
                        prop_assert!(!r.authenticates());
                    }
                }
                Action::Logout => {
                    m.tombstone_session(&sid, now);
                    logged_out = true;
                }
                Action::Refresh => match m.refresh(&held, now) {
                    Ok(issued) => {
                        prop_assert!(!logged_out, "a tombstoned session refreshed");
                        // A token is always immediately usable when issued.
                        prop_assert!(m.resolve(&issued.token.hash(), now).authenticates());
                        held = issued.token.hash();
                        // Coalescing hands back the same token, so track the
                        // distinct set — counting duplicates would overstate the
                        // live generation count.
                        if !issued_hashes.contains(&held) {
                            issued_hashes.push(held);
                        }
                    }
                    Err(_) => {
                        // Denial is only ever permanent-or-later: a denied token
                        // must never resolve as usable at the same instant.
                        prop_assert!(!m.resolve(&held, now).authenticates());
                    }
                },
            }

            // INV-6: the live set stays bounded no matter the interleaving.
            let live = issued_hashes
                .iter()
                .filter(|h| m.resolve(h, now).authenticates())
                .count();
            prop_assert!(live <= m.policy().max_live_gens, "live={live}");
        }
    }

    /// Nothing ever comes back from the dead: once a token has been observed to
    /// stop authenticating, no later activity may make it authenticate again.
    #[test]
    fn tokens_never_resurrect(steps in prop::collection::vec(1u64..300, 1..40)) {
        use std::collections::HashSet;

        let m = map();
        let (_, first) = new_session(&m, T0);
        let mut now = T0;
        let mut held = first.hash();
        let mut issued_hashes = vec![held];
        let mut seen_dead: HashSet<TokenHash> = HashSet::new();

        for step in steps {
            now = now.plus_secs(step);
            if let Ok(issued) = m.refresh(&held, now) {
                held = issued.token.hash();
                if !issued_hashes.contains(&held) {
                    issued_hashes.push(held);
                }
            }
            for hash in &issued_hashes {
                if m.resolve(hash, now).authenticates() {
                    prop_assert!(
                        !seen_dead.contains(hash),
                        "a token resurrected after being observed dead"
                    );
                } else {
                    seen_dead.insert(*hash);
                }
            }
        }
    }
}
