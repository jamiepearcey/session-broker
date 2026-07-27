//! Tests for the event stream.
//!
//! The stream is a hint channel, so the properties worth pinning are: it is
//! authenticated, it never crosses sessions, and it announces exactly once per
//! real state change — from the map itself, not from whichever handler happened
//! to cause it.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

use super::*;
use crate::clock::{Clock, TestClock, Timestamp};
use crate::session::{
    CustodyId, CustodyStatus, KillReason, SessionEvent, SessionMap, SessionPolicy, Sid,
};

const T0: Timestamp = Timestamp(1_700_000_000);
const ORIGIN: &str = "https://app.example.com";

/// Records what the map announced, so kill paths can be asserted without a
/// runtime or a socket.
#[derive(Default)]
struct Recorder(Mutex<Vec<SessionEvent>>);

impl Recorder {
    fn events(&self) -> Vec<SessionEvent> {
        self.0.lock().unwrap().clone()
    }
}

impl SessionObserver for Recorder {
    fn on_event(&self, event: SessionEvent) {
        self.0.lock().unwrap().push(event);
    }
}

fn map_with_recorder() -> (Arc<SessionMap>, Arc<Recorder>) {
    let map = Arc::new(SessionMap::new(SessionPolicy::default()));
    let recorder = Arc::new(Recorder::default());
    map.set_observer(recorder.clone());
    (map, recorder)
}

// --- what gets announced ---------------------------------------------------

#[test]
fn logout_announces_once_with_its_reason() {
    let (map, rec) = map_with_recorder();
    let sid = Sid("s1".into());
    map.create(sid.clone(), CustodyId("c1".into()), "user-1".into(), T0);

    assert!(map.tombstone_session(&sid, T0));
    assert_eq!(
        rec.events(),
        vec![SessionEvent::SessionKilled {
            sid: sid.clone(),
            reason: KillReason::LoggedOut
        }]
    );

    // Idempotent logout must not announce a second death.
    assert!(!map.tombstone_session(&sid, T0));
    assert_eq!(rec.events().len(), 1);
}

#[test]
fn upstream_revocation_announces_every_session_it_kills_with_the_right_reason() {
    let (map, rec) = map_with_recorder();
    let custody = CustodyId("shared".into());
    for n in 0..3 {
        map.create(Sid(format!("s{n}")), custody.clone(), "user-1".into(), T0);
    }

    assert_eq!(map.tombstone_by_custody(&custody, T0), 3);
    let events = rec.events();
    assert_eq!(events.len(), 3);
    assert!(events.iter().all(|e| matches!(
        e,
        SessionEvent::SessionKilled {
            reason: KillReason::UpstreamRevoked,
            ..
        }
    )));
}

#[test]
fn custody_health_is_announced_only_when_it_actually_changes() {
    let (map, rec) = map_with_recorder();
    let custody = CustodyId("c1".into());
    map.create(Sid("s1".into()), custody.clone(), "user-1".into(), T0);

    map.set_custody_status(&custody, CustodyStatus::Degraded);
    map.set_custody_status(&custody, CustodyStatus::Degraded); // no change
    map.set_custody_status(&custody, CustodyStatus::Dead);

    assert_eq!(
        rec.events(),
        vec![
            SessionEvent::CustodyChanged {
                sid: Sid("s1".into()),
                custody: CustodyStatus::Degraded
            },
            SessionEvent::CustodyChanged {
                sid: Sid("s1".into()),
                custody: CustodyStatus::Dead
            },
        ]
    );
}

#[test]
fn a_map_with_no_observer_still_kills_sessions() {
    // The event channel must never be load-bearing.
    let map = SessionMap::new(SessionPolicy::default());
    let sid = Sid("s1".into());
    let issued = map.create(sid.clone(), CustodyId("c1".into()), "user-1".into(), T0);
    assert!(map.tombstone_session(&sid, T0));
    assert!(!map.resolve(&issued.token.hash(), T0).authenticates());
}

// --- fan-out ---------------------------------------------------------------

#[tokio::test]
async fn a_subscriber_sees_only_its_own_session() {
    let map = Arc::new(SessionMap::new(SessionPolicy::default()));
    let events = SessionEvents::new();
    map.set_observer(events.clone());

    let mine = Sid("mine".into());
    let theirs = Sid("theirs".into());
    map.create(mine.clone(), CustodyId("c1".into()), "me".into(), T0);
    map.create(theirs.clone(), CustodyId("c2".into()), "them".into(), T0);

    let mut rx = events.subscribe();

    // Kill the *other* session first; it must not surface on this stream.
    map.tombstone_session(&theirs, T0);
    map.tombstone_session(&mine, T0);

    // The raw channel carries both; the per-session filter is what separates
    // them, so assert on the filter's own predicate.
    let first = rx.recv().await.unwrap();
    let second = rx.recv().await.unwrap();
    let for_me: Vec<_> = [first, second]
        .into_iter()
        .filter(|e| e.sid() == &mine)
        .collect();

    assert_eq!(
        for_me,
        vec![SessionEvent::SessionKilled {
            sid: mine,
            reason: KillReason::LoggedOut
        }]
    );
}

#[test]
fn the_wire_payload_matches_the_documented_contract() {
    let killed = SessionEvent::SessionKilled {
        sid: Sid("abc".into()),
        reason: KillReason::UpstreamRevoked,
    };
    assert_eq!(killed.name(), "session.killed");
    assert_eq!(
        serde_json::to_string(&payload(&killed)).unwrap(),
        r#"{"reason":"upstream_revoked","sid":"abc"}"#
    );

    let custody = SessionEvent::CustodyChanged {
        sid: Sid("abc".into()),
        custody: CustodyStatus::Degraded,
    };
    assert_eq!(custody.name(), "custody.changed");
    assert_eq!(
        serde_json::to_string(&payload(&custody)).unwrap(),
        r#"{"custody":"degraded","sid":"abc"}"#
    );
}

// --- the endpoint ----------------------------------------------------------

fn harness() -> (axum::Router, Arc<SessionMap>, TestClock) {
    let clock = TestClock::new(T0);
    let policy = SessionPolicy::default();
    let sessions = Arc::new(SessionMap::new(policy));
    let events = SessionEvents::new();
    sessions.set_observer(events.clone());
    let state = AppState {
        sessions: sessions.clone(),
        clock: Arc::new(clock.clone()),
        config: Arc::new(super::super::HttpConfig::new(ORIGIN, &policy).unwrap()),
        custody: None,
        audit: None,
        metrics: crate::telemetry::Metrics::new(),
    };
    let router = super::super::router(state).layer(Extension(events));
    (router, sessions, clock)
}

async fn status_of(router: &axum::Router, cookie: Option<&str>) -> StatusCode {
    let mut req = Request::builder()
        .method("GET")
        .uri("/session/events")
        .header("sec-fetch-site", "same-origin");
    if let Some(c) = cookie {
        req = req.header("cookie", format!("__Host-broker_session={c}"));
    }
    router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn the_stream_requires_a_live_session() {
    let (router, sessions, clock) = harness();

    assert_eq!(status_of(&router, None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        status_of(&router, Some("not-a-real-token")).await,
        StatusCode::UNAUTHORIZED
    );

    let sid = Sid("s1".into());
    let issued = sessions.create(sid.clone(), CustodyId("c1".into()), "user-1".into(), T0);
    let token = issued.token.expose_for_cookie().to_owned();
    assert_eq!(status_of(&router, Some(&token)).await, StatusCode::OK);

    // A killed session loses its stream too.
    sessions.tombstone_session(&sid, clock.now());
    assert_eq!(
        status_of(&router, Some(&token)).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_stale_but_refreshable_session_may_still_subscribe() {
    // The sleeping tab is exactly the one that most needs to be woken.
    let (router, sessions, clock) = harness();
    let issued = sessions.create(
        Sid("s1".into()),
        CustodyId("c1".into()),
        "user-1".into(),
        T0,
    );
    clock.advance(601); // past gen_ttl, still well inside idle expiry
    assert_eq!(
        status_of(&router, Some(issued.token.expose_for_cookie())).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_cross_origin_subscription_is_refused() {
    let (router, sessions, _clock) = harness();
    let issued = sessions.create(
        Sid("s1".into()),
        CustodyId("c1".into()),
        "user-1".into(),
        T0,
    );
    let request = Request::builder()
        .method("GET")
        .uri("/session/events")
        .header("sec-fetch-site", "cross-site")
        .header(
            "cookie",
            format!("__Host-broker_session={}", issued.token.expose_for_cookie()),
        )
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_response_is_an_event_stream() {
    let (router, sessions, _clock) = harness();
    let issued = sessions.create(
        Sid("s1".into()),
        CustodyId("c1".into()),
        "user-1".into(),
        T0,
    );
    let request = Request::builder()
        .method("GET")
        .uri("/session/events")
        .header("sec-fetch-site", "same-origin")
        .header(
            "cookie",
            format!("__Host-broker_session={}", issued.token.expose_for_cookie()),
        )
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap(),
        "text/event-stream"
    );
}
