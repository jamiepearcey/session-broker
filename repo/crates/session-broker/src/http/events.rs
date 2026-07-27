//! `GET /session/events` — a server-sent-event stream of things a live client
//! should hear about promptly.
//!
//! ## What this is, and what it is not
//!
//! It is a *latency optimisation*. Without it a revoked session is discovered
//! whenever the tab next makes a request or its lazy check fires — correct, but
//! possibly a minute late. With it, the tab hears within milliseconds.
//!
//! It is **not** enforcement. A backgrounded, disconnected or simply unlucky
//! client may never receive an event, so the 401 on the next request remains the
//! mechanism that actually ends a session (INV-7). Nothing here may become
//! load-bearing for security, and nothing here mutates state.
//!
//! ## Why no cookie is written here
//!
//! `Set-Cookie` is a response header, flushed once when the stream opens; a
//! browser will never read cookie material out of the event body, and trailers
//! are not processed either. So this endpoint deliberately carries no session
//! material at all — it says *what changed*, and the client's next ordinary
//! request carries the cookies, exactly as it already does. For the logout case
//! there is nothing to write anyway: the session is tombstoned server-side, so
//! the cookie still in the browser is already inert.
//!
//! ## Connection budget
//!
//! One stream occupies one HTTP/1.1 connection, and browsers allow six per
//! origin — so a per-tab stream would starve the pool at six tabs. Over HTTP/2
//! streams are multiplexed (~100 negotiated) and per-tab is fine. The client
//! SDK decides which regime it is in; the server serves either happily.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt as _};

use super::error::{ApiError, ErrorCode};
use super::{guards, AppState};
use crate::session::{Resolution, SessionEvent, SessionObserver, Sid};
use crate::token::TokenHash;

/// How many events may queue for a slow subscriber before it is dropped. A
/// client that falls this far behind has lost nothing that matters: it will
/// discover the truth on its next request, which is the guarantee anyway.
const CHANNEL_CAPACITY: usize = 64;

/// Heartbeat interval. Idle streams are killed by proxies and load balancers
/// long before any application-level timeout would notice.
const KEEPALIVE_SECS: u64 = 20;

/// The event fan-out. Handed to [`crate::session::SessionMap`] as its observer
/// and to the router as an extension.
#[derive(Clone)]
pub struct SessionEvents {
    tx: broadcast::Sender<SessionEvent>,
}

impl SessionEvents {
    pub fn new() -> Arc<SessionEvents> {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAPACITY);
        Arc::new(SessionEvents { tx })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.tx.subscribe()
    }

    /// Live subscriber count — useful in tests and for a metrics gauge.
    pub fn subscribers(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl SessionObserver for SessionEvents {
    fn on_event(&self, event: SessionEvent) {
        // `send` fails only when nobody is listening, which is the common case
        // and not an error: the session state has already changed either way.
        let _ = self.tx.send(event);
    }
}

impl std::fmt::Debug for SessionEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionEvents")
            .field("subscribers", &self.subscribers())
            .finish()
    }
}

/// `GET /session/events`.
///
/// Read-only, so there is no CSRF surface to defend — but it is still
/// same-origin-checked, because an `EventSource` opened from another origin has
/// no business holding a stream against this user's session. `EventSource`
/// cannot set request headers, which is precisely why the guard leans on
/// `Sec-Fetch-Site` (which the browser sets and script cannot forge) rather than
/// anything the caller supplies.
pub async fn stream(
    State(state): State<AppState>,
    Extension(events): Extension<Arc<SessionEvents>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = guards::require_same_origin(
        &headers,
        state.config.origin(),
        guards::AllowDirectNavigation::No,
    ) {
        return err.into_response();
    }

    let now = state.clock.now();
    let Some(hash) =
        guards::cookie(&headers, state.config.session_cookie_name()).map(TokenHash::of)
    else {
        return ApiError::new(ErrorCode::InvalidSession, "no session cookie presented")
            .with_login_url(state.config.login_url(None))
            .into_response();
    };

    // Only a live session may hold a stream. A stale-but-refreshable one counts:
    // the tab is legitimately signed in, it just has not refreshed yet, and
    // refusing it would mean the sleeping tab that most needs a wake-up call is
    // the one tab that cannot subscribe.
    let sid = match state.sessions.resolve(&hash, now) {
        Resolution::Active { sid, .. } | Resolution::StaleRefreshable { sid, .. } => sid,
        Resolution::HardExpired { reason, .. } => {
            return ApiError::new(
                ErrorCode::SessionExpired,
                format!("session expired ({reason:?})"),
            )
            .with_login_url(state.config.login_url(None))
            .into_response();
        }
        _ => {
            return ApiError::new(ErrorCode::InvalidSession, "no live session for this token")
                .with_login_url(state.config.login_url(None))
                .into_response();
        }
    };

    Sse::new(session_stream(events.subscribe(), sid))
        .keep_alive(
            KeepAlive::new()
                .interval(std::time::Duration::from_secs(KEEPALIVE_SECS))
                .text("keepalive"),
        )
        .into_response()
}

/// Filter the global fan-out down to one session.
///
/// Filtering here rather than keeping a channel per session keeps the session
/// map free of subscriber bookkeeping; at this scale a single broadcast plus a
/// predicate is cheaper than a map of channels, and it cannot leak one user's
/// events to another because the predicate is the only way out.
fn session_stream(
    rx: broadcast::Receiver<SessionEvent>,
    sid: Sid,
) -> impl Stream<Item = Result<Event, Infallible>> {
    BroadcastStream::new(rx).filter_map(move |received| {
        // A lagged receiver has missed events. Dropping the notice is right:
        // the client's next request still tells it the truth, and there is no
        // "partial" state to reconcile.
        let event = received.ok()?;
        if event.sid() != &sid {
            return None;
        }
        let data = serde_json::to_string(&payload(&event)).ok()?;
        Some(Ok(Event::default().event(event.name()).data(data)))
    })
}

/// The wire payload. Deliberately minimal: an identifier the client already
/// holds plus the reason. Nothing here is secret, and nothing here is a
/// credential.
fn payload(event: &SessionEvent) -> serde_json::Value {
    match event {
        SessionEvent::SessionKilled { sid, reason } => {
            serde_json::json!({ "sid": sid.0, "reason": reason })
        }
        SessionEvent::CustodyChanged { sid, custody } => {
            serde_json::json!({ "sid": sid.0, "custody": custody })
        }
    }
}

#[cfg(test)]
mod tests;
