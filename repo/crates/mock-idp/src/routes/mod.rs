//! Route wiring. Kept as one flat module list rather than nested
//! `oauth::` / `test_control::` namespaces — the crate is small enough that
//! the extra nesting would only add indirection, and the `/__test__` prefix
//! already does the namespacing that matters (see [`test_control`]).

mod authorize;
mod discovery;
mod jwks;
mod revoke;
mod test_control;
mod token;
mod userinfo;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub type SharedState = Arc<AppState>;

pub fn router(state: AppState) -> Router {
    let state: SharedState = Arc::new(state);
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(discovery::discovery),
        )
        .route("/authorize", get(authorize::authorize))
        .route("/token", post(token::token))
        .route("/jwks.json", get(jwks::jwks))
        .route("/userinfo", get(userinfo::userinfo))
        .route("/revoke", post(revoke::revoke))
        .route("/__test__/config", post(test_control::set_config))
        .route("/__test__/expire", post(test_control::expire))
        .route(
            "/__test__/revoke-refresh",
            post(test_control::revoke_refresh),
        )
        .route("/__test__/fail-next", post(test_control::fail_next))
        .route("/__test__/state", get(test_control::dump_state))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
