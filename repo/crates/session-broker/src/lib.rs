//! `session-broker` — a token custodian between a browser SPA and an upstream
//! OIDC provider.
//!
//! Three properties define it, in priority order:
//!
//! 1. **Non-invalidating rotation.** A new session cookie does not invalidate the
//!    previous one; generations overlap for a grace window. This removes the
//!    refresh race class outright instead of coordinating around it.
//! 2. **Local-only fast refresh.** Session lifetime is decoupled from upstream
//!    token lifetime; the refresh path performs no network I/O.
//! 3. **Server-side guarantees, dumb client.** Because the server tolerates
//!    races, the browser SDK needs no cross-tab coordination beyond one Web Lock.
//!
//! See `docs/architecture/implementation-strategy.md` and `.context/invariants.md`.

pub mod audit;
pub mod clock;
pub mod config;
pub mod custody;
pub mod http;
pub mod keepalive;
pub mod oauth;
pub mod session;
pub mod store;
pub mod telemetry;
pub mod token;

pub use clock::{Clock, SystemClock, TestClock, Timestamp};
pub use session::{
    CustodyId, CustodyStatus, ExpiredReason, IssuedCookies, RefreshDenied, Resolution,
    RevocationPolicy, SessionMap, SessionMeta, SessionPolicy, Sid,
};
pub use token::{SessionToken, TokenHash};
