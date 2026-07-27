//! Time, behind a trait, so every expiry rule in the broker can be tested
//! without sleeping.
//!
//! Whole seconds are sufficient: the shortest interval the design cares about is
//! the 30-second coalesce window, and the storage schema records epoch seconds.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// An epoch-seconds instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub i64);

impl Timestamp {
    pub const fn secs(self) -> i64 {
        self.0
    }

    /// Saturating add, so a comically large TTL cannot wrap an expiry backwards
    /// into the past and silently invalidate a session.
    pub const fn plus_secs(self, secs: u64) -> Timestamp {
        Timestamp(self.0.saturating_add(secs as i64))
    }

    /// Seconds elapsed since `earlier`, clamped at zero. Clamping matters because
    /// a backwards clock step must not make a fresh generation look ancient.
    pub const fn since(self, earlier: Timestamp) -> u64 {
        let d = self.0 - earlier.0;
        if d < 0 {
            0
        } else {
            d as u64
        }
    }
}

pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> Timestamp;
}

/// Wall clock. The only implementation used in production.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Timestamp(secs)
    }
}

/// A clock tests drive by hand. Shared cheaply; `advance` is visible to every
/// holder, including tasks running on another thread.
#[derive(Debug, Clone)]
pub struct TestClock(Arc<AtomicI64>);

impl TestClock {
    pub fn new(start: Timestamp) -> Self {
        TestClock(Arc::new(AtomicI64::new(start.secs())))
    }

    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs as i64, Ordering::SeqCst);
    }

    pub fn set(&self, at: Timestamp) {
        self.0.store(at.secs(), Ordering::SeqCst);
    }
}

impl Default for TestClock {
    fn default() -> Self {
        // An arbitrary but fixed origin, so failures reproduce byte-for-byte.
        TestClock::new(Timestamp(1_700_000_000))
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.0.load(Ordering::SeqCst))
    }
}
