//! In-memory rate limiting (M6).
//!
//! ## What this defends, and what it deliberately does not
//!
//! Two things, both about a caller who is *failing*:
//!
//! * **Brute force.** Repeated wrong `admin_api_key` or backend API key
//!   presentations. Both are shared secrets with no lockout of their own, so
//!   without a limiter an attacker's only cost is bandwidth.
//! * **Resource creation.** `/auth/login` mints a server-side transaction per
//!   call (INV-3). Unbounded, that is a free write amplifier.
//!
//! It does **not** limit `/authz`, which the edge calls on every request in the
//! platform — a limiter there is an outage waiting for a traffic spike. Nor
//! successful `/session/refresh`: coalescing already bounds the work a burst can
//! cause (that is ADR-0002's whole point), so a limiter would add a failure mode
//! to defend against a cost that is already near zero.
//!
//! ## Why the client-IP source is configuration, not a guess
//!
//! Behind an edge proxy (ADR-0015 in the platform repo puts Envoy in front of
//! this service) **every public-lane request arrives from the same peer**. Keying
//! on the peer address there would put the entire user base in one bucket, so the
//! first user to trip it would lock out everyone — strictly worse than no
//! limiting at all.
//!
//! So a client-IP header must be named explicitly in config before the public
//! lane is limited, and the value is taken from the **last** entry: proxies
//! append, so the last entry is what the nearest trusted proxy observed. The
//! first entry is whatever the client sent, which is a value an attacker picks —
//! and keying a rate limiter on an attacker-chosen string means they get a fresh
//! budget per request.
//!
//! The internal lane needs none of this: backends connect to it directly, so its
//! peer address is the caller.
//!
//! ## Single node, deliberately
//!
//! State is per-process, like everything else here (ADR-0005 puts the HA story
//! on Postgres, and it is not built). Two brokers behind a load balancer each
//! enforce their own budget, so the effective limit is `n × quota`. That is
//! worth knowing and not worth coordinating: this is a blunt instrument against
//! automation, not a fairness mechanism.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A refill-over-window budget: `burst` requests, with the full budget restored
/// over `per`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub burst: u32,
    pub per: Duration,
}

impl Quota {
    pub const fn new(burst: u32, per_secs: u64) -> Quota {
        Quota {
            burst,
            per: Duration::from_secs(per_secs),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Refused, with how long until one token is available again. Returned to
    /// the caller as `Retry-After` so a well-behaved client can back off
    /// instead of hammering — and so a badly-behaved one has no excuse.
    Deny {
        retry_after: Duration,
    },
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        matches!(self, Decision::Allow)
    }
}

#[derive(Debug)]
struct Bucket {
    /// Tokens remaining, scaled by [`SCALE`] so refill is integer arithmetic.
    tokens: u64,
    last: Instant,
}

/// Fixed-point scale for token accounting. Integer maths keeps this allocation-
/// and float-free on a path that runs while the service is under attack, which
/// is exactly when it should be cheapest.
const SCALE: u64 = 1_000_000;

/// A keyed token-bucket limiter.
pub struct Limiter {
    quota: Quota,
    buckets: Mutex<HashMap<String, Bucket>>,
    /// Upper bound on distinct keys held. See [`Limiter::check`] for what
    /// happens at the bound, which is the interesting part.
    capacity: usize,
}

impl std::fmt::Debug for Limiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Limiter")
            .field("quota", &self.quota)
            .field("capacity", &self.capacity)
            .field("tracked", &self.tracked())
            .finish()
    }
}

impl Limiter {
    pub fn new(quota: Quota, capacity: usize) -> Limiter {
        Limiter {
            quota,
            buckets: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    pub fn quota(&self) -> Quota {
        self.quota
    }

    pub fn tracked(&self) -> usize {
        self.buckets.lock().map(|b| b.len()).unwrap_or(0)
    }

    /// Spend one token for `key`.
    ///
    /// `now` is passed in rather than read here so tests can drive time without
    /// sleeping — the same reason [`crate::clock::Clock`] exists for the rest of
    /// the service.
    pub fn check_at(&self, key: &str, now: Instant) -> Decision {
        let Ok(mut buckets) = self.buckets.lock() else {
            // A poisoned mutex means a previous holder panicked. Allowing is the
            // right failure here: this is a defence-in-depth limiter, and taking
            // the service down because it cannot rate-limit turns a nuisance
            // into an outage.
            return Decision::Allow;
        };

        let capacity_tokens = self.quota.burst as u64 * SCALE;
        let per_nanos = self.quota.per.as_nanos().max(1) as u64;

        if let Some(bucket) = buckets.get_mut(key) {
            let elapsed = now.saturating_duration_since(bucket.last).as_nanos() as u64;
            let refill = (elapsed.saturating_mul(capacity_tokens)) / per_nanos;
            bucket.tokens = (bucket.tokens + refill).min(capacity_tokens);
            bucket.last = now;

            if bucket.tokens >= SCALE {
                bucket.tokens -= SCALE;
                return Decision::Allow;
            }
            let missing = SCALE - bucket.tokens;
            let wait_nanos = missing.saturating_mul(per_nanos) / capacity_tokens.max(1);
            return Decision::Deny {
                retry_after: Duration::from_nanos(wait_nanos.max(1)),
            };
        }

        // A new key. Make room if needed by dropping only buckets that have
        // refilled completely: a full bucket is indistinguishable from an absent
        // one, so forgetting it loses no information and cannot hand anyone a
        // budget they had already spent.
        if buckets.len() >= self.capacity {
            buckets.retain(|_, b| {
                let elapsed = now.saturating_duration_since(b.last).as_nanos() as u64;
                let refill = (elapsed.saturating_mul(capacity_tokens)) / per_nanos;
                (b.tokens + refill) < capacity_tokens
            });
            if buckets.len() >= self.capacity {
                // Every tracked key is mid-spend, so the table is full of
                // callers who are actively being limited. Refusing the new key
                // is fail-CLOSED, and deliberately so: the alternative is to
                // grow without bound, which turns a rate-limit bypass attempt
                // into a memory-exhaustion one.
                return Decision::Deny {
                    retry_after: self.quota.per,
                };
            }
        }

        buckets.insert(
            key.to_owned(),
            Bucket {
                tokens: capacity_tokens - SCALE,
                last: now,
            },
        );
        Decision::Allow
    }

    /// [`Limiter::check_at`] with the current instant.
    pub fn check(&self, key: &str) -> Decision {
        self.check_at(key, Instant::now())
    }
}

/// Where the client's address comes from on a given lane.
#[derive(Debug, Clone)]
pub enum ClientSource {
    /// The transport peer. Correct for the internal lane, where backends
    /// connect directly.
    Peer,
    /// A named header, appended by a trusted proxy. The LAST value is used.
    Header(String),
}

impl ClientSource {
    /// Resolve the key to limit on.
    ///
    /// Returns `None` when a header source is configured but absent, which means
    /// the request did not come through the proxy that was supposed to add it.
    /// The caller decides what that means; this function will not silently fall
    /// back to the peer, because falling back is how a limiter configured for a
    /// proxied deployment quietly starts bucketing everyone together.
    pub fn key(
        &self,
        peer: Option<&std::net::SocketAddr>,
        headers: &axum::http::HeaderMap,
    ) -> Option<String> {
        match self {
            ClientSource::Peer => peer.map(|addr| addr.ip().to_string()),
            ClientSource::Header(name) => headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .and_then(|raw| raw.rsplit(',').next())
                .map(|last| last.trim().to_owned())
                .filter(|v| !v.is_empty()),
        }
    }
}

#[cfg(test)]
mod tests;
