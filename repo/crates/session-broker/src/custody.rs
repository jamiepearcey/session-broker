//! Taking, holding and renewing the upstream grant (§6).
//!
//! This is the module the product's name refers to. Two responsibilities, kept
//! together because they share one hazard:
//!
//! * [`CustodySink`] — what `/auth/callback` calls to hand a freshly obtained
//!   grant over. Write-through, then scheduled.
//! * [`OidcUpstream`] — the [`Upstream`](crate::keepalive::Upstream) the
//!   keepalive worker drives. Loads the custody row, calls the IdP, and writes
//!   the result back.
//!
//! **The shared hazard is refresh-token rotation.** If the IdP issues
//! single-use refresh tokens, the token we just spent is already dead upstream
//! the moment the response arrives. If the process dies between that response
//! and the durable write, the grant is orphaned: the token on disk no longer
//! works, and no retry can recover it — the user must log in again, and under
//! the `kill` policy every session behind that custody dies. So the durable
//! write happens BEFORE the scheduler is told anything, on both paths here,
//! and it is write-through rather than write-behind (§5). This is off the hot
//! path, so INV-8 is untouched.

use std::sync::Arc;

use crate::clock::{Clock, Timestamp};
use crate::keepalive::{RefreshOutcome, Upstream};
use crate::oauth::{OidcClient, RefreshGrantError};
use crate::session::{CustodyId, CustodyStatus};
use crate::store::repo::{self, CustodyRow};
use crate::store::writer::{CustodyWrite, WriterHandle};
use crate::store::Reader;

/// A newly created custody, waiting to be scheduled. Sent to the keepalive
/// worker's channel so the worker owns its heap exclusively (§6) rather than
/// sharing a lock with request handlers.
#[derive(Debug, Clone)]
pub struct ScheduleRequest {
    pub custody: CustodyId,
    /// When the grant was issued — the point the lead fraction is measured
    /// from, not the expiry.
    pub issued_at: Timestamp,
    pub lifetime_secs: u64,
}

/// A grant just obtained from the IdP, on its way into custody.
///
/// Its `Debug` redacts both tokens: this struct exists at exactly the moment
/// they are most likely to end up in a log line.
pub struct NewGrant {
    pub sub: String,
    pub refresh_token: String,
    pub access_token: String,
    pub access_exp: Timestamp,
    pub scope: Option<String>,
}

impl std::fmt::Debug for NewGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewGrant")
            .field("sub", &self.sub)
            .field("refresh_token", &"redacted")
            .field("access_token", &"redacted")
            .field("access_exp", &self.access_exp)
            .field("scope", &self.scope)
            .finish()
    }
}

/// What `/auth/callback` uses to put a grant into custody.
#[derive(Clone)]
pub struct CustodySink {
    writer: WriterHandle,
    schedule: tokio::sync::mpsc::UnboundedSender<ScheduleRequest>,
}

impl std::fmt::Debug for CustodySink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CustodySink")
    }
}

impl CustodySink {
    pub fn new(
        writer: WriterHandle,
        schedule: tokio::sync::mpsc::UnboundedSender<ScheduleRequest>,
    ) -> CustodySink {
        CustodySink { writer, schedule }
    }

    /// Persist the grant, then schedule its renewal.
    ///
    /// Returns an error if the durable write failed, and the caller must then
    /// refuse to create a session: a session whose custody row never landed is
    /// one whose upstream calls will 500 forever, and whose foreign key does
    /// not exist — better to fail the login and let the user retry.
    ///
    /// Order matters and is not interchangeable. Scheduling first would let
    /// the keepalive worker try to renew a custody that is not on disk.
    pub fn take_custody(
        &self,
        custody: &CustodyId,
        grant: &NewGrant,
        now: Timestamp,
    ) -> Result<(), String> {
        let access_exp = grant.access_exp;
        let lifetime_secs = access_exp.secs().saturating_sub(now.secs()).max(1) as u64;

        self.writer.write_custody(CustodyWrite::Insert(CustodyRow {
            custody_id: custody.clone(),
            sub: grant.sub.clone(),
            refresh_tok: grant.refresh_token.as_bytes().to_vec(),
            access_tok: grant.access_token.as_bytes().to_vec(),
            access_exp,
            scope: grant.scope.clone(),
            status: CustodyStatus::Ok,
            // The real lead, not the expiry.
            //
            // The in-memory scheduler computes its own jittered deadline the
            // moment this custody is registered, so for a while this column was
            // written as `access_exp` on the grounds that only a cold restart
            // would ever read it. That stopped being true when the admin
            // console started showing it: an operator would see "next renewal"
            // and "token expires" at the same instant and reasonably conclude
            // the worker was about to miss its deadline. A stored value that
            // something displays is not a placeholder.
            next_refresh: now.plus_secs(
                (lifetime_secs as f64 * crate::keepalive::KeepalivePolicy::default().lead_fraction)
                    as u64,
            ),
            fail_count: 0,
            updated_at: now,
        }))?;

        // The worker is the only owner of the schedule, so a send failure means
        // it is gone — which is a degraded broker, not a failed login. The
        // grant is safely on disk and a restart will pick it up from
        // `custody_sched`.
        if self
            .schedule
            .send(ScheduleRequest {
                custody: custody.clone(),
                issued_at: now,
                lifetime_secs,
            })
            .is_err()
        {
            tracing::error!(
                custody = %custody.0,
                "keepalive worker is not running; this grant will not be renewed until restart"
            );
        }
        Ok(())
    }
}

/// The production [`Upstream`]: refresh-token grant against the configured IdP.
pub struct OidcUpstream {
    oidc: Arc<OidcClient>,
    reader: Arc<Reader>,
    writer: WriterHandle,
    clock: Arc<dyn Clock>,
}

impl OidcUpstream {
    pub fn new(
        oidc: Arc<OidcClient>,
        reader: Arc<Reader>,
        writer: WriterHandle,
        clock: Arc<dyn Clock>,
    ) -> OidcUpstream {
        OidcUpstream {
            oidc,
            reader,
            writer,
            clock,
        }
    }
}

impl Upstream for OidcUpstream {
    async fn refresh(&self, custody: &CustodyId) -> RefreshOutcome {
        let loaded = self
            .reader
            .with(|conn| repo::load_custody(conn, custody))
            .map_err(|e| e.to_string());

        let row = match loaded {
            Ok(Some(row)) => row,
            // The row is gone: nothing to renew, and retrying cannot bring it
            // back. Permanent, so the scheduler stops rather than spinning.
            Ok(None) => {
                tracing::warn!(custody = %custody.0, "custody row vanished; unscheduling");
                return RefreshOutcome::Permanent;
            }
            // A read failure is NOT permanent. Treating an unreadable row as a
            // revoked grant would tombstone every session behind it over what
            // may be a transient I/O problem — the worst possible response to
            // "we could not check".
            Err(e) => {
                tracing::error!(custody = %custody.0, error = %e, "custody read failed");
                return RefreshOutcome::Transient {
                    retry_after_secs: None,
                };
            }
        };

        let Ok(refresh_token) = String::from_utf8(row.refresh_tok) else {
            tracing::error!(custody = %custody.0, "stored refresh token is not valid UTF-8");
            return RefreshOutcome::Permanent;
        };

        let now = self.clock.now();
        let grant = match self.oidc.refresh_grant(&refresh_token, now).await {
            Ok(grant) => grant,
            Err(RefreshGrantError::Transient(e)) => {
                tracing::warn!(custody = %custody.0, error = %e, "upstream refresh failed; will retry");
                return RefreshOutcome::Transient {
                    retry_after_secs: None,
                };
            }
            Err(RefreshGrantError::Permanent(e)) => {
                tracing::warn!(custody = %custody.0, error = %e, "upstream grant is dead");
                return RefreshOutcome::Permanent;
            }
        };

        let rotated_refresh = grant.rotated_refresh_token.is_some();
        let refresh_to_store = grant.rotated_refresh_token.unwrap_or(refresh_token);

        // Write-through BEFORE reporting success. If this returns an error the
        // rotated token is lost, and saying "success" would leave the scheduler
        // believing a grant is healthy when the only copy of it is gone.
        if let Err(e) = self.writer.write_custody(CustodyWrite::Success {
            custody_id: custody.clone(),
            refresh_tok: refresh_to_store.into_bytes(),
            access_tok: grant.access_token.into_bytes(),
            access_exp: grant.expires_at,
            // Overwritten by the scheduler's own calculation on `record`; this
            // value only matters if the process dies before that happens.
            next_refresh: grant.expires_at,
            now,
        }) {
            tracing::error!(
                custody = %custody.0,
                error = %e,
                rotated_refresh,
                "durable custody write failed after a successful upstream refresh"
            );
            return RefreshOutcome::Transient {
                retry_after_secs: None,
            };
        }

        RefreshOutcome::Success {
            lifetime_secs: grant.lifetime_secs,
            rotated_refresh,
        }
    }
}
