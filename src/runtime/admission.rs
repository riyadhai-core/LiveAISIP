// Copyright 2026 RiyadhAI LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `LiveAISIP`.
//!
//! A high-performance SIP server developed by `RiyadhAI LLC` for large-scale
//! realtime AI telephony workloads.

//! Race-safe overload admission and retry suppression.

use crate::sip::headers::retry_after::RetryAfter;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// Maximum calls allowed by one controller.
pub const MAX_ADMISSION_CAPACITY: usize = 1_000_000;
/// Maximum remote target cooldowns retained.
pub const MAX_RETRY_SUPPRESSIONS: usize = 65_536;
/// Maximum hierarchical active-call permits grouped into one call lease.
pub const MAX_ADMISSION_LEASES_PER_CALL: usize = 16;

struct Shared {
    active: AtomicUsize,
    accepting: AtomicBool,
}

/// Move-only capacity lease released on every drop path.
pub struct AdmissionLease {
    shared: Arc<Shared>,
    released: bool,
}

impl AdmissionLease {
    /// Explicitly releases capacity; drop remains safe afterward.
    pub fn release(mut self) {
        self.release_inner();
    }
    fn release_inner(&mut self) {
        if !self.released {
            self.shared.active.fetch_sub(1, Ordering::AcqRel);
            self.released = true;
        }
    }
}
impl Drop for AdmissionLease {
    fn drop(&mut self) {
        self.release_inner();
    }
}
impl fmt::Debug for AdmissionLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmissionLease")
            .field("released", &self.released)
            .finish_non_exhaustive()
    }
}

/// Move-only group of global, project, trunk or destination call permits.
///
/// If acquisition of a later scope fails, dropping the partially built group
/// releases every earlier permit automatically.
#[derive(Default)]
pub struct AdmissionLeaseGroup {
    leases: Vec<AdmissionLease>,
}

impl AdmissionLeaseGroup {
    /// Creates an empty call admission group.
    #[must_use]
    pub const fn new() -> Self {
        Self { leases: Vec::new() }
    }

    /// Adds one acquired scope permit.
    ///
    /// # Errors
    ///
    /// Rejects excessive grouped scopes or allocation failure.
    pub fn push(&mut self, lease: AdmissionLease) -> Result<(), AdmissionError> {
        if self.leases.len() >= MAX_ADMISSION_LEASES_PER_CALL {
            return Err(AdmissionError::TooManyGroupedLeases);
        }
        self.leases
            .try_reserve(1)
            .map_err(|_| AdmissionError::AllocationFailed)?;
        self.leases.push(lease);
        Ok(())
    }

    /// Returns grouped permit count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    /// Returns whether no permit is owned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    /// Releases every scope immediately. Drop is safe afterward.
    pub fn release_all(&mut self) {
        self.leases.clear();
    }
}

impl fmt::Debug for AdmissionLeaseGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmissionLeaseGroup")
            .field("permit_count", &self.leases.len())
            .finish_non_exhaustive()
    }
}

/// 503 response policy returned before expensive allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverloadRejection {
    retry_after: RetryAfter,
}
impl OverloadRejection {
    /// SIP status to send.
    #[must_use]
    pub const fn status(self) -> u16 {
        503
    }
    /// Retry suppression interval.
    #[must_use]
    pub const fn retry_after(self) -> RetryAfter {
        self.retry_after
    }
}

/// Lock-free active-call admission gate.
pub struct AdmissionController {
    shared: Arc<Shared>,
    maximum: usize,
    retry_after: RetryAfter,
}

impl AdmissionController {
    /// Creates bounded admission state.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive capacity.
    pub fn new(maximum: usize, retry_after: RetryAfter) -> Result<Self, AdmissionError> {
        if maximum == 0 || maximum > MAX_ADMISSION_CAPACITY {
            return Err(AdmissionError::InvalidCapacity);
        }
        Ok(Self {
            shared: Arc::new(Shared {
                active: AtomicUsize::new(0),
                accepting: AtomicBool::new(true),
            }),
            maximum,
            retry_after,
        })
    }

    /// Attempts capacity before call/media allocation.
    ///
    /// # Errors
    ///
    /// Returns a 503 policy when capacity or shutdown rejects admission.
    pub fn try_admit(&self) -> Result<AdmissionLease, OverloadRejection> {
        if !self.shared.accepting.load(Ordering::Acquire) {
            return Err(OverloadRejection {
                retry_after: self.retry_after,
            });
        }
        let admitted =
            self.shared
                .active
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                    (active < self.maximum).then_some(active + 1)
                });
        if admitted.is_err() {
            return Err(OverloadRejection {
                retry_after: self.retry_after,
            });
        }
        if !self.shared.accepting.load(Ordering::Acquire) {
            self.shared.active.fetch_sub(1, Ordering::AcqRel);
            return Err(OverloadRejection {
                retry_after: self.retry_after,
            });
        }
        Ok(AdmissionLease {
            shared: Arc::clone(&self.shared),
            released: false,
        })
    }

    /// Fences new work while existing leases drain.
    pub fn begin_shutdown(&self) {
        self.shared.accepting.store(false, Ordering::Release);
    }
    /// Returns active lease count.
    #[must_use]
    pub fn active(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }
}

/// Bounded UAC cooldowns keyed by privacy-safe resolved-target identifiers.
pub struct RetrySuppressor {
    deadlines: HashMap<u64, Duration>,
    maximum: usize,
}
impl RetrySuppressor {
    /// Creates bounded cooldown table.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive capacity or allocation failure.
    pub fn new(maximum: usize) -> Result<Self, AdmissionError> {
        if maximum == 0 || maximum > MAX_RETRY_SUPPRESSIONS {
            return Err(AdmissionError::InvalidSuppressionCapacity);
        }
        let mut deadlines = HashMap::new();
        deadlines
            .try_reserve(maximum.min(1_024))
            .map_err(|_| AdmissionError::AllocationFailed)?;
        Ok(Self { deadlines, maximum })
    }

    /// Records 503 cooldown without unbounded target growth.
    ///
    /// # Errors
    ///
    /// Rejects table capacity or deadline overflow.
    pub fn note_503(
        &mut self,
        target: u64,
        now: Duration,
        retry: RetryAfter,
    ) -> Result<(), AdmissionError> {
        if !self.deadlines.contains_key(&target) && self.deadlines.len() == self.maximum {
            return Err(AdmissionError::SuppressionCapacityExceeded);
        }
        let deadline = now
            .checked_add(Duration::from_secs(u64::from(retry.seconds())))
            .ok_or(AdmissionError::TimeOverflow)?;
        self.deadlines.insert(target, deadline);
        Ok(())
    }

    /// Returns whether a target may be attempted, expiring elapsed cooldown.
    pub fn may_attempt(&mut self, target: u64, now: Duration) -> bool {
        match self.deadlines.get(&target).copied() {
            Some(deadline) if now < deadline => false,
            Some(_) => {
                self.deadlines.remove(&target);
                true
            }
            None => true,
        }
    }
}

/// Admission configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    /// Active-call capacity invalid.
    InvalidCapacity,
    /// Retry suppression capacity invalid.
    InvalidSuppressionCapacity,
    /// Fixed storage allocation failed.
    AllocationFailed,
    /// Cooldown table reached bound.
    SuppressionCapacityExceeded,
    /// Retry deadline overflowed.
    TimeOverflow,
    /// One call attempted to aggregate too many admission scopes.
    TooManyGroupedLeases,
}
impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime admission operation failed")
    }
}
impl StdError for AdmissionError {}

#[cfg(test)]
mod tests {
    use super::{AdmissionController, AdmissionLeaseGroup, RetrySuppressor};
    use crate::sip::headers::retry_after::RetryAfter;
    use std::time::Duration;

    #[test]
    fn leases_bound_calls_and_return_503_policy() {
        let controller = AdmissionController::new(1, RetryAfter::new(3))
            .unwrap_or_else(|_| panic!("controller"));
        let lease = controller.try_admit().unwrap_or_else(|_| panic!("lease"));
        let rejected = controller
            .try_admit()
            .err()
            .unwrap_or_else(|| panic!("rejection"));
        assert_eq!(rejected.status(), 503);
        assert_eq!(rejected.retry_after().seconds(), 3);
        drop(lease);
        assert!(controller.try_admit().is_ok());
    }

    #[test]
    fn retry_after_suppresses_target_until_deadline() {
        let mut suppressor = RetrySuppressor::new(2).unwrap_or_else(|_| panic!("suppressor"));
        assert!(
            suppressor
                .note_503(7, Duration::ZERO, RetryAfter::new(5))
                .is_ok()
        );
        assert!(!suppressor.may_attempt(7, Duration::from_secs(4)));
        assert!(suppressor.may_attempt(7, Duration::from_secs(5)));
    }

    #[test]
    fn grouped_admission_releases_every_scope_on_drop_and_explicit_release() {
        let global = AdmissionController::new(1, RetryAfter::new(3))
            .unwrap_or_else(|_| panic!("global controller"));
        let trunk = AdmissionController::new(1, RetryAfter::new(3))
            .unwrap_or_else(|_| panic!("trunk controller"));
        let mut group = AdmissionLeaseGroup::new();
        assert!(
            group
                .push(
                    global
                        .try_admit()
                        .unwrap_or_else(|_| panic!("global lease"))
                )
                .is_ok()
        );
        assert!(
            group
                .push(trunk.try_admit().unwrap_or_else(|_| panic!("trunk lease")))
                .is_ok()
        );
        assert_eq!(global.active(), 1);
        assert_eq!(trunk.active(), 1);
        group.release_all();
        assert_eq!(global.active(), 0);
        assert_eq!(trunk.active(), 0);

        let mut dropped = AdmissionLeaseGroup::new();
        assert!(
            dropped
                .push(
                    global
                        .try_admit()
                        .unwrap_or_else(|_| panic!("global lease"))
                )
                .is_ok()
        );
        drop(dropped);
        assert_eq!(global.active(), 0);
    }
}
