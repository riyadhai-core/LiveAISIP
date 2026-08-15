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

//! Bounded monotonic outbound-dial failure backoff.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use super::destination::Destination;

/// Hard maximum destinations with active dial suppression.
pub const MAX_DIAL_BACKOFFS: usize = 65_536;
/// Hard maximum one-destination dial suppression interval.
pub const MAX_DIAL_BACKOFF: Duration = Duration::from_secs(300);

/// Validated dial-backoff policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DialBackoffConfig {
    /// Maximum simultaneously suppressed destinations.
    pub maximum_destinations: usize,
    /// Delay after the first failure.
    pub initial_delay: Duration,
    /// Saturating delay ceiling.
    pub maximum_delay: Duration,
}

impl DialBackoffConfig {
    /// Returns production-oriented bounded defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            maximum_destinations: 8_192,
            initial_delay: Duration::from_millis(250),
            maximum_delay: Duration::from_secs(30),
        }
    }

    /// Validates all hard limits.
    ///
    /// # Errors
    ///
    /// Rejects zero, excessive, or inverted limits.
    pub fn validate(self) -> Result<(), DialBackoffError> {
        if self.maximum_destinations == 0 || self.maximum_destinations > MAX_DIAL_BACKOFFS {
            return Err(DialBackoffError::InvalidCapacity);
        }
        if self.initial_delay.is_zero()
            || self.maximum_delay < self.initial_delay
            || self.maximum_delay.as_secs() > MAX_DIAL_BACKOFF.as_secs()
        {
            return Err(DialBackoffError::InvalidDelay);
        }
        Ok(())
    }
}

impl Default for DialBackoffConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
struct FailureState {
    failures: u16,
    retry_at: Duration,
}

/// Current dial admission decision for one destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialPermission {
    /// No active failure suppression remains.
    Allowed,
    /// A previous failure still suppresses another dial.
    BackingOff {
        /// Monotonic duration until another dial may begin.
        remaining: Duration,
    },
}

/// Actor-owned bounded destination failure table.
pub struct DialBackoff {
    config: DialBackoffConfig,
    failures: HashMap<Destination, FailureState>,
}

impl DialBackoff {
    /// Creates empty backoff state.
    ///
    /// # Errors
    ///
    /// Rejects invalid configuration.
    pub fn new(config: DialBackoffConfig) -> Result<Self, DialBackoffError> {
        config.validate()?;
        Ok(Self {
            config,
            failures: HashMap::new(),
        })
    }

    /// Returns the current permission for one destination.
    pub fn permission(&mut self, destination: &Destination, now: Duration) -> DialPermission {
        match self.failures.get(destination).copied() {
            Some(state) if now < state.retry_at => DialPermission::BackingOff {
                remaining: state.retry_at - now,
            },
            Some(_) | None => DialPermission::Allowed,
        }
    }

    /// Records a failed dial and returns its new retry deadline.
    ///
    /// Repeated failures double the delay until the configured ceiling. A
    /// successful dial must call [`Self::note_success`] to reset history.
    ///
    /// # Errors
    ///
    /// Rejects table capacity, deadline overflow, and allocation failure.
    pub fn note_failure(
        &mut self,
        destination: Destination,
        now: Duration,
    ) -> Result<Duration, DialBackoffError> {
        if !self.failures.contains_key(&destination)
            && self.failures.len() >= self.config.maximum_destinations
        {
            self.failures.retain(|_, state| now < state.retry_at);
        }
        if !self.failures.contains_key(&destination)
            && self.failures.len() >= self.config.maximum_destinations
        {
            return Err(DialBackoffError::Capacity);
        }
        self.failures
            .try_reserve(1)
            .map_err(|_| DialBackoffError::AllocationFailed)?;
        let failures = self
            .failures
            .get(&destination)
            .map_or(1, |state| state.failures.saturating_add(1));
        let delay = exponential_delay(
            self.config.initial_delay,
            self.config.maximum_delay,
            failures,
        );
        let retry_at = now
            .checked_add(delay)
            .ok_or(DialBackoffError::TimeOverflow)?;
        self.failures
            .insert(destination, FailureState { failures, retry_at });
        Ok(retry_at)
    }

    /// Clears all failure history after a successful establishment.
    pub fn note_success(&mut self, destination: &Destination) -> bool {
        self.failures.remove(destination).is_some()
    }

    /// Returns the bounded number of suppressed destinations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.failures.len()
    }

    /// Returns whether no destination is suppressed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.failures.is_empty()
    }
}

impl fmt::Debug for DialBackoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DialBackoff")
            .field("suppressed_destinations", &self.failures.len())
            .field("maximum", &self.config.maximum_destinations)
            .finish_non_exhaustive()
    }
}

fn exponential_delay(initial: Duration, maximum: Duration, failures: u16) -> Duration {
    let mut delay = initial;
    for _ in 1..failures.min(64) {
        delay = delay.checked_mul(2).unwrap_or(maximum).min(maximum);
        if delay == maximum {
            break;
        }
    }
    delay
}

/// Dial-backoff configuration or state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialBackoffError {
    /// Destination-table capacity was zero or exceeded the hard ceiling.
    InvalidCapacity,
    /// Initial or maximum delay was invalid.
    InvalidDelay,
    /// Active destination table reached its configured bound.
    Capacity,
    /// Monotonic retry deadline overflowed.
    TimeOverflow,
    /// Bounded table allocation failed.
    AllocationFailed,
}

impl fmt::Display for DialBackoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("outbound SIP dial backoff failed")
    }
}

impl StdError for DialBackoffError {}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::{DialBackoff, DialBackoffConfig, DialBackoffError, DialPermission};
    use crate::sip::transport::destination::Destination;

    fn destination(port: u16) -> Destination {
        Destination::tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .unwrap_or_else(|_| panic!("destination"))
    }

    #[test]
    fn failures_back_off_exponentially_and_success_resets_history() {
        let mut backoff = DialBackoff::new(DialBackoffConfig {
            maximum_destinations: 2,
            initial_delay: Duration::from_secs(1),
            maximum_delay: Duration::from_secs(4),
        })
        .unwrap_or_else(|_| panic!("backoff"));
        let target = destination(5060);
        assert_eq!(
            backoff.note_failure(target.clone(), Duration::ZERO),
            Ok(Duration::from_secs(1))
        );
        assert_eq!(
            backoff.permission(&target, Duration::from_millis(250)),
            DialPermission::BackingOff {
                remaining: Duration::from_millis(750)
            }
        );
        assert_eq!(
            backoff.permission(&target, Duration::from_secs(1)),
            DialPermission::Allowed
        );
        assert_eq!(
            backoff.note_failure(target.clone(), Duration::from_secs(1)),
            Ok(Duration::from_secs(3))
        );
        assert!(backoff.note_success(&target));
        assert_eq!(
            backoff.permission(&target, Duration::from_secs(1)),
            DialPermission::Allowed
        );
    }

    #[test]
    fn destination_growth_is_bounded() {
        let mut backoff = DialBackoff::new(DialBackoffConfig {
            maximum_destinations: 1,
            ..DialBackoffConfig::new()
        })
        .unwrap_or_else(|_| panic!("backoff"));
        assert!(
            backoff
                .note_failure(destination(5060), Duration::ZERO)
                .is_ok()
        );
        assert_eq!(
            backoff.note_failure(destination(5061), Duration::ZERO),
            Err(DialBackoffError::Capacity)
        );
        assert!(
            backoff
                .note_failure(destination(5061), Duration::from_secs(1))
                .is_ok()
        );
    }
}
