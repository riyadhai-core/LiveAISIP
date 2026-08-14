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

//! Validated RFC 3261 transaction timer profiles.
//!
//! T1 estimates round-trip time, T2 caps non-INVITE retransmission spacing,
//! and T4 bounds network message lifetime. All derived timers use checked
//! arithmetic. Reliable transports suppress retransmission and linger timers
//! where RFC 3261 permits immediate termination.
//!
//! This module describes durations only. Scheduling, cancellation, timer-wheel
//! ownership, and stale-generation fencing belong to the transaction manager.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

/// RFC 3261 default T1.
pub const DEFAULT_T1: Duration = Duration::from_millis(500);

/// RFC 3261 default T2.
pub const DEFAULT_T2: Duration = Duration::from_secs(4);

/// RFC 3261 default T4.
pub const DEFAULT_T4: Duration = Duration::from_secs(5);

/// Minimum operational T1.
pub const MIN_T1: Duration = Duration::from_millis(100);

/// Maximum operational base timer.
pub const MAX_BASE_TIMER: Duration = Duration::from_secs(30);

/// Validated base transaction timers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerConfig {
    t1: Duration,
    t2: Duration,
    t4: Duration,
}

impl TimerConfig {
    /// Creates and validates a base timer profile.
    ///
    /// # Errors
    ///
    /// T1 must be between 100 ms and 30 s. T2 and T4 must be at least T1 and
    /// no greater than 30 s. Every 64*T1 derived deadline must fit Duration.
    pub const fn new(t1: Duration, t2: Duration, t4: Duration) -> Result<Self, TimerError> {
        if duration_less(t1, MIN_T1) || duration_greater(t1, MAX_BASE_TIMER) {
            return Err(TimerError::InvalidT1);
        }
        if duration_less(t2, t1) || duration_greater(t2, MAX_BASE_TIMER) {
            return Err(TimerError::InvalidT2);
        }
        if duration_less(t4, t1) || duration_greater(t4, MAX_BASE_TIMER) {
            return Err(TimerError::InvalidT4);
        }
        if t1.checked_mul(64).is_none() {
            return Err(TimerError::DerivedOverflow);
        }
        Ok(Self { t1, t2, t4 })
    }

    /// Returns T1.
    #[must_use]
    pub const fn t1(self) -> Duration {
        self.t1
    }

    /// Returns T2.
    #[must_use]
    pub const fn t2(self) -> Duration {
        self.t2
    }

    /// Returns T4.
    #[must_use]
    pub const fn t4(self) -> Duration {
        self.t4
    }

    /// Returns the complete derived profile for a transport class.
    #[must_use]
    pub fn profile(self, reliable: bool) -> TimerProfile {
        let sixty_four_t1 = self.t1.checked_mul(64).unwrap_or(Duration::MAX);
        TimerProfile {
            retransmit_initial: (!reliable).then_some(self.t1),
            retransmit_maximum: (!reliable).then_some(self.t2),
            invite_timeout: sixty_four_t1,
            non_invite_timeout: sixty_four_t1,
            completed_invite_linger: (!reliable).then_some(Duration::from_secs(32)),
            confirmed_invite_linger: (!reliable).then_some(self.t4),
            completed_non_invite_linger: (!reliable).then_some(self.t4),
            server_non_invite_lifetime: (!reliable).then_some(sixty_four_t1),
        }
    }
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            t1: DEFAULT_T1,
            t2: DEFAULT_T2,
            t4: DEFAULT_T4,
        }
    }
}

/// Derived transaction timing behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerProfile {
    retransmit_initial: Option<Duration>,
    retransmit_maximum: Option<Duration>,
    invite_timeout: Duration,
    non_invite_timeout: Duration,
    completed_invite_linger: Option<Duration>,
    confirmed_invite_linger: Option<Duration>,
    completed_non_invite_linger: Option<Duration>,
    server_non_invite_lifetime: Option<Duration>,
}

impl TimerProfile {
    /// Initial A/E/G retransmission interval, absent on reliable transports.
    #[must_use]
    pub const fn retransmit_initial(self) -> Option<Duration> {
        self.retransmit_initial
    }

    /// T2 retransmission cap, absent on reliable transports.
    #[must_use]
    pub const fn retransmit_maximum(self) -> Option<Duration> {
        self.retransmit_maximum
    }

    /// B/H INVITE timeout.
    #[must_use]
    pub const fn invite_timeout(self) -> Duration {
        self.invite_timeout
    }

    /// F non-INVITE timeout.
    #[must_use]
    pub const fn non_invite_timeout(self) -> Duration {
        self.non_invite_timeout
    }

    /// D completed client INVITE linger.
    #[must_use]
    pub const fn completed_invite_linger(self) -> Option<Duration> {
        self.completed_invite_linger
    }

    /// I confirmed server INVITE linger.
    #[must_use]
    pub const fn confirmed_invite_linger(self) -> Option<Duration> {
        self.confirmed_invite_linger
    }

    /// K completed client non-INVITE linger.
    #[must_use]
    pub const fn completed_non_invite_linger(self) -> Option<Duration> {
        self.completed_non_invite_linger
    }

    /// J completed server non-INVITE lifetime.
    #[must_use]
    pub const fn server_non_invite_lifetime(self) -> Option<Duration> {
        self.server_non_invite_lifetime
    }

    /// Computes the next exponential retransmission interval capped at T2.
    #[must_use]
    pub fn next_retransmit(self, current: Duration) -> Option<Duration> {
        let maximum = self.retransmit_maximum?;
        Some(current.checked_mul(2).unwrap_or(maximum).min(maximum))
    }
}

const fn duration_less(left: Duration, right: Duration) -> bool {
    left.as_nanos() < right.as_nanos()
}

const fn duration_greater(left: Duration, right: Duration) -> bool {
    left.as_nanos() > right.as_nanos()
}

/// Invalid transaction timer configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TimerError {
    /// T1 was outside its operational range.
    InvalidT1,
    /// T2 was outside its range or below T1.
    InvalidT2,
    /// T4 was outside its range or below T1.
    InvalidT4,
    /// A derived deadline overflowed.
    DerivedOverflow,
}

impl TimerError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::InvalidT1 => "invalid-t1",
            Self::InvalidT2 => "invalid-t2",
            Self::InvalidT4 => "invalid-t4",
            Self::DerivedOverflow => "derived-overflow",
        }
    }
}

impl fmt::Display for TimerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP transaction timer error: {}", self.class())
    }
}

impl StdError for TimerError {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{DEFAULT_T1, DEFAULT_T2, DEFAULT_T4, TimerConfig, TimerError};

    #[test]
    fn defaults_produce_rfc_deadlines() {
        let config = TimerConfig::default();
        assert_eq!(config.t1(), DEFAULT_T1);
        assert_eq!(config.t2(), DEFAULT_T2);
        assert_eq!(config.t4(), DEFAULT_T4);
        let profile = config.profile(false);
        assert_eq!(profile.invite_timeout(), Duration::from_secs(32));
        assert_eq!(profile.non_invite_timeout(), Duration::from_secs(32));
        assert_eq!(
            profile.completed_invite_linger(),
            Some(Duration::from_secs(32))
        );
    }

    #[test]
    fn reliable_transport_suppresses_retransmission_and_linger() {
        let profile = TimerConfig::default().profile(true);
        assert_eq!(profile.retransmit_initial(), None);
        assert_eq!(profile.retransmit_maximum(), None);
        assert_eq!(profile.completed_invite_linger(), None);
        assert_eq!(profile.confirmed_invite_linger(), None);
        assert_eq!(profile.completed_non_invite_linger(), None);
        assert_eq!(profile.server_non_invite_lifetime(), None);
    }

    #[test]
    fn retransmission_backoff_caps_at_t2() {
        let profile = TimerConfig::default().profile(false);
        assert_eq!(
            profile.next_retransmit(DEFAULT_T1),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            profile.next_retransmit(Duration::from_secs(3)),
            Some(DEFAULT_T2)
        );
        assert_eq!(profile.next_retransmit(DEFAULT_T2), Some(DEFAULT_T2));
    }

    #[test]
    fn rejects_invalid_base_relationships() {
        assert!(matches!(
            TimerConfig::new(Duration::ZERO, DEFAULT_T2, DEFAULT_T4),
            Err(TimerError::InvalidT1)
        ));
        assert!(matches!(
            TimerConfig::new(
                Duration::from_secs(5),
                Duration::from_secs(4),
                Duration::from_secs(5)
            ),
            Err(TimerError::InvalidT2)
        ));
        assert!(matches!(
            TimerConfig::new(
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(4)
            ),
            Err(TimerError::InvalidT4)
        ));
    }
}
