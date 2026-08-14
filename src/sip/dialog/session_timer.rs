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

//! RFC 4028 dialog session refresh scheduling and 422 retry.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

/// Session refresher from local perspective.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refresher {
    /// This endpoint is responsible for refreshing the session.
    Local,
    /// The remote endpoint is responsible for refreshing the session.
    Remote,
}
/// Due timer behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTimerAction {
    /// Send a session refresh request.
    Refresh,
    /// End the dialog because the negotiated interval elapsed.
    Expired,
    /// No timer action is currently required.
    None,
}

/// One negotiated dialog session timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionTimer {
    interval: Duration,
    minimum: Duration,
    refresher: Refresher,
    refresh_at: Duration,
    expires_at: Duration,
    active: bool,
    refreshing: bool,
    refresh_count: u32,
    failed_refreshes: u32,
}
impl SessionTimer {
    /// Creates negotiated timer.
    ///
    /// # Errors
    ///
    /// Rejects zero/below-minimum interval and deadline overflow.
    pub fn new(
        interval_seconds: u32,
        minimum_seconds: u32,
        refresher: Refresher,
        now: Duration,
    ) -> Result<Self, SessionTimerError> {
        if interval_seconds == 0 || minimum_seconds == 0 {
            return Err(SessionTimerError::ZeroInterval);
        }
        if interval_seconds < minimum_seconds {
            return Err(SessionTimerError::BelowMinimum);
        }
        let interval = Duration::from_secs(u64::from(interval_seconds));
        let minimum = Duration::from_secs(u64::from(minimum_seconds));
        let expires_at = now
            .checked_add(interval)
            .ok_or(SessionTimerError::TimeOverflow)?;
        let refresh_at = now
            .checked_add(interval / 2)
            .ok_or(SessionTimerError::TimeOverflow)?;
        Ok(Self {
            interval,
            minimum,
            refresher,
            refresh_at,
            expires_at,
            active: true,
            refreshing: false,
            refresh_count: 0,
            failed_refreshes: 0,
        })
    }
    /// Applies 422 Min-SE and returns retry interval seconds.
    ///
    /// # Errors
    ///
    /// Rejects zero or value outside `u32`.
    pub fn retry_after_422(&self, min_se_seconds: u32) -> Result<u32, SessionTimerError> {
        if min_se_seconds == 0 {
            return Err(SessionTimerError::ZeroInterval);
        }
        let current = u32::try_from(self.interval.as_secs())
            .map_err(|_| SessionTimerError::IntervalTooLarge)?;
        Ok(current.max(min_se_seconds))
    }
    /// Evaluates refresh/expiry independently of transport liveness.
    #[must_use]
    pub fn action(&self, now: Duration) -> SessionTimerAction {
        if !self.active {
            SessionTimerAction::None
        } else if now >= self.expires_at {
            SessionTimerAction::Expired
        } else if self.refresher == Refresher::Local && !self.refreshing && now >= self.refresh_at {
            SessionTimerAction::Refresh
        } else {
            SessionTimerAction::None
        }
    }
    /// Refreshes deadlines after successful negotiation.
    ///
    /// # Errors
    ///
    /// Rejects deadline overflow.
    pub fn refreshed(&mut self, now: Duration) -> Result<(), SessionTimerError> {
        self.expires_at = now
            .checked_add(self.interval)
            .ok_or(SessionTimerError::TimeOverflow)?;
        self.refresh_at = now
            .checked_add(self.interval / 2)
            .ok_or(SessionTimerError::TimeOverflow)?;
        self.refresh_count = self
            .refresh_count
            .checked_add(1)
            .ok_or(SessionTimerError::CounterExhausted)?;
        self.refreshing = false;
        Ok(())
    }

    /// Marks a local refresh request in flight exactly once.
    pub fn start_refresh(&mut self) -> bool {
        if !self.active || self.refresher != Refresher::Local || self.refreshing {
            return false;
        }
        self.refreshing = true;
        true
    }

    /// Records a failed refresh attempt without extending session expiry.
    ///
    /// # Errors
    ///
    /// Rejects a failure with no refresh in flight or counter exhaustion.
    pub fn fail_refresh(&mut self) -> Result<(), SessionTimerError> {
        if !self.refreshing {
            return Err(SessionTimerError::RefreshNotActive);
        }
        self.refreshing = false;
        self.failed_refreshes = self
            .failed_refreshes
            .checked_add(1)
            .ok_or(SessionTimerError::CounterExhausted)?;
        Ok(())
    }

    /// Permanently deactivates this negotiated timer.
    pub const fn deactivate(&mut self) {
        self.active = false;
        self.refreshing = false;
    }

    /// Returns whether a local refresh request is in flight.
    #[must_use]
    pub const fn is_refreshing(&self) -> bool {
        self.refreshing
    }

    /// Returns successful local or remote refresh count.
    #[must_use]
    pub const fn refresh_count(&self) -> u32 {
        self.refresh_count
    }

    /// Returns failed local refresh attempts.
    #[must_use]
    pub const fn failed_refreshes(&self) -> u32 {
        self.failed_refreshes
    }
    /// Returns negotiated minimum.
    #[must_use]
    pub const fn minimum(&self) -> Duration {
        self.minimum
    }
}

/// Session timer failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTimerError {
    /// Interval was zero.
    ZeroInterval,
    /// Interval was below Min-SE.
    BelowMinimum,
    /// Deadline overflowed.
    TimeOverflow,
    /// Interval could not fit wire seconds.
    IntervalTooLarge,
    /// A failure was recorded without an active refresh attempt.
    RefreshNotActive,
    /// Refresh diagnostic counter exhausted.
    CounterExhausted,
}
impl fmt::Display for SessionTimerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP session timer operation failed")
    }
}
impl StdError for SessionTimerError {}

#[cfg(test)]
mod tests {
    use super::{Refresher, SessionTimer, SessionTimerAction};
    use std::time::Duration;
    #[test]
    fn refresh_and_expiry_are_distinct() {
        let local = SessionTimer::new(100, 90, Refresher::Local, Duration::ZERO)
            .unwrap_or_else(|_| panic!("timer"));
        assert_eq!(
            local.action(Duration::from_secs(50)),
            SessionTimerAction::Refresh
        );
        let remote = SessionTimer::new(100, 90, Refresher::Remote, Duration::ZERO)
            .unwrap_or_else(|_| panic!("timer"));
        assert_eq!(
            remote.action(Duration::from_secs(50)),
            SessionTimerAction::None
        );
        assert_eq!(
            remote.action(Duration::from_secs(100)),
            SessionTimerAction::Expired
        );
        assert_eq!(remote.retry_after_422(180), Ok(180));
    }

    #[test]
    fn refresh_in_flight_and_failure_state_are_explicit() {
        let mut timer = SessionTimer::new(100, 90, Refresher::Local, Duration::ZERO)
            .unwrap_or_else(|_| panic!("timer"));
        assert!(timer.start_refresh());
        assert!(!timer.start_refresh());
        assert_eq!(
            timer.action(Duration::from_secs(50)),
            SessionTimerAction::None
        );
        assert!(timer.fail_refresh().is_ok());
        assert_eq!(timer.failed_refreshes(), 1);
        assert!(timer.start_refresh());
        assert!(timer.refreshed(Duration::from_secs(50)).is_ok());
        assert_eq!(timer.refresh_count(), 1);
        assert!(!timer.is_refreshing());
    }
}
