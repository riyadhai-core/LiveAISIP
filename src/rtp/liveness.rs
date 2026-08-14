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

//! Media activity tracking independent of SIP and transport liveness.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

/// Media liveness result at one monotonic instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaHealth {
    /// At least one valid media direction remains active within policy.
    Healthy,
    /// No valid inbound RTP/RTCP arrived before receive deadline.
    ReceiveTimedOut,
    /// Neither valid receive nor successful transmit activity remains.
    Inactive,
}

/// Independent per-session media activity timestamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaLiveness {
    started_at: Duration,
    receive_timeout: Duration,
    inactivity_timeout: Duration,
    last_valid_receive: Option<Duration>,
    last_transmit: Option<Duration>,
    last_rtcp_receive: Option<Duration>,
}

impl MediaLiveness {
    /// Creates media-only liveness state.
    ///
    /// # Errors
    ///
    /// Rejects zero deadlines or an inactivity timeout shorter than receive timeout.
    pub const fn new(
        started_at: Duration,
        receive_timeout: Duration,
        inactivity_timeout: Duration,
    ) -> Result<Self, MediaLivenessError> {
        if receive_timeout.is_zero() || inactivity_timeout.is_zero() {
            return Err(MediaLivenessError::ZeroTimeout);
        }
        if inactivity_timeout.as_nanos() < receive_timeout.as_nanos() {
            return Err(MediaLivenessError::InactivityBeforeReceiveTimeout);
        }
        Ok(Self {
            started_at,
            receive_timeout,
            inactivity_timeout,
            last_valid_receive: None,
            last_transmit: None,
            last_rtcp_receive: None,
        })
    }

    /// Records authenticated and stream-admitted RTP.
    ///
    /// # Errors
    ///
    /// Rejects time before session start.
    pub fn note_valid_receive(&mut self, now: Duration) -> Result<(), MediaLivenessError> {
        validate_monotonic(self.started_at, now)?;
        self.last_valid_receive = Some(now);
        Ok(())
    }

    /// Records a successfully emitted RTP packet.
    ///
    /// # Errors
    ///
    /// Rejects time before session start.
    pub fn note_transmit(&mut self, now: Duration) -> Result<(), MediaLivenessError> {
        validate_monotonic(self.started_at, now)?;
        self.last_transmit = Some(now);
        Ok(())
    }

    /// Records authenticated and parsed RTCP.
    ///
    /// # Errors
    ///
    /// Rejects time before session start.
    pub fn note_rtcp_receive(&mut self, now: Duration) -> Result<(), MediaLivenessError> {
        validate_monotonic(self.started_at, now)?;
        self.last_rtcp_receive = Some(now);
        Ok(())
    }

    /// Evaluates media health without consulting SIP dialog or socket state.
    ///
    /// # Errors
    ///
    /// Rejects time before session start or earlier than recorded activity.
    pub fn health(&self, now: Duration) -> Result<MediaHealth, MediaLivenessError> {
        validate_monotonic(self.started_at, now)?;
        let last_receive =
            latest(self.last_valid_receive, self.last_rtcp_receive).unwrap_or(self.started_at);
        let last_activity =
            latest(Some(last_receive), self.last_transmit).unwrap_or(self.started_at);
        if elapsed(now, last_activity)? >= self.inactivity_timeout {
            return Ok(MediaHealth::Inactive);
        }
        if elapsed(now, last_receive)? >= self.receive_timeout {
            return Ok(MediaHealth::ReceiveTimedOut);
        }
        Ok(MediaHealth::Healthy)
    }
}

fn latest(first: Option<Duration>, second: Option<Duration>) -> Option<Duration> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.max(second)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn validate_monotonic(start: Duration, now: Duration) -> Result<(), MediaLivenessError> {
    if now < start {
        Err(MediaLivenessError::ClockMovedBackward)
    } else {
        Ok(())
    }
}

fn elapsed(now: Duration, then: Duration) -> Result<Duration, MediaLivenessError> {
    now.checked_sub(then)
        .ok_or(MediaLivenessError::ClockMovedBackward)
}

/// Media liveness configuration or clock failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaLivenessError {
    /// A configured deadline was zero.
    ZeroTimeout,
    /// Aggregate inactivity would fire before receive silence.
    InactivityBeforeReceiveTimeout,
    /// Supplied monotonic time regressed.
    ClockMovedBackward,
}

impl fmt::Display for MediaLivenessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RTP media liveness evaluation failed")
    }
}

impl StdError for MediaLivenessError {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{MediaHealth, MediaLiveness};

    #[test]
    fn media_health_is_independent_and_deterministic() {
        let Ok(mut liveness) = MediaLiveness::new(
            Duration::ZERO,
            Duration::from_secs(5),
            Duration::from_secs(10),
        ) else {
            panic!("liveness")
        };
        assert_eq!(
            liveness.health(Duration::from_secs(4)),
            Ok(MediaHealth::Healthy)
        );
        assert_eq!(
            liveness.health(Duration::from_secs(5)),
            Ok(MediaHealth::ReceiveTimedOut)
        );
        assert!(liveness.note_transmit(Duration::from_secs(6)).is_ok());
        assert_eq!(
            liveness.health(Duration::from_secs(10)),
            Ok(MediaHealth::ReceiveTimedOut)
        );
        assert_eq!(
            liveness.health(Duration::from_secs(16)),
            Ok(MediaHealth::Inactive)
        );
    }

    #[test]
    fn valid_rtp_and_rtcp_refresh_receive_health() {
        let Ok(mut liveness) = MediaLiveness::new(
            Duration::ZERO,
            Duration::from_secs(5),
            Duration::from_secs(10),
        ) else {
            panic!("liveness")
        };
        assert!(liveness.note_valid_receive(Duration::from_secs(4)).is_ok());
        assert_eq!(
            liveness.health(Duration::from_secs(8)),
            Ok(MediaHealth::Healthy)
        );
        assert!(liveness.note_rtcp_receive(Duration::from_secs(8)).is_ok());
        assert_eq!(
            liveness.health(Duration::from_secs(12)),
            Ok(MediaHealth::Healthy)
        );
    }
}
