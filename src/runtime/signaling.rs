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

//! Independent signaling, dialog-session, and media health reporting.
//!
//! A connected socket does not prove a SIP dialog is refreshed, and a healthy
//! SIP dialog does not prove RTP is flowing. These axes remain deliberately
//! separate so the call actor can apply the correct recovery policy.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use crate::rtp::liveness::{MediaHealth, MediaLiveness, MediaLivenessError};
use crate::sip::dialog::{SessionTimer, SessionTimerAction};

/// Reliable signaling-transport health.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportHealth {
    /// Recent successful read or write activity exists.
    Healthy,
    /// No I/O occurred before the configured idle deadline.
    IdleTimedOut,
    /// The connection explicitly failed or closed.
    Failed,
}

/// SIP dialog/session health independent of its socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogSessionHealth {
    /// No session timer is negotiated.
    Unmanaged,
    /// The negotiated session interval remains current.
    Healthy,
    /// The local endpoint must refresh the session.
    RefreshDue,
    /// The negotiated session interval expired.
    Expired,
}

/// Three independent health axes at one monotonic instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallHealthSnapshot {
    /// Signaling connection health.
    pub transport: TransportHealth,
    /// SIP session-refresh health.
    pub dialog_session: DialogSessionHealth,
    /// RTP/RTCP activity health.
    pub media: MediaHealth,
}

/// Signaling I/O liveness with an explicit failure latch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportLiveness {
    started_at: Duration,
    idle_timeout: Duration,
    last_io: Duration,
    failed: bool,
}

impl TransportLiveness {
    /// Creates signaling transport liveness.
    ///
    /// # Errors
    ///
    /// Rejects a zero idle timeout.
    pub const fn new(
        started_at: Duration,
        idle_timeout: Duration,
    ) -> Result<Self, SignalingHealthError> {
        if idle_timeout.is_zero() {
            return Err(SignalingHealthError::ZeroTimeout);
        }
        Ok(Self {
            started_at,
            idle_timeout,
            last_io: started_at,
            failed: false,
        })
    }

    /// Records a successfully completed read or write.
    ///
    /// # Errors
    ///
    /// Rejects time regression or activity after failure was latched.
    pub fn note_io(&mut self, now: Duration) -> Result<(), SignalingHealthError> {
        self.validate_time(now)?;
        if self.failed {
            return Err(SignalingHealthError::AlreadyFailed);
        }
        self.last_io = now;
        Ok(())
    }

    /// Permanently latches connection failure.
    pub const fn fail(&mut self) {
        self.failed = true;
    }

    /// Evaluates only signaling-transport health.
    ///
    /// # Errors
    ///
    /// Rejects a monotonic time regression.
    pub fn health(&self, now: Duration) -> Result<TransportHealth, SignalingHealthError> {
        self.validate_time(now)?;
        if self.failed {
            return Ok(TransportHealth::Failed);
        }
        if now
            .checked_sub(self.last_io)
            .ok_or(SignalingHealthError::ClockMovedBackward)?
            >= self.idle_timeout
        {
            return Ok(TransportHealth::IdleTimedOut);
        }
        Ok(TransportHealth::Healthy)
    }

    fn validate_time(&self, now: Duration) -> Result<(), SignalingHealthError> {
        if now < self.started_at || now < self.last_io {
            Err(SignalingHealthError::ClockMovedBackward)
        } else {
            Ok(())
        }
    }
}

/// Evaluates all three health axes without collapsing them into one boolean.
///
/// # Errors
///
/// Propagates clock errors from transport or media liveness.
pub fn health_snapshot(
    now: Duration,
    transport: &TransportLiveness,
    session_timer: Option<&SessionTimer>,
    media: &MediaLiveness,
) -> Result<CallHealthSnapshot, SignalingHealthError> {
    let dialog_session = match session_timer.map(|timer| timer.action(now)) {
        None => DialogSessionHealth::Unmanaged,
        Some(SessionTimerAction::None) => DialogSessionHealth::Healthy,
        Some(SessionTimerAction::Refresh) => DialogSessionHealth::RefreshDue,
        Some(SessionTimerAction::Expired) => DialogSessionHealth::Expired,
    };
    Ok(CallHealthSnapshot {
        transport: transport.health(now)?,
        dialog_session,
        media: media.health(now).map_err(SignalingHealthError::Media)?,
    })
}

/// Health configuration or monotonic-clock failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalingHealthError {
    /// An idle timeout was zero.
    ZeroTimeout,
    /// Monotonic time moved backward.
    ClockMovedBackward,
    /// Activity was recorded after a terminal connection failure.
    AlreadyFailed,
    /// Media liveness evaluation failed.
    Media(MediaLivenessError),
}

impl fmt::Display for SignalingHealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime call health evaluation failed")
    }
}

impl StdError for SignalingHealthError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Media(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{DialogSessionHealth, TransportHealth, TransportLiveness, health_snapshot};
    use crate::rtp::liveness::MediaLiveness;
    use crate::sip::dialog::{Refresher, SessionTimer};

    #[test]
    fn health_axes_do_not_overwrite_each_other() {
        let transport = TransportLiveness::new(Duration::ZERO, Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("transport"));
        let media = MediaLiveness::new(
            Duration::ZERO,
            Duration::from_secs(2),
            Duration::from_secs(10),
        )
        .unwrap_or_else(|_| panic!("media"));
        let session = SessionTimer::new(100, 90, Refresher::Local, Duration::ZERO)
            .unwrap_or_else(|_| panic!("session"));

        let snapshot = health_snapshot(Duration::from_secs(5), &transport, Some(&session), &media)
            .unwrap_or_else(|_| panic!("health"));
        assert_eq!(snapshot.transport, TransportHealth::IdleTimedOut);
        assert_eq!(snapshot.dialog_session, DialogSessionHealth::Healthy);
        assert_eq!(
            snapshot.media,
            crate::rtp::liveness::MediaHealth::ReceiveTimedOut
        );
    }

    #[test]
    fn connection_failure_is_terminal() {
        let mut transport = TransportLiveness::new(Duration::ZERO, Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("transport"));
        transport.fail();
        assert_eq!(
            transport.health(Duration::from_secs(1)),
            Ok(TransportHealth::Failed)
        );
        assert!(transport.note_io(Duration::from_secs(1)).is_err());
    }
}
