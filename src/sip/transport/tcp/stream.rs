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

//! Hostile-network bounds for SIP TCP/TLS streams.

use crate::sip::framing::MAX_MESSAGE_BYTES;
use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

/// Maximum complete pipelined messages retained per connection.
pub const MAX_PIPELINED_MESSAGES: usize = 64;

/// TCP/TLS framing and deadline policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamLimits {
    /// Maximum unframed receive bytes.
    pub maximum_buffer_bytes: usize,
    /// Maximum completed messages awaiting dispatch.
    pub maximum_pipelined_messages: usize,
    /// No-activity connection deadline.
    pub idle_timeout: Duration,
    /// Establishment/TLS handshake deadline.
    pub handshake_timeout: Duration,
}

impl StreamLimits {
    /// Validates every stream-facing resource limit.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive limits and idle shorter than handshake timeout.
    pub const fn validate(self) -> Result<(), StreamPolicyError> {
        if self.maximum_buffer_bytes == 0 || self.maximum_buffer_bytes > MAX_MESSAGE_BYTES {
            return Err(StreamPolicyError::InvalidBufferLimit);
        }
        if self.maximum_pipelined_messages == 0
            || self.maximum_pipelined_messages > MAX_PIPELINED_MESSAGES
        {
            return Err(StreamPolicyError::InvalidPipelineLimit);
        }
        if self.idle_timeout.is_zero() || self.handshake_timeout.is_zero() {
            return Err(StreamPolicyError::ZeroTimeout);
        }
        if self.idle_timeout.as_nanos() < self.handshake_timeout.as_nanos() {
            return Err(StreamPolicyError::IdleBeforeHandshake);
        }
        Ok(())
    }
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            maximum_buffer_bytes: MAX_MESSAGE_BYTES,
            maximum_pipelined_messages: 16,
            idle_timeout: Duration::from_secs(120),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

/// Connection-local buffer and transport-liveness accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamTracker {
    limits: StreamLimits,
    opened_at: Duration,
    last_activity: Duration,
    buffered_bytes: usize,
    pipelined_messages: usize,
    handshake_complete: bool,
}

impl StreamTracker {
    /// Creates bounded stream state.
    ///
    /// # Errors
    ///
    /// Rejects invalid policy.
    pub fn new(limits: StreamLimits, now: Duration) -> Result<Self, StreamPolicyError> {
        limits.validate()?;
        Ok(Self {
            limits,
            opened_at: now,
            last_activity: now,
            buffered_bytes: 0,
            pipelined_messages: 0,
            handshake_complete: false,
        })
    }

    /// Marks establishment before handshake deadline.
    ///
    /// # Errors
    ///
    /// Rejects regressed time or expired handshake.
    pub fn complete_handshake(&mut self, now: Duration) -> Result<(), StreamPolicyError> {
        if elapsed(now, self.opened_at)? >= self.limits.handshake_timeout {
            return Err(StreamPolicyError::HandshakeTimedOut);
        }
        self.handshake_complete = true;
        self.last_activity = now;
        Ok(())
    }

    /// Accounts an inbound read before buffer growth.
    ///
    /// # Errors
    ///
    /// Rejects pre-handshake input, overflow, or regressed time.
    pub fn admit_read(&mut self, bytes: usize, now: Duration) -> Result<(), StreamPolicyError> {
        if !self.handshake_complete {
            return Err(StreamPolicyError::HandshakeIncomplete);
        }
        let next = self
            .buffered_bytes
            .checked_add(bytes)
            .ok_or(StreamPolicyError::BufferLimitExceeded)?;
        if next > self.limits.maximum_buffer_bytes {
            return Err(StreamPolicyError::BufferLimitExceeded);
        }
        elapsed(now, self.last_activity)?;
        self.buffered_bytes = next;
        self.last_activity = now;
        Ok(())
    }

    /// Accounts one complete framed message.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent length or pipeline overflow.
    pub fn frame_completed(&mut self, bytes: usize) -> Result<(), StreamPolicyError> {
        if bytes > self.buffered_bytes {
            return Err(StreamPolicyError::InvalidFramedLength);
        }
        if self.pipelined_messages == self.limits.maximum_pipelined_messages {
            return Err(StreamPolicyError::PipelineLimitExceeded);
        }
        self.buffered_bytes -= bytes;
        self.pipelined_messages += 1;
        Ok(())
    }

    /// Releases one delivered message.
    pub fn message_delivered(&mut self) {
        self.pipelined_messages = self.pipelined_messages.saturating_sub(1);
    }

    /// Checks transport idle deadline independently of dialog/media state.
    ///
    /// # Errors
    ///
    /// Rejects regressed monotonic time.
    pub fn idle_expired(&self, now: Duration) -> Result<bool, StreamPolicyError> {
        Ok(elapsed(now, self.last_activity)? >= self.limits.idle_timeout)
    }
}

fn elapsed(now: Duration, then: Duration) -> Result<Duration, StreamPolicyError> {
    now.checked_sub(then)
        .ok_or(StreamPolicyError::ClockMovedBackward)
}

/// Stream resource/deadline failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamPolicyError {
    /// Receive buffer limit invalid.
    InvalidBufferLimit,
    /// Pipeline count limit invalid.
    InvalidPipelineLimit,
    /// A deadline was zero.
    ZeroTimeout,
    /// Idle deadline was shorter than handshake deadline.
    IdleBeforeHandshake,
    /// Read arrived before establishment.
    HandshakeIncomplete,
    /// Establishment deadline expired.
    HandshakeTimedOut,
    /// Receive buffer limit exceeded.
    BufferLimitExceeded,
    /// Completed pipeline limit exceeded.
    PipelineLimitExceeded,
    /// Framed length exceeded buffered bytes.
    InvalidFramedLength,
    /// Monotonic time regressed.
    ClockMovedBackward,
}
impl fmt::Display for StreamPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP stream policy rejected operation")
    }
}
impl StdError for StreamPolicyError {}

#[cfg(test)]
mod tests {
    use super::{StreamLimits, StreamPolicyError, StreamTracker};
    use std::time::Duration;

    #[test]
    fn enforces_all_stream_bounds() {
        let limits = StreamLimits {
            maximum_buffer_bytes: 8,
            maximum_pipelined_messages: 1,
            idle_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(2),
        };
        let mut tracker =
            StreamTracker::new(limits, Duration::ZERO).unwrap_or_else(|_| panic!("tracker"));
        assert_eq!(
            tracker.admit_read(1, Duration::from_secs(1)),
            Err(StreamPolicyError::HandshakeIncomplete)
        );
        assert!(tracker.complete_handshake(Duration::from_secs(1)).is_ok());
        assert!(tracker.admit_read(8, Duration::from_secs(2)).is_ok());
        assert_eq!(
            tracker.admit_read(1, Duration::from_secs(2)),
            Err(StreamPolicyError::BufferLimitExceeded)
        );
        assert!(tracker.frame_completed(4).is_ok());
        assert_eq!(
            tracker.frame_completed(4),
            Err(StreamPolicyError::PipelineLimitExceeded)
        );
        assert_eq!(tracker.idle_expired(Duration::from_secs(12)), Ok(true));
    }
}
