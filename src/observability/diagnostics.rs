// Copyright 2026 RiyadhAI LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Bounded, privacy-safe per-call event timeline.

use std::collections::VecDeque;
use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

/// Maximum timeline events retained per call.
pub const MAX_TIMELINE_ENTRIES: usize = 1_024;

/// Low-cardinality event safe for production diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimelineEvent {
    /// Initial request left the Runtime.
    InviteSent,
    /// Nonfinal SIP response arrived.
    ProvisionalReceived,
    /// Provisional SDP activated media.
    EarlyMediaApplied,
    /// Final success response arrived.
    InviteAccepted,
    /// Final failure response arrived.
    InviteRejected,
    /// ACK was emitted.
    AckSent,
    /// CANCEL was emitted.
    CancelSent,
    /// BYE was emitted.
    ByeSent,
    /// Call reached terminal state.
    CallEnded,
    /// First valid RTP packet arrived.
    FirstRtpReceived,
    /// Remote RTP identity changed under policy.
    RtpSourceChanged,
    /// Negotiated media was atomically replaced.
    MediaReconfigured,
    /// A bounded realtime queue overflowed.
    QueueOverflow,
    /// Media activity deadline expired.
    MediaTimedOut,
    /// Signaling transport failed.
    TransportFailed,
}

/// One relative timestamp and optional numeric protocol detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimelineEntry {
    /// Offset from call creation.
    pub elapsed: Duration,
    /// Safe event class.
    pub event: TimelineEvent,
    /// Optional SIP status, payload type, or aggregate count.
    pub detail: Option<u32>,
}

/// Fixed-size ring retaining newest diagnostic events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallTimeline {
    started_at: Duration,
    capacity: usize,
    entries: VecDeque<TimelineEntry>,
    overwritten: u64,
}

impl CallTimeline {
    /// Allocates fixed timeline storage.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive capacity and allocation failure.
    pub fn new(started_at: Duration, capacity: usize) -> Result<Self, TimelineError> {
        if capacity == 0 || capacity > MAX_TIMELINE_ENTRIES {
            return Err(TimelineError::InvalidCapacity);
        }
        let mut entries = VecDeque::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| TimelineError::AllocationFailed)?;
        Ok(Self {
            started_at,
            capacity,
            entries,
            overwritten: 0,
        })
    }

    /// Records without exposing raw signaling, addresses, credentials or audio.
    ///
    /// # Errors
    ///
    /// Rejects monotonic time before call creation.
    pub fn record(
        &mut self,
        now: Duration,
        event: TimelineEvent,
        detail: Option<u32>,
    ) -> Result<(), TimelineError> {
        let elapsed = now
            .checked_sub(self.started_at)
            .ok_or(TimelineError::ClockMovedBackward)?;
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
            self.overwritten = self.overwritten.saturating_add(1);
        }
        self.entries.push_back(TimelineEntry {
            elapsed,
            event,
            detail,
        });
        Ok(())
    }

    /// Returns retained entries oldest to newest.
    #[must_use]
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &TimelineEntry> {
        self.entries.iter()
    }

    /// Returns number of old entries overwritten by the ring.
    #[must_use]
    pub const fn overwritten(&self) -> u64 {
        self.overwritten
    }
}

/// Timeline configuration or clock failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimelineError {
    /// Requested ring capacity was invalid.
    InvalidCapacity,
    /// Ring storage allocation failed.
    AllocationFailed,
    /// Supplied monotonic time preceded call creation.
    ClockMovedBackward,
}

impl fmt::Display for TimelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("call diagnostic timeline failed")
    }
}

impl StdError for TimelineError {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CallTimeline, TimelineEvent};

    #[test]
    fn timeline_retains_newest_entries_with_relative_time() {
        let Ok(mut timeline) = CallTimeline::new(Duration::from_secs(10), 2) else {
            panic!("timeline")
        };
        assert!(
            timeline
                .record(Duration::from_secs(11), TimelineEvent::InviteSent, None)
                .is_ok()
        );
        assert!(
            timeline
                .record(Duration::from_secs(12), TimelineEvent::AckSent, None)
                .is_ok()
        );
        assert!(
            timeline
                .record(Duration::from_secs(13), TimelineEvent::CallEnded, None)
                .is_ok()
        );
        let retained = timeline.entries().copied().collect::<Vec<_>>();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].event, TimelineEvent::AckSent);
        assert_eq!(retained[1].elapsed, Duration::from_secs(3));
        assert_eq!(timeline.overwritten(), 1);
    }
}
