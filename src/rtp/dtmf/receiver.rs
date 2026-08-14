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

//! Stateful RFC 4733 telephone-event reception.
//!
//! End packets are normally retransmitted for reliability. This receiver emits
//! completion exactly once, rejects duration regression transactionally, and
//! keeps only one active and one completed identity, so memory is constant.

use std::error::Error as StdError;
use std::fmt;

use crate::rtp::clock::signed_timestamp_distance;

use super::event::{TelephoneEvent, TelephoneEventCode};

/// Receiver interoperability and validation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DtmfReceiverConfig {
    require_marker_on_start: bool,
}

impl DtmfReceiverConfig {
    /// Creates receiver policy.
    #[must_use]
    pub const fn new(require_marker_on_start: bool) -> Self {
        Self {
            require_marker_on_start,
        }
    }

    /// Strict policy requiring the RTP marker on every observed event start.
    #[must_use]
    pub const fn strict() -> Self {
        Self::new(true)
    }

    /// Interoperable policy accepting peers that omit the start marker.
    #[must_use]
    pub const fn interoperable() -> Self {
        Self::new(false)
    }

    /// Returns whether a new event requires the RTP marker bit.
    #[must_use]
    pub const fn require_marker_on_start(self) -> bool {
        self.require_marker_on_start
    }
}

impl Default for DtmfReceiverConfig {
    fn default() -> Self {
        Self::interoperable()
    }
}

/// Semantic result of one valid telephone-event packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DtmfReceiveUpdate {
    /// A new event began.
    Started {
        /// Event code.
        code: TelephoneEventCode,
        /// Constant RTP timestamp identifying event start.
        start_timestamp: u32,
        /// Initial attenuation volume.
        volume: u8,
        /// Initial accumulated duration.
        duration: u16,
    },
    /// Active event duration increased.
    Continued {
        /// Event code.
        code: TelephoneEventCode,
        /// New accumulated duration.
        duration: u16,
    },
    /// Active event completed exactly once.
    Ended {
        /// Event code.
        code: TelephoneEventCode,
        /// Final accumulated duration.
        duration: u16,
        /// True when the first observed packet already carried the end bit.
        recovered_without_start: bool,
    },
    /// A newer event replaced an incomplete active event.
    Replaced {
        /// Interrupted event code.
        previous: TelephoneEventCode,
        /// Newly active event code.
        current: TelephoneEventCode,
        /// New event's initial duration.
        duration: u16,
    },
    /// Packet repeated state already observed.
    Duplicate,
    /// Packet belongs to an older event than current receiver state.
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EventState {
    code: TelephoneEventCode,
    start_timestamp: u32,
    volume: u8,
    duration: u16,
}

/// Constant-memory telephone-event lifecycle receiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DtmfReceiver {
    config: DtmfReceiverConfig,
    active: Option<EventState>,
    completed: Option<EventState>,
    packets: u64,
    duplicates: u64,
    stale: u64,
    completed_events: u64,
    interrupted_events: u64,
}

impl DtmfReceiver {
    /// Creates an empty receiver.
    #[must_use]
    pub const fn new(config: DtmfReceiverConfig) -> Self {
        Self {
            config,
            active: None,
            completed: None,
            packets: 0,
            duplicates: 0,
            stale: 0,
            completed_events: 0,
            interrupted_events: 0,
        }
    }

    /// Observes one parsed telephone-event RTP payload.
    ///
    /// The RTP timestamp must remain constant for all packets belonging to one
    /// event; duration carries progress instead.
    ///
    /// # Errors
    ///
    /// Rejects missing required start markers, conflicting codes sharing one
    /// start timestamp, and duration regression without changing event state.
    pub fn observe(
        &mut self,
        rtp_timestamp: u32,
        marker: bool,
        event: TelephoneEvent,
    ) -> Result<DtmfReceiveUpdate, DtmfReceiveError> {
        self.packets = self.packets.saturating_add(1);
        if let Some(active) = self.active {
            if active.start_timestamp == rtp_timestamp {
                return self.observe_active(active, event);
            }
            if signed_timestamp_distance(rtp_timestamp, active.start_timestamp) <= 0 {
                self.stale = self.stale.saturating_add(1);
                return Ok(DtmfReceiveUpdate::Stale);
            }
            self.validate_new_start(marker)?;
            return Ok(self.replace_active(active, rtp_timestamp, event));
        }

        if let Some(completed) = self.completed {
            if completed.start_timestamp == rtp_timestamp {
                if completed.code != event.code() {
                    return Err(DtmfReceiveError::ConflictingCode {
                        existing: completed.code,
                        received: event.code(),
                    });
                }
                self.duplicates = self.duplicates.saturating_add(1);
                return Ok(DtmfReceiveUpdate::Duplicate);
            }
            if signed_timestamp_distance(rtp_timestamp, completed.start_timestamp) <= 0 {
                self.stale = self.stale.saturating_add(1);
                return Ok(DtmfReceiveUpdate::Stale);
            }
        }
        self.validate_new_start(marker)?;
        Ok(self.start_or_recover(rtp_timestamp, event))
    }

    /// Returns active event code and current duration.
    #[must_use]
    pub const fn active_event(&self) -> Option<(TelephoneEventCode, u16)> {
        match self.active {
            Some(active) => Some((active.code, active.duration)),
            None => None,
        }
    }

    /// Returns observed telephone-event packet count.
    #[must_use]
    pub const fn packets(&self) -> u64 {
        self.packets
    }

    /// Returns deduplicated packet count.
    #[must_use]
    pub const fn duplicates(&self) -> u64 {
        self.duplicates
    }

    /// Returns stale packet count.
    #[must_use]
    pub const fn stale_packets(&self) -> u64 {
        self.stale
    }

    /// Returns emitted completed-event count.
    #[must_use]
    pub const fn completed_events(&self) -> u64 {
        self.completed_events
    }

    /// Returns events replaced before an end packet arrived.
    #[must_use]
    pub const fn interrupted_events(&self) -> u64 {
        self.interrupted_events
    }

    /// Clears active/replay state and counters.
    pub const fn reset(&mut self) {
        self.active = None;
        self.completed = None;
        self.packets = 0;
        self.duplicates = 0;
        self.stale = 0;
        self.completed_events = 0;
        self.interrupted_events = 0;
    }

    fn observe_active(
        &mut self,
        active: EventState,
        event: TelephoneEvent,
    ) -> Result<DtmfReceiveUpdate, DtmfReceiveError> {
        if active.code != event.code() {
            return Err(DtmfReceiveError::ConflictingCode {
                existing: active.code,
                received: event.code(),
            });
        }
        if event.duration() < active.duration {
            return Err(DtmfReceiveError::DurationRegressed {
                previous: active.duration,
                received: event.duration(),
            });
        }
        if event.duration() == active.duration && !event.is_end() {
            self.duplicates = self.duplicates.saturating_add(1);
            return Ok(DtmfReceiveUpdate::Duplicate);
        }
        let updated = EventState {
            volume: event.volume(),
            duration: event.duration(),
            ..active
        };
        if event.is_end() {
            self.active = None;
            self.completed = Some(updated);
            self.completed_events = self.completed_events.saturating_add(1);
            Ok(DtmfReceiveUpdate::Ended {
                code: updated.code,
                duration: updated.duration,
                recovered_without_start: false,
            })
        } else {
            self.active = Some(updated);
            Ok(DtmfReceiveUpdate::Continued {
                code: updated.code,
                duration: updated.duration,
            })
        }
    }

    fn start_or_recover(&mut self, rtp_timestamp: u32, event: TelephoneEvent) -> DtmfReceiveUpdate {
        let state = EventState {
            code: event.code(),
            start_timestamp: rtp_timestamp,
            volume: event.volume(),
            duration: event.duration(),
        };
        if event.is_end() {
            self.completed = Some(state);
            self.completed_events = self.completed_events.saturating_add(1);
            DtmfReceiveUpdate::Ended {
                code: state.code,
                duration: state.duration,
                recovered_without_start: true,
            }
        } else {
            self.active = Some(state);
            DtmfReceiveUpdate::Started {
                code: state.code,
                start_timestamp: state.start_timestamp,
                volume: state.volume,
                duration: state.duration,
            }
        }
    }

    fn replace_active(
        &mut self,
        active: EventState,
        rtp_timestamp: u32,
        event: TelephoneEvent,
    ) -> DtmfReceiveUpdate {
        self.interrupted_events = self.interrupted_events.saturating_add(1);
        let current = event.code();
        let duration = event.duration();
        let state = EventState {
            code: current,
            start_timestamp: rtp_timestamp,
            volume: event.volume(),
            duration,
        };
        if event.is_end() {
            self.active = None;
            self.completed = Some(state);
            self.completed_events = self.completed_events.saturating_add(1);
        } else {
            self.active = Some(state);
        }
        DtmfReceiveUpdate::Replaced {
            previous: active.code,
            current,
            duration,
        }
    }

    fn validate_new_start(&self, marker: bool) -> Result<(), DtmfReceiveError> {
        if self.config.require_marker_on_start && !marker {
            return Err(DtmfReceiveError::MissingStartMarker);
        }
        Ok(())
    }
}

impl Default for DtmfReceiver {
    fn default() -> Self {
        Self::new(DtmfReceiverConfig::default())
    }
}

/// Semantic telephone-event reception failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DtmfReceiveError {
    /// Strict policy required marker bit on a new event.
    MissingStartMarker,
    /// One start timestamp was reused for a different event code.
    ConflictingCode {
        /// Existing event code.
        existing: TelephoneEventCode,
        /// Received conflicting code.
        received: TelephoneEventCode,
    },
    /// Accumulated duration moved backwards.
    DurationRegressed {
        /// Previously accepted duration.
        previous: u16,
        /// Received smaller duration.
        received: u16,
    },
}

impl fmt::Display for DtmfReceiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingStartMarker => formatter.write_str("DTMF event start lacks RTP marker"),
            Self::ConflictingCode { existing, received } => write!(
                formatter,
                "DTMF timestamp changed code from {existing:?} to {received:?}"
            ),
            Self::DurationRegressed { previous, received } => write!(
                formatter,
                "DTMF duration regressed from {previous} to {received}"
            ),
        }
    }
}

impl StdError for DtmfReceiveError {}

#[cfg(test)]
mod tests {
    use super::{DtmfReceiveError, DtmfReceiveUpdate, DtmfReceiver, DtmfReceiverConfig};
    use crate::rtp::dtmf::{DtmfDigit, TelephoneEvent, TelephoneEventCode};

    fn event(digit: DtmfDigit, end: bool, duration: u16) -> TelephoneEvent {
        TelephoneEvent::new(TelephoneEventCode::Digit(digit), end, 10, duration)
            .unwrap_or_else(|_| panic!("event"))
    }

    #[test]
    fn emits_one_complete_lifecycle_and_deduplicates_end() {
        let mut receiver = DtmfReceiver::new(DtmfReceiverConfig::strict());
        assert!(matches!(
            receiver.observe(100, true, event(DtmfDigit::Five, false, 80)),
            Ok(DtmfReceiveUpdate::Started { .. })
        ));
        assert_eq!(
            receiver.observe(100, false, event(DtmfDigit::Five, false, 160)),
            Ok(DtmfReceiveUpdate::Continued {
                code: TelephoneEventCode::Digit(DtmfDigit::Five),
                duration: 160,
            })
        );
        assert!(matches!(
            receiver.observe(100, false, event(DtmfDigit::Five, true, 240)),
            Ok(DtmfReceiveUpdate::Ended {
                recovered_without_start: false,
                ..
            })
        ));
        assert_eq!(
            receiver.observe(100, false, event(DtmfDigit::Five, true, 240)),
            Ok(DtmfReceiveUpdate::Duplicate)
        );
        assert_eq!(receiver.completed_events(), 1);
        assert_eq!(receiver.duplicates(), 1);
    }

    #[test]
    fn recovers_when_only_end_packet_arrives() {
        let mut receiver = DtmfReceiver::default();
        assert!(matches!(
            receiver.observe(10, false, event(DtmfDigit::One, true, 320)),
            Ok(DtmfReceiveUpdate::Ended {
                recovered_without_start: true,
                ..
            })
        ));
        assert_eq!(receiver.completed_events(), 1);
    }

    #[test]
    fn rejects_regression_and_conflict_transactionally() {
        let mut receiver = DtmfReceiver::default();
        receiver
            .observe(10, false, event(DtmfDigit::One, false, 160))
            .unwrap_or_else(|_| panic!("start"));
        assert_eq!(
            receiver.observe(10, false, event(DtmfDigit::One, false, 80)),
            Err(DtmfReceiveError::DurationRegressed {
                previous: 160,
                received: 80,
            })
        );
        assert_eq!(
            receiver.observe(10, false, event(DtmfDigit::Two, false, 240)),
            Err(DtmfReceiveError::ConflictingCode {
                existing: TelephoneEventCode::Digit(DtmfDigit::One),
                received: TelephoneEventCode::Digit(DtmfDigit::Two),
            })
        );
        assert_eq!(
            receiver.active_event(),
            Some((TelephoneEventCode::Digit(DtmfDigit::One), 160))
        );
    }

    #[test]
    fn strict_marker_policy_and_interoperable_policy_differ() {
        let mut strict = DtmfReceiver::new(DtmfReceiverConfig::strict());
        assert_eq!(
            strict.observe(1, false, event(DtmfDigit::One, false, 80)),
            Err(DtmfReceiveError::MissingStartMarker)
        );
        let mut interoperable = DtmfReceiver::default();
        assert!(
            interoperable
                .observe(1, false, event(DtmfDigit::One, false, 80))
                .is_ok()
        );
    }

    #[test]
    fn newer_event_replaces_active_and_wrap_is_ordered() {
        let mut receiver = DtmfReceiver::default();
        receiver
            .observe(u32::MAX - 10, true, event(DtmfDigit::One, false, 80))
            .unwrap_or_else(|_| panic!("start"));
        assert_eq!(
            receiver.observe(20, true, event(DtmfDigit::Two, false, 80)),
            Ok(DtmfReceiveUpdate::Replaced {
                previous: TelephoneEventCode::Digit(DtmfDigit::One),
                current: TelephoneEventCode::Digit(DtmfDigit::Two),
                duration: 80,
            })
        );
        assert_eq!(receiver.interrupted_events(), 1);
        assert_eq!(
            receiver.observe(u32::MAX - 20, false, event(DtmfDigit::One, true, 160)),
            Ok(DtmfReceiveUpdate::Stale)
        );
        assert_eq!(receiver.stale_packets(), 1);
    }

    #[test]
    fn reset_clears_bounded_state_and_counters() {
        let mut receiver = DtmfReceiver::default();
        receiver
            .observe(1, false, event(DtmfDigit::One, true, 80))
            .unwrap_or_else(|_| panic!("event"));
        receiver.reset();
        assert_eq!(receiver.active_event(), None);
        assert_eq!(receiver.packets(), 0);
        assert_eq!(receiver.completed_events(), 0);
    }
}
