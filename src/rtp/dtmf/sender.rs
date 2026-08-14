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

//! Deterministic RFC 4733 telephone-event transmission.
//!
//! The event RTP timestamp remains constant while duration increases. Ending
//! packets repeat one final duration a bounded number of times for reliability;
//! pacing and RTP sequence assignment remain responsibilities of the caller.

use std::error::Error as StdError;
use std::fmt;

use super::event::{MAX_TELEPHONE_EVENT_VOLUME, TelephoneEvent, TelephoneEventCode};

/// Maximum configured end-packet repetition count.
pub const MAX_END_REPETITIONS: u8 = 10;
/// Recommended total end-packet count.
pub const DEFAULT_END_REPETITIONS: u8 = 3;

/// Immutable event generation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DtmfSenderConfig {
    packet_ticks: u16,
    maximum_ticks: u16,
    volume: u8,
    end_repetitions: u8,
}

impl DtmfSenderConfig {
    /// Creates bounded sender configuration.
    ///
    /// # Errors
    ///
    /// Rejects zero cadence, a maximum below one cadence, volume above 63,
    /// and end repetition outside 1–10.
    pub const fn new(
        packet_ticks: u16,
        maximum_ticks: u16,
        volume: u8,
        end_repetitions: u8,
    ) -> Result<Self, DtmfSenderError> {
        if packet_ticks == 0 {
            return Err(DtmfSenderError::ZeroPacketDuration);
        }
        if maximum_ticks < packet_ticks {
            return Err(DtmfSenderError::MaximumDurationTooShort {
                maximum: maximum_ticks,
                packet_duration: packet_ticks,
            });
        }
        if volume > MAX_TELEPHONE_EVENT_VOLUME {
            return Err(DtmfSenderError::VolumeOutOfRange {
                volume,
                maximum: MAX_TELEPHONE_EVENT_VOLUME,
            });
        }
        if end_repetitions == 0 || end_repetitions > MAX_END_REPETITIONS {
            return Err(DtmfSenderError::EndRepetitionsOutOfRange {
                repetitions: end_repetitions,
                maximum: MAX_END_REPETITIONS,
            });
        }
        Ok(Self {
            packet_ticks,
            maximum_ticks,
            volume,
            end_repetitions,
        })
    }

    /// Standard 10 ms 8 kHz cadence with an eight-second ceiling.
    ///
    /// # Errors
    ///
    /// Rejects volume above 63.
    pub const fn pcmu_10ms(volume: u8) -> Result<Self, DtmfSenderError> {
        Self::new(80, 64_000, volume, DEFAULT_END_REPETITIONS)
    }

    /// Returns duration added per generated progress packet.
    #[must_use]
    pub const fn packet_duration_ticks(self) -> u16 {
        self.packet_ticks
    }

    /// Returns automatic event-duration ceiling.
    #[must_use]
    pub const fn maximum_event_duration(self) -> u16 {
        self.maximum_ticks
    }

    /// Returns attenuation volume.
    #[must_use]
    pub const fn volume(self) -> u8 {
        self.volume
    }

    /// Returns total reliable end packets.
    #[must_use]
    pub const fn end_repetitions(self) -> u8 {
        self.end_repetitions
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Active,
    Ending {
        remaining: u8,
        final_duration_ready: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveEvent {
    code: TelephoneEventCode,
    timestamp: u32,
    duration: u16,
    packets: u32,
    phase: Phase,
}

/// Generated event payload with RTP header instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DtmfTransmitPacket {
    timestamp: u32,
    marker: bool,
    event: TelephoneEvent,
    final_retransmission: bool,
}

impl DtmfTransmitPacket {
    /// Returns constant event RTP timestamp.
    #[must_use]
    pub const fn rtp_timestamp(self) -> u32 {
        self.timestamp
    }

    /// Returns RTP marker value.
    #[must_use]
    pub const fn marker(self) -> bool {
        self.marker
    }

    /// Returns telephone-event payload fields.
    #[must_use]
    pub const fn event(self) -> TelephoneEvent {
        self.event
    }

    /// Returns whether this packet completes reliable retransmission.
    #[must_use]
    pub const fn is_final_retransmission(self) -> bool {
        self.final_retransmission
    }
}

/// Constant-memory telephone-event generator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DtmfSender {
    config: DtmfSenderConfig,
    active: Option<ActiveEvent>,
    started: u64,
    completed: u64,
    cancelled: u64,
    emitted: u64,
}

impl DtmfSender {
    /// Creates an idle sender.
    #[must_use]
    pub const fn new(config: DtmfSenderConfig) -> Self {
        Self {
            config,
            active: None,
            started: 0,
            completed: 0,
            cancelled: 0,
            emitted: 0,
        }
    }

    /// Starts an event at a caller-selected RTP timestamp.
    ///
    /// # Errors
    ///
    /// Rejects starting while another event remains active.
    pub fn start(
        &mut self,
        code: TelephoneEventCode,
        timestamp: u32,
    ) -> Result<(), DtmfSenderError> {
        if self.active.is_some() {
            return Err(DtmfSenderError::EventAlreadyActive);
        }
        self.active = Some(ActiveEvent {
            code,
            timestamp,
            duration: 0,
            packets: 0,
            phase: Phase::Active,
        });
        self.started = self.started.saturating_add(1);
        Ok(())
    }

    /// Requests reliable ending on the next generation cadence.
    ///
    /// # Errors
    ///
    /// Rejects an idle sender. Repeated ending requests are idempotent.
    pub fn request_end(&mut self) -> Result<(), DtmfSenderError> {
        let active = self.active.as_mut().ok_or(DtmfSenderError::NoActiveEvent)?;
        if active.phase == Phase::Active {
            active.phase = Phase::Ending {
                remaining: self.config.end_repetitions,
                final_duration_ready: false,
            };
        }
        Ok(())
    }

    /// Generates the next event packet; `None` means idle.
    ///
    /// # Errors
    ///
    /// Returns a defensive payload-construction failure.
    pub fn next_packet(&mut self) -> Result<Option<DtmfTransmitPacket>, DtmfSenderError> {
        let Some(mut active) = self.active else {
            return Ok(None);
        };
        let marker = active.packets == 0;
        let (is_end, final_retransmission) = match active.phase {
            Phase::Active => {
                active.duration = increment(active.duration, self.config);
                if active.duration == self.config.maximum_ticks {
                    let remaining = self.config.end_repetitions - 1;
                    active.phase = Phase::Ending {
                        remaining,
                        final_duration_ready: true,
                    };
                    (true, remaining == 0)
                } else {
                    (false, false)
                }
            }
            Phase::Ending {
                mut remaining,
                final_duration_ready,
            } => {
                if !final_duration_ready {
                    active.duration = increment(active.duration, self.config);
                }
                remaining -= 1;
                active.phase = Phase::Ending {
                    remaining,
                    final_duration_ready: true,
                };
                (true, remaining == 0)
            }
        };
        active.packets = active.packets.saturating_add(1);
        let event = TelephoneEvent::new(active.code, is_end, self.config.volume, active.duration)
            .map_err(|_| DtmfSenderError::PayloadConstructionFailed)?;
        let packet = DtmfTransmitPacket {
            timestamp: active.timestamp,
            marker,
            event,
            final_retransmission,
        };
        self.emitted = self.emitted.saturating_add(1);
        if final_retransmission {
            self.active = None;
            self.completed = self.completed.saturating_add(1);
        } else {
            self.active = Some(active);
        }
        Ok(Some(packet))
    }

    /// Cancels without emitting end packets and returns whether state changed.
    pub fn cancel(&mut self) -> bool {
        if self.active.take().is_some() {
            self.cancelled = self.cancelled.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Returns whether an event is active or ending.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active.is_some()
    }

    /// Returns configuration.
    #[must_use]
    pub const fn config(&self) -> DtmfSenderConfig {
        self.config
    }

    /// Returns started-event count.
    #[must_use]
    pub const fn started_events(&self) -> u64 {
        self.started
    }

    /// Returns reliably completed-event count.
    #[must_use]
    pub const fn completed_events(&self) -> u64 {
        self.completed
    }

    /// Returns cancelled-event count.
    #[must_use]
    pub const fn cancelled_events(&self) -> u64 {
        self.cancelled
    }

    /// Returns generated packet count.
    #[must_use]
    pub const fn emitted_packets(&self) -> u64 {
        self.emitted
    }
}

fn increment(duration: u16, config: DtmfSenderConfig) -> u16 {
    duration
        .saturating_add(config.packet_ticks)
        .min(config.maximum_ticks)
}

/// Sender configuration or lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DtmfSenderError {
    /// Generation duration increment was zero.
    ZeroPacketDuration,
    /// Maximum duration was shorter than one increment.
    MaximumDurationTooShort {
        /// Configured maximum.
        maximum: u16,
        /// Configured increment.
        packet_duration: u16,
    },
    /// Volume exceeded six-bit capacity.
    VolumeOutOfRange {
        /// Supplied volume.
        volume: u8,
        /// Maximum accepted volume.
        maximum: u8,
    },
    /// End repetition count was zero or excessive.
    EndRepetitionsOutOfRange {
        /// Supplied repetition count.
        repetitions: u8,
        /// Maximum accepted count.
        maximum: u8,
    },
    /// Another event remains active.
    EventAlreadyActive,
    /// Ending was requested while idle.
    NoActiveEvent,
    /// Validated configuration unexpectedly failed payload construction.
    PayloadConstructionFailed,
}

impl fmt::Display for DtmfSenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPacketDuration => formatter.write_str("DTMF packet duration is zero"),
            Self::MaximumDurationTooShort { .. } => {
                formatter.write_str("DTMF maximum duration is too short")
            }
            Self::VolumeOutOfRange { volume, maximum } => {
                write!(formatter, "DTMF volume {volume} exceeds {maximum}")
            }
            Self::EndRepetitionsOutOfRange {
                repetitions,
                maximum,
            } => write!(
                formatter,
                "DTMF end repetitions {repetitions} are outside 1..={maximum}"
            ),
            Self::EventAlreadyActive => formatter.write_str("DTMF event is already active"),
            Self::NoActiveEvent => formatter.write_str("no DTMF event is active"),
            Self::PayloadConstructionFailed => {
                formatter.write_str("DTMF payload construction failed")
            }
        }
    }
}

impl StdError for DtmfSenderError {}

#[cfg(test)]
mod tests {
    use super::{DtmfSender, DtmfSenderConfig, DtmfSenderError};
    use crate::rtp::dtmf::{DtmfDigit, TelephoneEventCode};

    fn sender() -> DtmfSender {
        DtmfSender::new(DtmfSenderConfig::new(80, 800, 10, 3).unwrap_or_else(|_| panic!("config")))
    }

    #[test]
    fn emits_progress_then_three_identical_end_packets() {
        let mut sender = sender();
        sender
            .start(TelephoneEventCode::Digit(DtmfDigit::Five), 1_000)
            .unwrap_or_else(|_| panic!("start"));
        let first = sender
            .next_packet()
            .unwrap_or_else(|_| panic!("packet"))
            .unwrap_or_else(|| panic!("some"));
        assert!(first.marker());
        assert_eq!(first.event().duration(), 80);
        sender.next_packet().unwrap_or_else(|_| panic!("packet"));
        sender.request_end().unwrap_or_else(|_| panic!("end"));
        let mut ends = Vec::new();
        for _ in 0..3 {
            ends.push(
                sender
                    .next_packet()
                    .unwrap_or_else(|_| panic!("packet"))
                    .unwrap_or_else(|| panic!("some")),
            );
        }
        assert!(ends.iter().all(|packet| packet.event().is_end()));
        assert!(ends.iter().all(|packet| packet.event().duration() == 240));
        assert!(ends[2].is_final_retransmission());
        assert!(!sender.is_active());
        assert_eq!(sender.completed_events(), 1);
    }

    #[test]
    fn immediate_end_has_marker_and_nonzero_duration() {
        let mut sender = sender();
        sender
            .start(TelephoneEventCode::Flash, 9)
            .unwrap_or_else(|_| panic!("start"));
        sender.request_end().unwrap_or_else(|_| panic!("end"));
        let packet = sender
            .next_packet()
            .unwrap_or_else(|_| panic!("packet"))
            .unwrap_or_else(|| panic!("some"));
        assert!(packet.marker());
        assert!(packet.event().is_end());
        assert_eq!(packet.event().duration(), 80);
        assert_eq!(packet.rtp_timestamp(), 9);
    }

    #[test]
    fn maximum_duration_automatically_ends() {
        let config = DtmfSenderConfig::new(80, 160, 0, 2).unwrap_or_else(|_| panic!("config"));
        let mut sender = DtmfSender::new(config);
        sender
            .start(TelephoneEventCode::Digit(DtmfDigit::One), 1)
            .unwrap_or_else(|_| panic!("start"));
        assert!(
            !sender
                .next_packet()
                .unwrap_or_else(|_| panic!("packet"))
                .unwrap_or_else(|| panic!("some"))
                .event()
                .is_end()
        );
        assert!(
            sender
                .next_packet()
                .unwrap_or_else(|_| panic!("packet"))
                .unwrap_or_else(|| panic!("some"))
                .event()
                .is_end()
        );
        assert!(
            sender
                .next_packet()
                .unwrap_or_else(|_| panic!("packet"))
                .unwrap_or_else(|| panic!("some"))
                .is_final_retransmission()
        );
    }

    #[test]
    fn validates_state_and_configuration() {
        let mut sender = sender();
        assert_eq!(sender.request_end(), Err(DtmfSenderError::NoActiveEvent));
        sender
            .start(TelephoneEventCode::Flash, 1)
            .unwrap_or_else(|_| panic!("start"));
        assert_eq!(
            sender.start(TelephoneEventCode::Flash, 2),
            Err(DtmfSenderError::EventAlreadyActive)
        );
        assert!(sender.cancel());
        assert_eq!(sender.cancelled_events(), 1);
        assert_eq!(
            DtmfSenderConfig::new(0, 80, 0, 3),
            Err(DtmfSenderError::ZeroPacketDuration)
        );
        assert!(matches!(
            DtmfSenderConfig::new(80, 800, 64, 3),
            Err(DtmfSenderError::VolumeOutOfRange { .. })
        ));
    }
}
