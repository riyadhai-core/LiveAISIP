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

//! RTP receive-stream admission and reporting state.
//!
//! This module is the stateful boundary after SRTP decryption and RTP parsing,
//! but before a packet is admitted to `NetEQ`. It binds negotiated payload type
//! and SSRC, applies RFC sequence validation, updates jitter/loss counters, and
//! produces bounded RTCP reception reports.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use crate::rtp::clock::{RtpClockError, RtpClockRate};
use crate::rtp::packet::RtpPacket;
use crate::rtp::packet::rtcp::{ReceptionReport, ReceptionReportError};
use crate::rtp::stats::{
    JitterEstimator, JitterUpdate, LossSnapshot, SequenceDisposition, SequenceTracker,
};

/// Negotiated immutable receive-stream parameters.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RtpReceiveConfig {
    payload_type: u8,
    clock_rate: RtpClockRate,
    expected_ssrc: Option<u32>,
}

impl fmt::Debug for RtpReceiveConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtpReceiveConfig")
            .field("payload_type", &self.payload_type)
            .field("clock_rate", &self.clock_rate)
            .field("has_expected_ssrc", &self.expected_ssrc.is_some())
            .finish()
    }
}

impl RtpReceiveConfig {
    /// Creates receive configuration for one negotiated payload format.
    ///
    /// # Errors
    ///
    /// Rejects payload types beyond the RTP seven-bit field.
    pub const fn new(
        payload_type: u8,
        clock_rate: RtpClockRate,
        expected_ssrc: Option<u32>,
    ) -> Result<Self, RtpStateError> {
        if payload_type > 127 {
            return Err(RtpStateError::PayloadTypeOutOfRange { payload_type });
        }
        Ok(Self {
            payload_type,
            clock_rate,
            expected_ssrc,
        })
    }

    /// Returns negotiated RTP payload type.
    #[must_use]
    pub const fn payload_type(self) -> u8 {
        self.payload_type
    }

    /// Returns negotiated RTP timestamp clock rate.
    #[must_use]
    pub const fn clock_rate(self) -> RtpClockRate {
        self.clock_rate
    }

    /// Returns signaling-provided SSRC, or `None` for first-packet learning.
    #[must_use]
    pub const fn expected_ssrc(self) -> Option<u32> {
        self.expected_ssrc
    }
}

/// Result of processing one packet at the receive-state boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceivePacketOutcome {
    /// Packet payload type differs from negotiated media.
    PayloadTypeRejected {
        /// Received payload type.
        actual: u8,
        /// Negotiated payload type.
        expected: u8,
    },
    /// Packet SSRC differs from the bound receive source.
    SourceRejected,
    /// Packet is withheld while the source completes sequence probation.
    SequenceRejected {
        /// Detailed sequence-validator result.
        disposition: SequenceDisposition,
    },
    /// Packet is admitted for delivery to `NetEQ`.
    Admitted {
        /// Detailed sequence-validator result.
        disposition: SequenceDisposition,
        /// Jitter-estimator update.
        jitter: JitterUpdate,
    },
}

/// Sequence/source admission for an auxiliary RTP payload such as RFC 4733.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuxiliaryPacketOutcome {
    /// Packet SSRC differs from the active media source.
    SourceRejected,
    /// Shared RTP sequence validation withheld the packet.
    SequenceRejected {
        /// Detailed shared sequence result.
        disposition: SequenceDisposition,
    },
    /// Packet participates in shared sequence/loss accounting but not audio jitter.
    Admitted {
        /// Detailed shared sequence result.
        disposition: SequenceDisposition,
    },
}

impl AuxiliaryPacketOutcome {
    /// Returns whether auxiliary payload parsing may continue.
    #[must_use]
    pub const fn admitted(self) -> bool {
        matches!(self, Self::Admitted { .. })
    }
}

impl ReceivePacketOutcome {
    /// Returns whether payload may be forwarded to `NetEQ`.
    #[must_use]
    pub const fn admitted(self) -> bool {
        matches!(self, Self::Admitted { .. })
    }
}

/// Stateful admission and statistics for one inbound RTP source.
#[derive(Clone, Eq, PartialEq)]
pub struct RtpReceiveState {
    config: RtpReceiveConfig,
    bound_ssrc: Option<u32>,
    sequence: SequenceTracker,
    jitter: JitterEstimator,
    admitted_packets: u64,
    admitted_payload_bytes: u64,
    rejected_payload_type: u64,
    rejected_source: u64,
    rejected_sequence: u64,
    last_sender_report: Option<SenderReportReference>,
}

impl fmt::Debug for RtpReceiveState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtpReceiveState")
            .field("config", &self.config)
            .field("source_bound", &self.bound_ssrc.is_some())
            .field("source_validated", &self.sequence.is_validated())
            .field("admitted_packets", &self.admitted_packets)
            .field("admitted_payload_bytes", &self.admitted_payload_bytes)
            .field("rejected_payload_type", &self.rejected_payload_type)
            .field("rejected_source", &self.rejected_source)
            .field("rejected_sequence", &self.rejected_sequence)
            .field("has_sender_report", &self.last_sender_report.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SenderReportReference {
    compact_ntp: u32,
    received_at: Duration,
}

impl RtpReceiveState {
    /// Creates empty state for one negotiated receive stream.
    #[must_use]
    pub fn new(config: RtpReceiveConfig) -> Self {
        Self {
            bound_ssrc: config.expected_ssrc,
            sequence: SequenceTracker::new(),
            jitter: JitterEstimator::new(config.clock_rate),
            config,
            admitted_packets: 0,
            admitted_payload_bytes: 0,
            rejected_payload_type: 0,
            rejected_source: 0,
            rejected_sequence: 0,
            last_sender_report: None,
        }
    }

    /// Admits a negotiated auxiliary payload into the same RTP sequence space.
    ///
    /// Telephone-event packets must affect expected/lost sequence accounting,
    /// but their constant event timestamps must not pollute audio interarrival
    /// jitter. Payload-type dispatch is performed by [`crate::rtp::session::RtpSession`].
    #[must_use]
    pub fn observe_auxiliary(&mut self, packet: &RtpPacket<'_>) -> AuxiliaryPacketOutcome {
        let header = packet.header();
        if self.bound_ssrc.is_some_and(|ssrc| ssrc != header.ssrc()) {
            self.rejected_source = self.rejected_source.saturating_add(1);
            return AuxiliaryPacketOutcome::SourceRejected;
        }
        self.bound_ssrc.get_or_insert(header.ssrc());
        let disposition = self.sequence.observe(header.sequence_number());
        if !disposition.accepted() {
            self.rejected_sequence = self.rejected_sequence.saturating_add(1);
            return AuxiliaryPacketOutcome::SequenceRejected { disposition };
        }
        self.admitted_packets = self.admitted_packets.saturating_add(1);
        self.admitted_payload_bytes = self
            .admitted_payload_bytes
            .saturating_add(packet.payload().len() as u64);
        AuxiliaryPacketOutcome::Admitted { disposition }
    }

    /// Validates and accounts one parsed RTP packet.
    ///
    /// A stream without a signaling-provided SSRC binds to the first packet
    /// that has the negotiated payload type. Isolated large sequence jumps and
    /// probation packets are not admitted to `NetEQ`.
    ///
    /// # Errors
    ///
    /// Returns media-clock conversion failure without admitting or accounting
    /// the packet as delivered.
    pub fn observe(
        &mut self,
        packet: &RtpPacket<'_>,
        arrival: Duration,
    ) -> Result<ReceivePacketOutcome, RtpStateError> {
        let header = packet.header();
        if header.payload_type() != self.config.payload_type {
            self.rejected_payload_type = self.rejected_payload_type.saturating_add(1);
            return Ok(ReceivePacketOutcome::PayloadTypeRejected {
                actual: header.payload_type(),
                expected: self.config.payload_type,
            });
        }
        if let Some(bound) = self.bound_ssrc {
            if header.ssrc() != bound {
                self.rejected_source = self.rejected_source.saturating_add(1);
                return Ok(ReceivePacketOutcome::SourceRejected);
            }
        } else {
            self.bound_ssrc = Some(header.ssrc());
        }

        let arrival_ticks = self
            .config
            .clock_rate
            .ticks_for_duration(arrival)
            .map_err(RtpStateError::Clock)?;
        let arrival_bytes = arrival_ticks.to_le_bytes();
        let arrival_timestamp = u32::from_le_bytes([
            arrival_bytes[0],
            arrival_bytes[1],
            arrival_bytes[2],
            arrival_bytes[3],
        ]);
        let disposition = self.sequence.observe(header.sequence_number());
        if !disposition.accepted() {
            self.rejected_sequence = self.rejected_sequence.saturating_add(1);
            return Ok(ReceivePacketOutcome::SequenceRejected { disposition });
        }
        if disposition == SequenceDisposition::SourceRestarted {
            self.jitter.reset();
            self.last_sender_report = None;
        }
        let jitter = self.jitter.observe(arrival_timestamp, header.timestamp());
        self.admitted_packets = self.admitted_packets.saturating_add(1);
        let payload_bytes = u64::try_from(packet.payload().len()).unwrap_or(u64::MAX);
        self.admitted_payload_bytes = self.admitted_payload_bytes.saturating_add(payload_bytes);
        Ok(ReceivePacketOutcome::Admitted {
            disposition,
            jitter,
        })
    }

    /// Records the compact NTP timestamp from a received RTCP Sender Report.
    ///
    /// A zero value clears the reference because RTCP uses zero to mean that no
    /// usable Sender Report is available.
    pub fn note_sender_report(&mut self, compact_ntp: u32, received_at: Duration) {
        self.last_sender_report = if compact_ntp == 0 {
            None
        } else {
            Some(SenderReportReference {
                compact_ntp,
                received_at,
            })
        };
    }

    /// Builds an RTCP reception-report block at `now`.
    ///
    /// Calling this advances the interval loss baseline used by the next RTCP
    /// report. Delay since the last Sender Report saturates at the 32-bit RTCP
    /// field instead of wrapping.
    ///
    /// # Errors
    ///
    /// Rejects an unbound or unvalidated source, time moving backwards, and
    /// reception-report construction failure.
    pub fn reception_report(&mut self, now: Duration) -> Result<ReceptionReport, RtpStateError> {
        let source_ssrc = self.bound_ssrc.ok_or(RtpStateError::SourceNotBound)?;
        if !self.sequence.is_validated() {
            return Err(RtpStateError::SourceNotValidated);
        }
        let sequence = self.sequence.snapshot();
        let loss = LossSnapshot::from_sequence(sequence);
        let (last_sender_report, delay) = self.sender_report_timing(now)?;
        ReceptionReport::new(
            source_ssrc,
            loss.fraction_lost(),
            loss.rtcp_cumulative_lost(),
            sequence.extended_highest_sequence_u32(),
            self.jitter.jitter(),
            last_sender_report,
            delay,
        )
        .map_err(RtpStateError::ReceptionReport)
    }

    /// Returns negotiated configuration.
    #[must_use]
    pub const fn config(&self) -> RtpReceiveConfig {
        self.config
    }

    /// Returns currently bound remote SSRC.
    #[must_use]
    pub const fn bound_ssrc(&self) -> Option<u32> {
        self.bound_ssrc
    }

    /// Returns sequence tracker for detailed observability.
    #[must_use]
    pub const fn sequence(&self) -> &SequenceTracker {
        &self.sequence
    }

    /// Returns jitter estimator for detailed observability.
    #[must_use]
    pub const fn jitter(&self) -> &JitterEstimator {
        &self.jitter
    }

    /// Returns packets admitted to `NetEQ`.
    #[must_use]
    pub const fn admitted_packets(&self) -> u64 {
        self.admitted_packets
    }

    /// Returns admitted RTP payload octets.
    #[must_use]
    pub const fn admitted_payload_bytes(&self) -> u64 {
        self.admitted_payload_bytes
    }

    /// Returns payload-type rejection count.
    #[must_use]
    pub const fn rejected_payload_type(&self) -> u64 {
        self.rejected_payload_type
    }

    /// Returns SSRC rejection count.
    #[must_use]
    pub const fn rejected_source(&self) -> u64 {
        self.rejected_source
    }

    /// Returns sequence admission rejection count.
    #[must_use]
    pub const fn rejected_sequence(&self) -> u64 {
        self.rejected_sequence
    }

    fn sender_report_timing(&self, now: Duration) -> Result<(u32, u32), RtpStateError> {
        let Some(reference) = self.last_sender_report else {
            return Ok((0, 0));
        };
        let elapsed = now
            .checked_sub(reference.received_at)
            .ok_or(RtpStateError::TimeMovedBackwards)?;
        Ok((reference.compact_ntp, delay_since_sender_report(elapsed)))
    }
}

fn delay_since_sender_report(elapsed: Duration) -> u32 {
    if elapsed.as_secs() >= 65_536 {
        return u32::MAX;
    }
    let whole = elapsed.as_secs() * 65_536;
    let fraction = u64::from(elapsed.subsec_nanos()) * 65_536 / 1_000_000_000;
    u32::try_from(whole + fraction).unwrap_or(u32::MAX)
}

/// Failure while configuring or updating RTP receive state.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RtpStateError {
    /// Configured payload type exceeds seven-bit RTP capacity.
    PayloadTypeOutOfRange {
        /// Supplied payload type.
        payload_type: u8,
    },
    /// Media-clock conversion failed.
    Clock(RtpClockError),
    /// No remote SSRC has been bound.
    SourceNotBound,
    /// Remote source has not completed sequence probation.
    SourceNotValidated,
    /// Monotonic reporting time preceded Sender Report receipt time.
    TimeMovedBackwards,
    /// Reception-report block construction failed.
    ReceptionReport(ReceptionReportError),
}

impl fmt::Display for RtpStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTypeOutOfRange { payload_type } => {
                write!(formatter, "RTP payload type {payload_type} exceeds 127")
            }
            Self::Clock(_) => formatter.write_str("RTP receive clock conversion failed"),
            Self::SourceNotBound => formatter.write_str("RTP receive source is not bound"),
            Self::SourceNotValidated => {
                formatter.write_str("RTP receive source has not completed probation")
            }
            Self::TimeMovedBackwards => formatter.write_str("RTP monotonic time moved backwards"),
            Self::ReceptionReport(_) => {
                formatter.write_str("RTCP reception-report construction failed")
            }
        }
    }
}

impl StdError for RtpStateError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Clock(source) => Some(source),
            Self::ReceptionReport(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ReceivePacketOutcome, RtpReceiveConfig, RtpReceiveState, RtpStateError};
    use crate::rtp::clock::RtpClockRate;
    use crate::rtp::packet::{RtpHeader, RtpPacket};
    use crate::rtp::stats::SequenceDisposition;

    fn packet(
        payload_type: u8,
        sequence: u16,
        timestamp: u32,
        ssrc: u32,
        payload: &[u8],
    ) -> RtpPacket<'_> {
        let header = RtpHeader::new(payload_type, sequence, timestamp, ssrc)
            .unwrap_or_else(|_| panic!("header"));
        RtpPacket::new(header, None, payload, 0).unwrap_or_else(|_| panic!("packet"))
    }

    fn state(expected_ssrc: Option<u32>) -> RtpReceiveState {
        let config = RtpReceiveConfig::new(0, RtpClockRate::TELEPHONY_8_KHZ, expected_ssrc)
            .unwrap_or_else(|_| panic!("config"));
        RtpReceiveState::new(config)
    }

    #[test]
    fn learns_source_and_admits_after_probation() {
        let mut state = state(None);
        let first = packet(0, 10, 80, 42, &[1; 80]);
        assert!(matches!(
            state
                .observe(&first, Duration::from_millis(10))
                .unwrap_or_else(|_| panic!("observe")),
            ReceivePacketOutcome::SequenceRejected {
                disposition: SequenceDisposition::Probation,
            }
        ));
        assert_eq!(state.bound_ssrc(), Some(42));
        let second = packet(0, 11, 160, 42, &[2; 80]);
        let outcome = state
            .observe(&second, Duration::from_millis(20))
            .unwrap_or_else(|_| panic!("observe"));
        assert!(outcome.admitted());
        assert_eq!(state.admitted_packets(), 1);
        assert_eq!(state.admitted_payload_bytes(), 80);
    }

    #[test]
    fn rejects_payload_and_source_without_mutating_sequence() {
        let mut state = state(Some(42));
        assert!(matches!(
            state
                .observe(&packet(8, 1, 0, 42, &[]), Duration::ZERO)
                .unwrap_or_else(|_| panic!("observe")),
            ReceivePacketOutcome::PayloadTypeRejected { .. }
        ));
        assert!(matches!(
            state
                .observe(&packet(0, 1, 0, 99, &[]), Duration::ZERO)
                .unwrap_or_else(|_| panic!("observe")),
            ReceivePacketOutcome::SourceRejected
        ));
        assert_eq!(state.sequence().received_packets(), 0);
        assert_eq!(state.rejected_payload_type(), 1);
        assert_eq!(state.rejected_source(), 1);
    }

    #[test]
    fn builds_reception_report_with_sender_timing() {
        let mut state = state(Some(42));
        state
            .observe(&packet(0, 10, 80, 42, &[0; 80]), Duration::from_millis(10))
            .unwrap_or_else(|_| panic!("observe"));
        state
            .observe(&packet(0, 11, 160, 42, &[0; 80]), Duration::from_millis(20))
            .unwrap_or_else(|_| panic!("observe"));
        state.note_sender_report(0x1234_5678, Duration::from_secs(1));
        let report = state
            .reception_report(Duration::from_millis(1_500))
            .unwrap_or_else(|_| panic!("report"));
        assert_eq!(report.source_ssrc(), 42);
        assert_eq!(report.last_sender_report(), 0x1234_5678);
        assert_eq!(report.delay_since_last_sender_report(), 32_768);
        assert_eq!(report.interarrival_jitter(), 0);
    }

    #[test]
    fn report_requires_valid_source_and_monotonic_time() {
        let mut unbound = state(None);
        assert_eq!(
            unbound.reception_report(Duration::ZERO),
            Err(RtpStateError::SourceNotBound)
        );
        let mut probation = state(Some(42));
        assert_eq!(
            probation.reception_report(Duration::ZERO),
            Err(RtpStateError::SourceNotValidated)
        );
        probation
            .observe(&packet(0, 1, 0, 42, &[]), Duration::ZERO)
            .unwrap_or_else(|_| panic!("observe"));
        probation
            .observe(&packet(0, 2, 80, 42, &[]), Duration::from_millis(10))
            .unwrap_or_else(|_| panic!("observe"));
        probation.note_sender_report(1, Duration::from_secs(2));
        assert_eq!(
            probation.reception_report(Duration::from_secs(1)),
            Err(RtpStateError::TimeMovedBackwards)
        );
    }

    #[test]
    fn validates_payload_type_configuration() {
        assert_eq!(
            RtpReceiveConfig::new(128, RtpClockRate::TELEPHONY_8_KHZ, None),
            Err(RtpStateError::PayloadTypeOutOfRange { payload_type: 128 })
        );
    }

    #[test]
    fn debug_does_not_expose_bound_source() {
        let state = state(Some(0xdead_beef));
        let debug = format!("{state:?}");
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("3735928559"));
    }
}
