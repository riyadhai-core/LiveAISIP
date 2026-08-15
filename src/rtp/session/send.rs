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

//! Allocation-free RTP transmission state and fixed-header serialization.
//!
//! One call thread owns one `RtpSendState`. Successful encoding advances RTP
//! sequence and timestamp state with protocol-defined wrapping arithmetic. The
//! encoded packet borrows caller-provided scratch storage, so the 10 ms media
//! path performs no packet allocation.

use std::error::Error as StdError;
use std::fmt;

use crate::rtp::clock::RtpClockRate;
use crate::rtp::packet::header::{RTP_FIXED_HEADER_BYTES, RTP_VERSION};
use crate::rtp::packet::rtp::MAX_RTP_PACKET_BYTES;

/// Maximum packetization interval admitted by the sender.
pub const MAX_PACKETIZATION_MILLISECONDS: u32 = 200;
/// Largest fixed-header RTP payload admitted by the sender.
pub const MAX_SEND_PAYLOAD_BYTES: usize = MAX_RTP_PACKET_BYTES - RTP_FIXED_HEADER_BYTES;

/// Immutable negotiated RTP send parameters.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RtpSendConfig {
    payload_type: u8,
    clock_rate: RtpClockRate,
    timestamp_step: u32,
    ssrc: u32,
    maximum_payload_bytes: usize,
}

impl RtpSendConfig {
    /// Creates a bounded fixed-header RTP send configuration.
    ///
    /// `timestamp_step` is the number of RTP clock ticks represented by one
    /// packet. For PCMU at 8 kHz it is 80 for 10 ms and 160 for 20 ms.
    ///
    /// # Errors
    ///
    /// Rejects invalid payload types, zero or excessive packetization, and
    /// zero or oversized encoded-payload limits.
    pub const fn new(
        payload_type: u8,
        clock_rate: RtpClockRate,
        timestamp_step: u32,
        ssrc: u32,
        maximum_payload_bytes: usize,
    ) -> Result<Self, RtpSendError> {
        if payload_type > 127 {
            return Err(RtpSendError::InvalidPayloadType { payload_type });
        }
        if timestamp_step == 0 {
            return Err(RtpSendError::ZeroTimestampStep);
        }
        let maximum_step = maximum_timestamp_step(clock_rate);
        if timestamp_step > maximum_step {
            return Err(RtpSendError::TimestampStepTooLarge {
                value: timestamp_step,
                maximum: maximum_step,
            });
        }
        if maximum_payload_bytes == 0 || maximum_payload_bytes > MAX_SEND_PAYLOAD_BYTES {
            return Err(RtpSendError::InvalidPayloadLimit {
                value: maximum_payload_bytes,
                maximum: MAX_SEND_PAYLOAD_BYTES,
            });
        }
        Ok(Self {
            payload_type,
            clock_rate,
            timestamp_step,
            ssrc,
            maximum_payload_bytes,
        })
    }

    /// Creates the standard 20 ms PCMU configuration.
    ///
    /// # Errors
    ///
    /// Rejects only an internally inconsistent constant configuration.
    pub const fn pcmu_20ms(ssrc: u32) -> Result<Self, RtpSendError> {
        Self::new(0, RtpClockRate::TELEPHONY_8_KHZ, 160, ssrc, 160)
    }

    /// Returns negotiated RTP payload type.
    #[must_use]
    pub const fn payload_type(self) -> u8 {
        self.payload_type
    }

    /// Returns negotiated RTP clock rate.
    #[must_use]
    pub const fn clock_rate(self) -> RtpClockRate {
        self.clock_rate
    }

    /// Returns timestamp ticks advanced after each packet.
    #[must_use]
    pub const fn timestamp_step(self) -> u32 {
        self.timestamp_step
    }

    /// Returns local synchronization source identifier.
    #[must_use]
    pub const fn ssrc(self) -> u32 {
        self.ssrc
    }

    /// Returns maximum admitted encoded payload bytes.
    #[must_use]
    pub const fn maximum_payload_bytes(self) -> usize {
        self.maximum_payload_bytes
    }
}

impl fmt::Debug for RtpSendConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtpSendConfig")
            .field("payload_type", &self.payload_type)
            .field("clock_rate", &self.clock_rate)
            .field("timestamp_step", &self.timestamp_step)
            .field("maximum_payload_bytes", &self.maximum_payload_bytes)
            .finish_non_exhaustive()
    }
}

/// One encoded RTP packet borrowing the caller's reusable scratch buffer.
pub struct EncodedRtpPacket<'a> {
    bytes: &'a [u8],
    sequence_number: u16,
    timestamp: u32,
    marker: bool,
    payload_octets: usize,
}

impl EncodedRtpPacket<'_> {
    /// Returns complete RTP wire bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns encoded RTP sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u16 {
        self.sequence_number
    }

    /// Returns encoded RTP timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Returns whether this packet marks a talkspurt/discontinuity boundary.
    #[must_use]
    pub const fn marker(&self) -> bool {
        self.marker
    }

    /// Returns payload octets for RTCP sender accounting.
    #[must_use]
    pub const fn payload_octets(&self) -> usize {
        self.payload_octets
    }
}

impl fmt::Debug for EncodedRtpPacket<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedRtpPacket")
            .field("marker", &self.marker)
            .field("payload_octets", &self.payload_octets)
            .field("wire_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Call-owned outbound RTP sequence, timestamp, and accounting state.
pub struct RtpSendState {
    config: RtpSendConfig,
    next_sequence_number: u16,
    next_timestamp: u32,
    marker_pending: bool,
    packets_encoded: u64,
    payload_octets_encoded: u64,
}

impl RtpSendState {
    /// Creates sender state at caller-randomized initial wire values.
    #[must_use]
    pub const fn new(
        config: RtpSendConfig,
        initial_sequence_number: u16,
        initial_timestamp: u32,
    ) -> Self {
        Self {
            config,
            next_sequence_number: initial_sequence_number,
            next_timestamp: initial_timestamp,
            marker_pending: true,
            packets_encoded: 0,
            payload_octets_encoded: 0,
        }
    }

    /// Encodes one packet directly into reusable caller storage.
    ///
    /// State advances only after every bound and counter check succeeds. The
    /// sequence number and timestamp wrap according to RTP wire semantics.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized payloads, insufficient output storage,
    /// checked length overflow, or exhausted local diagnostics counters.
    pub fn encode_next<'a>(
        &mut self,
        payload: &[u8],
        output: &'a mut [u8],
    ) -> Result<EncodedRtpPacket<'a>, RtpSendError> {
        if payload.is_empty() {
            return Err(RtpSendError::EmptyPayload);
        }
        if payload.len() > self.config.maximum_payload_bytes {
            return Err(RtpSendError::PayloadTooLarge {
                actual: payload.len(),
                maximum: self.config.maximum_payload_bytes,
            });
        }
        let required = RTP_FIXED_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(RtpSendError::LengthOverflow)?;
        if required > output.len() {
            return Err(RtpSendError::OutputTooSmall {
                required,
                available: output.len(),
            });
        }
        let next_packets = self
            .packets_encoded
            .checked_add(1)
            .ok_or(RtpSendError::CounterExhausted)?;
        let payload_octets =
            u64::try_from(payload.len()).map_err(|_| RtpSendError::LengthOverflow)?;
        let next_octets = self
            .payload_octets_encoded
            .checked_add(payload_octets)
            .ok_or(RtpSendError::CounterExhausted)?;

        let sequence_number = self.next_sequence_number;
        let timestamp = self.next_timestamp;
        let marker = self.marker_pending;
        output[0] = RTP_VERSION << 6;
        output[1] = u8::from(marker) << 7 | self.config.payload_type;
        output[2..4].copy_from_slice(&sequence_number.to_be_bytes());
        output[4..8].copy_from_slice(&timestamp.to_be_bytes());
        output[8..12].copy_from_slice(&self.config.ssrc.to_be_bytes());
        output[RTP_FIXED_HEADER_BYTES..required].copy_from_slice(payload);

        self.next_sequence_number = self.next_sequence_number.wrapping_add(1);
        self.next_timestamp = self.next_timestamp.wrapping_add(self.config.timestamp_step);
        self.marker_pending = false;
        self.packets_encoded = next_packets;
        self.payload_octets_encoded = next_octets;

        Ok(EncodedRtpPacket {
            bytes: &output[..required],
            sequence_number,
            timestamp,
            marker,
            payload_octets: payload.len(),
        })
    }

    /// Marks the next encoded packet as a new talkspurt/discontinuity.
    pub const fn mark_discontinuity(&mut self) {
        self.marker_pending = true;
    }

    /// Returns immutable negotiated send configuration.
    #[must_use]
    pub const fn config(&self) -> RtpSendConfig {
        self.config
    }

    /// Returns sequence number that will be used by the next packet.
    #[must_use]
    pub const fn next_sequence_number(&self) -> u16 {
        self.next_sequence_number
    }

    /// Returns timestamp that will be used by the next packet.
    #[must_use]
    pub const fn next_timestamp(&self) -> u32 {
        self.next_timestamp
    }

    /// Returns packets successfully encoded by this state owner.
    #[must_use]
    pub const fn packets_encoded(&self) -> u64 {
        self.packets_encoded
    }

    /// Returns RTP payload octets successfully encoded by this state owner.
    #[must_use]
    pub const fn payload_octets_encoded(&self) -> u64 {
        self.payload_octets_encoded
    }
}

impl fmt::Debug for RtpSendState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtpSendState")
            .field("config", &self.config)
            .field("marker_pending", &self.marker_pending)
            .field("packets_encoded", &self.packets_encoded)
            .field("payload_octets_encoded", &self.payload_octets_encoded)
            .finish_non_exhaustive()
    }
}

const fn maximum_timestamp_step(clock_rate: RtpClockRate) -> u32 {
    let step = clock_rate.get() / (1_000 / MAX_PACKETIZATION_MILLISECONDS);
    if step == 0 { 1 } else { step }
}

/// Outbound RTP configuration or serialization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RtpSendError {
    /// Payload type exceeded the seven-bit RTP field.
    InvalidPayloadType {
        /// Rejected payload type.
        payload_type: u8,
    },
    /// Packet timestamp progression was zero.
    ZeroTimestampStep,
    /// Packetization exceeded the operational 200 ms ceiling.
    TimestampStepTooLarge {
        /// Rejected timestamp step.
        value: u32,
        /// Largest step allowed at the negotiated clock rate.
        maximum: u32,
    },
    /// Configured encoded payload bound was invalid.
    InvalidPayloadLimit {
        /// Rejected bound.
        value: usize,
        /// Absolute fixed-header payload ceiling.
        maximum: usize,
    },
    /// Empty RTP media payload was supplied.
    EmptyPayload,
    /// Encoded codec payload exceeded the negotiated bound.
    PayloadTooLarge {
        /// Supplied bytes.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Reusable packet storage was too small.
    OutputTooSmall {
        /// Exact bytes required.
        required: usize,
        /// Available scratch bytes.
        available: usize,
    },
    /// Packet-length arithmetic overflowed.
    LengthOverflow,
    /// Local 64-bit diagnostic accounting exhausted.
    CounterExhausted,
}

impl fmt::Display for RtpSendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("outbound RTP packet rejected")
    }
}

impl StdError for RtpSendError {}

#[cfg(test)]
mod tests {
    use super::{RtpSendConfig, RtpSendError, RtpSendState};
    use crate::rtp::clock::RtpClockRate;
    use crate::rtp::packet::rtp::RtpPacket;

    fn config() -> RtpSendConfig {
        RtpSendConfig::pcmu_20ms(0x0102_0304).unwrap_or_else(|_| panic!("config"))
    }

    #[test]
    fn writes_pcma_or_pcmu_ready_fixed_header_without_allocation() {
        let mut sender = RtpSendState::new(config(), 65_535, 0xffff_ffb0);
        let mut scratch = [0_u8; 256];
        let pointer = scratch.as_ptr();
        {
            let first = sender
                .encode_next(&[0x55; 160], &mut scratch)
                .unwrap_or_else(|_| panic!("first"));
            assert_eq!(first.bytes().as_ptr(), pointer);
            assert_eq!(first.sequence_number(), 65_535);
            assert_eq!(first.timestamp(), 0xffff_ffb0);
            assert!(first.marker());
            assert_eq!(first.payload_octets(), 160);
            let parsed = RtpPacket::parse(first.bytes()).unwrap_or_else(|_| panic!("parse"));
            assert_eq!(parsed.header().payload_type(), 0);
            assert_eq!(parsed.header().ssrc(), 0x0102_0304);
            assert_eq!(parsed.payload(), &[0x55; 160]);
        }

        let second = sender
            .encode_next(&[0x7f; 160], &mut scratch)
            .unwrap_or_else(|_| panic!("second"));
        assert_eq!(second.sequence_number(), 0);
        assert_eq!(second.timestamp(), 0x50);
        assert!(!second.marker());
        assert_eq!(sender.next_sequence_number(), 1);
        assert_eq!(sender.next_timestamp(), 0xf0);
        assert_eq!(sender.packets_encoded(), 2);
        assert_eq!(sender.payload_octets_encoded(), 320);
    }

    #[test]
    fn failed_encoding_is_transactional_and_discontinuity_rearms_marker() {
        let mut sender = RtpSendState::new(config(), 10, 20);
        let mut undersized = [0_u8; 12];
        assert!(matches!(
            sender.encode_next(&[1], &mut undersized),
            Err(RtpSendError::OutputTooSmall {
                required: 13,
                available: 12,
            })
        ));
        assert_eq!(sender.next_sequence_number(), 10);
        assert_eq!(sender.next_timestamp(), 20);
        assert_eq!(sender.packets_encoded(), 0);

        let mut scratch = [0_u8; 172];
        {
            let first = sender
                .encode_next(&[1; 160], &mut scratch)
                .unwrap_or_else(|_| panic!("first"));
            assert!(first.marker());
        }
        sender.mark_discontinuity();
        let resumed = sender
            .encode_next(&[2; 160], &mut scratch)
            .unwrap_or_else(|_| panic!("resumed"));
        assert!(resumed.marker());
    }

    #[test]
    fn validates_negotiated_bounds_before_hot_path_use() {
        assert!(matches!(
            RtpSendConfig::new(128, RtpClockRate::TELEPHONY_8_KHZ, 160, 1, 160),
            Err(RtpSendError::InvalidPayloadType { .. })
        ));
        assert!(matches!(
            RtpSendConfig::new(0, RtpClockRate::TELEPHONY_8_KHZ, 0, 1, 160),
            Err(RtpSendError::ZeroTimestampStep)
        ));
        assert!(matches!(
            RtpSendConfig::new(0, RtpClockRate::TELEPHONY_8_KHZ, 1_601, 1, 160),
            Err(RtpSendError::TimestampStepTooLarge { .. })
        ));
        assert!(matches!(
            RtpSendConfig::new(0, RtpClockRate::TELEPHONY_8_KHZ, 160, 1, 0),
            Err(RtpSendError::InvalidPayloadLimit { .. })
        ));
    }

    #[test]
    fn rejects_payload_over_negotiated_limit_without_advancing() {
        let mut sender = RtpSendState::new(config(), 5, 10);
        let mut scratch = [0_u8; 256];
        assert!(matches!(
            sender.encode_next(&[0; 161], &mut scratch),
            Err(RtpSendError::PayloadTooLarge {
                actual: 161,
                maximum: 160,
            })
        ));
        assert_eq!(sender.next_sequence_number(), 5);
        assert_eq!(sender.next_timestamp(), 10);
    }
}
