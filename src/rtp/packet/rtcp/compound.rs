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

//! Bounded compound and reduced-size RTCP datagram handling.
//!
//! Strict mode requires an SR/RR first packet and a CNAME for that packet's
//! primary source. Reduced-size mode permits feedback or other RTCP packets to
//! stand alone only when that behavior was negotiated by the signaling layer.

use std::error::Error as StdError;
use std::fmt;

use super::bye::{Goodbye, GoodbyeError};
use super::header::{MAX_RTCP_PACKET_BYTES, RtcpHeader, RtcpHeaderError, RtcpPacketType};
use super::receiver_report::{ReceiverReport, ReceiverReportError};
use super::sdes::{SdesItemType, SourceDescription, SourceDescriptionError};
use super::sender_report::{SenderReport, SenderReportError};

/// Maximum RTCP packets accepted in one datagram.
pub const MAX_COMPOUND_PACKETS: usize = 64;

/// Validation policy selected from negotiated RTCP behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompoundPolicy {
    /// RFC 3550 compound rules, including first SR/RR and matching CNAME.
    Strict,
    /// RFC 5506 reduced-size framing; common safety rules still apply.
    ReducedSize,
}

/// An unknown but structurally validated RTCP packet preserved byte-for-byte.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueRtcpPacket {
    packet_type: RtcpPacketType,
    bytes: Vec<u8>,
}

impl OpaqueRtcpPacket {
    /// Returns the classified packet type.
    #[must_use]
    pub const fn packet_type(&self) -> RtcpPacketType {
        self.packet_type
    }

    /// Returns the exact validated packet bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn parse(input: &[u8], header: RtcpHeader) -> Result<Self, CompoundRtcpError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(header.packet_len())
            .map_err(|_| CompoundRtcpError::AllocationFailed)?;
        bytes.extend_from_slice(&input[..header.packet_len()]);
        Ok(Self {
            packet_type: header.packet_type(),
            bytes,
        })
    }
}

impl fmt::Debug for OpaqueRtcpPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueRtcpPacket")
            .field("packet_type", &self.packet_type)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// A supported or safely preserved RTCP packet.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum RtcpPacket {
    /// Sender Report.
    SenderReport(SenderReport),
    /// Receiver Report.
    ReceiverReport(ReceiverReport),
    /// Source Description.
    SourceDescription(SourceDescription),
    /// Goodbye.
    Goodbye(Goodbye),
    /// Unknown or not-yet-decoded valid RTCP packet.
    Opaque(OpaqueRtcpPacket),
}

impl RtcpPacket {
    /// Returns the packet type.
    #[must_use]
    pub const fn packet_type(&self) -> RtcpPacketType {
        match self {
            Self::SenderReport(_) => RtcpPacketType::SenderReport,
            Self::ReceiverReport(_) => RtcpPacketType::ReceiverReport,
            Self::SourceDescription(_) => RtcpPacketType::SourceDescription,
            Self::Goodbye(_) => RtcpPacketType::Goodbye,
            Self::Opaque(packet) => packet.packet_type,
        }
    }

    /// Serializes one packet.
    ///
    /// # Errors
    ///
    /// Delegates validated encoding failures from the concrete packet type.
    pub fn encode(&self) -> Result<Vec<u8>, CompoundRtcpError> {
        match self {
            Self::SenderReport(packet) => packet.encode().map_err(CompoundRtcpError::SenderReport),
            Self::ReceiverReport(packet) => {
                packet.encode().map_err(CompoundRtcpError::ReceiverReport)
            }
            Self::SourceDescription(packet) => packet
                .encode()
                .map_err(CompoundRtcpError::SourceDescription),
            Self::Goodbye(packet) => packet.encode().map_err(CompoundRtcpError::Goodbye),
            Self::Opaque(packet) => Ok(packet.bytes.clone()),
        }
    }

    fn primary_source(&self) -> Option<u32> {
        match self {
            Self::SenderReport(packet) => Some(packet.sender_ssrc()),
            Self::ReceiverReport(packet) => Some(packet.receiver_ssrc()),
            _ => None,
        }
    }

    fn has_padding(&self) -> Result<bool, CompoundRtcpError> {
        match self {
            Self::SenderReport(packet) => Ok(packet.padding_bytes() != 0),
            Self::ReceiverReport(packet) => Ok(packet.padding_bytes() != 0),
            Self::SourceDescription(packet) => Ok(packet.padding_bytes() != 0),
            Self::Goodbye(packet) => Ok(packet.padding_bytes() != 0),
            Self::Opaque(packet) => RtcpHeader::parse(&packet.bytes)
                .map(RtcpHeader::has_padding)
                .map_err(CompoundRtcpError::Header),
        }
    }
}

impl fmt::Debug for RtcpPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtcpPacket")
            .field("packet_type", &self.packet_type())
            .finish_non_exhaustive()
    }
}

/// A validated RTCP datagram containing one or more packets.
#[derive(Clone, Eq, PartialEq)]
pub struct CompoundRtcp {
    policy: CompoundPolicy,
    packets: Vec<RtcpPacket>,
}

impl CompoundRtcp {
    /// Parses an entire RTCP datagram under the selected negotiated policy.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized datagrams, malformed component packets,
    /// excessive packet counts, non-final padding, and strict compound-rule
    /// violations.
    pub fn parse(input: &[u8], policy: CompoundPolicy) -> Result<Self, CompoundRtcpError> {
        validate_datagram_shape(input)?;
        let mut packets = Vec::new();
        let mut offset = 0_usize;
        while offset < input.len() {
            let index = packets.len();
            if index >= MAX_COMPOUND_PACKETS {
                return Err(CompoundRtcpError::TooManyPackets {
                    attempted: index + 1,
                    maximum: MAX_COMPOUND_PACKETS,
                });
            }
            let remaining = &input[offset..];
            let header = RtcpHeader::parse(remaining)
                .map_err(|source| CompoundRtcpError::PacketHeader { index, source })?;
            let next_offset = offset
                .checked_add(header.packet_len())
                .ok_or(CompoundRtcpError::LengthOverflow)?;
            if header.has_padding() && next_offset != input.len() {
                return Err(CompoundRtcpError::PaddingBeforeFinalPacket { index });
            }
            let packet = parse_packet(remaining, header, index)?;
            packets
                .try_reserve(1)
                .map_err(|_| CompoundRtcpError::AllocationFailed)?;
            packets.push(packet);
            offset = next_offset;
        }
        validate_policy(&packets, policy)?;
        Ok(Self { policy, packets })
    }

    /// Constructs a compound datagram from validated packets.
    ///
    /// # Errors
    ///
    /// Enforces packet-count, padding-position, negotiated policy, aggregate
    /// length, and allocation bounds.
    pub fn new(packets: &[RtcpPacket], policy: CompoundPolicy) -> Result<Self, CompoundRtcpError> {
        validate_packet_count(packets.len())?;
        validate_padding_positions(packets)?;
        validate_policy(packets, policy)?;
        checked_encoded_len(packets)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(packets.len())
            .map_err(|_| CompoundRtcpError::AllocationFailed)?;
        owned.extend_from_slice(packets);
        Ok(Self {
            policy,
            packets: owned,
        })
    }

    /// Returns the negotiated validation policy.
    #[must_use]
    pub const fn policy(&self) -> CompoundPolicy {
        self.policy
    }

    /// Returns packets in wire order.
    #[must_use]
    pub fn packets(&self) -> &[RtcpPacket] {
        &self.packets
    }

    /// Serializes the full RTCP datagram.
    ///
    /// # Errors
    ///
    /// Revalidates structural and policy invariants before one bounded output
    /// allocation.
    pub fn encode(&self) -> Result<Vec<u8>, CompoundRtcpError> {
        validate_packet_count(self.packets.len())?;
        validate_padding_positions(&self.packets)?;
        validate_policy(&self.packets, self.policy)?;
        let length = checked_encoded_len(&self.packets)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| CompoundRtcpError::AllocationFailed)?;
        for packet in &self.packets {
            output.extend_from_slice(&packet.encode()?);
        }
        debug_assert_eq!(output.len(), length);
        Ok(output)
    }
}

impl fmt::Debug for CompoundRtcp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let packet_types: Vec<_> = self.packets.iter().map(RtcpPacket::packet_type).collect();
        formatter
            .debug_struct("CompoundRtcp")
            .field("policy", &self.policy)
            .field("packet_types", &packet_types)
            .finish()
    }
}

fn parse_packet(
    input: &[u8],
    header: RtcpHeader,
    index: usize,
) -> Result<RtcpPacket, CompoundRtcpError> {
    match header.packet_type() {
        RtcpPacketType::SenderReport => SenderReport::parse(input)
            .map(|(packet, _)| RtcpPacket::SenderReport(packet))
            .map_err(|source| CompoundRtcpError::TypedPacket {
                index,
                source: Box::new(source),
            }),
        RtcpPacketType::ReceiverReport => ReceiverReport::parse(input)
            .map(|(packet, _)| RtcpPacket::ReceiverReport(packet))
            .map_err(|source| CompoundRtcpError::TypedPacket {
                index,
                source: Box::new(source),
            }),
        RtcpPacketType::SourceDescription => SourceDescription::parse(input)
            .map(|(packet, _)| RtcpPacket::SourceDescription(packet))
            .map_err(|source| CompoundRtcpError::TypedPacket {
                index,
                source: Box::new(source),
            }),
        RtcpPacketType::Goodbye => Goodbye::parse(input)
            .map(|(packet, _)| RtcpPacket::Goodbye(packet))
            .map_err(|source| CompoundRtcpError::TypedPacket {
                index,
                source: Box::new(source),
            }),
        _ => OpaqueRtcpPacket::parse(input, header).map(RtcpPacket::Opaque),
    }
}

fn validate_datagram_shape(input: &[u8]) -> Result<(), CompoundRtcpError> {
    if input.is_empty() {
        return Err(CompoundRtcpError::EmptyDatagram);
    }
    if input.len() > MAX_RTCP_PACKET_BYTES {
        return Err(CompoundRtcpError::DatagramTooLarge {
            actual: input.len(),
            maximum: MAX_RTCP_PACKET_BYTES,
        });
    }
    if !input.len().is_multiple_of(4) {
        return Err(CompoundRtcpError::DatagramNotWordAligned {
            actual: input.len(),
        });
    }
    Ok(())
}

fn validate_packet_count(count: usize) -> Result<(), CompoundRtcpError> {
    if count == 0 {
        return Err(CompoundRtcpError::EmptyDatagram);
    }
    if count > MAX_COMPOUND_PACKETS {
        return Err(CompoundRtcpError::TooManyPackets {
            attempted: count,
            maximum: MAX_COMPOUND_PACKETS,
        });
    }
    Ok(())
}

fn validate_padding_positions(packets: &[RtcpPacket]) -> Result<(), CompoundRtcpError> {
    for (index, packet) in packets.iter().enumerate() {
        if packet.has_padding()? && index + 1 != packets.len() {
            return Err(CompoundRtcpError::PaddingBeforeFinalPacket { index });
        }
    }
    Ok(())
}

fn validate_policy(
    packets: &[RtcpPacket],
    policy: CompoundPolicy,
) -> Result<(), CompoundRtcpError> {
    validate_packet_count(packets.len())?;
    if policy == CompoundPolicy::ReducedSize {
        return Ok(());
    }
    let primary_source = packets[0]
        .primary_source()
        .ok_or(CompoundRtcpError::StrictFirstPacketMustBeReport)?;
    let has_cname = packets.iter().any(|packet| match packet {
        RtcpPacket::SourceDescription(sdes) => sdes.chunks().iter().any(|chunk| {
            chunk.source_ssrc() == primary_source
                && chunk
                    .items()
                    .iter()
                    .any(|item| item.item_type() == SdesItemType::CanonicalName)
        }),
        _ => false,
    });
    if !has_cname {
        return Err(CompoundRtcpError::MissingPrimaryCanonicalName);
    }
    Ok(())
}

fn checked_encoded_len(packets: &[RtcpPacket]) -> Result<usize, CompoundRtcpError> {
    let mut length = 0_usize;
    for packet in packets {
        let encoded = packet.encode()?;
        length = length
            .checked_add(encoded.len())
            .ok_or(CompoundRtcpError::LengthOverflow)?;
        if length > MAX_RTCP_PACKET_BYTES {
            return Err(CompoundRtcpError::DatagramTooLarge {
                actual: length,
                maximum: MAX_RTCP_PACKET_BYTES,
            });
        }
    }
    Ok(length)
}

/// Failure while parsing, constructing, or serializing compound RTCP.
#[derive(Debug)]
#[non_exhaustive]
pub enum CompoundRtcpError {
    /// Datagram contains no RTCP packet.
    EmptyDatagram,
    /// Datagram is not 32-bit aligned.
    DatagramNotWordAligned {
        /// Supplied datagram length.
        actual: usize,
    },
    /// Datagram exceeds UDP capacity.
    DatagramTooLarge {
        /// Supplied or encoded datagram length.
        actual: usize,
        /// Maximum accepted length.
        maximum: usize,
    },
    /// Packet count exceeds the operational bound.
    TooManyPackets {
        /// Packet count that would be accepted.
        attempted: usize,
        /// Maximum accepted packet count.
        maximum: usize,
    },
    /// Common-header parsing failed outside an indexed parse.
    Header(RtcpHeaderError),
    /// Indexed component common-header parsing failed.
    PacketHeader {
        /// Zero-based packet index.
        index: usize,
        /// Detailed common-header error.
        source: RtcpHeaderError,
    },
    /// Indexed typed packet parsing failed.
    TypedPacket {
        /// Zero-based packet index.
        index: usize,
        /// Detailed typed-packet error.
        source: Box<dyn StdError + Send + Sync>,
    },
    /// Sender Report encoding failed.
    SenderReport(SenderReportError),
    /// Receiver Report encoding failed.
    ReceiverReport(ReceiverReportError),
    /// SDES encoding failed.
    SourceDescription(SourceDescriptionError),
    /// BYE encoding failed.
    Goodbye(GoodbyeError),
    /// Only the final component packet may carry RTCP padding.
    PaddingBeforeFinalPacket {
        /// Zero-based padded packet index.
        index: usize,
    },
    /// Strict compound RTCP must begin with SR or RR.
    StrictFirstPacketMustBeReport,
    /// Strict compound RTCP lacks the primary source's CNAME.
    MissingPrimaryCanonicalName,
    /// Checked aggregate length arithmetic overflowed.
    LengthOverflow,
    /// Exact bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for CompoundRtcpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDatagram => formatter.write_str("RTCP datagram is empty"),
            Self::DatagramNotWordAligned { actual } => {
                write!(
                    formatter,
                    "RTCP datagram length {actual} is not word-aligned"
                )
            }
            Self::DatagramTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "RTCP datagram has {actual} bytes, maximum is {maximum}"
                )
            }
            Self::TooManyPackets { attempted, maximum } => {
                write!(
                    formatter,
                    "RTCP datagram has {attempted} packets, maximum is {maximum}"
                )
            }
            Self::Header(_) => formatter.write_str("invalid RTCP header"),
            Self::PacketHeader { index, .. } => write!(formatter, "invalid RTCP packet {index}"),
            Self::TypedPacket { index, .. } => {
                write!(formatter, "invalid typed RTCP packet {index}")
            }
            Self::SenderReport(_) => formatter.write_str("invalid Sender Report"),
            Self::ReceiverReport(_) => formatter.write_str("invalid Receiver Report"),
            Self::SourceDescription(_) => formatter.write_str("invalid Source Description"),
            Self::Goodbye(_) => formatter.write_str("invalid Goodbye packet"),
            Self::PaddingBeforeFinalPacket { index } => {
                write!(formatter, "RTCP packet {index} has non-final padding")
            }
            Self::StrictFirstPacketMustBeReport => {
                formatter.write_str("strict compound RTCP must begin with SR or RR")
            }
            Self::MissingPrimaryCanonicalName => {
                formatter.write_str("strict compound RTCP lacks primary CNAME")
            }
            Self::LengthOverflow => formatter.write_str("compound RTCP length overflow"),
            Self::AllocationFailed => formatter.write_str("compound RTCP allocation failed"),
        }
    }
}

impl StdError for CompoundRtcpError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Header(source) | Self::PacketHeader { source, .. } => Some(source),
            Self::TypedPacket { source, .. } => Some(source.as_ref()),
            Self::SenderReport(source) => Some(source),
            Self::ReceiverReport(source) => Some(source),
            Self::SourceDescription(source) => Some(source),
            Self::Goodbye(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CompoundPolicy, CompoundRtcp, CompoundRtcpError, RtcpPacket};
    use crate::rtp::packet::rtcp::{
        ReceiverReport, SdesChunk, SdesItem, SdesItemType, SourceDescription,
    };

    fn strict_packets() -> Vec<RtcpPacket> {
        let receiver = ReceiverReport::new(42, &[], 0).unwrap_or_else(|_| panic!("receiver"));
        let cname = SdesItem::new(SdesItemType::CanonicalName, b"runtime")
            .unwrap_or_else(|_| panic!("CNAME"));
        let chunk = SdesChunk::new(42, &[cname]).unwrap_or_else(|_| panic!("chunk"));
        let sdes = SourceDescription::new(&[chunk], 0).unwrap_or_else(|_| panic!("SDES"));
        vec![
            RtcpPacket::ReceiverReport(receiver),
            RtcpPacket::SourceDescription(sdes),
        ]
    }

    #[test]
    fn strict_compound_round_trips() {
        let original = CompoundRtcp::new(&strict_packets(), CompoundPolicy::Strict)
            .unwrap_or_else(|_| panic!("compound"));
        let bytes = original.encode().unwrap_or_else(|_| panic!("encode"));
        let parsed =
            CompoundRtcp::parse(&bytes, CompoundPolicy::Strict).unwrap_or_else(|_| panic!("parse"));
        assert_eq!(parsed, original);
        assert_eq!(parsed.packets().len(), 2);
    }

    #[test]
    fn reduced_size_accepts_standalone_feedback_opaquely() {
        let bytes = [0x8f, 206, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2];
        let parsed = CompoundRtcp::parse(&bytes, CompoundPolicy::ReducedSize)
            .unwrap_or_else(|_| panic!("parse"));
        assert_eq!(parsed.packets().len(), 1);
        assert!(matches!(parsed.packets()[0], RtcpPacket::Opaque(_)));
        assert_eq!(parsed.encode().unwrap_or_else(|_| panic!("encode")), bytes);
    }

    #[test]
    fn strict_mode_requires_report_and_matching_cname() {
        let only_sdes = &strict_packets()[1..];
        assert!(matches!(
            CompoundRtcp::new(only_sdes, CompoundPolicy::Strict),
            Err(CompoundRtcpError::StrictFirstPacketMustBeReport)
        ));
        let receiver = ReceiverReport::new(99, &[], 0).unwrap_or_else(|_| panic!("receiver"));
        let packets = [
            RtcpPacket::ReceiverReport(receiver),
            strict_packets().remove(1),
        ];
        assert!(matches!(
            CompoundRtcp::new(&packets, CompoundPolicy::Strict),
            Err(CompoundRtcpError::MissingPrimaryCanonicalName)
        ));
    }

    #[test]
    fn rejects_nonfinal_padding_and_empty_datagram() {
        assert!(matches!(
            CompoundRtcp::parse(&[], CompoundPolicy::ReducedSize),
            Err(CompoundRtcpError::EmptyDatagram)
        ));
        let padded = ReceiverReport::new(42, &[], 4).unwrap_or_else(|_| panic!("receiver"));
        let packets = [
            RtcpPacket::ReceiverReport(padded),
            strict_packets().remove(1),
        ];
        assert!(matches!(
            CompoundRtcp::new(&packets, CompoundPolicy::ReducedSize),
            Err(CompoundRtcpError::PaddingBeforeFinalPacket { index: 0 })
        ));
    }

    #[test]
    fn debug_exposes_only_packet_classes() {
        let compound = CompoundRtcp::new(&strict_packets(), CompoundPolicy::Strict)
            .unwrap_or_else(|_| panic!("compound"));
        let debug = format!("{compound:?}");
        assert!(debug.contains("ReceiverReport"));
        assert!(!debug.contains("runtime"));
        assert!(!debug.contains("42"));
    }
}
