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

//! Strict RTCP common-header parsing and serialization.
//!
//! The parser resolves the RFC 3550 length field into an exact packet boundary
//! before any packet-specific decoder runs. It also validates version, packet
//! type range, UDP size, and padding framing at this shared trust boundary.

use std::error::Error as StdError;
use std::fmt;

/// RTCP protocol version supported by this stack.
pub const RTCP_VERSION: u8 = 2;
/// Size of the RTCP common header.
pub const RTCP_HEADER_BYTES: usize = 4;
/// Smallest packet type in the RTCP multiplexing range.
pub const MIN_RTCP_PACKET_TYPE: u8 = 192;
/// Largest packet type in the RTCP multiplexing range.
pub const MAX_RTCP_PACKET_TYPE: u8 = 223;
/// Largest four-byte-aligned RTCP packet fitting in a UDP payload.
pub const MAX_RTCP_PACKET_BYTES: usize = 65_504;
/// Maximum value of the five-bit count or feedback-format field.
pub const MAX_RTCP_COUNT: u8 = 31;

/// RTCP packet type, preserving unrecognized values in the RTCP range.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RtcpPacketType {
    /// Full intra request, legacy assignment.
    Fir,
    /// Negative acknowledgment, legacy assignment.
    Nack,
    /// Sender report.
    SenderReport,
    /// Receiver report.
    ReceiverReport,
    /// Source description.
    SourceDescription,
    /// Goodbye.
    Goodbye,
    /// Application-defined packet.
    ApplicationDefined,
    /// Transport-layer feedback.
    TransportFeedback,
    /// Payload-specific feedback.
    PayloadFeedback,
    /// Extended report.
    ExtendedReport,
    /// Unrecognized but valid RTCP-range packet type.
    Other(u8),
}

impl RtcpPacketType {
    /// Classifies a raw packet-type octet.
    ///
    /// # Errors
    ///
    /// Values outside 192–223 cannot be unambiguously treated as RTCP.
    pub const fn from_raw(value: u8) -> Result<Self, RtcpHeaderError> {
        match value {
            192 => Ok(Self::Fir),
            193 => Ok(Self::Nack),
            200 => Ok(Self::SenderReport),
            201 => Ok(Self::ReceiverReport),
            202 => Ok(Self::SourceDescription),
            203 => Ok(Self::Goodbye),
            204 => Ok(Self::ApplicationDefined),
            205 => Ok(Self::TransportFeedback),
            206 => Ok(Self::PayloadFeedback),
            207 => Ok(Self::ExtendedReport),
            value if value >= MIN_RTCP_PACKET_TYPE && value <= MAX_RTCP_PACKET_TYPE => {
                Ok(Self::Other(value))
            }
            _ => Err(RtcpHeaderError::PacketTypeOutOfRange { packet_type: value }),
        }
    }

    /// Returns the wire packet-type octet.
    #[must_use]
    pub const fn as_raw(self) -> u8 {
        match self {
            Self::Fir => 192,
            Self::Nack => 193,
            Self::SenderReport => 200,
            Self::ReceiverReport => 201,
            Self::SourceDescription => 202,
            Self::Goodbye => 203,
            Self::ApplicationDefined => 204,
            Self::TransportFeedback => 205,
            Self::PayloadFeedback => 206,
            Self::ExtendedReport => 207,
            Self::Other(value) => value,
        }
    }
}

/// A validated RTCP common header and its resolved packet boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtcpHeader {
    padding: bool,
    count: u8,
    packet_type: RtcpPacketType,
    packet_len: usize,
    padding_bytes: u8,
}

impl RtcpHeader {
    /// Parses an RTCP common header and validates its full declared boundary.
    ///
    /// Trailing input is allowed because it may contain following packets in a
    /// compound RTCP datagram. [`Self::packet_len`] identifies the exact slice.
    ///
    /// # Errors
    ///
    /// Rejects truncation, unsupported versions, invalid packet types, lengths
    /// beyond UDP capacity, and malformed padding.
    pub fn parse(input: &[u8]) -> Result<Self, RtcpHeaderError> {
        if input.len() < RTCP_HEADER_BYTES {
            return Err(RtcpHeaderError::Truncated {
                required: RTCP_HEADER_BYTES,
                available: input.len(),
            });
        }
        let version = input[0] >> 6;
        if version != RTCP_VERSION {
            return Err(RtcpHeaderError::UnsupportedVersion { version });
        }
        let packet_type = RtcpPacketType::from_raw(input[1])?;
        let length_words_minus_one = usize::from(u16::from_be_bytes([input[2], input[3]]));
        let packet_len = length_words_minus_one
            .checked_add(1)
            .and_then(|words| words.checked_mul(4))
            .ok_or(RtcpHeaderError::LengthOverflow)?;
        if packet_len > MAX_RTCP_PACKET_BYTES {
            return Err(RtcpHeaderError::PacketTooLarge {
                actual: packet_len,
                maximum: MAX_RTCP_PACKET_BYTES,
            });
        }
        if input.len() < packet_len {
            return Err(RtcpHeaderError::Truncated {
                required: packet_len,
                available: input.len(),
            });
        }

        let padding = input[0] & 0x20 != 0;
        let padding_bytes = if padding {
            let value = input[packet_len - 1];
            if value == 0 {
                return Err(RtcpHeaderError::ZeroPaddingLength);
            }
            let body_bytes = packet_len - RTCP_HEADER_BYTES;
            if usize::from(value) > body_bytes {
                return Err(RtcpHeaderError::PaddingExceedsBody {
                    padding: usize::from(value),
                    available: body_bytes,
                });
            }
            value
        } else {
            0
        };

        Ok(Self {
            padding,
            count: input[0] & 0x1f,
            packet_type,
            packet_len,
            padding_bytes,
        })
    }

    /// Constructs a common header for an already sized packet.
    ///
    /// `packet_len` includes this four-byte header and any padding.
    ///
    /// # Errors
    ///
    /// Rejects counts above 31, non-word-aligned sizes, sizes beyond UDP
    /// capacity, and inconsistent padding.
    pub fn new(
        count: u8,
        packet_type: RtcpPacketType,
        packet_len: usize,
        padding_bytes: u8,
    ) -> Result<Self, RtcpHeaderError> {
        if count > MAX_RTCP_COUNT {
            return Err(RtcpHeaderError::CountOutOfRange { count });
        }
        RtcpPacketType::from_raw(packet_type.as_raw())?;
        validate_packet_len(packet_len)?;
        if usize::from(padding_bytes) > packet_len - RTCP_HEADER_BYTES {
            return Err(RtcpHeaderError::PaddingExceedsBody {
                padding: usize::from(padding_bytes),
                available: packet_len - RTCP_HEADER_BYTES,
            });
        }
        Ok(Self {
            padding: padding_bytes != 0,
            count,
            packet_type,
            packet_len,
            padding_bytes,
        })
    }

    /// Returns whether this packet declares padding.
    #[must_use]
    pub const fn has_padding(self) -> bool {
        self.padding
    }

    /// Returns the five-bit report count, source count, or feedback format.
    #[must_use]
    pub const fn count(self) -> u8 {
        self.count
    }

    /// Returns the classified packet type.
    #[must_use]
    pub const fn packet_type(self) -> RtcpPacketType {
        self.packet_type
    }

    /// Returns exact packet bytes declared by the RTCP length field.
    #[must_use]
    pub const fn packet_len(self) -> usize {
        self.packet_len
    }

    /// Returns padding bytes including the final padding-count octet.
    #[must_use]
    pub const fn padding_bytes(self) -> u8 {
        self.padding_bytes
    }

    /// Returns the unpadded packet-body length after the common header.
    #[must_use]
    pub const fn unpadded_body_len(self) -> usize {
        self.packet_len - RTCP_HEADER_BYTES - self.padding_bytes as usize
    }

    /// Encodes the four-byte common header.
    ///
    /// # Errors
    ///
    /// Rejects an internally unrepresentable length defensively.
    pub fn encode(self) -> Result<[u8; RTCP_HEADER_BYTES], RtcpHeaderError> {
        let words = self.packet_len / 4;
        let encoded_length = words
            .checked_sub(1)
            .ok_or(RtcpHeaderError::LengthOverflow)?;
        let encoded_length =
            u16::try_from(encoded_length).map_err(|_| RtcpHeaderError::LengthOverflow)?;
        let length_bytes = encoded_length.to_be_bytes();
        Ok([
            RTCP_VERSION << 6 | u8::from(self.padding) << 5 | self.count,
            self.packet_type.as_raw(),
            length_bytes[0],
            length_bytes[1],
        ])
    }
}

fn validate_packet_len(packet_len: usize) -> Result<(), RtcpHeaderError> {
    if packet_len < RTCP_HEADER_BYTES {
        return Err(RtcpHeaderError::PacketTooShort {
            actual: packet_len,
            minimum: RTCP_HEADER_BYTES,
        });
    }
    if !packet_len.is_multiple_of(4) {
        return Err(RtcpHeaderError::PacketNotWordAligned { actual: packet_len });
    }
    if packet_len > MAX_RTCP_PACKET_BYTES {
        return Err(RtcpHeaderError::PacketTooLarge {
            actual: packet_len,
            maximum: MAX_RTCP_PACKET_BYTES,
        });
    }
    Ok(())
}

/// Failure while parsing or constructing an RTCP common header.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RtcpHeaderError {
    /// Input ends before its declared packet boundary.
    Truncated {
        /// Required byte count.
        required: usize,
        /// Available byte count.
        available: usize,
    },
    /// The two-bit version is not RTP/RTCP version 2.
    UnsupportedVersion {
        /// Received version.
        version: u8,
    },
    /// Packet type is outside the RTCP multiplexing range.
    PacketTypeOutOfRange {
        /// Received packet type.
        packet_type: u8,
    },
    /// Five-bit count was not representable.
    CountOutOfRange {
        /// Supplied count.
        count: u8,
    },
    /// Packet is shorter than the common header.
    PacketTooShort {
        /// Supplied packet length.
        actual: usize,
        /// Minimum packet length.
        minimum: usize,
    },
    /// Constructed packet size is not four-byte aligned.
    PacketNotWordAligned {
        /// Supplied packet length.
        actual: usize,
    },
    /// Packet exceeds the bounded UDP payload size.
    PacketTooLarge {
        /// Declared packet length.
        actual: usize,
        /// Maximum accepted packet length.
        maximum: usize,
    },
    /// Checked length arithmetic overflowed.
    LengthOverflow,
    /// Padding bit is set but its count octet is zero.
    ZeroPaddingLength,
    /// Padding extends into or before the common header.
    PaddingExceedsBody {
        /// Declared padding bytes.
        padding: usize,
        /// Available packet-body bytes.
        available: usize,
    },
}

impl fmt::Display for RtcpHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                required,
                available,
            } => write!(
                formatter,
                "truncated RTCP packet: requires {required} bytes, has {available}"
            ),
            Self::UnsupportedVersion { version } => {
                write!(formatter, "unsupported RTCP version {version}")
            }
            Self::PacketTypeOutOfRange { packet_type } => {
                write!(formatter, "RTCP packet type {packet_type} is out of range")
            }
            Self::CountOutOfRange { count } => {
                write!(formatter, "RTCP count {count} exceeds 31")
            }
            Self::PacketTooShort { actual, minimum } => write!(
                formatter,
                "RTCP packet has {actual} bytes, minimum is {minimum}"
            ),
            Self::PacketNotWordAligned { actual } => write!(
                formatter,
                "RTCP packet length {actual} is not four-byte aligned"
            ),
            Self::PacketTooLarge { actual, maximum } => write!(
                formatter,
                "RTCP packet has {actual} bytes, maximum is {maximum}"
            ),
            Self::LengthOverflow => formatter.write_str("RTCP packet length overflow"),
            Self::ZeroPaddingLength => formatter.write_str("RTCP padding count is zero"),
            Self::PaddingExceedsBody { padding, available } => write!(
                formatter,
                "RTCP padding count {padding} exceeds {available} body bytes"
            ),
        }
    }
}

impl StdError for RtcpHeaderError {}

#[cfg(test)]
mod tests {
    use super::{MAX_RTCP_PACKET_BYTES, RtcpHeader, RtcpHeaderError, RtcpPacketType};

    #[test]
    fn parses_sender_report_boundary_with_trailing_compound_data() {
        let bytes = [0x81, 200, 0, 1, 1, 2, 3, 4, 9, 9, 9, 9];
        let header = RtcpHeader::parse(&bytes).unwrap_or_else(|_| panic!("header"));
        assert_eq!(header.packet_type(), RtcpPacketType::SenderReport);
        assert_eq!(header.count(), 1);
        assert_eq!(header.packet_len(), 8);
        assert_eq!(header.unpadded_body_len(), 4);
        assert_eq!(
            header.encode().unwrap_or_else(|_| panic!("encode")),
            [0x81, 200, 0, 1]
        );
    }

    #[test]
    fn validates_and_excludes_padding_from_body_length() {
        let bytes = [0xa0, 203, 0, 1, 0, 0, 0, 4];
        let header = RtcpHeader::parse(&bytes).unwrap_or_else(|_| panic!("header"));
        assert!(header.has_padding());
        assert_eq!(header.padding_bytes(), 4);
        assert_eq!(header.unpadded_body_len(), 0);
    }

    #[test]
    fn rejects_wrong_version_type_and_truncation() {
        assert_eq!(
            RtcpHeader::parse(&[0; 3]),
            Err(RtcpHeaderError::Truncated {
                required: 4,
                available: 3,
            })
        );
        assert_eq!(
            RtcpHeader::parse(&[0x40, 200, 0, 0]),
            Err(RtcpHeaderError::UnsupportedVersion { version: 1 })
        );
        assert_eq!(
            RtcpHeader::parse(&[0x80, 100, 0, 0]),
            Err(RtcpHeaderError::PacketTypeOutOfRange { packet_type: 100 })
        );
        assert_eq!(
            RtcpHeader::parse(&[0x80, 200, 0, 1]),
            Err(RtcpHeaderError::Truncated {
                required: 8,
                available: 4,
            })
        );
    }

    #[test]
    fn rejects_invalid_padding() {
        assert_eq!(
            RtcpHeader::parse(&[0xa0, 203, 0, 0]),
            Err(RtcpHeaderError::ZeroPaddingLength)
        );
        assert_eq!(
            RtcpHeader::parse(&[0xa0, 203, 0, 1, 0, 0, 0, 5]),
            Err(RtcpHeaderError::PaddingExceedsBody {
                padding: 5,
                available: 4,
            })
        );
    }

    #[test]
    fn constructor_checks_count_alignment_and_capacity() {
        assert_eq!(
            RtcpHeader::new(32, RtcpPacketType::ReceiverReport, 8, 0),
            Err(RtcpHeaderError::CountOutOfRange { count: 32 })
        );
        assert_eq!(
            RtcpHeader::new(0, RtcpPacketType::ReceiverReport, 7, 0),
            Err(RtcpHeaderError::PacketNotWordAligned { actual: 7 })
        );
        assert_eq!(
            RtcpHeader::new(
                0,
                RtcpPacketType::ReceiverReport,
                MAX_RTCP_PACKET_BYTES + 4,
                0,
            ),
            Err(RtcpHeaderError::PacketTooLarge {
                actual: MAX_RTCP_PACKET_BYTES + 4,
                maximum: MAX_RTCP_PACKET_BYTES,
            })
        );
    }

    #[test]
    fn preserves_unassigned_rtcp_packet_type() {
        let packet_type = RtcpPacketType::from_raw(210).unwrap_or_else(|_| panic!("packet type"));
        assert_eq!(packet_type, RtcpPacketType::Other(210));
        assert_eq!(packet_type.as_raw(), 210);
    }
}
