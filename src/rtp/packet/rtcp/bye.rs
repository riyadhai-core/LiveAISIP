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

//! Bounded RTCP BYE packet parsing and serialization.
//!
//! A BYE packet identifies up to 31 departing sources and may carry a bounded
//! reason string. Source identifiers and reason contents are intentionally
//! redacted from diagnostics.

use std::error::Error as StdError;
use std::fmt;

use super::header::{RTCP_HEADER_BYTES, RtcpHeader, RtcpHeaderError, RtcpPacketType};

/// Maximum BYE source count representable in the common header.
pub const MAX_GOODBYE_SOURCES: usize = 31;
/// Maximum BYE reason length carried by its one-octet field.
pub const MAX_GOODBYE_REASON_BYTES: usize = 255;

/// A validated, owned RTCP BYE packet.
#[derive(Clone, Eq, PartialEq)]
pub struct Goodbye {
    sources: Vec<u32>,
    reason: Option<Vec<u8>>,
    padding_bytes: u8,
}

impl Goodbye {
    /// Parses one BYE packet from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Rejects common-header failures, wrong type, zero or excessive sources,
    /// truncated reasons, nonzero alignment, and allocation failure.
    pub fn parse(input: &[u8]) -> Result<(Self, usize), GoodbyeError> {
        let header = RtcpHeader::parse(input).map_err(GoodbyeError::Header)?;
        if header.packet_type() != RtcpPacketType::Goodbye {
            return Err(GoodbyeError::WrongPacketType {
                actual: header.packet_type(),
            });
        }
        let source_count = usize::from(header.count());
        if source_count == 0 {
            return Err(GoodbyeError::NoSources);
        }
        let source_bytes = source_count
            .checked_mul(4)
            .ok_or(GoodbyeError::LengthOverflow)?;
        let body_end = RTCP_HEADER_BYTES
            .checked_add(header.unpadded_body_len())
            .ok_or(GoodbyeError::LengthOverflow)?;
        let sources_end = RTCP_HEADER_BYTES
            .checked_add(source_bytes)
            .ok_or(GoodbyeError::LengthOverflow)?;
        if sources_end > body_end {
            return Err(GoodbyeError::SourcesTruncated {
                required: source_bytes,
                available: body_end.saturating_sub(RTCP_HEADER_BYTES),
            });
        }
        let packet = &input[..header.packet_len()];
        let mut sources = Vec::new();
        sources
            .try_reserve_exact(source_count)
            .map_err(|_| GoodbyeError::AllocationFailed)?;
        for index in 0..source_count {
            sources.push(read_u32(packet, RTCP_HEADER_BYTES + index * 4));
        }

        let reason = if sources_end == body_end {
            None
        } else {
            let reason_length = usize::from(packet[sources_end]);
            let value_start = sources_end + 1;
            let value_end = value_start
                .checked_add(reason_length)
                .ok_or(GoodbyeError::LengthOverflow)?;
            if value_end > body_end {
                return Err(GoodbyeError::ReasonTruncated {
                    required: reason_length,
                    available: body_end - value_start,
                });
            }
            if packet[value_end..body_end].iter().any(|byte| *byte != 0) {
                return Err(GoodbyeError::NonZeroReasonAlignment);
            }
            let mut reason = Vec::new();
            reason
                .try_reserve_exact(reason_length)
                .map_err(|_| GoodbyeError::AllocationFailed)?;
            reason.extend_from_slice(&packet[value_start..value_end]);
            Some(reason)
        };

        Ok((
            Self {
                sources,
                reason,
                padding_bytes: header.padding_bytes(),
            },
            header.packet_len(),
        ))
    }

    /// Constructs a BYE packet by copying sources and optional reason.
    ///
    /// # Errors
    ///
    /// Rejects an empty source list, more than 31 sources, reasons beyond 255
    /// bytes, invalid external padding alignment, or allocation failure.
    pub fn new(
        sources: &[u32],
        reason: Option<&[u8]>,
        padding_bytes: u8,
    ) -> Result<Self, GoodbyeError> {
        validate_inputs(sources, reason)?;
        let length = packet_len(sources.len(), reason, padding_bytes)?;
        RtcpHeader::new(
            u8::try_from(sources.len()).map_err(|_| GoodbyeError::LengthOverflow)?,
            RtcpPacketType::Goodbye,
            length,
            padding_bytes,
        )
        .map_err(GoodbyeError::Header)?;
        let mut owned_sources = Vec::new();
        owned_sources
            .try_reserve_exact(sources.len())
            .map_err(|_| GoodbyeError::AllocationFailed)?;
        owned_sources.extend_from_slice(sources);
        let owned_reason = reason
            .map(|value| {
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(value.len())
                    .map_err(|_| GoodbyeError::AllocationFailed)?;
                owned.extend_from_slice(value);
                Ok(owned)
            })
            .transpose()?;
        Ok(Self {
            sources: owned_sources,
            reason: owned_reason,
            padding_bytes,
        })
    }

    /// Returns departing source identifiers in wire order.
    #[must_use]
    pub fn sources(&self) -> &[u32] {
        &self.sources
    }

    /// Returns the optional reason bytes.
    #[must_use]
    pub fn reason(&self) -> Option<&[u8]> {
        self.reason.as_deref()
    }

    /// Returns external RTCP padding bytes.
    #[must_use]
    pub const fn padding_bytes(&self) -> u8 {
        self.padding_bytes
    }

    /// Calculates exact encoded packet length.
    ///
    /// # Errors
    ///
    /// Returns checked length overflow.
    pub fn encoded_len(&self) -> Result<usize, GoodbyeError> {
        packet_len(
            self.sources.len(),
            self.reason.as_deref(),
            self.padding_bytes,
        )
    }

    /// Serializes the complete BYE packet with one exact allocation.
    ///
    /// # Errors
    ///
    /// Returns validation, framing, or allocation failure transactionally.
    pub fn encode(&self) -> Result<Vec<u8>, GoodbyeError> {
        validate_inputs(&self.sources, self.reason.as_deref())?;
        let length = self.encoded_len()?;
        let header = RtcpHeader::new(
            u8::try_from(self.sources.len()).map_err(|_| GoodbyeError::LengthOverflow)?,
            RtcpPacketType::Goodbye,
            length,
            self.padding_bytes,
        )
        .map_err(GoodbyeError::Header)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| GoodbyeError::AllocationFailed)?;
        output.extend_from_slice(&header.encode().map_err(GoodbyeError::Header)?);
        for source in &self.sources {
            output.extend_from_slice(&source.to_be_bytes());
        }
        if let Some(reason) = &self.reason {
            output.push(u8::try_from(reason.len()).map_err(|_| GoodbyeError::LengthOverflow)?);
            output.extend_from_slice(reason);
            let aligned = align_to_word(output.len())?;
            output.resize(aligned, 0);
        }
        if self.padding_bytes != 0 {
            output.resize(length, 0);
            let last = output.last_mut().ok_or(GoodbyeError::LengthOverflow)?;
            *last = self.padding_bytes;
        }
        debug_assert_eq!(output.len(), length);
        Ok(output)
    }
}

impl fmt::Debug for Goodbye {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Goodbye")
            .field("source_count", &self.sources.len())
            .field("reason_bytes", &self.reason.as_ref().map(Vec::len))
            .field("padding_bytes", &self.padding_bytes)
            .finish()
    }
}

fn validate_inputs(sources: &[u32], reason: Option<&[u8]>) -> Result<(), GoodbyeError> {
    if sources.is_empty() {
        return Err(GoodbyeError::NoSources);
    }
    if sources.len() > MAX_GOODBYE_SOURCES {
        return Err(GoodbyeError::TooManySources {
            actual: sources.len(),
            maximum: MAX_GOODBYE_SOURCES,
        });
    }
    if let Some(reason) = reason
        && reason.len() > MAX_GOODBYE_REASON_BYTES
    {
        return Err(GoodbyeError::ReasonTooLong {
            actual: reason.len(),
            maximum: MAX_GOODBYE_REASON_BYTES,
        });
    }
    Ok(())
}

fn packet_len(
    source_count: usize,
    reason: Option<&[u8]>,
    padding_bytes: u8,
) -> Result<usize, GoodbyeError> {
    let sources_length = source_count
        .checked_mul(4)
        .ok_or(GoodbyeError::LengthOverflow)?;
    let mut length = RTCP_HEADER_BYTES
        .checked_add(sources_length)
        .ok_or(GoodbyeError::LengthOverflow)?;
    if let Some(reason) = reason {
        length = length
            .checked_add(1)
            .and_then(|value| value.checked_add(reason.len()))
            .ok_or(GoodbyeError::LengthOverflow)?;
        length = align_to_word(length)?;
    }
    length = length
        .checked_add(usize::from(padding_bytes))
        .ok_or(GoodbyeError::LengthOverflow)?;
    if !length.is_multiple_of(4) {
        return Err(GoodbyeError::PacketNotWordAligned { actual: length });
    }
    Ok(length)
}

fn align_to_word(length: usize) -> Result<usize, GoodbyeError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(GoodbyeError::LengthOverflow)
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

/// Failure while parsing, constructing, or serializing a BYE packet.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GoodbyeError {
    /// RTCP common-header validation failed.
    Header(RtcpHeaderError),
    /// Packet type was not BYE.
    WrongPacketType {
        /// Actual packet type.
        actual: RtcpPacketType,
    },
    /// BYE carries no departing source.
    NoSources,
    /// Source count exceeds five-bit capacity.
    TooManySources {
        /// Supplied source count.
        actual: usize,
        /// Maximum accepted source count.
        maximum: usize,
    },
    /// Declared source identifiers cross the body boundary.
    SourcesTruncated {
        /// Required source bytes.
        required: usize,
        /// Available body bytes.
        available: usize,
    },
    /// Reason exceeds its one-octet capacity.
    ReasonTooLong {
        /// Supplied reason length.
        actual: usize,
        /// Maximum reason length.
        maximum: usize,
    },
    /// Declared reason crosses the body boundary.
    ReasonTruncated {
        /// Required reason bytes.
        required: usize,
        /// Available reason bytes.
        available: usize,
    },
    /// Internal reason alignment contains nonzero bytes.
    NonZeroReasonAlignment,
    /// Constructed packet length is not word-aligned.
    PacketNotWordAligned {
        /// Calculated packet length.
        actual: usize,
    },
    /// Checked length arithmetic overflowed.
    LengthOverflow,
    /// Exact bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for GoodbyeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(_) => formatter.write_str("invalid RTCP BYE header"),
            Self::WrongPacketType { actual } => {
                write!(formatter, "expected RTCP BYE, received {actual:?}")
            }
            Self::NoSources => formatter.write_str("RTCP BYE has no sources"),
            Self::TooManySources { actual, maximum } => {
                write!(
                    formatter,
                    "RTCP BYE has {actual} sources, maximum is {maximum}"
                )
            }
            Self::SourcesTruncated {
                required,
                available,
            } => write!(
                formatter,
                "RTCP BYE sources require {required} bytes, has {available}"
            ),
            Self::ReasonTooLong { actual, maximum } => write!(
                formatter,
                "RTCP BYE reason has {actual} bytes, maximum is {maximum}"
            ),
            Self::ReasonTruncated {
                required,
                available,
            } => write!(
                formatter,
                "RTCP BYE reason requires {required} bytes, has {available}"
            ),
            Self::NonZeroReasonAlignment => {
                formatter.write_str("RTCP BYE reason alignment is nonzero")
            }
            Self::PacketNotWordAligned { actual } => {
                write!(formatter, "RTCP BYE length {actual} is not word-aligned")
            }
            Self::LengthOverflow => formatter.write_str("RTCP BYE length overflow"),
            Self::AllocationFailed => formatter.write_str("RTCP BYE allocation failed"),
        }
    }
}

impl StdError for GoodbyeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Header(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Goodbye, GoodbyeError, MAX_GOODBYE_REASON_BYTES};
    use crate::rtp::packet::rtcp::RtcpPacketType;

    #[test]
    fn round_trips_sources_reason_and_compound_tail() {
        let original =
            Goodbye::new(&[0xdead_beef, 2], Some(b"shutdown"), 0).unwrap_or_else(|_| panic!("BYE"));
        let mut bytes = original.encode().unwrap_or_else(|_| panic!("encode"));
        let consumed = bytes.len();
        bytes.extend_from_slice(&[0x80, 203, 0, 0]);
        let (parsed, parsed_length) = Goodbye::parse(&bytes).unwrap_or_else(|_| panic!("parse"));
        assert_eq!(parsed, original);
        assert_eq!(parsed_length, consumed);
        assert_eq!(parsed.sources(), &[0xdead_beef, 2]);
        assert_eq!(parsed.reason(), Some(b"shutdown".as_slice()));
    }

    #[test]
    fn distinguishes_absent_and_empty_reason() {
        let absent = Goodbye::new(&[1], None, 0).unwrap_or_else(|_| panic!("BYE"));
        let empty = Goodbye::new(&[1], Some(b""), 0).unwrap_or_else(|_| panic!("BYE"));
        let absent_bytes = absent.encode().unwrap_or_else(|_| panic!("encode"));
        let empty_bytes = empty.encode().unwrap_or_else(|_| panic!("encode"));
        assert_eq!(absent_bytes.len(), 8);
        assert_eq!(empty_bytes.len(), 12);
        assert_eq!(
            Goodbye::parse(&empty_bytes)
                .unwrap_or_else(|_| panic!("parse"))
                .0
                .reason(),
            Some(b"".as_slice())
        );
    }

    #[test]
    fn rejects_wrong_type_zero_sources_and_truncated_reason() {
        assert_eq!(
            Goodbye::parse(&[0x80, 201, 0, 1, 0, 0, 0, 0]),
            Err(GoodbyeError::WrongPacketType {
                actual: RtcpPacketType::ReceiverReport,
            })
        );
        assert_eq!(
            Goodbye::parse(&[0x80, 203, 0, 0]),
            Err(GoodbyeError::NoSources)
        );
        assert_eq!(
            Goodbye::parse(&[0x81, 203, 0, 2, 0, 0, 0, 1, 4, b'a', 0, 0]),
            Err(GoodbyeError::ReasonTruncated {
                required: 4,
                available: 3,
            })
        );
    }

    #[test]
    fn constructor_enforces_bounds_and_padding_alignment() {
        assert_eq!(Goodbye::new(&[], None, 0), Err(GoodbyeError::NoSources));
        let long_reason = vec![0; MAX_GOODBYE_REASON_BYTES + 1];
        assert_eq!(
            Goodbye::new(&[1], Some(&long_reason), 0),
            Err(GoodbyeError::ReasonTooLong {
                actual: MAX_GOODBYE_REASON_BYTES + 1,
                maximum: MAX_GOODBYE_REASON_BYTES,
            })
        );
        assert_eq!(
            Goodbye::new(&[1], None, 1),
            Err(GoodbyeError::PacketNotWordAligned { actual: 9 })
        );
    }

    #[test]
    fn supports_external_padding() {
        let original = Goodbye::new(&[1], None, 4).unwrap_or_else(|_| panic!("BYE"));
        let bytes = original.encode().unwrap_or_else(|_| panic!("encode"));
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 0, 0, 4]);
        let (parsed, _) = Goodbye::parse(&bytes).unwrap_or_else(|_| panic!("parse"));
        assert_eq!(parsed.padding_bytes(), 4);
    }

    #[test]
    fn debug_redacts_sources_and_reason() {
        let packet = Goodbye::new(&[0xdead_beef], Some(b"private shutdown"), 0)
            .unwrap_or_else(|_| panic!("BYE"));
        let debug = format!("{packet:?}");
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("shutdown"));
    }
}
