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

//! Complete bounded RTP packet parsing and serialization.
//!
//! Packet parsing owns only the small validated header representation. Header
//! extension data and media payload remain borrowed from the received datagram.
//! Padding is validated before the payload slice is exposed, preventing media
//! decoders from observing attacker-controlled framing bytes.

use std::error::Error as StdError;
use std::fmt;

use super::extension::{RtpExtension, RtpExtensionError};
use super::header::{RtpHeader, RtpHeaderError};

/// Maximum accepted RTP packet size, matching the maximum UDP payload length.
pub const MAX_RTP_PACKET_BYTES: usize = 65_507;

/// A complete validated RTP version-2 packet.
#[derive(Clone, Eq, PartialEq)]
pub struct RtpPacket<'a> {
    header: RtpHeader,
    extension: Option<RtpExtension<'a>>,
    payload: &'a [u8],
    padding_bytes: u8,
}

impl<'a> RtpPacket<'a> {
    /// Parses one complete RTP datagram without copying media bytes.
    ///
    /// # Errors
    ///
    /// Rejects oversized input, invalid headers or extensions, inconsistent
    /// extension framing, and invalid RTP padding.
    pub fn parse(input: &'a [u8]) -> Result<Self, RtpPacketError> {
        if input.len() > MAX_RTP_PACKET_BYTES {
            return Err(RtpPacketError::PacketTooLarge {
                actual: input.len(),
                maximum: MAX_RTP_PACKET_BYTES,
            });
        }
        let (header, header_length) = RtpHeader::parse(input).map_err(RtpPacketError::Header)?;
        let (extension, payload_start) = if header.has_extension() {
            let extension_input = &input[header_length..];
            let (extension, extension_length) =
                RtpExtension::parse(extension_input).map_err(RtpPacketError::Extension)?;
            let payload_start = header_length
                .checked_add(extension_length)
                .ok_or(RtpPacketError::LengthOverflow)?;
            (Some(extension), payload_start)
        } else {
            (None, header_length)
        };

        let body = &input[payload_start..];
        let padding_bytes = if header.has_padding() {
            let Some(last) = body.last().copied() else {
                return Err(RtpPacketError::MissingPaddingLength);
            };
            if last == 0 {
                return Err(RtpPacketError::ZeroPaddingLength);
            }
            if usize::from(last) > body.len() {
                return Err(RtpPacketError::PaddingExceedsBody {
                    padding: usize::from(last),
                    available: body.len(),
                });
            }
            last
        } else {
            0
        };
        let payload_end = body.len() - usize::from(padding_bytes);

        Ok(Self {
            header,
            extension,
            payload: &body[..payload_end],
            padding_bytes,
        })
    }

    /// Constructs a packet over borrowed extension and payload data.
    ///
    /// Header extension and padding flags are canonicalized from the supplied
    /// values. A zero padding count disables padding.
    ///
    /// # Errors
    ///
    /// Rejects a packet whose exact encoded size exceeds the UDP limit.
    pub fn new(
        mut header: RtpHeader,
        extension: Option<RtpExtension<'a>>,
        payload: &'a [u8],
        padding_bytes: u8,
    ) -> Result<Self, RtpPacketError> {
        header.set_extension(extension.is_some());
        header.set_padding(padding_bytes != 0);
        let packet = Self {
            header,
            extension,
            payload,
            padding_bytes,
        };
        packet.checked_encoded_len()?;
        Ok(packet)
    }

    /// Returns the validated RTP header.
    #[must_use]
    pub const fn header(&self) -> &RtpHeader {
        &self.header
    }

    /// Returns the parsed extension when the extension bit was set.
    #[must_use]
    pub const fn extension(&self) -> Option<RtpExtension<'a>> {
        self.extension
    }

    /// Returns media payload with extension and padding removed.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Returns total RTP padding bytes, including the final count octet.
    #[must_use]
    pub const fn padding_bytes(&self) -> u8 {
        self.padding_bytes
    }

    /// Returns the exact encoded packet length.
    ///
    /// # Errors
    ///
    /// Rejects checked arithmetic overflow or a result beyond the UDP limit.
    pub fn checked_encoded_len(&self) -> Result<usize, RtpPacketError> {
        let extension_length = self.extension.map_or(0, RtpExtension::encoded_len);
        let length = self
            .header
            .encoded_len()
            .checked_add(extension_length)
            .and_then(|value| value.checked_add(self.payload.len()))
            .and_then(|value| value.checked_add(usize::from(self.padding_bytes)))
            .ok_or(RtpPacketError::LengthOverflow)?;
        if length > MAX_RTP_PACKET_BYTES {
            return Err(RtpPacketError::PacketTooLarge {
                actual: length,
                maximum: MAX_RTP_PACKET_BYTES,
            });
        }
        Ok(length)
    }

    /// Serializes the packet into one exactly sized datagram buffer.
    ///
    /// Padding bytes are deterministic zeros except for the required final
    /// count octet. No intermediate header or extension buffers are allocated.
    ///
    /// # Errors
    ///
    /// Returns framing, length, or allocation failures without partial output.
    pub fn encode(&self) -> Result<Vec<u8>, RtpPacketError> {
        let length = self.checked_encoded_len()?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| RtpPacketError::AllocationFailed)?;
        self.header
            .append_encoded(&mut output)
            .map_err(RtpPacketError::Header)?;
        if let Some(extension) = self.extension {
            extension
                .append_encoded(&mut output)
                .map_err(RtpPacketError::Extension)?;
        }
        output.extend_from_slice(self.payload);
        if self.padding_bytes != 0 {
            let padding_start = output.len();
            output.resize(length, 0);
            debug_assert!(output.len() > padding_start);
            let last = output.last_mut().ok_or(RtpPacketError::LengthOverflow)?;
            *last = self.padding_bytes;
        }
        debug_assert_eq!(output.len(), length);
        Ok(output)
    }
}

impl fmt::Debug for RtpPacket<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtpPacket")
            .field("header", &self.header)
            .field("extension", &self.extension)
            .field("payload_bytes", &self.payload.len())
            .field("padding_bytes", &self.padding_bytes)
            .finish()
    }
}

/// Failure while parsing, constructing, or serializing an RTP packet.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RtpPacketError {
    /// Fixed RTP header validation failed.
    Header(RtpHeaderError),
    /// RTP extension validation failed.
    Extension(RtpExtensionError),
    /// Packet exceeds the bounded UDP payload size.
    PacketTooLarge {
        /// Supplied or calculated packet length.
        actual: usize,
        /// Maximum accepted packet length.
        maximum: usize,
    },
    /// Checked packet-boundary arithmetic overflowed.
    LengthOverflow,
    /// Padding bit was set but no body byte carried its length.
    MissingPaddingLength,
    /// RTP padding count octet was zero.
    ZeroPaddingLength,
    /// Declared padding extends before the payload boundary.
    PaddingExceedsBody {
        /// Declared padding byte count.
        padding: usize,
        /// Bytes available after header and extension parsing.
        available: usize,
    },
    /// Exact output allocation could not be reserved.
    AllocationFailed,
}

impl fmt::Display for RtpPacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(_) => formatter.write_str("invalid RTP packet header"),
            Self::Extension(_) => formatter.write_str("invalid RTP packet extension"),
            Self::PacketTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "RTP packet has {actual} bytes, maximum is {maximum}"
                )
            }
            Self::LengthOverflow => formatter.write_str("RTP packet length overflow"),
            Self::MissingPaddingLength => {
                formatter.write_str("RTP padding bit is set without a padding count")
            }
            Self::ZeroPaddingLength => formatter.write_str("RTP padding count is zero"),
            Self::PaddingExceedsBody { padding, available } => write!(
                formatter,
                "RTP padding count {padding} exceeds {available} available bytes"
            ),
            Self::AllocationFailed => formatter.write_str("RTP packet allocation failed"),
        }
    }
}

impl StdError for RtpPacketError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Header(source) => Some(source),
            Self::Extension(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::{MAX_RTP_PACKET_BYTES, RtpPacket, RtpPacketError};
    use crate::rtp::packet::{RtpExtension, RtpHeader, RtpHeaderError};

    #[test]
    fn parses_complete_packet_zero_copy() {
        let bytes = [
            0xb0, 111, 0, 9, 0, 0, 0, 20, 0, 0, 0, 30, 0xab, 0xcd, 0, 1, 1, 2, 3, 4, 10, 11, 0, 0,
            0, 4,
        ];
        let packet = RtpPacket::parse(&bytes).unwrap_or_else(|_| panic!("packet"));
        assert_eq!(packet.header().payload_type(), 111);
        assert_eq!(packet.extension().map(RtpExtension::profile), Some(0xabcd));
        assert_eq!(packet.payload(), &[10, 11]);
        assert_eq!(packet.padding_bytes(), 4);
        assert!(std::ptr::eq(
            packet.payload().as_ptr(),
            bytes[20..].as_ptr()
        ));
    }

    #[test]
    fn constructed_packet_canonicalizes_flags_and_round_trips() {
        let header = RtpHeader::new(0, 1, 2, 3).unwrap_or_else(|_| panic!("header"));
        let extension =
            RtpExtension::opaque(0xabcd, &[1, 2, 3, 4]).unwrap_or_else(|_| panic!("extension"));
        let packet = RtpPacket::new(header, Some(extension), &[5, 6], 3)
            .unwrap_or_else(|_| panic!("packet"));
        assert!(packet.header().has_extension());
        assert!(packet.header().has_padding());
        let encoded = packet.encode().unwrap_or_else(|_| panic!("encode"));
        assert_eq!(&encoded[encoded.len() - 3..], &[0, 0, 3]);
        let reparsed = RtpPacket::parse(&encoded).unwrap_or_else(|_| panic!("reparse"));
        assert_eq!(reparsed.payload(), &[5, 6]);
        assert_eq!(reparsed.padding_bytes(), 3);
    }

    #[test]
    fn rejects_all_invalid_padding_boundaries() {
        let mut missing = [0_u8; 12];
        missing[0] = 0xa0;
        assert_eq!(
            RtpPacket::parse(&missing),
            Err(RtpPacketError::MissingPaddingLength)
        );

        let mut zero = [0_u8; 13];
        zero[0] = 0xa0;
        assert_eq!(
            RtpPacket::parse(&zero),
            Err(RtpPacketError::ZeroPaddingLength)
        );

        let mut excessive = [0_u8; 14];
        excessive[0] = 0xa0;
        excessive[13] = 3;
        assert_eq!(
            RtpPacket::parse(&excessive),
            Err(RtpPacketError::PaddingExceedsBody {
                padding: 3,
                available: 2,
            })
        );
    }

    #[test]
    fn propagates_header_and_extension_sources() {
        let Err(header_error) = RtpPacket::parse(&[0; 4]) else {
            panic!("expected header failure");
        };
        assert!(matches!(
            header_error,
            RtpPacketError::Header(RtpHeaderError::Truncated { .. })
        ));
        assert!(header_error.source().is_some());

        let mut truncated_extension = [0_u8; 12];
        truncated_extension[0] = 0x90;
        let Err(extension_error) = RtpPacket::parse(&truncated_extension) else {
            panic!("expected extension failure");
        };
        assert!(matches!(extension_error, RtpPacketError::Extension(_)));
        assert!(extension_error.source().is_some());
    }

    #[test]
    fn enforces_udp_packet_bound_before_parsing() {
        let bytes = vec![0_u8; MAX_RTP_PACKET_BYTES + 1];
        assert_eq!(
            RtpPacket::parse(&bytes),
            Err(RtpPacketError::PacketTooLarge {
                actual: MAX_RTP_PACKET_BYTES + 1,
                maximum: MAX_RTP_PACKET_BYTES,
            })
        );
    }

    #[test]
    fn debug_redacts_payload_and_source_identifier() {
        let header = RtpHeader::new(0, 1, 2, 0xdead_beef).unwrap_or_else(|_| panic!("header"));
        let packet = RtpPacket::new(header, None, &[222, 173, 190, 239], 0)
            .unwrap_or_else(|_| panic!("packet"));
        let debug = format!("{packet:?}");
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("222"));
    }
}
