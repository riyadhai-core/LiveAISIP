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

//! Bounded RTP version-2 header parsing and serialization.
//!
//! The fixed header and at most fifteen CSRC identifiers are decoded without
//! touching payload, extension, or padding bytes. The returned header length
//! lets the complete packet parser continue at the exact validated boundary.

use std::error::Error as StdError;
use std::fmt;

/// RTP protocol version supported by this stack.
pub const RTP_VERSION: u8 = 2;
/// Fixed RTP header size without CSRC identifiers.
pub const RTP_FIXED_HEADER_BYTES: usize = 12;
/// Maximum CSRC count encoded by the four-bit CC field.
pub const MAX_CSRC_COUNT: usize = 15;

/// A validated RTP version-2 header.
#[derive(Clone, Eq, PartialEq)]
pub struct RtpHeader {
    padding: bool,
    extension: bool,
    marker: bool,
    payload_type: u8,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    csrcs: Vec<u32>,
}

impl RtpHeader {
    /// Creates an RTP header without CSRC identifiers.
    ///
    /// # Errors
    ///
    /// Rejects payload types above 127.
    pub fn new(
        payload_type: u8,
        sequence_number: u16,
        timestamp: u32,
        ssrc: u32,
    ) -> Result<Self, RtpHeaderError> {
        if payload_type > 127 {
            return Err(RtpHeaderError::PayloadTypeOutOfRange { payload_type });
        }
        Ok(Self {
            padding: false,
            extension: false,
            marker: false,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrcs: Vec::new(),
        })
    }

    /// Parses a header and returns its exact encoded byte length.
    ///
    /// # Errors
    ///
    /// Rejects truncated input and RTP versions other than 2.
    pub fn parse(input: &[u8]) -> Result<(Self, usize), RtpHeaderError> {
        if input.len() < RTP_FIXED_HEADER_BYTES {
            return Err(RtpHeaderError::Truncated {
                required: RTP_FIXED_HEADER_BYTES,
                available: input.len(),
            });
        }
        let version = input[0] >> 6;
        if version != RTP_VERSION {
            return Err(RtpHeaderError::UnsupportedVersion { version });
        }
        let count = usize::from(input[0] & 0x0f);
        let length = RTP_FIXED_HEADER_BYTES
            .checked_add(count * 4)
            .ok_or(RtpHeaderError::LengthOverflow)?;
        if input.len() < length {
            return Err(RtpHeaderError::Truncated {
                required: length,
                available: input.len(),
            });
        }

        let mut csrcs = Vec::new();
        csrcs
            .try_reserve_exact(count)
            .map_err(|_| RtpHeaderError::AllocationFailed)?;
        for chunk in input[RTP_FIXED_HEADER_BYTES..length].chunks_exact(4) {
            csrcs.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }

        Ok((
            Self {
                padding: input[0] & 0x20 != 0,
                extension: input[0] & 0x10 != 0,
                marker: input[1] & 0x80 != 0,
                payload_type: input[1] & 0x7f,
                sequence_number: u16::from_be_bytes([input[2], input[3]]),
                timestamp: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
                ssrc: u32::from_be_bytes([input[8], input[9], input[10], input[11]]),
                csrcs,
            },
            length,
        ))
    }

    /// Returns whether RTP padding is present.
    #[must_use]
    pub const fn has_padding(&self) -> bool {
        self.padding
    }

    /// Sets the padding bit. Complete packet serialization must append valid
    /// padding when this is enabled.
    pub const fn set_padding(&mut self, padding: bool) {
        self.padding = padding;
    }

    /// Returns whether a header extension follows the CSRC list.
    #[must_use]
    pub const fn has_extension(&self) -> bool {
        self.extension
    }

    /// Sets the extension bit. Complete packet serialization must append a
    /// valid extension block when enabled.
    pub const fn set_extension(&mut self, extension: bool) {
        self.extension = extension;
    }

    /// Returns marker bit.
    #[must_use]
    pub const fn marker(&self) -> bool {
        self.marker
    }

    /// Sets marker bit.
    pub const fn set_marker(&mut self, marker: bool) {
        self.marker = marker;
    }

    /// Returns seven-bit payload type.
    #[must_use]
    pub const fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Replaces payload type.
    ///
    /// # Errors
    ///
    /// Rejects values above 127 without changing the header.
    pub fn set_payload_type(&mut self, payload_type: u8) -> Result<(), RtpHeaderError> {
        if payload_type > 127 {
            return Err(RtpHeaderError::PayloadTypeOutOfRange { payload_type });
        }
        self.payload_type = payload_type;
        Ok(())
    }

    /// Returns sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u16 {
        self.sequence_number
    }

    /// Sets sequence number.
    pub const fn set_sequence_number(&mut self, value: u16) {
        self.sequence_number = value;
    }

    /// Returns RTP timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Sets RTP timestamp.
    pub const fn set_timestamp(&mut self, value: u32) {
        self.timestamp = value;
    }

    /// Returns synchronization source identifier.
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Sets synchronization source identifier.
    pub const fn set_ssrc(&mut self, value: u32) {
        self.ssrc = value;
    }

    /// Returns contributing source identifiers in wire order.
    #[must_use]
    pub fn csrcs(&self) -> &[u32] {
        &self.csrcs
    }

    /// Adds a contributing source identifier.
    ///
    /// # Errors
    ///
    /// Rejects the sixteenth CSRC and allocation failure transactionally.
    pub fn push_csrc(&mut self, value: u32) -> Result<(), RtpHeaderError> {
        if self.csrcs.len() >= MAX_CSRC_COUNT {
            return Err(RtpHeaderError::TooManyCsrcs {
                maximum: MAX_CSRC_COUNT,
            });
        }
        self.csrcs
            .try_reserve(1)
            .map_err(|_| RtpHeaderError::AllocationFailed)?;
        self.csrcs.push(value);
        Ok(())
    }

    /// Returns exact encoded header size.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        RTP_FIXED_HEADER_BYTES + self.csrcs.len() * 4
    }

    /// Serializes the fixed header and CSRC list.
    ///
    /// # Errors
    ///
    /// Returns [`RtpHeaderError::AllocationFailed`] when the exact bounded
    /// allocation cannot be reserved.
    pub fn encode(&self) -> Result<Vec<u8>, RtpHeaderError> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(self.encoded_len())
            .map_err(|_| RtpHeaderError::AllocationFailed)?;
        self.append_encoded(&mut output)?;
        Ok(output)
    }

    pub(crate) fn append_encoded(&self, output: &mut Vec<u8>) -> Result<(), RtpHeaderError> {
        let count = u8::try_from(self.csrcs.len()).map_err(|_| RtpHeaderError::TooManyCsrcs {
            maximum: MAX_CSRC_COUNT,
        })?;
        output.push(
            RTP_VERSION << 6 | u8::from(self.padding) << 5 | u8::from(self.extension) << 4 | count,
        );
        output.push(u8::from(self.marker) << 7 | self.payload_type);
        output.extend_from_slice(&self.sequence_number.to_be_bytes());
        output.extend_from_slice(&self.timestamp.to_be_bytes());
        output.extend_from_slice(&self.ssrc.to_be_bytes());
        for csrc in &self.csrcs {
            output.extend_from_slice(&csrc.to_be_bytes());
        }
        Ok(())
    }
}

impl fmt::Debug for RtpHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtpHeader")
            .field("padding", &self.padding)
            .field("extension", &self.extension)
            .field("marker", &self.marker)
            .field("payload_type", &self.payload_type)
            .field("sequence_number", &self.sequence_number)
            .field("timestamp", &self.timestamp)
            .field("csrc_count", &self.csrcs.len())
            .finish_non_exhaustive()
    }
}

/// Failure to parse, mutate, or serialize an RTP header.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RtpHeaderError {
    /// Packet was shorter than its declared header.
    Truncated {
        /// Required byte count.
        required: usize,
        /// Available byte count.
        available: usize,
    },
    /// RTP version was unsupported.
    UnsupportedVersion {
        /// Received two-bit version.
        version: u8,
    },
    /// Payload type exceeded seven bits.
    PayloadTypeOutOfRange {
        /// Supplied payload type.
        payload_type: u8,
    },
    /// CSRC count exceeded four-bit capacity.
    TooManyCsrcs {
        /// Maximum accepted CSRC count.
        maximum: usize,
    },
    /// Checked header-size calculation overflowed.
    LengthOverflow,
    /// Exact bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for RtpHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid RTP header")
    }
}

impl StdError for RtpHeaderError {}

#[cfg(test)]
mod tests {
    use super::{MAX_CSRC_COUNT, RTP_FIXED_HEADER_BYTES, RtpHeader, RtpHeaderError};

    #[test]
    fn parses_and_serializes_header_with_csrcs() {
        let bytes = [
            0x92, 0xe0, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
        ];
        let (header, length) = RtpHeader::parse(&bytes).unwrap_or_else(|_| panic!("header"));
        assert_eq!(length, 20);
        assert!(header.has_extension());
        assert!(header.marker());
        assert_eq!(header.payload_type(), 96);
        assert_eq!(header.sequence_number(), 0x1234);
        assert_eq!(header.timestamp(), 0x0102_0304);
        assert_eq!(header.ssrc(), 0xaabb_ccdd);
        assert_eq!(header.csrcs(), &[1, 2]);
        assert_eq!(header.encode().unwrap_or_else(|_| panic!("encode")), bytes);
    }

    #[test]
    fn rejects_truncation_and_wrong_version() {
        assert_eq!(
            RtpHeader::parse(&[0; 4]),
            Err(RtpHeaderError::Truncated {
                required: RTP_FIXED_HEADER_BYTES,
                available: 4,
            })
        );
        let mut bytes = [0_u8; RTP_FIXED_HEADER_BYTES];
        bytes[0] = 0x40;
        assert_eq!(
            RtpHeader::parse(&bytes),
            Err(RtpHeaderError::UnsupportedVersion { version: 1 })
        );
    }

    #[test]
    fn csrc_capacity_is_transactional() {
        let mut header = RtpHeader::new(0, 1, 2, 3).unwrap_or_else(|_| panic!("header"));
        for value in 0..MAX_CSRC_COUNT {
            header
                .push_csrc(u32::try_from(value).unwrap_or_else(|_| panic!("value")))
                .unwrap_or_else(|_| panic!("CSRC"));
        }
        assert_eq!(
            header.push_csrc(99),
            Err(RtpHeaderError::TooManyCsrcs {
                maximum: MAX_CSRC_COUNT,
            })
        );
        assert_eq!(header.csrcs().len(), MAX_CSRC_COUNT);
    }

    #[test]
    fn payload_type_mutation_is_checked() {
        let mut header = RtpHeader::new(0, 1, 2, 3).unwrap_or_else(|_| panic!("header"));
        assert_eq!(
            header.set_payload_type(128),
            Err(RtpHeaderError::PayloadTypeOutOfRange { payload_type: 128 })
        );
        assert_eq!(header.payload_type(), 0);
    }

    #[test]
    fn debug_redacts_source_identifiers() {
        let header = RtpHeader::new(111, 10, 20, 0xdead_beef).unwrap_or_else(|_| panic!("header"));
        let debug = format!("{header:?}");
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("3735928559"));
    }
}
