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

//! Bounded RTCP Receiver Report parsing and serialization.
//!
//! The common-header report count must agree exactly with the unpadded packet
//! body. Reception reports are retained in wire order with a hard maximum of
//! 31, while source identifiers remain absent from diagnostic formatting.

use std::error::Error as StdError;
use std::fmt;

use super::header::{RTCP_HEADER_BYTES, RtcpHeader, RtcpHeaderError, RtcpPacketType};
use super::report_block::{RECEPTION_REPORT_BYTES, ReceptionReport, ReceptionReportError};

/// Receiver SSRC body size following the RTCP common header.
pub const RECEIVER_ID_BYTES: usize = 4;
/// Minimum Receiver Report packet size without report blocks.
pub const MIN_RECEIVER_REPORT_BYTES: usize = RTCP_HEADER_BYTES + RECEIVER_ID_BYTES;
/// Maximum report blocks representable by the RTCP count field.
pub const MAX_RECEIVER_REPORTS: usize = 31;

/// A validated, owned RTCP Receiver Report.
#[derive(Clone, Eq, PartialEq)]
pub struct ReceiverReport {
    receiver_ssrc: u32,
    reports: Vec<ReceptionReport>,
    padding_bytes: u8,
}

impl ReceiverReport {
    /// Parses one Receiver Report from the beginning of `input`.
    ///
    /// Trailing bytes may contain later packets in a compound RTCP datagram.
    ///
    /// # Errors
    ///
    /// Rejects common-header failures, wrong packet type, count/length
    /// disagreement, malformed report blocks, and allocation failure.
    pub fn parse(input: &[u8]) -> Result<(Self, usize), ReceiverReportError> {
        let header = RtcpHeader::parse(input).map_err(ReceiverReportError::Header)?;
        if header.packet_type() != RtcpPacketType::ReceiverReport {
            return Err(ReceiverReportError::WrongPacketType {
                actual: header.packet_type(),
            });
        }
        let expected = usize::from(header.count())
            .checked_mul(RECEPTION_REPORT_BYTES)
            .and_then(|value| value.checked_add(RECEIVER_ID_BYTES))
            .ok_or(ReceiverReportError::LengthOverflow)?;
        let actual = header.unpadded_body_len();
        if actual != expected {
            return Err(ReceiverReportError::BodyLengthMismatch {
                expected,
                actual,
                report_count: header.count(),
            });
        }

        let packet = &input[..header.packet_len()];
        let receiver_ssrc = read_u32(packet, RTCP_HEADER_BYTES);
        let report_count = usize::from(header.count());
        let mut reports = Vec::new();
        reports
            .try_reserve_exact(report_count)
            .map_err(|_| ReceiverReportError::AllocationFailed)?;
        for index in 0..report_count {
            let offset = MIN_RECEIVER_REPORT_BYTES
                .checked_add(
                    index
                        .checked_mul(RECEPTION_REPORT_BYTES)
                        .ok_or(ReceiverReportError::LengthOverflow)?,
                )
                .ok_or(ReceiverReportError::LengthOverflow)?;
            let report = ReceptionReport::parse(&packet[offset..])
                .map_err(|source| ReceiverReportError::Report { index, source })?;
            reports.push(report);
        }
        Ok((
            Self {
                receiver_ssrc,
                reports,
                padding_bytes: header.padding_bytes(),
            },
            header.packet_len(),
        ))
    }

    /// Constructs a Receiver Report with owned bounded report blocks.
    ///
    /// # Errors
    ///
    /// Rejects more than 31 reports, non-word-aligned padding, length failures,
    /// and allocation failure while copying the supplied reports.
    pub fn new(
        receiver_ssrc: u32,
        reports: &[ReceptionReport],
        padding_bytes: u8,
    ) -> Result<Self, ReceiverReportError> {
        validate_report_count(reports.len())?;
        let length = packet_len(reports.len(), padding_bytes)?;
        RtcpHeader::new(
            u8::try_from(reports.len()).map_err(|_| ReceiverReportError::LengthOverflow)?,
            RtcpPacketType::ReceiverReport,
            length,
            padding_bytes,
        )
        .map_err(ReceiverReportError::Header)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(reports.len())
            .map_err(|_| ReceiverReportError::AllocationFailed)?;
        owned.extend_from_slice(reports);
        Ok(Self {
            receiver_ssrc,
            reports: owned,
            padding_bytes,
        })
    }

    /// Returns the synchronization source generating this report.
    #[must_use]
    pub const fn receiver_ssrc(&self) -> u32 {
        self.receiver_ssrc
    }

    /// Returns reception reports in wire order.
    #[must_use]
    pub fn reports(&self) -> &[ReceptionReport] {
        &self.reports
    }

    /// Returns total padding bytes including the final count octet.
    #[must_use]
    pub const fn padding_bytes(&self) -> u8 {
        self.padding_bytes
    }

    /// Returns exact encoded packet length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        MIN_RECEIVER_REPORT_BYTES
            + self.reports.len() * RECEPTION_REPORT_BYTES
            + usize::from(self.padding_bytes)
    }

    /// Serializes the complete Receiver Report using one exact allocation.
    ///
    /// # Errors
    ///
    /// Returns defensive framing or allocation failures without partial output.
    pub fn encode(&self) -> Result<Vec<u8>, ReceiverReportError> {
        validate_report_count(self.reports.len())?;
        let length = packet_len(self.reports.len(), self.padding_bytes)?;
        let header = RtcpHeader::new(
            u8::try_from(self.reports.len()).map_err(|_| ReceiverReportError::LengthOverflow)?,
            RtcpPacketType::ReceiverReport,
            length,
            self.padding_bytes,
        )
        .map_err(ReceiverReportError::Header)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| ReceiverReportError::AllocationFailed)?;
        output.extend_from_slice(&header.encode().map_err(ReceiverReportError::Header)?);
        output.extend_from_slice(&self.receiver_ssrc.to_be_bytes());
        for report in &self.reports {
            output.extend_from_slice(&report.encode());
        }
        if self.padding_bytes != 0 {
            output.resize(length, 0);
            let last = output
                .last_mut()
                .ok_or(ReceiverReportError::LengthOverflow)?;
            *last = self.padding_bytes;
        }
        debug_assert_eq!(output.len(), length);
        Ok(output)
    }
}

impl fmt::Debug for ReceiverReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiverReport")
            .field("report_count", &self.reports.len())
            .field("padding_bytes", &self.padding_bytes)
            .finish_non_exhaustive()
    }
}

fn validate_report_count(count: usize) -> Result<(), ReceiverReportError> {
    if count > MAX_RECEIVER_REPORTS {
        return Err(ReceiverReportError::TooManyReports {
            actual: count,
            maximum: MAX_RECEIVER_REPORTS,
        });
    }
    Ok(())
}

fn packet_len(report_count: usize, padding_bytes: u8) -> Result<usize, ReceiverReportError> {
    let length = report_count
        .checked_mul(RECEPTION_REPORT_BYTES)
        .and_then(|value| value.checked_add(MIN_RECEIVER_REPORT_BYTES))
        .and_then(|value| value.checked_add(usize::from(padding_bytes)))
        .ok_or(ReceiverReportError::LengthOverflow)?;
    if !length.is_multiple_of(4) {
        return Err(ReceiverReportError::PacketNotWordAligned { actual: length });
    }
    Ok(length)
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

/// Failure while parsing, constructing, or serializing a Receiver Report.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReceiverReportError {
    /// RTCP common-header validation failed.
    Header(RtcpHeaderError),
    /// Packet type was not Receiver Report.
    WrongPacketType {
        /// Actual packet type.
        actual: RtcpPacketType,
    },
    /// Declared report count disagrees with the unpadded body size.
    BodyLengthMismatch {
        /// Required unpadded body bytes.
        expected: usize,
        /// Actual unpadded body bytes.
        actual: usize,
        /// Declared report count.
        report_count: u8,
    },
    /// A reception-report block failed validation.
    Report {
        /// Zero-based report index.
        index: usize,
        /// Detailed block error.
        source: ReceptionReportError,
    },
    /// Report count exceeds five-bit RTCP capacity.
    TooManyReports {
        /// Supplied report count.
        actual: usize,
        /// Maximum accepted count.
        maximum: usize,
    },
    /// Constructed packet size is not four-byte aligned.
    PacketNotWordAligned {
        /// Calculated packet length.
        actual: usize,
    },
    /// Checked packet-size arithmetic overflowed.
    LengthOverflow,
    /// Exact bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for ReceiverReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(_) => formatter.write_str("invalid RTCP Receiver Report header"),
            Self::WrongPacketType { actual } => {
                write!(formatter, "expected Receiver Report, received {actual:?}")
            }
            Self::BodyLengthMismatch {
                expected,
                actual,
                report_count,
            } => write!(
                formatter,
                "Receiver Report count {report_count} requires {expected} body bytes, has {actual}"
            ),
            Self::Report { index, .. } => {
                write!(formatter, "invalid Receiver Report reception block {index}")
            }
            Self::TooManyReports { actual, maximum } => write!(
                formatter,
                "Receiver Report has {actual} reports, maximum is {maximum}"
            ),
            Self::PacketNotWordAligned { actual } => write!(
                formatter,
                "Receiver Report length {actual} is not four-byte aligned"
            ),
            Self::LengthOverflow => formatter.write_str("Receiver Report length overflow"),
            Self::AllocationFailed => formatter.write_str("Receiver Report allocation failed"),
        }
    }
}

impl StdError for ReceiverReportError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Header(source) => Some(source),
            Self::Report { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_RECEIVER_REPORTS, MIN_RECEIVER_REPORT_BYTES, ReceiverReport, ReceiverReportError,
    };
    use crate::rtp::packet::rtcp::{ReceptionReport, RtcpPacketType};

    fn block() -> ReceptionReport {
        ReceptionReport::new(2, 3, 4, 5, 6, 7, 8).unwrap_or_else(|_| panic!("block"))
    }

    #[test]
    fn round_trips_reports_and_leaves_compound_tail() {
        let original = ReceiverReport::new(0xdead_beef, &[block(), block()], 0)
            .unwrap_or_else(|_| panic!("receiver report"));
        let mut bytes = original.encode().unwrap_or_else(|_| panic!("encode"));
        let consumed = bytes.len();
        bytes.extend_from_slice(&[0x80, 203, 0, 0]);
        let (parsed, parsed_length) =
            ReceiverReport::parse(&bytes).unwrap_or_else(|_| panic!("parse"));
        assert_eq!(parsed, original);
        assert_eq!(parsed_length, consumed);
        assert_eq!(parsed.receiver_ssrc(), 0xdead_beef);
        assert_eq!(parsed.reports(), &[block(), block()]);
    }

    #[test]
    fn supports_aligned_padding() {
        let report = ReceiverReport::new(1, &[], 4).unwrap_or_else(|_| panic!("receiver report"));
        let bytes = report.encode().unwrap_or_else(|_| panic!("encode"));
        assert_eq!(bytes.len(), MIN_RECEIVER_REPORT_BYTES + 4);
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 0, 0, 4]);
        let (parsed, _) = ReceiverReport::parse(&bytes).unwrap_or_else(|_| panic!("parse"));
        assert_eq!(parsed.padding_bytes(), 4);
    }

    #[test]
    fn rejects_wrong_type_and_count_length_mismatch() {
        let wrong = [
            0x80, 200, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            ReceiverReport::parse(&wrong),
            Err(ReceiverReportError::WrongPacketType {
                actual: RtcpPacketType::SenderReport,
            })
        );

        let mismatch = [0x81, 201, 0, 1, 0, 0, 0, 1];
        assert_eq!(
            ReceiverReport::parse(&mismatch),
            Err(ReceiverReportError::BodyLengthMismatch {
                expected: 28,
                actual: 4,
                report_count: 1,
            })
        );
    }

    #[test]
    fn constructor_enforces_report_count_and_alignment() {
        let blocks = vec![block(); MAX_RECEIVER_REPORTS + 1];
        assert_eq!(
            ReceiverReport::new(1, &blocks, 0),
            Err(ReceiverReportError::TooManyReports {
                actual: MAX_RECEIVER_REPORTS + 1,
                maximum: MAX_RECEIVER_REPORTS,
            })
        );
        assert_eq!(
            ReceiverReport::new(1, &[], 1),
            Err(ReceiverReportError::PacketNotWordAligned {
                actual: MIN_RECEIVER_REPORT_BYTES + 1,
            })
        );
    }

    #[test]
    fn debug_redacts_receiver_and_report_sources() {
        let report = ReceiverReport::new(0xdead_beef, &[block()], 0)
            .unwrap_or_else(|_| panic!("receiver report"));
        let debug = format!("{report:?}");
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("3735928559"));
    }
}
