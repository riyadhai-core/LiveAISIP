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

//! Bounded RTCP Sender Report parsing and serialization.
//!
//! Sender Reports connect an RTP clock to wall-clock time and carry up to 31
//! reception reports. Parsing requires the common-header count and packet
//! length to agree exactly, preventing trailing or under-counted report data.

use std::error::Error as StdError;
use std::fmt;

use super::header::{RTCP_HEADER_BYTES, RtcpHeader, RtcpHeaderError, RtcpPacketType};
use super::report_block::{RECEPTION_REPORT_BYTES, ReceptionReport, ReceptionReportError};

/// Sender-specific body size: SSRC plus five 32-bit sender fields.
pub const SENDER_INFORMATION_BYTES: usize = 24;
/// Minimum Sender Report packet size without reception reports.
pub const MIN_SENDER_REPORT_BYTES: usize = RTCP_HEADER_BYTES + SENDER_INFORMATION_BYTES;

/// RTP sender counters and clock correlation carried by a Sender Report.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RtcpSenderInfo {
    ntp_timestamp: u64,
    rtp_timestamp: u32,
    sender_packet_count: u32,
    sender_octet_count: u32,
}

impl RtcpSenderInfo {
    /// Creates sender timing and counter information.
    #[must_use]
    pub const fn new(
        ntp_timestamp: u64,
        rtp_timestamp: u32,
        sender_packet_count: u32,
        sender_octet_count: u32,
    ) -> Self {
        Self {
            ntp_timestamp,
            rtp_timestamp,
            sender_packet_count,
            sender_octet_count,
        }
    }

    /// Returns the 64-bit NTP timestamp.
    #[must_use]
    pub const fn ntp_timestamp(self) -> u64 {
        self.ntp_timestamp
    }

    /// Returns the RTP timestamp corresponding to the NTP timestamp.
    #[must_use]
    pub const fn rtp_timestamp(self) -> u32 {
        self.rtp_timestamp
    }

    /// Returns total RTP data packets transmitted by this sender.
    #[must_use]
    pub const fn sender_packet_count(self) -> u32 {
        self.sender_packet_count
    }

    /// Returns total RTP payload octets transmitted by this sender.
    #[must_use]
    pub const fn sender_octet_count(self) -> u32 {
        self.sender_octet_count
    }

    /// Returns the middle 32 bits used by reception-report LSR fields.
    #[must_use]
    pub const fn compact_ntp(self) -> u32 {
        ((self.ntp_timestamp >> 16) & 0xffff_ffff) as u32
    }
}

impl fmt::Debug for RtcpSenderInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtcpSenderInfo")
            .field("rtp_timestamp", &self.rtp_timestamp)
            .field("sender_packet_count", &self.sender_packet_count)
            .field("sender_octet_count", &self.sender_octet_count)
            .field("has_ntp_timestamp", &(self.ntp_timestamp != 0))
            .finish()
    }
}

/// A validated, owned RTCP Sender Report.
#[derive(Clone, Eq, PartialEq)]
pub struct SenderReport {
    sender_ssrc: u32,
    sender_info: RtcpSenderInfo,
    reports: Vec<ReceptionReport>,
    padding_bytes: u8,
}

impl SenderReport {
    /// Parses one Sender Report at the beginning of `input`.
    ///
    /// Trailing bytes may contain the next packet in a compound RTCP datagram.
    ///
    /// # Errors
    ///
    /// Rejects common-header failures, wrong packet type, count/length
    /// disagreement, malformed report blocks, and bounded allocation failure.
    pub fn parse(input: &[u8]) -> Result<(Self, usize), SenderReportError> {
        let header = RtcpHeader::parse(input).map_err(SenderReportError::Header)?;
        if header.packet_type() != RtcpPacketType::SenderReport {
            return Err(SenderReportError::WrongPacketType {
                actual: header.packet_type(),
            });
        }
        let report_bytes = usize::from(header.count())
            .checked_mul(RECEPTION_REPORT_BYTES)
            .ok_or(SenderReportError::LengthOverflow)?;
        let expected_unpadded_body = SENDER_INFORMATION_BYTES
            .checked_add(report_bytes)
            .ok_or(SenderReportError::LengthOverflow)?;
        let actual_unpadded_body = header.unpadded_body_len();
        if actual_unpadded_body != expected_unpadded_body {
            return Err(SenderReportError::BodyLengthMismatch {
                expected: expected_unpadded_body,
                actual: actual_unpadded_body,
                report_count: header.count(),
            });
        }

        let packet = &input[..header.packet_len()];
        let sender_ssrc = read_u32(packet, 4);
        let sender_info = RtcpSenderInfo::new(
            read_u64(packet, 8),
            read_u32(packet, 16),
            read_u32(packet, 20),
            read_u32(packet, 24),
        );
        let mut reports = Vec::new();
        reports
            .try_reserve_exact(usize::from(header.count()))
            .map_err(|_| SenderReportError::AllocationFailed)?;
        let reports_start = MIN_SENDER_REPORT_BYTES;
        for index in 0..usize::from(header.count()) {
            let offset = reports_start
                .checked_add(
                    index
                        .checked_mul(RECEPTION_REPORT_BYTES)
                        .ok_or(SenderReportError::LengthOverflow)?,
                )
                .ok_or(SenderReportError::LengthOverflow)?;
            let report = ReceptionReport::parse(&packet[offset..])
                .map_err(|source| SenderReportError::Report { index, source })?;
            reports.push(report);
        }
        Ok((
            Self {
                sender_ssrc,
                sender_info,
                reports,
                padding_bytes: header.padding_bytes(),
            },
            header.packet_len(),
        ))
    }

    /// Constructs a Sender Report from bounded reception reports.
    ///
    /// Padding is generated as zeros followed by its count octet. Because RTCP
    /// packets are word-aligned, a nonzero padding count must make the complete
    /// packet length divisible by four.
    ///
    /// # Errors
    ///
    /// Rejects more than 31 reports, invalid alignment, length overflow, and
    /// allocation failure while taking ownership of report data.
    pub fn new(
        sender_ssrc: u32,
        sender_info: RtcpSenderInfo,
        reports: &[ReceptionReport],
        padding_bytes: u8,
    ) -> Result<Self, SenderReportError> {
        if reports.len() > 31 {
            return Err(SenderReportError::TooManyReports {
                actual: reports.len(),
                maximum: 31,
            });
        }
        let packet_len = packet_len(reports.len(), padding_bytes)?;
        RtcpHeader::new(
            u8::try_from(reports.len()).map_err(|_| SenderReportError::LengthOverflow)?,
            RtcpPacketType::SenderReport,
            packet_len,
            padding_bytes,
        )
        .map_err(SenderReportError::Header)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(reports.len())
            .map_err(|_| SenderReportError::AllocationFailed)?;
        owned.extend_from_slice(reports);
        Ok(Self {
            sender_ssrc,
            sender_info,
            reports: owned,
            padding_bytes,
        })
    }

    /// Returns the synchronization source that generated this report.
    #[must_use]
    pub const fn sender_ssrc(&self) -> u32 {
        self.sender_ssrc
    }

    /// Returns sender timing and counters.
    #[must_use]
    pub const fn sender_info(&self) -> RtcpSenderInfo {
        self.sender_info
    }

    /// Returns reception reports in wire order.
    #[must_use]
    pub fn reports(&self) -> &[ReceptionReport] {
        &self.reports
    }

    /// Returns total padding bytes.
    #[must_use]
    pub const fn padding_bytes(&self) -> u8 {
        self.padding_bytes
    }

    /// Returns exact encoded packet length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        MIN_SENDER_REPORT_BYTES
            + self.reports.len() * RECEPTION_REPORT_BYTES
            + usize::from(self.padding_bytes)
    }

    /// Serializes the complete Sender Report with one exact allocation.
    ///
    /// # Errors
    ///
    /// Returns defensive framing or allocation failures without partial output.
    pub fn encode(&self) -> Result<Vec<u8>, SenderReportError> {
        let length = packet_len(self.reports.len(), self.padding_bytes)?;
        let header = RtcpHeader::new(
            u8::try_from(self.reports.len()).map_err(|_| SenderReportError::LengthOverflow)?,
            RtcpPacketType::SenderReport,
            length,
            self.padding_bytes,
        )
        .map_err(SenderReportError::Header)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| SenderReportError::AllocationFailed)?;
        output.extend_from_slice(&header.encode().map_err(SenderReportError::Header)?);
        output.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        output.extend_from_slice(&self.sender_info.ntp_timestamp.to_be_bytes());
        output.extend_from_slice(&self.sender_info.rtp_timestamp.to_be_bytes());
        output.extend_from_slice(&self.sender_info.sender_packet_count.to_be_bytes());
        output.extend_from_slice(&self.sender_info.sender_octet_count.to_be_bytes());
        for report in &self.reports {
            output.extend_from_slice(&report.encode());
        }
        if self.padding_bytes != 0 {
            output.resize(length, 0);
            let last = output.last_mut().ok_or(SenderReportError::LengthOverflow)?;
            *last = self.padding_bytes;
        }
        debug_assert_eq!(output.len(), length);
        Ok(output)
    }
}

impl fmt::Debug for SenderReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SenderReport")
            .field("sender_info", &self.sender_info)
            .field("report_count", &self.reports.len())
            .field("padding_bytes", &self.padding_bytes)
            .finish_non_exhaustive()
    }
}

fn packet_len(report_count: usize, padding_bytes: u8) -> Result<usize, SenderReportError> {
    let length = report_count
        .checked_mul(RECEPTION_REPORT_BYTES)
        .and_then(|value| value.checked_add(MIN_SENDER_REPORT_BYTES))
        .and_then(|value| value.checked_add(usize::from(padding_bytes)))
        .ok_or(SenderReportError::LengthOverflow)?;
    if !length.is_multiple_of(4) {
        return Err(SenderReportError::PacketNotWordAligned { actual: length });
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

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ])
}

/// Failure while parsing, constructing, or serializing a Sender Report.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SenderReportError {
    /// RTCP common-header validation failed.
    Header(RtcpHeaderError),
    /// Packet type was not Sender Report.
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
    /// Report count exceeds the common header's five-bit capacity.
    TooManyReports {
        /// Supplied report count.
        actual: usize,
        /// Maximum report count.
        maximum: usize,
    },
    /// Constructed packet size is not four-byte aligned.
    PacketNotWordAligned {
        /// Calculated packet length.
        actual: usize,
    },
    /// Checked length arithmetic overflowed.
    LengthOverflow,
    /// Exact bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for SenderReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(_) => formatter.write_str("invalid RTCP Sender Report header"),
            Self::WrongPacketType { actual } => {
                write!(formatter, "expected Sender Report, received {actual:?}")
            }
            Self::BodyLengthMismatch {
                expected,
                actual,
                report_count,
            } => write!(
                formatter,
                "Sender Report count {report_count} requires {expected} body bytes, has {actual}"
            ),
            Self::Report { index, .. } => {
                write!(formatter, "invalid Sender Report reception block {index}")
            }
            Self::TooManyReports { actual, maximum } => write!(
                formatter,
                "Sender Report has {actual} reception reports, maximum is {maximum}"
            ),
            Self::PacketNotWordAligned { actual } => write!(
                formatter,
                "Sender Report length {actual} is not four-byte aligned"
            ),
            Self::LengthOverflow => formatter.write_str("Sender Report length overflow"),
            Self::AllocationFailed => formatter.write_str("Sender Report allocation failed"),
        }
    }
}

impl StdError for SenderReportError {
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
    use super::{MIN_SENDER_REPORT_BYTES, RtcpSenderInfo, SenderReport, SenderReportError};
    use crate::rtp::packet::rtcp::{ReceptionReport, RtcpPacketType};

    fn reception_report() -> ReceptionReport {
        ReceptionReport::new(10, 2, -3, 4, 5, 6, 7).unwrap_or_else(|_| panic!("report"))
    }

    fn sender_info() -> RtcpSenderInfo {
        RtcpSenderInfo::new(0x0102_0304_0506_0708, 9, 10, 11)
    }

    #[test]
    fn round_trips_sender_report_and_trailing_compound_bytes() {
        let original = SenderReport::new(0xdead_beef, sender_info(), &[reception_report()], 0)
            .unwrap_or_else(|_| panic!("sender report"));
        let mut bytes = original.encode().unwrap_or_else(|_| panic!("encode"));
        let consumed = bytes.len();
        bytes.extend_from_slice(&[0x80, 203, 0, 0]);
        let (parsed, parsed_length) =
            SenderReport::parse(&bytes).unwrap_or_else(|_| panic!("parse"));
        assert_eq!(parsed, original);
        assert_eq!(parsed_length, consumed);
        assert_eq!(parsed.sender_ssrc(), 0xdead_beef);
        assert_eq!(parsed.sender_info(), sender_info());
        assert_eq!(parsed.reports(), &[reception_report()]);
    }

    #[test]
    fn supports_aligned_padding() {
        let original =
            SenderReport::new(1, sender_info(), &[], 4).unwrap_or_else(|_| panic!("sender report"));
        let bytes = original.encode().unwrap_or_else(|_| panic!("encode"));
        assert_eq!(bytes.len(), MIN_SENDER_REPORT_BYTES + 4);
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 0, 0, 4]);
        let (parsed, _) = SenderReport::parse(&bytes).unwrap_or_else(|_| panic!("parse"));
        assert_eq!(parsed.padding_bytes(), 4);
    }

    #[test]
    fn rejects_wrong_type_and_count_length_mismatch() {
        let wrong = [0x80, 201, 0, 1, 0, 0, 0, 0];
        assert_eq!(
            SenderReport::parse(&wrong),
            Err(SenderReportError::WrongPacketType {
                actual: RtcpPacketType::ReceiverReport,
            })
        );

        let mut mismatch = vec![0_u8; MIN_SENDER_REPORT_BYTES];
        mismatch[0] = 0x81;
        mismatch[1] = 200;
        mismatch[2..4].copy_from_slice(&[0, 6]);
        assert_eq!(
            SenderReport::parse(&mismatch),
            Err(SenderReportError::BodyLengthMismatch {
                expected: 48,
                actual: 24,
                report_count: 1,
            })
        );
    }

    #[test]
    fn constructor_rejects_excess_reports_and_misaligned_padding() {
        let reports = vec![reception_report(); 32];
        assert_eq!(
            SenderReport::new(1, sender_info(), &reports, 0),
            Err(SenderReportError::TooManyReports {
                actual: 32,
                maximum: 31,
            })
        );
        assert_eq!(
            SenderReport::new(1, sender_info(), &[], 1),
            Err(SenderReportError::PacketNotWordAligned {
                actual: MIN_SENDER_REPORT_BYTES + 1,
            })
        );
    }

    #[test]
    fn computes_compact_ntp_timestamp() {
        assert_eq!(sender_info().compact_ntp(), 0x0304_0506);
    }

    #[test]
    fn debug_redacts_ssrc_and_full_ntp_timestamp() {
        let report = SenderReport::new(0xdead_beef, sender_info(), &[], 0)
            .unwrap_or_else(|_| panic!("sender report"));
        let debug = format!("{report:?}");
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("0102030405060708"));
    }
}
