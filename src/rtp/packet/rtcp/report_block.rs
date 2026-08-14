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

//! RTCP reception-report block parsing and serialization.
//!
//! The signed cumulative-loss field is represented as `i32` but constrained to
//! its exact signed 24-bit wire range. Source identifiers are deliberately
//! omitted from `Debug` output to keep routine telemetry privacy-safe.

use std::error::Error as StdError;
use std::fmt;

/// Exact RFC 3550 reception-report block size.
pub const RECEPTION_REPORT_BYTES: usize = 24;
/// Lowest signed 24-bit cumulative packet-loss value.
pub const MIN_CUMULATIVE_LOST: i32 = -8_388_608;
/// Highest signed 24-bit cumulative packet-loss value.
pub const MAX_CUMULATIVE_LOST: i32 = 8_388_607;

/// One validated RTCP reception-report block.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReceptionReport {
    source_ssrc: u32,
    fraction_lost: u8,
    cumulative_lost: i32,
    extended_highest_sequence: u32,
    interarrival_jitter: u32,
    last_sender_report: u32,
    delay_since_last_sender_report: u32,
}

impl ReceptionReport {
    /// Parses the first complete reception-report block from `input`.
    ///
    /// # Errors
    ///
    /// Rejects input shorter than exactly one fixed-size report block.
    pub fn parse(input: &[u8]) -> Result<Self, ReceptionReportError> {
        if input.len() < RECEPTION_REPORT_BYTES {
            return Err(ReceptionReportError::Truncated {
                required: RECEPTION_REPORT_BYTES,
                available: input.len(),
            });
        }
        let cumulative_raw = u32::from_be_bytes([0, input[5], input[6], input[7]]);
        let cumulative_lost = if cumulative_raw & 0x0080_0000 != 0 {
            i64::from(cumulative_raw) - (1_i64 << 24)
        } else {
            i64::from(cumulative_raw)
        };
        let cumulative_lost = i32::try_from(cumulative_lost)
            .map_err(|_| ReceptionReportError::LossConversionFailed)?;

        Ok(Self {
            source_ssrc: read_u32(input, 0),
            fraction_lost: input[4],
            cumulative_lost,
            extended_highest_sequence: read_u32(input, 8),
            interarrival_jitter: read_u32(input, 12),
            last_sender_report: read_u32(input, 16),
            delay_since_last_sender_report: read_u32(input, 20),
        })
    }

    /// Constructs a report block from validated metric values.
    ///
    /// # Errors
    ///
    /// Rejects cumulative loss outside the signed 24-bit wire range.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        source_ssrc: u32,
        fraction_lost: u8,
        cumulative_lost: i32,
        extended_highest_sequence: u32,
        interarrival_jitter: u32,
        last_sender_report: u32,
        delay_since_last_sender_report: u32,
    ) -> Result<Self, ReceptionReportError> {
        if cumulative_lost < MIN_CUMULATIVE_LOST || cumulative_lost > MAX_CUMULATIVE_LOST {
            return Err(ReceptionReportError::CumulativeLossOutOfRange {
                value: cumulative_lost,
                minimum: MIN_CUMULATIVE_LOST,
                maximum: MAX_CUMULATIVE_LOST,
            });
        }
        Ok(Self {
            source_ssrc,
            fraction_lost,
            cumulative_lost,
            extended_highest_sequence,
            interarrival_jitter,
            last_sender_report,
            delay_since_last_sender_report,
        })
    }

    /// Returns the SSRC to which this report refers.
    #[must_use]
    pub const fn source_ssrc(self) -> u32 {
        self.source_ssrc
    }

    /// Returns loss since the previous report as a 0–255 fraction of 256.
    #[must_use]
    pub const fn fraction_lost(self) -> u8 {
        self.fraction_lost
    }

    /// Returns cumulative packets lost, including possible negative values.
    #[must_use]
    pub const fn cumulative_lost(self) -> i32 {
        self.cumulative_lost
    }

    /// Returns the extended highest received RTP sequence number.
    #[must_use]
    pub const fn extended_highest_sequence(self) -> u32 {
        self.extended_highest_sequence
    }

    /// Returns estimated interarrival jitter in RTP timestamp units.
    #[must_use]
    pub const fn interarrival_jitter(self) -> u32 {
        self.interarrival_jitter
    }

    /// Returns the middle 32 bits of the most recent sender-report NTP time.
    #[must_use]
    pub const fn last_sender_report(self) -> u32 {
        self.last_sender_report
    }

    /// Returns delay since that sender report in 1/65536-second units.
    #[must_use]
    pub const fn delay_since_last_sender_report(self) -> u32 {
        self.delay_since_last_sender_report
    }

    /// Serializes the exact 24-byte reception-report block.
    #[must_use]
    pub fn encode(self) -> [u8; RECEPTION_REPORT_BYTES] {
        let mut output = [0_u8; RECEPTION_REPORT_BYTES];
        output[0..4].copy_from_slice(&self.source_ssrc.to_be_bytes());
        output[4] = self.fraction_lost;
        let cumulative = self.cumulative_lost.to_be_bytes();
        output[5..8].copy_from_slice(&cumulative[1..4]);
        output[8..12].copy_from_slice(&self.extended_highest_sequence.to_be_bytes());
        output[12..16].copy_from_slice(&self.interarrival_jitter.to_be_bytes());
        output[16..20].copy_from_slice(&self.last_sender_report.to_be_bytes());
        output[20..24].copy_from_slice(&self.delay_since_last_sender_report.to_be_bytes());
        output
    }
}

impl fmt::Debug for ReceptionReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceptionReport")
            .field("fraction_lost", &self.fraction_lost)
            .field("cumulative_lost", &self.cumulative_lost)
            .field("extended_highest_sequence", &self.extended_highest_sequence)
            .field("interarrival_jitter", &self.interarrival_jitter)
            .field("has_last_sender_report", &(self.last_sender_report != 0))
            .finish_non_exhaustive()
    }
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

/// Failure while parsing or constructing an RTCP reception report.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReceptionReportError {
    /// Input ends before the fixed-size block boundary.
    Truncated {
        /// Required byte count.
        required: usize,
        /// Available byte count.
        available: usize,
    },
    /// Cumulative loss is not representable as a signed 24-bit integer.
    CumulativeLossOutOfRange {
        /// Supplied cumulative loss.
        value: i32,
        /// Minimum representable value.
        minimum: i32,
        /// Maximum representable value.
        maximum: i32,
    },
    /// Defensive signed-loss conversion failed.
    LossConversionFailed,
}

impl fmt::Display for ReceptionReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                required,
                available,
            } => write!(
                formatter,
                "truncated RTCP reception report: requires {required} bytes, has {available}"
            ),
            Self::CumulativeLossOutOfRange {
                value,
                minimum,
                maximum,
            } => write!(
                formatter,
                "RTCP cumulative loss {value} is outside {minimum}..={maximum}"
            ),
            Self::LossConversionFailed => {
                formatter.write_str("RTCP cumulative-loss conversion failed")
            }
        }
    }
}

impl StdError for ReceptionReportError {}

#[cfg(test)]
mod tests {
    use super::{
        MAX_CUMULATIVE_LOST, MIN_CUMULATIVE_LOST, RECEPTION_REPORT_BYTES, ReceptionReport,
        ReceptionReportError,
    };

    fn report(loss: i32) -> ReceptionReport {
        ReceptionReport::new(0xdead_beef, 128, loss, 0x0002_0003, 40, 50, 60)
            .unwrap_or_else(|_| panic!("report"))
    }

    #[test]
    fn round_trips_positive_and_negative_loss() {
        for loss in [-1, 0, 0x0012_3456, MIN_CUMULATIVE_LOST, MAX_CUMULATIVE_LOST] {
            let original = report(loss);
            let encoded = original.encode();
            let parsed = ReceptionReport::parse(&encoded).unwrap_or_else(|_| panic!("parse"));
            assert_eq!(parsed, original);
            assert_eq!(parsed.cumulative_lost(), loss);
        }
    }

    #[test]
    fn parses_all_metrics_in_network_order() {
        let parsed =
            ReceptionReport::parse(&report(7).encode()).unwrap_or_else(|_| panic!("parse"));
        assert_eq!(parsed.source_ssrc(), 0xdead_beef);
        assert_eq!(parsed.fraction_lost(), 128);
        assert_eq!(parsed.extended_highest_sequence(), 0x0002_0003);
        assert_eq!(parsed.interarrival_jitter(), 40);
        assert_eq!(parsed.last_sender_report(), 50);
        assert_eq!(parsed.delay_since_last_sender_report(), 60);
    }

    #[test]
    fn rejects_truncation() {
        assert_eq!(
            ReceptionReport::parse(&[0; RECEPTION_REPORT_BYTES - 1]),
            Err(ReceptionReportError::Truncated {
                required: RECEPTION_REPORT_BYTES,
                available: RECEPTION_REPORT_BYTES - 1,
            })
        );
    }

    #[test]
    fn rejects_values_outside_signed_24_bit_range() {
        assert_eq!(
            ReceptionReport::new(1, 0, MAX_CUMULATIVE_LOST + 1, 0, 0, 0, 0),
            Err(ReceptionReportError::CumulativeLossOutOfRange {
                value: MAX_CUMULATIVE_LOST + 1,
                minimum: MIN_CUMULATIVE_LOST,
                maximum: MAX_CUMULATIVE_LOST,
            })
        );
        assert_eq!(
            ReceptionReport::new(1, 0, MIN_CUMULATIVE_LOST - 1, 0, 0, 0, 0),
            Err(ReceptionReportError::CumulativeLossOutOfRange {
                value: MIN_CUMULATIVE_LOST - 1,
                minimum: MIN_CUMULATIVE_LOST,
                maximum: MAX_CUMULATIVE_LOST,
            })
        );
    }

    #[test]
    fn debug_redacts_source_and_timing_token() {
        let debug = format!("{:?}", report(3));
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("3735928559"));
        assert!(!debug.contains("50"));
    }
}
