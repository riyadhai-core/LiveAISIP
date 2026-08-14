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

//! RTCP round-trip-time calculation and bounded smoothing.
//!
//! RTCP uses the middle 32 bits of NTP timestamps as unsigned 16.16 fixed-point
//! seconds. Calculations use modular arithmetic so the compact timestamp's
//! roughly 18-hour rollover is handled without floating point.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

/// Compact NTP units per second.
pub const COMPACT_NTP_UNITS_PER_SECOND: u64 = 65_536;
/// Default maximum accepted RTT sample.
pub const DEFAULT_MAXIMUM_RTT: Duration = Duration::from_secs(60);

/// A middle-32-bit NTP timestamp used by RTCP.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CompactNtp(u32);

impl CompactNtp {
    /// Creates a compact timestamp from its exact wire value.
    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    /// Converts a duration since a caller-selected NTP-compatible epoch.
    ///
    /// Whole seconds wrap at 16 bits as required by the compact format.
    #[must_use]
    pub fn from_duration(value: Duration) -> Self {
        let seconds_bytes = value.as_secs().to_le_bytes();
        let low_seconds = u16::from_le_bytes([seconds_bytes[0], seconds_bytes[1]]);
        let fractional =
            u64::from(value.subsec_nanos()) * COMPACT_NTP_UNITS_PER_SECOND / 1_000_000_000;
        let fractional = u16::try_from(fractional).unwrap_or(u16::MAX);
        Self(u32::from(low_seconds) << 16 | u32::from(fractional))
    }

    /// Returns the exact 32-bit wire value.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Returns modular elapsed compact-NTP units from `earlier` to this value.
    #[must_use]
    pub const fn wrapping_elapsed_since(self, earlier: Self) -> u32 {
        self.0.wrapping_sub(earlier.0)
    }
}

/// Result of evaluating one RTCP RTT opportunity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RttUpdate {
    /// Report had no previous Sender Report reference (`LSR == 0`).
    NoSenderReport,
    /// Reported receiver delay was not smaller than total elapsed time.
    InvalidReceiverDelay {
        /// Modular elapsed units between LSR and arrival.
        elapsed_units: u32,
        /// Reported delay since last Sender Report.
        delay_units: u32,
    },
    /// Calculated RTT exceeded the configured safety ceiling.
    OutOfRange {
        /// Calculated sample.
        sample: Duration,
        /// Configured maximum.
        maximum: Duration,
    },
    /// A valid sample updated the estimator.
    Sampled {
        /// Calculated round-trip time.
        rtt: Duration,
    },
}

/// Bounded integer RTCP RTT estimator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RttEstimator {
    maximum_units: u32,
    smoothed_q3: u64,
    last_units: Option<u32>,
    minimum_units: Option<u32>,
    maximum_observed_units: Option<u32>,
    samples: u64,
    rejected_samples: u64,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    /// Creates an estimator accepting RTT samples up to 60 seconds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            maximum_units: duration_to_units(DEFAULT_MAXIMUM_RTT).unwrap_or(u32::MAX),
            smoothed_q3: 0,
            last_units: None,
            minimum_units: None,
            maximum_observed_units: None,
            samples: 0,
            rejected_samples: 0,
        }
    }

    /// Creates an estimator with a caller-selected positive RTT ceiling.
    ///
    /// # Errors
    ///
    /// Rejects zero or durations not representable in compact-NTP units.
    pub fn with_maximum(maximum: Duration) -> Result<Self, RttError> {
        let maximum_units = duration_to_units(maximum)?;
        if maximum_units == 0 {
            return Err(RttError::ZeroMaximum);
        }
        Ok(Self {
            maximum_units,
            smoothed_q3: 0,
            last_units: None,
            minimum_units: None,
            maximum_observed_units: None,
            samples: 0,
            rejected_samples: 0,
        })
    }

    /// Processes RTCP arrival time, LSR, and DLSR fields.
    ///
    /// The estimator computes `arrival - LSR - DLSR` in compact NTP units.
    pub fn observe(
        &mut self,
        arrival: CompactNtp,
        last_sender_report: u32,
        delay_since_last_sender_report: u32,
    ) -> RttUpdate {
        if last_sender_report == 0 {
            return RttUpdate::NoSenderReport;
        }
        let elapsed = arrival.wrapping_elapsed_since(CompactNtp::from_raw(last_sender_report));
        if elapsed <= delay_since_last_sender_report {
            self.rejected_samples = self.rejected_samples.saturating_add(1);
            return RttUpdate::InvalidReceiverDelay {
                elapsed_units: elapsed,
                delay_units: delay_since_last_sender_report,
            };
        }
        let sample_units = elapsed - delay_since_last_sender_report;
        let sample = units_to_duration(sample_units);
        if sample_units > self.maximum_units {
            self.rejected_samples = self.rejected_samples.saturating_add(1);
            return RttUpdate::OutOfRange {
                sample,
                maximum: units_to_duration(self.maximum_units),
            };
        }
        if self.samples == 0 {
            self.smoothed_q3 = u64::from(sample_units) << 3;
        } else {
            let decay = self.smoothed_q3.saturating_add(4) >> 3;
            self.smoothed_q3 = self
                .smoothed_q3
                .saturating_add(u64::from(sample_units))
                .saturating_sub(decay);
        }
        self.last_units = Some(sample_units);
        self.minimum_units = Some(
            self.minimum_units
                .map_or(sample_units, |current| current.min(sample_units)),
        );
        self.maximum_observed_units = Some(
            self.maximum_observed_units
                .map_or(sample_units, |current| current.max(sample_units)),
        );
        self.samples = self.samples.saturating_add(1);
        RttUpdate::Sampled { rtt: sample }
    }

    /// Returns most recently accepted RTT.
    #[must_use]
    pub fn last(self) -> Option<Duration> {
        self.last_units.map(units_to_duration)
    }

    /// Returns smoothed RTT using an integer one-eighth EWMA.
    #[must_use]
    pub fn smoothed(self) -> Option<Duration> {
        if self.samples == 0 {
            return None;
        }
        let units = (self.smoothed_q3.saturating_add(4)) >> 3;
        let units = u32::try_from(units.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
        Some(units_to_duration(units))
    }

    /// Returns minimum accepted RTT.
    #[must_use]
    pub fn minimum(self) -> Option<Duration> {
        self.minimum_units.map(units_to_duration)
    }

    /// Returns maximum accepted RTT.
    #[must_use]
    pub fn maximum(self) -> Option<Duration> {
        self.maximum_observed_units.map(units_to_duration)
    }

    /// Returns accepted sample count.
    #[must_use]
    pub const fn samples(self) -> u64 {
        self.samples
    }

    /// Returns invalid or out-of-range sample count.
    #[must_use]
    pub const fn rejected_samples(self) -> u64 {
        self.rejected_samples
    }

    /// Clears measurements while retaining the configured ceiling.
    pub const fn reset(&mut self) {
        self.smoothed_q3 = 0;
        self.last_units = None;
        self.minimum_units = None;
        self.maximum_observed_units = None;
        self.samples = 0;
        self.rejected_samples = 0;
    }
}

fn duration_to_units(value: Duration) -> Result<u32, RttError> {
    let whole = value
        .as_secs()
        .checked_mul(COMPACT_NTP_UNITS_PER_SECOND)
        .ok_or(RttError::DurationTooLarge)?;
    let fractional = u64::from(value.subsec_nanos()) * COMPACT_NTP_UNITS_PER_SECOND / 1_000_000_000;
    let total = whole
        .checked_add(fractional)
        .ok_or(RttError::DurationTooLarge)?;
    u32::try_from(total).map_err(|_| RttError::DurationTooLarge)
}

fn units_to_duration(units: u32) -> Duration {
    let seconds = u64::from(units) / COMPACT_NTP_UNITS_PER_SECOND;
    let fraction = u64::from(units) % COMPACT_NTP_UNITS_PER_SECOND;
    let nanos = fraction * 1_000_000_000 / COMPACT_NTP_UNITS_PER_SECOND;
    Duration::new(seconds, u32::try_from(nanos).unwrap_or(999_999_999))
}

/// RTT estimator configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RttError {
    /// Maximum accepted RTT was below one compact-NTP unit.
    ZeroMaximum,
    /// Duration could not fit the compact-NTP delta representation.
    DurationTooLarge,
}

impl fmt::Display for RttError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaximum => formatter.write_str("maximum RTT is zero"),
            Self::DurationTooLarge => formatter.write_str("RTT duration is too large"),
        }
    }
}

impl StdError for RttError {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CompactNtp, RttError, RttEstimator, RttUpdate};

    #[test]
    fn calculates_rtt_after_receiver_delay() {
        let mut estimator = RttEstimator::new();
        let arrival = CompactNtp::from_raw(0x0002_0000);
        assert_eq!(
            estimator.observe(arrival, 0x0001_0000, 0x0000_4000),
            RttUpdate::Sampled {
                rtt: Duration::from_millis(750),
            }
        );
        assert_eq!(estimator.last(), Some(Duration::from_millis(750)));
        assert_eq!(estimator.samples(), 1);
    }

    #[test]
    fn compact_timestamp_wrap_is_transparent() {
        let mut estimator = RttEstimator::new();
        assert_eq!(
            estimator.observe(CompactNtp::from_raw(0x0000_1000), 0xffff_0000, 0x0000_1000,),
            RttUpdate::Sampled {
                rtt: Duration::from_secs(1),
            }
        );
    }

    #[test]
    fn rejects_missing_invalid_and_excessive_samples() {
        let mut estimator = RttEstimator::with_maximum(Duration::from_secs(1))
            .unwrap_or_else(|_| panic!("estimator"));
        assert_eq!(
            estimator.observe(CompactNtp::from_raw(10), 0, 0),
            RttUpdate::NoSenderReport
        );
        assert_eq!(
            estimator.observe(CompactNtp::from_raw(200), 100, 100),
            RttUpdate::InvalidReceiverDelay {
                elapsed_units: 100,
                delay_units: 100,
            }
        );
        assert!(matches!(
            estimator.observe(CompactNtp::from_raw(200_000), 1, 0),
            RttUpdate::OutOfRange { .. }
        ));
        assert_eq!(estimator.rejected_samples(), 2);
        assert_eq!(estimator.samples(), 0);
    }

    #[test]
    fn smooths_and_tracks_minimum_and_maximum() {
        let mut estimator = RttEstimator::new();
        let first = CompactNtp::from_duration(Duration::from_millis(100)).as_raw();
        estimator.observe(CompactNtp::from_raw(first + 1), 1, 0);
        let second = CompactNtp::from_duration(Duration::from_millis(200)).as_raw();
        estimator.observe(CompactNtp::from_raw(second + 1), 1, 0);
        let minimum = estimator.minimum().unwrap_or_else(|| panic!("minimum"));
        let maximum = estimator.maximum().unwrap_or_else(|| panic!("maximum"));
        let smoothed = estimator.smoothed().unwrap_or_else(|| panic!("smoothed"));
        assert!(minimum >= Duration::from_millis(99));
        assert!(maximum >= Duration::from_millis(199));
        assert!(smoothed >= Duration::from_millis(111));
        assert!(smoothed <= Duration::from_millis(113));
    }

    #[test]
    fn validates_maximum_and_reset() {
        assert_eq!(
            RttEstimator::with_maximum(Duration::ZERO),
            Err(RttError::ZeroMaximum)
        );
        let mut estimator = RttEstimator::new();
        estimator.observe(CompactNtp::from_raw(100), 1, 0);
        estimator.reset();
        assert_eq!(estimator.samples(), 0);
        assert_eq!(estimator.last(), None);
        assert_eq!(estimator.smoothed(), None);
    }
}
