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

//! RTCP-safe packet-loss statistics.
//!
//! Internal counters remain wide enough for long-running calls. Conversion to
//! the RTCP signed 24-bit cumulative-loss field saturates explicitly and
//! records that saturation, rather than silently wrapping operational data.

use crate::rtp::packet::rtcp::report_block::{MAX_CUMULATIVE_LOST, MIN_CUMULATIVE_LOST};

use super::sequence::SequenceSnapshot;

/// Parts-per-million denominator used by lifetime loss rates.
pub const PARTS_PER_MILLION: u64 = 1_000_000;

/// Loss metrics derived from one sequence-statistics snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LossSnapshot {
    expected_packets: u64,
    received_packets: u64,
    raw_cumulative_lost: i64,
    rtcp_cumulative_lost: i32,
    fraction_lost: u8,
    loss_parts_per_million: u32,
    duplicate_excess: u64,
    cumulative_was_clamped: bool,
}

impl LossSnapshot {
    /// Derives bounded loss metrics from an RFC sequence snapshot.
    #[must_use]
    pub fn from_sequence(sequence: SequenceSnapshot) -> Self {
        let raw_cumulative_lost = sequence.cumulative_lost();
        let (rtcp_cumulative_lost, cumulative_was_clamped) =
            clamp_cumulative_loss(raw_cumulative_lost);
        let positive_lost = if raw_cumulative_lost > 0 {
            u64::try_from(raw_cumulative_lost).unwrap_or(u64::MAX)
        } else {
            0
        };
        let duplicate_excess = if raw_cumulative_lost < 0 {
            raw_cumulative_lost.unsigned_abs()
        } else {
            0
        };
        let loss_parts_per_million = calculate_ppm(positive_lost, sequence.expected_packets());
        Self {
            expected_packets: sequence.expected_packets(),
            received_packets: sequence.received_packets(),
            raw_cumulative_lost,
            rtcp_cumulative_lost,
            fraction_lost: sequence.fraction_lost(),
            loss_parts_per_million,
            duplicate_excess,
            cumulative_was_clamped,
        }
    }

    /// Returns packets expected during the current source epoch.
    #[must_use]
    pub const fn expected_packets(self) -> u64 {
        self.expected_packets
    }

    /// Returns accepted packets including duplicates.
    #[must_use]
    pub const fn received_packets(self) -> u64 {
        self.received_packets
    }

    /// Returns the wide unsaturated expected-minus-received value.
    #[must_use]
    pub const fn raw_cumulative_lost(self) -> i64 {
        self.raw_cumulative_lost
    }

    /// Returns cumulative loss safe for the signed 24-bit RTCP field.
    #[must_use]
    pub const fn rtcp_cumulative_lost(self) -> i32 {
        self.rtcp_cumulative_lost
    }

    /// Returns interval loss as a fraction of 256.
    #[must_use]
    pub const fn fraction_lost(self) -> u8 {
        self.fraction_lost
    }

    /// Returns positive lifetime loss in parts per million.
    ///
    /// Duplicate excess never produces a negative rate; it is reported by
    /// [`Self::duplicate_excess`] instead.
    #[must_use]
    pub const fn loss_parts_per_million(self) -> u32 {
        self.loss_parts_per_million
    }

    /// Returns received packets beyond expected count, normally duplicates.
    #[must_use]
    pub const fn duplicate_excess(self) -> u64 {
        self.duplicate_excess
    }

    /// Returns whether wide cumulative loss was saturated for RTCP encoding.
    #[must_use]
    pub const fn cumulative_was_clamped(self) -> bool {
        self.cumulative_was_clamped
    }
}

fn clamp_cumulative_loss(value: i64) -> (i32, bool) {
    if value > i64::from(MAX_CUMULATIVE_LOST) {
        (MAX_CUMULATIVE_LOST, true)
    } else if value < i64::from(MIN_CUMULATIVE_LOST) {
        (MIN_CUMULATIVE_LOST, true)
    } else {
        (i32::try_from(value).unwrap_or(0), false)
    }
}

fn calculate_ppm(lost: u64, expected: u64) -> u32 {
    if lost == 0 || expected == 0 {
        return 0;
    }
    let scaled = u128::from(lost).saturating_mul(u128::from(PARTS_PER_MILLION));
    let rounded = scaled.saturating_add(u128::from(expected / 2)) / u128::from(expected);
    u32::try_from(rounded.min(u128::from(PARTS_PER_MILLION))).unwrap_or(1_000_000)
}

#[cfg(test)]
mod tests {
    use super::{LossSnapshot, calculate_ppm, clamp_cumulative_loss};
    use crate::rtp::packet::rtcp::report_block::{MAX_CUMULATIVE_LOST, MIN_CUMULATIVE_LOST};
    use crate::rtp::stats::{SequenceDisposition, SequenceTracker};

    fn validated() -> SequenceTracker {
        let mut tracker = SequenceTracker::new();
        tracker.observe(100);
        assert_eq!(tracker.observe(101), SequenceDisposition::SourceValidated);
        tracker
    }

    #[test]
    fn derives_interval_and_lifetime_loss() {
        let mut tracker = validated();
        tracker.observe(102);
        tracker.observe(104);
        let loss = LossSnapshot::from_sequence(tracker.snapshot());
        assert_eq!(loss.expected_packets(), 4);
        assert_eq!(loss.received_packets(), 3);
        assert_eq!(loss.raw_cumulative_lost(), 1);
        assert_eq!(loss.rtcp_cumulative_lost(), 1);
        assert_eq!(loss.fraction_lost(), 64);
        assert_eq!(loss.loss_parts_per_million(), 250_000);
        assert_eq!(loss.duplicate_excess(), 0);
        assert!(!loss.cumulative_was_clamped());
    }

    #[test]
    fn reports_duplicates_separately_from_positive_loss() {
        let mut tracker = validated();
        tracker.observe(102);
        tracker.observe(102);
        tracker.observe(102);
        let loss = LossSnapshot::from_sequence(tracker.snapshot());
        assert_eq!(loss.raw_cumulative_lost(), -2);
        assert_eq!(loss.rtcp_cumulative_lost(), -2);
        assert_eq!(loss.duplicate_excess(), 2);
        assert_eq!(loss.loss_parts_per_million(), 0);
    }

    #[test]
    fn saturates_both_signed_24_bit_boundaries() {
        assert_eq!(
            clamp_cumulative_loss(i64::from(MAX_CUMULATIVE_LOST) + 1),
            (MAX_CUMULATIVE_LOST, true)
        );
        assert_eq!(
            clamp_cumulative_loss(i64::from(MIN_CUMULATIVE_LOST) - 1),
            (MIN_CUMULATIVE_LOST, true)
        );
        assert_eq!(clamp_cumulative_loss(7), (7, false));
    }

    #[test]
    fn ppm_rounds_and_handles_empty_intervals() {
        assert_eq!(calculate_ppm(0, 0), 0);
        assert_eq!(calculate_ppm(1, 3), 333_333);
        assert_eq!(calculate_ppm(2, 3), 666_667);
        assert_eq!(calculate_ppm(10, 5), 1_000_000);
    }

    #[test]
    fn unvalidated_sequence_produces_zero_metrics() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(5);
        let loss = LossSnapshot::from_sequence(tracker.snapshot());
        assert_eq!(loss.expected_packets(), 0);
        assert_eq!(loss.received_packets(), 0);
        assert_eq!(loss.rtcp_cumulative_lost(), 0);
        assert_eq!(loss.fraction_lost(), 0);
    }
}
