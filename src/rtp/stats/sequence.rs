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

//! RFC 3550 RTP sequence validation and loss accounting.
//!
//! The tracker rejects isolated spoofed sequence numbers, establishes a source
//! only after sequential probation, distinguishes normal wraparound from large
//! jumps, and retains reordered/duplicate packets in RFC reception accounting.

/// Sequence modulus for the 16-bit RTP wire field.
pub const RTP_SEQUENCE_MODULUS: u64 = 1 << 16;
/// Maximum normal forward jump before a source restart is suspected.
pub const MAX_DROPOUT: u16 = 3_000;
/// Maximum tolerated backward reordering window.
pub const MAX_MISORDER: u16 = 100;
/// Sequential packets required to establish a new source.
pub const MIN_SEQUENTIAL: u8 = 2;

/// Result of observing one RTP sequence number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceDisposition {
    /// Source is not yet validated by sequential probation.
    Probation,
    /// Packet established a validated source.
    SourceValidated,
    /// Packet advanced the highest sequence normally.
    InOrder,
    /// Packet advanced across the 16-bit wrap boundary.
    Wrapped,
    /// Packet was late, reordered, or a duplicate within the accepted window.
    ReorderedOrDuplicate,
    /// First implausible large jump was rejected pending confirmation.
    LargeJumpRejected,
    /// A second sequential packet confirmed a source sequence restart.
    SourceRestarted,
}

impl SequenceDisposition {
    /// Returns whether this observation contributes to received-packet counts.
    #[must_use]
    pub const fn accepted(self) -> bool {
        !matches!(self, Self::Probation | Self::LargeJumpRejected)
    }
}

/// Immutable reception statistics at one reporting instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceSnapshot {
    extended_highest_sequence: u64,
    expected_packets: u64,
    received_packets: u64,
    cumulative_lost: i64,
    fraction_lost: u8,
}

impl SequenceSnapshot {
    /// Returns the non-wrapping extended highest sequence.
    #[must_use]
    pub const fn extended_highest_sequence(self) -> u64 {
        self.extended_highest_sequence
    }

    /// Returns the low 32 bits used by an RTCP reception-report block.
    #[must_use]
    pub fn extended_highest_sequence_u32(self) -> u32 {
        let bytes = self.extended_highest_sequence.to_le_bytes();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    /// Returns packets expected since the current source epoch began.
    #[must_use]
    pub const fn expected_packets(self) -> u64 {
        self.expected_packets
    }

    /// Returns all accepted packets, including duplicates.
    #[must_use]
    pub const fn received_packets(self) -> u64 {
        self.received_packets
    }

    /// Returns expected minus received; duplicates may make this negative.
    #[must_use]
    pub const fn cumulative_lost(self) -> i64 {
        self.cumulative_lost
    }

    /// Returns interval loss as a fraction of 256 for RTCP reporting.
    #[must_use]
    pub const fn fraction_lost(self) -> u8 {
        self.fraction_lost
    }
}

/// Stateful RFC 3550 sequence validator and loss accumulator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceTracker {
    probation: u8,
    max_sequence: u16,
    bad_sequence: u16,
    base_sequence: u16,
    cycles: u64,
    received: u64,
    expected_prior: u64,
    received_prior: u64,
    validated: bool,
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SequenceTracker {
    /// Creates an unvalidated tracker requiring two sequential packets.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            probation: MIN_SEQUENTIAL,
            max_sequence: 0,
            bad_sequence: 0,
            base_sequence: 0,
            cycles: 0,
            received: 0,
            expected_prior: 0,
            received_prior: 0,
            validated: false,
        }
    }

    /// Observes one RTP sequence number.
    pub fn observe(&mut self, sequence: u16) -> SequenceDisposition {
        if !self.validated {
            return self.observe_probation(sequence);
        }

        let delta = sequence.wrapping_sub(self.max_sequence);
        let disposition = if delta == 0 {
            SequenceDisposition::ReorderedOrDuplicate
        } else if delta < MAX_DROPOUT {
            let wrapped = sequence < self.max_sequence;
            if wrapped {
                self.cycles = self.cycles.saturating_add(RTP_SEQUENCE_MODULUS);
            }
            self.max_sequence = sequence;
            if wrapped {
                SequenceDisposition::Wrapped
            } else {
                SequenceDisposition::InOrder
            }
        } else if delta <= u16::MAX - MAX_MISORDER {
            if sequence == self.bad_sequence {
                self.initialize_epoch(sequence);
                self.received = 1;
                return SequenceDisposition::SourceRestarted;
            }
            self.bad_sequence = sequence.wrapping_add(1);
            return SequenceDisposition::LargeJumpRejected;
        } else {
            SequenceDisposition::ReorderedOrDuplicate
        };
        self.received = self.received.saturating_add(1);
        disposition
    }

    /// Returns whether sequential probation has completed.
    #[must_use]
    pub const fn is_validated(&self) -> bool {
        self.validated
    }

    /// Returns remaining sequential probation packets.
    #[must_use]
    pub const fn probation_remaining(&self) -> u8 {
        self.probation
    }

    /// Returns accepted packet count in the current source epoch.
    #[must_use]
    pub const fn received_packets(&self) -> u64 {
        self.received
    }

    /// Produces statistics and advances interval baselines for the next report.
    ///
    /// Before source validation, all fields are zero.
    #[must_use]
    pub fn snapshot(&mut self) -> SequenceSnapshot {
        if !self.validated {
            return SequenceSnapshot {
                extended_highest_sequence: 0,
                expected_packets: 0,
                received_packets: 0,
                cumulative_lost: 0,
                fraction_lost: 0,
            };
        }
        let extended = self.cycles + u64::from(self.max_sequence);
        let expected = extended
            .saturating_sub(u64::from(self.base_sequence))
            .saturating_add(1);
        let cumulative_lost = signed_difference(expected, self.received);
        let expected_interval = expected.saturating_sub(self.expected_prior);
        let received_interval = self.received.saturating_sub(self.received_prior);
        let lost_interval = signed_difference(expected_interval, received_interval);
        let fraction_lost = interval_fraction(lost_interval, expected_interval);
        self.expected_prior = expected;
        self.received_prior = self.received;
        SequenceSnapshot {
            extended_highest_sequence: extended,
            expected_packets: expected,
            received_packets: self.received,
            cumulative_lost,
            fraction_lost,
        }
    }

    fn observe_probation(&mut self, sequence: u16) -> SequenceDisposition {
        if self.probation == MIN_SEQUENTIAL {
            self.max_sequence = sequence;
            self.probation -= 1;
            return SequenceDisposition::Probation;
        }
        if sequence == self.max_sequence.wrapping_add(1) {
            self.max_sequence = sequence;
            self.probation -= 1;
            if self.probation == 0 {
                self.initialize_epoch(sequence);
                self.received = 1;
                return SequenceDisposition::SourceValidated;
            }
        } else {
            self.max_sequence = sequence;
            self.probation = MIN_SEQUENTIAL - 1;
        }
        SequenceDisposition::Probation
    }

    fn initialize_epoch(&mut self, sequence: u16) {
        self.base_sequence = sequence;
        self.max_sequence = sequence;
        self.bad_sequence = sequence.wrapping_add(1);
        self.cycles = 0;
        self.received = 0;
        self.expected_prior = 0;
        self.received_prior = 0;
        self.probation = 0;
        self.validated = true;
    }
}

fn signed_difference(left: u64, right: u64) -> i64 {
    if left >= right {
        i64::try_from(left - right).unwrap_or(i64::MAX)
    } else {
        i64::try_from(right - left).map_or(i64::MIN, i64::saturating_neg)
    }
}

fn interval_fraction(lost: i64, expected: u64) -> u8 {
    if lost <= 0 || expected == 0 {
        return 0;
    }
    let lost = u128::try_from(lost).unwrap_or(u128::MAX);
    let value = lost.saturating_mul(256) / u128::from(expected);
    u8::try_from(value.min(255)).unwrap_or(255)
}

#[cfg(test)]
mod tests {
    use super::{SequenceDisposition, SequenceTracker};

    fn validated(start: u16) -> SequenceTracker {
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(start), SequenceDisposition::Probation);
        assert_eq!(
            tracker.observe(start.wrapping_add(1)),
            SequenceDisposition::SourceValidated
        );
        tracker
    }

    #[test]
    fn requires_sequential_probation() {
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(10), SequenceDisposition::Probation);
        assert_eq!(tracker.observe(20), SequenceDisposition::Probation);
        assert!(!tracker.is_validated());
        assert_eq!(tracker.observe(21), SequenceDisposition::SourceValidated);
        assert!(tracker.is_validated());
        assert_eq!(tracker.received_packets(), 1);
    }

    #[test]
    fn tracks_loss_and_interval_fraction() {
        let mut tracker = validated(100);
        assert_eq!(tracker.observe(102), SequenceDisposition::InOrder);
        assert_eq!(tracker.observe(104), SequenceDisposition::InOrder);
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.expected_packets(), 4);
        assert_eq!(snapshot.received_packets(), 3);
        assert_eq!(snapshot.cumulative_lost(), 1);
        assert_eq!(snapshot.fraction_lost(), 64);
        assert_eq!(tracker.snapshot().fraction_lost(), 0);
    }

    #[test]
    fn recognizes_wrap_and_extended_sequence() {
        let mut tracker = validated(u16::MAX - 1);
        assert_eq!(tracker.observe(0), SequenceDisposition::Wrapped);
        assert_eq!(tracker.observe(1), SequenceDisposition::InOrder);
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.extended_highest_sequence(), 65_537);
        assert_eq!(snapshot.extended_highest_sequence_u32(), 65_537);
    }

    #[test]
    fn accepts_reordered_and_duplicate_packets_for_rfc_accounting() {
        let mut tracker = validated(10);
        tracker.observe(12);
        assert_eq!(
            tracker.observe(11),
            SequenceDisposition::ReorderedOrDuplicate
        );
        assert_eq!(
            tracker.observe(12),
            SequenceDisposition::ReorderedOrDuplicate
        );
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.expected_packets(), 2);
        assert_eq!(snapshot.received_packets(), 4);
        assert_eq!(snapshot.cumulative_lost(), -2);
        assert_eq!(snapshot.fraction_lost(), 0);
    }

    #[test]
    fn confirms_large_jump_before_restarting_epoch() {
        let mut tracker = validated(10);
        assert_eq!(
            tracker.observe(20_000),
            SequenceDisposition::LargeJumpRejected
        );
        assert_eq!(tracker.received_packets(), 1);
        assert_eq!(
            tracker.observe(20_001),
            SequenceDisposition::SourceRestarted
        );
        assert_eq!(tracker.received_packets(), 1);
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.expected_packets(), 1);
        assert_eq!(snapshot.cumulative_lost(), 0);
    }

    #[test]
    fn dispositions_report_acceptance() {
        assert!(!SequenceDisposition::Probation.accepted());
        assert!(!SequenceDisposition::LargeJumpRejected.accepted());
        assert!(SequenceDisposition::InOrder.accepted());
        assert!(SequenceDisposition::ReorderedOrDuplicate.accepted());
    }
}
