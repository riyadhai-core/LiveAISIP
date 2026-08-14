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

//! Constant-memory delayed packet-loss observability.

/// Reordering window before an observed sequence gap becomes final loss.
pub const REORDER_WINDOW_PACKETS: usize = 64;
const REORDER_WINDOW_PACKETS_U64: u64 = 64;

/// Delayed loss snapshot independent of RTCP's immediate RFC accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelayedLossSnapshot {
    /// Missing packets still recoverable inside the reorder window.
    pub pending: u8,
    /// Gaps finalized after leaving the reorder window.
    pub finalized_lost: u64,
    /// Late packets that recovered a pending gap.
    pub recovered_late: u64,
}

/// Fixed-capacity pending-gap tracker for operational loss metrics.
#[derive(Clone, Eq, PartialEq)]
pub struct DelayedLossTracker {
    highest: Option<u64>,
    pending: [Option<u64>; REORDER_WINDOW_PACKETS],
    finalized_lost: u64,
    recovered_late: u64,
}

impl DelayedLossTracker {
    /// Creates empty loss observability state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: None,
            pending: [None; REORDER_WINDOW_PACKETS],
            finalized_lost: 0,
            recovered_late: 0,
        }
    }

    /// Observes one admitted RTP sequence number.
    pub fn observe(&mut self, sequence: u16) {
        let Some(highest) = self.highest else {
            self.highest = Some(u64::from(sequence));
            return;
        };
        let extended = extend_near(sequence, highest);
        if extended <= highest {
            if let Some(slot) = self
                .pending
                .iter_mut()
                .find(|slot| **slot == Some(extended))
            {
                *slot = None;
                self.recovered_late = self.recovered_late.saturating_add(1);
            }
            return;
        }

        let gap = extended - highest - 1;
        if gap > REORDER_WINDOW_PACKETS_U64 {
            self.finalized_lost = self
                .finalized_lost
                .saturating_add(gap - REORDER_WINDOW_PACKETS_U64);
        }
        let first_pending = extended.saturating_sub(gap.min(REORDER_WINDOW_PACKETS_U64));
        for missing in first_pending..extended {
            self.insert_pending(missing);
        }
        self.highest = Some(extended);
        self.finalize_old(extended);
    }

    /// Returns current bounded delayed-loss metrics.
    #[must_use]
    pub fn snapshot(&self) -> DelayedLossSnapshot {
        DelayedLossSnapshot {
            pending: u8::try_from(self.pending.iter().filter(|slot| slot.is_some()).count())
                .unwrap_or(u8::MAX),
            finalized_lost: self.finalized_lost,
            recovered_late: self.recovered_late,
        }
    }

    fn insert_pending(&mut self, sequence: u64) {
        if self.pending.contains(&Some(sequence)) {
            return;
        }
        if let Some(slot) = self.pending.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(sequence);
        } else {
            self.finalized_lost = self.finalized_lost.saturating_add(1);
            let oldest = self
                .pending
                .iter()
                .enumerate()
                .min_by_key(|(_, slot)| slot.unwrap_or(u64::MAX))
                .map_or(0, |(index, _)| index);
            self.pending[oldest] = Some(sequence);
        }
    }

    fn finalize_old(&mut self, highest: u64) {
        for slot in &mut self.pending {
            if slot.is_some_and(|missing| {
                highest.saturating_sub(missing) >= REORDER_WINDOW_PACKETS_U64
            })
            {
                *slot = None;
                self.finalized_lost = self.finalized_lost.saturating_add(1);
            }
        }
    }
}

impl Default for DelayedLossTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DelayedLossTracker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelayedLossTracker")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

fn extend_near(sequence: u16, highest: u64) -> u64 {
    let cycle = highest & !0xffff;
    let base = cycle | u64::from(sequence);
    let above = base.saturating_add(1 << 16);
    let below = base.checked_sub(1 << 16);
    [Some(base), Some(above), below]
        .into_iter()
        .flatten()
        .min_by_key(|candidate| candidate.abs_diff(highest))
        .unwrap_or(base)
}

#[cfg(test)]
mod tests {
    use super::DelayedLossTracker;

    #[test]
    fn late_packet_recovers_gap_before_window_finalizes_it() {
        let mut tracker = DelayedLossTracker::new();
        tracker.observe(10);
        tracker.observe(12);
        assert_eq!(tracker.snapshot().pending, 1);
        tracker.observe(11);
        assert_eq!(tracker.snapshot().pending, 0);
        assert_eq!(tracker.snapshot().recovered_late, 1);
        assert_eq!(tracker.snapshot().finalized_lost, 0);
    }

    #[test]
    fn old_gap_becomes_final_after_sixty_four_packets() {
        let mut tracker = DelayedLossTracker::new();
        tracker.observe(1);
        tracker.observe(3);
        for sequence in 4..=66 {
            tracker.observe(sequence);
        }
        assert_eq!(tracker.snapshot().pending, 0);
        assert_eq!(tracker.snapshot().finalized_lost, 1);
    }
}
