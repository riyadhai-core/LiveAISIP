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

//! Fixed-capacity queues with realtime diagnostics.

use std::collections::VecDeque;
use std::error::Error as StdError;
use std::fmt;

/// Hard protection against accidentally allocating an unbounded per-call queue.
pub const MAX_REALTIME_QUEUE_CAPACITY: usize = 65_536;

/// Full-queue behavior selected for one data path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverflowPolicy {
    /// Preserve queued work and reject the new item.
    DropNewest,
    /// Preserve low latency by evicting the oldest queued item.
    DropOldest,
}

/// Stable queue telemetry snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueDiagnostics {
    /// Configured item capacity.
    pub capacity: usize,
    /// Current queued item count.
    pub depth: usize,
    /// Maximum observed depth.
    pub high_water_mark: usize,
    /// Successfully accepted pushes.
    pub accepted: u64,
    /// Successfully returned pops.
    pub delivered: u64,
    /// Pushes attempted while full.
    pub overflows: u64,
    /// Items discarded by overflow policy.
    pub drops: u64,
    /// Pops attempted while empty.
    pub underflows: u64,
}

/// Result of one bounded push, retaining ownership of any dropped item.
#[derive(Debug, Eq, PartialEq)]
pub enum PushOutcome<T> {
    /// New item was admitted without loss.
    Accepted,
    /// New item was rejected.
    DroppedNewest(T),
    /// Old item was evicted and returned to the caller.
    DroppedOldest(T),
}

/// A preallocated, fixed-capacity, nonblocking queue.
pub struct BoundedQueue<T> {
    items: VecDeque<T>,
    capacity: usize,
    policy: OverflowPolicy,
    high_water_mark: usize,
    accepted: u64,
    delivered: u64,
    overflows: u64,
    drops: u64,
    underflows: u64,
}

impl<T> BoundedQueue<T> {
    /// Allocates storage for the complete fixed capacity.
    ///
    /// # Errors
    ///
    /// Rejects zero, excessive capacity, or allocation failure.
    pub fn new(capacity: usize, policy: OverflowPolicy) -> Result<Self, QueueError> {
        if capacity == 0 || capacity > MAX_REALTIME_QUEUE_CAPACITY {
            return Err(QueueError::InvalidCapacity {
                value: capacity,
                maximum: MAX_REALTIME_QUEUE_CAPACITY,
            });
        }
        let mut items = VecDeque::new();
        items
            .try_reserve_exact(capacity)
            .map_err(|_| QueueError::AllocationFailed)?;
        Ok(Self {
            items,
            capacity,
            policy,
            high_water_mark: 0,
            accepted: 0,
            delivered: 0,
            overflows: 0,
            drops: 0,
            underflows: 0,
        })
    }

    /// Pushes without growing beyond configured capacity.
    pub fn push(&mut self, item: T) -> PushOutcome<T> {
        if self.items.len() == self.capacity {
            self.overflows = self.overflows.saturating_add(1);
            self.drops = self.drops.saturating_add(1);
            return match self.policy {
                OverflowPolicy::DropNewest => PushOutcome::DroppedNewest(item),
                OverflowPolicy::DropOldest => {
                    let Some(dropped) = self.items.pop_front() else {
                        return PushOutcome::DroppedNewest(item);
                    };
                    self.items.push_back(item);
                    self.accepted = self.accepted.saturating_add(1);
                    PushOutcome::DroppedOldest(dropped)
                }
            };
        }
        self.items.push_back(item);
        self.accepted = self.accepted.saturating_add(1);
        self.high_water_mark = self.high_water_mark.max(self.items.len());
        PushOutcome::Accepted
    }

    /// Pops one item and accounts empty reads as underflow.
    pub fn pop(&mut self) -> Option<T> {
        let item = self.items.pop_front();
        if item.is_some() {
            self.delivered = self.delivered.saturating_add(1);
        } else {
            self.underflows = self.underflows.saturating_add(1);
        }
        item
    }

    /// Clears pending items without resetting lifetime diagnostics.
    pub fn clear(&mut self) -> usize {
        let removed = self.items.len();
        self.items.clear();
        self.drops = self
            .drops
            .saturating_add(u64::try_from(removed).unwrap_or(u64::MAX));
        removed
    }

    /// Returns current telemetry.
    #[must_use]
    pub fn diagnostics(&self) -> QueueDiagnostics {
        QueueDiagnostics {
            capacity: self.capacity,
            depth: self.items.len(),
            high_water_mark: self.high_water_mark,
            accepted: self.accepted,
            delivered: self.delivered,
            overflows: self.overflows,
            drops: self.drops,
            underflows: self.underflows,
        }
    }
}

impl<T> fmt::Debug for BoundedQueue<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedQueue")
            .field("policy", &self.policy)
            .field("diagnostics", &self.diagnostics())
            .finish_non_exhaustive()
    }
}

/// Queue configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    /// Capacity was zero or beyond the per-call maximum.
    InvalidCapacity {
        /// Rejected capacity.
        value: usize,
        /// Hard per-call maximum.
        maximum: usize,
    },
    /// Fixed storage could not be reserved.
    AllocationFailed,
}

impl fmt::Display for QueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded realtime queue configuration failed")
    }
}

impl StdError for QueueError {}

#[cfg(test)]
mod tests {
    use super::{BoundedQueue, OverflowPolicy, PushOutcome, QueueError};

    #[test]
    fn drop_newest_is_bounded_and_diagnostic() {
        let Ok(mut queue) = BoundedQueue::new(2, OverflowPolicy::DropNewest) else {
            panic!("queue")
        };
        assert_eq!(queue.push(1), PushOutcome::Accepted);
        assert_eq!(queue.push(2), PushOutcome::Accepted);
        assert_eq!(queue.push(3), PushOutcome::DroppedNewest(3));
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), None);
        let stats = queue.diagnostics();
        assert_eq!(stats.high_water_mark, 2);
        assert_eq!(stats.overflows, 1);
        assert_eq!(stats.drops, 1);
        assert_eq!(stats.underflows, 1);
    }

    #[test]
    fn drop_oldest_preserves_low_latency() {
        let Ok(mut queue) = BoundedQueue::new(2, OverflowPolicy::DropOldest) else {
            panic!("queue")
        };
        assert_eq!(queue.push(1), PushOutcome::Accepted);
        assert_eq!(queue.push(2), PushOutcome::Accepted);
        assert_eq!(queue.push(3), PushOutcome::DroppedOldest(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
    }

    #[test]
    fn validates_capacity_and_accounts_clear() {
        assert!(matches!(
            BoundedQueue::<u8>::new(0, OverflowPolicy::DropNewest),
            Err(QueueError::InvalidCapacity { .. })
        ));
        let Ok(mut queue) = BoundedQueue::new(4, OverflowPolicy::DropNewest) else {
            panic!("queue")
        };
        assert_eq!(queue.push(1), PushOutcome::Accepted);
        assert_eq!(queue.push(2), PushOutcome::Accepted);
        assert_eq!(queue.clear(), 2);
        assert_eq!(queue.diagnostics().drops, 2);
    }
}
