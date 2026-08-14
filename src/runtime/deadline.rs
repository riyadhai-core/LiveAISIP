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

//! Shared bounded monotonic deadline scheduler.

use std::collections::{BinaryHeap, HashSet};
use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

/// Hard ceiling for one runtime scheduler.
pub const MAX_DEADLINES: usize = 1_048_576;

/// Subsystem owning a scheduled deadline.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeadlineOwner {
    /// SIP transaction timer.
    Transaction,
    /// SIP dialog or session timer.
    Dialog,
    /// Call orchestration timer.
    Call,
    /// RTP, RTCP or DSP timer.
    Media,
    /// Signaling transport timer.
    Transport,
}

/// Unique cancellation handle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DeadlineId(u64);

impl DeadlineId {
    /// Returns the opaque scheduler sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Due deadline carrying owner generation and a low-cardinality event kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DueDeadline {
    id: DeadlineId,
    owner: DeadlineOwner,
    generation: u64,
    kind: u16,
    at: Duration,
}

impl DueDeadline {
    /// Returns cancellation identity.
    #[must_use]
    pub const fn id(self) -> DeadlineId {
        self.id
    }

    /// Returns owning subsystem.
    #[must_use]
    pub const fn owner(self) -> DeadlineOwner {
        self.owner
    }

    /// Returns the generation callers must validate against live state.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns caller-defined bounded event kind.
    #[must_use]
    pub const fn kind(self) -> u16 {
        self.kind
    }

    /// Returns absolute monotonic deadline.
    #[must_use]
    pub const fn at(self) -> Duration {
        self.at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry(DueDeadline);

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .0
            .at
            .cmp(&self.0.at)
            .then_with(|| other.0.id.0.cmp(&self.0.id.0))
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Actor-owned scheduler with bounded active occupancy.
pub struct DeadlineScheduler {
    maximum: usize,
    next_id: u64,
    heap: BinaryHeap<Entry>,
    active: HashSet<DeadlineId>,
}

impl DeadlineScheduler {
    /// Creates an empty scheduler.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive capacity.
    pub fn new(maximum: usize) -> Result<Self, DeadlineError> {
        if maximum == 0 || maximum > MAX_DEADLINES {
            return Err(DeadlineError::InvalidCapacity {
                value: maximum,
                maximum: MAX_DEADLINES,
            });
        }
        Ok(Self {
            maximum,
            next_id: 1,
            heap: BinaryHeap::new(),
            active: HashSet::new(),
        })
    }

    /// Schedules one absolute monotonic deadline.
    ///
    /// # Errors
    ///
    /// Rejects zero generations, capacity or identifier exhaustion, and
    /// allocation failure.
    pub fn schedule(
        &mut self,
        at: Duration,
        owner: DeadlineOwner,
        generation: u64,
        kind: u16,
    ) -> Result<DeadlineId, DeadlineError> {
        if generation == 0 {
            return Err(DeadlineError::ZeroGeneration);
        }
        if self.active.len() >= self.maximum {
            return Err(DeadlineError::Capacity {
                maximum: self.maximum,
            });
        }
        if self.heap.len() >= self.maximum {
            self.heap.retain(|entry| self.active.contains(&entry.0.id));
        }
        self.heap
            .try_reserve(1)
            .map_err(|_| DeadlineError::AllocationFailed)?;
        self.active
            .try_reserve(1)
            .map_err(|_| DeadlineError::AllocationFailed)?;
        let id = DeadlineId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(DeadlineError::IdExhausted)?;
        self.heap.push(Entry(DueDeadline {
            id,
            owner,
            generation,
            kind,
            at,
        }));
        self.active.insert(id);
        Ok(id)
    }

    /// Cancels one active deadline. Repeated cancellation is harmless.
    pub fn cancel(&mut self, id: DeadlineId) -> bool {
        self.active.remove(&id)
    }

    /// Returns the next active deadline at or before `now`.
    pub fn poll(&mut self, now: Duration) -> Option<DueDeadline> {
        loop {
            let entry = self.heap.peek()?;
            if entry.0.at > now {
                return None;
            }
            let entry = self.heap.pop()?.0;
            if self.active.remove(&entry.id) {
                return Some(entry);
            }
        }
    }

    /// Returns active deadline count, excluding canceled heap tombstones.
    #[must_use]
    pub fn len(&self) -> usize {
        self.active.len()
    }

    /// Returns whether no active deadline remains.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }
}

impl fmt::Debug for DeadlineScheduler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeadlineScheduler")
            .field("active", &self.active.len())
            .field("maximum", &self.maximum)
            .finish_non_exhaustive()
    }
}

/// Deadline scheduler failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlineError {
    /// Configured active deadline capacity was invalid.
    InvalidCapacity {
        /// Supplied capacity.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Active deadline capacity is exhausted.
    Capacity {
        /// Configured maximum.
        maximum: usize,
    },
    /// Owner generation zero is reserved as invalid.
    ZeroGeneration,
    /// Deadline ID space exhausted.
    IdExhausted,
    /// Bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for DeadlineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime deadline scheduling rejected")
    }
}

impl StdError for DeadlineError {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{DeadlineOwner, DeadlineScheduler};

    #[test]
    fn orders_deadlines_and_discards_canceled_entries() {
        let mut scheduler = DeadlineScheduler::new(4).unwrap_or_else(|_| panic!("scheduler"));
        let late = scheduler
            .schedule(Duration::from_secs(2), DeadlineOwner::Call, 7, 1)
            .unwrap_or_else(|_| panic!("late"));
        let early = scheduler
            .schedule(Duration::from_secs(1), DeadlineOwner::Transaction, 9, 2)
            .unwrap_or_else(|_| panic!("early"));
        assert!(scheduler.cancel(early));
        assert!(scheduler.poll(Duration::from_secs(1)).is_none());
        let due = scheduler
            .poll(Duration::from_secs(2))
            .unwrap_or_else(|| panic!("due"));
        assert_eq!(due.id(), late);
        assert_eq!(due.generation(), 7);
        assert!(scheduler.is_empty());
    }
}
