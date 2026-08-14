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

//! Bounded RTP/RTCP UDP port-pair allocation.
//!
//! RTP uses an even port and RTCP its immediately following odd port. A compact
//! bitmap provides fixed memory proportional to configured capacity. The
//! thread-safe pool returns move-only leases that release automatically on
//! every normal, error, cancellation, and panic unwind path.

use std::error::Error as StdError;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

const BITS_PER_WORD: usize = u64::BITS as usize;

/// One conventional RTP and RTCP UDP port pair.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PortPair {
    rtp: u16,
    rtcp: u16,
}

impl PortPair {
    /// Constructs a conventional even/odd pair.
    ///
    /// # Errors
    ///
    /// Rejects reserved port zero and odd RTP ports.
    pub const fn new(rtp: u16) -> Result<Self, PortAllocationError> {
        if rtp == 0 {
            return Err(PortAllocationError::RtpPortZero);
        }
        if !rtp.is_multiple_of(2) {
            return Err(PortAllocationError::RtpPortMustBeEven { port: rtp });
        }
        if rtp == u16::MAX - 1 {
            return Ok(Self {
                rtp,
                rtcp: u16::MAX,
            });
        }
        Ok(Self { rtp, rtcp: rtp + 1 })
    }

    /// Returns even RTP port.
    #[must_use]
    pub const fn rtp(self) -> u16 {
        self.rtp
    }

    /// Returns following odd RTCP port.
    #[must_use]
    pub const fn rtcp(self) -> u16 {
        self.rtcp
    }
}

/// Deterministic, non-thread-safe port-pair allocator.
#[derive(Clone, Eq, PartialEq)]
pub struct PortAllocator {
    first_rtp: u16,
    last_rtp: u16,
    allocated: Vec<u64>,
    capacity: usize,
    in_use: usize,
    cursor: usize,
}

impl PortAllocator {
    /// Creates an inclusive even RTP-port range.
    ///
    /// # Errors
    ///
    /// Rejects reversed ranges, odd endpoints, ranges ending beyond 65534, and
    /// bitmap allocation failure.
    pub fn new(first_rtp: u16, last_rtp: u16) -> Result<Self, PortAllocationError> {
        if first_rtp > last_rtp {
            return Err(PortAllocationError::RangeReversed {
                first: first_rtp,
                last: last_rtp,
            });
        }
        if first_rtp == 0 {
            return Err(PortAllocationError::RtpPortZero);
        }
        if !first_rtp.is_multiple_of(2) {
            return Err(PortAllocationError::RtpPortMustBeEven { port: first_rtp });
        }
        if !last_rtp.is_multiple_of(2) {
            return Err(PortAllocationError::RtpPortMustBeEven { port: last_rtp });
        }
        let capacity = usize::from((last_rtp - first_rtp) / 2) + 1;
        let words = capacity.div_ceil(BITS_PER_WORD);
        let mut allocated = Vec::new();
        allocated
            .try_reserve_exact(words)
            .map_err(|_| PortAllocationError::AllocationFailed)?;
        allocated.resize(words, 0);
        Ok(Self {
            first_rtp,
            last_rtp,
            allocated,
            capacity,
            in_use: 0,
            cursor: 0,
        })
    }

    /// Reserves the next available pair in round-robin order.
    #[must_use]
    pub fn allocate(&mut self) -> Option<PortPair> {
        if self.in_use == self.capacity {
            return None;
        }
        for distance in 0..self.capacity {
            let index = (self.cursor + distance) % self.capacity;
            if !self.bit(index) {
                self.set_bit(index, true);
                self.in_use += 1;
                self.cursor = (index + 1) % self.capacity;
                return self.pair_at(index);
            }
        }
        None
    }

    /// Reserves a specific configured pair.
    ///
    /// # Errors
    ///
    /// Rejects pairs outside the range or already allocated.
    pub fn reserve(&mut self, pair: PortPair) -> Result<(), PortAllocationError> {
        let index = self.index_of(pair)?;
        if self.bit(index) {
            return Err(PortAllocationError::AlreadyAllocated { pair });
        }
        self.set_bit(index, true);
        self.in_use += 1;
        Ok(())
    }

    /// Releases a currently allocated pair.
    ///
    /// # Errors
    ///
    /// Rejects pairs outside the range and double release.
    pub fn release(&mut self, pair: PortPair) -> Result<(), PortAllocationError> {
        let index = self.index_of(pair)?;
        if !self.bit(index) {
            return Err(PortAllocationError::NotAllocated { pair });
        }
        self.set_bit(index, false);
        self.in_use -= 1;
        Ok(())
    }

    /// Returns total configured pair capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns allocated pair count.
    #[must_use]
    pub const fn in_use(&self) -> usize {
        self.in_use
    }

    /// Returns currently available pair count.
    #[must_use]
    pub const fn available(&self) -> usize {
        self.capacity - self.in_use
    }

    fn index_of(&self, pair: PortPair) -> Result<usize, PortAllocationError> {
        if pair.rtp < self.first_rtp || pair.rtp > self.last_rtp || pair.rtcp != pair.rtp + 1 {
            return Err(PortAllocationError::OutsideRange { pair });
        }
        Ok(usize::from((pair.rtp - self.first_rtp) / 2))
    }

    fn pair_at(&self, index: usize) -> Option<PortPair> {
        let offset = u16::try_from(index.checked_mul(2)?).ok()?;
        let rtp = self.first_rtp.checked_add(offset)?;
        PortPair::new(rtp).ok()
    }

    fn bit(&self, index: usize) -> bool {
        let word = index / BITS_PER_WORD;
        let bit = index % BITS_PER_WORD;
        self.allocated[word] & (1_u64 << bit) != 0
    }

    fn set_bit(&mut self, index: usize, value: bool) {
        let word = index / BITS_PER_WORD;
        let mask = 1_u64 << (index % BITS_PER_WORD);
        if value {
            self.allocated[word] |= mask;
        } else {
            self.allocated[word] &= !mask;
        }
    }
}

impl fmt::Debug for PortAllocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortAllocator")
            .field("first_rtp", &self.first_rtp)
            .field("last_rtp", &self.last_rtp)
            .field("capacity", &self.capacity)
            .field("in_use", &self.in_use)
            .finish_non_exhaustive()
    }
}

/// Thread-safe allocator returning automatic lifetime leases.
#[derive(Clone, Debug)]
pub struct PortPool {
    inner: Arc<Mutex<PortAllocator>>,
}

impl PortPool {
    /// Creates a shared pool over an inclusive even RTP range.
    ///
    /// # Errors
    ///
    /// Delegates range and allocation validation.
    pub fn new(first_rtp: u16, last_rtp: u16) -> Result<Self, PortAllocationError> {
        Ok(Self {
            inner: Arc::new(Mutex::new(PortAllocator::new(first_rtp, last_rtp)?)),
        })
    }

    /// Allocates one move-only lease, or `None` when exhausted.
    #[must_use]
    pub fn allocate(&self) -> Option<PortLease> {
        let pair = recover_lock(&self.inner).allocate()?;
        Some(PortLease {
            pair,
            pool: Arc::clone(&self.inner),
            armed: true,
        })
    }

    /// Returns configured capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        recover_lock(&self.inner).capacity()
    }

    /// Returns allocated lease count.
    #[must_use]
    pub fn in_use(&self) -> usize {
        recover_lock(&self.inner).in_use()
    }
}

/// Move-only port reservation released automatically on drop.
pub struct PortLease {
    pair: PortPair,
    pool: Arc<Mutex<PortAllocator>>,
    armed: bool,
}

impl PortLease {
    /// Returns reserved pair.
    #[must_use]
    pub const fn pair(&self) -> PortPair {
        self.pair
    }

    /// Releases immediately instead of waiting for drop.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.armed {
            let _ = recover_lock(&self.pool).release(self.pair);
            self.armed = false;
        }
    }
}

impl Drop for PortLease {
    fn drop(&mut self) {
        self.release_inner();
    }
}

impl fmt::Debug for PortLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortLease")
            .field("pair", &self.pair)
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}

fn recover_lock(value: &Arc<Mutex<PortAllocator>>) -> MutexGuard<'_, PortAllocator> {
    match value.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Port-pair configuration or lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortAllocationError {
    /// RTP port zero is reserved and requests ephemeral OS allocation.
    RtpPortZero,
    /// RTP port was odd.
    RtpPortMustBeEven {
        /// Supplied RTP port.
        port: u16,
    },
    /// First range endpoint exceeded last.
    RangeReversed {
        /// First inclusive RTP port.
        first: u16,
        /// Last inclusive RTP port.
        last: u16,
    },
    /// Pair is outside configured range.
    OutsideRange {
        /// Supplied pair.
        pair: PortPair,
    },
    /// Pair is already reserved.
    AlreadyAllocated {
        /// Conflicting pair.
        pair: PortPair,
    },
    /// Pair was released without a reservation.
    NotAllocated {
        /// Unreserved pair.
        pair: PortPair,
    },
    /// Bitmap allocation failed.
    AllocationFailed,
}

impl fmt::Display for PortAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RtpPortZero => formatter.write_str("RTP port zero is reserved"),
            Self::RtpPortMustBeEven { port } => write!(formatter, "RTP port {port} is not even"),
            Self::RangeReversed { first, last } => {
                write!(formatter, "RTP port range {first}..={last} is reversed")
            }
            Self::OutsideRange { pair } => write!(formatter, "port pair {pair:?} is outside range"),
            Self::AlreadyAllocated { pair } => write!(formatter, "port pair {pair:?} is allocated"),
            Self::NotAllocated { pair } => write!(formatter, "port pair {pair:?} is not allocated"),
            Self::AllocationFailed => formatter.write_str("port allocator allocation failed"),
        }
    }
}

impl StdError for PortAllocationError {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::{PortAllocationError, PortAllocator, PortPair, PortPool};

    #[test]
    fn allocates_exhausts_and_reuses_round_robin() {
        let mut allocator =
            PortAllocator::new(10_000, 10_004).unwrap_or_else(|_| panic!("allocator"));
        let first = allocator.allocate().unwrap_or_else(|| panic!("first"));
        let second = allocator.allocate().unwrap_or_else(|| panic!("second"));
        let third = allocator.allocate().unwrap_or_else(|| panic!("third"));
        assert_eq!((first.rtp(), first.rtcp()), (10_000, 10_001));
        assert_eq!(second.rtp(), 10_002);
        assert_eq!(third.rtp(), 10_004);
        assert_eq!(allocator.allocate(), None);
        allocator
            .release(second)
            .unwrap_or_else(|_| panic!("release"));
        assert_eq!(allocator.allocate(), Some(second));
    }

    #[test]
    fn rejects_double_reservation_release_and_outside_pair() {
        let mut allocator =
            PortAllocator::new(20_000, 20_000).unwrap_or_else(|_| panic!("allocator"));
        let pair = PortPair::new(20_000).unwrap_or_else(|_| panic!("pair"));
        allocator
            .reserve(pair)
            .unwrap_or_else(|_| panic!("reserve"));
        assert_eq!(
            allocator.reserve(pair),
            Err(PortAllocationError::AlreadyAllocated { pair })
        );
        allocator
            .release(pair)
            .unwrap_or_else(|_| panic!("release"));
        assert_eq!(
            allocator.release(pair),
            Err(PortAllocationError::NotAllocated { pair })
        );
        let outside = PortPair::new(20_002).unwrap_or_else(|_| panic!("pair"));
        assert_eq!(
            allocator.reserve(outside),
            Err(PortAllocationError::OutsideRange { pair: outside })
        );
    }

    #[test]
    fn validates_range_shape() {
        assert_eq!(PortPair::new(0), Err(PortAllocationError::RtpPortZero));
        assert_eq!(
            PortAllocator::new(0, 10),
            Err(PortAllocationError::RtpPortZero)
        );
        assert_eq!(
            PortAllocator::new(10, 8),
            Err(PortAllocationError::RangeReversed { first: 10, last: 8 })
        );
        assert_eq!(
            PortAllocator::new(9, 10),
            Err(PortAllocationError::RtpPortMustBeEven { port: 9 })
        );
        assert_eq!(
            PortAllocator::new(8, 9),
            Err(PortAllocationError::RtpPortMustBeEven { port: 9 })
        );
    }

    #[test]
    fn lease_drop_and_explicit_release_return_capacity() {
        let pool = PortPool::new(30_000, 30_000).unwrap_or_else(|_| panic!("pool"));
        {
            let lease = pool.allocate().unwrap_or_else(|| panic!("lease"));
            assert_eq!(pool.in_use(), 1);
            assert!(pool.allocate().is_none());
            lease.release();
        }
        assert_eq!(pool.in_use(), 0);
        let lease = pool.allocate().unwrap_or_else(|| panic!("lease"));
        drop(lease);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn shared_pool_never_duplicates_concurrent_leases() {
        let pool = Arc::new(PortPool::new(40_000, 40_006).unwrap_or_else(|_| panic!("pool")));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let pool = Arc::clone(&pool);
            handles.push(thread::spawn(move || pool.allocate()));
        }
        let mut pairs = Vec::new();
        let mut leases = Vec::new();
        for handle in handles {
            if let Some(lease) = handle.join().unwrap_or_else(|_| panic!("thread")) {
                pairs.push(lease.pair());
                leases.push(lease);
            }
        }
        pairs.sort_by_key(|pair| pair.rtp());
        pairs.dedup();
        assert_eq!(pairs.len(), 4);
        drop(leases);
        assert_eq!(pool.in_use(), 0);
    }
}
