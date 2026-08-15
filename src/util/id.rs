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

//! Allocation-free opaque process-local identifiers.
//!
//! [`IdGenerator`] gives each successful allocation a distinct non-zero
//! 64-bit value. A randomized affine permutation prevents externally visible
//! identifiers and native thread names from directly revealing the allocation
//! sequence. The permutation is bijective over the supported counter space,
//! so randomization cannot introduce a collision.
//!
//! These identifiers provide identity and log-label privacy, not authority.
//! They must never be used as bearer credentials or cryptographic secrets.

use std::collections::hash_map::RandomState;
use std::error::Error as StdError;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

const OPAQUE_BIT: u64 = 1_u64 << 63;
const COUNTER_MASK: u64 = OPAQUE_BIT - 1;

/// One opaque identifier allocated within this process.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct OpaqueId(NonZeroU64);

impl OpaqueId {
    /// Returns the numeric representation used by internal generation tokens.
    #[must_use]
    pub(crate) const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Display for OpaqueId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:016x}", self.get())
    }
}

impl fmt::Debug for OpaqueId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueId([redacted])")
    }
}

/// Concurrent, allocation-free allocator for opaque process-local IDs.
///
/// The atomic counter establishes uniqueness. The per-generator permutation
/// only hides direct counter ordering; it is deliberately not a security
/// boundary. Relaxed ordering is sufficient because allocating an ID does not
/// publish any other memory.
pub(crate) struct IdGenerator {
    next: AtomicU64,
    multiplier: u64,
    offset: u64,
}

impl IdGenerator {
    /// Creates an independently randomized generator.
    #[must_use]
    pub(crate) fn new() -> Self {
        let entropy = RandomState::new();
        let multiplier = entropy_word(&entropy, 0x4c49_5645_4149_5349) | 1;
        let offset = entropy_word(&entropy, 0x5052_4f43_4553_5349) & COUNTER_MASK;
        Self::from_parts(1, multiplier, offset)
    }

    /// Allocates a unique opaque ID.
    ///
    /// # Errors
    ///
    /// Returns [`IdAllocationError::Exhausted`] after every supported counter
    /// value has been issued. Exhaustion is permanent and never wraps.
    pub(crate) fn allocate(&self) -> Result<OpaqueId, IdAllocationError> {
        let mut current = self.next.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return Err(IdAllocationError::Exhausted);
            }
            let successor = if current == COUNTER_MASK {
                0
            } else {
                current + 1
            };
            match self.next.compare_exchange_weak(
                current,
                successor,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let permuted = current
                        .wrapping_mul(self.multiplier)
                        .wrapping_add(self.offset)
                        & COUNTER_MASK;
                    let value = OPAQUE_BIT | permuted;
                    let Some(non_zero) = NonZeroU64::new(value) else {
                        unreachable!("the opaque marker bit is always set");
                    };
                    return Ok(OpaqueId(non_zero));
                }
                Err(observed) => current = observed,
            }
        }
    }

    const fn from_parts(next: u64, multiplier: u64, offset: u64) -> Self {
        Self {
            next: AtomicU64::new(next),
            multiplier: multiplier | 1,
            offset: offset & COUNTER_MASK,
        }
    }
}

impl Default for IdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for IdGenerator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdGenerator")
            .field("exhausted", &(self.next.load(Ordering::Relaxed) == 0))
            .finish_non_exhaustive()
    }
}

/// Permanent failure to allocate another process-local ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdAllocationError {
    /// The finite counter space was consumed without wrapping.
    Exhausted,
}

impl fmt::Display for IdAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("process-local identifier space is exhausted")
    }
}

impl StdError for IdAllocationError {}

fn entropy_word(state: &RandomState, domain: u64) -> u64 {
    let mut hasher = state.build_hasher();
    hasher.write_u64(domain);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use super::{COUNTER_MASK, IdAllocationError, IdGenerator};

    #[test]
    fn deterministic_permutation_is_unique_and_opaque() {
        let generator = IdGenerator::from_parts(1, 0x1357_9bdf, 0x2468_ace0);
        let mut values = HashSet::new();
        for _ in 0..100_000 {
            let id = generator
                .allocate()
                .unwrap_or_else(|_| panic!("identifier"));
            assert_ne!(id.get(), 0);
            assert!(id.get() & (1_u64 << 63) != 0);
            assert!(values.insert(id.get()));
        }
    }

    #[test]
    fn concurrent_allocations_do_not_collide() {
        let generator = Arc::new(IdGenerator::from_parts(1, 0x101, 0x202));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let generator = Arc::clone(&generator);
            workers.push(std::thread::spawn(move || {
                let mut values = Vec::with_capacity(10_000);
                for _ in 0..10_000 {
                    values.push(
                        generator
                            .allocate()
                            .unwrap_or_else(|_| panic!("identifier"))
                            .get(),
                    );
                }
                values
            }));
        }
        let mut observed = HashSet::new();
        for worker in workers {
            let values = worker.join().unwrap_or_else(|_| panic!("worker"));
            for value in values {
                assert!(observed.insert(value));
            }
        }
        assert_eq!(observed.len(), 80_000);
    }

    #[test]
    fn exhaustion_never_wraps() {
        let generator = IdGenerator::from_parts(COUNTER_MASK, 3, 7);
        assert!(generator.allocate().is_ok());
        assert_eq!(generator.allocate(), Err(IdAllocationError::Exhausted));
        assert_eq!(generator.allocate(), Err(IdAllocationError::Exhausted));
    }

    #[test]
    fn formatting_is_fixed_width_and_debug_is_redacted() {
        let generator = IdGenerator::from_parts(1, 1, 0);
        let id = generator
            .allocate()
            .unwrap_or_else(|_| panic!("identifier"));
        let display = id.to_string();
        assert_eq!(display.len(), 16);
        assert!(display.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(format!("{id:?}"), "OpaqueId([redacted])");
        assert!(!format!("{generator:?}").contains("multiplier"));
    }

    #[test]
    fn independent_permutations_change_the_sequence() {
        let first = IdGenerator::from_parts(1, 3, 5);
        let second = IdGenerator::from_parts(1, 7, 11);
        let first_id = first.allocate().unwrap_or_else(|_| panic!("identifier"));
        let second_id = second.allocate().unwrap_or_else(|_| panic!("identifier"));
        assert_ne!(first_id, second_id);
    }
}
