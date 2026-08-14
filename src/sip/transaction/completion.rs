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

//! Compact completed-INVITE authority for late and retransmitted responses.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::key::{KeyError, TransactionKey};
use crate::sip::validation::response::ValidatedResponse;

/// Hard maximum retained completed INVITE identities.
pub const MAX_COMPLETION_TOMBSTONES: usize = 262_144;

/// Action for a response matching compact completed state.
#[derive(Clone, Debug)]
pub enum CompletionDisposition {
    /// A 2xx must reach call/dialog logic for ACK and fork policy.
    DeliverLateSuccess {
        /// Original transaction generation used to fence stale call state.
        generation: u64,
    },
    /// A retransmitted non-2xx receives the exact cached ACK only.
    ResendFailureAck {
        /// Original transaction generation used to fence stale call state.
        generation: u64,
        /// Exact immutable ACK bytes retained from the completed transaction.
        ack: Arc<[u8]>,
    },
    /// The response is matched but needs no further work.
    Absorb {
        /// Original transaction generation used to fence stale call state.
        generation: u64,
    },
}

struct Tombstone {
    generation: u64,
    expires_at: Duration,
    failure_ack: Option<Arc<[u8]>>,
}

/// Actor-owned bounded completion store.
pub struct CompletionStore {
    maximum: usize,
    entries: HashMap<TransactionKey, Tombstone>,
}

impl CompletionStore {
    /// Creates an empty bounded store.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive capacity.
    pub fn new(maximum: usize) -> Result<Self, CompletionError> {
        if maximum == 0 || maximum > MAX_COMPLETION_TOMBSTONES {
            return Err(CompletionError::InvalidCapacity {
                value: maximum,
                maximum: MAX_COMPLETION_TOMBSTONES,
            });
        }
        Ok(Self {
            maximum,
            entries: HashMap::new(),
        })
    }

    /// Retains compact exact-result authority after heavy transaction removal.
    ///
    /// # Errors
    ///
    /// Rejects zero generations, capacity exhaustion, and allocation failure.
    pub fn retain(
        &mut self,
        key: TransactionKey,
        generation: u64,
        expires_at: Duration,
        failure_ack: Option<Arc<[u8]>>,
    ) -> Result<(), CompletionError> {
        if generation == 0 {
            return Err(CompletionError::ZeroGeneration);
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= self.maximum {
            return Err(CompletionError::Capacity {
                maximum: self.maximum,
            });
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| CompletionError::AllocationFailed)?;
        self.entries.insert(
            key,
            Tombstone {
                generation,
                expires_at,
                failure_ack,
            },
        );
        Ok(())
    }

    /// Routes a response without resurrecting the heavy transaction object.
    ///
    /// # Errors
    ///
    /// Rejects responses whose transaction identity cannot be derived.
    pub fn route(
        &mut self,
        response: &ValidatedResponse,
        now: Duration,
    ) -> Result<Option<CompletionDisposition>, CompletionError> {
        let key = TransactionKey::for_client_response(response).map_err(CompletionError::Key)?;
        if self
            .entries
            .get(&key)
            .is_some_and(|entry| now >= entry.expires_at)
        {
            self.entries.remove(&key);
            return Ok(None);
        }
        let Some(entry) = self.entries.get(&key) else {
            return Ok(None);
        };
        let code = response.response_line().status().as_u16();
        let disposition = match code {
            200..=299 => CompletionDisposition::DeliverLateSuccess {
                generation: entry.generation,
            },
            300..=699 => match &entry.failure_ack {
                Some(ack) => CompletionDisposition::ResendFailureAck {
                    generation: entry.generation,
                    ack: Arc::clone(ack),
                },
                None => CompletionDisposition::Absorb {
                    generation: entry.generation,
                },
            },
            _ => CompletionDisposition::Absorb {
                generation: entry.generation,
            },
        };
        Ok(Some(disposition))
    }

    /// Removes expired entries and returns the count reclaimed.
    pub fn sweep(&mut self, now: Duration) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.expires_at > now);
        before - self.entries.len()
    }

    /// Returns retained compact entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no completion state remains.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Debug for CompletionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionStore")
            .field("entries", &self.entries.len())
            .field("maximum", &self.maximum)
            .finish_non_exhaustive()
    }
}

/// Compact completion state failure.
#[derive(Debug)]
pub enum CompletionError {
    /// Configured tombstone capacity was invalid.
    InvalidCapacity {
        /// Supplied capacity.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Store reached configured capacity.
    Capacity {
        /// Configured maximum.
        maximum: usize,
    },
    /// Generation zero is reserved as invalid.
    ZeroGeneration,
    /// Response lacked a modern transaction key.
    Key(KeyError),
    /// Bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for CompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP transaction completion retention rejected")
    }
}

impl StdError for CompletionError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Key(error) => Some(error),
            _ => None,
        }
    }
}
