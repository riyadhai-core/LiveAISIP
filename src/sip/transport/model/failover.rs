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

//! Wire-commit-aware bounded SIP destination failover.

use std::error::Error as StdError;
use std::fmt;

use super::destination::Destination;

/// Hard upper bound for one RFC 3263 candidate plan.
pub const MAX_FAILOVER_CANDIDATES: usize = 64;

/// What is known about an outbound request reaching the network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireCommitState {
    /// Transport proves no request byte reached the wire.
    NotSent,
    /// The complete request was accepted by the transport.
    Sent,
    /// Partial write or ambiguous transport failure prevents certainty.
    Unknown,
}

/// One retired candidate that can still produce a late response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedAttempt {
    candidate_index: usize,
    generation: u64,
    commitment: WireCommitState,
}

impl RetainedAttempt {
    /// Returns candidate position in the immutable resolver result.
    #[must_use]
    pub const fn candidate_index(self) -> usize {
        self.candidate_index
    }

    /// Returns monotonic attempt generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns why late-response handling remains necessary.
    #[must_use]
    pub const fn commitment(self) -> WireCommitState {
        self.commitment
    }
}

/// Result of advancing to another resolved destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailoverDisposition {
    /// Retry is safe because the previous candidate provably received no bytes.
    SafeRetry,
    /// Retry is allowed but prior candidate state must remain for fork cleanup.
    RetryWithLateResponseRetention(RetainedAttempt),
    /// Candidate list is exhausted.
    Exhausted,
}

/// Bounded deterministic outbound candidate state.
pub struct FailoverPlan {
    candidates: Vec<Destination>,
    current: usize,
    generation: u64,
    commitment: WireCommitState,
    retained: Vec<RetainedAttempt>,
}

impl FailoverPlan {
    /// Creates a plan from resolver-ordered candidates.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessive candidate lists.
    pub fn new(candidates: Vec<Destination>) -> Result<Self, FailoverError> {
        if candidates.is_empty() {
            return Err(FailoverError::Empty);
        }
        if candidates.len() > MAX_FAILOVER_CANDIDATES {
            return Err(FailoverError::TooManyCandidates {
                maximum: MAX_FAILOVER_CANDIDATES,
            });
        }
        Ok(Self {
            candidates,
            current: 0,
            generation: 1,
            commitment: WireCommitState::NotSent,
            retained: Vec::new(),
        })
    }

    /// Returns the current concrete destination.
    #[must_use]
    pub fn current(&self) -> &Destination {
        &self.candidates[self.current]
    }

    /// Returns current attempt generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Records transport-authoritative wire commitment.
    pub const fn record_commitment(&mut self, state: WireCommitState) {
        self.commitment = state;
    }

    /// Advances to the next candidate while retaining ambiguous/sent attempts.
    ///
    /// # Errors
    ///
    /// Rejects generation exhaustion or retained-attempt allocation failure.
    pub fn advance(&mut self) -> Result<FailoverDisposition, FailoverError> {
        if self.current + 1 >= self.candidates.len() {
            return Ok(FailoverDisposition::Exhausted);
        }
        let disposition = if self.commitment == WireCommitState::NotSent {
            FailoverDisposition::SafeRetry
        } else {
            self.retained
                .try_reserve(1)
                .map_err(|_| FailoverError::AllocationFailed)?;
            let retained = RetainedAttempt {
                candidate_index: self.current,
                generation: self.generation,
                commitment: self.commitment,
            };
            self.retained.push(retained);
            FailoverDisposition::RetryWithLateResponseRetention(retained)
        };
        self.current += 1;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(FailoverError::GenerationExhausted)?;
        self.commitment = WireCommitState::NotSent;
        Ok(disposition)
    }

    /// Returns compact attempts that may still answer after failover.
    #[must_use]
    pub fn retained(&self) -> &[RetainedAttempt] {
        &self.retained
    }
}

impl fmt::Debug for FailoverPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailoverPlan")
            .field("candidate_count", &self.candidates.len())
            .field("current_index", &self.current)
            .field("generation", &self.generation)
            .field("commitment", &self.commitment)
            .field("retained_count", &self.retained.len())
            .finish_non_exhaustive()
    }
}

/// Invalid failover-plan operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailoverError {
    /// Resolver produced no usable destination.
    Empty,
    /// Resolver output exceeded the bounded plan.
    TooManyCandidates {
        /// Hard candidate count limit.
        maximum: usize,
    },
    /// Attempt generation exhausted.
    GenerationExhausted,
    /// Compact retention allocation failed.
    AllocationFailed,
}

impl fmt::Display for FailoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP destination failover rejected")
    }
}

impl StdError for FailoverError {}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{FailoverDisposition, FailoverPlan, WireCommitState};
    use crate::sip::transport::destination::Destination;

    fn destination(port: u16) -> Destination {
        Destination::udp(SocketAddr::from(([192, 0, 2, 1], port)))
            .unwrap_or_else(|_| panic!("destination"))
    }

    #[test]
    fn zero_wire_failure_retries_without_retention() {
        let mut plan = FailoverPlan::new(vec![destination(5060), destination(5061)])
            .unwrap_or_else(|_| panic!("plan"));
        assert_eq!(plan.advance(), Ok(FailoverDisposition::SafeRetry));
        assert!(plan.retained().is_empty());
    }

    #[test]
    fn possible_wire_delivery_retains_late_response_authority() {
        let mut plan = FailoverPlan::new(vec![destination(5060), destination(5061)])
            .unwrap_or_else(|_| panic!("plan"));
        plan.record_commitment(WireCommitState::Unknown);
        let Ok(FailoverDisposition::RetryWithLateResponseRetention(retained)) = plan.advance()
        else {
            panic!("retained retry")
        };
        assert_eq!(retained.candidate_index(), 0);
        assert_eq!(retained.generation(), 1);
        assert_eq!(retained.commitment(), WireCommitState::Unknown);
        assert_eq!(plan.generation(), 2);
    }
}
