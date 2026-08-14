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

//! Reliable provisional response and PRACK correlation state.

use crate::sip::types::method::Method;
use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// PRACK work for one reliable provisional response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrackDisposition {
    /// New response requires `PRACK` with this `RAck` tuple.
    SendPrack {
        /// Reliable provisional response sequence number.
        rseq: u32,
        /// Sequence number of the request being acknowledged.
        cseq: u32,
        /// Method of the request being acknowledged.
        method: Method,
    },
    /// Retransmission requires replaying the same `PRACK`.
    ReplayPrack {
        /// Reliable provisional response sequence number.
        rseq: u32,
        /// Sequence number of the request being acknowledged.
        cseq: u32,
        /// Method of the request being acknowledged.
        method: Method,
    },
}

/// UAC-side reliable-provisional ordering.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrackTracker {
    last: Option<(u32, u32, Method)>,
}
impl PrackTracker {
    /// Creates empty state.
    #[must_use]
    pub const fn new() -> Self {
        Self { last: None }
    }
    /// Observes `RSeq` and original `CSeq` tuple.
    ///
    /// # Errors
    ///
    /// Rejects zero, regressed `RSeq`, or conflicting retransmission.
    pub fn observe(
        &mut self,
        rseq: u32,
        cseq: u32,
        method: Method,
    ) -> Result<PrackDisposition, ReliableError> {
        if rseq == 0 || cseq == 0 {
            return Err(ReliableError::ZeroSequence);
        }
        if let Some((previous, previous_cseq, previous_method)) = &self.last {
            if rseq < *previous {
                return Err(ReliableError::OutOfOrder);
            }
            if rseq == *previous {
                if cseq != *previous_cseq || &method != previous_method {
                    return Err(ReliableError::ConflictingRetransmission);
                }
                return Ok(PrackDisposition::ReplayPrack { rseq, cseq, method });
            }
        }
        self.last = Some((rseq, cseq, method.clone()));
        Ok(PrackDisposition::SendPrack { rseq, cseq, method })
    }
}

/// Reliable provisional sequencing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReliableError {
    /// `RSeq` or `CSeq` was zero.
    ZeroSequence,
    /// `RSeq` regressed.
    OutOfOrder,
    /// Same `RSeq` carried different correlation.
    ConflictingRetransmission,
}
impl fmt::Display for ReliableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("reliable provisional response rejected")
    }
}
impl StdError for ReliableError {}

/// Exact identity carried by one `RAck` value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RackIdentity {
    rseq: u32,
    cseq: u32,
    method: Method,
}

impl RackIdentity {
    /// Creates a complete reliable-provisional acknowledgement identity.
    ///
    /// # Errors
    ///
    /// Rejects a zero reliable provisional sequence.
    pub fn new(rseq: u32, cseq: u32, method: Method) -> Result<Self, ReliableError> {
        if rseq == 0 {
            return Err(ReliableError::ZeroSequence);
        }
        Ok(Self { rseq, cseq, method })
    }

    /// Returns reliable provisional sequence.
    #[must_use]
    pub const fn rseq(&self) -> u32 {
        self.rseq
    }

    /// Returns original request `CSeq`.
    #[must_use]
    pub const fn cseq(&self) -> u32 {
        self.cseq
    }

    /// Returns original request method.
    #[must_use]
    pub const fn method(&self) -> &Method {
        &self.method
    }
}

/// Side effects emitted by reliable provisional server state.
#[derive(Clone, Debug)]
pub enum ReliableServerAction {
    /// Transmit or retransmit immutable provisional response bytes.
    Send(Arc<[u8]>),
    /// Schedule a generation-fenced retransmission.
    Schedule {
        /// Generation that must still own the pending response when fired.
        generation: u64,
        /// Delay before the retransmission becomes due.
        after: Duration,
    },
    /// Cancel the current retransmission generation.
    Cancel {
        /// Generation whose scheduled retransmission must be cancelled.
        generation: u64,
    },
}

/// Deterministic RFC 3262 retransmission and final-response fence.
pub struct ReliableProvisionalServer {
    pending: Option<PendingReliable>,
    next_generation: u64,
    initial_interval: Duration,
    maximum_interval: Duration,
}

struct PendingReliable {
    identity: RackIdentity,
    bytes: Arc<[u8]>,
    generation: u64,
    next_interval: Duration,
}

impl ReliableProvisionalServer {
    /// Creates state from validated T1/T2-style retransmission bounds.
    ///
    /// # Errors
    ///
    /// Rejects zero, inverted, or otherwise invalid retransmission intervals.
    pub fn new(
        initial_interval: Duration,
        maximum_interval: Duration,
    ) -> Result<Self, ReliableServerError> {
        if initial_interval.is_zero() || maximum_interval < initial_interval {
            return Err(ReliableServerError::InvalidTimerProfile);
        }
        Ok(Self {
            pending: None,
            next_generation: 1,
            initial_interval,
            maximum_interval,
        })
    }

    /// Starts one reliable provisional response.
    ///
    /// A second response cannot replace unacknowledged state. This prevents an
    /// old retransmission from racing a newer provisional or final response.
    ///
    /// # Errors
    ///
    /// Rejects empty bytes, an already pending response, or generation
    /// exhaustion.
    pub fn start(
        &mut self,
        identity: RackIdentity,
        bytes: Arc<[u8]>,
    ) -> Result<Vec<ReliableServerAction>, ReliableServerError> {
        if self.pending.is_some() {
            return Err(ReliableServerError::AlreadyPending);
        }
        if bytes.is_empty() {
            return Err(ReliableServerError::EmptyResponse);
        }
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .ok_or(ReliableServerError::GenerationExhausted)?;
        self.pending = Some(PendingReliable {
            identity,
            bytes: Arc::clone(&bytes),
            generation,
            next_interval: self.initial_interval,
        });
        Ok(vec![
            ReliableServerAction::Send(bytes),
            ReliableServerAction::Schedule {
                generation,
                after: self.initial_interval,
            },
        ])
    }

    /// Retransmits only when timer generation still owns pending state.
    ///
    /// # Errors
    ///
    /// Rejects missing pending state or a stale timer generation.
    pub fn on_timer(
        &mut self,
        generation: u64,
    ) -> Result<Vec<ReliableServerAction>, ReliableServerError> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(ReliableServerError::NoPending)?;
        if pending.generation != generation {
            return Err(ReliableServerError::StaleGeneration);
        }
        let current = pending.next_interval;
        pending.next_interval = current
            .checked_mul(2)
            .unwrap_or(self.maximum_interval)
            .min(self.maximum_interval);
        Ok(vec![
            ReliableServerAction::Send(Arc::clone(&pending.bytes)),
            ReliableServerAction::Schedule {
                generation,
                after: pending.next_interval,
            },
        ])
    }

    /// Accepts PRACK only when all three `RAck` fields match exactly.
    ///
    /// # Errors
    ///
    /// Rejects absent state or a nonmatching acknowledgement identity.
    pub fn on_prack(
        &mut self,
        identity: &RackIdentity,
    ) -> Result<Vec<ReliableServerAction>, ReliableServerError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(ReliableServerError::NoPending)?;
        if &pending.identity != identity {
            return Err(ReliableServerError::RackMismatch);
        }
        let generation = pending.generation;
        self.pending = None;
        Ok(vec![ReliableServerAction::Cancel { generation }])
    }

    /// Returns whether a final response may cross the wire.
    #[must_use]
    pub const fn final_response_allowed(&self) -> bool {
        self.pending.is_none()
    }

    /// Cancels pending reliable state before an externally mandated final.
    ///
    /// The returned cancellation must be processed before sending the final.
    pub fn fence_final(&mut self) -> Vec<ReliableServerAction> {
        self.pending.take().map_or_else(Vec::new, |pending| {
            vec![ReliableServerAction::Cancel {
                generation: pending.generation,
            }]
        })
    }
}

/// Reliable provisional server lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReliableServerError {
    /// Initial/maximum retransmission intervals were invalid.
    InvalidTimerProfile,
    /// Another reliable provisional remains unacknowledged.
    AlreadyPending,
    /// Serialized response was empty.
    EmptyResponse,
    /// No reliable provisional is awaiting PRACK.
    NoPending,
    /// Timer belonged to a retired response generation.
    StaleGeneration,
    /// `RAck` did not match `RSeq`, `CSeq` number and method exactly.
    RackMismatch,
    /// Monotonic generation exhausted.
    GenerationExhausted,
}

impl fmt::Display for ReliableServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("reliable provisional server state rejected")
    }
}

impl StdError for ReliableServerError {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{
        PrackDisposition, PrackTracker, RackIdentity, ReliableError, ReliableProvisionalServer,
        ReliableServerAction, ReliableServerError,
    };
    use crate::sip::types::method::Method;
    #[test]
    fn reliable_183_pracks_and_retransmission_replays() {
        let mut tracker = PrackTracker::new();
        assert!(matches!(
            tracker.observe(1, 7, Method::Invite),
            Ok(PrackDisposition::SendPrack { .. })
        ));
        assert!(matches!(
            tracker.observe(1, 7, Method::Invite),
            Ok(PrackDisposition::ReplayPrack { .. })
        ));
        assert_eq!(
            tracker.observe(0, 7, Method::Invite),
            Err(ReliableError::ZeroSequence)
        );
    }

    #[test]
    fn server_requires_exact_rack_and_fences_final_response() {
        let mut server =
            ReliableProvisionalServer::new(Duration::from_millis(500), Duration::from_secs(4))
                .unwrap_or_else(|_| panic!("server"));
        let identity =
            RackIdentity::new(1, 7, Method::Invite).unwrap_or_else(|_| panic!("identity"));
        let actions = server
            .start(identity.clone(), Arc::from(&b"183"[..]))
            .unwrap_or_else(|_| panic!("start"));
        let generation = match actions.get(1) {
            Some(ReliableServerAction::Schedule { generation, .. }) => *generation,
            _ => panic!("schedule"),
        };
        assert!(!server.final_response_allowed());
        let mismatch =
            RackIdentity::new(1, 8, Method::Invite).unwrap_or_else(|_| panic!("mismatch"));
        assert!(matches!(
            server.on_prack(&mismatch),
            Err(ReliableServerError::RackMismatch)
        ));
        assert!(server.on_timer(generation).is_ok());
        assert!(server.on_prack(&identity).is_ok());
        assert!(server.final_response_allowed());
        assert!(matches!(
            server.on_timer(generation),
            Err(ReliableServerError::NoPending)
        ));
    }
}
