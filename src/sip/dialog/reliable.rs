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

#[cfg(test)]
mod tests {
    use super::{PrackDisposition, PrackTracker, ReliableError};
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
}
