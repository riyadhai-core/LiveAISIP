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

//! Explicit bounded SIP 3xx redirect behavior.

use crate::sip::types::uri::Uri;
use std::error::Error as StdError;
use std::fmt;

/// Maximum Contacts accepted from one redirect.
pub const MAX_REDIRECT_CONTACTS: usize = 16;
/// Maximum redirects followed per call.
pub const MAX_REDIRECT_HOPS: usize = 8;

/// Application-selected 3xx behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedirectPolicy {
    /// Treat redirect as terminal rejection.
    Reject,
    /// Publish targets to Python without following.
    Report,
    /// Follow first safe, unvisited target.
    Follow {
        /// Maximum number of redirect hops before the call is terminated.
        maximum_hops: usize,
    },
}

/// Result of handling Contact targets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedirectDecision {
    /// Redirect is not followed.
    Rejected,
    /// Bounded validated targets are reported.
    Report(Vec<Uri>),
    /// Runtime should start a new attempt at this target.
    Follow(Uri),
}

/// Per-call redirect loop and downgrade guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedirectHandler {
    policy: RedirectPolicy,
    require_secure: bool,
    visited: Vec<Uri>,
}

impl RedirectHandler {
    /// Creates bounded redirect state.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive follow limit or allocation failure.
    pub fn new(policy: RedirectPolicy, require_secure: bool) -> Result<Self, RedirectError> {
        let capacity = match policy {
            RedirectPolicy::Follow { maximum_hops }
                if maximum_hops == 0 || maximum_hops > MAX_REDIRECT_HOPS =>
            {
                return Err(RedirectError::InvalidHopLimit);
            }
            RedirectPolicy::Follow { maximum_hops } => maximum_hops,
            _ => 0,
        };
        let mut visited = Vec::new();
        visited
            .try_reserve_exact(capacity)
            .map_err(|_| RedirectError::AllocationFailed)?;
        Ok(Self {
            policy,
            require_secure,
            visited,
        })
    }

    /// Applies policy to one 3xx Contact set.
    ///
    /// # Errors
    ///
    /// Rejects empty/excessive targets, secure downgrade, loops, or hop exhaustion.
    pub fn handle(&mut self, contacts: &[Uri]) -> Result<RedirectDecision, RedirectError> {
        if contacts.is_empty() || contacts.len() > MAX_REDIRECT_CONTACTS {
            return Err(RedirectError::InvalidContactCount);
        }
        if self.require_secure && contacts.iter().any(|uri| uri.scheme() != "sips") {
            return Err(RedirectError::SecurityDowngrade);
        }
        match self.policy {
            RedirectPolicy::Reject => Ok(RedirectDecision::Rejected),
            RedirectPolicy::Report => Ok(RedirectDecision::Report(contacts.to_vec())),
            RedirectPolicy::Follow { maximum_hops } => {
                if self.visited.len() == maximum_hops {
                    return Err(RedirectError::HopLimitExceeded);
                }
                let target = contacts
                    .iter()
                    .find(|target| !self.visited.contains(target))
                    .cloned()
                    .ok_or(RedirectError::LoopDetected)?;
                self.visited.push(target.clone());
                Ok(RedirectDecision::Follow(target))
            }
        }
    }
}

/// Redirect policy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedirectError {
    /// Follow limit invalid.
    InvalidHopLimit,
    /// Contact count invalid.
    InvalidContactCount,
    /// Secure call was redirected to insecure URI.
    SecurityDowngrade,
    /// All targets were already visited.
    LoopDetected,
    /// Maximum redirect attempts reached.
    HopLimitExceeded,
    /// Fixed storage allocation failed.
    AllocationFailed,
}
impl fmt::Display for RedirectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP redirect policy rejected targets")
    }
}
impl StdError for RedirectError {}

#[cfg(test)]
mod tests {
    use super::{RedirectDecision, RedirectError, RedirectHandler, RedirectPolicy};
    use crate::sip::parser::uri::parse_str;
    #[test]
    fn follow_is_bounded_and_loop_safe() {
        let target = parse_str("sip:b@example.com").unwrap_or_else(|_| panic!("uri"));
        let mut handler = RedirectHandler::new(RedirectPolicy::Follow { maximum_hops: 2 }, false)
            .unwrap_or_else(|_| panic!("handler"));
        assert!(matches!(
            handler.handle(std::slice::from_ref(&target)),
            Ok(RedirectDecision::Follow(_))
        ));
        assert_eq!(handler.handle(&[target]), Err(RedirectError::LoopDetected));
    }
    #[test]
    fn secure_redirect_never_downgrades() {
        let target = parse_str("sip:b@example.com").unwrap_or_else(|_| panic!("uri"));
        let mut handler = RedirectHandler::new(RedirectPolicy::Follow { maximum_hops: 2 }, true)
            .unwrap_or_else(|_| panic!("handler"));
        assert_eq!(
            handler.handle(&[target]),
            Err(RedirectError::SecurityDowngrade)
        );
    }
}
