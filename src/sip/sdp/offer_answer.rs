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

//! One serialized SDP offer/answer negotiation per dialog.

use std::error::Error as StdError;
use std::fmt;

/// Offer/answer ownership state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfferAnswerState {
    /// No negotiation is in flight.
    Stable,
    /// Local offer waits for remote answer.
    LocalOfferPending,
    /// Remote offer waits for local answer.
    RemoteOfferPending,
}

/// Generation-fenced negotiation capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfferToken {
    generation: u64,
    origin: OfferOrigin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OfferOrigin {
    Local,
    Remote,
}

/// Dialog-scoped offer/answer arbiter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfferAnswer {
    state: OfferAnswerState,
    generation: u64,
    completed: u64,
}

impl OfferAnswer {
    /// Creates stable negotiation state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: OfferAnswerState::Stable,
            generation: 1,
            completed: 0,
        }
    }

    /// Begins a local offer for INVITE, re-INVITE, UPDATE or PRACK.
    ///
    /// # Errors
    ///
    /// Rejects overlapping negotiation and generation exhaustion.
    pub fn begin_local_offer(&mut self) -> Result<OfferToken, OfferAnswerError> {
        self.begin(OfferOrigin::Local)
    }

    /// Begins a remote offer. Overlap maps to SIP 491 glare handling.
    ///
    /// # Errors
    ///
    /// Rejects overlapping negotiation and generation exhaustion.
    pub fn begin_remote_offer(&mut self) -> Result<OfferToken, OfferAnswerError> {
        self.begin(OfferOrigin::Remote)
    }

    /// Completes local-offer negotiation with remote answer.
    ///
    /// # Errors
    ///
    /// Rejects stale/wrong-origin tokens or state mismatch.
    pub fn apply_remote_answer(&mut self, token: OfferToken) -> Result<(), OfferAnswerError> {
        self.complete(token, OfferOrigin::Local)
    }

    /// Completes remote-offer negotiation after local answer is committed.
    ///
    /// # Errors
    ///
    /// Rejects stale/wrong-origin tokens or state mismatch.
    pub fn apply_local_answer(&mut self, token: OfferToken) -> Result<(), OfferAnswerError> {
        self.complete(token, OfferOrigin::Remote)
    }

    /// Aborts exact in-flight generation and returns stable state.
    ///
    /// # Errors
    ///
    /// Rejects a stale token.
    pub fn abort(&mut self, token: OfferToken) -> Result<(), OfferAnswerError> {
        self.validate_token(token)?;
        self.state = OfferAnswerState::Stable;
        Ok(())
    }

    /// Returns current arbiter state.
    #[must_use]
    pub const fn state(&self) -> OfferAnswerState {
        self.state
    }

    /// Returns completed negotiation count.
    #[must_use]
    pub const fn completed(&self) -> u64 {
        self.completed
    }

    fn begin(&mut self, origin: OfferOrigin) -> Result<OfferToken, OfferAnswerError> {
        if self.state != OfferAnswerState::Stable {
            return Err(OfferAnswerError::Glare);
        }
        let generation = self.generation;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(OfferAnswerError::GenerationExhausted)?;
        self.state = match origin {
            OfferOrigin::Local => OfferAnswerState::LocalOfferPending,
            OfferOrigin::Remote => OfferAnswerState::RemoteOfferPending,
        };
        Ok(OfferToken { generation, origin })
    }

    fn complete(
        &mut self,
        token: OfferToken,
        expected: OfferOrigin,
    ) -> Result<(), OfferAnswerError> {
        self.validate_token(token)?;
        if token.origin != expected {
            return Err(OfferAnswerError::WrongOfferOrigin);
        }
        self.state = OfferAnswerState::Stable;
        self.completed = self.completed.saturating_add(1);
        Ok(())
    }

    fn validate_token(&self, token: OfferToken) -> Result<(), OfferAnswerError> {
        let expected_state = match token.origin {
            OfferOrigin::Local => OfferAnswerState::LocalOfferPending,
            OfferOrigin::Remote => OfferAnswerState::RemoteOfferPending,
        };
        if self.state != expected_state || token.generation.saturating_add(1) != self.generation {
            return Err(OfferAnswerError::StaleToken);
        }
        Ok(())
    }
}

impl Default for OfferAnswer {
    fn default() -> Self {
        Self::new()
    }
}

/// Offer/answer serialization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfferAnswerError {
    /// Another offer/answer exchange is active; remote re-INVITE should receive 491.
    Glare,
    /// Token does not identify current generation.
    StaleToken,
    /// Answer API did not match offer origin.
    WrongOfferOrigin,
    /// Generation space cannot safely continue.
    GenerationExhausted,
}

impl fmt::Display for OfferAnswerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SDP offer/answer operation rejected")
    }
}

impl StdError for OfferAnswerError {}

#[cfg(test)]
mod tests {
    use super::{OfferAnswer, OfferAnswerError, OfferAnswerState};

    #[test]
    fn serializes_negotiations_and_reports_glare() {
        let mut state = OfferAnswer::new();
        let Ok(token) = state.begin_local_offer() else {
            panic!("offer")
        };
        assert_eq!(state.state(), OfferAnswerState::LocalOfferPending);
        assert_eq!(state.begin_remote_offer(), Err(OfferAnswerError::Glare));
        assert!(state.apply_remote_answer(token).is_ok());
        assert_eq!(state.state(), OfferAnswerState::Stable);
        assert_eq!(state.completed(), 1);
    }

    #[test]
    fn stale_generation_cannot_complete_new_offer() {
        let mut state = OfferAnswer::new();
        let first = state
            .begin_local_offer()
            .unwrap_or_else(|_| panic!("offer"));
        assert!(state.abort(first).is_ok());
        let second = state
            .begin_local_offer()
            .unwrap_or_else(|_| panic!("offer"));
        assert_eq!(
            state.apply_remote_answer(first),
            Err(OfferAnswerError::StaleToken)
        );
        assert!(state.apply_remote_answer(second).is_ok());
    }
}
