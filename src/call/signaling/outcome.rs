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

//! One transaction-routed SIP event and its fork-bound media answer.
//!
//! Keeping these values together prevents a response's SDP from being applied
//! to a different fork or lifecycle transition. The call thread consumes the
//! lifecycle event first, executes mandatory SIP effects, and only then may
//! commit the attached media generation when the resulting action selects the
//! same branch.

use std::fmt;

use crate::call::model::events::CallEvent;

use super::media::{MediaAnswerError, RemoteMediaAnswer};

/// SDP processing result retained beside the same response's call event.
pub enum MediaAnswerOutcome {
    /// SDP was valid, compatible, and fork-bound.
    Negotiated(Box<RemoteMediaAnswer>),
    /// SDP was present but invalid or incompatible.
    Invalid(MediaAnswerError),
}

impl fmt::Debug for MediaAnswerOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Negotiated(answer) => formatter.debug_tuple("Negotiated").field(answer).finish(),
            Self::Invalid(error) => formatter
                .debug_struct("Invalid")
                .field("class", &error.class())
                .finish(),
        }
    }
}

/// One ordered result produced by call-owned live signaling.
pub struct SignalingOutcome {
    event: CallEvent,
    media: Option<MediaAnswerOutcome>,
}

impl SignalingOutcome {
    /// Creates an event without negotiated media.
    #[must_use]
    pub const fn event(event: CallEvent) -> Self {
        Self { event, media: None }
    }

    /// Attaches the validated SDP answer from the same SIP response.
    #[must_use]
    pub fn with_media_answer(mut self, answer: RemoteMediaAnswer) -> Self {
        self.media = Some(MediaAnswerOutcome::Negotiated(Box::new(answer)));
        self
    }

    /// Attaches a privacy-safe invalid-media result from the same response.
    #[must_use]
    pub fn with_invalid_media(mut self, error: MediaAnswerError) -> Self {
        self.media = Some(MediaAnswerOutcome::Invalid(error));
        self
    }

    /// Returns the deterministic lifecycle event.
    #[must_use]
    pub const fn call_event(&self) -> &CallEvent {
        &self.event
    }

    /// Returns the fork-bound media answer, when the response carried one.
    #[must_use]
    pub const fn media(&self) -> Option<&MediaAnswerOutcome> {
        self.media.as_ref()
    }

    /// Consumes the outcome into its ordered call-thread inputs.
    #[must_use]
    pub fn into_parts(self) -> (CallEvent, Option<MediaAnswerOutcome>) {
        (self.event, self.media)
    }
}

impl fmt::Debug for SignalingOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignalingOutcome")
            .field("event", &self.event)
            .field("has_media_result", &self.media.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::SignalingOutcome;
    use crate::call::model::branch::DialogBranchId;
    use crate::call::model::events::CallEvent;

    #[test]
    fn retains_event_without_disclosing_media() {
        let branch = DialogBranchId::new("safe-branch").unwrap_or_else(|_| panic!("branch"));
        let outcome = SignalingOutcome::event(CallEvent::InviteAccepted { branch });
        assert!(matches!(
            outcome.call_event(),
            CallEvent::InviteAccepted { .. }
        ));
        assert!(outcome.media().is_none());
        assert!(format!("{outcome:?}").contains("has_media_result: false"));
    }
}
