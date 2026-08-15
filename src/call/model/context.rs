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

//! Single signaling authority for one call.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use super::events::{CallAction, CallCommand, CallEvent};
use super::lifecycle::{CallLifecycle, LifecycleError};
use crate::observability::{CallTimeline, TimelineError, TimelineEvent};

/// Default retained privacy-safe timeline events per call.
pub const DEFAULT_CALL_TIMELINE_CAPACITY: usize = 256;

/// Actor-owned call state, mutated only by its owning
/// [`CallRuntime`](crate::call::execution::runtime::CallRuntime).
pub struct CallContext {
    lifecycle: CallLifecycle,
    timeline: CallTimeline,
}

impl CallContext {
    /// Creates one isolated call authority.
    ///
    /// # Errors
    ///
    /// Preserves lifecycle and timeline allocation/configuration failures.
    pub fn new(started_at: Duration, timeline_capacity: usize) -> Result<Self, CallContextError> {
        Ok(Self {
            lifecycle: CallLifecycle::new().map_err(CallContextError::Lifecycle)?,
            timeline: CallTimeline::new(started_at, timeline_capacity)
                .map_err(CallContextError::Timeline)?,
        })
    }

    /// Applies exactly one event under the call runtime's exclusive authority.
    ///
    /// # Errors
    ///
    /// Preserves lifecycle and timeline failures.
    pub fn handle(
        &mut self,
        event: CallEvent,
        now: Duration,
    ) -> Result<Vec<CallAction>, CallContextError> {
        self.timeline
            .validate_time(now)
            .map_err(CallContextError::Timeline)?;
        let event_class = timeline_event(&event);
        let detail = timeline_detail(&event);
        let actions = self
            .lifecycle
            .handle(event)
            .map_err(CallContextError::Lifecycle)?;
        if let Some(event_class) = event_class {
            self.timeline
                .record(now, event_class, detail)
                .map_err(CallContextError::Timeline)?;
        }
        for action in &actions {
            if let Some(action_class) = timeline_action(action) {
                self.timeline
                    .record(now, action_class, None)
                    .map_err(CallContextError::Timeline)?;
            }
        }
        Ok(actions)
    }

    /// Returns immutable lifecycle for observations only.
    #[must_use]
    pub const fn lifecycle(&self) -> &CallLifecycle {
        &self.lifecycle
    }

    pub(crate) fn force_end(&mut self, reason: super::state::CallEndReason) -> Vec<CallAction> {
        self.lifecycle.force_end(reason)
    }

    /// Returns bounded call timeline.
    #[must_use]
    pub const fn timeline(&self) -> &CallTimeline {
        &self.timeline
    }
}

impl fmt::Debug for CallContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallContext")
            .field("lifecycle", &self.lifecycle)
            .field("timeline_entries", &self.timeline.entries().len())
            .finish_non_exhaustive()
    }
}

fn timeline_event(event: &CallEvent) -> Option<TimelineEvent> {
    match event {
        CallEvent::Command(CallCommand::Start)
        | CallEvent::CancelAccepted
        | CallEvent::SessionModification { .. } => None,
        CallEvent::Command(CallCommand::Hangup) => Some(TimelineEvent::HangupRequested),
        CallEvent::Command(
            CallCommand::BlindTransfer { .. } | CallCommand::AttendedTransfer { .. },
        ) => Some(TimelineEvent::TransferRequested),
        CallEvent::Provisional { .. } => Some(TimelineEvent::ProvisionalReceived),
        CallEvent::InviteAccepted { .. } => Some(TimelineEvent::InviteAccepted),
        CallEvent::InviteRejected { .. } => Some(TimelineEvent::InviteRejected),
        CallEvent::ByeCompleted { .. } | CallEvent::RemoteBye => Some(TimelineEvent::CallEnded),
        CallEvent::SignalingTimedOut => Some(TimelineEvent::SignalingTimedOut),
        CallEvent::MediaTimedOut => Some(TimelineEvent::MediaTimedOut),
        CallEvent::TransportFailed => Some(TimelineEvent::TransportFailed),
    }
}

fn timeline_action(action: &CallAction) -> Option<TimelineEvent> {
    match action {
        CallAction::SendInvite => Some(TimelineEvent::InviteSent),
        CallAction::SendCancel => Some(TimelineEvent::CancelSent),
        CallAction::SendAck { .. } => Some(TimelineEvent::AckSent),
        CallAction::SendBye { .. } => Some(TimelineEvent::ByeSent),
        CallAction::ApplyEarlyMedia { .. } => Some(TimelineEvent::EarlyMediaApplied),
        CallAction::SendRefer { .. } | CallAction::SendReferReplaces { .. } => {
            Some(TimelineEvent::TransferSent)
        }
        CallAction::Ended(_) => Some(TimelineEvent::CallEnded),
        CallAction::SelectBranch { .. } | CallAction::ApplySessionModification { .. } => None,
    }
}

fn timeline_detail(event: &CallEvent) -> Option<u32> {
    match event {
        CallEvent::InviteRejected { status, .. } => Some(u32::from(*status)),
        _ => None,
    }
}

/// Call actor construction or processing failure.
#[derive(Debug)]
pub enum CallContextError {
    /// Lifecycle rejected the serialized event.
    Lifecycle(LifecycleError),
    /// Timeline creation or recording failed.
    Timeline(TimelineError),
}

impl fmt::Display for CallContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("call context processing failed")
    }
}

impl StdError for CallContextError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Lifecycle(error) => Some(error),
            Self::Timeline(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::CallContext;
    use crate::call::events::{CallAction, CallCommand, CallEvent};

    #[test]
    fn only_actor_processing_mutates_lifecycle() {
        let Ok(mut context) = CallContext::new(Duration::ZERO, 4) else {
            panic!("context")
        };
        assert_eq!(
            context.lifecycle().state(),
            crate::call::state::CallState::Idle
        );
        assert!(matches!(
            context.handle(CallEvent::Command(CallCommand::Start), Duration::from_millis(1)),
            Ok(actions) if actions == vec![CallAction::SendInvite]
        ));
        assert_eq!(
            context.lifecycle().state(),
            crate::call::state::CallState::Inviting
        );
    }
}
