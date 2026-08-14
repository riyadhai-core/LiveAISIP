// Copyright 2026 RiyadhAI LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Single signaling authority for one call.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use crate::observability::{CallTimeline, TimelineError, TimelineEvent};
use crate::rtp::queue::{BoundedQueue, OverflowPolicy, PushOutcome, QueueDiagnostics, QueueError};

use super::events::{CallAction, CallEvent};
use super::lifecycle::{CallLifecycle, LifecycleError};

/// Default serialized event mailbox capacity per call.
pub const DEFAULT_CALL_MAILBOX_CAPACITY: usize = 256;
/// Default retained privacy-safe timeline events per call.
pub const DEFAULT_CALL_TIMELINE_CAPACITY: usize = 256;

/// Actor-owned state; producers may enqueue but cannot mutate lifecycle.
pub struct CallContext {
    lifecycle: CallLifecycle,
    inbox: BoundedQueue<CallEvent>,
    timeline: CallTimeline,
}

impl CallContext {
    /// Creates one isolated call authority.
    ///
    /// # Errors
    ///
    /// Preserves lifecycle, mailbox and timeline allocation/configuration failures.
    pub fn new(
        started_at: Duration,
        mailbox_capacity: usize,
        timeline_capacity: usize,
    ) -> Result<Self, CallContextError> {
        Ok(Self {
            lifecycle: CallLifecycle::new().map_err(CallContextError::Lifecycle)?,
            inbox: BoundedQueue::new(mailbox_capacity, OverflowPolicy::DropNewest)
                .map_err(CallContextError::Queue)?,
            timeline: CallTimeline::new(started_at, timeline_capacity)
                .map_err(CallContextError::Timeline)?,
        })
    }

    /// Enqueues one external event without mutating call state.
    ///
    /// # Errors
    ///
    /// Returns the event when bounded mailbox is full.
    pub fn submit(&mut self, event: CallEvent) -> Result<(), CallEvent> {
        match self.inbox.push(event) {
            PushOutcome::Accepted => Ok(()),
            PushOutcome::DroppedNewest(event) | PushOutcome::DroppedOldest(event) => Err(event),
        }
    }

    /// Lets the sole actor consume and mutate exactly one event.
    ///
    /// # Errors
    ///
    /// Preserves lifecycle and timeline failures.
    pub fn process_next(
        &mut self,
        now: Duration,
    ) -> Result<Option<Vec<CallAction>>, CallContextError> {
        let Some(event) = self.inbox.pop() else {
            return Ok(None);
        };
        let event_class = timeline_event(&event);
        let detail = timeline_detail(&event);
        let actions = self
            .lifecycle
            .handle(event)
            .map_err(CallContextError::Lifecycle)?;
        self.timeline
            .record(now, event_class, detail)
            .map_err(CallContextError::Timeline)?;
        Ok(Some(actions))
    }

    /// Returns immutable lifecycle for observations only.
    #[must_use]
    pub const fn lifecycle(&self) -> &CallLifecycle {
        &self.lifecycle
    }

    /// Returns mailbox metrics.
    #[must_use]
    pub fn mailbox_diagnostics(&self) -> QueueDiagnostics {
        self.inbox.diagnostics()
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
            .field("mailbox", &self.inbox.diagnostics())
            .field("timeline_entries", &self.timeline.entries().len())
            .finish_non_exhaustive()
    }
}

fn timeline_event(event: &CallEvent) -> TimelineEvent {
    match event {
        CallEvent::Command(_) => TimelineEvent::InviteSent,
        CallEvent::Provisional { has_sdp: true, .. } => TimelineEvent::EarlyMediaApplied,
        CallEvent::Provisional { .. } => TimelineEvent::ProvisionalReceived,
        CallEvent::InviteAccepted { .. } => TimelineEvent::InviteAccepted,
        CallEvent::InviteRejected { .. } => TimelineEvent::InviteRejected,
        CallEvent::CancelAccepted => TimelineEvent::CancelSent,
        CallEvent::ByeCompleted { .. } | CallEvent::RemoteBye => TimelineEvent::CallEnded,
        CallEvent::SignalingTimedOut | CallEvent::MediaTimedOut => TimelineEvent::MediaTimedOut,
        CallEvent::TransportFailed => TimelineEvent::TransportFailed,
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
    /// Mailbox construction failed.
    Queue(QueueError),
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
            Self::Queue(error) => Some(error),
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
        let Ok(mut context) = CallContext::new(Duration::ZERO, 2, 4) else {
            panic!("context")
        };
        assert!(
            context
                .submit(CallEvent::Command(CallCommand::Start))
                .is_ok()
        );
        assert_eq!(
            context.lifecycle().state(),
            crate::call::state::CallState::Idle
        );
        assert!(matches!(
            context.process_next(Duration::from_millis(1)),
            Ok(Some(actions)) if actions == vec![CallAction::SendInvite]
        ));
        assert_eq!(
            context.lifecycle().state(),
            crate::call::state::CallState::Inviting
        );
    }

    #[test]
    fn mailbox_is_bounded_and_observable() {
        let Ok(mut context) = CallContext::new(Duration::ZERO, 1, 4) else {
            panic!("context")
        };
        assert!(
            context
                .submit(CallEvent::Command(CallCommand::Start))
                .is_ok()
        );
        assert!(context.submit(CallEvent::TransportFailed).is_err());
        assert_eq!(context.mailbox_diagnostics().overflows, 1);
    }
}
