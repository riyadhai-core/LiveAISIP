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

//! Deterministic outbound call and CANCEL/fork race handling.

use std::error::Error as StdError;
use std::fmt;

use super::branch::{DialogBranchId, ForkError, ForkSet};
use super::events::{CallAction, CallCommand, CallEvent};
use super::state::{CallEndReason, CallState, reason_from_status};

/// Single-authority call lifecycle.
pub struct CallLifecycle {
    state: CallState,
    forks: ForkSet,
    selected: Option<DialogBranchId>,
    cancel_requested: bool,
    cancel_sent: bool,
    last_sip_status: Option<u16>,
}

impl CallLifecycle {
    /// Creates idle call state with bounded fork storage.
    ///
    /// # Errors
    ///
    /// Returns fork storage allocation failure.
    pub fn new() -> Result<Self, LifecycleError> {
        Ok(Self {
            state: CallState::Idle,
            forks: ForkSet::new().map_err(LifecycleError::Fork)?,
            selected: None,
            cancel_requested: false,
            cancel_sent: false,
            last_sip_status: None,
        })
    }

    /// Applies exactly one serialized event and returns ordered effects.
    ///
    /// # Errors
    ///
    /// Rejects events invalid for current state and bounded fork failures.
    pub fn handle(&mut self, event: CallEvent) -> Result<Vec<CallAction>, LifecycleError> {
        if self.state.is_terminal() {
            return Err(LifecycleError::AlreadyEnded);
        }
        match event {
            CallEvent::Command(command) => self.command(command),
            CallEvent::Provisional { branch, has_sdp } => self.provisional(branch, has_sdp),
            CallEvent::InviteAccepted { branch } => self.accepted(branch),
            CallEvent::InviteRejected { branch, status } => self.rejected(branch, status),
            CallEvent::CancelAccepted => Ok(Vec::new()),
            CallEvent::ByeCompleted { branch } => self.bye_completed(branch),
            CallEvent::RemoteBye => Ok(self.end(CallEndReason::RemoteHangup)),
            CallEvent::SignalingTimedOut => Ok(self.end(CallEndReason::SignalingTimeout)),
            CallEvent::MediaTimedOut => Ok(self.end(CallEndReason::MediaTimeout)),
            CallEvent::TransportFailed => Ok(self.end(CallEndReason::TransportFailure)),
            CallEvent::SessionModification { method, has_offer }
                if self.state == CallState::Established =>
            {
                Ok(vec![CallAction::ApplySessionModification {
                    method,
                    has_offer,
                }])
            }
            CallEvent::SessionModification { .. } => Err(LifecycleError::InvalidEvent),
        }
    }

    /// Returns current lifecycle.
    #[must_use]
    pub const fn state(&self) -> CallState {
        self.state
    }

    /// Returns all retained fork branches.
    #[must_use]
    pub const fn forks(&self) -> &ForkSet {
        &self.forks
    }

    /// Returns selected confirmed branch.
    #[must_use]
    pub const fn selected_branch(&self) -> Option<&DialogBranchId> {
        self.selected.as_ref()
    }

    /// Returns last final SIP status for detailed SDK diagnostics.
    #[must_use]
    pub const fn last_sip_status(&self) -> Option<u16> {
        self.last_sip_status
    }

    fn command(&mut self, command: CallCommand) -> Result<Vec<CallAction>, LifecycleError> {
        match command {
            CallCommand::Start if self.state == CallState::Idle => {
                self.state = CallState::Inviting;
                Ok(vec![CallAction::SendInvite])
            }
            CallCommand::Hangup
                if matches!(self.state, CallState::Inviting | CallState::Cancelling) =>
            {
                self.cancel_requested = true;
                self.state = CallState::Cancelling;
                if self.cancel_sent {
                    Ok(Vec::new())
                } else {
                    self.cancel_sent = true;
                    Ok(vec![CallAction::SendCancel])
                }
            }
            CallCommand::Hangup if self.state == CallState::Established => {
                let branch = self
                    .selected
                    .clone()
                    .ok_or(LifecycleError::MissingSelectedBranch)?;
                self.state = CallState::Terminating;
                Ok(vec![CallAction::SendBye { branch }])
            }
            CallCommand::BlindTransfer { target } if self.state == CallState::Established => {
                Ok(vec![CallAction::SendRefer { target }])
            }
            CallCommand::AttendedTransfer { other_call }
                if self.state == CallState::Established =>
            {
                Ok(vec![CallAction::SendReferReplaces { other_call }])
            }
            _ => Err(LifecycleError::InvalidEvent),
        }
    }

    fn provisional(
        &mut self,
        branch: DialogBranchId,
        has_sdp: bool,
    ) -> Result<Vec<CallAction>, LifecycleError> {
        if !matches!(self.state, CallState::Inviting | CallState::Cancelling) {
            return Err(LifecycleError::InvalidEvent);
        }
        self.forks
            .note_early(branch.clone())
            .map_err(LifecycleError::Fork)?;
        Ok(if has_sdp {
            vec![CallAction::ApplyEarlyMedia { branch }]
        } else {
            Vec::new()
        })
    }

    fn accepted(&mut self, branch: DialogBranchId) -> Result<Vec<CallAction>, LifecycleError> {
        if !matches!(
            self.state,
            CallState::Inviting
                | CallState::Cancelling
                | CallState::Established
                | CallState::Terminating
        ) {
            return Err(LifecycleError::InvalidEvent);
        }
        self.forks
            .note_confirmed(branch.clone())
            .map_err(LifecycleError::Fork)?;
        let mut actions = vec![CallAction::SendAck {
            branch: branch.clone(),
        }];
        if self.cancel_requested || self.state == CallState::Terminating {
            self.state = CallState::Terminating;
            actions.push(CallAction::SendBye { branch });
            return Ok(actions);
        }
        if self.selected.is_none() {
            self.selected = Some(branch.clone());
            self.state = CallState::Established;
            actions.push(CallAction::SelectBranch { branch });
        } else if self.selected.as_ref() != Some(&branch) {
            actions.push(CallAction::SendBye { branch });
        }
        Ok(actions)
    }

    fn rejected(
        &mut self,
        branch: DialogBranchId,
        status: u16,
    ) -> Result<Vec<CallAction>, LifecycleError> {
        if !(300..=699).contains(&status) {
            return Err(LifecycleError::InvalidFinalStatus);
        }
        self.last_sip_status = Some(status);
        self.forks
            .note_terminated(branch)
            .map_err(LifecycleError::Fork)?;
        if self.selected.is_some() || self.forks.has_live_branches() {
            return Ok(Vec::new());
        }
        let reason = if self.cancel_requested {
            CallEndReason::Canceled
        } else {
            reason_from_status(status)
        };
        Ok(self.end(reason))
    }

    fn bye_completed(&mut self, branch: DialogBranchId) -> Result<Vec<CallAction>, LifecycleError> {
        self.forks
            .note_terminated(branch)
            .map_err(LifecycleError::Fork)?;
        if self.state == CallState::Terminating && !self.forks.has_live_branches() {
            let reason = if self.cancel_requested {
                CallEndReason::Canceled
            } else {
                CallEndReason::LocalHangup
            };
            return Ok(self.end(reason));
        }
        Ok(Vec::new())
    }

    fn end(&mut self, reason: CallEndReason) -> Vec<CallAction> {
        self.state = CallState::Ended(reason);
        vec![CallAction::Ended(reason)]
    }

    /// Forces one terminal transition during runtime containment or shutdown.
    ///
    /// Repeated calls are idempotent and emit no duplicate terminal action.
    pub(crate) fn force_end(&mut self, reason: CallEndReason) -> Vec<CallAction> {
        if self.state.is_terminal() {
            Vec::new()
        } else {
            self.end(reason)
        }
    }
}

impl fmt::Debug for CallLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallLifecycle")
            .field("state", &self.state)
            .field("fork_count", &self.forks.len())
            .field("has_selected_branch", &self.selected.is_some())
            .field("cancel_requested", &self.cancel_requested)
            .field("last_sip_status", &self.last_sip_status)
            .finish_non_exhaustive()
    }
}

/// Call lifecycle failure.
#[derive(Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// Event is invalid for current state.
    InvalidEvent,
    /// A final INVITE status was outside 300..=699.
    InvalidFinalStatus,
    /// Terminal call received another event.
    AlreadyEnded,
    /// Established state lacked selected branch.
    MissingSelectedBranch,
    /// Fork storage or identity failed.
    Fork(ForkError),
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("call lifecycle event rejected")
    }
}

impl StdError for LifecycleError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Fork(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CallLifecycle;
    use crate::call::events::{CallAction, CallCommand, CallEvent, SessionModificationMethod};
    use crate::call::leg::DialogBranchId;
    use crate::call::state::{CallEndReason, CallState};

    fn branch(value: &str) -> DialogBranchId {
        DialogBranchId::new(value).unwrap_or_else(|_| panic!("branch"))
    }

    fn started() -> CallLifecycle {
        let mut call = CallLifecycle::new().unwrap_or_else(|_| panic!("call"));
        assert_eq!(
            call.handle(CallEvent::Command(CallCommand::Start)),
            Ok(vec![CallAction::SendInvite])
        );
        call
    }

    #[test]
    fn cancel_then_487_ends_canceled() {
        let mut call = started();
        assert_eq!(
            call.handle(CallEvent::Command(CallCommand::Hangup)),
            Ok(vec![CallAction::SendCancel])
        );
        assert_eq!(call.handle(CallEvent::CancelAccepted), Ok(Vec::new()));
        assert_eq!(
            call.handle(CallEvent::InviteRejected {
                branch: branch("a"),
                status: 487,
            }),
            Ok(vec![CallAction::Ended(CallEndReason::Canceled)])
        );
    }

    #[test]
    fn cancel_race_with_200_acknowledges_then_byes() {
        let mut call = started();
        assert!(call.handle(CallEvent::Command(CallCommand::Hangup)).is_ok());
        let accepted = branch("winner");
        assert_eq!(
            call.handle(CallEvent::InviteAccepted {
                branch: accepted.clone()
            }),
            Ok(vec![
                CallAction::SendAck {
                    branch: accepted.clone()
                },
                CallAction::SendBye { branch: accepted }
            ])
        );
        assert_eq!(call.state(), CallState::Terminating);
    }

    #[test]
    fn every_forked_200_is_acked_and_unwanted_dialog_is_byed() {
        let mut call = started();
        let first = branch("first");
        let second = branch("second");
        assert_eq!(
            call.handle(CallEvent::InviteAccepted {
                branch: first.clone()
            }),
            Ok(vec![
                CallAction::SendAck {
                    branch: first.clone()
                },
                CallAction::SelectBranch { branch: first }
            ])
        );
        assert_eq!(
            call.handle(CallEvent::InviteAccepted {
                branch: second.clone()
            }),
            Ok(vec![
                CallAction::SendAck {
                    branch: second.clone()
                },
                CallAction::SendBye { branch: second }
            ])
        );
    }

    #[test]
    fn established_session_modification_preserves_invite_or_update_method() {
        let mut call = started();
        let selected = branch("selected");
        assert!(
            call.handle(CallEvent::InviteAccepted { branch: selected })
                .is_ok()
        );
        for method in [
            SessionModificationMethod::Invite,
            SessionModificationMethod::Update,
        ] {
            assert_eq!(
                call.handle(CallEvent::SessionModification {
                    method,
                    has_offer: true,
                }),
                Ok(vec![CallAction::ApplySessionModification {
                    method,
                    has_offer: true,
                }])
            );
        }
    }

    #[test]
    fn session_modification_is_rejected_before_dialog_establishment() {
        let mut call = started();
        assert_eq!(
            call.handle(CallEvent::SessionModification {
                method: SessionModificationMethod::Update,
                has_offer: false,
            }),
            Err(super::LifecycleError::InvalidEvent)
        );
    }
}
