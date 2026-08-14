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

//! Owned SIP dialog state.
//!
//! A [`Dialog`] binds identity, lifecycle, route set, remote target, and `CSeq`
//! ordering into one invariant-preserving object. It contains no sockets,
//! timers, or application callbacks, allowing a manager to own concurrency
//! and admission independently from deterministic protocol state.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::headers::cseq::{CSeq, MAX_CSEQ_SEQUENCE};
use crate::sip::types::method::Method;
use crate::sip::types::uri::Uri;

use super::id::DialogId;
use super::route::{RouteSet, RoutingPlan};
use super::state::{DialogState, DialogStateError};

/// Complete protocol state for one SIP dialog.
#[derive(Clone, Eq, PartialEq)]
pub struct Dialog {
    id: DialogId,
    state: DialogState,
    route_set: RouteSet,
    remote_target: Uri,
    local_sequence: u32,
    remote_sequence: Option<u32>,
}

impl Dialog {
    /// Creates a dialog with validated, role-oriented state.
    ///
    /// `local_sequence` is normally the `CSeq` of the request that established
    /// a UAC dialog. A UAS supplies the establishing request's `CSeq` as
    /// `remote_sequence`; a UAC normally supplies `None` until it receives an
    /// independently sequenced in-dialog request.
    ///
    /// # Errors
    ///
    /// Returns [`DialogError::SequenceTooLarge`] when either initial sequence
    /// exceeds the SIP `CSeq` ceiling.
    pub fn new(
        id: DialogId,
        state: DialogState,
        route_set: RouteSet,
        remote_target: Uri,
        local_sequence: u32,
        remote_sequence: Option<u32>,
    ) -> Result<Self, DialogError> {
        validate_sequence(local_sequence, DialogSequenceRole::Local)?;
        if let Some(sequence) = remote_sequence {
            validate_sequence(sequence, DialogSequenceRole::Remote)?;
        }
        Ok(Self {
            id,
            state,
            route_set,
            remote_target,
            local_sequence,
            remote_sequence,
        })
    }

    /// Returns the stable dialog identifier.
    #[must_use]
    pub const fn id(&self) -> &DialogId {
        &self.id
    }

    /// Returns lifecycle state.
    #[must_use]
    pub const fn state(&self) -> DialogState {
        self.state
    }

    /// Returns the immutable route set.
    #[must_use]
    pub const fn route_set(&self) -> &RouteSet {
        &self.route_set
    }

    /// Returns the current remote target.
    #[must_use]
    pub const fn remote_target(&self) -> &Uri {
        &self.remote_target
    }

    /// Returns the latest locally allocated sequence number.
    #[must_use]
    pub const fn local_sequence(&self) -> u32 {
        self.local_sequence
    }

    /// Returns the latest accepted independently sequenced remote `CSeq`.
    #[must_use]
    pub const fn remote_sequence(&self) -> Option<u32> {
        self.remote_sequence
    }

    /// Produces the routing plan for the next outbound in-dialog request.
    ///
    /// # Errors
    ///
    /// Rejects use after dialog termination.
    pub fn routing_plan(&self) -> Result<RoutingPlan, DialogError> {
        self.state.ensure_active().map_err(DialogError::State)?;
        Ok(self.route_set.plan(&self.remote_target))
    }

    /// Allocates the next local `CSeq` for a newly generated request.
    ///
    /// ACK and CANCEL reuse an existing transaction sequence and must not call
    /// this operation.
    ///
    /// # Errors
    ///
    /// Rejects use after termination, ACK/CANCEL allocation, and exhaustion at
    /// the SIP `CSeq` maximum.
    pub fn next_local_cseq(&mut self, method: Method) -> Result<CSeq, DialogError> {
        self.state.ensure_active().map_err(DialogError::State)?;
        if matches!(method, Method::Ack | Method::Cancel) {
            return Err(DialogError::NonIncrementingMethod(method));
        }
        let Some(sequence) = self.local_sequence.checked_add(1) else {
            return Err(DialogError::LocalSequenceExhausted);
        };
        if sequence > MAX_CSEQ_SEQUENCE {
            return Err(DialogError::LocalSequenceExhausted);
        }
        self.local_sequence = sequence;
        CSeq::new(sequence, method).map_err(|_| DialogError::LocalSequenceExhausted)
    }

    /// Validates and records the `CSeq` of an incoming in-dialog request.
    ///
    /// Independently sequenced methods must strictly increase. ACK and CANCEL
    /// do not advance dialog sequence state and are accepted only when their
    /// sequence equals the currently recorded remote sequence.
    ///
    /// # Errors
    ///
    /// Rejects use after termination and non-monotonic remote requests.
    pub fn accept_remote_cseq(&mut self, cseq: &CSeq) -> Result<(), DialogError> {
        self.state.ensure_active().map_err(DialogError::State)?;
        let received = cseq.sequence();
        if matches!(cseq.method(), Method::Ack | Method::Cancel) {
            if self.remote_sequence == Some(received) {
                return Ok(());
            }
            return Err(DialogError::RemoteSequenceOutOfOrder {
                received,
                current: self.remote_sequence,
            });
        }
        if self
            .remote_sequence
            .is_some_and(|current| received <= current)
        {
            return Err(DialogError::RemoteSequenceOutOfOrder {
                received,
                current: self.remote_sequence,
            });
        }
        self.remote_sequence = Some(received);
        Ok(())
    }

    /// Replaces the remote target after a successful target-refresh operation.
    ///
    /// # Errors
    ///
    /// Rejects mutation after dialog termination.
    pub fn update_remote_target(&mut self, remote_target: Uri) -> Result<(), DialogError> {
        self.state.ensure_active().map_err(DialogError::State)?;
        self.remote_target = remote_target;
        Ok(())
    }

    /// Confirms an early dialog. Repeated confirmation is harmless.
    ///
    /// # Errors
    ///
    /// Rejects confirmation after termination.
    pub fn confirm(&mut self) -> Result<(), DialogError> {
        self.state.confirm().map_err(DialogError::State)
    }

    /// Terminates the dialog, returning `true` only on the first call.
    #[must_use]
    pub fn terminate(&mut self) -> bool {
        self.state.terminate()
    }
}

impl fmt::Debug for Dialog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Dialog")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("route_count", &self.route_set.len())
            .field("remote_target_scheme", &self.remote_target.scheme())
            .field("local_sequence", &self.local_sequence)
            .field("remote_sequence", &self.remote_sequence)
            .finish_non_exhaustive()
    }
}

/// Ownership side of a dialog sequence number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogSequenceRole {
    /// Locally generated sequence numbers.
    Local,
    /// Remotely generated sequence numbers.
    Remote,
}

impl fmt::Display for DialogSequenceRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Local => "local",
            Self::Remote => "remote",
        })
    }
}

/// A rejected dialog operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DialogError {
    /// Lifecycle state rejected the operation.
    State(DialogStateError),
    /// An initial `CSeq` exceeded the SIP maximum.
    SequenceTooLarge {
        /// Sequence ownership side.
        role: DialogSequenceRole,
        /// Supplied sequence number.
        sequence: u32,
        /// Largest accepted sequence number.
        maximum: u32,
    },
    /// No further local sequence number can be allocated.
    LocalSequenceExhausted,
    /// ACK or CANCEL was incorrectly submitted for sequence allocation.
    NonIncrementingMethod(Method),
    /// A remote request did not satisfy dialog `CSeq` ordering.
    RemoteSequenceOutOfOrder {
        /// Received sequence number.
        received: u32,
        /// Previously accepted remote sequence, if one exists.
        current: Option<u32>,
    },
}

impl fmt::Display for DialogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::SequenceTooLarge {
                role,
                sequence,
                maximum,
            } => write!(
                formatter,
                "{role} dialog sequence {sequence} exceeds maximum {maximum}"
            ),
            Self::LocalSequenceExhausted => formatter.write_str("local dialog CSeq is exhausted"),
            Self::NonIncrementingMethod(method) => {
                write!(formatter, "{method} does not allocate a new dialog CSeq")
            }
            Self::RemoteSequenceOutOfOrder { received, current } => write!(
                formatter,
                "remote dialog CSeq {received} is not valid after {current:?}"
            ),
        }
    }
}

impl StdError for DialogError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::State(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_sequence(sequence: u32, role: DialogSequenceRole) -> Result<(), DialogError> {
    if sequence > MAX_CSEQ_SEQUENCE {
        Err(DialogError::SequenceTooLarge {
            role,
            sequence,
            maximum: MAX_CSEQ_SEQUENCE,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::sip::headers::call_id::CallId;
    use crate::sip::headers::cseq::{CSeq, MAX_CSEQ_SEQUENCE};
    use crate::sip::parser::uri::parse_str;
    use crate::sip::types::method::Method;

    use super::{Dialog, DialogError};
    use crate::sip::dialog::{DialogId, DialogState, RouteSet};

    fn dialog(local_sequence: u32, remote_sequence: Option<u32>) -> Dialog {
        let call_id =
            CallId::new("private-call@example.org").unwrap_or_else(|_| panic!("valid call id"));
        let id = DialogId::new(call_id, "local-secret", "remote-secret")
            .unwrap_or_else(|_| panic!("valid dialog id"));
        let target =
            parse_str("sip:private-user@target.example").unwrap_or_else(|_| panic!("valid target"));
        Dialog::new(
            id,
            DialogState::early(),
            RouteSet::empty(),
            target,
            local_sequence,
            remote_sequence,
        )
        .unwrap_or_else(|_| panic!("valid dialog"))
    }

    #[test]
    fn local_sequence_increments_for_new_requests() {
        let mut dialog = dialog(10, None);
        let Ok(cseq) = dialog.next_local_cseq(Method::Update) else {
            panic!("sequence must advance")
        };
        assert_eq!(cseq.sequence(), 11);
        assert_eq!(cseq.method(), &Method::Update);
        assert_eq!(dialog.local_sequence(), 11);
    }

    #[test]
    fn ack_and_cancel_do_not_allocate_dialog_sequences() {
        let mut dialog = dialog(10, None);
        assert_eq!(
            dialog.next_local_cseq(Method::Ack),
            Err(DialogError::NonIncrementingMethod(Method::Ack))
        );
        assert_eq!(dialog.local_sequence(), 10);
    }

    #[test]
    fn local_sequence_exhaustion_does_not_mutate_state() {
        let mut dialog = dialog(MAX_CSEQ_SEQUENCE, None);
        assert_eq!(
            dialog.next_local_cseq(Method::Bye),
            Err(DialogError::LocalSequenceExhausted)
        );
        assert_eq!(dialog.local_sequence(), MAX_CSEQ_SEQUENCE);
    }

    #[test]
    fn remote_sequence_must_increase_except_ack_cancel() {
        let mut dialog = dialog(10, Some(20));
        let next = CSeq::new(21, Method::Update).unwrap_or_else(|_| panic!("valid cseq"));
        assert_eq!(dialog.accept_remote_cseq(&next), Ok(()));
        let replay = CSeq::new(21, Method::Info).unwrap_or_else(|_| panic!("valid cseq"));
        assert!(matches!(
            dialog.accept_remote_cseq(&replay),
            Err(DialogError::RemoteSequenceOutOfOrder { .. })
        ));
        let ack = CSeq::new(21, Method::Ack).unwrap_or_else(|_| panic!("valid cseq"));
        assert_eq!(dialog.accept_remote_cseq(&ack), Ok(()));
        assert_eq!(dialog.remote_sequence(), Some(21));
    }

    #[test]
    fn terminated_dialog_rejects_mutation_and_routing() {
        let mut dialog = dialog(10, None);
        assert!(dialog.terminate());
        assert!(dialog.routing_plan().is_err());
        assert!(dialog.next_local_cseq(Method::Bye).is_err());
        let target = parse_str("sip:new.example").unwrap_or_else(|_| panic!("valid target"));
        assert!(dialog.update_remote_target(target).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let dialog = dialog(10, None);
        let debug = format!("{dialog:?}");
        assert!(!debug.contains("private-call"));
        assert!(!debug.contains("local-secret"));
        assert!(!debug.contains("remote-secret"));
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("target.example"));
    }
}
