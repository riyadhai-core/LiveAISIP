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

//! Events entering and actions leaving the single call authority.

use super::branch::DialogBranchId;
use super::state::CallEndReason;
use crate::sip::parser::uri::{ParseError as UriParseError, parse_str};
use crate::sip::types::uri::Uri;
use std::error::Error as StdError;
use std::fmt;

/// Generation-fenced reference to another local call actor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CallReference {
    call_id: u64,
    generation: u64,
}

impl CallReference {
    pub(crate) const fn new(call_id: u64, generation: u64) -> Self {
        Self {
            call_id,
            generation,
        }
    }

    /// Returns application call identifier.
    #[must_use]
    pub const fn call_id(self) -> u64 {
        self.call_id
    }

    /// Returns nonreused actor generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Validated SIP or SIPS target for blind transfer.
#[derive(Clone, Eq, PartialEq)]
pub struct TransferTarget(Uri);

impl TransferTarget {
    /// Parses and validates a transfer target.
    ///
    /// # Errors
    ///
    /// Rejects malformed and non-SIP absolute URIs.
    pub fn parse(value: &str) -> Result<Self, TransferTargetError> {
        let uri = parse_str(value).map_err(TransferTargetError::Parse)?;
        if !uri.is_sip() {
            return Err(TransferTargetError::NotSipUri);
        }
        Ok(Self(uri))
    }

    /// Returns the validated target URI.
    #[must_use]
    pub const fn uri(&self) -> &Uri {
        &self.0
    }
}

impl fmt::Debug for TransferTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferTarget")
            .field("scheme", &self.0.scheme())
            .finish_non_exhaustive()
    }
}

/// Transfer-target validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferTargetError {
    /// URI syntax was invalid.
    Parse(UriParseError),
    /// Target used a non-SIP absolute scheme.
    NotSipUri,
}

impl fmt::Display for TransferTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("transfer target is invalid")
    }
}

impl StdError for TransferTargetError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::NotSipUri => None,
        }
    }
}

/// Commands accepted from the Runtime/Python control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallCommand {
    /// Emit the initial INVITE.
    Start,
    /// Cancel an outstanding attempt or BYE an established call.
    Hangup,
    /// Blind transfer to an already validated target handle.
    BlindTransfer {
        /// Validated transfer target.
        target: TransferTarget,
    },
    /// Attended transfer replacing this dialog with another local call.
    AttendedTransfer {
        /// Local call whose dialog supplies Replaces identity.
        other_call: CallReference,
    },
}

/// Serialized network, timer, media and control event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallEvent {
    /// Owner command.
    Command(CallCommand),
    /// Tagged provisional response created/refreshed an early dialog.
    Provisional {
        /// Remote To-tag branch.
        branch: DialogBranchId,
        /// Whether response established usable early media.
        has_sdp: bool,
    },
    /// A branch returned 2xx to INVITE.
    InviteAccepted {
        /// Confirmed remote To-tag branch.
        branch: DialogBranchId,
    },
    /// A branch returned non-2xx final response.
    InviteRejected {
        /// Final response branch.
        branch: DialogBranchId,
        /// Numeric SIP status.
        status: u16,
    },
    /// CANCEL transaction received 2xx; INVITE remains independently pending.
    CancelAccepted,
    /// BYE transaction completed for a branch.
    ByeCompleted {
        /// Cleaned-up confirmed branch.
        branch: DialogBranchId,
    },
    /// Selected remote dialog sent BYE.
    RemoteBye,
    /// Signaling deadline expired.
    SignalingTimedOut,
    /// Media inactivity policy expired.
    MediaTimedOut,
    /// Signaling transport failed.
    TransportFailed,
    /// In-dialog offer/answer request preserving the signaling method.
    SessionModification {
        /// INVITE and UPDATE have distinct transaction/race semantics.
        method: SessionModificationMethod,
        /// Whether this request carries an SDP offer.
        has_offer: bool,
    },
}

/// SIP method initiating an in-dialog session modification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionModificationMethod {
    /// Re-INVITE transaction.
    Invite,
    /// UPDATE transaction.
    Update,
}

/// Explicit side effect produced by deterministic call state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallAction {
    /// Send initial INVITE.
    SendInvite,
    /// Send CANCEL for the initial INVITE transaction.
    SendCancel,
    /// ACK every 2xx branch, including unwanted fork winners.
    SendAck {
        /// Confirmed branch being acknowledged.
        branch: DialogBranchId,
    },
    /// End one confirmed dialog.
    SendBye {
        /// Confirmed branch being terminated.
        branch: DialogBranchId,
    },
    /// Select first usable confirmed branch.
    SelectBranch {
        /// First usable confirmed branch.
        branch: DialogBranchId,
    },
    /// Start or reconfigure early media from one branch.
    ApplyEarlyMedia {
        /// Early dialog whose SDP should be applied.
        branch: DialogBranchId,
    },
    /// Send REFER for blind transfer.
    SendRefer {
        /// Validated transfer target.
        target: TransferTarget,
    },
    /// Send REFER with Replaces for attended transfer.
    SendReferReplaces {
        /// Local call supplying replacement dialog.
        other_call: CallReference,
    },
    /// Deliver explicit re-INVITE/UPDATE negotiation to dialog/media owner.
    ApplySessionModification {
        /// Original SIP method.
        method: SessionModificationMethod,
        /// Whether the request contains an SDP offer.
        has_offer: bool,
    },
    /// Publish stable terminal outcome.
    Ended(CallEndReason),
}
