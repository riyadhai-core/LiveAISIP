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

//! Events entering and actions leaving the single call authority.

use super::leg::DialogBranchId;
use super::state::CallEndReason;

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
        target: Box<str>,
    },
    /// Attended transfer replacing this dialog with another local call.
    AttendedTransfer {
        /// Local call whose dialog supplies Replaces identity.
        other_call: u64,
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
        target: Box<str>,
    },
    /// Send REFER with Replaces for attended transfer.
    SendReferReplaces {
        /// Local call supplying replacement dialog.
        other_call: u64,
    },
    /// Publish stable terminal outcome.
    Ended(CallEndReason),
}
