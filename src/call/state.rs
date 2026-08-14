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

//! Stable call lifecycle and termination classifications.

/// Actor-owned outbound call lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallState {
    /// Constructed but INVITE not emitted.
    Idle,
    /// Initial INVITE is outstanding.
    Inviting,
    /// CANCEL was requested while INVITE final response remains outstanding.
    Cancelling,
    /// One selected confirmed dialog carries the call.
    Established,
    /// BYE cleanup is in progress.
    Terminating,
    /// Terminal state with stable reason.
    Ended(CallEndReason),
}

impl CallState {
    /// Returns whether no further call mutation is valid.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ended(_))
    }
}

/// SDK-stable reason independent of carrier-specific text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallEndReason {
    /// Remote endpoint reported busy.
    RemoteBusy,
    /// Remote endpoint rejected the call.
    RemoteRejected,
    /// No usable target or service was available.
    RemoteUnavailable,
    /// No final answer arrived before policy deadline.
    NoAnswer,
    /// Outbound attempt was canceled before use.
    Canceled,
    /// Local owner ended an established call.
    LocalHangup,
    /// Remote endpoint sent BYE.
    RemoteHangup,
    /// SIP transaction/dialog deadline expired.
    SignalingTimeout,
    /// Network transport failed.
    TransportFailure,
    /// Authentication could not be completed.
    AuthenticationFailed,
    /// Valid media became inactive.
    MediaTimeout,
    /// SDP or codec negotiation failed.
    MediaNegotiationFailed,
    /// Media protection could not satisfy policy.
    SecurityFailure,
    /// Internal invariant or resource failed.
    InternalError,
    /// Transfer completed and replaced this call.
    Transferred,
}

/// Maps final INVITE status into an SDK-stable reason.
#[must_use]
pub const fn reason_from_status(status: u16) -> CallEndReason {
    match status {
        401 | 407 => CallEndReason::AuthenticationFailed,
        404 | 410 | 480 | 502 | 503 | 504 => CallEndReason::RemoteUnavailable,
        408 => CallEndReason::NoAnswer,
        486 | 600 => CallEndReason::RemoteBusy,
        487 => CallEndReason::Canceled,
        _ => CallEndReason::RemoteRejected,
    }
}
