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

//! RTP session admission and processing failures.

use std::error::Error as StdError;
use std::fmt;

use crate::rtp::dtmf::TelephoneEventError;
use crate::rtp::liveness::MediaLivenessError;
use crate::rtp::packet::rtcp::CompoundRtcpError;
use crate::rtp::packet::rtp::RtpPacketError;
use crate::rtp::queue::QueueError;
use crate::rtp::security::MediaSecurityError;
use crate::rtp::session::receive::RtpStateError;
use crate::rtp::session::rtcp::RtcpSchedulerError;
use crate::rtp::transport::symmetric::SymmetricError;

/// RTP session admission failure.
#[derive(Debug)]
pub enum RtpSessionError {
    /// Security policy rejected packet protection.
    Security(MediaSecurityError),
    /// RTP framing was invalid.
    Packet(RtpPacketError),
    /// Stream state rejected an operation.
    ReceiveState(RtpStateError),
    /// Symmetric endpoint state rejected network source.
    Endpoint(SymmetricError),
    /// Media liveness clock rejected timestamp.
    Liveness(MediaLivenessError),
    /// Queue could not be configured.
    Queue(QueueError),
    /// Compound RTCP parsing or negotiated-policy validation failed.
    CompoundRtcp(CompoundRtcpError),
    /// RTCP scheduling or packet construction failed.
    Rtcp(RtcpSchedulerError),
    /// RTCP was used before session configuration.
    RtcpNotConfigured,
    /// Telephone-event mapping conflicted with negotiated audio.
    InvalidTelephoneEventConfig,
    /// RFC 4733 payload syntax was invalid.
    Dtmf(TelephoneEventError),
    /// Event code was not present in negotiated SDP `fmtp`.
    TelephoneEventNotNegotiated,
    /// Configured preallocated payload limit was invalid.
    InvalidPayloadLimit {
        /// Rejected payload bound.
        value: usize,
        /// Absolute RTP packet ceiling.
        maximum: usize,
    },
    /// Encoded RTP payload exceeded its negotiated/preallocated slot.
    PayloadTooLarge {
        /// Received encoded payload bytes.
        actual: usize,
        /// Configured maximum encoded payload bytes.
        maximum: usize,
    },
    /// Internal queue/pool ownership invariant was exhausted.
    PacketPoolExhausted,
    /// Queue capacity multiplied by slot size exceeded per-session memory policy.
    PacketPoolTooLarge {
        /// Requested preallocated bytes.
        requested: usize,
        /// Hard per-session preallocation ceiling.
        maximum: usize,
    },
    /// Packet-pool setup allocation failed.
    AllocationFailed,
}

impl fmt::Display for RtpSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RTP session processing failed")
    }
}

impl StdError for RtpSessionError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Security(error) => Some(error),
            Self::Packet(error) => Some(error),
            Self::ReceiveState(error) => Some(error),
            Self::Endpoint(error) => Some(error),
            Self::Liveness(error) => Some(error),
            Self::Queue(error) => Some(error),
            Self::CompoundRtcp(error) => Some(error),
            Self::Rtcp(error) => Some(error),
            Self::Dtmf(error) => Some(error),
            Self::AllocationFailed
            | Self::InvalidPayloadLimit { .. }
            | Self::PayloadTooLarge { .. }
            | Self::PacketPoolExhausted
            | Self::PacketPoolTooLarge { .. }
            | Self::RtcpNotConfigured
            | Self::InvalidTelephoneEventConfig
            | Self::TelephoneEventNotNegotiated => None,
        }
    }
}
