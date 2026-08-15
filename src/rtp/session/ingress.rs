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

//! Typed outcomes at the RTP and RTCP session ingress boundaries.

use crate::rtp::dtmf::TelephoneEvent;
use crate::rtp::session::receive::{AuxiliaryPacketOutcome, ReceivePacketOutcome};
use crate::rtp::transport::symmetric::SymmetricObservation;
use crate::rtp::transport::udp::DatagramClassification;

/// Result of one RTP datagram at the session boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtpIngressOutcome {
    /// Datagram was not RTP-family media.
    ClassifiedOut(DatagramClassification),
    /// Packet is waiting for SSRC probation.
    SourceProbation,
    /// Packet attempted an unauthorized SSRC switch.
    SourceRejected,
    /// Source switched; downstream source-specific state must reset.
    SourceSwitched,
    /// Packet failed payload, SSRC or sequence admission.
    StreamRejected(ReceivePacketOutcome),
    /// Negotiated auxiliary payload failed shared source/sequence admission.
    AuxiliaryRejected(AuxiliaryPacketOutcome),
    /// Packet entered the bounded playout-ingress queue.
    Queued {
        /// Symmetric endpoint observation after stream validation.
        endpoint: SymmetricObservation,
    },
    /// Packet was valid but the full ingress queue dropped it.
    QueueDropped,
    /// Negotiated telephone-event was parsed outside the audio playout path.
    TelephoneEvent {
        /// Exact RFC 4733 payload.
        event: TelephoneEvent,
        /// Symmetric endpoint observation after authentication and source validation.
        endpoint: SymmetricObservation,
    },
}

/// Result of one RTCP datagram at the session boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtcpIngressOutcome {
    /// Datagram was not RTCP-family control traffic.
    ClassifiedOut(DatagramClassification),
    /// Primary RTCP source did not match the active RTP source.
    SourceRejected,
    /// Valid control packets updated session state.
    Accepted {
        /// Symmetric RTCP endpoint observation.
        endpoint: SymmetricObservation,
        /// Number of packets in the compound datagram.
        packet_count: usize,
        /// Whether a Sender Report refreshed LSR/DLSR timing.
        sender_report: bool,
    },
}
