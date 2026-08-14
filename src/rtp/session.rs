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

//! `LiveAISIP`.
//!
//! A high-performance SIP server developed by `RiyadhAI LLC` for large-scale
//! realtime AI telephony workloads.

//! Owned inbound RTP session boundary before `NetEq`.

use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use super::liveness::{MediaLiveness, MediaLivenessError};
use super::packet::rtp::{RtpPacket, RtpPacketError};
use super::queue::{BoundedQueue, OverflowPolicy, PushOutcome, QueueDiagnostics, QueueError};
use super::security::{MediaSecurityError, MediaSecurityPolicy, PacketProtection};
use super::source::{RemoteSourceTracker, SourceObservation, SourcePolicy};
use super::state::{ReceivePacketOutcome, RtpReceiveConfig, RtpReceiveState, RtpStateError};
use super::transport::socket::Component;
use super::transport::symmetric::{SymmetricEndpoints, SymmetricError, SymmetricObservation};
use super::transport::udp::{DatagramClassification, DatagramClassifier};

/// Default packets waiting for immediate `NetEq` insertion.
pub const DEFAULT_INGRESS_QUEUE_PACKETS: usize = 128;

/// Owned packet metadata and payload admitted for `NetEq` insertion.
pub struct NetEqPacket {
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    payload_type: u8,
    marker: bool,
    payload: Box<[u8]>,
}

impl NetEqPacket {
    /// Returns RTP sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u16 {
        self.sequence_number
    }

    /// Returns RTP timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Returns synchronization source.
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Returns negotiated wire payload type.
    #[must_use]
    pub const fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Returns RTP marker bit.
    #[must_use]
    pub const fn marker(&self) -> bool {
        self.marker
    }

    /// Returns encoded codec payload.
    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl fmt::Debug for NetEqPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetEqPacket")
            .field("payload_type", &self.payload_type)
            .field("marker", &self.marker)
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

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
    /// Packet entered the bounded `NetEq` queue.
    Queued {
        /// Symmetric endpoint observation after stream validation.
        endpoint: SymmetricObservation,
    },
    /// Packet was valid but the full ingress queue dropped it.
    QueueDropped,
}

/// One owned receive session with no shared mutable state.
pub struct RtpSession {
    receive_config: RtpReceiveConfig,
    receive: RtpReceiveState,
    source: RemoteSourceTracker,
    endpoints: SymmetricEndpoints,
    classifier: DatagramClassifier,
    security: MediaSecurityPolicy,
    liveness: MediaLiveness,
    ingress: BoundedQueue<NetEqPacket>,
    source_resets: u64,
}

impl RtpSession {
    /// Creates a bounded inbound media session.
    ///
    /// # Errors
    ///
    /// Preserves queue configuration failure.
    pub fn new(
        receive_config: RtpReceiveConfig,
        source_policy: SourcePolicy,
        endpoints: SymmetricEndpoints,
        security: MediaSecurityPolicy,
        liveness: MediaLiveness,
        ingress_capacity: usize,
    ) -> Result<Self, RtpSessionError> {
        let source = RemoteSourceTracker::new(receive_config.expected_ssrc(), source_policy);
        Ok(Self {
            receive: RtpReceiveState::new(receive_config),
            receive_config,
            source,
            endpoints,
            classifier: DatagramClassifier::default(),
            security,
            liveness,
            ingress: BoundedQueue::new(ingress_capacity, OverflowPolicy::DropNewest)
                .map_err(RtpSessionError::Queue)?,
            source_resets: 0,
        })
    }

    /// Processes one already-decrypted/authenticated RTP-socket datagram.
    ///
    /// # Errors
    ///
    /// Preserves security, RTP parsing, stream state, endpoint, clock and
    /// bounded-allocation failures. State changes occur only after each
    /// corresponding validation boundary succeeds.
    pub fn ingest_rtp(
        &mut self,
        network_source: SocketAddr,
        datagram: &[u8],
        arrival: Duration,
        protection: PacketProtection,
    ) -> Result<RtpIngressOutcome, RtpSessionError> {
        self.security
            .admit(protection)
            .map_err(RtpSessionError::Security)?;
        let classification = self.classifier.classify(Component::Rtp, datagram);
        if classification != DatagramClassification::Rtp {
            return Ok(RtpIngressOutcome::ClassifiedOut(classification));
        }
        let packet = RtpPacket::parse(datagram).map_err(RtpSessionError::Packet)?;
        let header = packet.header();
        let source = self.source.observe(header.ssrc(), header.sequence_number());
        match source {
            SourceObservation::Probation { .. } => return Ok(RtpIngressOutcome::SourceProbation),
            SourceObservation::Rejected => return Ok(RtpIngressOutcome::SourceRejected),
            SourceObservation::Switched => {
                self.rebind_receive_state(header.ssrc())?;
                return Ok(RtpIngressOutcome::SourceSwitched);
            }
            SourceObservation::Bound => self.rebind_receive_state(header.ssrc())?,
            SourceObservation::Current => {}
        }

        let stream = self
            .receive
            .observe(&packet, arrival)
            .map_err(RtpSessionError::ReceiveState)?;
        if !stream.admitted() {
            return Ok(RtpIngressOutcome::StreamRejected(stream));
        }
        let endpoint = self
            .endpoints
            .observe_validated_source(Component::Rtp, network_source)
            .map_err(RtpSessionError::Endpoint)?;
        self.liveness
            .note_valid_receive(arrival)
            .map_err(RtpSessionError::Liveness)?;
        let owned = own_packet(&packet)?;
        match self.ingress.push(owned) {
            PushOutcome::Accepted => Ok(RtpIngressOutcome::Queued { endpoint }),
            PushOutcome::DroppedNewest(_) | PushOutcome::DroppedOldest(_) => {
                Ok(RtpIngressOutcome::QueueDropped)
            }
        }
    }

    /// Removes the next admitted packet for immediate `NetEq` insertion.
    pub fn pop_neteq_packet(&mut self) -> Option<NetEqPacket> {
        self.ingress.pop()
    }

    /// Returns current send destination after validated symmetric learning.
    #[must_use]
    pub const fn remote_rtp_destination(&self) -> SocketAddr {
        self.endpoints.destination(Component::Rtp)
    }

    /// Returns ingress queue diagnostics.
    #[must_use]
    pub fn ingress_diagnostics(&self) -> QueueDiagnostics {
        self.ingress.diagnostics()
    }

    /// Returns accepted SSRC reset count.
    #[must_use]
    pub const fn source_resets(&self) -> u64 {
        self.source_resets
    }

    fn rebind_receive_state(&mut self, ssrc: u32) -> Result<(), RtpSessionError> {
        let config = RtpReceiveConfig::new(
            self.receive_config.payload_type(),
            self.receive_config.clock_rate(),
            Some(ssrc),
        )
        .map_err(RtpSessionError::ReceiveState)?;
        self.receive = RtpReceiveState::new(config);
        self.ingress.clear();
        self.source_resets = self.source_resets.saturating_add(1);
        Ok(())
    }
}

impl fmt::Debug for RtpSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtpSession")
            .field("receive_config", &self.receive_config)
            .field("source", &self.source)
            .field("endpoints", &self.endpoints)
            .field("security", &self.security)
            .field("ingress", &self.ingress.diagnostics())
            .field("source_resets", &self.source_resets)
            .finish_non_exhaustive()
    }
}

fn own_packet(packet: &RtpPacket<'_>) -> Result<NetEqPacket, RtpSessionError> {
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(packet.payload().len())
        .map_err(|_| RtpSessionError::AllocationFailed)?;
    payload.extend_from_slice(packet.payload());
    let header = packet.header();
    Ok(NetEqPacket {
        sequence_number: header.sequence_number(),
        timestamp: header.timestamp(),
        ssrc: header.ssrc(),
        payload_type: header.payload_type(),
        marker: header.marker(),
        payload: payload.into_boxed_slice(),
    })
}

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
    /// Packet payload ownership allocation failed.
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
            Self::AllocationFailed => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::{RtpIngressOutcome, RtpSession};
    use crate::rtp::clock::RtpClockRate;
    use crate::rtp::liveness::MediaLiveness;
    use crate::rtp::security::{MediaSecurityPolicy, PacketProtection};
    use crate::rtp::source::SourcePolicy;
    use crate::rtp::state::RtpReceiveConfig;
    use crate::rtp::transport::symmetric::{SymmetricConfig, SymmetricEndpoints};

    fn address(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn session(security: MediaSecurityPolicy) -> RtpSession {
        let Ok(clock) = RtpClockRate::new(8_000) else {
            panic!("clock")
        };
        let Ok(receive) = RtpReceiveConfig::new(0, clock, Some(7)) else {
            panic!("receive")
        };
        let Ok(endpoints) =
            SymmetricEndpoints::new(address(10_000), address(10_001), SymmetricConfig::default())
        else {
            panic!("endpoints")
        };
        let Ok(liveness) = MediaLiveness::new(
            Duration::ZERO,
            Duration::from_secs(5),
            Duration::from_secs(10),
        ) else {
            panic!("liveness")
        };
        let Ok(session) = RtpSession::new(
            receive,
            SourcePolicy::default(),
            endpoints,
            security,
            liveness,
            1,
        ) else {
            panic!("session")
        };
        session
    }

    fn packet(sequence: u16) -> [u8; 13] {
        let mut bytes = [0_u8; 13];
        bytes[0] = 0x80;
        bytes[1] = 0;
        bytes[2..4].copy_from_slice(&sequence.to_be_bytes());
        bytes[4..8].copy_from_slice(&(u32::from(sequence) * 80).to_be_bytes());
        bytes[8..12].copy_from_slice(&7_u32.to_be_bytes());
        bytes[12] = 0x55;
        bytes
    }

    #[test]
    fn secure_session_refuses_plain_packet_without_downgrade() {
        let mut session = session(MediaSecurityPolicy::SecureRequired);
        assert!(
            session
                .ingest_rtp(
                    address(20_000),
                    &packet(1),
                    Duration::ZERO,
                    PacketProtection::Plain
                )
                .is_err()
        );
        assert_eq!(session.ingress_diagnostics().depth, 0);
    }

    #[test]
    fn admitted_packets_are_bounded_before_neteq() {
        let mut session = session(MediaSecurityPolicy::PlainAllowed);
        for sequence in 1..=3 {
            let result = session.ingest_rtp(
                address(20_000),
                &packet(sequence),
                Duration::from_millis(u64::from(sequence) * 10),
                PacketProtection::Plain,
            );
            assert!(result.is_ok());
        }
        assert_eq!(session.ingress_diagnostics().depth, 1);
        assert!(session.pop_neteq_packet().is_some());
        assert!(session.pop_neteq_packet().is_none());
        assert_eq!(session.ingress_diagnostics().underflows, 1);
    }

    #[test]
    fn non_rtp_bytes_stop_at_classifier() {
        let mut session = session(MediaSecurityPolicy::PlainAllowed);
        assert!(matches!(
            session.ingest_rtp(
                address(20_000),
                &[0, 1],
                Duration::ZERO,
                PacketProtection::Plain
            ),
            Ok(RtpIngressOutcome::ClassifiedOut(_))
        ));
    }
}
