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

//! Owned inbound RTP session boundary before `NetEq`.

/// RTP receive-state validation and sequence tracking.
pub mod receive;
/// Call-owned RTCP scheduling and report construction.
pub mod rtcp;

use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use self::receive::{
    AuxiliaryPacketOutcome, ReceivePacketOutcome, RtpReceiveConfig, RtpReceiveState, RtpStateError,
};
use self::rtcp::{RtcpScheduleConfig, RtcpScheduler, RtcpSchedulerError, ScheduledReport};
use super::dtmf::{TelephoneEvent, TelephoneEventError};
use super::liveness::{MediaLiveness, MediaLivenessError};
use super::packet::rtcp::{CompoundPolicy, CompoundRtcp, CompoundRtcpError, Goodbye, RtcpPacket};
use super::packet::rtp::{MAX_RTP_PACKET_BYTES, RtpPacket, RtpPacketError};
use super::queue::{BoundedQueue, OverflowPolicy, PushOutcome, QueueDiagnostics, QueueError};
use super::security::{MediaSecurityError, MediaSecurityPolicy, PacketProtection};
use super::source::{RemoteSourceTracker, SourceObservation, SourcePolicy};
use super::stats::reorder::{DelayedLossSnapshot, DelayedLossTracker};
use super::transport::socket::Component;
use super::transport::symmetric::{SymmetricEndpoints, SymmetricError, SymmetricObservation};
use super::transport::udp::{DatagramClassification, DatagramClassifier};

/// Default packets waiting for immediate `NetEq` insertion.
pub const DEFAULT_INGRESS_QUEUE_PACKETS: usize = 128;
/// Default encoded payload storage reserved for every `NetEq` ingress slot.
pub const DEFAULT_NETEQ_PAYLOAD_BYTES: usize = 2_048;
/// Hard per-session byte ceiling for preallocated encoded packet slots.
pub const MAX_NETEQ_PACKET_POOL_BYTES: usize = 4 * 1_024 * 1_024;

/// Negotiated RFC 4733 stream descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelephoneEventConfig {
    payload_type: u8,
    clock_rate: u32,
    allowed_events: [u64; 4],
}

impl TelephoneEventConfig {
    /// Creates the common keypad event set 0 through 15.
    ///
    /// # Errors
    ///
    /// Rejects invalid payload types or a zero RTP clock rate.
    pub const fn standard(payload_type: u8, clock_rate: u32) -> Result<Self, RtpSessionError> {
        if payload_type > 127 || clock_rate == 0 {
            return Err(RtpSessionError::InvalidTelephoneEventConfig);
        }
        Ok(Self {
            payload_type,
            clock_rate,
            allowed_events: [0xffff, 0, 0, 0],
        })
    }

    /// Creates an event descriptor from a negotiated 256-bit allow set.
    ///
    /// # Errors
    ///
    /// Rejects invalid payload types, a zero clock rate, or an empty event set.
    pub const fn new(
        payload_type: u8,
        clock_rate: u32,
        allowed_events: [u64; 4],
    ) -> Result<Self, RtpSessionError> {
        if payload_type > 127
            || clock_rate == 0
            || (allowed_events[0] | allowed_events[1] | allowed_events[2] | allowed_events[3]) == 0
        {
            return Err(RtpSessionError::InvalidTelephoneEventConfig);
        }
        Ok(Self {
            payload_type,
            clock_rate,
            allowed_events,
        })
    }

    /// Returns negotiated dynamic payload type.
    #[must_use]
    pub const fn payload_type(self) -> u8 {
        self.payload_type
    }

    /// Returns negotiated event timestamp clock.
    #[must_use]
    pub const fn clock_rate(self) -> u32 {
        self.clock_rate
    }

    /// Returns whether one event code was negotiated.
    #[must_use]
    pub const fn allows(self, event: u8) -> bool {
        let word = event as usize / 64;
        let bit = event as usize % 64;
        self.allowed_events[word] & (1_u64 << bit) != 0
    }
}

struct NetEqPacketSlot {
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    payload_type: u8,
    marker: bool,
    payload_length: usize,
    occupied: bool,
}

struct NetEqPacketPool {
    slots: Vec<NetEqPacketSlot>,
    payloads: Box<[u8]>,
    free: Vec<usize>,
    maximum_payload_bytes: usize,
}

impl NetEqPacketPool {
    fn new(queue_capacity: usize, maximum_payload_bytes: usize) -> Result<Self, RtpSessionError> {
        if maximum_payload_bytes == 0 || maximum_payload_bytes > MAX_RTP_PACKET_BYTES {
            return Err(RtpSessionError::InvalidPayloadLimit {
                value: maximum_payload_bytes,
                maximum: MAX_RTP_PACKET_BYTES,
            });
        }
        let slot_count = queue_capacity
            .checked_add(1)
            .ok_or(RtpSessionError::AllocationFailed)?;
        let pool_bytes = slot_count
            .checked_mul(maximum_payload_bytes)
            .ok_or(RtpSessionError::AllocationFailed)?;
        if pool_bytes > MAX_NETEQ_PACKET_POOL_BYTES {
            return Err(RtpSessionError::PacketPoolTooLarge {
                requested: pool_bytes,
                maximum: MAX_NETEQ_PACKET_POOL_BYTES,
            });
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(slot_count)
            .map_err(|_| RtpSessionError::AllocationFailed)?;
        for _ in 0..slot_count {
            slots.push(NetEqPacketSlot {
                sequence_number: 0,
                timestamp: 0,
                ssrc: 0,
                payload_type: 0,
                marker: false,
                payload_length: 0,
                occupied: false,
            });
        }
        let mut payloads = Vec::new();
        payloads
            .try_reserve_exact(pool_bytes)
            .map_err(|_| RtpSessionError::AllocationFailed)?;
        payloads.resize(pool_bytes, 0);
        let mut free = Vec::new();
        free.try_reserve_exact(slot_count)
            .map_err(|_| RtpSessionError::AllocationFailed)?;
        free.extend((0..slot_count).rev());
        Ok(Self {
            slots,
            payloads: payloads.into_boxed_slice(),
            free,
            maximum_payload_bytes,
        })
    }

    fn store(&mut self, packet: &RtpPacket<'_>) -> Result<usize, RtpSessionError> {
        if packet.payload().len() > self.maximum_payload_bytes {
            return Err(RtpSessionError::PayloadTooLarge {
                actual: packet.payload().len(),
                maximum: self.maximum_payload_bytes,
            });
        }
        let index = self
            .free
            .pop()
            .ok_or(RtpSessionError::PacketPoolExhausted)?;
        let slot = &mut self.slots[index];
        if slot.occupied {
            return Err(RtpSessionError::PacketPoolExhausted);
        }
        let header = packet.header();
        slot.sequence_number = header.sequence_number();
        slot.timestamp = header.timestamp();
        slot.ssrc = header.ssrc();
        slot.payload_type = header.payload_type();
        slot.marker = header.marker();
        let payload_start = index * self.maximum_payload_bytes;
        let payload_end = payload_start + packet.payload().len();
        self.payloads[payload_start..payload_end].copy_from_slice(packet.payload());
        slot.payload_length = packet.payload().len();
        slot.occupied = true;
        Ok(index)
    }

    fn release(&mut self, index: usize) {
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };
        if !slot.occupied {
            return;
        }
        slot.payload_length = 0;
        slot.occupied = false;
        self.free.push(index);
    }

    fn packet(&mut self, index: usize) -> Option<NetEqPacket<'_>> {
        self.slots
            .get(index)
            .is_some_and(|slot| slot.occupied)
            .then_some(NetEqPacket { pool: self, index })
    }
}

/// Borrowed checkout of one preallocated packet slot admitted for `NetEq`.
///
/// Dropping this value immediately returns its storage to the owning session.
/// Keeping it alive deliberately keeps the session mutably borrowed, so the
/// receive loop cannot overwrite the payload before `NetEq::InsertPacket`.
pub struct NetEqPacket<'a> {
    pool: &'a mut NetEqPacketPool,
    index: usize,
}

impl NetEqPacket<'_> {
    fn slot(&self) -> &NetEqPacketSlot {
        &self.pool.slots[self.index]
    }

    /// Returns RTP sequence number.
    #[must_use]
    pub fn sequence_number(&self) -> u16 {
        self.slot().sequence_number
    }

    /// Returns RTP timestamp.
    #[must_use]
    pub fn timestamp(&self) -> u32 {
        self.slot().timestamp
    }

    /// Returns synchronization source.
    #[must_use]
    pub fn ssrc(&self) -> u32 {
        self.slot().ssrc
    }

    /// Returns negotiated wire payload type.
    #[must_use]
    pub fn payload_type(&self) -> u8 {
        self.slot().payload_type
    }

    /// Returns RTP marker bit.
    #[must_use]
    pub fn marker(&self) -> bool {
        self.slot().marker
    }

    /// Returns encoded codec payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let slot = self.slot();
        let payload_start = self.index * self.pool.maximum_payload_bytes;
        &self.pool.payloads[payload_start..payload_start + slot.payload_length]
    }
}

impl Drop for NetEqPacket<'_> {
    fn drop(&mut self) {
        self.pool.release(self.index);
    }
}

impl fmt::Debug for NetEqPacket<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let slot = self.slot();
        formatter
            .debug_struct("NetEqPacket")
            .field("payload_type", &slot.payload_type)
            .field("marker", &slot.marker)
            .field("payload_bytes", &slot.payload_length)
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
    /// Negotiated auxiliary payload failed shared source/sequence admission.
    AuxiliaryRejected(AuxiliaryPacketOutcome),
    /// Packet entered the bounded `NetEq` queue.
    Queued {
        /// Symmetric endpoint observation after stream validation.
        endpoint: SymmetricObservation,
    },
    /// Packet was valid but the full ingress queue dropped it.
    QueueDropped,
    /// Negotiated telephone-event was parsed outside the audio/NetEq path.
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

/// One owned receive session with no shared mutable state.
pub struct RtpSession {
    receive_config: RtpReceiveConfig,
    receive: RtpReceiveState,
    source: RemoteSourceTracker,
    endpoints: SymmetricEndpoints,
    classifier: DatagramClassifier,
    security: MediaSecurityPolicy,
    liveness: MediaLiveness,
    ingress: BoundedQueue<usize>,
    packet_pool: NetEqPacketPool,
    source_resets: u64,
    rtcp: Option<RtcpScheduler>,
    rtcp_policy: CompoundPolicy,
    telephone_event: Option<TelephoneEventConfig>,
    delayed_loss: DelayedLossTracker,
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
        Self::new_with_payload_limit(
            receive_config,
            source_policy,
            endpoints,
            security,
            liveness,
            ingress_capacity,
            DEFAULT_NETEQ_PAYLOAD_BYTES,
        )
    }

    /// Creates a bounded session with explicit preallocated payload-slot size.
    ///
    /// # Errors
    ///
    /// Rejects invalid queue/payload bounds and allocation failure.
    pub fn new_with_payload_limit(
        receive_config: RtpReceiveConfig,
        source_policy: SourcePolicy,
        endpoints: SymmetricEndpoints,
        security: MediaSecurityPolicy,
        liveness: MediaLiveness,
        ingress_capacity: usize,
        maximum_payload_bytes: usize,
    ) -> Result<Self, RtpSessionError> {
        let source = RemoteSourceTracker::new(receive_config.expected_ssrc(), source_policy);
        let ingress = BoundedQueue::new(ingress_capacity, OverflowPolicy::DropNewest)
            .map_err(RtpSessionError::Queue)?;
        let packet_pool = NetEqPacketPool::new(ingress_capacity, maximum_payload_bytes)?;
        Ok(Self {
            receive: RtpReceiveState::new(receive_config),
            receive_config,
            source,
            endpoints,
            classifier: DatagramClassifier::default(),
            security,
            liveness,
            ingress,
            packet_pool,
            source_resets: 0,
            rtcp: None,
            rtcp_policy: CompoundPolicy::Strict,
            telephone_event: None,
            delayed_loss: DelayedLossTracker::new(),
        })
    }

    /// Installs negotiated telephone-event routing.
    ///
    /// The event payload type must differ from audio and use the same RTP clock
    /// domain so both streams can safely share sequence/timestamp machinery.
    ///
    /// # Errors
    ///
    /// Rejects an event mapping that collides with audio or uses another clock.
    pub fn configure_telephone_event(
        &mut self,
        config: TelephoneEventConfig,
    ) -> Result<(), RtpSessionError> {
        if config.payload_type() == self.receive_config.payload_type()
            || config.clock_rate() != self.receive_config.clock_rate().get()
        {
            return Err(RtpSessionError::InvalidTelephoneEventConfig);
        }
        self.telephone_event = Some(config);
        Ok(())
    }

    /// Installs or atomically replaces session-owned RTCP scheduling state.
    ///
    /// # Errors
    ///
    /// Preserves RTCP scheduler validation and allocation failures.
    pub fn configure_rtcp(
        &mut self,
        config: RtcpScheduleConfig,
        local_ssrc: u32,
        cname: &[u8],
        policy: CompoundPolicy,
        now: Duration,
    ) -> Result<(), RtpSessionError> {
        let scheduler =
            RtcpScheduler::new(config, local_ssrc, cname, now).map_err(RtpSessionError::Rtcp)?;
        self.rtcp = Some(scheduler);
        self.rtcp_policy = policy;
        Ok(())
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

        if let Some(config) = self.telephone_event
            && header.payload_type() == config.payload_type()
        {
            let auxiliary = self.receive.observe_auxiliary(&packet);
            if !auxiliary.admitted() {
                return Ok(RtpIngressOutcome::AuxiliaryRejected(auxiliary));
            }
            let event = TelephoneEvent::parse(packet.payload()).map_err(RtpSessionError::Dtmf)?;
            if !config.allows(event.code().as_raw()) {
                return Err(RtpSessionError::TelephoneEventNotNegotiated);
            }
            self.delayed_loss.observe(header.sequence_number());
            let endpoint = self
                .endpoints
                .observe_validated_source(Component::Rtp, network_source)
                .map_err(RtpSessionError::Endpoint)?;
            self.liveness
                .note_valid_receive(arrival)
                .map_err(RtpSessionError::Liveness)?;
            return Ok(RtpIngressOutcome::TelephoneEvent { event, endpoint });
        }

        let stream = self
            .receive
            .observe(&packet, arrival)
            .map_err(RtpSessionError::ReceiveState)?;
        if !stream.admitted() {
            return Ok(RtpIngressOutcome::StreamRejected(stream));
        }
        self.delayed_loss.observe(header.sequence_number());
        let endpoint = self
            .endpoints
            .observe_validated_source(Component::Rtp, network_source)
            .map_err(RtpSessionError::Endpoint)?;
        self.liveness
            .note_valid_receive(arrival)
            .map_err(RtpSessionError::Liveness)?;
        let slot = self.packet_pool.store(&packet)?;
        match self.ingress.push(slot) {
            PushOutcome::Accepted => Ok(RtpIngressOutcome::Queued { endpoint }),
            PushOutcome::DroppedNewest(dropped) | PushOutcome::DroppedOldest(dropped) => {
                self.packet_pool.release(dropped);
                Ok(RtpIngressOutcome::QueueDropped)
            }
        }
    }

    /// Processes one already-decrypted/authenticated RTCP-socket datagram.
    ///
    /// # Errors
    ///
    /// Preserves security, compound parsing, endpoint and clock failures.
    pub fn ingest_rtcp(
        &mut self,
        network_source: SocketAddr,
        datagram: &[u8],
        arrival: Duration,
        protection: PacketProtection,
    ) -> Result<RtcpIngressOutcome, RtpSessionError> {
        self.security
            .admit(protection)
            .map_err(RtpSessionError::Security)?;
        let classification = self.classifier.classify(Component::Rtcp, datagram);
        if classification != DatagramClassification::Rtcp {
            return Ok(RtcpIngressOutcome::ClassifiedOut(classification));
        }
        let compound = CompoundRtcp::parse(datagram, self.rtcp_policy)
            .map_err(RtpSessionError::CompoundRtcp)?;
        let active_ssrc = self.source.active_ssrc();
        let primary = compound.packets().iter().find_map(|packet| match packet {
            RtcpPacket::SenderReport(report) => Some(report.sender_ssrc()),
            RtcpPacket::ReceiverReport(report) => Some(report.receiver_ssrc()),
            _ => None,
        });
        if active_ssrc.is_none() || primary != active_ssrc {
            return Ok(RtcpIngressOutcome::SourceRejected);
        }
        let mut sender_report = false;
        for packet in compound.packets() {
            if let RtcpPacket::SenderReport(report) = packet {
                self.receive
                    .note_sender_report(report.sender_info().compact_ntp(), arrival);
                sender_report = true;
            }
        }
        let endpoint = self
            .endpoints
            .observe_validated_source(Component::Rtcp, network_source)
            .map_err(RtpSessionError::Endpoint)?;
        self.liveness
            .note_rtcp_receive(arrival)
            .map_err(RtpSessionError::Liveness)?;
        Ok(RtcpIngressOutcome::Accepted {
            endpoint,
            packet_count: compound.packets().len(),
            sender_report,
        })
    }

    /// Accounts one successfully sent RTP payload for the next Sender Report.
    pub fn note_rtp_sent(&mut self, payload_octets: usize) {
        if let Some(rtcp) = &mut self.rtcp {
            rtcp.note_rtp_sent(payload_octets);
        }
    }

    /// Polls the session-owned RTCP report cadence.
    ///
    /// # Errors
    ///
    /// Rejects polling before RTCP configuration and preserves scheduler errors.
    pub fn poll_rtcp(
        &mut self,
        now: Duration,
        ntp_timestamp: u64,
        rtp_timestamp: u32,
    ) -> Result<Option<ScheduledReport>, RtpSessionError> {
        let rtcp = self
            .rtcp
            .as_mut()
            .ok_or(RtpSessionError::RtcpNotConfigured)?;
        rtcp.poll(now, ntp_timestamp, rtp_timestamp, Some(&mut self.receive))
            .map_err(RtpSessionError::Rtcp)
    }

    /// Builds final RTCP BYE under the session's local SSRC.
    ///
    /// # Errors
    ///
    /// Rejects use before configuration and preserves construction failures.
    pub fn rtcp_goodbye(&self, reason: Option<&[u8]>) -> Result<Goodbye, RtpSessionError> {
        self.rtcp
            .as_ref()
            .ok_or(RtpSessionError::RtcpNotConfigured)?
            .goodbye(reason)
            .map_err(RtpSessionError::Rtcp)
    }

    /// Removes the next admitted packet for immediate `NetEq` insertion.
    ///
    /// The returned checkout borrows this session and returns its slot on drop.
    pub fn pop_neteq_packet(&mut self) -> Option<NetEqPacket<'_>> {
        let slot = self.ingress.pop()?;
        self.packet_pool.packet(slot)
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

    /// Returns reorder-window loss observability independent of RTCP counters.
    #[must_use]
    pub fn delayed_loss(&self) -> DelayedLossSnapshot {
        self.delayed_loss.snapshot()
    }

    fn rebind_receive_state(&mut self, ssrc: u32) -> Result<(), RtpSessionError> {
        let config = RtpReceiveConfig::new(
            self.receive_config.payload_type(),
            self.receive_config.clock_rate(),
            Some(ssrc),
        )
        .map_err(RtpSessionError::ReceiveState)?;
        self.receive = RtpReceiveState::new(config);
        let packet_pool = &mut self.packet_pool;
        self.ingress.clear_with(|slot| packet_pool.release(slot));
        self.source_resets = self.source_resets.saturating_add(1);
        self.delayed_loss = DelayedLossTracker::new();
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
            .field("rtcp_configured", &self.rtcp.is_some())
            .finish_non_exhaustive()
    }
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::{RtcpIngressOutcome, RtpIngressOutcome, RtpSession, TelephoneEventConfig};
    use crate::rtp::clock::RtpClockRate;
    use crate::rtp::liveness::MediaLiveness;
    use crate::rtp::packet::rtcp::{
        CompoundPolicy, CompoundRtcp, RtcpPacket, RtcpSenderInfo, SdesChunk, SdesItem,
        SdesItemType, SenderReport, SourceDescription,
    };
    use crate::rtp::security::{MediaSecurityPolicy, PacketProtection};
    use crate::rtp::session::receive::RtpReceiveConfig;
    use crate::rtp::session::rtcp::{RtcpScheduleConfig, ScheduledReport};
    use crate::rtp::source::SourcePolicy;
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

    fn telephone_event_packet(sequence: u16) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[0] = 0x80;
        bytes[1] = 101;
        bytes[2..4].copy_from_slice(&sequence.to_be_bytes());
        bytes[4..8].copy_from_slice(&160_u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&7_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&[5, 0x80 | 10, 0, 160]);
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
    fn neteq_packet_slots_are_reused_without_hot_path_allocation() {
        let mut session = session(MediaSecurityPolicy::PlainAllowed);
        for sequence in 1..=2 {
            assert!(
                session
                    .ingest_rtp(
                        address(20_000),
                        &packet(sequence),
                        Duration::from_millis(u64::from(sequence) * 10),
                        PacketProtection::Plain,
                    )
                    .is_ok()
            );
        }
        let Some(first) = session.pop_neteq_packet() else {
            panic!("first packet")
        };
        assert_eq!(first.payload(), &[0x55]);
        let payload_pointer = first.payload().as_ptr();
        drop(first);

        assert!(matches!(
            session.ingest_rtp(
                address(20_000),
                &packet(3),
                Duration::from_millis(30),
                PacketProtection::Plain,
            ),
            Ok(RtpIngressOutcome::Queued { .. })
        ));
        let Some(second) = session.pop_neteq_packet() else {
            panic!("second packet")
        };
        assert_eq!(second.payload().as_ptr(), payload_pointer);
        assert_eq!(second.sequence_number(), 3);
    }

    #[test]
    fn explicit_packet_slot_payload_bound_is_enforced_before_copy() {
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
        let Ok(mut session) = RtpSession::new_with_payload_limit(
            receive,
            SourcePolicy::default(),
            endpoints,
            MediaSecurityPolicy::PlainAllowed,
            liveness,
            1,
            1,
        ) else {
            panic!("session")
        };
        let mut oversized = [0_u8; 14];
        oversized[..12].copy_from_slice(&packet(1)[..12]);
        oversized[12..].copy_from_slice(&[1, 2]);
        assert!(
            session
                .ingest_rtp(
                    address(20_000),
                    &oversized,
                    Duration::from_millis(10),
                    PacketProtection::Plain,
                )
                .is_ok()
        );
        oversized[2..4].copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            session.ingest_rtp(
                address(20_000),
                &oversized,
                Duration::from_millis(20),
                PacketProtection::Plain,
            ),
            Err(super::RtpSessionError::PayloadTooLarge {
                actual: 2,
                maximum: 1
            })
        ));
        assert_eq!(session.ingress_diagnostics().depth, 0);
    }

    #[test]
    fn packet_pool_rejects_excessive_total_preallocation_before_allocating() {
        assert!(matches!(
            super::NetEqPacketPool::new(65_536, 2_048),
            Err(super::RtpSessionError::PacketPoolTooLarge { .. })
        ));
        assert!(matches!(
            super::NetEqPacketPool::new(1, 0),
            Err(super::RtpSessionError::InvalidPayloadLimit { .. })
        ));
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

    #[test]
    fn negotiated_telephone_event_never_enters_neteq_audio_queue() {
        let mut session = session(MediaSecurityPolicy::PlainAllowed);
        session
            .configure_telephone_event(
                TelephoneEventConfig::standard(101, 8_000)
                    .unwrap_or_else(|_| panic!("event config")),
            )
            .unwrap_or_else(|_| panic!("configure"));
        for sequence in 1..=2 {
            assert!(
                session
                    .ingest_rtp(
                        address(20_000),
                        &packet(sequence),
                        Duration::from_millis(u64::from(sequence) * 10),
                        PacketProtection::Plain,
                    )
                    .is_ok()
            );
        }
        let depth = session.ingress_diagnostics().depth;
        assert!(matches!(
            session.ingest_rtp(
                address(20_000),
                &telephone_event_packet(3),
                Duration::from_millis(30),
                PacketProtection::Plain,
            ),
            Ok(RtpIngressOutcome::TelephoneEvent { event, .. }) if event.digit().is_some()
        ));
        assert_eq!(session.ingress_diagnostics().depth, depth);
    }

    #[test]
    fn session_owns_rtcp_ingress_timing_and_report_schedule() {
        let mut session = session(MediaSecurityPolicy::PlainAllowed);
        for sequence in 1..=3 {
            assert!(
                session
                    .ingest_rtp(
                        address(20_000),
                        &packet(sequence),
                        Duration::from_millis(u64::from(sequence) * 10),
                        PacketProtection::Plain,
                    )
                    .is_ok()
            );
        }
        session
            .configure_rtcp(
                RtcpScheduleConfig::default(),
                9,
                b"runtime@example.invalid",
                CompoundPolicy::Strict,
                Duration::ZERO,
            )
            .unwrap_or_else(|_| panic!("RTCP config"));

        let sender = SenderReport::new(
            7,
            RtcpSenderInfo::new(0x0001_0002_0003_0004, 240, 3, 3),
            &[],
            0,
        )
        .unwrap_or_else(|_| panic!("sender report"));
        let item = SdesItem::new(SdesItemType::CanonicalName, b"remote@example.invalid")
            .unwrap_or_else(|_| panic!("item"));
        let chunk = SdesChunk::new(7, &[item]).unwrap_or_else(|_| panic!("chunk"));
        let description =
            SourceDescription::new(&[chunk], 0).unwrap_or_else(|_| panic!("description"));
        let compound = CompoundRtcp::new(
            &[
                RtcpPacket::SenderReport(sender),
                RtcpPacket::SourceDescription(description),
            ],
            CompoundPolicy::Strict,
        )
        .unwrap_or_else(|_| panic!("compound"))
        .encode()
        .unwrap_or_else(|_| panic!("encode"));
        assert!(matches!(
            session.ingest_rtcp(
                address(20_001),
                &compound,
                Duration::from_secs(1),
                PacketProtection::Plain,
            ),
            Ok(RtcpIngressOutcome::Accepted {
                sender_report: true,
                packet_count: 2,
                ..
            })
        ));
        assert!(matches!(
            session.poll_rtcp(Duration::from_secs(5), 0, 400),
            Ok(Some(ScheduledReport::Receiver { .. }))
        ));
        session.note_rtp_sent(160);
        assert!(matches!(
            session.poll_rtcp(Duration::from_secs(10), 1, 800),
            Ok(Some(ScheduledReport::Sender { .. }))
        ));
        assert!(session.rtcp_goodbye(Some(b"normal")).is_ok());
    }
}
