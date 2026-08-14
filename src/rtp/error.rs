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

//! Public RTP subsystem error envelope and low-cardinality classification.
//!
//! Detailed protocol, session, transport, and allocator errors remain owned by
//! their modules. [`RtpError`] preserves those concrete sources while giving
//! runtime code one stable boundary for metrics and lifecycle decisions.
//!
//! The envelope's `Debug` and `Display` implementations intentionally expose
//! only classifications. They never format packet bytes, RTP identifiers,
//! socket addresses, port ranges, CNAMEs, or operating-system error messages.

use std::error::Error as StdError;
use std::fmt;
use std::io;

use super::liveness::MediaLivenessError;
use super::packet::RtpPacketError;
use super::packet::rtcp::CompoundRtcpError;
use super::queue::QueueError;
use super::rtcp_scheduler::RtcpSchedulerError;
use super::session::RtpSessionError;
use super::state::RtpStateError;
use super::transport::allocator::PortAllocationError;
use super::transport::socket::SocketError;
use super::transport::symmetric::SymmetricError;

/// Convenience result type for end-to-end RTP subsystem operations.
pub type Result<T> = std::result::Result<T, RtpError>;

/// Subsystem layer that produced an [`RtpError`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RtpErrorLayer {
    /// RTP data-packet parsing, construction, or serialization.
    DataPacket,
    /// Compound RTCP parsing, construction, or validation.
    ControlPacket,
    /// Stateful RTP/RTCP session processing.
    Session,
    /// UDP socket binding, configuration, receive, or send.
    Transport,
    /// RTP/RTCP port-pair allocation and lifecycle.
    PortAllocator,
}

impl RtpErrorLayer {
    /// Returns a stable label suitable for structured diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DataPacket => "data-packet",
            Self::ControlPacket => "control-packet",
            Self::Session => "session",
            Self::Transport => "transport",
            Self::PortAllocator => "port-allocator",
        }
    }
}

impl fmt::Display for RtpErrorLayer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable operational class independent of detailed protocol error variants.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RtpErrorClass {
    /// Configuration or negotiated parameters were invalid.
    InvalidConfiguration,
    /// An RTP or RTCP datagram was malformed or exceeded framing bounds.
    InvalidDatagram,
    /// Security, endpoint, or negotiation policy rejected an input.
    PolicyRejected,
    /// Stateful processing was requested at an invalid time or generation.
    InvalidState,
    /// A bounded allocation, queue, or packet pool could not be obtained.
    ResourceExhausted,
    /// An operating-system transport operation failed.
    TransportIo,
}

impl RtpErrorClass {
    /// Returns a stable low-cardinality label for metrics and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid-configuration",
            Self::InvalidDatagram => "invalid-datagram",
            Self::PolicyRejected => "policy-rejected",
            Self::InvalidState => "invalid-state",
            Self::ResourceExhausted => "resource-exhausted",
            Self::TransportIo => "transport-io",
        }
    }
}

impl fmt::Display for RtpErrorClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// End-to-end RTP subsystem failure preserving its typed owner error.
#[non_exhaustive]
pub enum RtpError {
    /// RTP data-packet failure.
    DataPacket(RtpPacketError),
    /// Compound RTCP packet failure.
    ControlPacket(CompoundRtcpError),
    /// Stateful RTP session failure.
    Session(RtpSessionError),
    /// RTP/RTCP datagram transport failure.
    Transport(SocketError),
    /// RTP/RTCP port allocation failure.
    PortAllocation(PortAllocationError),
}

impl RtpError {
    /// Returns the subsystem layer that owns the detailed failure.
    #[must_use]
    pub const fn layer(&self) -> RtpErrorLayer {
        match self {
            Self::DataPacket(_) => RtpErrorLayer::DataPacket,
            Self::ControlPacket(_) => RtpErrorLayer::ControlPacket,
            Self::Session(_) => RtpErrorLayer::Session,
            Self::Transport(_) => RtpErrorLayer::Transport,
            Self::PortAllocation(_) => RtpErrorLayer::PortAllocator,
        }
    }

    /// Returns a stable operational failure class.
    #[must_use]
    pub const fn class(&self) -> RtpErrorClass {
        match self {
            Self::DataPacket(error) => classify_rtp_packet(error),
            Self::ControlPacket(error) => classify_rtcp_packet(error),
            Self::Session(error) => classify_session(error),
            Self::Transport(error) => classify_transport(error),
            Self::PortAllocation(error) => classify_port_allocation(*error),
        }
    }

    /// Returns the underlying operating-system error kind when available.
    ///
    /// This intentionally omits the operating-system message because that text
    /// may contain local or remote endpoint data.
    #[must_use]
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Transport(error) => error.io_kind(),
            _ => None,
        }
    }

    /// Returns whether the failure is an ordinary nonblocking readiness miss.
    #[must_use]
    pub fn is_would_block(&self) -> bool {
        self.io_kind() == Some(io::ErrorKind::WouldBlock)
    }
}

impl fmt::Debug for RtpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtpError")
            .field("layer", &self.layer())
            .field("class", &self.class())
            .field("io_kind", &self.io_kind())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RtpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RTP {} failure ({})", self.layer(), self.class())
    }
}

impl StdError for RtpError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::DataPacket(source) => Some(source),
            Self::ControlPacket(source) => Some(source),
            Self::Session(source) => Some(source),
            Self::Transport(source) => Some(source),
            Self::PortAllocation(source) => Some(source),
        }
    }
}

impl From<RtpPacketError> for RtpError {
    fn from(error: RtpPacketError) -> Self {
        Self::DataPacket(error)
    }
}

impl From<CompoundRtcpError> for RtpError {
    fn from(error: CompoundRtcpError) -> Self {
        Self::ControlPacket(error)
    }
}

impl From<RtpSessionError> for RtpError {
    fn from(error: RtpSessionError) -> Self {
        Self::Session(error)
    }
}

impl From<SocketError> for RtpError {
    fn from(error: SocketError) -> Self {
        Self::Transport(error)
    }
}

impl From<PortAllocationError> for RtpError {
    fn from(error: PortAllocationError) -> Self {
        Self::PortAllocation(error)
    }
}

const fn classify_rtp_packet(error: &RtpPacketError) -> RtpErrorClass {
    match error {
        RtpPacketError::AllocationFailed => RtpErrorClass::ResourceExhausted,
        RtpPacketError::Header(_)
        | RtpPacketError::Extension(_)
        | RtpPacketError::PacketTooLarge { .. }
        | RtpPacketError::LengthOverflow
        | RtpPacketError::MissingPaddingLength
        | RtpPacketError::ZeroPaddingLength
        | RtpPacketError::PaddingExceedsBody { .. } => RtpErrorClass::InvalidDatagram,
    }
}

const fn classify_rtcp_packet(error: &CompoundRtcpError) -> RtpErrorClass {
    match error {
        CompoundRtcpError::AllocationFailed => RtpErrorClass::ResourceExhausted,
        CompoundRtcpError::EmptyDatagram
        | CompoundRtcpError::DatagramNotWordAligned { .. }
        | CompoundRtcpError::DatagramTooLarge { .. }
        | CompoundRtcpError::TooManyPackets { .. }
        | CompoundRtcpError::Header(_)
        | CompoundRtcpError::PacketHeader { .. }
        | CompoundRtcpError::TypedPacket { .. }
        | CompoundRtcpError::SenderReport(_)
        | CompoundRtcpError::ReceiverReport(_)
        | CompoundRtcpError::SourceDescription(_)
        | CompoundRtcpError::Goodbye(_)
        | CompoundRtcpError::PaddingBeforeFinalPacket { .. }
        | CompoundRtcpError::StrictFirstPacketMustBeReport
        | CompoundRtcpError::MissingPrimaryCanonicalName
        | CompoundRtcpError::LengthOverflow => RtpErrorClass::InvalidDatagram,
    }
}

const fn classify_session(error: &RtpSessionError) -> RtpErrorClass {
    match error {
        RtpSessionError::Security(_) | RtpSessionError::TelephoneEventNotNegotiated => {
            RtpErrorClass::PolicyRejected
        }
        RtpSessionError::Packet(_)
        | RtpSessionError::CompoundRtcp(_)
        | RtpSessionError::Dtmf(_)
        | RtpSessionError::PayloadTooLarge { .. } => RtpErrorClass::InvalidDatagram,
        RtpSessionError::ReceiveState(error) => classify_receive_state(error),
        RtpSessionError::Endpoint(error) => classify_symmetric(*error),
        RtpSessionError::Liveness(error) => classify_liveness(*error),
        RtpSessionError::Queue(error) => classify_queue(error),
        RtpSessionError::Rtcp(error) => classify_rtcp_scheduler(error),
        RtpSessionError::RtcpNotConfigured | RtpSessionError::PacketPoolExhausted => {
            RtpErrorClass::InvalidState
        }
        RtpSessionError::InvalidTelephoneEventConfig
        | RtpSessionError::InvalidPayloadLimit { .. }
        | RtpSessionError::PacketPoolTooLarge { .. } => RtpErrorClass::InvalidConfiguration,
        RtpSessionError::AllocationFailed => RtpErrorClass::ResourceExhausted,
    }
}

const fn classify_receive_state(error: &RtpStateError) -> RtpErrorClass {
    match error {
        RtpStateError::PayloadTypeOutOfRange { .. } | RtpStateError::Clock(_) => {
            RtpErrorClass::InvalidConfiguration
        }
        RtpStateError::SourceNotBound
        | RtpStateError::SourceNotValidated
        | RtpStateError::TimeMovedBackwards
        | RtpStateError::ReceptionReport(_) => RtpErrorClass::InvalidState,
    }
}

const fn classify_symmetric(error: SymmetricError) -> RtpErrorClass {
    match error {
        SymmetricError::SourceAddressFamilyMismatch { .. } => RtpErrorClass::PolicyRejected,
        SymmetricError::ZeroInitialLatchThreshold
        | SymmetricError::ZeroPortRebindThreshold
        | SymmetricError::MixedAddressFamilies
        | SymmetricError::PortZero { .. }
        | SymmetricError::UnspecifiedAddress { .. }
        | SymmetricError::MulticastAddress { .. }
        | SymmetricError::BroadcastAddress { .. } => RtpErrorClass::InvalidConfiguration,
    }
}

const fn classify_liveness(error: MediaLivenessError) -> RtpErrorClass {
    match error {
        MediaLivenessError::ZeroTimeout | MediaLivenessError::InactivityBeforeReceiveTimeout => {
            RtpErrorClass::InvalidConfiguration
        }
        MediaLivenessError::ClockMovedBackward => RtpErrorClass::InvalidState,
    }
}

const fn classify_queue(error: &QueueError) -> RtpErrorClass {
    match error {
        QueueError::InvalidCapacity { .. } => RtpErrorClass::InvalidConfiguration,
        QueueError::AllocationFailed => RtpErrorClass::ResourceExhausted,
    }
}

const fn classify_rtcp_scheduler(error: &RtcpSchedulerError) -> RtpErrorClass {
    match error {
        RtcpSchedulerError::ZeroInterval | RtcpSchedulerError::InvalidCname => {
            RtpErrorClass::InvalidConfiguration
        }
        RtcpSchedulerError::AllocationFailed => RtpErrorClass::ResourceExhausted,
        RtcpSchedulerError::TimeOverflow
        | RtcpSchedulerError::ReceiveState(_)
        | RtcpSchedulerError::SenderReport(_)
        | RtcpSchedulerError::ReceiverReport(_)
        | RtcpSchedulerError::SourceDescription(_)
        | RtcpSchedulerError::Goodbye(_) => RtpErrorClass::InvalidState,
    }
}

const fn classify_transport(error: &SocketError) -> RtpErrorClass {
    match error {
        SocketError::InvalidDatagramLimit { .. }
        | SocketError::ZeroTimeout
        | SocketError::TimeoutOnNonblockingSocket
        | SocketError::BufferLimitMismatch { .. }
        | SocketError::EmptyDatagram { .. }
        | SocketError::DestinationPortZero { .. } => RtpErrorClass::InvalidConfiguration,
        SocketError::AllocationFailed => RtpErrorClass::ResourceExhausted,
        SocketError::DatagramTooLarge { .. } => RtpErrorClass::InvalidDatagram,
        SocketError::Bind { .. }
        | SocketError::Configure { .. }
        | SocketError::LocalAddress { .. }
        | SocketError::Receive { .. }
        | SocketError::Send { .. }
        | SocketError::PartialDatagram { .. } => RtpErrorClass::TransportIo,
    }
}

const fn classify_port_allocation(error: PortAllocationError) -> RtpErrorClass {
    match error {
        PortAllocationError::RtpPortZero
        | PortAllocationError::RtpPortMustBeEven { .. }
        | PortAllocationError::RangeReversed { .. }
        | PortAllocationError::OutsideRange { .. } => RtpErrorClass::InvalidConfiguration,
        PortAllocationError::AlreadyAllocated { .. } | PortAllocationError::NotAllocated { .. } => {
            RtpErrorClass::InvalidState
        }
        PortAllocationError::AllocationFailed => RtpErrorClass::ResourceExhausted,
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::io;

    use super::{RtpError, RtpErrorClass, RtpErrorLayer};
    use crate::rtp::packet::RtpPacketError;
    use crate::rtp::packet::rtcp::CompoundRtcpError;
    use crate::rtp::session::RtpSessionError;
    use crate::rtp::transport::Component;
    use crate::rtp::transport::allocator::PortAllocationError;
    use crate::rtp::transport::socket::SocketError;

    #[test]
    fn packet_errors_preserve_source_and_classify_capacity() {
        let error = RtpError::from(RtpPacketError::AllocationFailed);
        assert_eq!(error.layer(), RtpErrorLayer::DataPacket);
        assert_eq!(error.class(), RtpErrorClass::ResourceExhausted);
        assert!(error.source().is_some());

        let malformed = RtpError::from(RtpPacketError::MissingPaddingLength);
        assert_eq!(malformed.class(), RtpErrorClass::InvalidDatagram);
    }

    #[test]
    fn control_packet_errors_have_a_distinct_layer() {
        let error = RtpError::from(CompoundRtcpError::EmptyDatagram);
        assert_eq!(error.layer(), RtpErrorLayer::ControlPacket);
        assert_eq!(error.class(), RtpErrorClass::InvalidDatagram);
    }

    #[test]
    fn session_errors_distinguish_policy_state_and_capacity() {
        let policy = RtpError::from(RtpSessionError::TelephoneEventNotNegotiated);
        assert_eq!(policy.class(), RtpErrorClass::PolicyRejected);

        let state = RtpError::from(RtpSessionError::RtcpNotConfigured);
        assert_eq!(state.class(), RtpErrorClass::InvalidState);

        let capacity = RtpError::from(RtpSessionError::AllocationFailed);
        assert_eq!(capacity.class(), RtpErrorClass::ResourceExhausted);
    }

    #[test]
    fn transport_exposes_only_io_kind_for_readiness() {
        let source = io::Error::new(io::ErrorKind::WouldBlock, "peer 203.0.113.4:4000");
        let error = RtpError::from(SocketError::Receive {
            component: Component::Rtp,
            source,
        });
        assert_eq!(error.layer(), RtpErrorLayer::Transport);
        assert_eq!(error.class(), RtpErrorClass::TransportIo);
        assert_eq!(error.io_kind(), Some(io::ErrorKind::WouldBlock));
        assert!(error.is_would_block());
    }

    #[test]
    fn allocator_errors_distinguish_configuration_state_and_capacity() {
        let configuration = RtpError::from(PortAllocationError::RtpPortZero);
        assert_eq!(configuration.class(), RtpErrorClass::InvalidConfiguration);

        let capacity = RtpError::from(PortAllocationError::AllocationFailed);
        assert_eq!(capacity.class(), RtpErrorClass::ResourceExhausted);
    }

    #[test]
    fn routine_diagnostics_are_redacted() {
        let source = io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "secret-peer.example:45678",
        );
        let error = RtpError::from(SocketError::Send {
            component: Component::Rtcp,
            source,
        });
        let debug = format!("{error:?}");
        let display = error.to_string();
        for output in [&debug, &display] {
            assert!(!output.contains("secret-peer"));
            assert!(!output.contains("45678"));
        }
        assert!(debug.contains("TransportIo"));
        assert_eq!(display, "RTP transport failure (transport-io)");
    }
}
