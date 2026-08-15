// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Transport planning, attachment, queue, socket, and shutdown failures.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::transport::connection::ConnectionState;
use crate::sip::transport::destination::Protocol;
use crate::sip::transport::manager::ManagerError;
use crate::sip::transport::tcp_driver::TcpDriverError;
use crate::sip::transport::tls_driver::TlsDriverError;
use crate::sip::transport::udp::UdpError;
use crate::sip::transport::udp_driver::UdpDriverError;

/// Transport planning, attachment, queue, socket, or shutdown failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServiceError {
    /// Reliable manager configuration or operation failed.
    Manager(ManagerError),
    /// Per-poll commit budget was zero or excessive.
    InvalidWriteCommitBudget {
        /// Rejected value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// A UDP destination was passed to reliable planning.
    DatagramReliablePlan,
    /// Identity was unknown to the reliable registry.
    ConnectionNotPlanned,
    /// Identity had no attached socket driver.
    ConnectionNotAttached,
    /// Identity already owned a socket driver.
    ConnectionAlreadyAttached,
    /// Driver was attached after connecting state ended.
    ConnectionNotConnecting {
        /// Observed lifecycle.
        state: ConnectionState,
    },
    /// Planned and attached reliable protocols differed.
    DriverProtocolMismatch {
        /// Planned protocol.
        expected: Protocol,
        /// Driver protocol.
        actual: Protocol,
    },
    /// Connected peer endpoint differed from the planned destination.
    DriverPeerMismatch,
    /// Driver generation differed from planned flow identity.
    DriverFlowMismatch,
    /// Verified TLS identity differed from planned destination identity.
    DriverIdentityMismatch,
    /// Active driver/message ownership became inconsistent.
    InternalWriteInvariant,
    /// Manager/driver indexes became inconsistent.
    InternalConnectionInvariant,
    /// Bounded result allocation failed.
    AllocationFailed,
    /// UDP payload admission failed.
    UdpAdmission(UdpError),
    /// UDP socket/framing/validation failed.
    UdpDriver(UdpDriverError),
    /// TCP driver failed.
    Tcp(TcpDriverError),
    /// TLS driver failed.
    Tls(TlsDriverError),
    /// New UDP receive/send was attempted after shutdown fencing.
    ShuttingDown,
    /// Graceful close was requested before queue drain completed.
    DrainIncomplete {
        /// Messages still waiting in the connection queue.
        queued_messages: usize,
        /// Whether one message has ambiguous/partial driver ownership.
        inflight: bool,
    },
    /// UDP response route could not become a validated destination.
    InvalidDatagramRoute,
    /// Reliable response referenced a retired or unattached flow generation.
    StaleFlow,
}

impl ServiceError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Manager(_) => "manager",
            Self::InvalidWriteCommitBudget { .. } => "invalid-write-commit-budget",
            Self::DatagramReliablePlan => "datagram-reliable-plan",
            Self::ConnectionNotPlanned => "connection-not-planned",
            Self::ConnectionNotAttached => "connection-not-attached",
            Self::ConnectionAlreadyAttached => "connection-already-attached",
            Self::ConnectionNotConnecting { .. } => "connection-not-connecting",
            Self::DriverProtocolMismatch { .. } => "driver-protocol-mismatch",
            Self::DriverPeerMismatch => "driver-peer-mismatch",
            Self::DriverFlowMismatch => "driver-flow-mismatch",
            Self::DriverIdentityMismatch => "driver-identity-mismatch",
            Self::InternalWriteInvariant => "internal-write-invariant",
            Self::InternalConnectionInvariant => "internal-connection-invariant",
            Self::AllocationFailed => "allocation-failed",
            Self::UdpAdmission(_) => "udp-admission",
            Self::UdpDriver(_) => "udp-driver",
            Self::Tcp(_) => "tcp-driver",
            Self::Tls(_) => "tls-driver",
            Self::ShuttingDown => "shutting-down",
            Self::DrainIncomplete { .. } => "drain-incomplete",
            Self::InvalidDatagramRoute => "invalid-datagram-route",
            Self::StaleFlow => "stale-flow",
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP transport service error: {}", self.class())
    }
}

impl StdError for ServiceError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Manager(source) => Some(source),
            Self::UdpAdmission(source) => Some(source),
            Self::UdpDriver(source) => Some(source),
            Self::Tcp(source) => Some(source),
            Self::Tls(source) => Some(source),
            _ => None,
        }
    }
}
