// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Reactor construction, registration, wait, and orchestration failures.

use std::error::Error as StdError;
use std::fmt;
use std::io;

use super::super::service::{FailedConnection, ServiceError};

/// Reactor construction, registration, wait, or orchestration failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReactorError {
    /// Ready-event capacity was zero or excessive.
    InvalidReadyEventLimit {
        /// Rejected value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Per-source read budget was zero or excessive.
    InvalidReadBudget {
        /// Rejected value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Combined result capacity exceeded its hard bound.
    BatchLimitExceeded {
        /// Attempted maximum result records.
        attempted: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Readiness-driven UDP requires nonblocking socket operation.
    BlockingUdpDriver,
    /// Readiness-driven reliable I/O requires a nonblocking driver.
    BlockingReliableDriver,
    /// A reliable identity was registered twice.
    DuplicateRegistration,
    /// Monotonic readiness keys were exhausted; keys are never reused.
    RegistrationKeyExhausted,
    /// Bounded allocation failed.
    AllocationFailed,
    /// Socket-handle duplication failed.
    DuplicateSocket(io::Error),
    /// Wake-socket creation, configuration, or I/O failed.
    WakeSocket(io::Error),
    /// The reactor's wake peer closed unexpectedly.
    WakeClosed,
    /// Native readiness backend construction failed.
    PollerCreate(io::Error),
    /// Initial native source registration failed.
    PollerRegister(io::Error),
    /// Native source re-arm or removal failed.
    PollerModify(io::Error),
    /// Native readiness wait failed.
    PollerWait(io::Error),
    /// UDP readiness reached a terminal socket condition.
    UdpReadinessTerminal,
    /// Transport service operation failed.
    Service(ServiceError),
    /// Reliable readiness registration failed after driver attachment; all
    /// admitted work is included in the recovery object.
    ReliableRegistration {
        /// Native registration failure.
        source: io::Error,
        /// Ambiguous and provably unsent work recovered from the flow.
        recovery: FailedConnection,
    },
    /// Registration failure was followed by an internal rollback failure.
    RegistrationRollback {
        /// Native registration failure.
        source: io::Error,
        /// Unexpected service rollback failure.
        rollback: Box<ServiceError>,
    },
    /// Reactor and registration indexes became inconsistent.
    InternalRegistrationInvariant,
}

impl ReactorError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::InvalidReadyEventLimit { .. } => "invalid-ready-event-limit",
            Self::InvalidReadBudget { .. } => "invalid-read-budget",
            Self::BatchLimitExceeded { .. } => "batch-limit-exceeded",
            Self::BlockingUdpDriver => "blocking-udp-driver",
            Self::BlockingReliableDriver => "blocking-reliable-driver",
            Self::DuplicateRegistration => "duplicate-registration",
            Self::RegistrationKeyExhausted => "registration-key-exhausted",
            Self::AllocationFailed => "allocation-failed",
            Self::DuplicateSocket(_) => "duplicate-socket",
            Self::WakeSocket(_) => "wake-socket",
            Self::WakeClosed => "wake-closed",
            Self::PollerCreate(_) => "poller-create",
            Self::PollerRegister(_) => "poller-register",
            Self::PollerModify(_) => "poller-modify",
            Self::PollerWait(_) => "poller-wait",
            Self::UdpReadinessTerminal => "udp-readiness-terminal",
            Self::Service(_) => "service",
            Self::ReliableRegistration { .. } => "reliable-registration",
            Self::RegistrationRollback { .. } => "registration-rollback",
            Self::InternalRegistrationInvariant => "internal-registration-invariant",
        }
    }

    /// Returns recovered reliable work when registration failed after attach.
    #[must_use]
    pub const fn recovery(&self) -> Option<&FailedConnection> {
        match self {
            Self::ReliableRegistration { recovery, .. } => Some(recovery),
            _ => None,
        }
    }
}

impl fmt::Display for ReactorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP transport reactor error: {}", self.class())
    }
}

impl StdError for ReactorError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::DuplicateSocket(source)
            | Self::WakeSocket(source)
            | Self::PollerCreate(source)
            | Self::PollerRegister(source)
            | Self::PollerModify(source)
            | Self::PollerWait(source)
            | Self::ReliableRegistration { source, .. }
            | Self::RegistrationRollback { source, .. } => Some(source),
            Self::Service(source) => Some(source),
            _ => None,
        }
    }
}
