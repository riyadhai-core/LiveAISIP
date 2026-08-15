// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Call-runtime construction, ownership, and processing failures.

use std::error::Error as StdError;
use std::fmt;

use crate::call::execution::deadline::{DeadlineError, DeadlineOwner};
use crate::call::model::context::CallContextError;
use crate::call::model::redirect::RedirectError;
use crate::call::signaling::SignalingError;
use crate::rtp::session::RtpWireSendError;
use crate::rtp::transport::SocketError;
use crate::sip::dialog::DialogManagerError;
use crate::sip::transaction::manager::ManagerError as TransactionManagerError;

/// Call runtime construction, ownership, or processing failure.
#[derive(Debug)]
pub enum CallRuntimeError {
    /// A different native thread attempted mutable access.
    WrongOwnerThread,
    /// Graceful shutdown interval was zero.
    ZeroShutdownGrace,
    /// Call-local resources were installed twice or after ownership started.
    ResourcesAlreadyInstalled,
    /// Absolute monotonic calculation overflowed.
    TimeOverflow,
    /// SIP transaction registry construction failed.
    Transactions(TransactionManagerError),
    /// SIP dialog registry construction failed.
    Dialogs(DialogManagerError),
    /// Redirect policy allocation or validation failed.
    Redirect(RedirectError),
    /// Deadline scheduler operation failed.
    Deadlines(DeadlineError),
    /// Deterministic call context rejected an event.
    Context(CallContextError),
    /// RTP readiness arrived before its complete call-owned resource set.
    MediaResourcesUnavailable,
    /// Fatal call-owned RTP or RTCP socket operation failed.
    MediaSocket(SocketError),
    /// Outbound RTP encoding, policy, or wire execution failed.
    RtpWire(RtpWireSendError),
    /// SIP action required a call-owned signaling driver that was not installed.
    SignalingUnavailable,
    /// Call-owned SIP transport, transaction, or timer execution failed.
    Signaling(SignalingError),
    /// A due deadline owner had no installed exhaustive executor.
    UnsupportedDeadlineOwner(DeadlineOwner),
    /// A due deadline kind was not defined for its owner.
    UnknownDeadlineKind {
        /// Deadline owner.
        owner: DeadlineOwner,
        /// Unrecognized low-cardinality kind.
        kind: u16,
    },
    /// Session-refresh work was scheduled without negotiated timer state.
    SessionTimerUnavailable,
    /// Session refresh became due before its wire executor was installed.
    SessionRefreshExecutorUnavailable,
    /// Session timer work was scheduled before the negotiated instant.
    PrematureSessionDeadline,
    /// Transfer expiry was scheduled without an active transfer tracker.
    TransferUnavailable,
}

impl fmt::Display for CallRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("call runtime operation failed")
    }
}

impl StdError for CallRuntimeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Transactions(source) => Some(source),
            Self::Dialogs(source) => Some(source),
            Self::Redirect(source) => Some(source),
            Self::Deadlines(source) => Some(source),
            Self::Context(source) => Some(source),
            Self::MediaSocket(source) => Some(source),
            Self::RtpWire(source) => Some(source),
            Self::Signaling(source) => Some(source),
            Self::WrongOwnerThread
            | Self::ZeroShutdownGrace
            | Self::ResourcesAlreadyInstalled
            | Self::TimeOverflow
            | Self::MediaResourcesUnavailable
            | Self::SignalingUnavailable
            | Self::UnsupportedDeadlineOwner(_)
            | Self::UnknownDeadlineKind { .. }
            | Self::SessionTimerUnavailable
            | Self::SessionRefreshExecutorUnavailable
            | Self::PrematureSessionDeadline
            | Self::TransferUnavailable => None,
        }
    }
}
