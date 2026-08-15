// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Ordered results from one bounded transport-reactor turn.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::sync::Arc;

use super::super::ReceivedMessage;
use super::super::connection::ConnectionId;
use super::super::service::{FailedConnection, ServiceError};

/// Why an established reliable source was retired by the reactor.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReactorSourceError {
    /// Driver, framing, parsing, validation, TLS, or service failure.
    Transport(ServiceError),
    /// The readiness backend reported a terminal condition without a more
    /// specific protocol-driver error.
    ReadinessTerminal,
    /// Re-arming or removing the operating-system registration failed.
    Readiness(io::Error),
}

impl ReactorSourceError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Transport(_) => "transport",
            Self::ReadinessTerminal => "readiness-terminal",
            Self::Readiness(_) => "readiness",
        }
    }
}

impl fmt::Display for ReactorSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP reactor source error: {}", self.class())
    }
}

impl StdError for ReactorSourceError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::Readiness(source) => Some(source),
            Self::ReadinessTerminal => None,
        }
    }
}

/// One result produced by a bounded reactor turn.
#[non_exhaustive]
pub enum ReactorEvent {
    /// A malformed or otherwise rejected UDP datagram. The UDP socket remains
    /// active because one datagram cannot desynchronize later datagrams.
    DatagramRejected(ServiceError),
    /// Exact immutable reliable messages fully committed in queue order.
    ReliableCommitted {
        /// Actor-owned connection identity.
        connection_id: ConnectionId,
        /// Messages proven fully accepted by the kernel/TLS transport.
        messages: Vec<Arc<[u8]>>,
    },
    /// A reliable flow failed and its ambiguous/unsent work was recovered.
    ReliableFailed {
        /// Actor-owned connection identity.
        connection_id: ConnectionId,
        /// Failure that caused retirement.
        error: ReactorSourceError,
        /// Exact in-flight and queued work recovered without byte copies.
        recovery: FailedConnection,
    },
    /// A fully drained reliable flow completed graceful shutdown.
    ReliableClosed {
        /// Retired actor-owned connection identity.
        connection_id: ConnectionId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BatchSlot {
    Inbound(usize),
    Event(usize),
}

/// Borrowed item in exact reactor processing order.
#[derive(Clone, Copy, Debug)]
pub enum ReactorBatchItem<'a> {
    /// Parsed and semantically validated inbound SIP message.
    Inbound(&'a ReceivedMessage),
    /// Transport commit, rejection, failure, or graceful-close event.
    Event(&'a ReactorEvent),
}

/// Iterator over one batch in exact reactor processing order.
pub struct ReactorBatchIter<'a> {
    batch: &'a ReactorBatch,
    offset: usize,
}

impl<'a> Iterator for ReactorBatchIter<'a> {
    type Item = ReactorBatchItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let slot = *self.batch.order.get(self.offset)?;
        self.offset += 1;
        match slot {
            BatchSlot::Inbound(index) => {
                self.batch.inbound.get(index).map(ReactorBatchItem::Inbound)
            }
            BatchSlot::Event(index) => self.batch.events.get(index).map(ReactorBatchItem::Event),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.batch.order.len().saturating_sub(self.offset);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ReactorBatchIter<'_> {}
impl std::iter::FusedIterator for ReactorBatchIter<'_> {}

impl fmt::Debug for ReactorEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatagramRejected(error) => formatter
                .debug_struct("DatagramRejected")
                .field("class", &error.class())
                .finish(),
            Self::ReliableCommitted {
                connection_id,
                messages,
            } => formatter
                .debug_struct("ReliableCommitted")
                .field("connection_id", connection_id)
                .field("messages", &messages.len())
                .finish(),
            Self::ReliableFailed {
                connection_id,
                error,
                recovery,
            } => formatter
                .debug_struct("ReliableFailed")
                .field("connection_id", connection_id)
                .field("class", &error.class())
                .field("recovery", recovery)
                .finish(),
            Self::ReliableClosed { connection_id } => formatter
                .debug_struct("ReliableClosed")
                .field("connection_id", connection_id)
                .finish(),
        }
    }
}

/// Results from one bounded reactor wait/drain turn.
pub struct ReactorBatch {
    pub(super) inbound: Vec<ReceivedMessage>,
    pub(super) events: Vec<ReactorEvent>,
    pub(super) order: Vec<BatchSlot>,
    pub(super) notified: bool,
}

impl ReactorBatch {
    /// Returns parsed and semantically validated inbound messages in receive order.
    #[must_use]
    pub fn inbound(&self) -> &[ReceivedMessage] {
        &self.inbound
    }

    /// Returns events in reactor processing order.
    #[must_use]
    pub fn events(&self) -> &[ReactorEvent] {
        &self.events
    }

    /// Iterates inbound messages and transport events in exact processing order.
    #[must_use]
    pub const fn iter(&self) -> ReactorBatchIter<'_> {
        ReactorBatchIter {
            batch: self,
            offset: 0,
        }
    }

    /// Returns whether an explicit notifier wake was consumed.
    #[must_use]
    pub const fn notified(&self) -> bool {
        self.notified
    }
}

impl<'a> IntoIterator for &'a ReactorBatch {
    type Item = ReactorBatchItem<'a>;
    type IntoIter = ReactorBatchIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for ReactorBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReactorBatch")
            .field("inbound", &self.inbound.len())
            .field("events", &self.events.len())
            .field("ordered_items", &self.order.len())
            .field("notified", &self.notified)
            .finish_non_exhaustive()
    }
}
