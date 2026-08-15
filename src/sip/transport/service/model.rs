// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Connection plans and commit-aware service results.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

use crate::sip::transport::connection::{ConnectionId, ConnectionState};
use crate::sip::transport::destination::Destination;
use crate::sip::transport::failover::WireCommitState;
use crate::sip::transport::flow::FlowId;

/// Nonblocking plan for one deduplicated reliable destination.
#[derive(Clone)]
pub struct ReliableConnectionPlan {
    pub(super) id: ConnectionId,
    pub(super) flow_id: FlowId,
    pub(super) destination: Destination,
    pub(super) created: bool,
    pub(super) state: ConnectionState,
}

impl ReliableConnectionPlan {
    /// Returns registry identity.
    #[must_use]
    pub const fn id(&self) -> ConnectionId {
        self.id
    }

    /// Returns the exact flow identity the driver must use.
    #[must_use]
    pub const fn flow_id(&self) -> FlowId {
        self.flow_id
    }

    /// Returns the concrete TCP/TLS destination for connector work.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Returns whether this call created new connecting state.
    #[must_use]
    pub const fn created(&self) -> bool {
        self.created
    }

    /// Returns the lifecycle observed while planning.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.state
    }
}

impl fmt::Debug for ReliableConnectionPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReliableConnectionPlan")
            .field("id", &self.id)
            .field("flow_id", &self.flow_id)
            .field("protocol", &self.destination.protocol())
            .field("created", &self.created)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Messages proven fully committed during one bounded actor poll.
pub struct WriteBatch {
    pub(super) committed: Vec<Arc<[u8]>>,
    pub(super) write_pending: bool,
    pub(super) queued_messages: usize,
    pub(super) queued_bytes: usize,
}

impl WriteBatch {
    /// Returns exact immutable messages committed in queue order.
    #[must_use]
    pub fn committed(&self) -> &[Arc<[u8]>] {
        &self.committed
    }

    /// Returns whether one message remains partially committed by the driver.
    #[must_use]
    pub const fn write_pending(&self) -> bool {
        self.write_pending
    }

    /// Returns messages still waiting in the admitted connection queue.
    #[must_use]
    pub const fn queued_messages(&self) -> usize {
        self.queued_messages
    }

    /// Returns aggregate bytes still waiting in the connection queue.
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Consumes the result into committed immutable messages.
    #[must_use]
    pub fn into_committed(self) -> Vec<Arc<[u8]>> {
        self.committed
    }
}

impl fmt::Debug for WriteBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WriteBatch")
            .field("committed_messages", &self.committed.len())
            .field("write_pending", &self.write_pending)
            .field("queued_messages", &self.queued_messages)
            .field("queued_bytes", &self.queued_bytes)
            .finish_non_exhaustive()
    }
}

/// Reliable messages retired because their connection failed.
pub struct FailedConnection {
    pub(super) id: ConnectionId,
    pub(super) inflight: Option<Arc<[u8]>>,
    pub(super) queued: VecDeque<Arc<[u8]>>,
}

impl FailedConnection {
    /// Returns retired connection identity.
    #[must_use]
    pub const fn id(&self) -> ConnectionId {
        self.id
    }

    /// Returns the message with ambiguous wire commitment, when present.
    #[must_use]
    pub fn inflight(&self) -> Option<&Arc<[u8]>> {
        self.inflight.as_ref()
    }

    /// Returns conservative commitment for the in-flight message.
    #[must_use]
    pub const fn inflight_commitment(&self) -> Option<WireCommitState> {
        if self.inflight.is_some() {
            Some(WireCommitState::Unknown)
        } else {
            None
        }
    }

    /// Returns messages proven never handed to the socket driver.
    #[must_use]
    pub const fn queued(&self) -> &VecDeque<Arc<[u8]>> {
        &self.queued
    }

    /// Consumes the failure into ambiguous and provably unsent work.
    #[must_use]
    pub fn into_parts(self) -> (Option<Arc<[u8]>>, VecDeque<Arc<[u8]>>) {
        (self.inflight, self.queued)
    }
}

impl fmt::Debug for FailedConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedConnection")
            .field("id", &self.id)
            .field("inflight", &self.inflight.is_some())
            .field("queued_messages", &self.queued.len())
            .finish_non_exhaustive()
    }
}

/// Progress while gracefully closing one drained reliable flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceShutdownProgress {
    /// TLS shutdown records still await socket writability.
    Pending,
    /// The flow was closed and removed from both service indexes.
    Complete,
}

/// Result of accepting a response route from transport-truth metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSendDisposition {
    /// One complete UDP response datagram reached the kernel.
    DatagramCommitted,
    /// A response was admitted to this existing reliable flow's queue.
    ReliableQueued {
        /// Actor-owned connection identity for later write polling.
        connection_id: ConnectionId,
    },
}
