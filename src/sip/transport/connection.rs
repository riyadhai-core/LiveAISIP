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

//! Reliable SIP transport connection primitives.
//!
//! TCP and TLS connections use explicit nonzero identities and a monotonic
//! lifecycle. Each connection owns a queue bounded independently by message
//! count and total bytes. Enqueue operations fail immediately under pressure;
//! signaling producers never wait while holding transaction or dialog state.
//!
//! Socket I/O, reconnect policy, keepalives, and connection pooling remain in
//! their dedicated transport layers.

use std::collections::VecDeque;
use std::error::Error as StdError;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;

use crate::sip::framing::MAX_MESSAGE_BYTES;

use super::destination::{Destination, Protocol};

/// Hard upper bound for queued messages on one connection.
pub const MAX_CONNECTION_QUEUE_MESSAGES: usize = 4_096;

/// Hard upper bound for queued bytes on one connection.
pub const MAX_CONNECTION_QUEUE_BYTES: usize = 16 * 1024 * 1024;

/// Stable nonzero identity for one connection generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ConnectionId(NonZeroU64);

impl ConnectionId {
    /// Creates a connection identity.
    ///
    /// # Errors
    ///
    /// Rejects zero, which is reserved as an invalid sentinel.
    pub const fn new(value: u64) -> Result<Self, ConnectionError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(ConnectionError::ZeroConnectionId),
        }
    }

    /// Returns the numeric identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Reliable connection lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnectionState {
    /// Socket establishment or TLS handshake is in progress.
    Connecting,
    /// The connection accepts new outbound messages.
    Established,
    /// Existing queued writes may drain but new writes are rejected.
    Draining,
    /// The connection is terminal and cannot be reused.
    Closed,
}

/// Configured outbound queue limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueLimits {
    /// Maximum queued message count.
    pub messages: usize,
    /// Maximum aggregate queued bytes.
    pub bytes: usize,
}

impl QueueLimits {
    /// Production-oriented default limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            messages: 512,
            bytes: 4 * 1024 * 1024,
        }
    }

    /// Validates both nonzero limits against hard safety ceilings.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration error for zero or excessive limits.
    pub const fn validate(self) -> Result<(), ConnectionError> {
        if self.messages == 0 || self.messages > MAX_CONNECTION_QUEUE_MESSAGES {
            return Err(ConnectionError::InvalidMessageLimit {
                value: self.messages,
                maximum: MAX_CONNECTION_QUEUE_MESSAGES,
            });
        }
        if self.bytes == 0 || self.bytes > MAX_CONNECTION_QUEUE_BYTES {
            return Err(ConnectionError::InvalidByteLimit {
                value: self.bytes,
                maximum: MAX_CONNECTION_QUEUE_BYTES,
            });
        }
        Ok(())
    }
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Reliable SIP connection metadata and bounded outbound queue.
pub struct Connection {
    id: ConnectionId,
    destination: Destination,
    state: ConnectionState,
    limits: QueueLimits,
    queued_bytes: usize,
    queue: VecDeque<Arc<[u8]>>,
}

impl Connection {
    /// Creates connecting TCP/TLS state with an empty bounded queue.
    ///
    /// # Errors
    ///
    /// Rejects UDP destinations and invalid queue limits.
    pub fn new(
        id: ConnectionId,
        destination: Destination,
        limits: QueueLimits,
    ) -> Result<Self, ConnectionError> {
        limits.validate()?;
        if destination.protocol() == Protocol::Udp {
            return Err(ConnectionError::DatagramDestination);
        }
        Ok(Self {
            id,
            destination,
            state: ConnectionState::Connecting,
            limits,
            queued_bytes: 0,
            queue: VecDeque::new(),
        })
    }

    /// Moves the lifecycle forward without permitting regression.
    ///
    /// # Errors
    ///
    /// Rejects skipped, repeated, or backward transitions.
    pub fn transition(&mut self, next: ConnectionState) -> Result<(), ConnectionError> {
        let valid = matches!(
            (self.state, next),
            (
                ConnectionState::Connecting,
                ConnectionState::Established | ConnectionState::Closed
            ) | (
                ConnectionState::Established,
                ConnectionState::Draining | ConnectionState::Closed
            ) | (ConnectionState::Draining, ConnectionState::Closed)
        );
        if !valid {
            return Err(ConnectionError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        Ok(())
    }

    /// Queues one complete serialized SIP message.
    ///
    /// # Errors
    ///
    /// Requires established state and rejects empty, oversized, count-bound,
    /// byte-bound, or allocation-failing inserts without queue mutation.
    pub fn enqueue(&mut self, message: Arc<[u8]>) -> Result<(), ConnectionError> {
        if self.state != ConnectionState::Established {
            return Err(ConnectionError::NotWritable { state: self.state });
        }
        if message.is_empty() {
            return Err(ConnectionError::EmptyMessage);
        }
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(ConnectionError::MessageTooLarge {
                length: message.len(),
                maximum: MAX_MESSAGE_BYTES,
            });
        }
        if self.queue.len() >= self.limits.messages {
            return Err(ConnectionError::QueueMessageLimit {
                maximum: self.limits.messages,
            });
        }
        let Some(next_bytes) = self.queued_bytes.checked_add(message.len()) else {
            return Err(ConnectionError::QueueByteLimit {
                maximum: self.limits.bytes,
            });
        };
        if next_bytes > self.limits.bytes {
            return Err(ConnectionError::QueueByteLimit {
                maximum: self.limits.bytes,
            });
        }
        self.queue
            .try_reserve(1)
            .map_err(|_| ConnectionError::AllocationFailed)?;
        self.queue.push_back(message);
        self.queued_bytes = next_bytes;
        Ok(())
    }

    /// Removes the oldest queued message.
    pub fn pop_front(&mut self) -> Option<Arc<[u8]>> {
        let message = self.queue.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(message.len());
        Some(message)
    }

    /// Returns the identity.
    #[must_use]
    pub const fn id(&self) -> ConnectionId {
        self.id
    }

    /// Returns the destination.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Returns lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    /// Returns queued message count.
    #[must_use]
    pub fn queued_messages(&self) -> usize {
        self.queue.len()
    }

    /// Returns aggregate queued bytes.
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Connection")
            .field("id", &self.id)
            .field("protocol", &self.destination.protocol())
            .field("state", &self.state)
            .field("queued_messages", &self.queue.len())
            .field("queued_bytes", &self.queued_bytes)
            .finish_non_exhaustive()
    }
}

/// Failure in reliable connection state or admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnectionError {
    /// Connection ID was zero.
    ZeroConnectionId,
    /// Queue message limit was invalid.
    InvalidMessageLimit {
        /// Configured value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Queue byte limit was invalid.
    InvalidByteLimit {
        /// Configured value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// UDP was passed to reliable connection state.
    DatagramDestination,
    /// Lifecycle transition was invalid.
    InvalidTransition {
        /// Current state.
        from: ConnectionState,
        /// Requested state.
        to: ConnectionState,
    },
    /// Current state does not accept writes.
    NotWritable {
        /// Current non-writable state.
        state: ConnectionState,
    },
    /// Empty message was supplied.
    EmptyMessage,
    /// One message exceeded the framing bound.
    MessageTooLarge {
        /// Message length.
        length: usize,
        /// Maximum message length.
        maximum: usize,
    },
    /// Queue count capacity was exhausted.
    QueueMessageLimit {
        /// Configured maximum count.
        maximum: usize,
    },
    /// Queue byte capacity was exhausted.
    QueueByteLimit {
        /// Configured maximum bytes.
        maximum: usize,
    },
    /// Queue reservation failed.
    AllocationFailed,
}

impl ConnectionError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::ZeroConnectionId => "zero-connection-id",
            Self::InvalidMessageLimit { .. } => "invalid-message-limit",
            Self::InvalidByteLimit { .. } => "invalid-byte-limit",
            Self::DatagramDestination => "datagram-destination",
            Self::InvalidTransition { .. } => "invalid-transition",
            Self::NotWritable { .. } => "not-writable",
            Self::EmptyMessage => "empty-message",
            Self::MessageTooLarge { .. } => "message-too-large",
            Self::QueueMessageLimit { .. } => "queue-message-limit",
            Self::QueueByteLimit { .. } => "queue-byte-limit",
            Self::AllocationFailed => "allocation-failed",
        }
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP connection error: {}", self.class())
    }
}

impl StdError for ConnectionError {}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use super::{Connection, ConnectionError, ConnectionId, ConnectionState, QueueLimits};
    use crate::sip::transport::destination::Destination;

    fn connection(limits: QueueLimits) -> Connection {
        let Ok(id) = ConnectionId::new(1) else {
            panic!("id")
        };
        let Ok(destination) = Destination::tcp(SocketAddr::from(([192, 0, 2, 1], 5060))) else {
            panic!("destination")
        };
        let Ok(connection) = Connection::new(id, destination, limits) else {
            panic!("connection")
        };
        connection
    }

    #[test]
    fn lifecycle_is_monotonic() {
        let mut connection = connection(QueueLimits::default());
        assert!(connection.transition(ConnectionState::Established).is_ok());
        assert!(connection.transition(ConnectionState::Draining).is_ok());
        assert!(connection.transition(ConnectionState::Closed).is_ok());
        assert!(matches!(
            connection.transition(ConnectionState::Established),
            Err(ConnectionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn queue_applies_count_and_byte_backpressure_transactionally() {
        let mut connection = connection(QueueLimits {
            messages: 2,
            bytes: 6,
        });
        assert!(connection.transition(ConnectionState::Established).is_ok());
        assert!(connection.enqueue(Arc::from(&b"abc"[..])).is_ok());
        assert!(connection.enqueue(Arc::from(&b"def"[..])).is_ok());
        assert!(matches!(
            connection.enqueue(Arc::from(&b"x"[..])),
            Err(ConnectionError::QueueMessageLimit { .. })
        ));
        assert_eq!(connection.queued_messages(), 2);
        assert_eq!(connection.queued_bytes(), 6);
        assert_eq!(connection.pop_front().as_deref(), Some(&b"abc"[..]));
        assert_eq!(connection.queued_bytes(), 3);
    }

    #[test]
    fn rejects_udp_zero_ids_and_writes_before_establishment() {
        assert!(matches!(
            ConnectionId::new(0),
            Err(ConnectionError::ZeroConnectionId)
        ));
        let mut connection = connection(QueueLimits::default());
        assert!(matches!(
            connection.enqueue(Arc::from(&b"message"[..])),
            Err(ConnectionError::NotWritable { .. })
        ));
        let Ok(id) = ConnectionId::new(2) else {
            panic!("id")
        };
        let Ok(udp) = Destination::udp(SocketAddr::from(([192, 0, 2, 1], 5060))) else {
            panic!("udp")
        };
        assert!(matches!(
            Connection::new(id, udp, QueueLimits::default()),
            Err(ConnectionError::DatagramDestination)
        ));
    }

    #[test]
    fn debug_omits_destination_and_payload() {
        let mut connection = connection(QueueLimits::default());
        assert!(connection.transition(ConnectionState::Established).is_ok());
        assert!(
            connection
                .enqueue(Arc::from(&b"private-message"[..]))
                .is_ok()
        );
        let debug = format!("{connection:?}");
        assert!(!debug.contains("private-message"));
        assert!(!debug.contains("192.0.2.1"));
    }
}
