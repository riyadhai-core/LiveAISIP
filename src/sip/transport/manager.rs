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

//! Actor-owned reliable SIP connection registry.
//!
//! The manager is intentionally synchronous and not internally locked. One
//! signaling actor owns it and receives bounded commands from concurrent
//! producers. This preserves deterministic state transitions and avoids a
//! global mutex on transaction hot paths.
//!
//! Destinations are deduplicated, connection count is bounded, registration
//! reserves both indexes before mutation, and shutdown permanently fences new
//! registrations and writes.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use super::connection::{Connection, ConnectionError, ConnectionId, ConnectionState, QueueLimits};
use super::destination::Destination;

/// Hard maximum reliable connections owned by one manager.
pub const MAX_RELIABLE_CONNECTIONS: usize = 65_536;

/// Reliable transport manager configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagerConfig {
    /// Maximum active or connecting reliable destinations.
    pub max_connections: usize,
    /// Per-connection outbound queue limits.
    pub queue_limits: QueueLimits,
}

impl ManagerConfig {
    /// Creates production-oriented defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_connections: 8_192,
            queue_limits: QueueLimits::new(),
        }
    }

    /// Validates hard manager and queue ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive connection capacity or invalid queue limits.
    pub const fn validate(self) -> Result<(), ManagerError> {
        if self.max_connections == 0 || self.max_connections > MAX_RELIABLE_CONNECTIONS {
            return Err(ManagerError::InvalidConnectionLimit {
                value: self.max_connections,
                maximum: MAX_RELIABLE_CONNECTIONS,
            });
        }
        match self.queue_limits.validate() {
            Ok(()) => Ok(()),
            Err(error) => Err(ManagerError::Connection(error)),
        }
    }
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of registering a destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registration {
    id: ConnectionId,
    created: bool,
}

impl Registration {
    /// Returns connection identity.
    #[must_use]
    pub const fn id(self) -> ConnectionId {
        self.id
    }

    /// Returns whether new connecting state was created.
    #[must_use]
    pub const fn created(self) -> bool {
        self.created
    }
}

/// Bounded reliable connection registry.
pub struct TransportManager {
    config: ManagerConfig,
    next_id: u64,
    shutting_down: bool,
    connections: HashMap<ConnectionId, Connection>,
    destinations: HashMap<Destination, ConnectionId>,
}

impl TransportManager {
    /// Creates an empty validated registry.
    ///
    /// # Errors
    ///
    /// Rejects invalid manager configuration.
    pub fn new(config: ManagerConfig) -> Result<Self, ManagerError> {
        config.validate()?;
        Ok(Self {
            config,
            next_id: 1,
            shutting_down: false,
            connections: HashMap::new(),
            destinations: HashMap::new(),
        })
    }

    /// Returns an existing destination registration or creates connecting state.
    ///
    /// # Errors
    ///
    /// Rejects shutdown, capacity exhaustion, datagram destinations, identity
    /// exhaustion, and allocation failure without partial index mutation.
    pub fn register(&mut self, destination: Destination) -> Result<Registration, ManagerError> {
        if self.shutting_down {
            return Err(ManagerError::ShuttingDown);
        }
        if let Some(id) = self.destinations.get(&destination).copied() {
            return Ok(Registration { id, created: false });
        }
        if self.connections.len() >= self.config.max_connections {
            return Err(ManagerError::Capacity {
                maximum: self.config.max_connections,
            });
        }

        let id = self.allocate_id()?;
        let connection = Connection::new(id, destination.clone(), self.config.queue_limits)?;
        self.connections
            .try_reserve(1)
            .map_err(|_| ManagerError::AllocationFailed)?;
        self.destinations
            .try_reserve(1)
            .map_err(|_| ManagerError::AllocationFailed)?;
        self.connections.insert(id, connection);
        self.destinations.insert(destination, id);
        Ok(Registration { id, created: true })
    }

    /// Marks a connecting socket as established.
    ///
    /// # Errors
    ///
    /// Rejects unknown IDs and invalid lifecycle transitions.
    pub fn establish(&mut self, id: ConnectionId) -> Result<(), ManagerError> {
        self.connection_mut(id)?
            .transition(ConnectionState::Established)
            .map_err(ManagerError::Connection)
    }

    /// Enqueues a complete immutable SIP message.
    ///
    /// # Errors
    ///
    /// Rejects shutdown, unknown IDs, non-writable state, and queue pressure.
    pub fn enqueue(&mut self, id: ConnectionId, message: Arc<[u8]>) -> Result<(), ManagerError> {
        if self.shutting_down {
            return Err(ManagerError::ShuttingDown);
        }
        self.connection_mut(id)?
            .enqueue(message)
            .map_err(ManagerError::Connection)
    }

    /// Removes and closes one registration, returning whether it existed.
    pub fn remove(&mut self, id: ConnectionId) -> bool {
        let Some(mut connection) = self.connections.remove(&id) else {
            return false;
        };
        self.destinations.remove(connection.destination());
        let _ = connection.transition(ConnectionState::Closed);
        true
    }

    /// Permanently fences new work and begins deterministic connection drain.
    pub fn begin_shutdown(&mut self) {
        self.shutting_down = true;
        for connection in self.connections.values_mut() {
            match connection.state() {
                ConnectionState::Connecting => {
                    let _ = connection.transition(ConnectionState::Closed);
                }
                ConnectionState::Established => {
                    let _ = connection.transition(ConnectionState::Draining);
                }
                ConnectionState::Draining | ConnectionState::Closed => {}
            }
        }
    }

    /// Returns a connection by identity.
    #[must_use]
    pub fn connection(&self, id: ConnectionId) -> Option<&Connection> {
        self.connections.get(&id)
    }

    /// Returns current registration count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Returns whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Returns whether shutdown fencing is active.
    #[must_use]
    pub const fn is_shutting_down(&self) -> bool {
        self.shutting_down
    }

    fn connection_mut(&mut self, id: ConnectionId) -> Result<&mut Connection, ManagerError> {
        self.connections
            .get_mut(&id)
            .ok_or(ManagerError::UnknownConnection)
    }

    fn allocate_id(&mut self) -> Result<ConnectionId, ManagerError> {
        for _ in 0..=self.connections.len() {
            let candidate = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id == 0 {
                self.next_id = 1;
            }
            if let Ok(id) = ConnectionId::new(candidate)
                && !self.connections.contains_key(&id)
            {
                return Ok(id);
            }
        }
        Err(ManagerError::ConnectionIdExhausted)
    }
}

impl fmt::Debug for TransportManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportManager")
            .field("connections", &self.connections.len())
            .field("maximum", &self.config.max_connections)
            .field("shutting_down", &self.shutting_down)
            .finish_non_exhaustive()
    }
}

/// Reliable transport registry failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ManagerError {
    /// Configured connection capacity was invalid.
    InvalidConnectionLimit {
        /// Configured value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Registry is shutting down.
    ShuttingDown,
    /// Connection capacity was exhausted.
    Capacity {
        /// Configured maximum.
        maximum: usize,
    },
    /// Connection identity space was exhausted.
    ConnectionIdExhausted,
    /// Connection identity was unknown.
    UnknownConnection,
    /// Per-connection operation failed.
    Connection(ConnectionError),
    /// Bounded index allocation failed.
    AllocationFailed,
}

impl From<ConnectionError> for ManagerError {
    fn from(error: ConnectionError) -> Self {
        Self::Connection(error)
    }
}

impl ManagerError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::InvalidConnectionLimit { .. } => "invalid-connection-limit",
            Self::ShuttingDown => "shutting-down",
            Self::Capacity { .. } => "capacity",
            Self::ConnectionIdExhausted => "connection-id-exhausted",
            Self::UnknownConnection => "unknown-connection",
            Self::Connection(_) => "connection",
            Self::AllocationFailed => "allocation-failed",
        }
    }
}

impl fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP transport manager error: {}", self.class())
    }
}

impl StdError for ManagerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use super::{ManagerConfig, ManagerError, TransportManager};
    use crate::sip::transport::connection::{ConnectionState, QueueLimits};
    use crate::sip::transport::destination::Destination;

    fn destination(port: u16) -> Destination {
        let Ok(value) = Destination::tcp(SocketAddr::from(([192, 0, 2, 10], port))) else {
            panic!("destination")
        };
        value
    }

    #[test]
    fn deduplicates_destination_and_routes_queue_work() {
        let Ok(mut manager) = TransportManager::new(ManagerConfig::default()) else {
            panic!("manager")
        };
        let Ok(first) = manager.register(destination(5060)) else {
            panic!("register")
        };
        let Ok(second) = manager.register(destination(5060)) else {
            panic!("register")
        };
        assert!(first.created());
        assert!(!second.created());
        assert_eq!(first.id(), second.id());
        assert!(manager.establish(first.id()).is_ok());
        assert!(
            manager
                .enqueue(first.id(), Arc::from(&b"message"[..]))
                .is_ok()
        );
        assert_eq!(
            manager
                .connection(first.id())
                .map(crate::sip::transport::connection::Connection::queued_messages),
            Some(1)
        );
    }

    #[test]
    fn capacity_and_shutdown_are_hard_fences() {
        let config = ManagerConfig {
            max_connections: 1,
            queue_limits: QueueLimits::default(),
        };
        let Ok(mut manager) = TransportManager::new(config) else {
            panic!("manager")
        };
        let Ok(registration) = manager.register(destination(5060)) else {
            panic!("register")
        };
        assert!(matches!(
            manager.register(destination(5061)),
            Err(ManagerError::Capacity { .. })
        ));
        assert!(manager.establish(registration.id()).is_ok());
        manager.begin_shutdown();
        assert_eq!(
            manager
                .connection(registration.id())
                .map(crate::sip::transport::connection::Connection::state),
            Some(ConnectionState::Draining)
        );
        assert!(matches!(
            manager.enqueue(registration.id(), Arc::from(&b"x"[..])),
            Err(ManagerError::ShuttingDown)
        ));
    }

    #[test]
    fn removal_clears_both_indexes_and_debug_is_redacted() {
        let Ok(mut manager) = TransportManager::new(ManagerConfig::default()) else {
            panic!("manager")
        };
        let Ok(registration) = manager.register(destination(5060)) else {
            panic!("register")
        };
        assert!(manager.remove(registration.id()));
        assert!(manager.is_empty());
        let debug = format!("{manager:?}");
        assert!(!debug.contains("192.0.2.10"));
    }
}
