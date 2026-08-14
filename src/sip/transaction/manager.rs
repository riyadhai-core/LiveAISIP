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

//! Bounded actor-owned SIP transaction registry.
//!
//! One signaling actor owns this registry. Concurrent producers communicate
//! through bounded queues outside this module, avoiding shared locks on the
//! transaction hot path. Every registration receives a generation token so
//! delayed timer events cannot affect a later transaction reusing the same
//! RFC key.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;

use super::client::{Action as ClientAction, ClientError, ClientTransaction, Timer as ClientTimer};
use super::key::TransactionKey;
use super::server::{Action as ServerAction, ServerError, ServerTransaction, Timer as ServerTimer};

/// Hard maximum transactions in one registry.
pub const MAX_TRANSACTIONS: usize = 1_048_576;

/// Transaction owner role.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Role {
    /// Locally initiated transaction.
    Client,
    /// Remotely initiated transaction.
    Server,
}

/// Generation-fenced handle used by timer callbacks.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Token {
    key: TransactionKey,
    generation: u64,
    role: Role,
}

impl Token {
    /// Returns transaction role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns opaque generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

struct Entry<T> {
    generation: u64,
    transaction: T,
}

/// Actor-owned bounded transaction manager.
pub struct TransactionManager {
    maximum: usize,
    next_generation: u64,
    shutting_down: bool,
    clients: HashMap<TransactionKey, Entry<ClientTransaction>>,
    servers: HashMap<TransactionKey, Entry<ServerTransaction>>,
}

impl TransactionManager {
    /// Creates an empty registry with a validated capacity.
    ///
    /// # Errors
    ///
    /// Rejects zero or capacity above the hard maximum.
    pub fn new(maximum: usize) -> Result<Self, ManagerError> {
        if maximum == 0 || maximum > MAX_TRANSACTIONS {
            return Err(ManagerError::InvalidCapacity {
                value: maximum,
                maximum: MAX_TRANSACTIONS,
            });
        }
        Ok(Self {
            maximum,
            next_generation: 1,
            shutting_down: false,
            clients: HashMap::new(),
            servers: HashMap::new(),
        })
    }

    /// Registers a client transaction transactionally.
    ///
    /// # Errors
    ///
    /// Rejects shutdown, duplicate key, capacity, or allocation failure.
    pub fn insert_client(&mut self, transaction: ClientTransaction) -> Result<Token, ManagerError> {
        self.admit(transaction.key(), Role::Client)?;
        let token = self.token(transaction.key().clone(), Role::Client);
        self.clients
            .try_reserve(1)
            .map_err(|_| ManagerError::AllocationFailed)?;
        self.clients.insert(
            token.key.clone(),
            Entry {
                generation: token.generation,
                transaction,
            },
        );
        Ok(token)
    }

    /// Registers a server transaction transactionally.
    ///
    /// # Errors
    ///
    /// Rejects shutdown, duplicate key, capacity, or allocation failure.
    pub fn insert_server(&mut self, transaction: ServerTransaction) -> Result<Token, ManagerError> {
        self.admit(transaction.key(), Role::Server)?;
        let token = self.token(transaction.key().clone(), Role::Server);
        self.servers
            .try_reserve(1)
            .map_err(|_| ManagerError::AllocationFailed)?;
        self.servers.insert(
            token.key.clone(),
            Entry {
                generation: token.generation,
                transaction,
            },
        );
        Ok(token)
    }

    /// Routes a generation-fenced client timer.
    ///
    /// # Errors
    ///
    /// Rejects stale, unknown, wrong-role, or transaction-invalid timers.
    pub fn client_timer(
        &mut self,
        token: &Token,
        timer: ClientTimer,
    ) -> Result<Vec<ClientAction>, ManagerError> {
        if token.role != Role::Client {
            return Err(ManagerError::WrongRole);
        }
        let entry = self
            .clients
            .get_mut(&token.key)
            .ok_or(ManagerError::Unknown)?;
        if entry.generation != token.generation {
            return Err(ManagerError::StaleGeneration);
        }
        entry
            .transaction
            .on_timer(timer)
            .map_err(ManagerError::Client)
    }

    /// Routes a generation-fenced server timer.
    ///
    /// # Errors
    ///
    /// Rejects stale, unknown, wrong-role, or transaction-invalid timers.
    pub fn server_timer(
        &mut self,
        token: &Token,
        timer: ServerTimer,
    ) -> Result<Vec<ServerAction>, ManagerError> {
        if token.role != Role::Server {
            return Err(ManagerError::WrongRole);
        }
        let entry = self
            .servers
            .get_mut(&token.key)
            .ok_or(ManagerError::Unknown)?;
        if entry.generation != token.generation {
            return Err(ManagerError::StaleGeneration);
        }
        entry
            .transaction
            .on_timer(timer)
            .map_err(ManagerError::Server)
    }

    /// Removes the exact generation represented by a token.
    pub fn remove(&mut self, token: &Token) -> bool {
        match token.role {
            Role::Client => remove_generation(&mut self.clients, token),
            Role::Server => remove_generation(&mut self.servers, token),
        }
    }

    /// Permanently fences new transaction admission.
    pub const fn begin_shutdown(&mut self) {
        self.shutting_down = true;
    }

    /// Returns total transaction count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.clients.len().saturating_add(self.servers.len())
    }

    /// Returns whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty() && self.servers.is_empty()
    }

    fn admit(&self, key: &TransactionKey, role: Role) -> Result<(), ManagerError> {
        if self.shutting_down {
            return Err(ManagerError::ShuttingDown);
        }
        if self.len() >= self.maximum {
            return Err(ManagerError::Capacity {
                maximum: self.maximum,
            });
        }
        let duplicate = match role {
            Role::Client => self.clients.contains_key(key),
            Role::Server => self.servers.contains_key(key),
        };
        if duplicate {
            return Err(ManagerError::Duplicate);
        }
        Ok(())
    }

    fn token(&mut self, key: TransactionKey, role: Role) -> Token {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        Token {
            key,
            generation,
            role,
        }
    }
}

fn remove_generation<T>(map: &mut HashMap<TransactionKey, Entry<T>>, token: &Token) -> bool {
    if map
        .get(&token.key)
        .is_some_and(|entry| entry.generation == token.generation)
    {
        map.remove(&token.key);
        true
    } else {
        false
    }
}

impl fmt::Debug for TransactionManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionManager")
            .field("clients", &self.clients.len())
            .field("servers", &self.servers.len())
            .field("maximum", &self.maximum)
            .field("shutting_down", &self.shutting_down)
            .finish_non_exhaustive()
    }
}

/// Transaction registry failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ManagerError {
    /// Capacity configuration was invalid.
    InvalidCapacity {
        /// Configured capacity.
        value: usize,
        /// Hard maximum capacity.
        maximum: usize,
    },
    /// Shutdown fencing is active.
    ShuttingDown,
    /// Registry capacity was exhausted.
    Capacity {
        /// Configured maximum capacity.
        maximum: usize,
    },
    /// Same role/key already exists.
    Duplicate,
    /// Token role did not match operation.
    WrongRole,
    /// Transaction was unknown.
    Unknown,
    /// Token referred to an older generation.
    StaleGeneration,
    /// Client engine rejected event.
    Client(ClientError),
    /// Server engine rejected event.
    Server(ServerError),
    /// Bounded map allocation failed.
    AllocationFailed,
}

impl fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP transaction manager error")
    }
}

impl StdError for ManagerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Server(error) => Some(error),
            _ => None,
        }
    }
}
