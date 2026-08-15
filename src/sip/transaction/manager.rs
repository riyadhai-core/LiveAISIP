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
use std::time::Duration;

use super::client::{Action as ClientAction, ClientError, ClientTransaction, Timer as ClientTimer};
use super::completion::{CompletionDisposition, CompletionError, CompletionStore};
use super::key::{KeyError, TransactionKey};
use super::server::{
    Action as ServerAction, DuplicateRequestDisposition, ServerError, ServerTransaction,
    Timer as ServerTimer,
};
use super::state::ServerState;
use crate::sip::types::method::Method;
use crate::sip::validation::request::ValidatedRequest;
use crate::sip::validation::response::ValidatedResponse;

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

/// Generation-fenced actions emitted by one routed transaction event.
pub struct RoutedActions<A> {
    token: Token,
    actions: Vec<A>,
}

impl<A> RoutedActions<A> {
    /// Returns the token that must fence every scheduled action.
    #[must_use]
    pub const fn token(&self) -> &Token {
        &self.token
    }

    /// Returns emitted actions in required processing order.
    #[must_use]
    pub fn actions(&self) -> &[A] {
        &self.actions
    }

    /// Consumes the route result into its token and actions.
    #[must_use]
    pub fn into_parts(self) -> (Token, Vec<A>) {
        (self.token, self.actions)
    }
}

impl<A> fmt::Debug for RoutedActions<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoutedActions")
            .field("role", &self.token.role())
            .field("generation", &self.token.generation())
            .field("action_count", &self.actions.len())
            .finish_non_exhaustive()
    }
}

/// Routing result for an inbound non-ACK request.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServerRequestRoute {
    /// No transaction exists; the owner must create and admit one.
    New,
    /// An existing transaction absorbed the retransmitted request.
    Existing(RoutedActions<ServerAction>),
}

/// Routing result for an inbound ACK request.
#[derive(Debug)]
#[non_exhaustive]
pub enum AckRoute {
    /// A non-2xx INVITE server transaction consumed the ACK.
    Transaction(RoutedActions<ServerAction>),
    /// The ACK does not belong to transaction state and must reach dialog/TU logic.
    Dialog,
}

/// Routing result including compact completed-INVITE state.
#[derive(Debug)]
pub enum ClientResponseRoute {
    /// A live heavy transaction processed the response.
    Live(RoutedActions<ClientAction>),
    /// Compact completion state handled a late/retransmitted final response.
    Retained(CompletionDisposition),
    /// No live or retained transaction matched.
    Unknown,
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
    completions: CompletionStore,
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
            completions: CompletionStore::new(maximum).map_err(ManagerError::Completion)?,
        })
    }

    /// Registers a client transaction transactionally.
    ///
    /// # Errors
    ///
    /// Rejects shutdown, duplicate key, capacity, or allocation failure.
    pub fn insert_client(&mut self, transaction: ClientTransaction) -> Result<Token, ManagerError> {
        self.admit(transaction.key(), Role::Client)?;
        let token = self.token(transaction.key().clone(), Role::Client)?;
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

    /// Starts and registers one client transaction as an atomic owner action.
    ///
    /// Starting occurs only after admission and map allocation have been
    /// proven possible. The returned token must fence every emitted timer
    /// action before any initial send is executed by the transport owner.
    ///
    /// # Errors
    ///
    /// Rejects shutdown, duplicate keys, capacity/allocation failure, or a
    /// transaction that had already been started.
    pub fn start_client(
        &mut self,
        mut transaction: ClientTransaction,
    ) -> Result<RoutedActions<ClientAction>, ManagerError> {
        self.admit(transaction.key(), Role::Client)?;
        self.clients
            .try_reserve(1)
            .map_err(|_| ManagerError::AllocationFailed)?;
        let token = self.token(transaction.key().clone(), Role::Client)?;
        let actions = transaction.start().map_err(ManagerError::Client)?;
        self.clients.insert(
            token.key.clone(),
            Entry {
                generation: token.generation,
                transaction,
            },
        );
        Ok(RoutedActions { token, actions })
    }

    /// Registers a server transaction transactionally.
    ///
    /// # Errors
    ///
    /// Rejects shutdown, duplicate key, capacity, or allocation failure.
    pub fn insert_server(&mut self, transaction: ServerTransaction) -> Result<Token, ManagerError> {
        self.admit(transaction.key(), Role::Server)?;
        let token = self.token(transaction.key().clone(), Role::Server)?;
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

    /// Routes a validated response to its client transaction.
    ///
    /// The returned token must accompany every emitted timer operation so a
    /// delayed callback cannot target a later transaction reusing the key.
    ///
    /// # Errors
    ///
    /// Rejects invalid transaction keys, unknown transactions, or response
    /// events rejected by the client state machine.
    pub fn route_response(
        &mut self,
        response: &ValidatedResponse,
    ) -> Result<RoutedActions<ClientAction>, ManagerError> {
        let key = TransactionKey::for_client_response(response).map_err(ManagerError::Key)?;
        let entry = self.clients.get_mut(&key).ok_or(ManagerError::Unknown)?;
        let token = Token {
            key,
            generation: entry.generation,
            role: Role::Client,
        };
        let actions = entry
            .transaction
            .on_response(response)
            .map_err(ManagerError::Client)?;
        Ok(RoutedActions { token, actions })
    }

    /// Routes through live state first, then compact completed-INVITE state.
    ///
    /// # Errors
    ///
    /// Preserves transaction-key, live-state, and completion-store failures.
    pub fn route_response_at(
        &mut self,
        response: &ValidatedResponse,
        now: Duration,
    ) -> Result<ClientResponseRoute, ManagerError> {
        let key = TransactionKey::for_client_response(response).map_err(ManagerError::Key)?;
        if self.clients.contains_key(&key) {
            return self.route_response(response).map(ClientResponseRoute::Live);
        }
        self.completions
            .route(response, now)
            .map_err(ManagerError::Completion)
            .map(|disposition| {
                disposition.map_or(ClientResponseRoute::Unknown, ClientResponseRoute::Retained)
            })
    }

    /// Routes a validated non-ACK request to existing server transaction state.
    ///
    /// `New` means the signaling owner must create, start, and insert a server
    /// transaction before delivering the request. `Existing` means the request
    /// was a retransmission and must not be delivered again.
    ///
    /// # Errors
    ///
    /// Rejects ACK, which must use [`Self::route_ack`], invalid transaction
    /// keys, or an invalid existing transaction state.
    pub fn route_request(
        &mut self,
        request: &ValidatedRequest,
    ) -> Result<ServerRequestRoute, ManagerError> {
        if request.request_line().method() == &Method::Ack {
            return Err(ManagerError::UnexpectedAck);
        }
        let key = TransactionKey::for_server_request(request).map_err(ManagerError::Key)?;
        let Some(entry) = self.servers.get(&key) else {
            return Ok(ServerRequestRoute::New);
        };
        let token = Token {
            key,
            generation: entry.generation,
            role: Role::Server,
        };
        let actions = match entry.transaction.on_duplicate_request() {
            DuplicateRequestDisposition::ReplayResponse(bytes) => {
                vec![ServerAction::SendResponse(bytes)]
            }
            DuplicateRequestDisposition::Absorb => Vec::new(),
        };
        Ok(ServerRequestRoute::Existing(RoutedActions {
            token,
            actions,
        }))
    }

    /// Routes a validated ACK without confusing transaction ACKs and 2xx ACKs.
    ///
    /// ACK for a completed non-2xx INVITE transaction is consumed here. A
    /// repeated ACK in Confirmed is absorbed with no actions. ACK for a 2xx
    /// response, or one without matching transaction state, is returned to
    /// dialog/TU processing.
    ///
    /// # Errors
    ///
    /// Rejects non-ACK input, invalid transaction keys, or an ACK transition
    /// rejected from an otherwise eligible Completed transaction.
    pub fn route_ack(&mut self, request: &ValidatedRequest) -> Result<AckRoute, ManagerError> {
        if request.request_line().method() != &Method::Ack {
            return Err(ManagerError::ExpectedAck);
        }
        let key = TransactionKey::for_server_request(request).map_err(ManagerError::Key)?;
        let Some(entry) = self.servers.get_mut(&key) else {
            return Ok(AckRoute::Dialog);
        };

        let actions = match entry.transaction.state() {
            ServerState::Completed => entry.transaction.on_ack().map_err(ManagerError::Server)?,
            ServerState::Confirmed => Vec::new(),
            _ => return Ok(AckRoute::Dialog),
        };
        let token = Token {
            key,
            generation: entry.generation,
            role: Role::Server,
        };
        Ok(AckRoute::Transaction(RoutedActions { token, actions }))
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

    /// Removes exact live state and retains compact INVITE completion authority.
    ///
    /// The caller supplies monotonic time so this manager remains clock-free.
    ///
    /// # Errors
    ///
    /// Rejects deadline overflow, missing invariant state, or completion-store
    /// capacity and allocation failures.
    pub fn complete_at(&mut self, token: &Token, now: Duration) -> Result<bool, ManagerError> {
        if token.role != Role::Client {
            return Ok(remove_generation(&mut self.servers, token));
        }
        let matching = self
            .clients
            .get(&token.key)
            .is_some_and(|entry| entry.generation == token.generation);
        if !matching {
            return Ok(false);
        }
        let entry = self
            .clients
            .remove(&token.key)
            .ok_or(ManagerError::Unknown)?;
        if entry.transaction.kind() == super::state::TransactionKind::Invite
            && (matches!(
                entry.transaction.state(),
                super::state::ClientState::Completed | super::state::ClientState::Accepted
            ) || entry.transaction.retained_failure_ack().is_some())
        {
            let expires_at = now
                .checked_add(entry.transaction.completion_retention())
                .ok_or(ManagerError::TimeOverflow)?;
            self.completions
                .retain(
                    token.key.clone(),
                    token.generation,
                    expires_at,
                    entry.transaction.retained_failure_ack(),
                )
                .map_err(ManagerError::Completion)?;
        }
        Ok(true)
    }

    /// Reclaims expired compact completion state.
    pub fn sweep_completions(&mut self, now: Duration) -> usize {
        self.completions.sweep(now)
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

    fn token(&mut self, key: TransactionKey, role: Role) -> Result<Token, ManagerError> {
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(ManagerError::GenerationExhausted)?;
        Ok(Token {
            key,
            generation,
            role,
        })
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
            .field("completions", &self.completions.len())
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
    /// A received response or request lacked a modern transaction key.
    Key(KeyError),
    /// ACK was passed to the ordinary request-routing API.
    UnexpectedAck,
    /// A non-ACK request was passed to the ACK-routing API.
    ExpectedAck,
    /// The monotonic generation space was exhausted.
    GenerationExhausted,
    /// Client engine rejected event.
    Client(ClientError),
    /// Server engine rejected event.
    Server(ServerError),
    /// Compact completion retention failed.
    Completion(CompletionError),
    /// Completion expiry arithmetic overflowed.
    TimeOverflow,
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
            Self::Key(error) => Some(error),
            Self::Client(error) => Some(error),
            Self::Server(error) => Some(error),
            Self::Completion(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use std::time::Duration;

    use super::{
        AckRoute, ClientResponseRoute, ManagerError, Role, ServerRequestRoute, TransactionManager,
    };
    use crate::sip::parser::message::parse;
    use crate::sip::transaction::client::{Action as ClientAction, ClientTransaction};
    use crate::sip::transaction::server::{Action as ServerAction, ServerTransaction};
    use crate::sip::transaction::timer::TimerConfig;
    use crate::sip::types::status::StatusCode;
    use crate::sip::validation;

    fn request(method: &str, branch: &str) -> validation::request::ValidatedRequest {
        let bytes = format!(
            "{method} sip:x@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP host;branch={branch}\r\n\
From: <sip:a@example.com>;tag=a\r\nTo: <sip:x@example.com>;tag=b\r\n\
Call-ID: one@example.com\r\nCSeq: 1 {method}\r\n\
Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
        );
        let Ok(raw) = parse(Arc::from(bytes.into_bytes())) else {
            panic!("parse request")
        };
        let Ok(request) = validation::request::validate(raw) else {
            panic!("validate request")
        };
        request
    }

    fn response(status: u16) -> validation::response::ValidatedResponse {
        let bytes = format!(
            "SIP/2.0 {status} Test\r\n\
Via: SIP/2.0/UDP host;branch=z9hG4bK-one\r\n\
From: <sip:a@example.com>;tag=a\r\nTo: <sip:x@example.com>;tag=b\r\n\
Call-ID: one@example.com\r\nCSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n"
        );
        let Ok(raw) = parse(Arc::from(bytes.into_bytes())) else {
            panic!("parse response")
        };
        let Ok(response) = validation::response::validate(raw) else {
            panic!("validate response")
        };
        response
    }

    #[test]
    fn response_dispatch_returns_generation_fenced_client_actions() {
        let Ok(mut transaction) = ClientTransaction::new(
            request("INVITE", "z9hG4bK-one"),
            false,
            TimerConfig::default(),
        ) else {
            panic!("client transaction")
        };
        assert!(transaction.start().is_ok());
        let Ok(mut manager) = TransactionManager::new(8) else {
            panic!("manager")
        };
        let Ok(inserted) = manager.insert_client(transaction) else {
            panic!("insert")
        };

        let Ok(routed) = manager.route_response(&response(486)) else {
            panic!("route response")
        };
        assert_eq!(routed.token(), &inserted);
        assert_eq!(routed.token().role(), Role::Client);
        assert!(matches!(
            routed.actions().first(),
            Some(ClientAction::SendAck(_))
        ));
    }

    #[test]
    fn start_client_returns_fenced_initial_send_and_timers() {
        let transaction = ClientTransaction::new(
            request("INVITE", "z9hG4bK-one"),
            false,
            TimerConfig::default(),
        )
        .unwrap_or_else(|_| panic!("client transaction"));
        let mut manager = TransactionManager::new(8).unwrap_or_else(|_| panic!("manager"));
        let routed = manager
            .start_client(transaction)
            .unwrap_or_else(|_| panic!("start"));

        assert_eq!(routed.token().role(), Role::Client);
        assert!(matches!(
            routed.actions().first(),
            Some(ClientAction::Send(_))
        ));
        assert_eq!(
            routed
                .actions()
                .iter()
                .filter(|action| matches!(action, ClientAction::Schedule { .. }))
                .count(),
            2
        );
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn retransmitted_request_is_absorbed_without_redelivery() {
        let invite = request("INVITE", "z9hG4bK-one");
        let Ok(mut transaction) = ServerTransaction::new(&invite, false, TimerConfig::default())
        else {
            panic!("server transaction")
        };
        assert!(transaction.start().is_ok());
        let Ok(mut manager) = TransactionManager::new(8) else {
            panic!("manager")
        };
        let Ok(inserted) = manager.insert_server(transaction) else {
            panic!("insert")
        };

        let Ok(ServerRequestRoute::Existing(routed)) = manager.route_request(&invite) else {
            panic!("existing request")
        };
        assert_eq!(routed.token(), &inserted);
        assert!(routed.actions().is_empty());

        let different = request("INVITE", "z9hG4bK-two");
        assert!(matches!(
            manager.route_request(&different),
            Ok(ServerRequestRoute::New)
        ));
        let ack = request("ACK", "z9hG4bK-one");
        assert!(matches!(
            manager.route_request(&ack),
            Err(ManagerError::UnexpectedAck)
        ));
    }

    #[test]
    fn transaction_ack_is_consumed_and_repeated_ack_is_absorbed() {
        let invite = request("INVITE", "z9hG4bK-one");
        let Ok(mut transaction) = ServerTransaction::new(&invite, false, TimerConfig::default())
        else {
            panic!("server transaction")
        };
        assert!(transaction.start().is_ok());
        assert!(
            transaction
                .send_response(StatusCode::BUSY_HERE, Arc::from(&b"failure"[..]))
                .is_ok()
        );
        let Ok(mut manager) = TransactionManager::new(8) else {
            panic!("manager")
        };
        let Ok(inserted) = manager.insert_server(transaction) else {
            panic!("insert")
        };
        let ack = request("ACK", "z9hG4bK-one");

        let Ok(AckRoute::Transaction(first)) = manager.route_ack(&ack) else {
            panic!("transaction ACK")
        };
        assert_eq!(first.token(), &inserted);
        assert!(first.actions().iter().any(|action| matches!(
            action,
            ServerAction::Cancel(crate::sip::transaction::server::Timer::Retransmit)
        )));

        let Ok(AckRoute::Transaction(repeated)) = manager.route_ack(&ack) else {
            panic!("repeated transaction ACK")
        };
        assert!(repeated.actions().is_empty());
    }

    #[test]
    fn ack_for_success_response_is_left_for_dialog_logic() {
        let invite = request("INVITE", "z9hG4bK-one");
        let Ok(mut transaction) = ServerTransaction::new(&invite, false, TimerConfig::default())
        else {
            panic!("server transaction")
        };
        assert!(transaction.start().is_ok());
        assert!(
            transaction
                .send_response(StatusCode::OK, Arc::from(&b"success"[..]))
                .is_ok()
        );
        let Ok(mut manager) = TransactionManager::new(8) else {
            panic!("manager")
        };
        assert!(manager.insert_server(transaction).is_ok());

        let Ok(ServerRequestRoute::Existing(duplicate)) = manager.route_request(&invite) else {
            panic!("accepted duplicate INVITE")
        };
        assert!(duplicate.actions().is_empty());

        let ack = request("ACK", "z9hG4bK-one");
        assert!(matches!(manager.route_ack(&ack), Ok(AckRoute::Dialog)));
        assert!(matches!(
            manager.route_ack(&invite),
            Err(ManagerError::ExpectedAck)
        ));
    }

    #[test]
    fn generation_exhaustion_never_wraps_or_reuses_tokens() {
        let Ok(mut manager) = TransactionManager::new(8) else {
            panic!("manager")
        };
        manager.next_generation = u64::MAX;
        let Ok(transaction) = ClientTransaction::new(
            request("INVITE", "z9hG4bK-one"),
            false,
            TimerConfig::default(),
        ) else {
            panic!("client transaction")
        };
        assert!(matches!(
            manager.insert_client(transaction),
            Err(ManagerError::GenerationExhausted)
        ));
        assert!(manager.is_empty());
        assert_eq!(manager.next_generation, u64::MAX);
    }

    #[test]
    fn compact_completion_routes_late_success_after_heavy_state_removal() {
        let Ok(mut transaction) = ClientTransaction::new(
            request("INVITE", "z9hG4bK-one"),
            true,
            TimerConfig::default(),
        ) else {
            panic!("transaction")
        };
        assert!(transaction.start().is_ok());
        assert!(transaction.on_response(&response(486)).is_ok());
        let Ok(mut manager) = TransactionManager::new(8) else {
            panic!("manager")
        };
        let token = manager
            .insert_client(transaction)
            .unwrap_or_else(|_| panic!("insert"));
        assert!(matches!(
            manager.complete_at(&token, Duration::ZERO),
            Ok(true)
        ));
        assert!(matches!(
            manager.route_response_at(&response(200), Duration::from_secs(1)),
            Ok(ClientResponseRoute::Retained(
                super::CompletionDisposition::DeliverLateSuccess { .. }
            ))
        ));
        assert_eq!(manager.sweep_completions(Duration::from_secs(33)), 1);
        assert!(matches!(
            manager.route_response_at(&response(200), Duration::from_secs(33)),
            Ok(ClientResponseRoute::Unknown)
        ));
    }
}
