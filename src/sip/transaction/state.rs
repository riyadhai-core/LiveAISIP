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

//! Role-aware SIP transaction states.
//!
//! INVITE and non-INVITE transactions have distinct legal state graphs. These
//! wrappers validate every transition and keep impossible role/kind/state
//! combinations unrepresentable outside this module. Response classification
//! is numeric and does not depend on reason phrases.
//!
//! Timer scheduling and message side effects remain in client and server
//! transaction engines; this module owns only deterministic state legality.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::types::method::Method;
use crate::sip::types::status::StatusCode;

/// Transaction method family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransactionKind {
    /// INVITE transaction.
    Invite,
    /// Every non-INVITE transaction, including ACK and CANCEL when standalone.
    NonInvite,
}

impl TransactionKind {
    /// Classifies a method.
    #[must_use]
    pub const fn from_method(method: &Method) -> Self {
        if matches!(method, Method::Invite) {
            Self::Invite
        } else {
            Self::NonInvite
        }
    }
}

/// Client transaction state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientState {
    /// INVITE sent, no response received.
    Calling,
    /// Non-INVITE sent, no response received.
    Trying,
    /// Provisional response received.
    Proceeding,
    /// 3xx-6xx INVITE response received and ACK handling is active.
    Completed,
    /// 2xx INVITE response received; retransmitted 2xx responses remain matchable.
    Accepted,
    /// Transaction is terminal.
    Terminated,
}

/// Validated client state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientMachine {
    kind: TransactionKind,
    state: ClientState,
}

impl ClientMachine {
    /// Creates the correct initial state for a transaction kind.
    #[must_use]
    pub const fn new(kind: TransactionKind) -> Self {
        Self {
            kind,
            state: match kind {
                TransactionKind::Invite => ClientState::Calling,
                TransactionKind::NonInvite => ClientState::Trying,
            },
        }
    }

    /// Applies a received response status.
    ///
    /// # Errors
    ///
    /// Rejects responses after termination and transitions not legal for the
    /// current method family and state.
    #[allow(
        clippy::match_same_arms,
        reason = "distinct RFC client transitions remain explicit for protocol auditability"
    )]
    pub fn on_response(&mut self, status: StatusCode) -> Result<ClientState, StateError> {
        let code = status.as_u16();
        let next = match (self.kind, self.state, code) {
            (_, ClientState::Terminated, _) => return Err(StateError::Terminal),
            (
                TransactionKind::Invite,
                ClientState::Calling | ClientState::Proceeding,
                100..=199,
            ) => ClientState::Proceeding,
            (
                TransactionKind::Invite,
                ClientState::Calling | ClientState::Proceeding,
                200..=299,
            ) => ClientState::Accepted,
            (
                TransactionKind::Invite,
                ClientState::Calling | ClientState::Proceeding,
                300..=699,
            ) => ClientState::Completed,
            (TransactionKind::Invite, ClientState::Accepted, 200..=299) => ClientState::Accepted,
            (TransactionKind::Invite, ClientState::Completed, 300..=699) => ClientState::Completed,
            (
                TransactionKind::NonInvite,
                ClientState::Trying | ClientState::Proceeding,
                100..=199,
            ) => ClientState::Proceeding,
            (
                TransactionKind::NonInvite,
                ClientState::Trying | ClientState::Proceeding,
                200..=699,
            ) => ClientState::Completed,
            (TransactionKind::NonInvite, ClientState::Completed, 200..=699) => {
                ClientState::Completed
            }
            _ => {
                return Err(StateError::InvalidClientTransition {
                    kind: self.kind,
                    from: self.state,
                });
            }
        };
        self.state = next;
        Ok(next)
    }

    /// Applies the state-appropriate terminal timer.
    ///
    /// # Errors
    ///
    /// Only completed or accepted state can terminate by linger timer.
    pub fn on_linger_timeout(&mut self) -> Result<(), StateError> {
        if !matches!(self.state, ClientState::Completed | ClientState::Accepted) {
            return Err(StateError::InvalidClientTransition {
                kind: self.kind,
                from: self.state,
            });
        }
        self.state = ClientState::Terminated;
        Ok(())
    }

    /// Applies B/F request timeout.
    ///
    /// # Errors
    ///
    /// Only pre-final states can time out.
    pub fn on_request_timeout(&mut self) -> Result<(), StateError> {
        if !matches!(
            self.state,
            ClientState::Calling | ClientState::Trying | ClientState::Proceeding
        ) {
            return Err(StateError::InvalidClientTransition {
                kind: self.kind,
                from: self.state,
            });
        }
        self.state = ClientState::Terminated;
        Ok(())
    }

    /// Returns method family.
    #[must_use]
    pub const fn kind(self) -> TransactionKind {
        self.kind
    }

    /// Returns current state.
    #[must_use]
    pub const fn state(self) -> ClientState {
        self.state
    }

    /// Returns whether state is terminal.
    #[must_use]
    pub const fn is_terminated(self) -> bool {
        matches!(self.state, ClientState::Terminated)
    }
}

/// Server transaction state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ServerState {
    /// Request received; application may produce provisional/final response.
    Proceeding,
    /// Final non-2xx response sent.
    Completed,
    /// ACK received for a non-2xx INVITE response.
    Confirmed,
    /// 2xx INVITE response sent and retransmissions remain matchable.
    Accepted,
    /// Transaction is terminal.
    Terminated,
}

/// Validated server state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerMachine {
    kind: TransactionKind,
    state: ServerState,
}

impl ServerMachine {
    /// Creates initial proceeding state.
    #[must_use]
    pub const fn new(kind: TransactionKind) -> Self {
        Self {
            kind,
            state: ServerState::Proceeding,
        }
    }

    /// Applies an application response.
    ///
    /// # Errors
    ///
    /// Rejects status/state combinations outside the RFC state graph.
    #[allow(
        clippy::match_same_arms,
        reason = "distinct RFC server transitions remain explicit for protocol auditability"
    )]
    pub fn on_response(&mut self, status: StatusCode) -> Result<ServerState, StateError> {
        let code = status.as_u16();
        let next = match (self.kind, self.state, code) {
            (_, ServerState::Terminated, _) => return Err(StateError::Terminal),
            (_, ServerState::Proceeding, 100..=199) => ServerState::Proceeding,
            (TransactionKind::Invite, ServerState::Proceeding, 200..=299) => ServerState::Accepted,
            (TransactionKind::Invite, ServerState::Proceeding, 300..=699) => ServerState::Completed,
            (TransactionKind::Invite, ServerState::Accepted, 200..=299) => ServerState::Accepted,
            (TransactionKind::Invite, ServerState::Completed, 300..=699) => ServerState::Completed,
            (TransactionKind::NonInvite, ServerState::Proceeding, 200..=699) => {
                ServerState::Completed
            }
            (TransactionKind::NonInvite, ServerState::Completed, 200..=699) => {
                ServerState::Completed
            }
            _ => {
                return Err(StateError::InvalidServerTransition {
                    kind: self.kind,
                    from: self.state,
                });
            }
        };
        self.state = next;
        Ok(next)
    }

    /// Applies ACK to a completed INVITE server transaction.
    ///
    /// # Errors
    ///
    /// Only completed INVITE state accepts this event.
    pub fn on_ack(&mut self) -> Result<(), StateError> {
        if self.kind != TransactionKind::Invite || self.state != ServerState::Completed {
            return Err(StateError::InvalidServerTransition {
                kind: self.kind,
                from: self.state,
            });
        }
        self.state = ServerState::Confirmed;
        Ok(())
    }

    /// Applies the appropriate terminal timer.
    ///
    /// # Errors
    ///
    /// Only completed, confirmed, or accepted state can terminate.
    pub fn on_termination_timeout(&mut self) -> Result<(), StateError> {
        if !matches!(
            self.state,
            ServerState::Completed | ServerState::Confirmed | ServerState::Accepted
        ) {
            return Err(StateError::InvalidServerTransition {
                kind: self.kind,
                from: self.state,
            });
        }
        self.state = ServerState::Terminated;
        Ok(())
    }

    /// Returns current state.
    #[must_use]
    pub const fn state(self) -> ServerState {
        self.state
    }
}

/// Illegal transaction state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StateError {
    /// Event arrived after termination.
    Terminal,
    /// Client transition was illegal.
    InvalidClientTransition {
        /// Method family.
        kind: TransactionKind,
        /// Current state.
        from: ClientState,
    },
    /// Server transition was illegal.
    InvalidServerTransition {
        /// Method family.
        kind: TransactionKind,
        /// Current state.
        from: ServerState,
    },
}

impl StateError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::InvalidClientTransition { .. } => "invalid-client-transition",
            Self::InvalidServerTransition { .. } => "invalid-server-transition",
        }
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP transaction state error: {}", self.class())
    }
}

impl StdError for StateError {}

#[cfg(test)]
mod tests {
    use super::{
        ClientMachine, ClientState, ServerMachine, ServerState, StateError, TransactionKind,
    };
    use crate::sip::types::status::StatusCode;

    #[test]
    fn invite_client_separates_accepted_and_completed_paths() {
        let mut success = ClientMachine::new(TransactionKind::Invite);
        assert_eq!(
            success.on_response(StatusCode::RINGING),
            Ok(ClientState::Proceeding)
        );
        assert_eq!(
            success.on_response(StatusCode::OK),
            Ok(ClientState::Accepted)
        );

        let mut failure = ClientMachine::new(TransactionKind::Invite);
        assert_eq!(
            failure.on_response(StatusCode::BUSY_HERE),
            Ok(ClientState::Completed)
        );
        assert!(failure.on_linger_timeout().is_ok());
        assert!(failure.is_terminated());
    }

    #[test]
    fn non_invite_client_uses_trying_proceeding_completed() {
        let mut machine = ClientMachine::new(TransactionKind::NonInvite);
        assert_eq!(machine.state(), ClientState::Trying);
        assert_eq!(
            machine.on_response(StatusCode::TRYING),
            Ok(ClientState::Proceeding)
        );
        assert_eq!(
            machine.on_response(StatusCode::OK),
            Ok(ClientState::Completed)
        );
    }

    #[test]
    fn invite_server_requires_completed_before_ack() {
        let mut machine = ServerMachine::new(TransactionKind::Invite);
        assert!(matches!(
            machine.on_ack(),
            Err(StateError::InvalidServerTransition { .. })
        ));
        assert_eq!(
            machine.on_response(StatusCode::BUSY_HERE),
            Ok(ServerState::Completed)
        );
        assert!(machine.on_ack().is_ok());
        assert_eq!(machine.state(), ServerState::Confirmed);
    }

    #[test]
    fn terminated_state_rejects_late_events() {
        let mut machine = ClientMachine::new(TransactionKind::NonInvite);
        assert!(machine.on_request_timeout().is_ok());
        assert!(matches!(
            machine.on_response(StatusCode::OK),
            Err(StateError::Terminal)
        ));
    }
}
