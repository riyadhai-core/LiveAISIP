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

//! Deterministic SIP client transaction engine.
//!
//! The engine performs no I/O and owns no clock. It consumes validated
//! responses and timer events, then emits explicit actions for the transport,
//! timer wheel, and transaction manager. Immutable request bytes are retained
//! for retransmission without copying.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::key::{KeyError, TransactionKey};
use super::state::{ClientMachine, ClientState, StateError, TransactionKind};
use super::timer::{TimerConfig, TimerProfile};
use crate::sip::validation::request::ValidatedRequest;
use crate::sip::validation::response::ValidatedResponse;

/// Client transaction timer identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Timer {
    /// A/E request retransmission.
    Retransmit,
    /// B/F overall response timeout.
    RequestTimeout,
    /// D/K/M completed or accepted linger.
    Linger,
}

/// Side effect requested from the transaction owner.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Action {
    /// Send or retransmit immutable request bytes.
    Send(Arc<[u8]>),
    /// Schedule one generation-fenced timer.
    Schedule {
        /// Timer identity.
        timer: Timer,
        /// Delay from the scheduler's current instant.
        after: Duration,
    },
    /// Cancel a previously scheduled timer.
    Cancel(Timer),
    /// Deliver a response to the transaction user.
    DeliverResponse,
    /// Remove this transaction after emitted actions are processed.
    Terminate,
}

/// Deterministic client transaction state.
pub struct ClientTransaction {
    key: TransactionKey,
    machine: ClientMachine,
    profile: TimerProfile,
    request: Arc<[u8]>,
    next_retransmit: Option<Duration>,
    started: bool,
}

impl ClientTransaction {
    /// Creates a transaction from a fully validated outbound request.
    ///
    /// # Errors
    ///
    /// Requires a modern RFC 3261 transaction key.
    pub fn new(
        request: ValidatedRequest,
        reliable: bool,
        timers: TimerConfig,
    ) -> Result<Self, ClientError> {
        let key = TransactionKey::for_client_request(&request)?;
        let kind = TransactionKind::from_method(request.request_line().method());
        let profile = timers.profile(reliable);
        let bytes = request.into_message().into_bytes();
        Ok(Self {
            key,
            machine: ClientMachine::new(kind),
            profile,
            request: bytes,
            next_retransmit: profile.retransmit_initial(),
            started: false,
        })
    }

    /// Starts initial transmission and timers exactly once.
    ///
    /// # Errors
    ///
    /// Rejects repeated starts.
    pub fn start(&mut self) -> Result<Vec<Action>, ClientError> {
        if self.started {
            return Err(ClientError::AlreadyStarted);
        }
        self.started = true;
        let mut actions = vec![
            Action::Send(Arc::clone(&self.request)),
            Action::Schedule {
                timer: Timer::RequestTimeout,
                after: if self.machine.kind() == TransactionKind::Invite {
                    self.profile.invite_timeout()
                } else {
                    self.profile.non_invite_timeout()
                },
            },
        ];
        if let Some(after) = self.next_retransmit {
            actions.push(Action::Schedule {
                timer: Timer::Retransmit,
                after,
            });
        }
        Ok(actions)
    }

    /// Applies a validated response matching this transaction.
    ///
    /// # Errors
    ///
    /// Rejects pre-start, key mismatch, or illegal state transitions.
    pub fn on_response(
        &mut self,
        response: &ValidatedResponse,
    ) -> Result<Vec<Action>, ClientError> {
        self.require_started()?;
        if TransactionKey::for_client_response(response)? != self.key {
            return Err(ClientError::KeyMismatch);
        }
        let previous = self.machine.state();
        let state = self
            .machine
            .on_response(response.response_line().status())?;
        let mut actions = vec![Action::DeliverResponse];

        if state == ClientState::Proceeding
            && self.machine.kind() == TransactionKind::Invite
            && previous == ClientState::Calling
        {
            actions.push(Action::Cancel(Timer::Retransmit));
            self.next_retransmit = None;
        }

        if matches!(state, ClientState::Completed | ClientState::Accepted)
            && !matches!(previous, ClientState::Completed | ClientState::Accepted)
        {
            actions.push(Action::Cancel(Timer::Retransmit));
            actions.push(Action::Cancel(Timer::RequestTimeout));
            self.next_retransmit = None;
            let linger = match (self.machine.kind(), state) {
                (TransactionKind::Invite, ClientState::Accepted) => {
                    Some(self.profile.invite_timeout())
                }
                (TransactionKind::Invite, ClientState::Completed) => {
                    self.profile.completed_invite_linger()
                }
                (TransactionKind::NonInvite, ClientState::Completed) => {
                    self.profile.completed_non_invite_linger()
                }
                _ => None,
            };
            if let Some(after) = linger {
                actions.push(Action::Schedule {
                    timer: Timer::Linger,
                    after,
                });
            } else {
                self.machine.on_linger_timeout()?;
                actions.push(Action::Terminate);
            }
        }
        Ok(actions)
    }

    /// Applies a scheduler event.
    ///
    /// # Errors
    ///
    /// Rejects pre-start or timers invalid for the current state.
    pub fn on_timer(&mut self, timer: Timer) -> Result<Vec<Action>, ClientError> {
        self.require_started()?;
        match timer {
            Timer::RequestTimeout => {
                self.machine.on_request_timeout()?;
                Ok(vec![Action::Cancel(Timer::Retransmit), Action::Terminate])
            }
            Timer::Linger => {
                self.machine.on_linger_timeout()?;
                Ok(vec![Action::Terminate])
            }
            Timer::Retransmit => {
                let current = self.next_retransmit.ok_or(ClientError::InvalidTimer)?;
                let allowed = match self.machine.kind() {
                    TransactionKind::Invite => self.machine.state() == ClientState::Calling,
                    TransactionKind::NonInvite => matches!(
                        self.machine.state(),
                        ClientState::Trying | ClientState::Proceeding
                    ),
                };
                if !allowed {
                    return Err(ClientError::InvalidTimer);
                }
                let next = self
                    .profile
                    .next_retransmit(current)
                    .ok_or(ClientError::InvalidTimer)?;
                self.next_retransmit = Some(next);
                Ok(vec![
                    Action::Send(Arc::clone(&self.request)),
                    Action::Schedule {
                        timer: Timer::Retransmit,
                        after: next,
                    },
                ])
            }
        }
    }

    /// Returns transaction key.
    #[must_use]
    pub const fn key(&self) -> &TransactionKey {
        &self.key
    }

    /// Returns current client state.
    #[must_use]
    pub const fn state(&self) -> ClientState {
        self.machine.state()
    }

    fn require_started(&self) -> Result<(), ClientError> {
        if self.started {
            Ok(())
        } else {
            Err(ClientError::NotStarted)
        }
    }
}

impl fmt::Debug for ClientTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientTransaction")
            .field("state", &self.machine.state())
            .field("request_bytes", &self.request.len())
            .field("started", &self.started)
            .finish_non_exhaustive()
    }
}

/// Client transaction processing failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// Transaction key construction failed.
    Key(KeyError),
    /// State transition failed.
    State(StateError),
    /// Start was called twice.
    AlreadyStarted,
    /// Event arrived before start.
    NotStarted,
    /// Response belonged to another transaction.
    KeyMismatch,
    /// Timer was stale or invalid for current state.
    InvalidTimer,
}

impl From<KeyError> for ClientError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<StateError> for ClientError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP client transaction error")
    }
}

impl StdError for ClientError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Key(error) => Some(error),
            Self::State(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{Action, ClientTransaction, Timer};
    use crate::sip::parser::message::parse;
    use crate::sip::transaction::state::ClientState;
    use crate::sip::transaction::timer::TimerConfig;
    use crate::sip::validation;

    fn request() -> validation::request::ValidatedRequest {
        let bytes = b"INVITE sip:x@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP host;branch=z9hG4bK-one\r\n\
From: <sip:a@example.com>;tag=a\r\nTo: <sip:x@example.com>\r\n\
Call-ID: one@example.com\r\nCSeq: 1 INVITE\r\n\
Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n";
        let Ok(raw) = parse(Arc::from(&bytes[..])) else {
            panic!("parse")
        };
        let Ok(value) = validation::request::validate(raw) else {
            panic!("validate")
        };
        value
    }

    fn response(status: u16, reason: &str) -> validation::response::ValidatedResponse {
        let bytes = format!(
            "SIP/2.0 {status} {reason}\r\n\
Via: SIP/2.0/UDP host;branch=z9hG4bK-one\r\n\
From: <sip:a@example.com>;tag=a\r\nTo: <sip:x@example.com>;tag=b\r\n\
Call-ID: one@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        );
        let Ok(raw) = parse(Arc::from(bytes.into_bytes())) else {
            panic!("parse")
        };
        let Ok(value) = validation::response::validate(raw) else {
            panic!("validate")
        };
        value
    }

    #[test]
    fn unreliable_invite_runs_send_provisional_success_and_linger_paths() {
        let Ok(mut transaction) = ClientTransaction::new(request(), false, TimerConfig::default())
        else {
            panic!("transaction")
        };
        let Ok(start) = transaction.start() else {
            panic!("start")
        };
        assert!(start.iter().any(|action| matches!(action, Action::Send(_))));
        assert!(start.iter().any(|action| matches!(
            action,
            Action::Schedule {
                timer: Timer::Retransmit,
                ..
            }
        )));

        let Ok(retransmit) = transaction.on_timer(Timer::Retransmit) else {
            panic!("retransmit")
        };
        assert!(matches!(retransmit.first(), Some(Action::Send(_))));

        let Ok(provisional) = transaction.on_response(&response(180, "Ringing")) else {
            panic!("provisional")
        };
        assert_eq!(transaction.state(), ClientState::Proceeding);
        assert!(
            provisional
                .iter()
                .any(|action| matches!(action, Action::Cancel(Timer::Retransmit)))
        );

        let Ok(success) = transaction.on_response(&response(200, "OK")) else {
            panic!("success")
        };
        assert_eq!(transaction.state(), ClientState::Accepted);
        assert!(success.iter().any(|action| matches!(
            action,
            Action::Schedule {
                timer: Timer::Linger,
                ..
            }
        )));
        let Ok(done) = transaction.on_timer(Timer::Linger) else {
            panic!("linger")
        };
        assert!(matches!(done.as_slice(), [Action::Terminate]));
        assert_eq!(transaction.state(), ClientState::Terminated);
    }
}
