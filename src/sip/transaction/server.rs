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

//! Deterministic SIP server transaction engine.
//!
//! This engine performs no socket I/O and owns no clock. It emits actions for
//! request delivery, response transmission, retransmission scheduling, timer
//! cancellation, and termination. The last response is retained immutably so
//! duplicate requests can be answered without rebuilding protocol state.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::key::{KeyError, TransactionKey};
use super::state::{ServerMachine, ServerState, StateError, TransactionKind};
use super::timer::{TimerConfig, TimerProfile};
use crate::sip::types::status::StatusCode;
use crate::sip::validation::request::ValidatedRequest;

/// Server transaction timer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Timer {
    /// G response retransmission.
    Retransmit,
    /// H/L final-response lifetime.
    FinalResponseLifetime,
    /// I/J terminal linger.
    Termination,
}

/// Side effect requested from the transaction owner.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Action {
    /// Deliver the initial request to application/dialog logic.
    DeliverRequest,
    /// Send immutable response bytes.
    SendResponse(Arc<[u8]>),
    /// Schedule a generation-fenced timer.
    Schedule {
        /// Timer identity.
        timer: Timer,
        /// Delay from scheduler current time.
        after: Duration,
    },
    /// Cancel a timer.
    Cancel(Timer),
    /// Remove the transaction.
    Terminate,
}

/// Deterministic server transaction.
pub struct ServerTransaction {
    key: TransactionKey,
    machine: ServerMachine,
    profile: TimerProfile,
    reliable: bool,
    last_response: Option<Arc<[u8]>>,
    next_retransmit: Option<Duration>,
    started: bool,
}

impl ServerTransaction {
    /// Creates state for a validated inbound request.
    ///
    /// # Errors
    ///
    /// Requires a modern RFC 3261 transaction key.
    pub fn new(
        request: &ValidatedRequest,
        reliable: bool,
        timers: TimerConfig,
    ) -> Result<Self, ServerError> {
        let key = TransactionKey::for_server_request(request)?;
        let kind = TransactionKind::from_method(request.request_line().method());
        let profile = timers.profile(reliable);
        Ok(Self {
            key,
            machine: ServerMachine::new(kind),
            profile,
            reliable,
            last_response: None,
            next_retransmit: profile.retransmit_initial(),
            started: false,
        })
    }

    /// Delivers the request exactly once.
    ///
    /// # Errors
    ///
    /// Rejects repeated starts.
    pub fn start(&mut self) -> Result<Vec<Action>, ServerError> {
        if self.started {
            return Err(ServerError::AlreadyStarted);
        }
        self.started = true;
        Ok(vec![Action::DeliverRequest])
    }

    /// Records and transmits a fully serialized response.
    ///
    /// # Errors
    ///
    /// Rejects pre-start, empty bytes, or illegal state/status transitions.
    pub fn send_response(
        &mut self,
        status: StatusCode,
        bytes: Arc<[u8]>,
    ) -> Result<Vec<Action>, ServerError> {
        self.require_started()?;
        if bytes.is_empty() {
            return Err(ServerError::EmptyResponse);
        }
        let previous = self.machine.state();
        let state = self.machine.on_response(status)?;
        self.last_response = Some(Arc::clone(&bytes));
        let mut actions = vec![Action::SendResponse(bytes)];

        if state != previous && matches!(state, ServerState::Completed | ServerState::Accepted) {
            match (self.machine_kind(), state) {
                (TransactionKind::Invite, ServerState::Completed) => {
                    if !self.reliable
                        && let Some(after) = self.next_retransmit
                    {
                        actions.push(Action::Schedule {
                            timer: Timer::Retransmit,
                            after,
                        });
                    }
                    actions.push(Action::Schedule {
                        timer: Timer::FinalResponseLifetime,
                        after: self.profile.invite_timeout(),
                    });
                }
                (TransactionKind::Invite, ServerState::Accepted) => {
                    actions.push(Action::Schedule {
                        timer: Timer::FinalResponseLifetime,
                        after: self.profile.invite_timeout(),
                    });
                }
                (TransactionKind::NonInvite, ServerState::Completed) => {
                    if let Some(after) = self.profile.server_non_invite_lifetime() {
                        actions.push(Action::Schedule {
                            timer: Timer::Termination,
                            after,
                        });
                    } else {
                        self.machine.on_termination_timeout()?;
                        actions.push(Action::Terminate);
                    }
                }
                _ => {}
            }
        }
        Ok(actions)
    }

    /// Replays the last response for a duplicate request.
    #[must_use]
    pub fn on_duplicate_request(&self) -> Option<Action> {
        self.last_response
            .as_ref()
            .map(|bytes| Action::SendResponse(Arc::clone(bytes)))
    }

    /// Applies ACK to a non-2xx INVITE final response.
    ///
    /// # Errors
    ///
    /// Rejects ACK in every other state.
    pub fn on_ack(&mut self) -> Result<Vec<Action>, ServerError> {
        self.require_started()?;
        self.machine.on_ack()?;
        let mut actions = vec![
            Action::Cancel(Timer::Retransmit),
            Action::Cancel(Timer::FinalResponseLifetime),
        ];
        if let Some(after) = self.profile.confirmed_invite_linger() {
            actions.push(Action::Schedule {
                timer: Timer::Termination,
                after,
            });
        } else {
            self.machine.on_termination_timeout()?;
            actions.push(Action::Terminate);
        }
        Ok(actions)
    }

    /// Applies a scheduled timer event.
    ///
    /// # Errors
    ///
    /// Rejects stale timers for the current state.
    pub fn on_timer(&mut self, timer: Timer) -> Result<Vec<Action>, ServerError> {
        self.require_started()?;
        match timer {
            Timer::Retransmit if self.machine.state() == ServerState::Completed => {
                let response = self
                    .last_response
                    .as_ref()
                    .ok_or(ServerError::InvalidTimer)?;
                let current = self.next_retransmit.ok_or(ServerError::InvalidTimer)?;
                let next = self
                    .profile
                    .next_retransmit(current)
                    .ok_or(ServerError::InvalidTimer)?;
                self.next_retransmit = Some(next);
                Ok(vec![
                    Action::SendResponse(Arc::clone(response)),
                    Action::Schedule {
                        timer: Timer::Retransmit,
                        after: next,
                    },
                ])
            }
            Timer::FinalResponseLifetime
                if matches!(
                    self.machine.state(),
                    ServerState::Completed | ServerState::Accepted
                ) =>
            {
                self.machine.on_termination_timeout()?;
                Ok(vec![Action::Cancel(Timer::Retransmit), Action::Terminate])
            }
            Timer::Termination
                if matches!(
                    self.machine.state(),
                    ServerState::Completed | ServerState::Confirmed
                ) =>
            {
                self.machine.on_termination_timeout()?;
                Ok(vec![Action::Terminate])
            }
            _ => Err(ServerError::InvalidTimer),
        }
    }

    /// Returns transaction key.
    #[must_use]
    pub const fn key(&self) -> &TransactionKey {
        &self.key
    }

    /// Returns current state.
    #[must_use]
    pub const fn state(&self) -> ServerState {
        self.machine.state()
    }

    fn machine_kind(&self) -> TransactionKind {
        if self.key.is_invite() {
            TransactionKind::Invite
        } else {
            TransactionKind::NonInvite
        }
    }

    fn require_started(&self) -> Result<(), ServerError> {
        if self.started {
            Ok(())
        } else {
            Err(ServerError::NotStarted)
        }
    }
}

impl fmt::Debug for ServerTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerTransaction")
            .field("state", &self.machine.state())
            .field("response_present", &self.last_response.is_some())
            .field("started", &self.started)
            .finish_non_exhaustive()
    }
}

/// Server transaction processing failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServerError {
    /// Key construction failed.
    Key(KeyError),
    /// State transition failed.
    State(StateError),
    /// Start was called twice.
    AlreadyStarted,
    /// Event arrived before start.
    NotStarted,
    /// Serialized response was empty.
    EmptyResponse,
    /// Timer was stale for current state.
    InvalidTimer,
}

impl From<KeyError> for ServerError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}
impl From<StateError> for ServerError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}
impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP server transaction error")
    }
}
impl StdError for ServerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Key(error) => Some(error),
            Self::State(error) => Some(error),
            _ => None,
        }
    }
}
