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
use crate::sip::builder::request::{BuildError as RequestBuildError, RequestBuilder};
use crate::sip::headers::cseq::{CSeq, ParseError as CSeqParseError};
use crate::sip::headers::from::FromHeader;
use crate::sip::headers::max_forwards::MaxForwards;
use crate::sip::headers::to::ToHeader;
use crate::sip::headers::via::Via;
use crate::sip::types::header::{Header, HeaderKind, HeaderName, HeaderValue, HeaderValueError};
use crate::sip::types::method::Method;
use crate::sip::types::uri::Uri;
use crate::sip::validation::headers::{
    LogicalValueError, analyze_logical_value, materialize_logical_value, trim_horizontal_whitespace,
};
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
    /// Send the transaction-owned ACK for a non-2xx INVITE response.
    SendAck(Arc<[u8]>),
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
    non_2xx_ack_template: Option<Non2xxAckTemplate>,
    non_2xx_ack: Option<Arc<[u8]>>,
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
        let non_2xx_ack_template = if kind == TransactionKind::Invite {
            Some(Non2xxAckTemplate::from_request(&request)?)
        } else {
            None
        };
        let bytes = request.into_message().into_bytes();
        Ok(Self {
            key,
            machine: ClientMachine::new(kind),
            profile,
            request: bytes,
            non_2xx_ack_template,
            non_2xx_ack: None,
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
        let status = response.response_line().status();
        let mut next_machine = self.machine;
        let state = next_machine.on_response(status)?;
        let non_2xx_invite = self.machine.kind() == TransactionKind::Invite
            && (300..=699).contains(&status.as_u16());
        let late_forked_success = self.machine.kind() == TransactionKind::Invite
            && previous == ClientState::Completed
            && (200..=299).contains(&status.as_u16());

        let ack = if non_2xx_invite {
            if let Some(bytes) = &self.non_2xx_ack {
                Some(Arc::clone(bytes))
            } else {
                let template = self
                    .non_2xx_ack_template
                    .as_ref()
                    .ok_or(ClientError::MissingAckTemplate)?;
                Some(template.build(response.core_headers().to_header())?)
            }
        } else {
            None
        };

        self.machine = next_machine;
        if self.non_2xx_ack.is_none()
            && let Some(bytes) = &ack
        {
            self.non_2xx_ack = Some(Arc::clone(bytes));
        }

        let retransmitted_failure = non_2xx_invite && previous == ClientState::Completed;
        let mut actions = Vec::new();
        if let Some(bytes) = ack {
            actions.push(Action::SendAck(bytes));
        }
        if !retransmitted_failure {
            actions.push(Action::DeliverResponse);
        }

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
        if late_forked_success {
            // Replace Timer D with RFC 6026 Timer M. A stale generation-fenced
            // Timer D callback is harmless, but explicit cancellation keeps
            // scheduler occupancy bounded and diagnostics accurate.
            actions.push(Action::Cancel(Timer::Linger));
            actions.push(Action::Schedule {
                timer: Timer::Linger,
                after: self.profile.invite_timeout(),
            });
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
                let next = match self.machine.kind() {
                    TransactionKind::Invite => self.profile.next_invite_client_retransmit(current),
                    TransactionKind::NonInvite => self.profile.next_non_invite_client_retransmit(
                        current,
                        self.machine.state() == ClientState::Proceeding,
                    ),
                }
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

    /// Returns transaction method family.
    #[must_use]
    pub const fn kind(&self) -> TransactionKind {
        self.machine.kind()
    }

    /// Returns compact failure ACK bytes when one was constructed.
    #[must_use]
    pub fn retained_failure_ack(&self) -> Option<Arc<[u8]>> {
        self.non_2xx_ack.as_ref().map(Arc::clone)
    }

    /// Returns Timer-M-sized late response retention interval.
    #[must_use]
    pub const fn completion_retention(&self) -> Duration {
        self.profile.invite_timeout()
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
            .field("non_2xx_ack_cached", &self.non_2xx_ack.is_some())
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
    /// An INVITE transaction lacked its construction-time ACK template.
    MissingAckTemplate,
    /// The transaction-owned non-2xx ACK could not be constructed safely.
    Ack(AckBuildError),
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

impl From<AckBuildError> for ClientError {
    fn from(error: AckBuildError) -> Self {
        Self::Ack(error)
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
            Self::Ack(error) => Some(error),
            _ => None,
        }
    }
}

struct Non2xxAckTemplate {
    uri: Uri,
    via: Via,
    from: FromHeader,
    call_id: crate::sip::headers::call_id::CallId,
    sequence: u32,
    max_forwards: MaxForwards,
    routes: Vec<Header>,
}

impl Non2xxAckTemplate {
    fn from_request(request: &ValidatedRequest) -> Result<Self, AckBuildError> {
        let core = request.core_headers();
        let max_forwards = core
            .max_forwards()
            .ok_or(AckBuildError::MissingMaxForwards)?;
        let routes = copy_route_fields(request)?;

        Ok(Self {
            uri: request.request_line().uri().clone(),
            via: Via::new(core.topmost_via().clone()),
            from: core.from_header().clone(),
            call_id: core.call_id().clone(),
            sequence: core.cseq().sequence(),
            max_forwards,
            routes,
        })
    }

    fn build(&self, to: &ToHeader) -> Result<Arc<[u8]>, AckBuildError> {
        let cseq = CSeq::new(self.sequence, Method::Ack).map_err(AckBuildError::CSeq)?;
        let mut builder = RequestBuilder::new(
            Method::Ack,
            self.uri.clone(),
            &self.via,
            &self.from,
            to,
            &self.call_id,
            &cseq,
            self.max_forwards,
        )
        .map_err(AckBuildError::Request)?;

        for route in &self.routes {
            builder
                .push_header(route.clone())
                .map_err(AckBuildError::Request)?;
        }

        let bytes = builder.serialize().map_err(AckBuildError::Request)?;
        Ok(Arc::from(bytes))
    }
}

fn copy_route_fields(request: &ValidatedRequest) -> Result<Vec<Header>, AckBuildError> {
    let mut routes = Vec::new();
    for field in request.message().header_views() {
        if HeaderKind::from_name_bytes(field.name()) != Some(HeaderKind::Route) {
            continue;
        }

        let analysis = analyze_logical_value(field.value()).map_err(AckBuildError::RouteValue)?;
        let value = materialize_logical_value(analysis).map_err(AckBuildError::RouteValue)?;
        let value = HeaderValue::from_bytes(trim_horizontal_whitespace(value.as_ref()))
            .map_err(AckBuildError::HeaderValue)?;
        routes
            .try_reserve_exact(1)
            .map_err(|_| AckBuildError::AllocationFailed)?;
        routes.push(Header::new(HeaderName::known(HeaderKind::Route), value));
    }
    Ok(routes)
}

/// Failure to prepare or serialize a transaction-owned non-2xx ACK.
#[derive(Debug)]
#[non_exhaustive]
pub enum AckBuildError {
    /// The validated outbound request unexpectedly omitted Max-Forwards.
    MissingMaxForwards,
    /// A copied Route field could not be normalized safely.
    RouteValue(LogicalValueError),
    /// A normalized Route field could not become an outbound value.
    HeaderValue(HeaderValueError),
    /// The ACK `CSeq` could not be constructed.
    CSeq(CSeqParseError),
    /// Bounded request construction or serialization failed.
    Request(RequestBuildError),
    /// Bounded template allocation failed.
    AllocationFailed,
}

impl fmt::Display for AckBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP non-2xx ACK construction failed")
    }
}

impl StdError for AckBuildError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::RouteValue(error) => Some(error),
            Self::HeaderValue(error) => Some(error),
            Self::CSeq(error) => Some(error),
            Self::Request(error) => Some(error),
            Self::MissingMaxForwards | Self::AllocationFailed => None,
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

    fn request_with_routes() -> validation::request::ValidatedRequest {
        let bytes = b"INVITE sip:x@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP host;branch=z9hG4bK-one\r\n\
From: <sip:a@example.com>;tag=a\r\nTo: <sip:x@example.com>\r\n\
Call-ID: one@example.com\r\nCSeq: 1 INVITE\r\n\
Max-Forwards: 70\r\n\
Route: <sip:first.example.com;lr>\r\n\
Route: <sip:second.example.com;lr>\r\n\
Content-Length: 0\r\n\r\n";
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

    #[test]
    fn non_2xx_invite_ack_is_built_owned_and_retransmitted_without_redelivery() {
        let Ok(mut transaction) =
            ClientTransaction::new(request_with_routes(), false, TimerConfig::default())
        else {
            panic!("transaction")
        };
        assert!(transaction.start().is_ok());

        let failure_response = response(486, "Busy Here");
        let Ok(first) = transaction.on_response(&failure_response) else {
            panic!("failure response")
        };
        assert_eq!(transaction.state(), ClientState::Completed);
        assert!(matches!(first.first(), Some(Action::SendAck(_))));
        assert!(matches!(first.get(1), Some(Action::DeliverResponse)));

        let Some(Action::SendAck(first_ack)) = first.first() else {
            panic!("missing ACK")
        };
        let Ok(raw_ack) = parse(Arc::clone(first_ack)) else {
            panic!("parse ACK")
        };
        let Ok(ack) = validation::request::validate(raw_ack) else {
            panic!("validate ACK")
        };

        assert_eq!(
            ack.request_line().method(),
            &crate::sip::types::method::Method::Ack
        );
        assert_eq!(ack.request_line().uri().to_string(), "sip:x@example.com");
        assert_eq!(ack.core_headers().cseq().sequence(), 1);
        assert_eq!(
            ack.core_headers().cseq().method(),
            &crate::sip::types::method::Method::Ack
        );
        assert_eq!(ack.core_headers().to_header().tag(), Some("b"));
        assert_eq!(ack.core_headers().via_entry_count(), 1);
        assert_eq!(
            ack.core_headers().topmost_via().branch(),
            Some("z9hG4bK-one")
        );
        assert_eq!(ack.message().body(), b"");

        let routes: Vec<&[u8]> = ack
            .message()
            .header_views()
            .filter(|header| header.kind() == Some(&crate::sip::types::header::HeaderKind::Route))
            .map(crate::sip::types::message::RawHeaderView::value)
            .collect();
        assert_eq!(
            routes,
            vec![
                b" <sip:first.example.com;lr>".as_slice(),
                b" <sip:second.example.com;lr>".as_slice()
            ]
        );

        let Ok(repeated) = transaction.on_response(&failure_response) else {
            panic!("retransmitted failure response")
        };
        let [Action::SendAck(repeated_ack)] = repeated.as_slice() else {
            panic!("retransmitted response must only resend ACK")
        };
        assert!(Arc::ptr_eq(first_ack, repeated_ack));
    }

    #[test]
    fn successful_invite_response_never_generates_transaction_ack() {
        let Ok(mut transaction) = ClientTransaction::new(request(), false, TimerConfig::default())
        else {
            panic!("transaction")
        };
        assert!(transaction.start().is_ok());
        let Ok(actions) = transaction.on_response(&response(200, "OK")) else {
            panic!("response")
        };
        assert!(
            actions
                .iter()
                .all(|action| !matches!(action, Action::SendAck(_)))
        );
    }

    #[test]
    fn late_forked_success_after_failure_enters_timer_m_window() {
        let Ok(mut transaction) = ClientTransaction::new(request(), false, TimerConfig::default())
        else {
            panic!("transaction")
        };
        assert!(transaction.start().is_ok());
        assert!(transaction.on_response(&response(486, "Busy Here")).is_ok());
        assert_eq!(transaction.state(), ClientState::Completed);

        let actions = transaction
            .on_response(&response(200, "OK"))
            .unwrap_or_else(|_| panic!("late success"));
        assert_eq!(transaction.state(), ClientState::Accepted);
        assert!(matches!(actions.first(), Some(Action::DeliverResponse)));
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::Cancel(Timer::Linger)))
        );
        assert!(actions.iter().any(|action| matches!(
            action,
            Action::Schedule {
                timer: Timer::Linger,
                ..
            }
        )));
    }
}
