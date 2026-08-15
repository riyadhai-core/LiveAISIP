// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Call-owned executable UDP SIP signaling.
//!
//! This module binds the deterministic client transaction engine to a real
//! [`UdpDriver`]. It remains owned and invoked exclusively by one
//! [`CallRuntime`](super::runtime::CallRuntime); socket I/O never mutates call
//! state from another thread.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::runtime::deadline::{DeadlineError, DeadlineId, DeadlineOwner, DeadlineScheduler};
use crate::sip::auth::{
    AuthChallenge, AuthContext, AuthContextError, AuthScope, ChallengeParseError, DigestCredentials,
};
use crate::sip::builder::request::RequestBuilder;
use crate::sip::headers::authorization::Authorization;
use crate::sip::headers::call_id::CallId;
use crate::sip::headers::content_type::ContentType;
use crate::sip::headers::cseq::CSeq;
use crate::sip::headers::from::FromHeader;
use crate::sip::headers::max_forwards::MaxForwards;
use crate::sip::headers::proxy_authorization::ProxyAuthorization;
use crate::sip::headers::to::ToHeader;
use crate::sip::headers::via::Via;
use crate::sip::parser::message;
use crate::sip::transaction::client::{Action, ClientTransaction, Timer};
use crate::sip::transaction::completion::CompletionDisposition;
use crate::sip::transaction::manager::{
    ClientResponseRoute, ManagerError, Token, TransactionManager,
};
use crate::sip::transaction::timer::TimerConfig;
use crate::sip::transport::destination::Destination;
use crate::sip::transport::udp::{OutboundDatagram, UdpConfig, UdpError};
use crate::sip::transport::udp_driver::{
    InboundMessage, UdpDriver, UdpDriverConfig, UdpDriverError,
};
use crate::sip::types::header::{Header, HeaderKind, HeaderName, HeaderValue};
use crate::sip::types::method::Method;
use crate::sip::types::uri::Uri;
use crate::sip::validation::headers::{
    LogicalValueError, analyze_logical_value, materialize_logical_value, trim_horizontal_whitespace,
};
use crate::sip::validation::request::ValidatedRequest;
use crate::sip::validation::response::ValidatedResponse;
use crate::util::id::IdGenerator;
use crate::util::time::checked_deadline;

use super::events::{CallAction, CallEvent};
use super::leg::{DialogBranchId, MAX_FORKED_DIALOGS};

/// Maximum SIP datagrams drained for one call-thread readiness turn.
pub const MAX_SIGNALING_DATAGRAMS_PER_POLL: usize = 64;
/// Maximum simultaneously tracked client transaction timers per call.
pub const MAX_CLIENT_TRANSACTION_TIMERS: usize = 384;

struct TimerEntry {
    id: DeadlineId,
    token: Token,
    timer: Timer,
}

struct RequestTemplate {
    request_uri: Uri,
    from: FromHeader,
    initial_to: ToHeader,
    call_id: CallId,
    invite_sequence: u32,
    max_forwards: MaxForwards,
    extension_headers: Vec<Header>,
    content_type: Option<ContentType>,
    body: Box<[u8]>,
}

struct ConfirmedBranch {
    id: DialogBranchId,
    to: ToHeader,
    invite_sequence: u32,
}

/// One call-owned UDP socket, destination, initial transaction, and timers.
pub struct UdpSignaling {
    driver: UdpDriver,
    destination: Destination,
    advertised_addr: SocketAddr,
    udp: UdpConfig,
    initial_invite: Option<ValidatedRequest>,
    template: Option<RequestTemplate>,
    credentials: Option<DigestCredentials>,
    server_authorization: Option<Authorization>,
    proxy_authorization: Option<ProxyAuthorization>,
    confirmed: Vec<ConfirmedBranch>,
    identifiers: IdGenerator,
    timers: Vec<TimerEntry>,
    received: u64,
    rejected: u64,
    sent: u64,
}

impl UdpSignaling {
    /// Binds a nonblocking UDP socket for one outbound call.
    ///
    /// # Errors
    ///
    /// Preserves destination, socket, and fixed timer-storage failures.
    pub fn bind(
        local: SocketAddr,
        remote: SocketAddr,
        driver: UdpDriverConfig,
        udp: UdpConfig,
    ) -> Result<Self, SignalingError> {
        let destination = Destination::udp(remote).map_err(SignalingError::Destination)?;
        let driver = UdpDriver::bind(local, driver).map_err(SignalingError::Driver)?;
        let mut timers = Vec::new();
        timers
            .try_reserve_exact(MAX_CLIENT_TRANSACTION_TIMERS)
            .map_err(|_| SignalingError::AllocationFailed)?;
        let mut confirmed = Vec::new();
        confirmed
            .try_reserve_exact(MAX_FORKED_DIALOGS)
            .map_err(|_| SignalingError::AllocationFailed)?;
        let advertised_addr = driver.local_addr();
        Ok(Self {
            driver,
            destination,
            advertised_addr,
            udp,
            initial_invite: None,
            template: None,
            credentials: None,
            server_authorization: None,
            proxy_authorization: None,
            confirmed,
            identifiers: IdGenerator::new(),
            timers,
            received: 0,
            rejected: 0,
            sent: 0,
        })
    }

    /// Returns the actual bound local signaling endpoint.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.driver.local_addr()
    }

    /// Selects the reachable address serialized into generated Via fields.
    ///
    /// This is required when the socket is bound to a wildcard address. The
    /// port must be the actual bound UDP port so responses return to this
    /// call-owned socket.
    ///
    /// # Errors
    ///
    /// Rejects an unspecified IP, port zero, or a port different from the
    /// bound socket.
    pub fn with_advertised_addr(mut self, address: SocketAddr) -> Result<Self, SignalingError> {
        if address.ip().is_unspecified()
            || address.port() == 0
            || address.port() != self.driver.local_addr().port()
        {
            return Err(SignalingError::InvalidAdvertisedAddress);
        }
        self.advertised_addr = address;
        Ok(self)
    }

    /// Returns the address generated into Via by this signaling owner.
    #[must_use]
    pub const fn advertised_addr(&self) -> SocketAddr {
        self.advertised_addr
    }

    /// Installs validated Digest credentials before the call starts.
    ///
    /// Password material remains inside the redacted credential type and is
    /// never copied into diagnostics or retained by generated SIP headers.
    #[must_use]
    pub fn with_credentials(mut self, credentials: DigestCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Installs the already parsed and semantically validated initial INVITE.
    ///
    /// # Errors
    ///
    /// Rejects replacement or a non-INVITE request.
    pub fn install_initial_invite(
        &mut self,
        request: ValidatedRequest,
    ) -> Result<(), SignalingError> {
        if self.initial_invite.is_some() {
            return Err(SignalingError::InitialInviteAlreadyInstalled);
        }
        if request.request_line().method() != &crate::sip::types::method::Method::Invite {
            return Err(SignalingError::InitialRequestNotInvite);
        }
        let core = request.core_headers();
        let max_forwards = core
            .max_forwards()
            .ok_or(SignalingError::InitialInviteMissingMaxForwards)?;
        let mut extension_headers = Vec::new();
        extension_headers
            .try_reserve_exact(request.message().header_count())
            .map_err(|_| SignalingError::AllocationFailed)?;
        for field in request.message().header_views() {
            let kind = field.kind().copied();
            if kind.is_some_and(is_retry_managed_header) {
                continue;
            }
            let analysis = analyze_logical_value(field.value())
                .map_err(SignalingError::HeaderNormalization)?;
            let logical =
                materialize_logical_value(analysis).map_err(SignalingError::HeaderNormalization)?;
            let value = trim_horizontal_whitespace(logical.as_ref());
            let name = HeaderName::from_bytes(field.name()).map_err(SignalingError::HeaderName)?;
            let value = HeaderValue::from_bytes(value).map_err(SignalingError::HeaderValue)?;
            extension_headers.push(Header::new(name, value));
        }
        self.template = Some(RequestTemplate {
            request_uri: request.request_line().uri().clone(),
            from: core.from_header().clone(),
            initial_to: core.to_header().clone(),
            call_id: core.call_id().clone(),
            invite_sequence: core.cseq().sequence(),
            max_forwards,
            extension_headers,
            content_type: core.content_type().cloned(),
            body: request.message().body().into(),
        });
        self.initial_invite = Some(request);
        Ok(())
    }

    /// Starts and sends the installed initial INVITE transaction.
    ///
    /// # Errors
    ///
    /// Preserves transaction, transport, timer, and monotonic failures.
    pub(crate) fn start(
        &mut self,
        transactions: &mut TransactionManager,
        deadlines: &mut DeadlineScheduler,
        now: Duration,
    ) -> Result<(), SignalingError> {
        let request = self
            .initial_invite
            .take()
            .ok_or(SignalingError::InitialInviteMissing)?;
        let transaction = ClientTransaction::new(request, false, TimerConfig::default())
            .map_err(SignalingError::Client)?;
        let routed = transactions
            .start_client(transaction)
            .map_err(SignalingError::Transactions)?;
        let (token, actions) = routed.into_parts();
        self.execute_actions(transactions, deadlines, &token, actions, now)?;
        Ok(())
    }

    /// Drains and routes a bounded batch of real UDP SIP messages.
    ///
    /// # Errors
    ///
    /// Fatal socket and transaction failures are returned. One malformed
    /// datagram is counted and isolated without terminating the call.
    pub(crate) fn poll(
        &mut self,
        transactions: &mut TransactionManager,
        deadlines: &mut DeadlineScheduler,
        authentication: &mut AuthContext,
        now: Duration,
    ) -> Result<Vec<CallEvent>, SignalingError> {
        let mut events = Vec::new();
        for _ in 0..MAX_SIGNALING_DATAGRAMS_PER_POLL {
            let received = match self.driver.receive() {
                Ok(received) => received,
                Err(error) if error.io_kind() == Some(io::ErrorKind::WouldBlock) => break,
                Err(error) if error.io_kind().is_some() => {
                    return Err(SignalingError::Driver(error));
                }
                Err(_) => {
                    self.rejected = self.rejected.saturating_add(1);
                    continue;
                }
            };
            self.received = self.received.saturating_add(1);
            let InboundMessage::Response(response) = received.message() else {
                self.rejected = self.rejected.saturating_add(1);
                continue;
            };
            let route = transactions
                .route_response_at(response, now)
                .map_err(SignalingError::Transactions)?;
            let deliver = match route {
                ClientResponseRoute::Live(routed) => {
                    let (token, actions) = routed.into_parts();
                    self.execute_actions(transactions, deadlines, &token, actions, now)?
                }
                ClientResponseRoute::Retained(CompletionDisposition::ResendFailureAck {
                    ack,
                    ..
                }) => {
                    self.send(ack)?;
                    false
                }
                ClientResponseRoute::Retained(CompletionDisposition::DeliverLateSuccess {
                    ..
                }) => true,
                ClientResponseRoute::Retained(CompletionDisposition::Absorb { .. })
                | ClientResponseRoute::Unknown => false,
            };
            if deliver
                && self.retry_authenticated_invite(
                    response,
                    transactions,
                    deadlines,
                    authentication,
                    now,
                )?
            {
                continue;
            }
            if deliver && let Some(event) = response_event(response)? {
                if let CallEvent::InviteAccepted { branch } = &event {
                    self.remember_confirmed(
                        branch.clone(),
                        response.core_headers().to_header(),
                        response.core_headers().cseq().sequence(),
                    )?;
                }
                events.push(event);
            }
        }
        Ok(events)
    }

    /// Executes SIP wire effects selected by deterministic call lifecycle.
    pub(crate) fn execute_call_actions(
        &mut self,
        actions: &[CallAction],
        transactions: &mut TransactionManager,
        deadlines: &mut DeadlineScheduler,
        now: Duration,
    ) -> Result<(), SignalingError> {
        for action in actions {
            match action {
                CallAction::SendCancel => {
                    let request = self.build_request(Method::Cancel, None)?;
                    self.start_request(request, transactions, deadlines, now)?;
                }
                CallAction::SendAck { branch } => {
                    let request = self.build_request(Method::Ack, Some(branch))?;
                    self.send(request.into_message().into_bytes())?;
                }
                CallAction::SendBye { branch } => {
                    let request = self.build_request(Method::Bye, Some(branch))?;
                    self.start_request(request, transactions, deadlines, now)?;
                }
                CallAction::SendInvite
                | CallAction::SelectBranch { .. }
                | CallAction::ApplyEarlyMedia { .. }
                | CallAction::SendRefer { .. }
                | CallAction::SendReferReplaces { .. }
                | CallAction::ApplySessionModification { .. }
                | CallAction::Ended(_) => {}
            }
        }
        Ok(())
    }

    /// Applies one due generation-fenced client transaction timer.
    pub(crate) fn on_deadline(
        &mut self,
        id: DeadlineId,
        transactions: &mut TransactionManager,
        deadlines: &mut DeadlineScheduler,
        now: Duration,
    ) -> Result<Option<CallEvent>, SignalingError> {
        let Some(index) = self.timers.iter().position(|entry| entry.id == id) else {
            return Ok(None);
        };
        let entry = self.timers.swap_remove(index);
        let actions = transactions
            .client_timer(&entry.token, entry.timer)
            .map_err(SignalingError::Transactions)?;
        self.execute_actions(transactions, deadlines, &entry.token, actions, now)?;
        Ok((entry.timer == Timer::RequestTimeout).then_some(CallEvent::SignalingTimedOut))
    }

    fn execute_actions(
        &mut self,
        transactions: &mut TransactionManager,
        deadlines: &mut DeadlineScheduler,
        token: &Token,
        actions: Vec<Action>,
        now: Duration,
    ) -> Result<bool, SignalingError> {
        let mut deliver = false;
        for action in actions {
            match action {
                Action::Send(bytes) | Action::SendAck(bytes) => self.send(bytes)?,
                Action::Schedule { timer, after } => {
                    self.cancel_timer(token, timer, deadlines);
                    if self.timers.len() >= MAX_CLIENT_TRANSACTION_TIMERS {
                        return Err(SignalingError::TimerCapacity);
                    }
                    let at =
                        checked_deadline(now, after).map_err(|_| SignalingError::TimeOverflow)?;
                    let id = deadlines
                        .schedule(
                            at,
                            DeadlineOwner::Transaction,
                            token.generation(),
                            timer_kind(timer),
                        )
                        .map_err(SignalingError::Deadlines)?;
                    self.timers.push(TimerEntry {
                        id,
                        token: token.clone(),
                        timer,
                    });
                }
                Action::Cancel(timer) => self.cancel_timer(token, timer, deadlines),
                Action::DeliverResponse => deliver = true,
                Action::Terminate => {
                    self.cancel_token(token, deadlines);
                    transactions
                        .complete_at(token, now)
                        .map_err(SignalingError::Transactions)?;
                }
            }
        }
        Ok(deliver)
    }

    fn start_request(
        &mut self,
        request: ValidatedRequest,
        transactions: &mut TransactionManager,
        deadlines: &mut DeadlineScheduler,
        now: Duration,
    ) -> Result<(), SignalingError> {
        let transaction = ClientTransaction::new(request, false, TimerConfig::default())
            .map_err(SignalingError::Client)?;
        let (token, actions) = transactions
            .start_client(transaction)
            .map_err(SignalingError::Transactions)?
            .into_parts();
        self.execute_actions(transactions, deadlines, &token, actions, now)?;
        Ok(())
    }

    fn build_request(
        &mut self,
        method: Method,
        branch: Option<&DialogBranchId>,
    ) -> Result<ValidatedRequest, SignalingError> {
        let template = self
            .template
            .as_ref()
            .ok_or(SignalingError::InitialInviteMissing)?;
        let to = match branch {
            Some(branch) => self
                .confirmed
                .iter()
                .find(|confirmed| &confirmed.id == branch)
                .map(|confirmed| &confirmed.to)
                .ok_or(SignalingError::UnknownDialogBranch)?,
            None => &template.initial_to,
        };
        let sequence = match method {
            Method::Ack => branch
                .and_then(|id| self.confirmed.iter().find(|entry| &entry.id == id))
                .map_or(template.invite_sequence, |entry| entry.invite_sequence),
            Method::Cancel => template.invite_sequence,
            _ => template
                .invite_sequence
                .checked_add(1)
                .ok_or(SignalingError::SequenceExhausted)?,
        };
        let cseq = CSeq::new(sequence, method.clone()).map_err(SignalingError::CSeq)?;
        let id = self
            .identifiers
            .allocate()
            .map_err(|_| SignalingError::IdentifierExhausted)?;
        let via_text = format!("SIP/2.0/UDP {};branch=z9hG4bK-{id}", self.advertised_addr);
        let via = Via::from_bytes(via_text.as_bytes()).map_err(SignalingError::Via)?;
        let request = RequestBuilder::new(
            method,
            template.request_uri.clone(),
            &via,
            &template.from,
            to,
            &template.call_id,
            &cseq,
            template.max_forwards,
        )
        .map_err(SignalingError::Build)?
        .build()
        .serialize()
        .map_err(SignalingError::Serialize)?;
        let raw =
            message::parse(Arc::from(request.into_boxed_slice())).map_err(SignalingError::Parse)?;
        crate::sip::validation::request::validate(raw).map_err(SignalingError::ValidateRequest)
    }

    fn remember_confirmed(
        &mut self,
        id: DialogBranchId,
        to: &ToHeader,
        invite_sequence: u32,
    ) -> Result<(), SignalingError> {
        if let Some(existing) = self.confirmed.iter_mut().find(|entry| entry.id == id) {
            existing.to = to.clone();
            existing.invite_sequence = invite_sequence;
            return Ok(());
        }
        if self.confirmed.len() >= MAX_FORKED_DIALOGS {
            return Err(SignalingError::DialogBranchCapacity);
        }
        self.confirmed.push(ConfirmedBranch {
            id,
            to: to.clone(),
            invite_sequence,
        });
        Ok(())
    }

    fn retry_authenticated_invite(
        &mut self,
        response: &ValidatedResponse,
        transactions: &mut TransactionManager,
        deadlines: &mut DeadlineScheduler,
        authentication: &mut AuthContext,
        now: Duration,
    ) -> Result<bool, SignalingError> {
        let scope = match response.response_line().status().as_u16() {
            401 => AuthScope::Server,
            407 => AuthScope::Proxy,
            _ => return Ok(false),
        };
        if response.core_headers().cseq().method() != &Method::Invite {
            return Ok(false);
        }
        let Some(credentials) = self.credentials.as_ref() else {
            return Ok(false);
        };
        let template = self
            .template
            .as_ref()
            .ok_or(SignalingError::InitialInviteMissing)?;
        if response.core_headers().cseq().sequence() != template.invite_sequence {
            return Ok(false);
        }

        let challenges = collect_challenges(response, scope)?;
        authentication
            .install(scope, &challenges)
            .map_err(SignalingError::Authentication)?;
        let uri = template.request_uri.to_string();
        let identifier = self
            .identifiers
            .allocate()
            .map_err(|_| SignalingError::IdentifierExhausted)?;
        let client_nonce = format!("liveaisip-{identifier}");
        let digest = authentication
            .authorize(
                scope,
                credentials,
                &Method::Invite,
                &uri,
                &template.body,
                &client_nonce,
            )
            .map_err(SignalingError::Authentication)?;
        match scope {
            AuthScope::Server => {
                self.server_authorization = Some(
                    Authorization::from_digest(&digest).map_err(SignalingError::Authorization)?,
                );
            }
            AuthScope::Proxy => {
                self.proxy_authorization = Some(
                    ProxyAuthorization::from_digest(&digest)
                        .map_err(SignalingError::ProxyAuthorization)?,
                );
            }
        }

        let sequence = template
            .invite_sequence
            .checked_add(1)
            .ok_or(SignalingError::SequenceExhausted)?;
        let request = self.build_authenticated_invite(sequence)?;
        self.template
            .as_mut()
            .ok_or(SignalingError::InitialInviteMissing)?
            .invite_sequence = sequence;
        self.start_request(request, transactions, deadlines, now)?;
        Ok(true)
    }

    fn build_authenticated_invite(
        &mut self,
        sequence: u32,
    ) -> Result<ValidatedRequest, SignalingError> {
        let template = self
            .template
            .as_ref()
            .ok_or(SignalingError::InitialInviteMissing)?;
        let cseq = CSeq::new(sequence, Method::Invite).map_err(SignalingError::CSeq)?;
        let id = self
            .identifiers
            .allocate()
            .map_err(|_| SignalingError::IdentifierExhausted)?;
        let via_text = format!("SIP/2.0/UDP {};branch=z9hG4bK-{id}", self.advertised_addr);
        let via = Via::from_bytes(via_text.as_bytes()).map_err(SignalingError::Via)?;
        let mut builder = RequestBuilder::new(
            Method::Invite,
            template.request_uri.clone(),
            &via,
            &template.from,
            &template.initial_to,
            &template.call_id,
            &cseq,
            template.max_forwards,
        )
        .map_err(SignalingError::Build)?;
        for header in &template.extension_headers {
            builder
                .push_header(header.clone())
                .map_err(SignalingError::Build)?;
        }
        if let Some(value) = &self.server_authorization {
            builder
                .push_typed(HeaderKind::Authorization, value)
                .map_err(SignalingError::Build)?;
        }
        if let Some(value) = &self.proxy_authorization {
            builder
                .push_typed(HeaderKind::ProxyAuthorization, value)
                .map_err(SignalingError::Build)?;
        }
        if let Some(content_type) = &template.content_type {
            builder = builder
                .with_body(content_type, &template.body)
                .map_err(SignalingError::Build)?;
        }
        serialize_and_validate(builder)
    }

    fn send(&mut self, bytes: Arc<[u8]>) -> Result<(), SignalingError> {
        let datagram = OutboundDatagram::new(self.destination.clone(), bytes, self.udp)
            .map_err(SignalingError::Udp)?;
        self.driver
            .send(&datagram)
            .map_err(SignalingError::Driver)?;
        self.sent = self.sent.saturating_add(1);
        Ok(())
    }

    fn cancel_timer(&mut self, token: &Token, timer: Timer, deadlines: &mut DeadlineScheduler) {
        if let Some(index) = self
            .timers
            .iter()
            .position(|entry| &entry.token == token && entry.timer == timer)
        {
            let entry = self.timers.swap_remove(index);
            deadlines.cancel(entry.id);
        }
    }

    fn cancel_token(&mut self, token: &Token, deadlines: &mut DeadlineScheduler) {
        let mut index = 0;
        while index < self.timers.len() {
            if &self.timers[index].token == token {
                let entry = self.timers.swap_remove(index);
                deadlines.cancel(entry.id);
            } else {
                index += 1;
            }
        }
    }
}

fn is_retry_managed_header(kind: HeaderKind) -> bool {
    matches!(
        kind,
        HeaderKind::Via
            | HeaderKind::From
            | HeaderKind::To
            | HeaderKind::CallId
            | HeaderKind::CSeq
            | HeaderKind::MaxForwards
            | HeaderKind::ContentLength
            | HeaderKind::ContentType
            | HeaderKind::Authorization
            | HeaderKind::ProxyAuthorization
    )
}

fn collect_challenges(
    response: &ValidatedResponse,
    scope: AuthScope,
) -> Result<Vec<AuthChallenge>, SignalingError> {
    let expected = match scope {
        AuthScope::Server => HeaderKind::WwwAuthenticate,
        AuthScope::Proxy => HeaderKind::ProxyAuthenticate,
    };
    let mut challenges = Vec::new();
    for field in response.message().header_views() {
        if field.kind().copied() != Some(expected) {
            continue;
        }
        let analysis =
            analyze_logical_value(field.value()).map_err(SignalingError::HeaderNormalization)?;
        let logical =
            materialize_logical_value(analysis).map_err(SignalingError::HeaderNormalization)?;
        let value = trim_horizontal_whitespace(logical.as_ref());
        let challenge = AuthChallenge::from_bytes(value).map_err(SignalingError::Challenge)?;
        challenges
            .try_reserve_exact(1)
            .map_err(|_| SignalingError::AllocationFailed)?;
        challenges.push(challenge);
    }
    Ok(challenges)
}

fn serialize_and_validate(builder: RequestBuilder) -> Result<ValidatedRequest, SignalingError> {
    let request = builder
        .build()
        .serialize()
        .map_err(SignalingError::Serialize)?;
    let raw =
        message::parse(Arc::from(request.into_boxed_slice())).map_err(SignalingError::Parse)?;
    crate::sip::validation::request::validate(raw).map_err(SignalingError::ValidateRequest)
}

impl fmt::Debug for UdpSignaling {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpSignaling")
            .field("initial_invite_installed", &self.initial_invite.is_some())
            .field("active_timers", &self.timers.len())
            .field("received", &self.received)
            .field("rejected", &self.rejected)
            .field("sent", &self.sent)
            .finish_non_exhaustive()
    }
}

fn timer_kind(timer: Timer) -> u16 {
    match timer {
        Timer::Retransmit => 1,
        Timer::RequestTimeout => 2,
        Timer::Linger => 3,
    }
}

fn response_event(response: &ValidatedResponse) -> Result<Option<CallEvent>, SignalingError> {
    let status = response.response_line().status().as_u16();
    let method = response.core_headers().cseq().method();
    if status == 100 || !(100..=699).contains(&status) {
        return Ok(None);
    }
    let tag = response
        .core_headers()
        .to_header()
        .tag()
        .unwrap_or("untagged-final");
    let branch = DialogBranchId::new(tag).map_err(SignalingError::Branch)?;
    Ok(match (method, status) {
        (Method::Invite, 101..=199) => Some(CallEvent::Provisional {
            branch,
            has_sdp: !response.message().body().is_empty(),
        }),
        (Method::Invite, 200..=299) => Some(CallEvent::InviteAccepted { branch }),
        (Method::Invite, 300..=699) => Some(CallEvent::InviteRejected { branch, status }),
        (Method::Cancel, 200..=299) => Some(CallEvent::CancelAccepted),
        (Method::Bye, 200..=299) => Some(CallEvent::ByeCompleted { branch }),
        _ => None,
    })
}

/// Executable UDP signaling failure.
#[derive(Debug)]
pub enum SignalingError {
    /// Concrete remote endpoint was invalid.
    Destination(crate::sip::transport::destination::DestinationError),
    /// UDP socket, receive, parse, validation, or send failed.
    Driver(UdpDriverError),
    /// Datagram exceeded UDP admission policy.
    Udp(UdpError),
    /// Client transaction construction failed.
    Client(crate::sip::transaction::client::ClientError),
    /// Transaction manager rejected an operation.
    Transactions(ManagerError),
    /// Shared deadline scheduler rejected an operation.
    Deadlines(DeadlineError),
    /// Initial request was not INVITE.
    InitialRequestNotInvite,
    /// Initial INVITE omitted request-mandatory Max-Forwards.
    InitialInviteMissingMaxForwards,
    /// Initial INVITE was installed more than once.
    InitialInviteAlreadyInstalled,
    /// Start occurred before an initial INVITE was installed.
    InitialInviteMissing,
    /// Bounded transaction timer table filled.
    TimerCapacity,
    /// Fixed storage allocation failed.
    AllocationFailed,
    /// Monotonic deadline overflowed.
    TimeOverflow,
    /// Response dialog branch was invalid.
    Branch(super::leg::ForkError),
    /// A generated Via value was invalid.
    Via(crate::sip::headers::via::ParseError),
    /// A generated `CSeq` value was invalid.
    CSeq(crate::sip::headers::cseq::ParseError),
    /// A generated request violated builder invariants.
    Build(crate::sip::builder::request::BuildError),
    /// Canonical generated request serialization failed.
    Serialize(crate::sip::serializer::message::SerializeError),
    /// Generated request parsing unexpectedly failed.
    Parse(crate::sip::parser::message::ParseError),
    /// Generated request semantic validation unexpectedly failed.
    ValidateRequest(crate::sip::validation::request::ValidationError),
    /// Opaque transaction branch allocation exhausted.
    IdentifierExhausted,
    /// In-dialog action referenced an unknown fork branch.
    UnknownDialogBranch,
    /// Confirmed fork branch storage reached its hard bound.
    DialogBranchCapacity,
    /// No further in-dialog `CSeq` could be represented.
    SequenceExhausted,
    /// Generated Via address was not reachable or did not match the socket port.
    InvalidAdvertisedAddress,
    /// A raw initial or challenge header could not be safely unfolded.
    HeaderNormalization(LogicalValueError),
    /// A preserved initial extension header name was invalid.
    HeaderName(crate::sip::types::header::HeaderNameError),
    /// A preserved initial extension header value was invalid.
    HeaderValue(crate::sip::types::header::HeaderValueError),
    /// A received authentication challenge was invalid.
    Challenge(ChallengeParseError),
    /// Stateful Digest authentication rejected the challenge or calculation.
    Authentication(AuthContextError),
    /// Calculated origin-server credentials violated an internal invariant.
    Authorization(crate::sip::headers::authorization::ParseError),
    /// Calculated proxy credentials violated an internal invariant.
    ProxyAuthorization(crate::sip::headers::proxy_authorization::ParseError),
}

impl fmt::Display for SignalingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("call-owned SIP signaling failed")
    }
}

impl StdError for SignalingError {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::sync::Arc;
    use std::time::Duration;

    use super::UdpSignaling;
    use crate::call::events::{CallAction, CallEvent};
    use crate::runtime::deadline::DeadlineScheduler;
    use crate::sip::auth::{AuthContext, DigestCredentials};
    use crate::sip::parser::message;
    use crate::sip::transaction::manager::TransactionManager;
    use crate::sip::transport::udp::UdpConfig;
    use crate::sip::transport::udp_driver::UdpDriverConfig;
    use crate::sip::validation;

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn header_value<'a>(message: &'a str, name: &str) -> &'a str {
        message
            .split("\r\n")
            .find_map(|line| line.strip_prefix(name))
            .map_or_else(|| panic!("missing header"), str::trim)
    }

    fn receive_request(peer: &UdpSocket, buffer: &mut [u8]) -> (String, SocketAddr) {
        let (length, source) = peer
            .recv_from(buffer)
            .unwrap_or_else(|_| panic!("receive request"));
        let text =
            std::str::from_utf8(&buffer[..length]).unwrap_or_else(|_| panic!("request utf8"));
        (text.to_owned(), source)
    }

    fn receive_ack_and_invite(peer: &UdpSocket, buffer: &mut [u8]) -> (String, String) {
        let (first, _) = receive_request(peer, buffer);
        let (second, _) = receive_request(peer, buffer);
        match (first.starts_with("ACK "), second.starts_with("INVITE ")) {
            (true, true) => (first, second),
            (false, false) if first.starts_with("INVITE ") && second.starts_with("ACK ") => {
                (second, first)
            }
            _ => panic!("expected ACK and INVITE"),
        }
    }

    fn poll_until_datagram_processed(
        signaling: &mut UdpSignaling,
        transactions: &mut TransactionManager,
        deadlines: &mut DeadlineScheduler,
        authentication: &mut AuthContext,
        first_tick: u64,
    ) -> Vec<CallEvent> {
        for tick in first_tick..first_tick.saturating_add(100) {
            let events = signaling
                .poll(
                    transactions,
                    deadlines,
                    authentication,
                    Duration::from_millis(tick),
                )
                .unwrap_or_else(|_| panic!("poll response"));
            if signaling.received != 0 {
                return events;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("response not processed")
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one continuous wire scenario verifies sequential server and proxy auth"
    )]
    fn real_udp_digest_retries_preserve_body_and_isolate_server_and_proxy_credentials() {
        let peer = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("peer"));
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("timeout"));
        let remote = peer.local_addr().unwrap_or_else(|_| panic!("peer address"));
        let credentials = DigestCredentials::new("runtime", "never-on-wire")
            .unwrap_or_else(|_| panic!("credentials"));
        let mut signaling = UdpSignaling::bind(
            localhost(0),
            remote,
            UdpDriverConfig::default(),
            UdpConfig::default(),
        )
        .unwrap_or_else(|_| panic!("signaling"))
        .with_credentials(credentials);
        let local = signaling.local_addr();
        let body = "v=0\r\nm=audio 40000 RTP/AVP 0\r\n";
        let request = format!(
            "INVITE sip:service@127.0.0.1 SIP/2.0\r\n\
             Via: SIP/2.0/UDP {local};branch=z9hG4bK-auth-initial\r\n\
             From: <sip:runtime@127.0.0.1>;tag=local-tag\r\n\
             To: <sip:service@127.0.0.1>\r\n\
             Call-ID: auth-wire-test@127.0.0.1\r\n\
             CSeq: 1 INVITE\r\n\
             Max-Forwards: 70\r\n\
             Subject: preserved-extension\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let raw = message::parse(Arc::from(request.into_bytes()))
            .unwrap_or_else(|_| panic!("parse request"));
        let invite =
            validation::request::validate(raw).unwrap_or_else(|_| panic!("validate request"));
        signaling
            .install_initial_invite(invite)
            .unwrap_or_else(|_| panic!("install"));
        let mut transactions =
            TransactionManager::new(8).unwrap_or_else(|_| panic!("transactions"));
        let mut deadlines = DeadlineScheduler::new(32).unwrap_or_else(|_| panic!("deadlines"));
        let mut authentication = AuthContext::new();
        signaling
            .start(&mut transactions, &mut deadlines, Duration::ZERO)
            .unwrap_or_else(|_| panic!("start"));

        let mut received = [0_u8; 4_096];
        let (initial, source) = receive_request(&peer, &mut received);
        assert!(initial.starts_with("INVITE "));
        let unauthorized = format!(
            "SIP/2.0 401 Unauthorized\r\n\
             Via: {}\r\n\
             From: <sip:runtime@127.0.0.1>;tag=local-tag\r\n\
             To: <sip:service@127.0.0.1>;tag=server-tag\r\n\
             Call-ID: auth-wire-test@127.0.0.1\r\n\
             CSeq: 1 INVITE\r\n\
             WWW-Authenticate: Digest realm=\"freeswitch\", nonce=\"server-nonce\", algorithm=SHA-256, qop=\"auth\"\r\n\
             Content-Length: 0\r\n\r\n",
            header_value(&initial, "Via:")
        );
        peer.send_to(unauthorized.as_bytes(), source)
            .unwrap_or_else(|_| panic!("send 401"));
        let events = poll_until_datagram_processed(
            &mut signaling,
            &mut transactions,
            &mut deadlines,
            &mut authentication,
            1,
        );
        assert!(events.is_empty());
        let (server_ack, server_invite) = receive_ack_and_invite(&peer, &mut received);
        assert!(server_ack.contains("CSeq: 1 ACK"));
        assert!(server_invite.contains("CSeq: 2 INVITE"));
        assert!(server_invite.contains("Authorization: Digest "));
        assert!(!server_invite.contains("Proxy-Authorization:"));
        assert!(server_invite.contains("Subject: preserved-extension"));
        assert!(server_invite.ends_with(body));
        assert!(!server_invite.contains("never-on-wire"));
        assert_ne!(
            header_value(&server_invite, "Via:"),
            header_value(&initial, "Via:")
        );

        let proxy_required = format!(
            "SIP/2.0 407 Proxy Authentication Required\r\n\
             Via: {}\r\n\
             From: <sip:runtime@127.0.0.1>;tag=local-tag\r\n\
             To: <sip:service@127.0.0.1>;tag=proxy-tag\r\n\
             Call-ID: auth-wire-test@127.0.0.1\r\n\
             CSeq: 2 INVITE\r\n\
             Proxy-Authenticate: Digest realm=\"proxy\", nonce=\"proxy-nonce\", algorithm=SHA-256, qop=\"auth\"\r\n\
             Content-Length: 0\r\n\r\n",
            header_value(&server_invite, "Via:")
        );
        peer.send_to(proxy_required.as_bytes(), source)
            .unwrap_or_else(|_| panic!("send 407"));
        let received_before_proxy = signaling.received;
        for tick in 101..=200 {
            let events = signaling
                .poll(
                    &mut transactions,
                    &mut deadlines,
                    &mut authentication,
                    Duration::from_millis(tick),
                )
                .unwrap_or_else(|_| panic!("poll 407"));
            assert!(events.is_empty());
            if signaling.received > received_before_proxy {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(signaling.received > received_before_proxy);
        let (proxy_ack, proxy_invite) = receive_ack_and_invite(&peer, &mut received);
        assert!(proxy_ack.contains("CSeq: 2 ACK"));
        assert!(proxy_invite.contains("CSeq: 3 INVITE"));
        assert!(proxy_invite.contains("Authorization: Digest "));
        assert!(proxy_invite.contains("Proxy-Authorization: Digest "));
        assert!(proxy_invite.ends_with(body));
        assert!(!proxy_invite.contains("never-on-wire"));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one continuous wire scenario verifies transaction races and datagram ordering"
    )]
    fn real_udp_invite_provisional_failure_and_ack_follow_transaction_engine() {
        let peer = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("peer"));
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("timeout"));
        let remote = peer.local_addr().unwrap_or_else(|_| panic!("peer address"));
        let mut signaling = UdpSignaling::bind(
            localhost(0),
            remote,
            UdpDriverConfig::default(),
            UdpConfig::default(),
        )
        .unwrap_or_else(|_| panic!("signaling"));
        let local = signaling.local_addr();
        let request = format!(
            "INVITE sip:service@127.0.0.1 SIP/2.0\r\n\
             Via: SIP/2.0/UDP {local};branch=z9hG4bK-wire-test\r\n\
             From: <sip:runtime@127.0.0.1>;tag=local-tag\r\n\
             To: <sip:service@127.0.0.1>\r\n\
             Call-ID: wire-test@127.0.0.1\r\n\
             CSeq: 1 INVITE\r\n\
             Max-Forwards: 70\r\n\
             Content-Length: 0\r\n\r\n"
        );
        let raw = message::parse(Arc::from(request.into_bytes()))
            .unwrap_or_else(|_| panic!("parse request"));
        let invite =
            validation::request::validate(raw).unwrap_or_else(|_| panic!("validate request"));
        signaling
            .install_initial_invite(invite)
            .unwrap_or_else(|_| panic!("install"));
        let mut transactions =
            TransactionManager::new(8).unwrap_or_else(|_| panic!("transactions"));
        let mut deadlines = DeadlineScheduler::new(32).unwrap_or_else(|_| panic!("deadlines"));
        let mut authentication = AuthContext::new();

        signaling
            .start(&mut transactions, &mut deadlines, Duration::ZERO)
            .unwrap_or_else(|_| panic!("start"));
        let mut received = [0_u8; 2_048];
        let (length, source) = peer
            .recv_from(&mut received)
            .unwrap_or_else(|_| panic!("receive INVITE"));
        assert!(received[..length].starts_with(b"INVITE "));

        let response = |status: u16, reason: &str| {
            format!(
                "SIP/2.0 {status} {reason}\r\n\
                 Via: SIP/2.0/UDP {local};branch=z9hG4bK-wire-test\r\n\
                 From: <sip:runtime@127.0.0.1>;tag=local-tag\r\n\
                 To: <sip:service@127.0.0.1>;tag=remote-tag\r\n\
                 Call-ID: wire-test@127.0.0.1\r\n\
                 CSeq: 1 INVITE\r\n\
                 Content-Length: 0\r\n\r\n"
            )
        };
        let provisional = response(180, "Ringing");
        peer.send_to(provisional.as_bytes(), source)
            .unwrap_or_else(|_| panic!("send 180"));
        let mut events = Vec::new();
        for tick in 1..=100 {
            events = signaling
                .poll(
                    &mut transactions,
                    &mut deadlines,
                    &mut authentication,
                    Duration::from_millis(tick),
                )
                .unwrap_or_else(|_| panic!("poll 180"));
            if !events.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(matches!(events.as_slice(), [CallEvent::Provisional { .. }]));
        signaling
            .execute_call_actions(
                &[CallAction::SendCancel],
                &mut transactions,
                &mut deadlines,
                Duration::from_millis(100),
            )
            .unwrap_or_else(|_| panic!("CANCEL"));
        let (cancel_length, _) = peer
            .recv_from(&mut received)
            .unwrap_or_else(|_| panic!("receive CANCEL"));
        assert!(received[..cancel_length].starts_with(b"CANCEL "));

        let failure = response(486, "Busy Here");
        peer.send_to(failure.as_bytes(), source)
            .unwrap_or_else(|_| panic!("send 486"));
        let mut events = Vec::new();
        for tick in 101..=200 {
            events = signaling
                .poll(
                    &mut transactions,
                    &mut deadlines,
                    &mut authentication,
                    Duration::from_millis(tick),
                )
                .unwrap_or_else(|_| panic!("poll 486"));
            if !events.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(matches!(
            events.as_slice(),
            [CallEvent::InviteRejected { status: 486, .. }]
        ));
        let (length, _) = peer
            .recv_from(&mut received)
            .unwrap_or_else(|_| panic!("receive ACK"));
        assert!(received[..length].starts_with(b"ACK "));

        let success = response(200, "OK");
        peer.send_to(success.as_bytes(), source)
            .unwrap_or_else(|_| panic!("send late 200"));
        let mut events = Vec::new();
        for tick in 201..=300 {
            events = signaling
                .poll(
                    &mut transactions,
                    &mut deadlines,
                    &mut authentication,
                    Duration::from_millis(tick),
                )
                .unwrap_or_else(|_| panic!("poll 200"));
            if !events.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let [CallEvent::InviteAccepted { branch }] = events.as_slice() else {
            panic!("accepted branch")
        };
        signaling
            .execute_call_actions(
                &[
                    CallAction::SendAck {
                        branch: branch.clone(),
                    },
                    CallAction::SendBye {
                        branch: branch.clone(),
                    },
                ],
                &mut transactions,
                &mut deadlines,
                Duration::from_millis(301),
            )
            .unwrap_or_else(|_| panic!("ACK and BYE"));
        let (ack_length, _) = peer
            .recv_from(&mut received)
            .unwrap_or_else(|_| panic!("receive success ACK"));
        assert!(received[..ack_length].starts_with(b"ACK "));
        let (bye_length, _) = peer
            .recv_from(&mut received)
            .unwrap_or_else(|_| panic!("receive BYE"));
        assert!(received[..bye_length].starts_with(b"BYE "));
    }
}
