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

//! Exclusive mutable state owner for one active call.
//!
//! This type contains no thread spawn/join machinery and remains directly
//! testable. [`super::thread::CallThread`] claims it once, then every mutating
//! method verifies the native owner thread before touching protocol state.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::thread::{self, ThreadId};
use std::time::Duration;

use crate::call::execution::deadline::{
    DeadlineError, DeadlineId, DeadlineOwner, DeadlineScheduler,
};
use crate::call::media::controller::MediaController;
use crate::rtp::security::PacketProtection;
use crate::rtp::session::{RtcpIngressOutcome, RtpIngressOutcome, RtpSession};
use crate::rtp::transport::{Component, MediaPacketScratch, MediaSocketPair, SocketError};
use crate::runtime::admission::AdmissionLeaseGroup;
use crate::sip::auth::AuthContext;
use crate::sip::dialog::{
    DialogManager, DialogManagerError, PrackTracker, SessionTimer, SessionTimerAction,
};
use crate::sip::transaction::manager::{
    ManagerError as TransactionManagerError, TransactionManager,
};
use crate::sip::transport::failover::FailoverPlan;
use crate::util::time::{advance_periodic, checked_deadline, minimum_deadline};

use crate::call::model::context::{CallContext, CallContextError};
use crate::call::model::events::{CallAction, CallCommand, CallEvent};
use crate::call::model::redirect::{RedirectError, RedirectHandler, RedirectPolicy};
use crate::call::model::state::{CallEndReason, CallState};
use crate::call::model::transfer::TransferTracker;
use crate::call::signaling::{SignalingError, UdpSignaling};

use super::timer::CallTimer;

/// Default per-call SIP transaction capacity.
pub const DEFAULT_CALL_TRANSACTION_CAPACITY: usize = 128;
/// Default per-call SIP dialog/fork capacity.
pub const DEFAULT_CALL_DIALOG_CAPACITY: usize = 32;
/// Default active deadline capacity per call.
pub const DEFAULT_CALL_DEADLINE_CAPACITY: usize = 256;
/// Default graceful protocol cleanup interval.
pub const DEFAULT_CALL_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
/// Native media cadence.
pub const MEDIA_TICK_INTERVAL: Duration = Duration::from_millis(10);
/// Maximum media ticks executed in one scheduling cycle.
pub const MAX_MEDIA_TICKS_PER_CYCLE: u64 = 8;
/// Maximum due protocol deadlines consumed before returning to the mailbox.
pub const MAX_DUE_DEADLINES_PER_CYCLE: usize = 64;
/// Maximum media datagrams consumed for one readiness notification.
pub const MAX_MEDIA_DATAGRAMS_PER_POLL: usize = 64;
/// Maximum delay before the owner thread checks its nonblocking SIP socket.
pub const SIGNALING_IO_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Immutable capacities and teardown policy for one call runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallRuntimeConfig {
    transaction_capacity: usize,
    dialog_capacity: usize,
    deadline_capacity: usize,
    shutdown_grace: Duration,
    require_secure_media: bool,
    redirect_policy: RedirectPolicy,
}

impl CallRuntimeConfig {
    /// Creates explicit per-call ownership capacities.
    #[must_use]
    pub const fn new(
        transaction_capacity: usize,
        dialog_capacity: usize,
        deadline_capacity: usize,
        shutdown_grace: Duration,
        require_secure_media: bool,
    ) -> Self {
        Self {
            transaction_capacity,
            dialog_capacity,
            deadline_capacity,
            shutdown_grace,
            require_secure_media,
            redirect_policy: RedirectPolicy::Reject,
        }
    }

    /// Selects the bounded per-call 3xx policy before runtime construction.
    #[must_use]
    pub const fn with_redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = policy;
        self
    }

    /// Returns the graceful cleanup interval.
    #[must_use]
    pub const fn shutdown_grace(self) -> Duration {
        self.shutdown_grace
    }
}

impl Default for CallRuntimeConfig {
    fn default() -> Self {
        Self::new(
            DEFAULT_CALL_TRANSACTION_CAPACITY,
            DEFAULT_CALL_DIALOG_CAPACITY,
            DEFAULT_CALL_DEADLINE_CAPACITY,
            DEFAULT_CALL_SHUTDOWN_GRACE,
            false,
        )
    }
}

/// Direction of one native/Python audio readiness notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioDirection {
    /// Audio produced by native receive processing for Python.
    Receive,
    /// Audio produced by Python for native packetization.
    Transmit,
}

/// Bounded mailbox message entering a call thread.
#[derive(Debug)]
#[non_exhaustive]
pub enum CallMessage {
    /// Serialized SIP, control, timeout, or call-lifecycle event.
    Event(CallEvent),
    /// RTP or RTCP socket readiness notification.
    NetworkReady(Component),
    /// Call-owned SIP signaling socket is readable.
    SignalingReady,
    /// Generation-fenced native audio queue notification.
    AudioReady {
        /// Media generation attached by the producer.
        generation: u64,
        /// Receive or transmit queue direction.
        direction: AudioDirection,
    },
    /// Idempotent runtime shutdown request.
    Shutdown,
    #[cfg(test)]
    /// Test-only unexpected panic injection for containment verification.
    PanicForContainmentTest,
}

/// Privacy-safe counters owned and published by the call thread.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CallRuntimeDiagnostics {
    /// Messages processed on the owner thread.
    pub processed_messages: u64,
    /// Due protocol deadlines processed.
    pub processed_deadlines: u64,
    /// Ten-millisecond media ticks executed.
    pub media_ticks: u64,
    /// Media ticks skipped after a late wakeup.
    pub skipped_media_ticks: u64,
    /// Stale generation-fenced audio notifications rejected.
    pub stale_media_work: u64,
    /// RTP and RTCP datagrams removed from call-owned sockets.
    pub media_datagrams_received: u64,
    /// Oversized, malformed, unauthenticated, or stream-invalid media datagrams.
    pub media_datagrams_rejected: u64,
    /// Audio RTP packets admitted to the bounded `NetEq` ingress queue.
    pub rtp_audio_packets_queued: u64,
    /// Negotiated RFC 4733 packets handled outside the audio decoder path.
    pub dtmf_packets_received: u64,
    /// Valid compound RTCP datagrams admitted to session state.
    pub rtcp_packets_accepted: u64,
}

/// All mutable state associated with exactly one active call.
pub struct CallRuntime {
    owner: Option<ThreadId>,
    context: CallContext,
    transactions: TransactionManager,
    dialogs: DialogManager,
    authentication: AuthContext,
    prack: PrackTracker,
    session_timer: Option<SessionTimer>,
    redirect: RedirectHandler,
    transfer: Option<TransferTracker>,
    failover: Option<FailoverPlan>,
    deadlines: DeadlineScheduler,
    media: MediaController,
    media_sockets: Option<MediaSocketPair>,
    packet_scratch: Option<MediaPacketScratch>,
    rtp_session: Option<RtpSession>,
    signaling: Option<UdpSignaling>,
    admission: AdmissionLeaseGroup,
    shutdown_grace: Duration,
    shutdown_deadline: Option<Duration>,
    next_media_deadline: Option<Duration>,
    next_signaling_poll: Option<Duration>,
    shutting_down: bool,
    cleaned_up: bool,
    diagnostics: CallRuntimeDiagnostics,
}

impl CallRuntime {
    /// Allocates every currently configured call-local registry before spawn.
    ///
    /// Acquired admission leases move into this value first, so any later
    /// construction or native-thread spawn failure releases them by RAII.
    ///
    /// # Errors
    ///
    /// Preserves transaction, dialog, deadline, and shutdown-policy failures.
    pub fn new(
        context: CallContext,
        admission: AdmissionLeaseGroup,
        config: CallRuntimeConfig,
    ) -> Result<Self, CallRuntimeError> {
        if config.shutdown_grace.is_zero() {
            return Err(CallRuntimeError::ZeroShutdownGrace);
        }
        Ok(Self {
            owner: None,
            context,
            transactions: TransactionManager::new(config.transaction_capacity)
                .map_err(CallRuntimeError::Transactions)?,
            dialogs: DialogManager::new(config.dialog_capacity)
                .map_err(CallRuntimeError::Dialogs)?,
            authentication: AuthContext::new(),
            prack: PrackTracker::new(),
            session_timer: None,
            redirect: RedirectHandler::new(config.redirect_policy, config.require_secure_media)
                .map_err(CallRuntimeError::Redirect)?,
            transfer: None,
            failover: None,
            deadlines: DeadlineScheduler::new(config.deadline_capacity)
                .map_err(CallRuntimeError::Deadlines)?,
            media: MediaController::new(config.require_secure_media),
            media_sockets: None,
            packet_scratch: None,
            rtp_session: None,
            signaling: None,
            admission,
            shutdown_grace: config.shutdown_grace,
            shutdown_deadline: None,
            next_media_deadline: None,
            next_signaling_poll: None,
            shutting_down: false,
            cleaned_up: false,
            diagnostics: CallRuntimeDiagnostics::default(),
        })
    }

    /// Installs preallocated RTP/RTCP sockets before ownership is claimed.
    ///
    /// # Errors
    ///
    /// Rejects replacement or installation after the runtime starts.
    pub fn with_media_sockets(
        mut self,
        sockets: MediaSocketPair,
    ) -> Result<Self, CallRuntimeError> {
        if self.owner.is_some() || self.media_sockets.is_some() {
            return Err(CallRuntimeError::ResourcesAlreadyInstalled);
        }
        self.media_sockets = Some(sockets);
        Ok(self)
    }

    /// Installs the preconstructed RTP session before ownership is claimed.
    ///
    /// # Errors
    ///
    /// Rejects replacement or installation after the runtime starts.
    pub fn with_rtp_session(mut self, session: RtpSession) -> Result<Self, CallRuntimeError> {
        if self.owner.is_some() || self.rtp_session.is_some() {
            return Err(CallRuntimeError::ResourcesAlreadyInstalled);
        }
        self.rtp_session = Some(session);
        Ok(self)
    }

    /// Installs permanent heap-backed packet scratch storage before spawn.
    ///
    /// # Errors
    ///
    /// Rejects replacement or installation after ownership starts.
    pub fn with_packet_scratch(
        mut self,
        scratch: MediaPacketScratch,
    ) -> Result<Self, CallRuntimeError> {
        if self.owner.is_some() || self.packet_scratch.is_some() {
            return Err(CallRuntimeError::ResourcesAlreadyInstalled);
        }
        self.packet_scratch = Some(scratch);
        Ok(self)
    }

    /// Installs one resolved destination failover plan before spawn.
    ///
    /// # Errors
    ///
    /// Rejects replacement or installation after ownership starts.
    pub fn with_failover_plan(mut self, plan: FailoverPlan) -> Result<Self, CallRuntimeError> {
        if self.owner.is_some() || self.failover.is_some() {
            return Err(CallRuntimeError::ResourcesAlreadyInstalled);
        }
        self.failover = Some(plan);
        Ok(self)
    }

    /// Installs one prebound call-owned UDP signaling driver before spawn.
    ///
    /// # Errors
    ///
    /// Rejects replacement or installation after ownership starts.
    pub fn with_udp_signaling(mut self, signaling: UdpSignaling) -> Result<Self, CallRuntimeError> {
        if self.owner.is_some() || self.signaling.is_some() {
            return Err(CallRuntimeError::ResourcesAlreadyInstalled);
        }
        self.signaling = Some(signaling);
        Ok(self)
    }

    /// Returns whether emitted actions are already executed by an installed
    /// call-owned signaling driver and therefore form an observational stream.
    ///
    /// Without a signaling driver, embedders may still use the action channel
    /// as the required effect boundary, so delivery remains strict.
    #[must_use]
    pub(crate) const fn actions_are_observational(&self) -> bool {
        self.signaling.is_some()
    }

    /// Claims this runtime for the current native thread exactly once.
    ///
    /// # Errors
    ///
    /// Rejects a second, different native owner.
    pub fn claim_current_thread(&mut self) -> Result<(), CallRuntimeError> {
        let current = thread::current().id();
        match self.owner {
            None => {
                self.owner = Some(current);
                Ok(())
            }
            Some(owner) if owner == current => Ok(()),
            Some(_) => Err(CallRuntimeError::WrongOwnerThread),
        }
    }

    /// Applies one serialized mailbox message.
    ///
    /// # Errors
    ///
    /// Rejects off-owner mutation and preserves call-context failures.
    ///
    /// # Panics
    ///
    /// Only the test-only containment message deliberately panics in test builds.
    pub fn handle(
        &mut self,
        message: CallMessage,
        now: Duration,
    ) -> Result<Vec<CallAction>, CallRuntimeError> {
        self.verify_owner()?;
        self.diagnostics.processed_messages = self.diagnostics.processed_messages.saturating_add(1);
        match message {
            CallMessage::Event(event) => {
                let actions = self
                    .context
                    .handle(event, now)
                    .map_err(CallRuntimeError::Context)?;
                if let Some(signaling) = self.signaling.as_mut() {
                    if actions
                        .iter()
                        .any(|action| matches!(action, CallAction::SendInvite))
                    {
                        signaling
                            .start(&mut self.transactions, &mut self.deadlines, now)
                            .map_err(CallRuntimeError::Signaling)?;
                        self.next_signaling_poll = Some(
                            checked_deadline(now, SIGNALING_IO_POLL_INTERVAL)
                                .map_err(|_| CallRuntimeError::TimeOverflow)?,
                        );
                    }
                    signaling
                        .execute_call_actions(
                            &actions,
                            &mut self.transactions,
                            &mut self.dialogs,
                            &mut self.deadlines,
                            now,
                        )
                        .map_err(CallRuntimeError::Signaling)?;
                }
                Ok(actions)
            }
            CallMessage::NetworkReady(component) => self.poll_network(component, now),
            CallMessage::SignalingReady => self.poll_signaling(now),
            CallMessage::AudioReady {
                generation,
                direction: _,
            } => {
                let current = self
                    .media
                    .work_token()
                    .map(crate::call::media::controller::MediaWorkToken::generation);
                if current != Some(generation) {
                    self.diagnostics.stale_media_work =
                        self.diagnostics.stale_media_work.saturating_add(1);
                }
                Ok(Vec::new())
            }
            CallMessage::Shutdown => self.begin_shutdown(now),
            #[cfg(test)]
            CallMessage::PanicForContainmentTest => panic!("contained call runtime panic"),
        }
    }

    /// Drains bounded work from one ready call-owned RTP or RTCP socket.
    ///
    /// Each datagram is received into permanent call-local scratch storage and
    /// immediately submitted to the call-owned [`RtpSession`]. Malformed,
    /// unauthenticated, and otherwise stream-invalid packets are isolated to
    /// the packet; fatal socket errors fail the call. Secure sessions never
    /// reinterpret rejected clear packets as authenticated media.
    ///
    /// # Errors
    ///
    /// Rejects calls from any non-owner thread.
    pub fn poll_network(
        &mut self,
        component: Component,
        now: Duration,
    ) -> Result<Vec<CallAction>, CallRuntimeError> {
        self.verify_owner()?;
        let sockets = self
            .media_sockets
            .as_ref()
            .ok_or(CallRuntimeError::MediaResourcesUnavailable)?;
        let scratch = self
            .packet_scratch
            .as_mut()
            .ok_or(CallRuntimeError::MediaResourcesUnavailable)?;
        let session = self
            .rtp_session
            .as_mut()
            .ok_or(CallRuntimeError::MediaResourcesUnavailable)?;

        for _ in 0..MAX_MEDIA_DATAGRAMS_PER_POLL {
            let datagram = match sockets.receive(component, scratch.receive()) {
                Ok(datagram) => datagram,
                Err(error) if error.io_kind() == Some(io::ErrorKind::WouldBlock) => break,
                Err(SocketError::DatagramTooLarge { .. }) => {
                    self.diagnostics.media_datagrams_received =
                        self.diagnostics.media_datagrams_received.saturating_add(1);
                    self.diagnostics.media_datagrams_rejected =
                        self.diagnostics.media_datagrams_rejected.saturating_add(1);
                    continue;
                }
                Err(error) => return Err(CallRuntimeError::MediaSocket(error)),
            };
            self.diagnostics.media_datagrams_received =
                self.diagnostics.media_datagrams_received.saturating_add(1);
            let accepted = match component {
                Component::Rtp => match session.ingest_rtp(
                    datagram.source(),
                    datagram.payload(),
                    now,
                    PacketProtection::Plain,
                ) {
                    Ok(RtpIngressOutcome::Queued { .. }) => {
                        self.diagnostics.rtp_audio_packets_queued =
                            self.diagnostics.rtp_audio_packets_queued.saturating_add(1);
                        true
                    }
                    Ok(RtpIngressOutcome::TelephoneEvent { .. }) => {
                        self.diagnostics.dtmf_packets_received =
                            self.diagnostics.dtmf_packets_received.saturating_add(1);
                        true
                    }
                    Ok(RtpIngressOutcome::SourceProbation | RtpIngressOutcome::SourceSwitched) => {
                        true
                    }
                    Ok(
                        RtpIngressOutcome::ClassifiedOut(_)
                        | RtpIngressOutcome::SourceRejected
                        | RtpIngressOutcome::StreamRejected(_)
                        | RtpIngressOutcome::AuxiliaryRejected(_)
                        | RtpIngressOutcome::QueueDropped,
                    )
                    | Err(_) => false,
                },
                Component::Rtcp => match session.ingest_rtcp(
                    datagram.source(),
                    datagram.payload(),
                    now,
                    PacketProtection::Plain,
                ) {
                    Ok(RtcpIngressOutcome::Accepted { .. }) => {
                        self.diagnostics.rtcp_packets_accepted =
                            self.diagnostics.rtcp_packets_accepted.saturating_add(1);
                        true
                    }
                    Ok(
                        RtcpIngressOutcome::ClassifiedOut(_) | RtcpIngressOutcome::SourceRejected,
                    )
                    | Err(_) => false,
                },
            };
            if !accepted {
                self.diagnostics.media_datagrams_rejected =
                    self.diagnostics.media_datagrams_rejected.saturating_add(1);
            }
        }
        Ok(Vec::new())
    }

    /// Drains bounded SIP UDP responses and applies their lifecycle events on
    /// this same owner thread.
    ///
    /// # Errors
    ///
    /// Rejects missing signaling resources and preserves transport,
    /// transaction, deadline, and lifecycle failures.
    pub fn poll_signaling(&mut self, now: Duration) -> Result<Vec<CallAction>, CallRuntimeError> {
        self.verify_owner()?;
        let signaling = self
            .signaling
            .as_mut()
            .ok_or(CallRuntimeError::SignalingUnavailable)?;
        let events = signaling
            .poll(
                &mut self.transactions,
                &mut self.dialogs,
                &mut self.deadlines,
                &mut self.authentication,
                now,
            )
            .map_err(CallRuntimeError::Signaling)?;
        let mut actions = Vec::new();
        for event in events {
            let produced = self
                .context
                .handle(event, now)
                .map_err(CallRuntimeError::Context)?;
            signaling
                .execute_call_actions(
                    &produced,
                    &mut self.transactions,
                    &mut self.dialogs,
                    &mut self.deadlines,
                    now,
                )
                .map_err(CallRuntimeError::Signaling)?;
            actions.extend(produced);
        }
        Ok(actions)
    }

    /// Schedules one generation-fenced call-local deadline.
    ///
    /// # Errors
    ///
    /// Rejects off-owner mutation and preserves bounded scheduler failures.
    pub fn schedule_call_deadline(
        &mut self,
        timer: CallTimer,
        at: Duration,
        generation: u64,
    ) -> Result<DeadlineId, CallRuntimeError> {
        self.verify_owner()?;
        self.deadlines
            .schedule(at, DeadlineOwner::Call, generation, timer.kind())
            .map_err(CallRuntimeError::Deadlines)
    }

    /// Cancels one call-owned deadline idempotently.
    ///
    /// # Errors
    ///
    /// Rejects off-owner mutation.
    pub fn cancel_deadline(&mut self, id: DeadlineId) -> Result<bool, CallRuntimeError> {
        self.verify_owner()?;
        Ok(self.deadlines.cancel(id))
    }

    /// Starts the absolute ten-millisecond media clock.
    ///
    /// # Errors
    ///
    /// Rejects off-owner mutation or monotonic overflow.
    pub fn start_media_clock(&mut self, now: Duration) -> Result<(), CallRuntimeError> {
        self.verify_owner()?;
        self.next_media_deadline = Some(
            checked_deadline(now, MEDIA_TICK_INTERVAL)
                .map_err(|_| CallRuntimeError::TimeOverflow)?,
        );
        Ok(())
    }

    /// Processes bounded due work without busy-spinning.
    ///
    /// The media clock advances from its previous absolute deadline. A late
    /// wakeup never shifts the ten-millisecond grid.
    ///
    /// # Errors
    ///
    /// Rejects off-owner mutation and preserves context failures.
    pub fn process_due_deadlines(
        &mut self,
        now: Duration,
    ) -> Result<Vec<CallAction>, CallRuntimeError> {
        self.verify_owner()?;
        let mut actions = Vec::new();
        if self
            .next_signaling_poll
            .is_some_and(|deadline| now >= deadline)
        {
            actions.extend(self.poll_signaling(now)?);
            let current = self
                .next_signaling_poll
                .ok_or(CallRuntimeError::TimeOverflow)?;
            let advance = advance_periodic(current, now, SIGNALING_IO_POLL_INTERVAL, 1)
                .map_err(|_| CallRuntimeError::TimeOverflow)?
                .ok_or(CallRuntimeError::TimeOverflow)?;
            self.next_signaling_poll = Some(advance.next_deadline());
        }
        for _ in 0..MAX_DUE_DEADLINES_PER_CYCLE {
            let Some(due) = self.deadlines.poll(now) else {
                break;
            };
            self.diagnostics.processed_deadlines =
                self.diagnostics.processed_deadlines.saturating_add(1);
            if due.owner() == DeadlineOwner::Transaction {
                let signaling = self
                    .signaling
                    .as_mut()
                    .ok_or(CallRuntimeError::SignalingUnavailable)?;
                if let Some(event) = signaling
                    .on_deadline(due.id(), &mut self.transactions, &mut self.deadlines, now)
                    .map_err(CallRuntimeError::Signaling)?
                {
                    actions.extend(
                        self.context
                            .handle(event, now)
                            .map_err(CallRuntimeError::Context)?,
                    );
                }
                continue;
            }
            if due.owner() != DeadlineOwner::Call {
                return Err(CallRuntimeError::UnsupportedDeadlineOwner(due.owner()));
            }
            let timer =
                CallTimer::from_kind(due.kind()).ok_or(CallRuntimeError::UnknownDeadlineKind {
                    owner: due.owner(),
                    kind: due.kind(),
                })?;
            self.dispatch_call_deadline(timer, now, &mut actions)?;
            if self.is_finished() {
                break;
            }
        }
        self.process_media_clock(now)?;
        if self
            .shutdown_deadline
            .is_some_and(|deadline| now >= deadline)
            && !self.is_finished()
        {
            actions.extend(self.context.force_end(CallEndReason::LocalHangup));
        }
        Ok(actions)
    }

    /// Returns the earliest call-local absolute deadline.
    ///
    /// # Errors
    ///
    /// Rejects calls from any non-owner thread.
    pub fn next_deadline(&mut self) -> Result<Option<Duration>, CallRuntimeError> {
        self.verify_owner()?;
        Ok(minimum_deadline([
            self.deadlines.next_deadline(),
            self.shutdown_deadline,
            self.next_media_deadline,
            self.next_signaling_poll,
        ]))
    }

    /// Begins the sole idempotent call teardown path.
    ///
    /// # Errors
    ///
    /// Rejects off-owner mutation, monotonic overflow, or lifecycle failure.
    pub fn begin_shutdown(&mut self, now: Duration) -> Result<Vec<CallAction>, CallRuntimeError> {
        self.verify_owner()?;
        if self.shutting_down {
            return Ok(Vec::new());
        }
        self.shutting_down = true;
        self.transactions.begin_shutdown();
        self.dialogs.begin_shutdown();
        self.media.begin_draining();
        self.next_media_deadline = None;
        self.next_signaling_poll = None;
        self.shutdown_deadline = Some(
            checked_deadline(now, self.shutdown_grace)
                .map_err(|_| CallRuntimeError::TimeOverflow)?,
        );
        match self.context.lifecycle().state() {
            CallState::Idle => Ok(self.context.force_end(CallEndReason::LocalHangup)),
            CallState::Inviting | CallState::Established => self
                .context
                .handle(CallEvent::Command(CallCommand::Hangup), now)
                .map_err(CallRuntimeError::Context),
            CallState::Cancelling | CallState::Terminating | CallState::Ended(_) => Ok(Vec::new()),
        }
    }

    /// Returns whether protocol state reached a terminal call outcome.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.context.lifecycle().state().is_terminal()
    }

    /// Runs idempotent ordered local resource release on the owner thread.
    ///
    /// # Errors
    ///
    /// Rejects cleanup from a non-owner thread.
    pub fn finish_cleanup(&mut self) -> Result<(), CallRuntimeError> {
        self.verify_owner()?;
        if self.cleaned_up {
            return Ok(());
        }
        self.shutting_down = true;
        self.transactions.begin_shutdown();
        self.dialogs.begin_shutdown();
        self.next_media_deadline = None;
        self.next_signaling_poll = None;
        self.media.begin_draining();
        self.media.close();
        self.signaling = None;
        self.rtp_session = None;
        self.media_sockets = None;
        self.packet_scratch = None;
        self.admission.release_all();
        self.cleaned_up = true;
        Ok(())
    }

    /// Returns privacy-safe owner-thread diagnostics.
    #[must_use]
    pub const fn diagnostics(&self) -> CallRuntimeDiagnostics {
        self.diagnostics
    }

    /// Returns whether RTP/RTCP sockets are currently owned.
    #[must_use]
    pub const fn has_media_sockets(&self) -> bool {
        self.media_sockets.is_some()
    }

    /// Returns owner-only mutable SIP transaction state.
    ///
    /// # Errors
    ///
    /// Rejects access from a non-owner thread.
    pub fn transactions(&mut self) -> Result<&mut TransactionManager, CallRuntimeError> {
        self.verify_owner()?;
        Ok(&mut self.transactions)
    }

    /// Returns owner-only mutable SIP dialog state.
    ///
    /// # Errors
    ///
    /// Rejects access from a non-owner thread.
    pub fn dialogs(&mut self) -> Result<&mut DialogManager, CallRuntimeError> {
        self.verify_owner()?;
        Ok(&mut self.dialogs)
    }

    /// Returns owner-only mutable negotiated media state.
    ///
    /// # Errors
    ///
    /// Rejects access from a non-owner thread.
    pub fn media(&mut self) -> Result<&mut MediaController, CallRuntimeError> {
        self.verify_owner()?;
        Ok(&mut self.media)
    }

    /// Returns owner-only mutable RTP session state when negotiated.
    ///
    /// # Errors
    ///
    /// Rejects access from a non-owner thread.
    pub fn rtp_session(&mut self) -> Result<Option<&mut RtpSession>, CallRuntimeError> {
        self.verify_owner()?;
        Ok(self.rtp_session.as_mut())
    }

    /// Returns owner-only RTP/RTCP socket ownership when allocated.
    ///
    /// # Errors
    ///
    /// Rejects access from a non-owner thread.
    pub fn media_sockets(&mut self) -> Result<Option<&mut MediaSocketPair>, CallRuntimeError> {
        self.verify_owner()?;
        Ok(self.media_sockets.as_mut())
    }

    /// Returns owner-only mutable Digest challenge state.
    ///
    /// # Errors
    ///
    /// Rejects access from a non-owner thread.
    pub fn authentication(&mut self) -> Result<&mut AuthContext, CallRuntimeError> {
        self.verify_owner()?;
        Ok(&mut self.authentication)
    }

    /// Returns owner-only mutable reliable-provisional tracking.
    ///
    /// # Errors
    ///
    /// Rejects access from a non-owner thread.
    pub fn prack(&mut self) -> Result<&mut PrackTracker, CallRuntimeError> {
        self.verify_owner()?;
        Ok(&mut self.prack)
    }

    /// Replaces the negotiated SIP session timer on the owner thread.
    ///
    /// # Errors
    ///
    /// Rejects access from a non-owner thread.
    pub fn set_session_timer(
        &mut self,
        timer: Option<SessionTimer>,
    ) -> Result<(), CallRuntimeError> {
        self.verify_owner()?;
        self.session_timer = timer;
        Ok(())
    }

    /// Returns owner-only mutable redirect loop state.
    ///
    /// # Errors
    ///
    /// Rejects access from a non-owner thread.
    pub fn redirect(&mut self) -> Result<&mut RedirectHandler, CallRuntimeError> {
        self.verify_owner()?;
        Ok(&mut self.redirect)
    }

    /// Creates or returns owner-only REFER subscription state.
    ///
    /// # Errors
    ///
    /// Rejects access from a non-owner thread.
    pub fn transfer(&mut self) -> Result<&mut TransferTracker, CallRuntimeError> {
        self.verify_owner()?;
        Ok(self.transfer.get_or_insert_with(TransferTracker::new))
    }

    /// Returns owner-only mutable destination failover state when configured.
    ///
    /// # Errors
    ///
    /// Rejects access from a non-owner thread.
    pub fn failover(&mut self) -> Result<Option<&mut FailoverPlan>, CallRuntimeError> {
        self.verify_owner()?;
        Ok(self.failover.as_mut())
    }

    fn verify_owner(&self) -> Result<(), CallRuntimeError> {
        if self.owner == Some(thread::current().id()) {
            Ok(())
        } else {
            Err(CallRuntimeError::WrongOwnerThread)
        }
    }

    fn dispatch_call_deadline(
        &mut self,
        timer: CallTimer,
        now: Duration,
        actions: &mut Vec<CallAction>,
    ) -> Result<(), CallRuntimeError> {
        let event = match timer {
            CallTimer::NoAnswer => Some(CallEvent::SignalingTimedOut),
            CallTimer::MediaInactivity => Some(CallEvent::MediaTimedOut),
            CallTimer::TransportLiveness => Some(CallEvent::TransportFailed),
            CallTimer::Transfer => {
                let transfer = self
                    .transfer
                    .as_mut()
                    .ok_or(CallRuntimeError::TransferUnavailable)?;
                transfer.expire();
                None
            }
            CallTimer::SessionRefresh => {
                let timer = self
                    .session_timer
                    .as_mut()
                    .ok_or(CallRuntimeError::SessionTimerUnavailable)?;
                match timer.action(now) {
                    SessionTimerAction::Refresh if timer.start_refresh() => {
                        return Err(CallRuntimeError::SessionRefreshExecutorUnavailable);
                    }
                    SessionTimerAction::Expired => Some(CallEvent::SignalingTimedOut),
                    SessionTimerAction::Refresh | SessionTimerAction::None => {
                        return Err(CallRuntimeError::PrematureSessionDeadline);
                    }
                }
            }
        };
        if let Some(event) = event {
            actions.extend(
                self.context
                    .handle(event, now)
                    .map_err(CallRuntimeError::Context)?,
            );
        }
        Ok(())
    }

    fn process_media_clock(&mut self, now: Duration) -> Result<(), CallRuntimeError> {
        let Some(next) = self.next_media_deadline else {
            return Ok(());
        };
        let Some(advance) =
            advance_periodic(next, now, MEDIA_TICK_INTERVAL, MAX_MEDIA_TICKS_PER_CYCLE)
                .map_err(|_| CallRuntimeError::TimeOverflow)?
        else {
            return Ok(());
        };
        self.diagnostics.media_ticks = self
            .diagnostics
            .media_ticks
            .saturating_add(advance.executed());
        self.diagnostics.skipped_media_ticks = self
            .diagnostics
            .skipped_media_ticks
            .saturating_add(advance.skipped());
        self.next_media_deadline = Some(advance.next_deadline());
        Ok(())
    }
}

impl fmt::Debug for CallRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallRuntime")
            .field("owner_claimed", &self.owner.is_some())
            .field("state", &self.context.lifecycle().state())
            .field("transactions", &self.transactions.len())
            .field("dialogs", &self.dialogs.len())
            .field("session_timer", &self.session_timer.is_some())
            .field("transfer", &self.transfer.is_some())
            .field("failover", &self.failover.is_some())
            .field("deadlines", &self.deadlines.len())
            .field("media_sockets", &self.media_sockets.is_some())
            .field("packet_scratch", &self.packet_scratch.is_some())
            .field("rtp_session", &self.rtp_session.is_some())
            .field("signaling", &self.signaling.is_some())
            .field("signaling_poll_active", &self.next_signaling_poll.is_some())
            .field("shutting_down", &self.shutting_down)
            .field("cleaned_up", &self.cleaned_up)
            .field("diagnostics", &self.diagnostics)
            .finish_non_exhaustive()
    }
}

/// Call runtime construction, ownership, or processing failure.
#[derive(Debug)]
pub enum CallRuntimeError {
    /// A different native thread attempted mutable access.
    WrongOwnerThread,
    /// Graceful shutdown interval was zero.
    ZeroShutdownGrace,
    /// Call-local resources were installed twice or after ownership started.
    ResourcesAlreadyInstalled,
    /// Absolute monotonic calculation overflowed.
    TimeOverflow,
    /// SIP transaction registry construction failed.
    Transactions(TransactionManagerError),
    /// SIP dialog registry construction failed.
    Dialogs(DialogManagerError),
    /// Redirect policy allocation or validation failed.
    Redirect(RedirectError),
    /// Deadline scheduler operation failed.
    Deadlines(DeadlineError),
    /// Deterministic call context rejected an event.
    Context(CallContextError),
    /// RTP readiness arrived before its complete call-owned resource set.
    MediaResourcesUnavailable,
    /// Fatal call-owned RTP or RTCP socket operation failed.
    MediaSocket(SocketError),
    /// SIP action required a call-owned signaling driver that was not installed.
    SignalingUnavailable,
    /// Call-owned SIP transport, transaction, or timer execution failed.
    Signaling(SignalingError),
    /// A due deadline owner had no installed exhaustive executor.
    UnsupportedDeadlineOwner(DeadlineOwner),
    /// A due deadline kind was not defined for its owner.
    UnknownDeadlineKind {
        /// Deadline owner.
        owner: DeadlineOwner,
        /// Unrecognized low-cardinality kind.
        kind: u16,
    },
    /// Session-refresh work was scheduled without negotiated timer state.
    SessionTimerUnavailable,
    /// Session refresh became due before its wire executor was installed.
    SessionRefreshExecutorUnavailable,
    /// Session timer work was scheduled before the negotiated instant.
    PrematureSessionDeadline,
    /// Transfer expiry was scheduled without an active transfer tracker.
    TransferUnavailable,
}

impl fmt::Display for CallRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("call runtime operation failed")
    }
}

impl StdError for CallRuntimeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Transactions(source) => Some(source),
            Self::Dialogs(source) => Some(source),
            Self::Redirect(source) => Some(source),
            Self::Deadlines(source) => Some(source),
            Self::Context(source) => Some(source),
            Self::MediaSocket(source) => Some(source),
            Self::Signaling(source) => Some(source),
            Self::WrongOwnerThread
            | Self::ZeroShutdownGrace
            | Self::ResourcesAlreadyInstalled
            | Self::TimeOverflow
            | Self::MediaResourcesUnavailable
            | Self::SignalingUnavailable
            | Self::UnsupportedDeadlineOwner(_)
            | Self::UnknownDeadlineKind { .. }
            | Self::SessionTimerUnavailable
            | Self::SessionRefreshExecutorUnavailable
            | Self::PrematureSessionDeadline
            | Self::TransferUnavailable => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::thread;
    use std::time::Duration;

    use super::{
        CallMessage, CallRuntime, CallRuntimeConfig, CallRuntimeError, MAX_MEDIA_TICKS_PER_CYCLE,
        MEDIA_TICK_INTERVAL,
    };
    use crate::call::context::CallContext;
    use crate::call::events::{CallAction, CallCommand, CallEvent};
    use crate::call::timers::CallTimer;
    use crate::call::transfer::TransferState;
    use crate::rtp::clock::RtpClockRate;
    use crate::rtp::liveness::MediaLiveness;
    use crate::rtp::security::MediaSecurityPolicy;
    use crate::rtp::session::RtpSession;
    use crate::rtp::source::SourcePolicy;
    use crate::rtp::state::RtpReceiveConfig;
    use crate::rtp::transport::symmetric::{SymmetricConfig, SymmetricEndpoints};
    use crate::rtp::transport::{
        Component, DEFAULT_MAX_MEDIA_DATAGRAM_BYTES, MediaPacketScratch, MediaSocketPair, PortPool,
        SocketConfig,
    };
    use crate::runtime::admission::AdmissionLeaseGroup;
    use crate::runtime::deadline::DeadlineOwner;
    use crate::sip::dialog::{Refresher, SessionTimer};

    fn runtime() -> CallRuntime {
        let context = CallContext::new(Duration::ZERO, 16).unwrap_or_else(|_| panic!("context"));
        CallRuntime::new(
            context,
            AdmissionLeaseGroup::new(),
            CallRuntimeConfig::default(),
        )
        .unwrap_or_else(|_| panic!("runtime"))
    }

    fn address(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn media_session(remote_rtp: SocketAddr) -> RtpSession {
        let clock = RtpClockRate::new(8_000).unwrap_or_else(|_| panic!("clock"));
        let receive =
            RtpReceiveConfig::new(0, clock, Some(7)).unwrap_or_else(|_| panic!("receive config"));
        let control_endpoint = SocketAddr::new(
            remote_rtp.ip(),
            remote_rtp
                .port()
                .checked_add(1)
                .unwrap_or(remote_rtp.port()),
        );
        let endpoints =
            SymmetricEndpoints::new(remote_rtp, control_endpoint, SymmetricConfig::default())
                .unwrap_or_else(|_| panic!("endpoints"));
        let liveness = MediaLiveness::new(
            Duration::ZERO,
            Duration::from_secs(5),
            Duration::from_secs(10),
        )
        .unwrap_or_else(|_| panic!("liveness"));
        RtpSession::new(
            receive,
            SourcePolicy::default(),
            endpoints,
            MediaSecurityPolicy::PlainAllowed,
            liveness,
            8,
        )
        .unwrap_or_else(|_| panic!("session"))
    }

    fn media_sockets() -> (PortPool, MediaSocketPair) {
        for port in (42_000_u16..60_000).step_by(2) {
            let pool = PortPool::new(port, port).unwrap_or_else(|_| panic!("pool"));
            let lease = pool.allocate().unwrap_or_else(|| panic!("lease"));
            if let Ok(sockets) = MediaSocketPair::bind(
                lease,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                SocketConfig::default(),
            ) {
                return (pool, sockets);
            }
        }
        panic!("free RTP pair")
    }

    fn rtp_packet(sequence: u16) -> [u8; 13] {
        let mut packet = [0_u8; 13];
        packet[0] = 0x80;
        packet[1] = 0;
        packet[2..4].copy_from_slice(&sequence.to_be_bytes());
        packet[4..8].copy_from_slice(&(u32::from(sequence) * 80).to_be_bytes());
        packet[8..12].copy_from_slice(&7_u32.to_be_bytes());
        packet[12] = 0x55;
        packet
    }

    #[test]
    fn runtime_rejects_mutation_before_owner_claim() {
        let mut runtime = runtime();
        assert!(
            runtime
                .handle(
                    CallMessage::Event(CallEvent::Command(CallCommand::Start)),
                    Duration::ZERO,
                )
                .is_err()
        );
        runtime
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim"));
        assert!(matches!(
            runtime.handle(
                CallMessage::Event(CallEvent::Command(CallCommand::Start)),
                Duration::ZERO,
            ),
            Ok(actions) if actions == vec![CallAction::SendInvite]
        ));
    }

    #[test]
    fn runtime_cannot_move_mutation_to_another_thread() {
        let mut runtime = runtime();
        runtime
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim"));
        let joined =
            thread::spawn(move || runtime.handle(CallMessage::Shutdown, Duration::ZERO)).join();
        assert!(matches!(joined, Ok(Err(_))));
    }

    #[test]
    fn media_clock_uses_absolute_progression_after_late_wakeup() {
        let mut runtime = runtime();
        runtime
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim"));
        runtime
            .start_media_clock(Duration::ZERO)
            .unwrap_or_else(|_| panic!("clock"));
        runtime
            .process_due_deadlines(Duration::from_millis(105))
            .unwrap_or_else(|_| panic!("due"));
        assert_eq!(runtime.diagnostics().media_ticks, MAX_MEDIA_TICKS_PER_CYCLE);
        assert_eq!(runtime.diagnostics().skipped_media_ticks, 2);
        assert_eq!(
            runtime
                .next_deadline()
                .unwrap_or_else(|_| panic!("deadline")),
            Some(Duration::from_millis(110))
        );
        assert_eq!(MEDIA_TICK_INTERVAL, Duration::from_millis(10));
    }

    #[test]
    fn transfer_deadline_fails_only_transfer_state_without_ending_call() {
        let mut runtime = runtime();
        runtime
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim"));
        assert_eq!(
            runtime
                .transfer()
                .unwrap_or_else(|_| panic!("transfer"))
                .state(),
            TransferState::ReferPending
        );
        runtime
            .schedule_call_deadline(CallTimer::Transfer, Duration::from_secs(1), 1)
            .unwrap_or_else(|_| panic!("schedule"));
        assert_eq!(
            runtime
                .process_due_deadlines(Duration::from_secs(1))
                .unwrap_or_else(|_| panic!("due")),
            Vec::new()
        );
        assert_eq!(
            runtime
                .transfer()
                .unwrap_or_else(|_| panic!("transfer"))
                .state(),
            TransferState::Failed
        );
        assert!(!runtime.is_finished());
    }

    #[test]
    fn session_refresh_and_expiry_have_distinct_dispositions() {
        let mut local = runtime();
        local
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim local"));
        local
            .set_session_timer(Some(
                SessionTimer::new(100, 90, Refresher::Local, Duration::ZERO)
                    .unwrap_or_else(|_| panic!("local timer")),
            ))
            .unwrap_or_else(|_| panic!("set local"));
        local
            .schedule_call_deadline(CallTimer::SessionRefresh, Duration::from_secs(50), 1)
            .unwrap_or_else(|_| panic!("schedule local"));
        assert!(matches!(
            local.process_due_deadlines(Duration::from_secs(50)),
            Err(CallRuntimeError::SessionRefreshExecutorUnavailable)
        ));
        assert!(!local.is_finished());

        let mut remote = runtime();
        remote
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim remote"));
        remote
            .set_session_timer(Some(
                SessionTimer::new(100, 90, Refresher::Remote, Duration::ZERO)
                    .unwrap_or_else(|_| panic!("remote timer")),
            ))
            .unwrap_or_else(|_| panic!("set remote"));
        remote
            .schedule_call_deadline(CallTimer::SessionRefresh, Duration::from_secs(100), 1)
            .unwrap_or_else(|_| panic!("schedule remote"));
        let actions = remote
            .process_due_deadlines(Duration::from_secs(100))
            .unwrap_or_else(|_| panic!("expiry"));
        assert!(matches!(actions.as_slice(), [CallAction::Ended(_)]));
        assert!(remote.is_finished());
    }

    #[test]
    fn unsupported_or_unknown_deadlines_are_never_silently_consumed() {
        let mut unsupported = runtime();
        unsupported
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim"));
        unsupported
            .deadlines
            .schedule(Duration::ZERO, DeadlineOwner::Dialog, 1, 1)
            .unwrap_or_else(|_| panic!("schedule"));
        assert!(matches!(
            unsupported.process_due_deadlines(Duration::ZERO),
            Err(CallRuntimeError::UnsupportedDeadlineOwner(
                DeadlineOwner::Dialog
            ))
        ));

        let mut unknown = runtime();
        unknown
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim"));
        unknown
            .deadlines
            .schedule(Duration::ZERO, DeadlineOwner::Call, 1, u16::MAX)
            .unwrap_or_else(|_| panic!("schedule"));
        assert!(matches!(
            unknown.process_due_deadlines(Duration::ZERO),
            Err(CallRuntimeError::UnknownDeadlineKind {
                owner: DeadlineOwner::Call,
                kind: u16::MAX
            })
        ));
    }

    #[test]
    fn cleanup_is_idempotent() {
        let mut runtime = runtime();
        runtime
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim"));
        assert!(runtime.finish_cleanup().is_ok());
        assert!(runtime.finish_cleanup().is_ok());
    }

    #[test]
    fn stale_media_generation_work_is_rejected() {
        let mut runtime = runtime();
        runtime
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim"));
        assert!(
            runtime
                .handle(
                    CallMessage::AudioReady {
                        generation: 99,
                        direction: super::AudioDirection::Transmit,
                    },
                    Duration::ZERO,
                )
                .is_ok()
        );
        assert_eq!(runtime.diagnostics().stale_media_work, 1);
    }

    #[test]
    fn network_readiness_requires_complete_call_owned_media_resources() {
        let mut runtime = runtime();
        runtime
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim"));
        assert!(matches!(
            runtime.poll_network(Component::Rtp, Duration::ZERO),
            Err(CallRuntimeError::MediaResourcesUnavailable)
        ));
    }

    #[test]
    fn owner_thread_drains_real_rtp_socket_into_session_without_packet_allocation() {
        let (_pool, sockets) = media_sockets();
        let destination = sockets
            .local_addr(Component::Rtp)
            .unwrap_or_else(|_| panic!("local RTP"));
        let sender = UdpSocket::bind(address(0)).unwrap_or_else(|_| panic!("sender"));
        let remote = sender
            .local_addr()
            .unwrap_or_else(|_| panic!("sender address"));
        let scratch = MediaPacketScratch::new(DEFAULT_MAX_MEDIA_DATAGRAM_BYTES)
            .unwrap_or_else(|_| panic!("scratch"));
        let mut runtime = runtime()
            .with_media_sockets(sockets)
            .and_then(|runtime| runtime.with_packet_scratch(scratch))
            .and_then(|runtime| runtime.with_rtp_session(media_session(remote)))
            .unwrap_or_else(|_| panic!("media runtime"));
        runtime
            .claim_current_thread()
            .unwrap_or_else(|_| panic!("claim"));

        for sequence in 1..=3 {
            let packet = rtp_packet(sequence);
            assert_eq!(
                sender
                    .send_to(&packet, destination)
                    .unwrap_or_else(|_| panic!("send RTP")),
                packet.len()
            );
        }
        assert!(
            sender
                .send_to(&[0, 1], destination)
                .is_ok_and(|written| written == 2)
        );

        assert!(
            runtime
                .poll_network(Component::Rtp, Duration::from_millis(30))
                .is_ok()
        );
        let diagnostics = runtime.diagnostics();
        assert_eq!(diagnostics.media_datagrams_received, 4);
        assert!(diagnostics.rtp_audio_packets_queued >= 1);
        assert!(diagnostics.media_datagrams_rejected >= 1);
    }
}
