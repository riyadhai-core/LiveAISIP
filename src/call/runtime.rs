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
use std::thread::{self, ThreadId};
use std::time::Duration;

use crate::rtp::session::RtpSession;
use crate::rtp::transport::{Component, MediaPacketScratch, MediaSocketPair};
use crate::runtime::admission::AdmissionLeaseGroup;
use crate::runtime::deadline::{DeadlineError, DeadlineId, DeadlineOwner, DeadlineScheduler};
use crate::runtime::media::MediaController;
use crate::sip::auth::AuthContext;
use crate::sip::dialog::{DialogManager, DialogManagerError, PrackTracker, SessionTimer};
use crate::sip::transaction::manager::{
    ManagerError as TransactionManagerError, TransactionManager,
};
use crate::sip::transport::failover::FailoverPlan;

use super::context::{CallContext, CallContextError};
use super::events::{CallAction, CallCommand, CallEvent};
use super::redirect::{RedirectError, RedirectHandler, RedirectPolicy};
use super::state::{CallEndReason, CallState};
use super::timers::CallTimer;
use super::transfer::TransferTracker;

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
    admission: AdmissionLeaseGroup,
    shutdown_grace: Duration,
    shutdown_deadline: Option<Duration>,
    next_media_deadline: Option<Duration>,
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
            admission,
            shutdown_grace: config.shutdown_grace,
            shutdown_deadline: None,
            next_media_deadline: None,
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
            CallMessage::Event(event) => self
                .context
                .handle(event, now)
                .map_err(CallRuntimeError::Context),
            CallMessage::NetworkReady(component) => self.poll_network(component, now),
            CallMessage::AudioReady {
                generation,
                direction: _,
            } => {
                let current = self
                    .media
                    .work_token()
                    .map(crate::runtime::media::MediaWorkToken::generation);
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

    /// Polls call-owned sockets after readiness was delivered to this owner.
    ///
    /// Socket parsing remains in RTP/SIP transport modules; this ownership
    /// boundary intentionally performs no protocol mutation until those
    /// drivers are installed into the runtime.
    ///
    /// # Errors
    ///
    /// Rejects calls from any non-owner thread.
    pub fn poll_network(
        &mut self,
        _component: Component,
        _now: Duration,
    ) -> Result<Vec<CallAction>, CallRuntimeError> {
        self.verify_owner()?;
        Ok(Vec::new())
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
            now.checked_add(MEDIA_TICK_INTERVAL)
                .ok_or(CallRuntimeError::TimeOverflow)?,
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
        for _ in 0..MAX_DUE_DEADLINES_PER_CYCLE {
            let Some(due) = self.deadlines.poll(now) else {
                break;
            };
            self.diagnostics.processed_deadlines =
                self.diagnostics.processed_deadlines.saturating_add(1);
            let Some(timer) = CallTimer::from_kind(due.kind()) else {
                continue;
            };
            let event = match timer {
                CallTimer::NoAnswer | CallTimer::SessionRefresh | CallTimer::Transfer => {
                    CallEvent::SignalingTimedOut
                }
                CallTimer::MediaInactivity => CallEvent::MediaTimedOut,
                CallTimer::TransportLiveness => CallEvent::TransportFailed,
            };
            actions.extend(
                self.context
                    .handle(event, now)
                    .map_err(CallRuntimeError::Context)?,
            );
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
        self.shutdown_deadline = Some(
            now.checked_add(self.shutdown_grace)
                .ok_or(CallRuntimeError::TimeOverflow)?,
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
        self.media.begin_draining();
        self.media.close();
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

    fn process_media_clock(&mut self, now: Duration) -> Result<(), CallRuntimeError> {
        let Some(next) = self.next_media_deadline else {
            return Ok(());
        };
        if now < next {
            return Ok(());
        }
        let interval_nanos = MEDIA_TICK_INTERVAL.as_nanos();
        let late_nanos = now.saturating_sub(next).as_nanos();
        let due = u64::try_from(late_nanos / interval_nanos)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let executed = due.min(MAX_MEDIA_TICKS_PER_CYCLE);
        self.diagnostics.media_ticks = self.diagnostics.media_ticks.saturating_add(executed);
        self.diagnostics.skipped_media_ticks = self
            .diagnostics
            .skipped_media_ticks
            .saturating_add(due.saturating_sub(executed));
        let advance = duration_mul(MEDIA_TICK_INTERVAL, due)?;
        self.next_media_deadline = Some(
            next.checked_add(advance)
                .ok_or(CallRuntimeError::TimeOverflow)?,
        );
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
            .field("shutting_down", &self.shutting_down)
            .field("cleaned_up", &self.cleaned_up)
            .field("diagnostics", &self.diagnostics)
            .finish_non_exhaustive()
    }
}

fn minimum_deadline<const N: usize>(deadlines: [Option<Duration>; N]) -> Option<Duration> {
    deadlines.into_iter().flatten().min()
}

fn duration_mul(value: Duration, multiplier: u64) -> Result<Duration, CallRuntimeError> {
    let nanos = value
        .as_nanos()
        .checked_mul(u128::from(multiplier))
        .ok_or(CallRuntimeError::TimeOverflow)?;
    let seconds = nanos / 1_000_000_000;
    let subsecond =
        u32::try_from(nanos % 1_000_000_000).map_err(|_| CallRuntimeError::TimeOverflow)?;
    Ok(Duration::new(
        u64::try_from(seconds).map_err(|_| CallRuntimeError::TimeOverflow)?,
        subsecond,
    ))
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
            Self::WrongOwnerThread
            | Self::ZeroShutdownGrace
            | Self::ResourcesAlreadyInstalled
            | Self::TimeOverflow => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use super::{
        CallMessage, CallRuntime, CallRuntimeConfig, MAX_MEDIA_TICKS_PER_CYCLE, MEDIA_TICK_INTERVAL,
    };
    use crate::call::context::CallContext;
    use crate::call::events::{CallAction, CallCommand, CallEvent};
    use crate::runtime::admission::AdmissionLeaseGroup;

    fn runtime() -> CallRuntime {
        let context = CallContext::new(Duration::ZERO, 16).unwrap_or_else(|_| panic!("context"));
        CallRuntime::new(
            context,
            AdmissionLeaseGroup::new(),
            CallRuntimeConfig::default(),
        )
        .unwrap_or_else(|_| panic!("runtime"))
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
}
