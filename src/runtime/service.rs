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

//! Bounded application-facing service above the process runtime engine.
//!
//! SIP correctness effects execute inside call threads. Notifications are a
//! best-effort observer stream and can never block ACK, CANCEL, BYE, timers, or
//! media work. Exact terminal outcomes remain queryable until acknowledged.

use std::collections::{HashMap, VecDeque};
use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use crate::call::execution::handle::{CallStatusSnapshot, CallToken};
use crate::call::execution::manager::CallManagerError;
use crate::call::execution::thread::{CallExit, CallExitKind};
use crate::call::model::events::{CallAction, CallCommand};
use crate::runtime::dial::OutboundDialConfig;
use crate::runtime::engine::{DialedCall, RuntimeEngine, RuntimeEngineConfig, RuntimeEngineError};
use crate::runtime::shutdown::{ShutdownAction, ShutdownPhase};

/// Maximum observer notifications retained by one worker service.
pub const MAX_RUNTIME_NOTIFICATION_CAPACITY: usize = 1_000_000;
/// Maximum action batches drained from one call during one service pump.
pub const MAX_ACTION_BATCHES_PER_CALL_PUMP: usize = 64;

/// Immutable process service capacities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeServiceConfig {
    engine: RuntimeEngineConfig,
    notification_capacity: usize,
}

impl RuntimeServiceConfig {
    /// Creates a process service configuration.
    #[must_use]
    pub const fn new(engine: RuntimeEngineConfig, notification_capacity: usize) -> Self {
        Self {
            engine,
            notification_capacity,
        }
    }

    /// Returns the process engine configuration.
    #[must_use]
    pub const fn engine(self) -> RuntimeEngineConfig {
        self.engine
    }

    /// Returns fixed observer notification capacity.
    #[must_use]
    pub const fn notification_capacity(self) -> usize {
        self.notification_capacity
    }
}

struct ActiveCall {
    token: CallToken,
    next_sequence: u64,
}

/// Process-level application service with bounded observer delivery.
pub struct RuntimeService {
    engine: RuntimeEngine,
    calls: HashMap<u64, ActiveCall>,
    terminal: HashMap<u64, TerminalOutcome>,
    notifications: VecDeque<RuntimeNotification>,
    notification_capacity: usize,
    notifications_dropped: u64,
    scratch: Vec<CallToken>,
    call_capacity: usize,
}

impl RuntimeService {
    /// Allocates all service registries and observer storage before accepting
    /// calls.
    ///
    /// # Errors
    ///
    /// Rejects invalid notification capacity, engine configuration, or any
    /// bounded registry allocation failure.
    pub fn new(config: RuntimeServiceConfig) -> Result<Self, RuntimeServiceError> {
        if config.notification_capacity == 0
            || config.notification_capacity > MAX_RUNTIME_NOTIFICATION_CAPACITY
        {
            return Err(RuntimeServiceError::InvalidNotificationCapacity);
        }
        let call_capacity = config.engine.maximum_calls();
        let engine = RuntimeEngine::new(config.engine).map_err(RuntimeServiceError::Engine)?;
        let mut calls = HashMap::new();
        calls
            .try_reserve(call_capacity)
            .map_err(|_| RuntimeServiceError::AllocationFailed)?;
        let mut terminal = HashMap::new();
        terminal
            .try_reserve(call_capacity)
            .map_err(|_| RuntimeServiceError::AllocationFailed)?;
        let mut notifications = VecDeque::new();
        notifications
            .try_reserve_exact(config.notification_capacity)
            .map_err(|_| RuntimeServiceError::AllocationFailed)?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(call_capacity)
            .map_err(|_| RuntimeServiceError::AllocationFailed)?;
        Ok(Self {
            engine,
            calls,
            terminal,
            notifications,
            notification_capacity: config.notification_capacity,
            notifications_dropped: 0,
            scratch,
            call_capacity,
        })
    }

    /// Atomically starts one outbound call and publishes a best-effort start
    /// notification.
    ///
    /// Retained unacknowledged terminal outcomes consume service capacity so
    /// they can never be silently overwritten by new calls.
    ///
    /// # Errors
    ///
    /// Rejects duplicate identities, full retained-outcome capacity, or any
    /// engine dial failure.
    pub fn dial(
        &mut self,
        call_id: u64,
        config: OutboundDialConfig,
    ) -> Result<DialedCall, RuntimeServiceError> {
        if self.calls.contains_key(&call_id) || self.terminal.contains_key(&call_id) {
            return Err(RuntimeServiceError::DuplicateCall);
        }
        if self.calls.len().saturating_add(self.terminal.len()) >= self.call_capacity {
            return Err(RuntimeServiceError::OutcomeCapacity);
        }
        let dialed = self
            .engine
            .dial(call_id, config)
            .map_err(RuntimeServiceError::Engine)?;
        let token = dialed.token();
        self.calls.insert(
            call_id,
            ActiveCall {
                token,
                next_sequence: 2,
            },
        );
        self.enqueue(RuntimeNotification::new(
            token,
            1,
            RuntimeNotificationKind::DialStarted,
        ));
        Ok(dialed)
    }

    /// Submits one bounded public command to an active call.
    ///
    /// # Errors
    ///
    /// Rejects unknown calls and preserves engine mailbox failures.
    pub fn command(&self, call_id: u64, command: CallCommand) -> Result<(), RuntimeServiceError> {
        let call = self
            .calls
            .get(&call_id)
            .ok_or(RuntimeServiceError::UnknownCall)?;
        self.engine
            .command(call.token, command)
            .map_err(RuntimeServiceError::Engine)
    }

    /// Requests graceful termination of one active call.
    ///
    /// # Errors
    ///
    /// Rejects unknown calls and preserves engine mailbox failures.
    pub fn hangup(&self, call_id: u64) -> Result<(), RuntimeServiceError> {
        self.command(call_id, CallCommand::Hangup)
    }

    /// Drains bounded observer actions and joins terminal calls.
    ///
    /// This operation never waits for action delivery. A full notification
    /// queue drops observer data while protocol effects continue inside the
    /// call thread. Terminal reports are retained independently.
    ///
    /// # Errors
    ///
    /// Preserves call lookup, action queue, sequence, and join failures.
    pub fn pump(&mut self) -> Result<RuntimePumpReport, RuntimeServiceError> {
        self.scratch.clear();
        self.scratch
            .extend(self.calls.values().map(|call| call.token));
        let mut action_batches = 0_usize;
        let mut calls_completed = 0_usize;
        for index in 0..self.scratch.len() {
            let token = self.scratch[index];
            let call_id = token.call_id();
            for _ in 0..MAX_ACTION_BATCHES_PER_CALL_PUMP {
                match self.engine.receive_actions(token, Duration::ZERO) {
                    Ok(Some(actions)) => {
                        action_batches = action_batches.saturating_add(1);
                        for action in actions {
                            self.publish_action(call_id, action)?;
                        }
                    }
                    Ok(None) | Err(RuntimeEngineError::Calls(CallManagerError::CallClosed)) => {
                        break;
                    }
                    Err(error) => return Err(RuntimeServiceError::Engine(error)),
                }
            }
            let status = self
                .engine
                .handle(token)
                .map_err(RuntimeServiceError::Engine)?
                .status();
            if status.phase.is_terminal() {
                let exit = self
                    .engine
                    .remove(token)
                    .map_err(RuntimeServiceError::Engine)?;
                self.finish_call(token, exit)?;
                calls_completed = calls_completed.saturating_add(1);
            }
        }
        Ok(RuntimePumpReport {
            calls_scanned: self.scratch.len(),
            action_batches,
            calls_completed,
        })
    }

    /// Returns the latest active or retained terminal snapshot.
    #[must_use]
    pub fn snapshot(&self, call_id: u64) -> Option<RuntimeCallSnapshot> {
        if let Some(call) = self.calls.get(&call_id) {
            return self
                .engine
                .handle(call.token)
                .ok()
                .map(|handle| RuntimeCallSnapshot::Active {
                    token: call.token,
                    status: handle.status(),
                });
        }
        self.terminal
            .get(&call_id)
            .copied()
            .map(RuntimeCallSnapshot::Terminal)
    }

    /// Returns an exact terminal outcome without acknowledging it.
    #[must_use]
    pub fn terminal_outcome(&self, call_id: u64) -> Option<TerminalOutcome> {
        self.terminal.get(&call_id).copied()
    }

    /// Acknowledges and removes one retained terminal outcome.
    pub fn take_terminal_outcome(&mut self, call_id: u64) -> Option<TerminalOutcome> {
        self.terminal.remove(&call_id)
    }

    /// Pops the oldest retained observer notification.
    pub fn next_notification(&mut self) -> Option<RuntimeNotification> {
        self.notifications.pop_front()
    }

    /// Returns bounded observer queue counters.
    #[must_use]
    pub fn notification_snapshot(&self) -> NotificationQueueSnapshot {
        NotificationQueueSnapshot {
            capacity: self.notification_capacity,
            depth: self.notifications.len(),
            dropped: self.notifications_dropped,
        }
    }

    /// Fences new calls and begins graceful process drain.
    ///
    /// # Errors
    ///
    /// Preserves shutdown state and monotonic-time failures.
    pub fn begin_shutdown(&mut self, now: Duration) -> Result<(), RuntimeServiceError> {
        self.engine
            .begin_shutdown(now)
            .map_err(RuntimeServiceError::Engine)
    }

    /// Advances process drain and retains every completed or forced outcome.
    ///
    /// # Errors
    ///
    /// Preserves engine shutdown, join, and notification sequence failures.
    pub fn poll_shutdown(
        &mut self,
        now: Duration,
    ) -> Result<ServiceShutdownProgress, RuntimeServiceError> {
        let progress = self
            .engine
            .poll_shutdown(now)
            .map_err(RuntimeServiceError::Engine)?;
        let action = progress.action();
        let completed = progress.completed_exits().len();
        let forced = progress.forced_exits().len();
        for report in progress
            .completed_exits()
            .iter()
            .chain(progress.forced_exits())
            .copied()
        {
            self.finish_call(report.token(), report.exit())?;
        }
        Ok(ServiceShutdownProgress {
            action,
            completed,
            forced,
        })
    }

    /// Returns calls whose dedicated owner thread is not terminal.
    #[must_use]
    pub fn active_calls(&self) -> usize {
        self.engine.active_calls()
    }

    /// Returns every engine-registered call, including terminal calls awaiting
    /// the next service pump.
    #[must_use]
    pub fn registered_calls(&self) -> usize {
        self.engine.registered_calls()
    }

    /// Returns terminal native calls awaiting service reaping.
    #[must_use]
    pub fn terminal_unreaped_calls(&self) -> usize {
        self.engine.terminal_unreaped_calls()
    }

    /// Returns unacknowledged terminal outcome count.
    #[must_use]
    pub fn retained_outcomes(&self) -> usize {
        self.terminal.len()
    }

    /// Returns process shutdown phase.
    #[must_use]
    pub const fn shutdown_phase(&self) -> ShutdownPhase {
        self.engine.shutdown_phase()
    }

    fn publish_action(
        &mut self,
        call_id: u64,
        action: CallAction,
    ) -> Result<(), RuntimeServiceError> {
        let (token, sequence) = self.next_sequence(call_id)?;
        self.enqueue(RuntimeNotification::new(
            token,
            sequence,
            RuntimeNotificationKind::Action(action),
        ));
        Ok(())
    }

    fn finish_call(&mut self, token: CallToken, exit: CallExit) -> Result<(), RuntimeServiceError> {
        let active = self
            .calls
            .remove(&token.call_id())
            .ok_or(RuntimeServiceError::UnknownCall)?;
        if active.token != token {
            return Err(RuntimeServiceError::StaleCallGeneration);
        }
        let sequence = active.next_sequence;
        let outcome = TerminalOutcome {
            token,
            exit,
            final_sequence: sequence,
        };
        if self.terminal.insert(token.call_id(), outcome).is_some() {
            return Err(RuntimeServiceError::DuplicateCall);
        }
        self.enqueue(RuntimeNotification::new(
            token,
            sequence,
            RuntimeNotificationKind::CallExited(exit.kind()),
        ));
        Ok(())
    }

    fn next_sequence(&mut self, call_id: u64) -> Result<(CallToken, u64), RuntimeServiceError> {
        let call = self
            .calls
            .get_mut(&call_id)
            .ok_or(RuntimeServiceError::UnknownCall)?;
        let sequence = call.next_sequence;
        call.next_sequence = sequence
            .checked_add(1)
            .ok_or(RuntimeServiceError::NotificationSequenceExhausted)?;
        Ok((call.token, sequence))
    }

    fn enqueue(&mut self, notification: RuntimeNotification) {
        if self.notifications.len() < self.notification_capacity {
            self.notifications.push_back(notification);
            return;
        }
        if notification.kind.is_terminal()
            && let Some(index) = self
                .notifications
                .iter()
                .position(|queued| !queued.kind.is_terminal())
        {
            let _ = self.notifications.remove(index);
            self.notifications_dropped = self.notifications_dropped.saturating_add(1);
            self.notifications.push_back(notification);
            return;
        }
        self.notifications_dropped = self.notifications_dropped.saturating_add(1);
    }
}

impl fmt::Debug for RuntimeService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeService")
            .field("active_calls", &self.calls.len())
            .field("retained_outcomes", &self.terminal.len())
            .field("notification_depth", &self.notifications.len())
            .field("notifications_dropped", &self.notifications_dropped)
            .field("shutdown_phase", &self.engine.shutdown_phase())
            .finish_non_exhaustive()
    }
}

/// One ordered best-effort application notification.
pub struct RuntimeNotification {
    call: CallToken,
    sequence: u64,
    kind: RuntimeNotificationKind,
}

impl RuntimeNotification {
    const fn new(call: CallToken, sequence: u64, kind: RuntimeNotificationKind) -> Self {
        Self {
            call,
            sequence,
            kind,
        }
    }

    /// Returns the exact call generation.
    #[must_use]
    pub const fn call(&self) -> CallToken {
        self.call
    }

    /// Returns the strictly increasing per-call notification sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns notification payload.
    #[must_use]
    pub const fn kind(&self) -> &RuntimeNotificationKind {
        &self.kind
    }
}

impl fmt::Debug for RuntimeNotification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeNotification")
            .field("call", &self.call)
            .field("sequence", &self.sequence)
            .field("class", &self.kind.class())
            .finish()
    }
}

/// Low-cardinality observer notification payload.
pub enum RuntimeNotificationKind {
    /// Call was admitted and its native owner thread was started.
    DialStarted,
    /// One observational action produced after internal effects executed.
    Action(CallAction),
    /// Native call thread ended; exact outcome is retained separately.
    CallExited(CallExitKind),
}

impl RuntimeNotificationKind {
    /// Returns a stable low-cardinality notification class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::DialStarted => "dial-started",
            Self::Action(action) => action_class(action),
            Self::CallExited(_) => "call-exited",
        }
    }

    const fn is_terminal(&self) -> bool {
        matches!(self, Self::CallExited(_))
    }
}

impl fmt::Debug for RuntimeNotificationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeNotificationKind")
            .field("class", &self.class())
            .finish_non_exhaustive()
    }
}

/// Exact terminal outcome retained until application acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalOutcome {
    token: CallToken,
    exit: CallExit,
    final_sequence: u64,
}

impl TerminalOutcome {
    /// Returns exact call generation.
    #[must_use]
    pub const fn token(self) -> CallToken {
        self.token
    }

    /// Returns privacy-safe call-thread outcome and diagnostics.
    #[must_use]
    pub const fn exit(self) -> CallExit {
        self.exit
    }

    /// Returns sequence reserved for the terminal notification.
    #[must_use]
    pub const fn final_sequence(self) -> u64 {
        self.final_sequence
    }
}

/// Active or retained terminal call snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCallSnapshot {
    /// Live generation and queue/thread status.
    Active {
        /// Exact call generation.
        token: CallToken,
        /// Native owner and bounded queue status.
        status: CallStatusSnapshot,
    },
    /// Terminal outcome awaiting acknowledgement.
    Terminal(TerminalOutcome),
}

/// Bounded observer queue state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NotificationQueueSnapshot {
    /// Fixed notification capacity.
    pub capacity: usize,
    /// Current retained notification count.
    pub depth: usize,
    /// Notifications dropped or displaced due to queue pressure.
    pub dropped: u64,
}

/// Result of one nonblocking service pump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimePumpReport {
    /// Calls inspected.
    pub calls_scanned: usize,
    /// Action batches removed from per-call observer queues.
    pub action_batches: usize,
    /// Calls joined and retained as exact terminal outcomes.
    pub calls_completed: usize,
}

/// Result of one service shutdown poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceShutdownProgress {
    /// Shutdown transition emitted by the engine.
    pub action: ShutdownAction,
    /// Calls naturally completed this poll.
    pub completed: usize,
    /// Calls forced to terminate this poll.
    pub forced: usize,
}

/// Application service failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum RuntimeServiceError {
    /// Notification capacity was zero or above the process hard limit.
    InvalidNotificationCapacity,
    /// Bounded service storage allocation failed.
    AllocationFailed,
    /// Call identity is active or has an unacknowledged terminal outcome.
    DuplicateCall,
    /// Active calls plus retained outcomes reached configured capacity.
    OutcomeCapacity,
    /// No active call has this identity.
    UnknownCall,
    /// Registry identity disagreed with the generation-fenced call token.
    StaleCallGeneration,
    /// Per-call notification sequence cannot advance without wrapping.
    NotificationSequenceExhausted,
    /// Process engine operation failed.
    Engine(RuntimeEngineError),
}

impl fmt::Display for RuntimeServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime service operation failed")
    }
}

impl StdError for RuntimeServiceError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Engine(error) => Some(error),
            Self::InvalidNotificationCapacity
            | Self::AllocationFailed
            | Self::DuplicateCall
            | Self::OutcomeCapacity
            | Self::UnknownCall
            | Self::StaleCallGeneration
            | Self::NotificationSequenceExhausted => None,
        }
    }
}

const fn action_class(action: &CallAction) -> &'static str {
    match action {
        CallAction::SendInvite => "send-invite",
        CallAction::SendCancel => "send-cancel",
        CallAction::SendAck { .. } => "send-ack",
        CallAction::SendBye { .. } => "send-bye",
        CallAction::SelectBranch { .. } => "select-branch",
        CallAction::ApplyEarlyMedia { .. } => "apply-early-media",
        CallAction::SendRefer { .. } => "send-refer",
        CallAction::SendReferReplaces { .. } => "send-refer-replaces",
        CallAction::ApplySessionModification { .. } => "apply-session-modification",
        CallAction::Ended(_) => "ended",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::Duration;

    use super::{
        RuntimeCallSnapshot, RuntimeNotificationKind, RuntimeService, RuntimeServiceConfig,
        RuntimeServiceError,
    };
    use crate::call::execution::thread::CallThreadConfig;
    use crate::runtime::dial::OutboundDialConfig;
    use crate::runtime::engine::RuntimeEngineConfig;
    use crate::runtime::shutdown::ShutdownAction;
    use crate::sip::headers::retry_after::RetryAfter;
    use crate::sip::parser::uri;

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn service(maximum: usize, notifications: usize) -> RuntimeService {
        RuntimeService::new(RuntimeServiceConfig::new(
            RuntimeEngineConfig::new(
                maximum,
                RetryAfter::new(3),
                CallThreadConfig::default(),
                Duration::from_secs(1),
            ),
            notifications,
        ))
        .unwrap_or_else(|_| panic!("service"))
    }

    fn dial_config(destination: SocketAddr) -> OutboundDialConfig {
        let caller =
            uri::parse_str("sip:runtime@example.invalid").unwrap_or_else(|_| panic!("caller"));
        let target =
            uri::parse_str("sip:1000@example.invalid").unwrap_or_else(|_| panic!("target"));
        OutboundDialConfig::new(caller, target, localhost(0), destination)
            .unwrap_or_else(|_| panic!("dial config"))
            .with_inactive_pcmu_sdp()
    }

    fn header_value<'a>(message: &'a str, name: &str) -> &'a str {
        message
            .split("\r\n")
            .find_map(|line| line.strip_prefix(name))
            .map_or_else(|| panic!("missing header"), str::trim)
    }

    fn failure_response(invite: &str) -> String {
        format!(
            "SIP/2.0 486 Busy Here\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag=remote\r\n\
             Call-ID: {}\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n",
            header_value(invite, "Via:"),
            header_value(invite, "From:"),
            header_value(invite, "To:"),
            header_value(invite, "Call-ID:"),
            header_value(invite, "CSeq:")
        )
    }

    #[test]
    fn full_observer_queue_never_loses_queryable_terminal_outcome() {
        let peer = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("peer"));
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("timeout"));
        let remote = peer.local_addr().unwrap_or_else(|_| panic!("remote"));
        let mut service = service(1, 1);
        let dialed = service
            .dial(7, dial_config(remote))
            .unwrap_or_else(|_| panic!("dial"));
        let mut buffer = [0_u8; 4_096];
        let (length, source) = peer
            .recv_from(&mut buffer)
            .unwrap_or_else(|_| panic!("INVITE"));
        let invite = std::str::from_utf8(&buffer[..length]).unwrap_or_else(|_| panic!("UTF-8"));
        peer.send_to(failure_response(invite).as_bytes(), source)
            .unwrap_or_else(|_| panic!("486"));
        let _ = peer
            .recv_from(&mut buffer)
            .unwrap_or_else(|_| panic!("ACK"));

        for _ in 0..100 {
            let report = service.pump().unwrap_or_else(|_| panic!("pump"));
            if report.calls_completed == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(service.active_calls(), 0);
        let outcome = service
            .terminal_outcome(7)
            .unwrap_or_else(|| panic!("outcome"));
        assert_eq!(outcome.token(), dialed.token());
        assert_eq!(outcome.exit().runtime().last_sip_status, Some(486));
        assert!(service.notification_snapshot().dropped >= 1);
        let notification = service
            .next_notification()
            .unwrap_or_else(|| panic!("notification"));
        assert!(matches!(
            notification.kind(),
            RuntimeNotificationKind::CallExited(_)
        ));
        assert!(matches!(
            service.snapshot(7),
            Some(RuntimeCallSnapshot::Terminal(_))
        ));
    }

    #[test]
    fn unacknowledged_outcome_blocks_reuse_until_explicit_take() {
        let peer = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("peer"));
        let remote = peer.local_addr().unwrap_or_else(|_| panic!("remote"));
        let mut service = service(1, 8);
        let _ = service
            .dial(1, dial_config(remote))
            .unwrap_or_else(|_| panic!("dial"));
        service
            .begin_shutdown(Duration::ZERO)
            .unwrap_or_else(|_| panic!("shutdown"));
        let progress = service
            .poll_shutdown(Duration::from_secs(1))
            .unwrap_or_else(|_| panic!("force"));
        assert!(matches!(
            progress.action,
            ShutdownAction::ForceTerminate { active_calls: 1 }
        ));
        assert_eq!(service.retained_outcomes(), 1);
        assert!(matches!(
            service.dial(2, dial_config(remote)),
            Err(RuntimeServiceError::OutcomeCapacity | RuntimeServiceError::Engine(_))
        ));
        assert!(service.take_terminal_outcome(1).is_some());
        assert_eq!(service.retained_outcomes(), 0);
    }

    #[test]
    fn configuration_and_debug_are_bounded_and_redacted() {
        let config = RuntimeServiceConfig::new(
            RuntimeEngineConfig::new(
                1,
                RetryAfter::new(3),
                CallThreadConfig::default(),
                Duration::from_secs(1),
            ),
            0,
        );
        assert!(matches!(
            RuntimeService::new(config),
            Err(RuntimeServiceError::InvalidNotificationCapacity)
        ));
        let debug = format!("{:?}", service(1, 1));
        assert!(debug.contains("active_calls"));
        assert!(!debug.contains("127.0.0.1"));
    }
}
