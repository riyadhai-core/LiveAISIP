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

//! Dedicated native OS-thread execution wrapper for one [`super::runtime::CallRuntime`].

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};

use crate::util::time::MonotonicClock;

use super::handle::{
    ActionReceiver, ActionSender, CallQueueSnapshot, CallToken, CommandReceiver, CommandSender,
    QueueMetrics, SharedCallStatus,
};
use super::runtime::{CallRuntime, CallRuntimeDiagnostics};

/// Default inbound messages queued per call thread.
pub const DEFAULT_CALL_MAILBOX_CAPACITY: usize = 256;
/// Default action batches waiting for the external signaling driver.
pub const DEFAULT_CALL_ACTION_CAPACITY: usize = 256;
/// Hard per-call queue capacity ceiling.
pub const MAX_CALL_QUEUE_CAPACITY: usize = 65_536;
/// Conservative native stack reserved per active call.
pub const DEFAULT_CALL_THREAD_STACK_BYTES: usize = 512 * 1_024;
/// Smallest supported per-call native stack.
pub const MIN_CALL_THREAD_STACK_BYTES: usize = 128 * 1_024;
/// Largest supported per-call native stack.
pub const MAX_CALL_THREAD_STACK_BYTES: usize = 8 * 1_024 * 1_024;

/// Validated native call-thread resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallThreadConfig {
    mailbox_capacity: usize,
    action_capacity: usize,
    stack_size: usize,
}

impl CallThreadConfig {
    /// Validates bounded queues and native stack size.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive queues and stack sizes outside hard limits.
    pub const fn new(
        mailbox_capacity: usize,
        action_capacity: usize,
        stack_size: usize,
    ) -> Result<Self, CallThreadError> {
        if mailbox_capacity < 2 || mailbox_capacity > MAX_CALL_QUEUE_CAPACITY {
            return Err(CallThreadError::InvalidMailboxCapacity);
        }
        if action_capacity == 0 || action_capacity > MAX_CALL_QUEUE_CAPACITY {
            return Err(CallThreadError::InvalidActionCapacity);
        }
        if stack_size < MIN_CALL_THREAD_STACK_BYTES || stack_size > MAX_CALL_THREAD_STACK_BYTES {
            return Err(CallThreadError::InvalidStackSize);
        }
        Ok(Self {
            mailbox_capacity,
            action_capacity,
            stack_size,
        })
    }

    /// Returns fixed inbound mailbox capacity.
    #[must_use]
    pub const fn mailbox_capacity(self) -> usize {
        self.mailbox_capacity
    }

    /// Returns fixed outbound action capacity.
    #[must_use]
    pub const fn action_capacity(self) -> usize {
        self.action_capacity
    }

    /// Returns native stack reservation in bytes.
    #[must_use]
    pub const fn stack_size(self) -> usize {
        self.stack_size
    }
}

impl Default for CallThreadConfig {
    fn default() -> Self {
        Self {
            mailbox_capacity: DEFAULT_CALL_MAILBOX_CAPACITY,
            action_capacity: DEFAULT_CALL_ACTION_CAPACITY,
            stack_size: DEFAULT_CALL_THREAD_STACK_BYTES,
        }
    }
}

/// Terminal native call-thread outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallExitKind {
    /// Call reached terminal protocol state and released resources.
    Completed,
    /// A normal runtime or bounded-queue failure ended only this call.
    Failed,
    /// An unexpected Rust panic was caught at the call-thread boundary.
    Panicked,
}

/// Final privacy-safe native call-thread report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallExit {
    kind: CallExitKind,
    runtime: CallRuntimeDiagnostics,
    commands: CallQueueSnapshot,
    actions: CallQueueSnapshot,
}

impl CallExit {
    /// Returns terminal outcome class.
    #[must_use]
    pub const fn kind(self) -> CallExitKind {
        self.kind
    }

    /// Returns final owner-runtime counters.
    #[must_use]
    pub const fn runtime(self) -> CallRuntimeDiagnostics {
        self.runtime
    }

    /// Returns final inbound mailbox counters.
    #[must_use]
    pub const fn command_queue(self) -> CallQueueSnapshot {
        self.commands
    }

    /// Returns final outbound action queue counters.
    #[must_use]
    pub const fn action_queue(self) -> CallQueueSnapshot {
        self.actions
    }
}

/// Native thread join owner. It never exposes the call runtime.
pub struct CallThread {
    join: Option<JoinHandle<CallExit>>,
}

pub(crate) struct SpawnedCall {
    pub(crate) thread: CallThread,
    pub(crate) commands: CommandSender,
    pub(crate) command_metrics: Arc<QueueMetrics>,
    pub(crate) actions: ActionReceiver,
    pub(crate) action_metrics: Arc<QueueMetrics>,
    pub(crate) status: Arc<SharedCallStatus>,
}

impl CallThread {
    /// Spawns exactly one dedicated native owner for `runtime`.
    ///
    /// # Errors
    ///
    /// Preserves native thread creation failure. Captured runtime resources are
    /// dropped automatically if the OS refuses to create the thread.
    pub(crate) fn spawn(
        token: CallToken,
        runtime: CallRuntime,
        config: CallThreadConfig,
    ) -> Result<SpawnedCall, CallThreadError> {
        Self::spawn_with(token, runtime, config, |builder, entry| {
            builder.spawn(entry)
        })
    }

    fn spawn_with<F>(
        token: CallToken,
        runtime: CallRuntime,
        config: CallThreadConfig,
        spawn: F,
    ) -> Result<SpawnedCall, CallThreadError>
    where
        F: FnOnce(
            thread::Builder,
            Box<dyn FnOnce() -> CallExit + Send>,
        ) -> io::Result<JoinHandle<CallExit>>,
    {
        let (command_tx, command_rx) = mpsc::sync_channel(config.mailbox_capacity);
        let command_metrics = Arc::new(QueueMetrics::new(config.mailbox_capacity));
        let commands = CommandSender::new(command_tx, Arc::clone(&command_metrics));
        let command_receiver = CommandReceiver::new(command_rx, Arc::clone(&command_metrics));

        let (action_tx, action_rx) = mpsc::sync_channel(config.action_capacity);
        let action_metrics = Arc::new(QueueMetrics::new(config.action_capacity));
        let action_sender = ActionSender::new(action_tx, Arc::clone(&action_metrics));
        let actions = ActionReceiver::new(action_rx, Arc::clone(&action_metrics));

        let status = Arc::new(SharedCallStatus::new());
        let thread_status = Arc::clone(&status);
        let exit_commands = Arc::clone(&command_metrics);
        let exit_actions = Arc::clone(&action_metrics);
        let name = format!("liveaisip-call-{:x}", token.generation());
        let builder = thread::Builder::new()
            .name(name)
            .stack_size(config.stack_size);
        let entry: Box<dyn FnOnce() -> CallExit + Send> = Box::new(move || {
            call_thread_entry(
                runtime,
                command_receiver,
                action_sender,
                thread_status,
                exit_commands,
                exit_actions,
            )
        });
        let join = spawn(builder, entry).map_err(CallThreadError::Spawn)?;
        Ok(SpawnedCall {
            thread: Self { join: Some(join) },
            commands,
            command_metrics,
            actions,
            action_metrics,
            status,
        })
    }

    /// Joins once and returns final cleanup evidence.
    ///
    /// # Errors
    ///
    /// Rejects repeated join and reports a panic outside the containment guard.
    pub fn join(&mut self) -> Result<CallExit, CallThreadError> {
        let join = self.join.take().ok_or(CallThreadError::AlreadyJoined)?;
        join.join().map_err(|_| CallThreadError::UncontainedPanic)
    }
}

impl fmt::Debug for CallThread {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallThread")
            .field("join_pending", &self.join.is_some())
            .finish_non_exhaustive()
    }
}

fn call_thread_entry(
    mut runtime: CallRuntime,
    commands: CommandReceiver,
    actions: ActionSender,
    status: Arc<SharedCallStatus>,
    command_metrics: Arc<QueueMetrics>,
    action_metrics: Arc<QueueMetrics>,
) -> CallExit {
    let owner = thread::current().id();
    status.mark_running(owner);
    let clock = MonotonicClock::start();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        runtime.claim_current_thread().map_err(|_| ())?;
        run_call(&mut runtime, &commands, &actions, &clock)
    }));
    let mut kind = match outcome {
        Ok(Ok(())) => CallExitKind::Completed,
        Ok(Err(())) => CallExitKind::Failed,
        Err(_) => CallExitKind::Panicked,
    };
    let cleanup = catch_unwind(AssertUnwindSafe(|| runtime.finish_cleanup()));
    if !matches!(cleanup, Ok(Ok(()))) {
        kind = CallExitKind::Panicked;
    }
    match kind {
        CallExitKind::Completed => status.mark_completed(),
        CallExitKind::Failed => status.mark_failed(),
        CallExitKind::Panicked => status.mark_panicked(),
    }
    let command_snapshot = command_metrics.snapshot();
    let action_snapshot = action_metrics.snapshot();
    drop(commands);
    drop(actions);
    drop(status);
    drop(command_metrics);
    drop(action_metrics);
    CallExit {
        kind,
        runtime: runtime.diagnostics(),
        commands: command_snapshot,
        actions: action_snapshot,
    }
}

fn run_call(
    runtime: &mut CallRuntime,
    commands: &CommandReceiver,
    actions: &ActionSender,
    clock: &MonotonicClock,
) -> Result<(), ()> {
    let mut mailbox_open = true;
    loop {
        let now = clock.now();
        let due = runtime.process_due_deadlines(now).map_err(|_| ())?;
        publish_actions(runtime, actions, due)?;
        if runtime.is_finished() {
            return Ok(());
        }
        let deadline = runtime.next_deadline().map_err(|_| ())?;
        let wait = deadline.map(|at| clock.remaining_until(at));
        let message = if mailbox_open {
            match wait {
                Some(timeout) => match commands.recv_timeout(timeout) {
                    Ok(message) => Some(message),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => {
                        mailbox_open = false;
                        None
                    }
                },
                None => {
                    if let Ok(message) = commands.recv() {
                        Some(message)
                    } else {
                        mailbox_open = false;
                        None
                    }
                }
            }
        } else {
            match wait {
                Some(timeout) if !timeout.is_zero() => thread::park_timeout(timeout),
                None => return Err(()),
                _ => {}
            }
            None
        };
        if let Some(message) = message {
            let produced = runtime.handle(message, clock.now()).map_err(|_| ())?;
            publish_actions(runtime, actions, produced)?;
        } else if !mailbox_open {
            let produced = runtime.begin_shutdown(clock.now()).map_err(|_| ())?;
            publish_actions(runtime, actions, produced)?;
        }
    }
}

fn publish_actions(
    runtime: &CallRuntime,
    actions: &ActionSender,
    produced: Vec<crate::call::model::events::CallAction>,
) -> Result<(), ()> {
    if produced.is_empty() {
        return Ok(());
    }
    if actions.try_send(produced).is_err() && !runtime.actions_are_observational() {
        return Err(());
    }
    Ok(())
}

/// Native call-thread configuration, spawn, or join failure.
pub enum CallThreadError {
    /// Inbound mailbox lacked an event slot plus the reserved shutdown slot,
    /// or exceeded the hard ceiling.
    InvalidMailboxCapacity,
    /// Outbound action capacity was zero or excessive.
    InvalidActionCapacity,
    /// Native stack size was outside validated limits.
    InvalidStackSize,
    /// The operating system refused native thread creation.
    Spawn(io::Error),
    /// Native thread was already joined by another handle clone.
    AlreadyJoined,
    /// Panic escaped the outer containment boundary.
    UncontainedPanic,
}

impl fmt::Debug for CallThreadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallThreadError")
            .field("class", &self.class())
            .finish_non_exhaustive()
    }
}

impl CallThreadError {
    /// Returns stable privacy-safe error classification.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::InvalidMailboxCapacity => "invalid-mailbox-capacity",
            Self::InvalidActionCapacity => "invalid-action-capacity",
            Self::InvalidStackSize => "invalid-stack-size",
            Self::Spawn(_) => "spawn",
            Self::AlreadyJoined => "already-joined",
            Self::UncontainedPanic => "uncontained-panic",
        }
    }
}

impl fmt::Display for CallThreadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "call thread error: {}", self.class())
    }
}

impl StdError for CallThreadError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Spawn(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use super::{CallExitKind, CallThread, CallThreadConfig};
    use crate::call::context::CallContext;
    use crate::call::events::{CallAction, CallCommand, CallEvent};
    use crate::call::handle::{ActionSender, CallHandle, CallThreadPhase, CallToken, QueueMetrics};
    use crate::call::leg::DialogBranchId;
    use crate::call::runtime::{
        CallMessage, CallRuntime, CallRuntimeConfig, DEFAULT_CALL_DEADLINE_CAPACITY,
        DEFAULT_CALL_DIALOG_CAPACITY, DEFAULT_CALL_TRANSACTION_CAPACITY,
    };
    use crate::call::signaling::UdpSignaling;
    use crate::call::state::CallEndReason;
    use crate::rtp::transport::{MediaSocketPair, PortPool, SocketConfig};
    use crate::runtime::admission::{AdmissionController, AdmissionLeaseGroup};
    use crate::sip::headers::retry_after::RetryAfter;
    use crate::sip::transport::udp::UdpConfig;
    use crate::sip::transport::udp_driver::UdpDriverConfig;

    fn runtime(admission: AdmissionLeaseGroup) -> CallRuntime {
        let context = CallContext::new(Duration::ZERO, 32).unwrap_or_else(|_| panic!("context"));
        let config = CallRuntimeConfig::new(
            DEFAULT_CALL_TRANSACTION_CAPACITY,
            DEFAULT_CALL_DIALOG_CAPACITY,
            DEFAULT_CALL_DEADLINE_CAPACITY,
            Duration::from_millis(1),
            false,
        );
        CallRuntime::new(context, admission, config).unwrap_or_else(|_| panic!("runtime"))
    }

    fn spawn(runtime: CallRuntime, generation: u64) -> CallHandle {
        let token = CallToken::new(generation, generation);
        let spawned = CallThread::spawn(token, runtime, CallThreadConfig::default())
            .unwrap_or_else(|_| panic!("spawn"));
        CallHandle::from_spawned(token, spawned)
    }

    #[test]
    fn each_call_has_a_distinct_native_owner_thread() {
        let first = spawn(runtime(AdmissionLeaseGroup::new()), 1);
        let second = spawn(runtime(AdmissionLeaseGroup::new()), 2);
        for _ in 0..1_000 {
            if first.status().owner_thread.is_some() && second.status().owner_thread.is_some() {
                break;
            }
            std::thread::yield_now();
        }
        assert!(first.status().owner_thread.is_some());
        assert!(second.status().owner_thread.is_some());
        assert_ne!(first.status().owner_thread, second.status().owner_thread);
        assert!(first.request_shutdown().is_ok());
        assert!(second.request_shutdown().is_ok());
        assert!(first.join().is_ok());
        assert!(second.join().is_ok());
    }

    #[test]
    fn panic_is_contained_and_releases_admission() {
        let controller = AdmissionController::new(1, RetryAfter::new(1))
            .unwrap_or_else(|_| panic!("controller"));
        let mut leases = AdmissionLeaseGroup::new();
        leases
            .push(controller.try_admit().unwrap_or_else(|_| panic!("lease")))
            .unwrap_or_else(|_| panic!("group"));
        let handle = spawn(runtime(leases), 3);
        assert!(handle.submit(CallMessage::PanicForContainmentTest).is_ok());
        let exit = handle.join().unwrap_or_else(|_| panic!("join"));
        assert_eq!(exit.kind(), CallExitKind::Panicked);
        assert_eq!(handle.status().phase, CallThreadPhase::Panicked);
        assert_eq!(controller.active(), 0);
    }

    #[test]
    fn spawn_failure_unwinds_runtime_resources() {
        let controller = Arc::new(
            AdmissionController::new(1, RetryAfter::new(1))
                .unwrap_or_else(|_| panic!("controller")),
        );
        let mut leases = AdmissionLeaseGroup::new();
        leases
            .push(controller.try_admit().unwrap_or_else(|_| panic!("lease")))
            .unwrap_or_else(|_| panic!("group"));
        let token = CallToken::new(4, 4);
        let result = CallThread::spawn_with(
            token,
            runtime(leases),
            CallThreadConfig::default(),
            |_builder, _entry| Err(io::Error::other("injected spawn failure")),
        );
        assert!(result.is_err());
        assert_eq!(controller.active(), 0);
    }

    #[test]
    fn one_call_failure_does_not_end_another_call() {
        let failed = spawn(runtime(AdmissionLeaseGroup::new()), 5);
        let healthy = spawn(runtime(AdmissionLeaseGroup::new()), 6);
        assert!(failed.submit(CallMessage::PanicForContainmentTest).is_ok());
        assert_eq!(
            failed.join().unwrap_or_else(|_| panic!("join")).kind(),
            CallExitKind::Panicked
        );
        assert!(
            healthy
                .submit(CallMessage::Event(CallEvent::Command(CallCommand::Start)))
                .is_ok()
        );
        assert!(
            healthy
                .recv_actions_timeout(Duration::from_secs(1))
                .is_ok_and(|actions| actions.is_some())
        );
        assert_eq!(healthy.status().phase, CallThreadPhase::Running);
        assert!(healthy.request_shutdown().is_ok());
        assert!(healthy.join().is_ok());
    }

    #[test]
    fn full_observer_queue_cannot_fail_runtime_with_internal_signaling() {
        let peer =
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("peer"));
        let remote = peer.local_addr().unwrap_or_else(|_| panic!("remote"));
        let signaling = UdpSignaling::bind(
            std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            remote,
            UdpDriverConfig::default(),
            UdpConfig::default(),
        )
        .unwrap_or_else(|_| panic!("signaling"));
        let runtime = runtime(AdmissionLeaseGroup::new())
            .with_udp_signaling(signaling)
            .unwrap_or_else(|_| panic!("runtime signaling"));
        let (sender, _receiver) = mpsc::sync_channel(1);
        let metrics = Arc::new(QueueMetrics::new(1));
        let actions = ActionSender::new(sender, Arc::clone(&metrics));
        let batch = || vec![CallAction::Ended(CallEndReason::LocalHangup)];

        assert!(super::publish_actions(&runtime, &actions, batch()).is_ok());
        assert!(super::publish_actions(&runtime, &actions, batch()).is_ok());
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.depth, 1);
        assert_eq!(snapshot.rejected_full, 1);
    }

    #[test]
    fn panic_during_established_call_is_contained() {
        let handle = spawn(runtime(AdmissionLeaseGroup::new()), 7);
        assert!(
            handle
                .submit(CallMessage::Event(CallEvent::Command(CallCommand::Start)))
                .is_ok()
        );
        let _ = handle.recv_actions_timeout(Duration::from_secs(1));
        let branch = DialogBranchId::new("established").unwrap_or_else(|_| panic!("branch"));
        assert!(
            handle
                .submit(CallMessage::Event(CallEvent::InviteAccepted { branch }))
                .is_ok()
        );
        let _ = handle.recv_actions_timeout(Duration::from_secs(1));
        assert!(handle.submit(CallMessage::PanicForContainmentTest).is_ok());
        assert_eq!(
            handle.join().unwrap_or_else(|_| panic!("join")).kind(),
            CallExitKind::Panicked
        );
    }

    #[test]
    fn rtp_port_lease_and_sockets_release_on_thread_exit() {
        let mut selected = None;
        for port in (42_000_u16..60_000).step_by(2) {
            let pool = PortPool::new(port, port).unwrap_or_else(|_| panic!("pool"));
            let lease = pool.allocate().unwrap_or_else(|| panic!("lease"));
            if let Ok(sockets) = MediaSocketPair::bind(
                lease,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                SocketConfig::default(),
            ) {
                selected = Some((pool, sockets));
                break;
            }
        }
        let (pool, sockets) = selected.unwrap_or_else(|| panic!("free RTP pair"));
        let runtime = runtime(AdmissionLeaseGroup::new())
            .with_media_sockets(sockets)
            .unwrap_or_else(|_| panic!("install sockets"));
        let handle = spawn(runtime, 8);
        assert_eq!(pool.in_use(), 1);
        assert!(handle.request_shutdown().is_ok());
        assert!(handle.join().is_ok());
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn sequential_call_thread_stress_leaks_no_threads() {
        for generation in 10..1_010 {
            let handle = spawn(runtime(AdmissionLeaseGroup::new()), generation);
            assert!(handle.request_shutdown().is_ok());
            assert_eq!(
                handle.join().unwrap_or_else(|_| panic!("join")).kind(),
                CallExitKind::Completed
            );
        }
    }

    #[test]
    fn simultaneous_call_threads_have_unique_owners_and_drain() {
        let handles: Vec<_> = (2_000..2_064)
            .map(|generation| spawn(runtime(AdmissionLeaseGroup::new()), generation))
            .collect();
        let mut owners = HashSet::new();
        for handle in &handles {
            for _ in 0..1_000 {
                if handle.status().owner_thread.is_some() {
                    break;
                }
                std::thread::yield_now();
            }
            owners.insert(
                handle
                    .status()
                    .owner_thread
                    .unwrap_or_else(|| panic!("owner")),
            );
        }
        assert_eq!(owners.len(), handles.len());
        for handle in &handles {
            assert!(handle.request_shutdown().is_ok());
        }
        for handle in handles {
            assert!(handle.join().is_ok());
        }
    }
}
