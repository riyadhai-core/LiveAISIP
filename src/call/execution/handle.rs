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

//! External generation-fenced capability for one live call thread.

use std::error::Error as StdError;
use std::fmt;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::ThreadId;
use std::time::Duration;

use super::reactor::CallReactorNotifier;
use super::runtime::CallMessage;
use super::thread::{CallExit, CallThread, CallThreadError, SpawnedCall};
use crate::call::model::events::{CallAction, CallEvent, CallReference};

/// Generation-fenced identity for one native call runtime.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CallToken {
    call_id: u64,
    generation: u64,
}

impl CallToken {
    pub(crate) const fn new(call_id: u64, generation: u64) -> Self {
        Self {
            call_id,
            generation,
        }
    }

    /// Returns a generation-fenced reference for attended transfer.
    #[must_use]
    pub const fn reference(self) -> CallReference {
        CallReference::new(self.call_id, self.generation)
    }

    /// Returns application-assigned opaque call identity.
    #[must_use]
    pub const fn call_id(self) -> u64 {
        self.call_id
    }

    /// Returns the nonreused runtime generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Bounded queue counters safe for low-cardinality observability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CallQueueSnapshot {
    /// Fixed queue capacity.
    pub capacity: usize,
    /// Currently reserved/enqueued messages.
    pub depth: usize,
    /// Maximum observed occupancy.
    pub high_water_mark: usize,
    /// Messages rejected because the queue was full.
    pub rejected_full: u64,
    /// Messages rejected after the receiver closed.
    pub rejected_closed: u64,
    /// Accepted messages whose redundant wake notification failed.
    pub wake_failures: u64,
}

pub(crate) struct QueueMetrics {
    capacity: usize,
    depth: AtomicUsize,
    high_water: AtomicUsize,
    rejected_full: AtomicU64,
    rejected_closed: AtomicU64,
    wake_failures: AtomicU64,
}

impl QueueMetrics {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            depth: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            rejected_full: AtomicU64::new(0),
            rejected_closed: AtomicU64::new(0),
            wake_failures: AtomicU64::new(0),
        }
    }

    fn reserve(&self, limit: usize) -> bool {
        let reserved = self
            .depth
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |depth| {
                (depth < limit).then_some(depth + 1)
            });
        let Ok(previous) = reserved else {
            self.rejected_full.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let depth = previous + 1;
        self.high_water.fetch_max(depth, Ordering::Relaxed);
        true
    }

    fn release(&self) {
        let previous = self.depth.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }

    fn note_closed(&self) {
        self.rejected_closed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> CallQueueSnapshot {
        CallQueueSnapshot {
            capacity: self.capacity,
            depth: self.depth.load(Ordering::Acquire),
            high_water_mark: self.high_water.load(Ordering::Relaxed),
            rejected_full: self.rejected_full.load(Ordering::Relaxed),
            rejected_closed: self.rejected_closed.load(Ordering::Relaxed),
            wake_failures: self.wake_failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone)]
pub(crate) struct CommandSender {
    sender: SyncSender<CallMessage>,
    metrics: Arc<QueueMetrics>,
    notifier: Option<CallReactorNotifier>,
}

impl CommandSender {
    pub(crate) fn new(sender: SyncSender<CallMessage>, metrics: Arc<QueueMetrics>) -> Self {
        Self {
            sender,
            metrics,
            notifier: None,
        }
    }

    pub(crate) fn with_notifier(mut self, notifier: CallReactorNotifier) -> Self {
        self.notifier = Some(notifier);
        self
    }

    fn try_send(&self, message: CallMessage) -> Result<(), CallSubmitError> {
        let limit = if matches!(message, CallMessage::Shutdown) {
            self.metrics.capacity
        } else {
            self.metrics.capacity.saturating_sub(1)
        };
        if !self.metrics.reserve(limit) {
            return Err(CallSubmitError::new(CallSubmitErrorKind::Full, message));
        }
        match self.sender.try_send(message) {
            Ok(()) => {
                if self
                    .notifier
                    .as_ref()
                    .is_some_and(|notifier| notifier.notify().is_err())
                {
                    self.metrics.wake_failures.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }
            Err(TrySendError::Full(message)) => {
                self.metrics.release();
                self.metrics.rejected_full.fetch_add(1, Ordering::Relaxed);
                Err(CallSubmitError::new(CallSubmitErrorKind::Full, message))
            }
            Err(TrySendError::Disconnected(message)) => {
                self.metrics.release();
                self.metrics.note_closed();
                Err(CallSubmitError::new(CallSubmitErrorKind::Closed, message))
            }
        }
    }
}

pub(crate) struct CommandReceiver {
    receiver: Receiver<CallMessage>,
    metrics: Arc<QueueMetrics>,
}

impl CommandReceiver {
    pub(crate) fn new(receiver: Receiver<CallMessage>, metrics: Arc<QueueMetrics>) -> Self {
        Self { receiver, metrics }
    }

    pub(crate) fn try_recv(&self) -> Result<Option<CallMessage>, TryRecvError> {
        match self.receiver.try_recv() {
            Ok(message) => {
                self.metrics.release();
                Ok(Some(message))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(TryRecvError::Disconnected),
        }
    }
}

pub(crate) struct ActionSender {
    sender: SyncSender<Vec<CallAction>>,
    metrics: Arc<QueueMetrics>,
}

impl ActionSender {
    pub(crate) fn new(sender: SyncSender<Vec<CallAction>>, metrics: Arc<QueueMetrics>) -> Self {
        Self { sender, metrics }
    }

    pub(crate) fn try_send(&self, actions: Vec<CallAction>) -> Result<(), Vec<CallAction>> {
        if actions.is_empty() {
            return Ok(());
        }
        if !self.metrics.reserve(self.metrics.capacity) {
            return Err(actions);
        }
        match self.sender.try_send(actions) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(actions)) => {
                self.metrics.release();
                self.metrics.rejected_full.fetch_add(1, Ordering::Relaxed);
                Err(actions)
            }
            Err(TrySendError::Disconnected(actions)) => {
                self.metrics.release();
                self.metrics.note_closed();
                Err(actions)
            }
        }
    }
}

pub(crate) struct ActionReceiver {
    receiver: Receiver<Vec<CallAction>>,
    metrics: Arc<QueueMetrics>,
}

impl ActionReceiver {
    pub(crate) fn new(receiver: Receiver<Vec<CallAction>>, metrics: Arc<QueueMetrics>) -> Self {
        Self { receiver, metrics }
    }

    fn try_recv(&self) -> Result<Option<Vec<CallAction>>, CallActionReceiveError> {
        match self.receiver.try_recv() {
            Ok(actions) => {
                self.metrics.release();
                Ok(Some(actions))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(CallActionReceiveError::Closed),
        }
    }

    fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<Vec<CallAction>>, CallActionReceiveError> {
        match self.receiver.recv_timeout(timeout) {
            Ok(actions) => {
                self.metrics.release();
                Ok(Some(actions))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(CallActionReceiveError::Closed)
            }
        }
    }
}

const STATUS_STARTING: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_COMPLETED: u8 = 2;
const STATUS_FAILED: u8 = 3;
const STATUS_PANICKED: u8 = 4;

pub(crate) struct SharedCallStatus {
    phase: AtomicU8,
    owner: OnceLock<ThreadId>,
}

impl SharedCallStatus {
    pub(crate) const fn new() -> Self {
        Self {
            phase: AtomicU8::new(STATUS_STARTING),
            owner: OnceLock::new(),
        }
    }

    pub(crate) fn mark_running(&self, owner: ThreadId) {
        let _ = self.owner.set(owner);
        self.phase.store(STATUS_RUNNING, Ordering::Release);
    }

    pub(crate) fn mark_completed(&self) {
        self.phase.store(STATUS_COMPLETED, Ordering::Release);
    }

    pub(crate) fn mark_failed(&self) {
        self.phase.store(STATUS_FAILED, Ordering::Release);
    }

    pub(crate) fn mark_panicked(&self) {
        self.phase.store(STATUS_PANICKED, Ordering::Release);
    }

    fn snapshot(&self) -> (CallThreadPhase, Option<ThreadId>) {
        let phase = match self.phase.load(Ordering::Acquire) {
            STATUS_STARTING => CallThreadPhase::Starting,
            STATUS_RUNNING => CallThreadPhase::Running,
            STATUS_COMPLETED => CallThreadPhase::Completed,
            STATUS_PANICKED => CallThreadPhase::Panicked,
            _ => CallThreadPhase::Failed,
        };
        (phase, self.owner.get().copied())
    }
}

/// Externally observable native call-thread phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallThreadPhase {
    /// Native thread was requested but has not entered its run loop.
    Starting,
    /// Native owner thread is processing the call.
    Running,
    /// Call ended and cleanup completed normally.
    Completed,
    /// A normal runtime or required external-effect failure ended the call.
    Failed,
    /// An unexpected Rust panic was contained at the thread boundary.
    Panicked,
}

impl CallThreadPhase {
    /// Returns whether the call thread has reached a terminal phase.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Panicked)
    }
}

/// Safe immutable status for one call capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallStatusSnapshot {
    /// Current native-thread phase.
    pub phase: CallThreadPhase,
    /// Native owner identity after thread entry.
    pub owner_thread: Option<ThreadId>,
    /// Inbound bounded mailbox counters.
    pub commands: CallQueueSnapshot,
    /// Outbound bounded action queue counters.
    pub actions: CallQueueSnapshot,
}

/// The only external capability for controlling one live call.
#[derive(Clone)]
pub struct CallHandle {
    token: CallToken,
    commands: CommandSender,
    command_metrics: Arc<QueueMetrics>,
    actions: Arc<Mutex<ActionReceiver>>,
    action_metrics: Arc<QueueMetrics>,
    status: Arc<SharedCallStatus>,
    thread: Arc<Mutex<CallThread>>,
}

impl CallHandle {
    pub(crate) fn from_spawned(token: CallToken, spawned: SpawnedCall) -> Self {
        Self {
            token,
            commands: spawned.commands,
            command_metrics: spawned.command_metrics,
            actions: Arc::new(Mutex::new(spawned.actions)),
            action_metrics: spawned.action_metrics,
            status: spawned.status,
            thread: Arc::new(Mutex::new(spawned.thread)),
        }
    }

    /// Returns generation-fenced identity.
    #[must_use]
    pub const fn token(&self) -> CallToken {
        self.token
    }

    /// Enqueues one complete call-thread message without blocking.
    ///
    /// # Errors
    ///
    /// Returns the unsent message when the bounded mailbox is full or closed.
    pub fn submit(&self, message: CallMessage) -> Result<(), CallSubmitError> {
        self.commands.try_send(message)
    }

    /// Enqueues one SIP/control call event without blocking.
    ///
    /// # Errors
    ///
    /// Preserves bounded mailbox rejection.
    pub fn submit_event(&self, event: CallEvent) -> Result<(), CallSubmitError> {
        self.submit(CallMessage::Event(event))
    }

    /// Requests idempotent graceful shutdown without blocking.
    ///
    /// # Errors
    ///
    /// Preserves bounded mailbox rejection.
    pub fn request_shutdown(&self) -> Result<(), CallSubmitError> {
        self.submit(CallMessage::Shutdown)
    }

    /// Tries to receive one ordered action batch emitted by the owner thread.
    ///
    /// For a runtime with call-owned signaling installed, this is a bounded
    /// best-effort observer stream: protocol effects execute before publication
    /// and a slow observer may miss batches. Queue metrics expose such drops.
    /// Without installed signaling, the stream is the strict external effect
    /// boundary and queue rejection terminates that incomplete call runtime.
    ///
    /// # Errors
    ///
    /// Reports closure after the thread drops its output sender.
    pub fn try_recv_actions(&self) -> Result<Option<Vec<CallAction>>, CallActionReceiveError> {
        recover_lock(&self.actions).try_recv()
    }

    /// Waits for one action batch for at most `timeout`.
    ///
    /// # Errors
    ///
    /// Reports closure after the thread drops its output sender.
    pub fn recv_actions_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<Vec<CallAction>>, CallActionReceiveError> {
        recover_lock(&self.actions).recv_timeout(timeout)
    }

    /// Returns safe status without accessing mutable call state.
    #[must_use]
    pub fn status(&self) -> CallStatusSnapshot {
        let (phase, owner_thread) = self.status.snapshot();
        CallStatusSnapshot {
            phase,
            owner_thread,
            commands: self.command_metrics.snapshot(),
            actions: self.action_metrics.snapshot(),
        }
    }

    /// Joins the native thread exactly once.
    ///
    /// # Errors
    ///
    /// Reports an already joined thread or an uncontained thread panic.
    pub fn join(&self) -> Result<CallExit, CallThreadError> {
        recover_lock(&self.thread).join()
    }
}

impl fmt::Debug for CallHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallHandle")
            .field("generation", &self.token.generation)
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

/// Bounded call submission rejection class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallSubmitErrorKind {
    /// Fixed mailbox capacity was occupied.
    Full,
    /// The call thread had closed its receiver.
    Closed,
}

/// Failed nonblocking call submission preserving the unsent message.
pub struct CallSubmitError {
    kind: CallSubmitErrorKind,
    message: CallMessage,
}

impl CallSubmitError {
    fn new(kind: CallSubmitErrorKind, message: CallMessage) -> Self {
        Self { kind, message }
    }

    /// Returns the stable rejection class.
    #[must_use]
    pub const fn kind(&self) -> CallSubmitErrorKind {
        self.kind
    }

    /// Recovers ownership of the unsent message.
    #[must_use]
    pub fn into_message(self) -> CallMessage {
        self.message
    }
}

impl fmt::Debug for CallSubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallSubmitError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for CallSubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("call mailbox rejected message")
    }
}

impl StdError for CallSubmitError {}

/// Outbound call-action queue failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallActionReceiveError {
    /// Owner thread closed the queue after terminal cleanup.
    Closed,
}

impl fmt::Display for CallActionReceiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("call action queue is closed")
    }
}

impl StdError for CallActionReceiveError {}

fn recover_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::mpsc;

    use super::{CommandSender, QueueMetrics};
    use crate::call::execution::runtime::CallMessage;
    use crate::call::model::events::{CallCommand, CallEvent};

    #[test]
    fn command_queue_reserves_shutdown_capacity_and_counts_overflow() {
        let (raw_sender, receiver) = mpsc::sync_channel(2);
        let metrics = Arc::new(QueueMetrics::new(2));
        let sender = CommandSender::new(raw_sender, Arc::clone(&metrics));
        assert!(
            sender
                .try_send(CallMessage::Event(CallEvent::Command(CallCommand::Start)))
                .is_ok()
        );
        assert!(
            sender
                .try_send(CallMessage::Event(CallEvent::TransportFailed))
                .is_err()
        );
        assert!(sender.try_send(CallMessage::Shutdown).is_ok());
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.depth, 2);
        assert_eq!(snapshot.high_water_mark, 2);
        assert_eq!(snapshot.rejected_full, 1);
        drop(receiver);
    }
}
