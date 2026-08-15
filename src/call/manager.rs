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

//! Bounded registry of external call capabilities.
//!
//! The manager never stores or exposes mutable call internals. Every entry is
//! only a [`CallHandle`](super::handle::CallHandle); the dedicated native call
//! thread exclusively owns [`CallRuntime`](super::runtime::CallRuntime).

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use super::events::{CallAction, CallEvent};
use super::handle::{CallActionReceiveError, CallHandle, CallSubmitErrorKind, CallToken};
use super::runtime::{CallMessage, CallRuntime};
use super::thread::{CallExit, CallThread, CallThreadConfig, CallThreadError};
use crate::util::id::IdGenerator;

/// Maximum calls configurable in one registry.
pub const MAX_CALL_MANAGER_CAPACITY: usize = 1_000_000;

/// Handle-only active call registry.
pub struct CallManager {
    calls: HashMap<u64, CallHandle>,
    capacity: usize,
    generations: IdGenerator,
    accepting: bool,
    thread_config: CallThreadConfig,
}

impl CallManager {
    /// Creates a bounded registry with default call-thread resources.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive capacity or allocation failure.
    pub fn new(capacity: usize) -> Result<Self, CallManagerError> {
        Self::with_thread_config(capacity, CallThreadConfig::default())
    }

    /// Creates a registry with explicit native stack and mailbox capacities.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive capacity or allocation failure.
    pub fn with_thread_config(
        capacity: usize,
        thread_config: CallThreadConfig,
    ) -> Result<Self, CallManagerError> {
        if capacity == 0 || capacity > MAX_CALL_MANAGER_CAPACITY {
            return Err(CallManagerError::InvalidCapacity);
        }
        let mut calls = HashMap::new();
        calls
            .try_reserve(capacity.min(1_024))
            .map_err(|_| CallManagerError::AllocationFailed)?;
        Ok(Self {
            calls,
            capacity,
            generations: IdGenerator::new(),
            accepting: true,
            thread_config,
        })
    }

    /// Moves one fully allocated runtime into exactly one dedicated OS thread.
    ///
    /// Call validation, admission acquisition, and call-local allocation must
    /// already have succeeded before this boundary. Registry capacity is
    /// reserved before spawn, so successful thread creation cannot be followed
    /// by a fallible insertion allocation.
    ///
    /// # Errors
    ///
    /// Rejects shutdown, duplicate identity, capacity/generation exhaustion,
    /// allocation failure, or native thread creation failure.
    pub fn spawn(
        &mut self,
        call_id: u64,
        runtime: CallRuntime,
    ) -> Result<CallToken, CallManagerError> {
        if !self.accepting {
            return Err(CallManagerError::ShuttingDown);
        }
        if self.calls.contains_key(&call_id) {
            return Err(CallManagerError::DuplicateCall);
        }
        if self.calls.len() >= self.capacity {
            return Err(CallManagerError::AtCapacity);
        }
        self.calls
            .try_reserve(1)
            .map_err(|_| CallManagerError::AllocationFailed)?;
        let generation = self
            .generations
            .allocate()
            .map_err(|_| CallManagerError::GenerationExhausted)?
            .get();
        let token = CallToken::new(call_id, generation);
        let spawned = CallThread::spawn(token, runtime, self.thread_config)
            .map_err(CallManagerError::Thread)?;
        let handle = CallHandle::from_spawned(token, spawned);
        self.calls.insert(call_id, handle);
        Ok(token)
    }

    /// Routes one event through the bounded call mailbox.
    ///
    /// # Errors
    ///
    /// Rejects unknown/stale calls, full mailbox, or closed owner thread.
    pub fn submit(&self, token: CallToken, event: CallEvent) -> Result<(), CallManagerError> {
        self.submit_message(token, CallMessage::Event(event))
    }

    /// Routes one complete message through the bounded call mailbox.
    ///
    /// # Errors
    ///
    /// Rejects unknown/stale calls, full mailbox, or closed owner thread.
    pub fn submit_message(
        &self,
        token: CallToken,
        message: CallMessage,
    ) -> Result<(), CallManagerError> {
        self.entry(token)?
            .submit(message)
            .map_err(|error| match error.kind() {
                CallSubmitErrorKind::Full => CallManagerError::MailboxFull,
                CallSubmitErrorKind::Closed => CallManagerError::CallClosed,
            })
    }

    /// Tries to receive one action batch already produced by the call thread.
    ///
    /// `now` is retained for source compatibility; all mutation and clock
    /// evaluation now occur inside the owner thread.
    ///
    /// # Errors
    ///
    /// Rejects unknown/stale calls or a closed action queue.
    pub fn process_next(
        &self,
        token: CallToken,
        _now: Duration,
    ) -> Result<Option<Vec<CallAction>>, CallManagerError> {
        self.entry(token)?
            .try_recv_actions()
            .map_err(|CallActionReceiveError::Closed| CallManagerError::CallClosed)
    }

    /// Waits for one owner-produced action batch for at most `timeout`.
    ///
    /// # Errors
    ///
    /// Rejects unknown/stale calls or a closed action queue.
    pub fn receive_actions(
        &self,
        token: CallToken,
        timeout: Duration,
    ) -> Result<Option<Vec<CallAction>>, CallManagerError> {
        self.entry(token)?
            .recv_actions_timeout(timeout)
            .map_err(|CallActionReceiveError::Closed| CallManagerError::CallClosed)
    }

    /// Returns a cloned external capability without exposing runtime state.
    ///
    /// # Errors
    ///
    /// Rejects unknown or stale generation tokens.
    pub fn handle(&self, token: CallToken) -> Result<CallHandle, CallManagerError> {
        Ok(self.entry(token)?.clone())
    }

    /// Requests shutdown, removes, and joins one exact call generation.
    ///
    /// The registry entry is removed before joining, so no manager collection
    /// mutation is held across the native wait.
    ///
    /// # Errors
    ///
    /// Rejects unknown/stale calls or native join failure.
    pub fn remove(&mut self, token: CallToken) -> Result<CallExit, CallManagerError> {
        self.verify(token)?;
        let handle = self
            .calls
            .remove(&token.call_id())
            .ok_or(CallManagerError::UnknownCall)?;
        let _ = handle.request_shutdown();
        handle.join().map_err(CallManagerError::Thread)
    }

    /// Joins every terminal call and returns the number reaped.
    ///
    /// # Errors
    ///
    /// Preserves native join failure after removing the affected entry.
    pub fn reap_finished(&mut self) -> Result<usize, CallManagerError> {
        let mut completed = Vec::new();
        completed
            .try_reserve(self.calls.len())
            .map_err(|_| CallManagerError::AllocationFailed)?;
        completed.extend(
            self.calls
                .iter()
                .filter_map(|(id, handle)| handle.status().phase.is_terminal().then_some(*id)),
        );
        let mut reaped = 0;
        for id in completed {
            let handle = self
                .calls
                .remove(&id)
                .ok_or(CallManagerError::UnknownCall)?;
            handle.join().map_err(CallManagerError::Thread)?;
            reaped += 1;
        }
        Ok(reaped)
    }

    /// Stops admission, requests every call to drain, clears the registry, and
    /// joins all native call threads.
    ///
    /// # Errors
    ///
    /// Preserves native join failure after all calls have been signaled.
    pub fn shutdown_all(&mut self) -> Result<Vec<CallExit>, CallManagerError> {
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(self.calls.len())
            .map_err(|_| CallManagerError::AllocationFailed)?;
        let mut exits = Vec::new();
        exits
            .try_reserve_exact(self.calls.len())
            .map_err(|_| CallManagerError::AllocationFailed)?;
        self.accepting = false;
        for handle in self.calls.values() {
            let _ = handle.request_shutdown();
        }
        handles.extend(self.calls.drain().map(|(_, handle)| handle));
        let mut first_error = None;
        for handle in handles {
            match handle.join() {
                Ok(exit) => exits.push(exit),
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if let Some(error) = first_error {
            return Err(CallManagerError::Thread(error));
        }
        Ok(exits)
    }

    /// Stops new call admission while existing owner threads continue.
    pub const fn begin_shutdown(&mut self) {
        self.accepting = false;
    }

    /// Returns active registered call count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.calls.len()
    }

    /// Returns whether no call handles remain.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }

    fn entry(&self, token: CallToken) -> Result<&CallHandle, CallManagerError> {
        self.verify(token)?;
        self.calls
            .get(&token.call_id())
            .ok_or(CallManagerError::UnknownCall)
    }

    fn verify(&self, token: CallToken) -> Result<(), CallManagerError> {
        let handle = self
            .calls
            .get(&token.call_id())
            .ok_or(CallManagerError::UnknownCall)?;
        if handle.token().generation() != token.generation() {
            return Err(CallManagerError::StaleToken);
        }
        Ok(())
    }
}

impl fmt::Debug for CallManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let terminal = self
            .calls
            .values()
            .filter(|handle| handle.status().phase.is_terminal())
            .count();
        formatter
            .debug_struct("CallManager")
            .field("capacity", &self.capacity)
            .field("active_calls", &self.calls.len())
            .field("terminal_calls", &terminal)
            .field("accepting", &self.accepting)
            .finish_non_exhaustive()
    }
}

/// Call registry, mailbox, spawn, or join failure.
pub enum CallManagerError {
    /// Capacity setting was unsafe.
    InvalidCapacity,
    /// Registry/output allocation failed.
    AllocationFailed,
    /// Registry stopped new admission.
    ShuttingDown,
    /// Call ID is already active.
    DuplicateCall,
    /// Active call capacity was reached.
    AtCapacity,
    /// Generation counter cannot safely continue.
    GenerationExhausted,
    /// No active handle has this call ID.
    UnknownCall,
    /// Token belongs to an older native call generation.
    StaleToken,
    /// Bounded inbound mailbox rejected an event.
    MailboxFull,
    /// Native call/action channel is closed.
    CallClosed,
    /// Native thread configuration, spawn, or join failed.
    Thread(CallThreadError),
}

impl fmt::Debug for CallManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallManagerError")
            .field("class", &self.class())
            .finish_non_exhaustive()
    }
}

impl CallManagerError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::InvalidCapacity => "invalid-capacity",
            Self::AllocationFailed => "allocation-failed",
            Self::ShuttingDown => "shutting-down",
            Self::DuplicateCall => "duplicate-call",
            Self::AtCapacity => "at-capacity",
            Self::GenerationExhausted => "generation-exhausted",
            Self::UnknownCall => "unknown-call",
            Self::StaleToken => "stale-token",
            Self::MailboxFull => "mailbox-full",
            Self::CallClosed => "call-closed",
            Self::Thread(_) => "thread",
        }
    }
}

impl fmt::Display for CallManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "call manager error: {}", self.class())
    }
}

impl StdError for CallManagerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Thread(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CallManager, CallManagerError};
    use crate::call::context::CallContext;
    use crate::call::events::{CallAction, CallCommand, CallEvent};
    use crate::call::handle::CallThreadPhase;
    use crate::call::runtime::{
        CallRuntime, CallRuntimeConfig, DEFAULT_CALL_DEADLINE_CAPACITY,
        DEFAULT_CALL_DIALOG_CAPACITY, DEFAULT_CALL_TRANSACTION_CAPACITY,
    };
    use crate::runtime::admission::AdmissionLeaseGroup;

    fn runtime() -> CallRuntime {
        let context = CallContext::new(Duration::ZERO, 32).unwrap_or_else(|_| panic!("context"));
        let config = CallRuntimeConfig::new(
            DEFAULT_CALL_TRANSACTION_CAPACITY,
            DEFAULT_CALL_DIALOG_CAPACITY,
            DEFAULT_CALL_DEADLINE_CAPACITY,
            Duration::from_millis(1),
            false,
        );
        CallRuntime::new(context, AdmissionLeaseGroup::new(), config)
            .unwrap_or_else(|_| panic!("runtime"))
    }

    #[test]
    fn stale_token_cannot_reach_reused_call_id() {
        let mut manager = CallManager::new(1).unwrap_or_else(|_| panic!("manager"));
        let first = manager
            .spawn(7, runtime())
            .unwrap_or_else(|_| panic!("spawn"));
        assert!(manager.remove(first).is_ok());
        let second = manager
            .spawn(7, runtime())
            .unwrap_or_else(|_| panic!("spawn"));
        assert_ne!(first.generation(), second.generation());
        assert!(matches!(
            manager.submit(first, CallEvent::Command(CallCommand::Start)),
            Err(CallManagerError::StaleToken | CallManagerError::UnknownCall)
        ));
        assert!(
            manager
                .submit(second, CallEvent::Command(CallCommand::Start))
                .is_ok()
        );
        let actions = manager
            .receive_actions(second, Duration::from_secs(1))
            .unwrap_or_else(|_| panic!("actions"));
        assert_eq!(actions, Some(vec![CallAction::SendInvite]));
        assert!(manager.remove(second).is_ok());
    }

    #[test]
    fn admission_and_shutdown_are_bounded() {
        let mut manager = CallManager::new(1).unwrap_or_else(|_| panic!("manager"));
        let token = manager
            .spawn(1, runtime())
            .unwrap_or_else(|_| panic!("spawn"));
        assert!(matches!(
            manager.spawn(2, runtime()),
            Err(CallManagerError::AtCapacity)
        ));
        manager.begin_shutdown();
        assert!(matches!(
            manager.spawn(2, runtime()),
            Err(CallManagerError::ShuttingDown)
        ));
        assert!(manager.remove(token).is_ok());
    }

    #[test]
    fn shutdown_all_signals_then_joins_every_thread() {
        let mut manager = CallManager::new(4).unwrap_or_else(|_| panic!("manager"));
        for id in 1..=4 {
            manager
                .spawn(id, runtime())
                .unwrap_or_else(|_| panic!("spawn"));
        }
        let exits = manager
            .shutdown_all()
            .unwrap_or_else(|_| panic!("shutdown"));
        assert_eq!(exits.len(), 4);
        assert!(manager.is_empty());
    }

    #[test]
    fn remote_bye_releases_thread_without_other_call_failure() {
        let mut manager = CallManager::new(2).unwrap_or_else(|_| panic!("manager"));
        let first = manager
            .spawn(1, runtime())
            .unwrap_or_else(|_| panic!("first"));
        let second = manager
            .spawn(2, runtime())
            .unwrap_or_else(|_| panic!("second"));
        assert!(
            manager
                .submit(first, CallEvent::Command(CallCommand::Start))
                .is_ok()
        );
        assert!(manager.submit(first, CallEvent::RemoteBye).is_ok());
        let _ = manager.receive_actions(first, Duration::from_secs(1));
        let _ = manager.receive_actions(first, Duration::from_secs(1));
        for _ in 0..1_000 {
            if manager
                .handle(first)
                .is_ok_and(|handle| handle.status().phase == CallThreadPhase::Completed)
            {
                break;
            }
            std::thread::yield_now();
        }
        assert!(manager.handle(second).is_ok());
        assert!(manager.remove(first).is_ok());
        assert!(manager.remove(second).is_ok());
    }
}
