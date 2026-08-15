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

//! Process-worker lifecycle above the bounded runtime service.
//!
//! The worker owns admission, readiness, observer pumping, and graceful drain.
//! It never owns mutable per-call SIP, dialog, RTP, or media state; those
//! objects remain exclusively inside their dedicated call threads.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use crate::call::model::events::CallCommand;
use crate::runtime::dial::OutboundDialConfig;
use crate::runtime::engine::DialedCall;
use crate::runtime::service::{
    NotificationQueueSnapshot, RuntimeCallSnapshot, RuntimeNotification, RuntimePumpReport,
    RuntimeService, RuntimeServiceConfig, RuntimeServiceError, ServiceShutdownProgress,
    TerminalOutcome,
};
use crate::runtime::shutdown::{ShutdownAction, ShutdownPhase};
use crate::util::time::MonotonicClock;

/// Process worker admission and lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerPhase {
    /// All fixed resources were allocated and new calls are accepted.
    Ready,
    /// Admission is fenced while calls drain or are force-terminated.
    Draining,
    /// Every call thread has been joined and no new work is accepted.
    Stopped,
}

impl WorkerPhase {
    /// Returns whether the worker may accept a new call.
    #[must_use]
    pub const fn accepts_calls(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Returns whether the worker is safe to advertise as ready.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Process worker around one bounded runtime service.
pub struct RuntimeWorker {
    service: RuntimeService,
    clock: MonotonicClock,
    phase: WorkerPhase,
    last_poll: Duration,
    polls: u64,
    calls_started: u64,
    calls_completed: u64,
    calls_forced: u64,
}

impl RuntimeWorker {
    /// Allocates the complete service boundary before becoming ready.
    ///
    /// # Errors
    ///
    /// Preserves service capacity validation and allocation failures.
    pub fn new(config: RuntimeServiceConfig) -> Result<Self, RuntimeWorkerError> {
        let service = RuntimeService::new(config).map_err(RuntimeWorkerError::Service)?;
        Ok(Self {
            service,
            clock: MonotonicClock::start(),
            phase: WorkerPhase::Ready,
            last_poll: Duration::ZERO,
            polls: 0,
            calls_started: 0,
            calls_completed: 0,
            calls_forced: 0,
        })
    }

    /// Atomically admits and starts one outbound call using the worker clock.
    ///
    /// # Errors
    ///
    /// Rejects calls after draining begins and preserves service dial failure.
    pub fn dial(
        &mut self,
        call_id: u64,
        config: OutboundDialConfig,
    ) -> Result<DialedCall, RuntimeWorkerError> {
        if !self.phase.accepts_calls() {
            return Err(RuntimeWorkerError::NotAccepting { phase: self.phase });
        }
        let next_started = self
            .calls_started
            .checked_add(1)
            .ok_or(RuntimeWorkerError::CounterExhausted)?;
        let dialed = self
            .service
            .dial(call_id, config)
            .map_err(RuntimeWorkerError::Service)?;
        self.calls_started = next_started;
        Ok(dialed)
    }

    /// Submits one bounded command to an active call.
    ///
    /// Commands remain available during drain so operators can terminate or
    /// otherwise control calls already admitted before the fence.
    ///
    /// # Errors
    ///
    /// Preserves service call lookup and bounded mailbox failures.
    pub fn command(&self, call_id: u64, command: CallCommand) -> Result<(), RuntimeWorkerError> {
        self.service
            .command(call_id, command)
            .map_err(RuntimeWorkerError::Service)
    }

    /// Requests graceful termination of one active call.
    ///
    /// # Errors
    ///
    /// Preserves service call lookup and bounded mailbox failures.
    pub fn hangup(&self, call_id: u64) -> Result<(), RuntimeWorkerError> {
        self.service
            .hangup(call_id)
            .map_err(RuntimeWorkerError::Service)
    }

    /// Performs one nonblocking process-worker iteration.
    ///
    /// Ready workers drain bounded observer work. Draining workers additionally
    /// advance graceful shutdown and eventually join every call thread.
    ///
    /// # Errors
    ///
    /// Preserves service pump, shutdown, join, and counter failures.
    pub fn poll(&mut self) -> Result<WorkerPollReport, RuntimeWorkerError> {
        self.poll_at(self.clock.now())
    }

    /// Fences new admission and starts graceful drain using the worker clock.
    ///
    /// # Errors
    ///
    /// Rejects repeated or post-stop shutdown and preserves service failure.
    pub fn begin_shutdown(&mut self) -> Result<(), RuntimeWorkerError> {
        self.begin_shutdown_at(self.clock.now())
    }

    /// Returns active or retained terminal state for one application call ID.
    #[must_use]
    pub fn call_snapshot(&self, call_id: u64) -> Option<RuntimeCallSnapshot> {
        self.service.snapshot(call_id)
    }

    /// Returns one retained terminal outcome without acknowledging it.
    #[must_use]
    pub fn terminal_outcome(&self, call_id: u64) -> Option<TerminalOutcome> {
        self.service.terminal_outcome(call_id)
    }

    /// Acknowledges and removes one retained terminal outcome.
    pub fn take_terminal_outcome(&mut self, call_id: u64) -> Option<TerminalOutcome> {
        self.service.take_terminal_outcome(call_id)
    }

    /// Pops the oldest best-effort observer notification.
    pub fn next_notification(&mut self) -> Option<RuntimeNotification> {
        self.service.next_notification()
    }

    /// Returns a privacy-safe process-worker snapshot.
    #[must_use]
    pub fn snapshot(&self) -> WorkerSnapshot {
        WorkerSnapshot {
            phase: self.phase,
            uptime: self.clock.now(),
            active_calls: self.service.active_calls(),
            registered_calls: self.service.registered_calls(),
            terminal_unreaped_calls: self.service.terminal_unreaped_calls(),
            retained_outcomes: self.service.retained_outcomes(),
            notifications: self.service.notification_snapshot(),
            polls: self.polls,
            calls_started: self.calls_started,
            calls_completed: self.calls_completed,
            calls_forced: self.calls_forced,
        }
    }

    fn begin_shutdown_at(&mut self, now: Duration) -> Result<(), RuntimeWorkerError> {
        if now < self.last_poll {
            return Err(RuntimeWorkerError::ClockMovedBackward);
        }
        match self.phase {
            WorkerPhase::Ready => {}
            WorkerPhase::Draining => return Err(RuntimeWorkerError::AlreadyDraining),
            WorkerPhase::Stopped => return Err(RuntimeWorkerError::AlreadyStopped),
        }
        self.service
            .begin_shutdown(now)
            .map_err(RuntimeWorkerError::Service)?;
        self.last_poll = now;
        self.phase = WorkerPhase::Draining;
        Ok(())
    }

    fn poll_at(&mut self, now: Duration) -> Result<WorkerPollReport, RuntimeWorkerError> {
        if now < self.last_poll {
            return Err(RuntimeWorkerError::ClockMovedBackward);
        }
        let next_polls = self
            .polls
            .checked_add(1)
            .ok_or(RuntimeWorkerError::CounterExhausted)?;
        if self.phase == WorkerPhase::Stopped {
            self.last_poll = now;
            self.polls = next_polls;
            return Ok(WorkerPollReport {
                phase: self.phase,
                service: empty_pump_report(),
                shutdown: None,
            });
        }

        let service = self.service.pump().map_err(RuntimeWorkerError::Service)?;
        self.calls_completed = self
            .calls_completed
            .saturating_add(service.calls_completed as u64);
        let shutdown = if self.phase == WorkerPhase::Draining {
            let progress = self
                .service
                .poll_shutdown(now)
                .map_err(RuntimeWorkerError::Service)?;
            self.calls_completed = self
                .calls_completed
                .saturating_add(progress.completed as u64)
                .saturating_add(progress.forced as u64);
            self.calls_forced = self.calls_forced.saturating_add(progress.forced as u64);
            if progress.action == ShutdownAction::Complete
                || self.service.shutdown_phase() == ShutdownPhase::Complete
            {
                self.phase = WorkerPhase::Stopped;
            }
            Some(progress)
        } else {
            None
        };
        self.last_poll = now;
        self.polls = next_polls;
        Ok(WorkerPollReport {
            phase: self.phase,
            service,
            shutdown,
        })
    }
}

impl fmt::Debug for RuntimeWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snapshot = self.snapshot();
        formatter
            .debug_struct("RuntimeWorker")
            .field("phase", &snapshot.phase)
            .field("active_calls", &snapshot.active_calls)
            .field("registered_calls", &snapshot.registered_calls)
            .field("retained_outcomes", &snapshot.retained_outcomes)
            .field("polls", &snapshot.polls)
            .field("calls_started", &snapshot.calls_started)
            .field("calls_completed", &snapshot.calls_completed)
            .field("calls_forced", &snapshot.calls_forced)
            .finish_non_exhaustive()
    }
}

/// Result of one nonblocking worker iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerPollReport {
    /// Worker phase after this iteration.
    pub phase: WorkerPhase,
    /// Bounded observer and terminal work completed by the service.
    pub service: RuntimePumpReport,
    /// Shutdown progress when the worker is draining.
    pub shutdown: Option<ServiceShutdownProgress>,
}

/// Privacy-safe worker readiness, capacity, and lifecycle counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerSnapshot {
    /// Current worker lifecycle.
    pub phase: WorkerPhase,
    /// Monotonic elapsed worker lifetime.
    pub uptime: Duration,
    /// Calls whose native owner thread remains nonterminal.
    pub active_calls: usize,
    /// Calls still present in the native registry.
    pub registered_calls: usize,
    /// Terminal native calls awaiting a worker poll.
    pub terminal_unreaped_calls: usize,
    /// Exact outcomes awaiting application acknowledgement.
    pub retained_outcomes: usize,
    /// Bounded best-effort observer queue state.
    pub notifications: NotificationQueueSnapshot,
    /// Successful worker polling iterations.
    pub polls: u64,
    /// Calls successfully started during this worker lifetime.
    pub calls_started: u64,
    /// Calls reaped or forced during this worker lifetime.
    pub calls_completed: u64,
    /// Calls force-terminated after graceful drain elapsed.
    pub calls_forced: u64,
}

impl WorkerSnapshot {
    /// Returns whether this worker may be advertised for new placement.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.phase.is_ready()
    }
}

/// Process-worker lifecycle or service failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum RuntimeWorkerError {
    /// Worker is draining or stopped and cannot admit a new call.
    NotAccepting {
        /// Current worker lifecycle.
        phase: WorkerPhase,
    },
    /// Graceful drain was already active.
    AlreadyDraining,
    /// Worker had already completed shutdown.
    AlreadyStopped,
    /// A caller-provided deterministic test clock regressed.
    ClockMovedBackward,
    /// A worker lifetime counter could not advance without wrapping.
    CounterExhausted,
    /// Bounded runtime service operation failed.
    Service(RuntimeServiceError),
}

impl RuntimeWorkerError {
    /// Returns a stable low-cardinality failure class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::NotAccepting { .. } => "not-accepting",
            Self::AlreadyDraining => "already-draining",
            Self::AlreadyStopped => "already-stopped",
            Self::ClockMovedBackward => "clock-moved-backward",
            Self::CounterExhausted => "counter-exhausted",
            Self::Service(_) => "service",
        }
    }
}

impl fmt::Display for RuntimeWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "runtime worker operation failed: {}",
            self.class()
        )
    }
}

impl StdError for RuntimeWorkerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Service(error) => Some(error),
            Self::NotAccepting { .. }
            | Self::AlreadyDraining
            | Self::AlreadyStopped
            | Self::ClockMovedBackward
            | Self::CounterExhausted => None,
        }
    }
}

const fn empty_pump_report() -> RuntimePumpReport {
    RuntimePumpReport {
        calls_scanned: 0,
        action_batches: 0,
        calls_completed: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::Duration;

    use super::{RuntimeWorker, RuntimeWorkerError, WorkerPhase};
    use crate::call::execution::thread::CallThreadConfig;
    use crate::runtime::{
        OutboundDialConfig, RuntimeEngineConfig, RuntimeServiceConfig, TerminalOutcome,
    };
    use crate::sip::headers::retry_after::RetryAfter;
    use crate::sip::parser::uri;

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn worker() -> RuntimeWorker {
        RuntimeWorker::new(RuntimeServiceConfig::new(
            RuntimeEngineConfig::new(
                1,
                RetryAfter::new(3),
                CallThreadConfig::default(),
                Duration::from_secs(5),
            ),
            32,
        ))
        .unwrap_or_else(|_| panic!("worker"))
    }

    fn dial_config(destination: SocketAddr) -> OutboundDialConfig {
        let caller =
            uri::parse_str("sip:worker@example.invalid").unwrap_or_else(|_| panic!("caller"));
        let target =
            uri::parse_str("sip:1000@example.invalid").unwrap_or_else(|_| panic!("target"));
        OutboundDialConfig::new(caller, target, localhost(0), destination)
            .unwrap_or_else(|_| panic!("dial"))
            .with_inactive_pcmu_sdp()
    }

    #[test]
    fn fixed_resources_are_ready_before_first_call() {
        let worker = worker();
        let snapshot = worker.snapshot();
        assert_eq!(snapshot.phase, WorkerPhase::Ready);
        assert!(snapshot.is_ready());
        assert_eq!(snapshot.active_calls, 0);
        assert_eq!(snapshot.notifications.capacity, 32);
        let debug = format!("{worker:?}");
        assert!(!debug.contains("worker@example.invalid"));
        assert!(!debug.contains("127.0.0.1"));
    }

    #[test]
    fn drain_fences_dials_forces_call_and_retains_exact_outcome() {
        let peer = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("peer"));
        peer.set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap_or_else(|_| panic!("timeout"));
        let destination = peer.local_addr().unwrap_or_else(|_| panic!("destination"));
        let mut worker = worker();
        let dialed = worker
            .dial(7, dial_config(destination))
            .unwrap_or_else(|_| panic!("dial"));
        let mut invite = [0_u8; 2_048];
        let (length, _) = peer
            .recv_from(&mut invite)
            .unwrap_or_else(|_| panic!("INVITE"));
        assert!(invite[..length].starts_with(b"INVITE "));
        assert_eq!(worker.snapshot().calls_started, 1);

        worker
            .begin_shutdown_at(Duration::ZERO)
            .unwrap_or_else(|_| panic!("shutdown"));
        assert!(matches!(
            worker.dial(8, dial_config(destination)),
            Err(RuntimeWorkerError::NotAccepting {
                phase: WorkerPhase::Draining
            })
        ));
        let waiting = worker
            .poll_at(Duration::from_secs(4))
            .unwrap_or_else(|_| panic!("waiting"));
        assert_eq!(waiting.phase, WorkerPhase::Draining);
        let forced = worker
            .poll_at(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("force"));
        assert_eq!(forced.shutdown.map(|value| value.forced), Some(1));
        let stopped = worker
            .poll_at(Duration::from_secs(6))
            .unwrap_or_else(|_| panic!("complete"));
        assert_eq!(stopped.phase, WorkerPhase::Stopped);
        let snapshot = worker.snapshot();
        assert!(!snapshot.is_ready());
        assert_eq!(snapshot.calls_forced, 1);
        assert_eq!(snapshot.retained_outcomes, 1);
        assert_eq!(
            worker
                .terminal_outcome(dialed.token().call_id())
                .map(TerminalOutcome::token),
            Some(dialed.token())
        );
    }

    #[test]
    fn deterministic_poll_rejects_time_regression() {
        let mut worker = worker();
        assert!(worker.poll_at(Duration::from_secs(2)).is_ok());
        assert!(matches!(
            worker.poll_at(Duration::from_secs(1)),
            Err(RuntimeWorkerError::ClockMovedBackward)
        ));
    }
}
