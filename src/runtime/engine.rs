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

//! Bounded process-level owner for call admission and native call threads.
//!
//! The engine stores only generation-fenced external call capabilities. Every
//! mutable SIP, dialog, RTP, and media object remains exclusively owned by its
//! dedicated call thread.

use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use crate::call::execution::handle::{CallHandle, CallToken};
use crate::call::execution::manager::{CallManager, CallManagerError};
use crate::call::execution::thread::{CallExit, CallThreadConfig};
use crate::call::model::events::{CallAction, CallCommand, CallEvent};
use crate::runtime::admission::{
    AdmissionController, AdmissionError, AdmissionLeaseGroup, OverloadRejection,
};
use crate::runtime::dial::{OutboundDialConfig, OutboundDialError};
use crate::runtime::shutdown::{ShutdownAction, ShutdownCoordinator, ShutdownError, ShutdownPhase};
use crate::sip::headers::retry_after::RetryAfter;

/// Immutable process-engine capacity and shutdown policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeEngineConfig {
    maximum_calls: usize,
    overload_retry_after: RetryAfter,
    call_thread: CallThreadConfig,
    shutdown_grace: Duration,
}

impl RuntimeEngineConfig {
    /// Creates explicit process-level call limits.
    ///
    /// Validation is completed by [`RuntimeEngine::new`] so the same
    /// authoritative admission and call-manager bounds remain in force.
    #[must_use]
    pub const fn new(
        maximum_calls: usize,
        overload_retry_after: RetryAfter,
        call_thread: CallThreadConfig,
        shutdown_grace: Duration,
    ) -> Self {
        Self {
            maximum_calls,
            overload_retry_after,
            call_thread,
            shutdown_grace,
        }
    }

    /// Returns the maximum active calls owned by this worker process.
    #[must_use]
    pub const fn maximum_calls(self) -> usize {
        self.maximum_calls
    }

    /// Returns the bounded native call-thread policy.
    #[must_use]
    pub const fn call_thread(self) -> CallThreadConfig {
        self.call_thread
    }

    /// Returns graceful drain time before forced termination.
    #[must_use]
    pub const fn shutdown_grace(self) -> Duration {
        self.shutdown_grace
    }
}

/// Process-level call engine with bounded admission and generation fencing.
pub struct RuntimeEngine {
    calls: CallManager,
    admission: AdmissionController,
    shutdown: ShutdownCoordinator,
    shutdown_grace: Duration,
}

impl RuntimeEngine {
    /// Allocates the bounded call registry and admission controller.
    ///
    /// # Errors
    ///
    /// Rejects invalid capacity, zero shutdown grace, or registry allocation
    /// failure.
    pub fn new(config: RuntimeEngineConfig) -> Result<Self, RuntimeEngineError> {
        if config.shutdown_grace.is_zero() {
            return Err(RuntimeEngineError::ZeroShutdownGrace);
        }
        let admission = AdmissionController::new(config.maximum_calls, config.overload_retry_after)
            .map_err(RuntimeEngineError::Admission)?;
        let calls = CallManager::with_thread_config(config.maximum_calls, config.call_thread)
            .map_err(RuntimeEngineError::Calls)?;
        Ok(Self {
            calls,
            admission,
            shutdown: ShutdownCoordinator::new(),
            shutdown_grace: config.shutdown_grace,
        })
    }

    /// Admits, prepares, spawns, and starts one outbound call atomically.
    ///
    /// No INVITE is emitted unless native thread creation and bounded command
    /// queue installation both succeed. Admission and socket resources unwind
    /// on every failure path.
    ///
    /// # Errors
    ///
    /// Returns overload policy, preparation, spawn, or start-rollback failure.
    pub fn dial(
        &mut self,
        call_id: u64,
        config: OutboundDialConfig,
        now: Duration,
    ) -> Result<DialedCall, RuntimeEngineError> {
        let lease = self
            .admission
            .try_admit()
            .map_err(RuntimeEngineError::Overloaded)?;
        let mut leases = AdmissionLeaseGroup::new();
        leases.push(lease).map_err(RuntimeEngineError::Admission)?;
        let prepared = config
            .prepare(now, leases)
            .map_err(RuntimeEngineError::Dial)?;
        let local_addr = prepared.local_addr();
        let advertised_addr = prepared.advertised_addr();
        let token = self
            .calls
            .spawn(call_id, prepared.into_runtime())
            .map_err(RuntimeEngineError::Calls)?;
        if let Err(start) = self
            .calls
            .submit(token, CallEvent::Command(CallCommand::Start))
        {
            let cleanup = self.calls.remove(token).err();
            return Err(RuntimeEngineError::Start { start, cleanup });
        }
        Ok(DialedCall {
            token,
            local_addr,
            advertised_addr,
        })
    }

    /// Submits one public call command through the bounded call mailbox.
    ///
    /// # Errors
    ///
    /// Rejects an unknown/stale token, full mailbox, or closed call thread.
    pub fn command(
        &self,
        token: CallToken,
        command: CallCommand,
    ) -> Result<(), RuntimeEngineError> {
        self.calls
            .submit(token, CallEvent::Command(command))
            .map_err(RuntimeEngineError::Calls)
    }

    /// Requests graceful call termination.
    ///
    /// # Errors
    ///
    /// Preserves bounded mailbox and generation-fence failures.
    pub fn hangup(&self, token: CallToken) -> Result<(), RuntimeEngineError> {
        self.command(token, CallCommand::Hangup)
    }

    /// Returns a cloned generation-fenced external capability.
    ///
    /// # Errors
    ///
    /// Rejects an unknown or stale token.
    pub fn handle(&self, token: CallToken) -> Result<CallHandle, RuntimeEngineError> {
        self.calls.handle(token).map_err(RuntimeEngineError::Calls)
    }

    /// Waits for one bounded observer action batch.
    ///
    /// Correctness-critical SIP effects execute inside the call thread before
    /// these observational actions are delivered.
    ///
    /// # Errors
    ///
    /// Rejects unknown/stale calls or a closed observer queue.
    pub fn receive_actions(
        &self,
        token: CallToken,
        timeout: Duration,
    ) -> Result<Option<Vec<CallAction>>, RuntimeEngineError> {
        self.calls
            .receive_actions(token, timeout)
            .map_err(RuntimeEngineError::Calls)
    }

    /// Removes and joins one exact call generation.
    ///
    /// # Errors
    ///
    /// Rejects unknown/stale tokens or native join failure.
    pub fn remove(&mut self, token: CallToken) -> Result<CallExit, RuntimeEngineError> {
        self.calls.remove(token).map_err(RuntimeEngineError::Calls)
    }

    /// Joins all terminal calls and returns the number removed.
    ///
    /// # Errors
    ///
    /// Preserves registry allocation and native join failure.
    pub fn reap_finished(&mut self) -> Result<usize, RuntimeEngineError> {
        self.calls
            .reap_finished()
            .map_err(RuntimeEngineError::Calls)
    }

    /// Joins terminal calls and returns their privacy-safe final reports.
    ///
    /// # Errors
    ///
    /// Preserves registry allocation and native join failure.
    pub fn reap_finished_reports(&mut self) -> Result<Vec<CallExit>, RuntimeEngineError> {
        self.calls
            .reap_finished_reports()
            .map_err(RuntimeEngineError::Calls)
    }

    /// Fences admission and begins graceful process drain.
    ///
    /// Existing calls continue until completion or the configured deadline.
    ///
    /// # Errors
    ///
    /// Rejects repeated shutdown or monotonic deadline overflow.
    pub fn begin_shutdown(&mut self, now: Duration) -> Result<(), RuntimeEngineError> {
        self.shutdown
            .begin(now, self.shutdown_grace)
            .map_err(RuntimeEngineError::Shutdown)?;
        self.admission.begin_shutdown();
        self.calls.begin_shutdown();
        Ok(())
    }

    /// Reaps completed calls and advances graceful shutdown.
    ///
    /// At the force boundary every remaining call is signaled before joins
    /// begin. The returned reports preserve each call's privacy-safe terminal
    /// diagnostics.
    ///
    /// # Errors
    ///
    /// Rejects polling before shutdown, time regression, allocation failure,
    /// or native join failure.
    pub fn poll_shutdown(
        &mut self,
        now: Duration,
    ) -> Result<RuntimeShutdownProgress, RuntimeEngineError> {
        let completed = self
            .calls
            .reap_finished_reports()
            .map_err(RuntimeEngineError::Calls)?;
        let action = self
            .shutdown
            .poll(now, self.calls.len())
            .map_err(RuntimeEngineError::Shutdown)?;
        let forced = if matches!(action, ShutdownAction::ForceTerminate { .. }) {
            self.calls
                .shutdown_all()
                .map_err(RuntimeEngineError::Calls)?
        } else {
            Vec::new()
        };
        Ok(RuntimeShutdownProgress {
            action,
            completed,
            forced,
        })
    }

    /// Returns registered call count, including terminal calls not yet reaped.
    #[must_use]
    pub fn active_calls(&self) -> usize {
        self.calls.len()
    }

    /// Returns currently held active-call admission leases.
    #[must_use]
    pub fn admitted_calls(&self) -> usize {
        self.admission.active()
    }

    /// Returns process shutdown phase.
    #[must_use]
    pub const fn shutdown_phase(&self) -> ShutdownPhase {
        self.shutdown.phase()
    }
}

impl fmt::Debug for RuntimeEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeEngine")
            .field("registered_calls", &self.calls.len())
            .field("admitted_calls", &self.admission.active())
            .field("shutdown_phase", &self.shutdown.phase())
            .finish_non_exhaustive()
    }
}

/// Generation-fenced call identity plus resolved signaling endpoints.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DialedCall {
    token: CallToken,
    local_addr: SocketAddr,
    advertised_addr: SocketAddr,
}

impl DialedCall {
    /// Returns the generation-fenced call capability.
    #[must_use]
    pub const fn token(self) -> CallToken {
        self.token
    }

    /// Returns the actual bound call-owned UDP endpoint.
    #[must_use]
    pub const fn local_addr(self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the endpoint serialized into initial Via and Contact fields.
    #[must_use]
    pub const fn advertised_addr(self) -> SocketAddr {
        self.advertised_addr
    }
}

impl fmt::Debug for DialedCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DialedCall")
            .field("token", &self.token)
            .field(
                "address_family",
                &if self.local_addr.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                },
            )
            .field(
                "uses_address_translation",
                &(self.local_addr != self.advertised_addr),
            )
            .finish_non_exhaustive()
    }
}

/// Result of one process-shutdown poll.
pub struct RuntimeShutdownProgress {
    action: ShutdownAction,
    completed: Vec<CallExit>,
    forced: Vec<CallExit>,
}

impl RuntimeShutdownProgress {
    /// Returns the state transition emitted by the shutdown coordinator.
    #[must_use]
    pub const fn action(&self) -> ShutdownAction {
        self.action
    }

    /// Returns calls that naturally completed and were joined this poll.
    #[must_use]
    pub const fn reaped(&self) -> usize {
        self.completed.len()
    }

    /// Returns terminal reports for calls that completed naturally this poll.
    #[must_use]
    pub fn completed_exits(&self) -> &[CallExit] {
        &self.completed
    }

    /// Returns terminal reports for calls forcibly drained at the deadline.
    #[must_use]
    pub fn forced_exits(&self) -> &[CallExit] {
        &self.forced
    }

    /// Consumes the progress report into forced terminal call reports.
    #[must_use]
    pub fn into_forced_exits(self) -> Vec<CallExit> {
        self.forced
    }
}

impl fmt::Debug for RuntimeShutdownProgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeShutdownProgress")
            .field("action", &self.action)
            .field("reaped", &self.completed.len())
            .field("forced_calls", &self.forced.len())
            .finish()
    }
}

/// Process-level runtime engine failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum RuntimeEngineError {
    /// Process shutdown grace was zero.
    ZeroShutdownGrace,
    /// Active-call capacity or lease grouping was invalid.
    Admission(AdmissionError),
    /// Active-call admission returned an overload policy.
    Overloaded(OverloadRejection),
    /// Outbound socket, INVITE, or call runtime preparation failed.
    Dial(OutboundDialError),
    /// Call registry, mailbox, native spawn, or join failed.
    Calls(CallManagerError),
    /// Initial Start enqueue failed; optional cleanup failure is retained.
    Start {
        /// Initial bounded mailbox failure.
        start: CallManagerError,
        /// Failure while removing the unstarted call, if any.
        cleanup: Option<CallManagerError>,
    },
    /// Graceful-shutdown state transition failed.
    Shutdown(ShutdownError),
}

impl RuntimeEngineError {
    /// Returns overload response policy when admission rejected a call.
    #[must_use]
    pub const fn overload(&self) -> Option<OverloadRejection> {
        match self {
            Self::Overloaded(policy) => Some(*policy),
            _ => None,
        }
    }
}

impl fmt::Display for RuntimeEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime engine operation failed")
    }
}

impl StdError for RuntimeEngineError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Dial(error) => Some(error),
            Self::Calls(error) => Some(error),
            Self::Start { start, .. } => Some(start),
            Self::Shutdown(error) => Some(error),
            Self::ZeroShutdownGrace | Self::Overloaded(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::Duration;

    use super::{RuntimeEngine, RuntimeEngineConfig, RuntimeEngineError};
    use crate::call::execution::thread::CallThreadConfig;
    use crate::runtime::dial::OutboundDialConfig;
    use crate::runtime::shutdown::{ShutdownAction, ShutdownPhase};
    use crate::sip::headers::retry_after::RetryAfter;
    use crate::sip::parser::uri;

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn engine(maximum: usize) -> RuntimeEngine {
        RuntimeEngine::new(RuntimeEngineConfig::new(
            maximum,
            RetryAfter::new(3),
            CallThreadConfig::default(),
            Duration::from_secs(5),
        ))
        .unwrap_or_else(|_| panic!("engine"))
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

    #[test]
    fn dial_atomically_admits_spawns_starts_and_releases() {
        let peer = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("peer"));
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("timeout"));
        let remote = peer.local_addr().unwrap_or_else(|_| panic!("remote"));
        let mut engine = engine(1);
        let token = engine
            .dial(7, dial_config(remote), Duration::ZERO)
            .unwrap_or_else(|_| panic!("dial"))
            .token();
        let mut buffer = [0_u8; 2_048];
        let (length, _) = peer
            .recv_from(&mut buffer)
            .unwrap_or_else(|_| panic!("INVITE"));
        assert!(buffer[..length].starts_with(b"INVITE "));
        assert_eq!(engine.active_calls(), 1);
        assert_eq!(engine.admitted_calls(), 1);
        engine.hangup(token).unwrap_or_else(|_| panic!("hangup"));
        let _ = engine.remove(token).unwrap_or_else(|_| panic!("remove"));
        assert_eq!(engine.active_calls(), 0);
        assert_eq!(engine.admitted_calls(), 0);
    }

    #[test]
    fn overload_happens_before_second_socket_and_releases_after_remove() {
        let peer = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("peer"));
        let remote = peer.local_addr().unwrap_or_else(|_| panic!("remote"));
        let mut engine = engine(1);
        let token = engine
            .dial(1, dial_config(remote), Duration::ZERO)
            .unwrap_or_else(|_| panic!("first dial"))
            .token();
        let error = engine
            .dial(2, dial_config(remote), Duration::ZERO)
            .err()
            .unwrap_or_else(|| panic!("overload"));
        let policy = error.overload().unwrap_or_else(|| panic!("policy"));
        assert_eq!(policy.status(), 503);
        assert_eq!(policy.retry_after().seconds(), 3);
        let _ = engine.remove(token).unwrap_or_else(|_| panic!("remove"));
        assert_eq!(engine.admitted_calls(), 0);
    }

    #[test]
    fn graceful_shutdown_fences_new_dials_then_forces_remaining_calls() {
        let peer = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("peer"));
        let remote = peer.local_addr().unwrap_or_else(|_| panic!("remote"));
        let mut engine = engine(2);
        let _token = engine
            .dial(1, dial_config(remote), Duration::ZERO)
            .unwrap_or_else(|_| panic!("dial"));
        engine
            .begin_shutdown(Duration::from_secs(1))
            .unwrap_or_else(|_| panic!("begin shutdown"));
        assert_eq!(engine.shutdown_phase(), ShutdownPhase::Draining);
        assert!(matches!(
            engine.dial(2, dial_config(remote), Duration::from_secs(2)),
            Err(RuntimeEngineError::Overloaded(_))
        ));
        let waiting = engine
            .poll_shutdown(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("poll waiting"));
        assert_eq!(waiting.action(), ShutdownAction::None);
        let forced = engine
            .poll_shutdown(Duration::from_secs(6))
            .unwrap_or_else(|_| panic!("poll forced"));
        assert!(matches!(
            forced.action(),
            ShutdownAction::ForceTerminate { active_calls: 1 }
        ));
        assert_eq!(forced.forced_exits().len(), 1);
        assert_eq!(engine.active_calls(), 0);
        assert_eq!(engine.admitted_calls(), 0);
        let complete = engine
            .poll_shutdown(Duration::from_secs(7))
            .unwrap_or_else(|_| panic!("poll complete"));
        assert_eq!(complete.action(), ShutdownAction::Complete);
        assert_eq!(engine.shutdown_phase(), ShutdownPhase::Complete);
    }

    #[test]
    fn configuration_rejects_zero_grace_and_redacts_engine_state() {
        let config = RuntimeEngineConfig::new(
            1,
            RetryAfter::new(3),
            CallThreadConfig::default(),
            Duration::ZERO,
        );
        assert!(matches!(
            RuntimeEngine::new(config),
            Err(RuntimeEngineError::ZeroShutdownGrace)
        ));
        let debug = format!("{:?}", engine(1));
        assert!(debug.contains("registered_calls"));
        assert!(!debug.contains("127.0.0.1"));
    }
}
