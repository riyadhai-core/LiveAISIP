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

//! One-thread, readiness-driven SIP transport reactor.
//!
//! This is the operating-system scheduling boundary around
//! [`TransportService`]. Linux/Android use `epoll`; Apple and supported BSD
//! targets use `kqueue`. Both backends are one-shot, so every delivered source
//! is explicitly re-armed after bounded work. No socket gets a private thread.
//!
//! Socket handles used for readiness are duplicates of the handles owned by
//! the protocol drivers. That separation makes registration lifetime explicit:
//! a failed or gracefully retired driver cannot leave the poller referring to
//! a closed descriptor, and a poll handle never performs protocol I/O itself.
//!
//! Fairness is enforced twice: the operating system returns a bounded event
//! batch, and each readable source may produce only a bounded number of SIP
//! messages per turn. Reliable drivers can already contain pipelined complete
//! frames after one socket read, so budget exhaustion schedules a bounded
//! synthetic continuation rather than waiting for readiness that may not recur.

use std::collections::{HashMap, VecDeque};
use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::ReceivedMessage;
use super::connection::ConnectionId;
use super::destination::Destination;
use super::flow::EgressRoute;
use super::service::{
    FailedConnection, ReliableConnectionPlan, RouteSendDisposition, ServiceError,
    ServiceShutdownProgress, TransportService,
};
use super::tcp_driver::TcpDriver;
use super::tls_driver::TlsDriver;

/// Maximum operating-system readiness records accepted in one wait.
pub const MAX_READY_EVENTS: usize = 1_024;

/// Maximum messages consumed from one readable source in one turn.
pub const MAX_READS_PER_SOURCE: usize = 64;

/// Maximum result records allocated by one reactor poll.
pub const MAX_BATCH_EVENTS: usize = 131_072;

const WAKE_KEY: usize = 0;
const UDP_KEY: usize = 1;
const FIRST_RELIABLE_KEY: usize = 2;

/// Bounded readiness and per-source fairness policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReactorConfig {
    ready_events: usize,
    reads_per_source: usize,
}

impl ReactorConfig {
    /// Creates explicit readiness and read-drain budgets.
    ///
    /// # Errors
    ///
    /// Rejects zero values, hard-limit violations, and a combination whose
    /// maximum result batch would exceed [`MAX_BATCH_EVENTS`].
    pub const fn new(ready_events: usize, reads_per_source: usize) -> Result<Self, ReactorError> {
        if ready_events == 0 || ready_events > MAX_READY_EVENTS {
            return Err(ReactorError::InvalidReadyEventLimit {
                value: ready_events,
                maximum: MAX_READY_EVENTS,
            });
        }
        if reads_per_source == 0 || reads_per_source > MAX_READS_PER_SOURCE {
            return Err(ReactorError::InvalidReadBudget {
                value: reads_per_source,
                maximum: MAX_READS_PER_SOURCE,
            });
        }
        let Some(batch_events) = ready_events.checked_mul(reads_per_source + 2) else {
            return Err(ReactorError::BatchLimitExceeded {
                attempted: usize::MAX,
                maximum: MAX_BATCH_EVENTS,
            });
        };
        if batch_events > MAX_BATCH_EVENTS {
            return Err(ReactorError::BatchLimitExceeded {
                attempted: batch_events,
                maximum: MAX_BATCH_EVENTS,
            });
        }
        Ok(Self {
            ready_events,
            reads_per_source,
        })
    }

    /// Returns the maximum readiness records collected per wait.
    #[must_use]
    pub const fn ready_events(self) -> usize {
        self.ready_events
    }

    /// Returns the maximum inbound messages consumed per readable source.
    #[must_use]
    pub const fn reads_per_source(self) -> usize {
        self.reads_per_source
    }

    const fn batch_events(self) -> usize {
        self.ready_events * (self.reads_per_source + 2)
    }
}

impl Default for ReactorConfig {
    fn default() -> Self {
        Self {
            ready_events: 256,
            reads_per_source: 16,
        }
    }
}

/// One independently callable wake handle.
pub struct ReactorNotifier {
    writer: UnixStream,
}

impl ReactorNotifier {
    /// Wakes a blocked reactor wait.
    ///
    /// Wake bytes are coalesced. A full nonblocking wake socket is success
    /// because it already guarantees pending readability.
    ///
    /// # Errors
    ///
    /// Preserves operating-system wake-socket write failure.
    pub fn notify(&self) -> io::Result<()> {
        let mut writer = &self.writer;
        match writer.write(&[1]) {
            Ok(_) => Ok(()),
            Err(source) if source.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(source) => Err(source),
        }
    }
}

impl fmt::Debug for ReactorNotifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReactorNotifier")
            .finish_non_exhaustive()
    }
}

/// Why an established reliable source was retired by the reactor.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReactorSourceError {
    /// Driver, framing, parsing, validation, TLS, or service failure.
    Transport(ServiceError),
    /// The readiness backend reported a terminal condition without a more
    /// specific protocol-driver error.
    ReadinessTerminal,
    /// Re-arming or removing the operating-system registration failed.
    Readiness(io::Error),
}

impl ReactorSourceError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Transport(_) => "transport",
            Self::ReadinessTerminal => "readiness-terminal",
            Self::Readiness(_) => "readiness",
        }
    }
}

impl fmt::Display for ReactorSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP reactor source error: {}", self.class())
    }
}

impl StdError for ReactorSourceError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::Readiness(source) => Some(source),
            Self::ReadinessTerminal => None,
        }
    }
}

/// One result produced by a bounded reactor turn.
#[non_exhaustive]
pub enum ReactorEvent {
    /// A malformed or otherwise rejected UDP datagram. The UDP socket remains
    /// active because one datagram cannot desynchronize later datagrams.
    DatagramRejected(ServiceError),
    /// Exact immutable reliable messages fully committed in queue order.
    ReliableCommitted {
        /// Actor-owned connection identity.
        connection_id: ConnectionId,
        /// Messages proven fully accepted by the kernel/TLS transport.
        messages: Vec<Arc<[u8]>>,
    },
    /// A reliable flow failed and its ambiguous/unsent work was recovered.
    ReliableFailed {
        /// Actor-owned connection identity.
        connection_id: ConnectionId,
        /// Failure that caused retirement.
        error: ReactorSourceError,
        /// Exact in-flight and queued work recovered without byte copies.
        recovery: FailedConnection,
    },
    /// A fully drained reliable flow completed graceful shutdown.
    ReliableClosed {
        /// Retired actor-owned connection identity.
        connection_id: ConnectionId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchSlot {
    Inbound(usize),
    Event(usize),
}

/// Borrowed item in exact reactor processing order.
#[derive(Clone, Copy, Debug)]
pub enum ReactorBatchItem<'a> {
    /// Parsed and semantically validated inbound SIP message.
    Inbound(&'a ReceivedMessage),
    /// Transport commit, rejection, failure, or graceful-close event.
    Event(&'a ReactorEvent),
}

/// Iterator over one batch in exact reactor processing order.
pub struct ReactorBatchIter<'a> {
    batch: &'a ReactorBatch,
    offset: usize,
}

impl<'a> Iterator for ReactorBatchIter<'a> {
    type Item = ReactorBatchItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let slot = *self.batch.order.get(self.offset)?;
        self.offset += 1;
        match slot {
            BatchSlot::Inbound(index) => {
                self.batch.inbound.get(index).map(ReactorBatchItem::Inbound)
            }
            BatchSlot::Event(index) => self.batch.events.get(index).map(ReactorBatchItem::Event),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.batch.order.len().saturating_sub(self.offset);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ReactorBatchIter<'_> {}
impl std::iter::FusedIterator for ReactorBatchIter<'_> {}

impl fmt::Debug for ReactorEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatagramRejected(error) => formatter
                .debug_struct("DatagramRejected")
                .field("class", &error.class())
                .finish(),
            Self::ReliableCommitted {
                connection_id,
                messages,
            } => formatter
                .debug_struct("ReliableCommitted")
                .field("connection_id", connection_id)
                .field("messages", &messages.len())
                .finish(),
            Self::ReliableFailed {
                connection_id,
                error,
                recovery,
            } => formatter
                .debug_struct("ReliableFailed")
                .field("connection_id", connection_id)
                .field("class", &error.class())
                .field("recovery", recovery)
                .finish(),
            Self::ReliableClosed { connection_id } => formatter
                .debug_struct("ReliableClosed")
                .field("connection_id", connection_id)
                .finish(),
        }
    }
}

/// Results from one bounded reactor wait/drain turn.
pub struct ReactorBatch {
    inbound: Vec<ReceivedMessage>,
    events: Vec<ReactorEvent>,
    order: Vec<BatchSlot>,
    notified: bool,
}

impl ReactorBatch {
    /// Returns parsed and semantically validated inbound messages in receive order.
    #[must_use]
    pub fn inbound(&self) -> &[ReceivedMessage] {
        &self.inbound
    }

    /// Returns events in reactor processing order.
    #[must_use]
    pub fn events(&self) -> &[ReactorEvent] {
        &self.events
    }

    /// Iterates inbound messages and transport events in exact processing order.
    #[must_use]
    pub const fn iter(&self) -> ReactorBatchIter<'_> {
        ReactorBatchIter {
            batch: self,
            offset: 0,
        }
    }

    /// Returns whether an explicit notifier wake was consumed.
    #[must_use]
    pub const fn notified(&self) -> bool {
        self.notified
    }
}

impl<'a> IntoIterator for &'a ReactorBatch {
    type Item = ReactorBatchItem<'a>;
    type IntoIter = ReactorBatchIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for ReactorBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReactorBatch")
            .field("inbound", &self.inbound.len())
            .field("events", &self.events.len())
            .field("ordered_items", &self.order.len())
            .field("notified", &self.notified)
            .finish_non_exhaustive()
    }
}

struct ReliableRegistration {
    key: usize,
    source: TcpStream,
    buffered_continuation: bool,
}

/// Actor-owned readiness reactor around one transport service.
pub struct TransportReactor {
    poller: OsPoller,
    wake_reader: UnixStream,
    notifier: ReactorNotifier,
    udp_source: std::net::UdpSocket,
    udp_registered: bool,
    service: TransportService,
    config: ReactorConfig,
    registrations: HashMap<ConnectionId, ReliableRegistration>,
    by_key: HashMap<usize, ConnectionId>,
    continuations: VecDeque<usize>,
    ready: Vec<OsReady>,
    next_key: usize,
}

impl TransportReactor {
    /// Registers one nonblocking transport service with the native poller.
    ///
    /// # Errors
    ///
    /// Rejects blocking UDP configuration, allocation failure, socket-handle
    /// duplication, wake-socket setup, or native poller construction and
    /// registration failure.
    pub fn new(service: TransportService, config: ReactorConfig) -> Result<Self, ReactorError> {
        let config = ReactorConfig::new(config.ready_events, config.reads_per_source)?;
        if !service.udp_nonblocking() {
            return Err(ReactorError::BlockingUdpDriver);
        }

        let udp_source = service
            .try_clone_udp_socket()
            .map_err(ReactorError::DuplicateSocket)?;
        let (wake_reader, wake_writer) = UnixStream::pair().map_err(ReactorError::WakeSocket)?;
        wake_reader
            .set_nonblocking(true)
            .map_err(ReactorError::WakeSocket)?;
        wake_writer
            .set_nonblocking(true)
            .map_err(ReactorError::WakeSocket)?;

        let poller = OsPoller::new(config.ready_events).map_err(ReactorError::PollerCreate)?;
        poller
            .add(wake_reader.as_raw_fd(), WAKE_KEY, Interest::READ)
            .map_err(ReactorError::PollerRegister)?;
        poller
            .add(udp_source.as_raw_fd(), UDP_KEY, Interest::READ)
            .map_err(ReactorError::PollerRegister)?;

        let mut ready = Vec::new();
        ready
            .try_reserve_exact(config.ready_events)
            .map_err(|_| ReactorError::AllocationFailed)?;

        Ok(Self {
            poller,
            wake_reader,
            notifier: ReactorNotifier {
                writer: wake_writer,
            },
            udp_source,
            udp_registered: true,
            service,
            config,
            registrations: HashMap::new(),
            by_key: HashMap::new(),
            continuations: VecDeque::new(),
            ready,
            next_key: FIRST_RELIABLE_KEY,
        })
    }

    /// Returns a clonable cross-thread wake handle.
    ///
    /// # Errors
    ///
    /// Preserves operating-system handle duplication failure.
    pub fn try_notifier(&self) -> Result<ReactorNotifier, ReactorError> {
        Ok(ReactorNotifier {
            writer: self
                .notifier
                .writer
                .try_clone()
                .map_err(ReactorError::WakeSocket)?,
        })
    }

    /// Returns read-only access to transport state.
    #[must_use]
    pub const fn service(&self) -> &TransportService {
        &self.service
    }

    /// Plans or reuses one reliable destination without blocking connection I/O.
    ///
    /// # Errors
    ///
    /// Preserves transport planning, shutdown, capacity, and allocation failure.
    pub fn plan_reliable(
        &mut self,
        destination: Destination,
    ) -> Result<ReliableConnectionPlan, ReactorError> {
        self.service
            .plan_reliable(destination)
            .map_err(ReactorError::Service)
    }

    /// Attaches and registers one established nonblocking TCP driver.
    ///
    /// # Errors
    ///
    /// Rejects blocking/mismatched drivers and preserves attachment,
    /// registration, allocation, and rollback failure.
    pub fn attach_tcp(&mut self, id: ConnectionId, driver: TcpDriver) -> Result<(), ReactorError> {
        if !driver.config().nonblocking() {
            return Err(ReactorError::BlockingReliableDriver);
        }
        self.prepare_reliable_registration(id)?;
        self.service
            .attach_tcp(id, driver)
            .map_err(ReactorError::Service)?;
        self.register_reliable(id)
    }

    /// Attaches and registers one verified nonblocking TLS driver.
    ///
    /// # Errors
    ///
    /// Rejects blocking/mismatched/unverified drivers and preserves attachment,
    /// registration, allocation, and rollback failure.
    pub fn attach_tls(&mut self, id: ConnectionId, driver: TlsDriver) -> Result<(), ReactorError> {
        if !driver.nonblocking() {
            return Err(ReactorError::BlockingReliableDriver);
        }
        self.prepare_reliable_registration(id)?;
        self.service
            .attach_tls(id, driver)
            .map_err(ReactorError::Service)?;
        self.register_reliable(id)
    }

    /// Admits a reliable message and arms socket writability.
    ///
    /// # Errors
    ///
    /// Preserves queue admission, registration re-arm, and failure-recovery
    /// errors.
    pub fn enqueue_reliable(
        &mut self,
        id: ConnectionId,
        message: Arc<[u8]>,
    ) -> Result<(), ReactorError> {
        self.service
            .enqueue_reliable(id, message)
            .map_err(ReactorError::Service)?;
        self.rearm_reliable_or_recover(id)
    }

    /// Sends one response through authoritative ingress routing.
    ///
    /// # Errors
    ///
    /// Preserves route, UDP send, reliable admission, re-arm, and recovery
    /// failures.
    pub fn send_route(
        &mut self,
        route: EgressRoute,
        message: Arc<[u8]>,
    ) -> Result<RouteSendDisposition, ReactorError> {
        let disposition = self
            .service
            .send_route(route, message)
            .map_err(ReactorError::Service)?;
        if let RouteSendDisposition::ReliableQueued { connection_id } = disposition {
            self.rearm_reliable_or_recover(connection_id)?;
        }
        Ok(disposition)
    }

    /// Fences new work, unregisters UDP ingress, and makes every reliable flow
    /// writable so queued data and graceful close can advance.
    ///
    /// # Errors
    ///
    /// Preserves native readiness removal or re-arm failure.
    pub fn begin_shutdown(&mut self) -> Result<(), ReactorError> {
        if self.udp_registered {
            self.poller
                .delete(self.udp_source.as_raw_fd())
                .map_err(ReactorError::PollerModify)?;
            self.udp_registered = false;
        }
        self.service.begin_shutdown();
        for registration in self.registrations.values() {
            self.poller
                .modify(
                    registration.source.as_raw_fd(),
                    registration.key,
                    Interest::READ_WRITE,
                )
                .map_err(ReactorError::PollerModify)?;
        }
        Ok(())
    }

    /// Waits for native readiness and performs one bounded fair drain turn.
    ///
    /// `None` waits indefinitely until I/O or a notifier wake. A synthetic
    /// continuation never blocks because it represents already-buffered work.
    ///
    /// # Errors
    ///
    /// Preserves bounded allocation, poller wait/re-arm, wake-socket,
    /// transport-driver, graceful-shutdown, and recovery failures.
    pub fn poll(&mut self, timeout: Option<Duration>) -> Result<ReactorBatch, ReactorError> {
        self.ready.clear();
        self.collect_continuations();
        if self.ready.is_empty() {
            self.poller
                .wait(&mut self.ready, timeout)
                .map_err(ReactorError::PollerWait)?;
            coalesce_ready(&mut self.ready);
        }

        let mut inbound = Vec::new();
        inbound
            .try_reserve(self.config.ready_events)
            .map_err(|_| ReactorError::AllocationFailed)?;
        let mut events = Vec::new();
        events
            .try_reserve_exact(self.config.batch_events())
            .map_err(|_| ReactorError::AllocationFailed)?;
        let mut order = Vec::new();
        order
            .try_reserve_exact(self.config.batch_events())
            .map_err(|_| ReactorError::AllocationFailed)?;
        let mut notified = false;

        for index in 0..self.ready.len() {
            let ready = self.ready[index];
            match ready.key {
                WAKE_KEY => {
                    notified = true;
                    self.drain_wake()?;
                    self.poller
                        .modify(self.wake_reader.as_raw_fd(), WAKE_KEY, Interest::READ)
                        .map_err(ReactorError::PollerModify)?;
                }
                UDP_KEY if self.udp_registered => {
                    if ready.terminal {
                        return Err(ReactorError::UdpReadinessTerminal);
                    }
                    self.process_udp(&mut inbound, &mut events, &mut order)?;
                    self.poller
                        .modify(self.udp_source.as_raw_fd(), UDP_KEY, Interest::READ)
                        .map_err(ReactorError::PollerModify)?;
                }
                key => {
                    let Some(id) = self.by_key.get(&key).copied() else {
                        continue;
                    };
                    self.process_reliable(id, ready, &mut inbound, &mut events, &mut order)?;
                }
            }
        }

        Ok(ReactorBatch {
            inbound,
            events,
            order,
            notified,
        })
    }

    fn register_reliable(&mut self, id: ConnectionId) -> Result<(), ReactorError> {
        if self.registrations.contains_key(&id) {
            return Err(ReactorError::DuplicateRegistration);
        }
        if self.service.reliable_nonblocking(id) != Some(true) {
            let recovery = self
                .service
                .fail_connection(id)
                .map_err(ReactorError::Service)?;
            return Err(ReactorError::ReliableRegistration {
                source: io::Error::new(io::ErrorKind::InvalidInput, "blocking reliable driver"),
                recovery,
            });
        }

        let key = self.allocate_key()?;
        let source = match self.service.try_clone_reliable_socket(id) {
            Ok(source) => source,
            Err(source) => return Err(self.rollback_registration(id, source)),
        };
        if let Err(source_error) = self.poller.add(source.as_raw_fd(), key, Interest::READ) {
            return Err(self.rollback_registration(id, source_error));
        }

        self.by_key.insert(key, id);
        self.registrations.insert(
            id,
            ReliableRegistration {
                key,
                source,
                buffered_continuation: false,
            },
        );
        Ok(())
    }

    fn prepare_reliable_registration(&mut self, id: ConnectionId) -> Result<(), ReactorError> {
        if self.registrations.contains_key(&id) {
            return Err(ReactorError::DuplicateRegistration);
        }
        if self.next_key == usize::MAX {
            return Err(ReactorError::RegistrationKeyExhausted);
        }
        self.registrations
            .try_reserve(1)
            .map_err(|_| ReactorError::AllocationFailed)?;
        self.by_key
            .try_reserve(1)
            .map_err(|_| ReactorError::AllocationFailed)?;
        self.continuations
            .try_reserve(1)
            .map_err(|_| ReactorError::AllocationFailed)
    }

    fn rollback_registration(&mut self, id: ConnectionId, source: io::Error) -> ReactorError {
        match self.service.fail_connection(id) {
            Ok(recovery) => ReactorError::ReliableRegistration { source, recovery },
            Err(rollback) => ReactorError::RegistrationRollback {
                source,
                rollback: Box::new(rollback),
            },
        }
    }

    fn allocate_key(&mut self) -> Result<usize, ReactorError> {
        let key = self.next_key;
        self.next_key = self
            .next_key
            .checked_add(1)
            .ok_or(ReactorError::RegistrationKeyExhausted)?;
        Ok(key)
    }

    fn collect_continuations(&mut self) {
        while self.ready.len() < self.config.ready_events {
            let Some(key) = self.continuations.pop_front() else {
                break;
            };
            let Some(id) = self.by_key.get(&key).copied() else {
                continue;
            };
            let Some(registration) = self.registrations.get_mut(&id) else {
                continue;
            };
            if !registration.buffered_continuation {
                continue;
            }
            registration.buffered_continuation = false;
            self.ready.push(OsReady {
                key,
                readable: true,
                writable: self.service.reliable_wants_write(id),
                terminal: false,
            });
        }
    }

    fn process_udp(
        &mut self,
        inbound: &mut Vec<ReceivedMessage>,
        events: &mut Vec<ReactorEvent>,
        order: &mut Vec<BatchSlot>,
    ) -> Result<(), ReactorError> {
        for _ in 0..self.config.reads_per_source {
            match self.service.receive_udp() {
                Ok(message) => push_inbound(inbound, order, message)?,
                Err(error) if is_would_block(&error) => break,
                Err(error) => {
                    let persistent_io = service_io_kind(&error).is_some();
                    push_event(events, order, ReactorEvent::DatagramRejected(error));
                    if persistent_io {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn process_reliable(
        &mut self,
        id: ConnectionId,
        ready: OsReady,
        inbound: &mut Vec<ReceivedMessage>,
        events: &mut Vec<ReactorEvent>,
        order: &mut Vec<BatchSlot>,
    ) -> Result<(), ReactorError> {
        let mut still_active = true;
        if ready.readable {
            let mut exhausted = true;
            for _ in 0..self.config.reads_per_source {
                match self.service.receive_reliable(id) {
                    Ok(message) => push_inbound(inbound, order, message)?,
                    Err(error) if is_would_block(&error) => {
                        exhausted = false;
                        break;
                    }
                    Err(error) => {
                        self.fail_reliable(
                            id,
                            ReactorSourceError::Transport(error),
                            events,
                            order,
                        )?;
                        still_active = false;
                        exhausted = false;
                        break;
                    }
                }
            }
            if exhausted && still_active {
                self.schedule_continuation(id)?;
            }
        }

        if still_active && ready.writable {
            match self.service.poll_write(id) {
                Ok(batch) => {
                    let committed = batch.into_committed();
                    if !committed.is_empty() {
                        push_event(
                            events,
                            order,
                            ReactorEvent::ReliableCommitted {
                                connection_id: id,
                                messages: committed,
                            },
                        );
                    }
                }
                Err(error) => {
                    self.fail_reliable(id, ReactorSourceError::Transport(error), events, order)?;
                    still_active = false;
                }
            }
        }

        if still_active && ready.terminal {
            self.fail_reliable(id, ReactorSourceError::ReadinessTerminal, events, order)?;
            still_active = false;
        }

        if still_active
            && self.service.is_shutting_down()
            && self.service.reliable_write_drained(id)
        {
            match self.service.shutdown_connection(id) {
                Ok(ServiceShutdownProgress::Pending) => {}
                Ok(ServiceShutdownProgress::Complete) => {
                    self.remove_registration(id)
                        .map_err(ReactorError::PollerModify)?;
                    push_event(
                        events,
                        order,
                        ReactorEvent::ReliableClosed { connection_id: id },
                    );
                    still_active = false;
                }
                Err(error) => {
                    self.fail_reliable(id, ReactorSourceError::Transport(error), events, order)?;
                    still_active = false;
                }
            }
        }

        if still_active && let Err(source) = self.rearm_reliable(id) {
            self.fail_reliable(id, ReactorSourceError::Readiness(source), events, order)?;
        }
        Ok(())
    }

    fn schedule_continuation(&mut self, id: ConnectionId) -> Result<(), ReactorError> {
        let registration = self
            .registrations
            .get_mut(&id)
            .ok_or(ReactorError::InternalRegistrationInvariant)?;
        if !registration.buffered_continuation {
            registration.buffered_continuation = true;
            self.continuations.push_back(registration.key);
        }
        Ok(())
    }

    fn rearm_reliable(&self, id: ConnectionId) -> io::Result<()> {
        let registration = self.registrations.get(&id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "reliable registration missing")
        })?;
        let interest = if self.service.reliable_wants_write(id) {
            Interest::READ_WRITE
        } else {
            Interest::READ
        };
        self.poller
            .modify(registration.source.as_raw_fd(), registration.key, interest)
    }

    fn rearm_reliable_or_recover(&mut self, id: ConnectionId) -> Result<(), ReactorError> {
        if let Err(source) = self.rearm_reliable(id) {
            self.remove_registration(id).ok();
            let recovery = self
                .service
                .fail_connection(id)
                .map_err(ReactorError::Service)?;
            return Err(ReactorError::ReliableRegistration { source, recovery });
        }
        Ok(())
    }

    fn fail_reliable(
        &mut self,
        id: ConnectionId,
        mut error: ReactorSourceError,
        events: &mut Vec<ReactorEvent>,
        order: &mut Vec<BatchSlot>,
    ) -> Result<(), ReactorError> {
        if let Err(source) = self.remove_registration(id)
            && matches!(error, ReactorSourceError::ReadinessTerminal)
        {
            error = ReactorSourceError::Readiness(source);
        }
        let recovery = self
            .service
            .fail_connection(id)
            .map_err(ReactorError::Service)?;
        push_event(
            events,
            order,
            ReactorEvent::ReliableFailed {
                connection_id: id,
                error,
                recovery,
            },
        );
        Ok(())
    }

    fn remove_registration(&mut self, id: ConnectionId) -> io::Result<()> {
        let Some(registration) = self.registrations.remove(&id) else {
            return Ok(());
        };
        self.by_key.remove(&registration.key);
        self.poller.delete(registration.source.as_raw_fd())
    }

    fn drain_wake(&self) -> Result<(), ReactorError> {
        let mut storage = [0_u8; 128];
        let mut reader = &self.wake_reader;
        loop {
            match reader.read(&mut storage) {
                Ok(0) => return Err(ReactorError::WakeClosed),
                Ok(_) => {}
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                Err(source) => return Err(ReactorError::WakeSocket(source)),
            }
        }
    }
}

impl fmt::Debug for TransportReactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportReactor")
            .field("reliable_registrations", &self.registrations.len())
            .field("buffered_continuations", &self.continuations.len())
            .field("udp_registered", &self.udp_registered)
            .field("shutting_down", &self.service.is_shutting_down())
            .finish_non_exhaustive()
    }
}

impl Drop for TransportReactor {
    fn drop(&mut self) {
        for registration in self.registrations.values() {
            let _ = self.poller.delete(registration.source.as_raw_fd());
        }
        if self.udp_registered {
            let _ = self.poller.delete(self.udp_source.as_raw_fd());
        }
        let _ = self.poller.delete(self.wake_reader.as_raw_fd());
    }
}

fn is_would_block(error: &ServiceError) -> bool {
    service_io_kind(error) == Some(io::ErrorKind::WouldBlock)
}

fn service_io_kind(error: &ServiceError) -> Option<io::ErrorKind> {
    match error {
        ServiceError::UdpDriver(source) => source.io_kind(),
        ServiceError::Tcp(source) => source.io_kind(),
        ServiceError::Tls(source) => source.io_kind(),
        _ => None,
    }
}

fn push_inbound(
    inbound: &mut Vec<ReceivedMessage>,
    order: &mut Vec<BatchSlot>,
    message: ReceivedMessage,
) -> Result<(), ReactorError> {
    if inbound.len() == inbound.capacity() {
        inbound
            .try_reserve(1)
            .map_err(|_| ReactorError::AllocationFailed)?;
    }
    let index = inbound.len();
    inbound.push(message);
    order.push(BatchSlot::Inbound(index));
    Ok(())
}

fn push_event(events: &mut Vec<ReactorEvent>, order: &mut Vec<BatchSlot>, event: ReactorEvent) {
    let index = events.len();
    events.push(event);
    order.push(BatchSlot::Event(index));
}

fn coalesce_ready(ready: &mut Vec<OsReady>) {
    ready.sort_unstable_by_key(|event| event.key);
    let mut output = 0_usize;
    for input in 0..ready.len() {
        let event = ready[input];
        if output != 0 && ready[output - 1].key == event.key {
            let combined = &mut ready[output - 1];
            combined.readable |= event.readable;
            combined.writable |= event.writable;
            combined.terminal |= event.terminal;
        } else {
            ready[output] = event;
            output += 1;
        }
    }
    ready.truncate(output);
}

/// Reactor construction, registration, wait, or orchestration failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReactorError {
    /// Ready-event capacity was zero or excessive.
    InvalidReadyEventLimit {
        /// Rejected value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Per-source read budget was zero or excessive.
    InvalidReadBudget {
        /// Rejected value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Combined result capacity exceeded its hard bound.
    BatchLimitExceeded {
        /// Attempted maximum result records.
        attempted: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Readiness-driven UDP requires nonblocking socket operation.
    BlockingUdpDriver,
    /// Readiness-driven reliable I/O requires a nonblocking driver.
    BlockingReliableDriver,
    /// A reliable identity was registered twice.
    DuplicateRegistration,
    /// Monotonic readiness keys were exhausted; keys are never reused.
    RegistrationKeyExhausted,
    /// Bounded allocation failed.
    AllocationFailed,
    /// Socket-handle duplication failed.
    DuplicateSocket(io::Error),
    /// Wake-socket creation, configuration, or I/O failed.
    WakeSocket(io::Error),
    /// The reactor's wake peer closed unexpectedly.
    WakeClosed,
    /// Native readiness backend construction failed.
    PollerCreate(io::Error),
    /// Initial native source registration failed.
    PollerRegister(io::Error),
    /// Native source re-arm or removal failed.
    PollerModify(io::Error),
    /// Native readiness wait failed.
    PollerWait(io::Error),
    /// UDP readiness reached a terminal socket condition.
    UdpReadinessTerminal,
    /// Transport service operation failed.
    Service(ServiceError),
    /// Reliable readiness registration failed after driver attachment; all
    /// admitted work is included in the recovery object.
    ReliableRegistration {
        /// Native registration failure.
        source: io::Error,
        /// Ambiguous and provably unsent work recovered from the flow.
        recovery: FailedConnection,
    },
    /// Registration failure was followed by an internal rollback failure.
    RegistrationRollback {
        /// Native registration failure.
        source: io::Error,
        /// Unexpected service rollback failure.
        rollback: Box<ServiceError>,
    },
    /// Reactor and registration indexes became inconsistent.
    InternalRegistrationInvariant,
}

impl ReactorError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::InvalidReadyEventLimit { .. } => "invalid-ready-event-limit",
            Self::InvalidReadBudget { .. } => "invalid-read-budget",
            Self::BatchLimitExceeded { .. } => "batch-limit-exceeded",
            Self::BlockingUdpDriver => "blocking-udp-driver",
            Self::BlockingReliableDriver => "blocking-reliable-driver",
            Self::DuplicateRegistration => "duplicate-registration",
            Self::RegistrationKeyExhausted => "registration-key-exhausted",
            Self::AllocationFailed => "allocation-failed",
            Self::DuplicateSocket(_) => "duplicate-socket",
            Self::WakeSocket(_) => "wake-socket",
            Self::WakeClosed => "wake-closed",
            Self::PollerCreate(_) => "poller-create",
            Self::PollerRegister(_) => "poller-register",
            Self::PollerModify(_) => "poller-modify",
            Self::PollerWait(_) => "poller-wait",
            Self::UdpReadinessTerminal => "udp-readiness-terminal",
            Self::Service(_) => "service",
            Self::ReliableRegistration { .. } => "reliable-registration",
            Self::RegistrationRollback { .. } => "registration-rollback",
            Self::InternalRegistrationInvariant => "internal-registration-invariant",
        }
    }

    /// Returns recovered reliable work when registration failed after attach.
    #[must_use]
    pub const fn recovery(&self) -> Option<&FailedConnection> {
        match self {
            Self::ReliableRegistration { recovery, .. } => Some(recovery),
            _ => None,
        }
    }
}

impl fmt::Display for ReactorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP transport reactor error: {}", self.class())
    }
}

impl StdError for ReactorError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::DuplicateSocket(source)
            | Self::WakeSocket(source)
            | Self::PollerCreate(source)
            | Self::PollerRegister(source)
            | Self::PollerModify(source)
            | Self::PollerWait(source)
            | Self::ReliableRegistration { source, .. }
            | Self::RegistrationRollback { source, .. } => Some(source),
            Self::Service(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct Interest {
    readable: bool,
    writable: bool,
}

impl Interest {
    const READ: Self = Self {
        readable: true,
        writable: false,
    };
    const READ_WRITE: Self = Self {
        readable: true,
        writable: true,
    };
}

#[derive(Clone, Copy, Debug)]
struct OsReady {
    key: usize,
    readable: bool,
    writable: bool,
    terminal: bool,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct OsPoller {
    descriptor: OwnedFd,
    events: Box<[libc::epoll_event]>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl OsPoller {
    fn new(capacity: usize) -> io::Result<Self> {
        // SAFETY: `epoll_create1` has no pointer arguments; a nonnegative
        // return value is a newly owned descriptor.
        let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful `epoll_create1` transfers unique descriptor
        // ownership to this value.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut events = Vec::new();
        events.try_reserve_exact(capacity).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "epoll event allocation failed")
        })?;
        events.resize_with(capacity, || libc::epoll_event { events: 0, u64: 0 });
        Ok(Self {
            descriptor,
            events: events.into_boxed_slice(),
        })
    }

    fn add(&self, source: RawFd, key: usize, interest: Interest) -> io::Result<()> {
        self.control(libc::EPOLL_CTL_ADD, source, key, interest)
    }

    fn modify(&self, source: RawFd, key: usize, interest: Interest) -> io::Result<()> {
        self.control(libc::EPOLL_CTL_MOD, source, key, interest)
    }

    fn delete(&self, source: RawFd) -> io::Result<()> {
        // SAFETY: descriptors are valid for the duration of the call; Linux
        // ignores the event pointer for `EPOLL_CTL_DEL`.
        let result = unsafe {
            libc::epoll_ctl(
                self.descriptor.as_raw_fd(),
                libc::EPOLL_CTL_DEL,
                source,
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(source)
            }
        }
    }

    fn wait(&mut self, output: &mut Vec<OsReady>, timeout: Option<Duration>) -> io::Result<()> {
        let deadline = timeout.and_then(|duration| Instant::now().checked_add(duration));
        loop {
            let milliseconds = epoll_timeout(timeout, deadline);
            let maximum = i32::try_from(self.events.len()).unwrap_or(i32::MAX);
            // SAFETY: the event slice is initialized writable storage and the
            // descriptor is an owned epoll instance.
            let count = unsafe {
                libc::epoll_wait(
                    self.descriptor.as_raw_fd(),
                    self.events.as_mut_ptr(),
                    maximum,
                    milliseconds,
                )
            };
            if count >= 0 {
                for event in &self.events[..usize::try_from(count).unwrap_or(0)] {
                    let flags = event.events as i32;
                    output.push(OsReady {
                        key: usize::try_from(event.u64).unwrap_or(usize::MAX),
                        readable: flags & libc::EPOLLIN != 0,
                        writable: flags & libc::EPOLLOUT != 0,
                        terminal: flags & (libc::EPOLLERR | libc::EPOLLHUP | libc::EPOLLRDHUP) != 0,
                    });
                }
                return Ok(());
            }
            let source = io::Error::last_os_error();
            if source.kind() != io::ErrorKind::Interrupted {
                return Err(source);
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Ok(());
            }
        }
    }

    fn control(
        &self,
        operation: i32,
        source: RawFd,
        key: usize,
        interest: Interest,
    ) -> io::Result<()> {
        let mut flags = libc::EPOLLONESHOT | libc::EPOLLERR | libc::EPOLLHUP | libc::EPOLLRDHUP;
        if interest.readable {
            flags |= libc::EPOLLIN;
        }
        if interest.writable {
            flags |= libc::EPOLLOUT;
        }
        let mut event = libc::epoll_event {
            events: flags as u32,
            u64: key as u64,
        };
        // SAFETY: all descriptors are live and `event` is initialized for the
        // duration of the control call.
        let result =
            unsafe { libc::epoll_ctl(self.descriptor.as_raw_fd(), operation, source, &mut event) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn epoll_timeout(original: Option<Duration>, deadline: Option<Instant>) -> i32 {
    if original.is_none() {
        return -1;
    }
    let remaining = deadline
        .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
        .unwrap_or(Duration::ZERO);
    if remaining.is_zero() {
        return 0;
    }
    let milliseconds = remaining.as_millis().saturating_add(1);
    i32::try_from(milliseconds).unwrap_or(i32::MAX)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
struct OsPoller {
    descriptor: OwnedFd,
    events: Box<[libc::kevent]>,
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
impl OsPoller {
    fn new(capacity: usize) -> io::Result<Self> {
        // SAFETY: `kqueue` has no arguments; a nonnegative result is a newly
        // owned descriptor.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful `kqueue` transfers unique descriptor ownership.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: `descriptor` is live and `F_SETFD` consumes only the integer
        // flag value. Ownership remains with `descriptor` on every outcome.
        if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut events = Vec::new();
        events.try_reserve_exact(capacity).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "kqueue event allocation failed")
        })?;
        events.resize_with(capacity, zero_kevent);
        Ok(Self {
            descriptor,
            events: events.into_boxed_slice(),
        })
    }

    fn add(&self, source: RawFd, key: usize, interest: Interest) -> io::Result<()> {
        self.modify(source, key, interest)
    }

    fn modify(&self, source: RawFd, key: usize, interest: Interest) -> io::Result<()> {
        if interest.readable {
            self.change(source, key, libc::EVFILT_READ, true)?;
        } else {
            self.change(source, key, libc::EVFILT_READ, false)?;
        }
        if interest.writable {
            self.change(source, key, libc::EVFILT_WRITE, true)
        } else {
            self.change(source, key, libc::EVFILT_WRITE, false)
        }
    }

    fn delete(&self, source: RawFd) -> io::Result<()> {
        let read = self.change(source, 0, libc::EVFILT_READ, false);
        let write = self.change(source, 0, libc::EVFILT_WRITE, false);
        read.and(write)
    }

    fn wait(&mut self, output: &mut Vec<OsReady>, timeout: Option<Duration>) -> io::Result<()> {
        let deadline = timeout.and_then(|duration| Instant::now().checked_add(duration));
        loop {
            let remaining = deadline.map(|deadline| {
                deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::ZERO)
            });
            let timespec = remaining.map(duration_timespec);
            let timeout_pointer = timespec.as_ref().map_or(std::ptr::null(), |value| value);
            let maximum = i32::try_from(self.events.len()).unwrap_or(i32::MAX);
            // SAFETY: the event slice is initialized writable storage; change
            // pointers are null because this call only waits.
            let count = unsafe {
                libc::kevent(
                    self.descriptor.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    self.events.as_mut_ptr(),
                    maximum,
                    timeout_pointer,
                )
            };
            if count >= 0 {
                for event in &self.events[..usize::try_from(count).unwrap_or(0)] {
                    output.push(OsReady {
                        key: event.udata as usize,
                        readable: event.filter == libc::EVFILT_READ,
                        writable: event.filter == libc::EVFILT_WRITE,
                        terminal: event.flags & (libc::EV_EOF | libc::EV_ERROR) != 0,
                    });
                }
                return Ok(());
            }
            let source = io::Error::last_os_error();
            if source.kind() != io::ErrorKind::Interrupted {
                return Err(source);
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Ok(());
            }
        }
    }

    fn change(&self, source: RawFd, key: usize, filter: i16, enable: bool) -> io::Result<()> {
        let ident = libc::uintptr_t::try_from(source)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative descriptor"))?;
        let flags = if enable {
            libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT
        } else {
            libc::EV_DELETE
        };
        let change = libc::kevent {
            ident,
            filter,
            flags,
            fflags: 0,
            data: 0,
            udata: key as *mut libc::c_void,
        };
        // SAFETY: `change` is initialized and borrowed for this call; no event
        // output is requested.
        let result = unsafe {
            libc::kevent(
                self.descriptor.as_raw_fd(),
                &raw const change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            let source = io::Error::last_os_error();
            if !enable && source.raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(source)
            }
        }
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn zero_kevent() -> libc::kevent {
    libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn duration_timespec(duration: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: libc::time_t::try_from(duration.as_secs()).unwrap_or(libc::time_t::MAX),
        tv_nsec: libc::c_long::from(duration.subsec_nanos()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
    use std::sync::Arc;
    use std::time::Duration;

    use super::{
        MAX_BATCH_EVENTS, MAX_READS_PER_SOURCE, MAX_READY_EVENTS, ReactorBatchItem, ReactorConfig,
        ReactorError, ReactorEvent, TransportReactor, coalesce_ready,
    };
    use crate::sip::transport::connection::QueueLimits;
    use crate::sip::transport::destination::Destination;
    use crate::sip::transport::manager::ManagerConfig;
    use crate::sip::transport::service::{ServiceConfig, TransportService};
    use crate::sip::transport::tcp_driver::{TcpDriver, TcpDriverConfig};
    use crate::sip::transport::udp::UdpConfig;
    use crate::sip::transport::udp_driver::{UdpDriver, UdpDriverConfig};

    const UDP_REQUEST: &[u8] = b"OPTIONS sip:runtime@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP caller.example.com;branch=z9hG4bK-reactor;rport\r\n\
From: <sip:caller@example.com>;tag=a\r\n\
To: <sip:runtime@example.com>\r\n\
Call-ID: reactor-udp@example.com\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n";

    const TCP_REQUEST: &[u8] = b"OPTIONS sip:runtime@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP caller.example.com;branch=z9hG4bK-reactor\r\n\
From: <sip:caller@example.com>;tag=a\r\n\
To: <sip:runtime@example.com>\r\n\
Call-ID: reactor-tcp@example.com\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n";

    fn reactor(reads_per_source: usize) -> TransportReactor {
        let udp = UdpDriver::bind(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            UdpDriverConfig::new(4_096).unwrap_or_else(|_| panic!("UDP config")),
        )
        .unwrap_or_else(|_| panic!("UDP bind"));
        let service = TransportService::new(
            udp,
            ServiceConfig::new(
                ManagerConfig {
                    max_connections: 8,
                    queue_limits: QueueLimits {
                        messages: 8,
                        bytes: 32 * 1024,
                    },
                },
                UdpConfig::new(4_096).unwrap_or_else(|_| panic!("UDP admission")),
                4,
            )
            .unwrap_or_else(|_| panic!("service config")),
        )
        .unwrap_or_else(|_| panic!("service"));
        TransportReactor::new(
            service,
            ReactorConfig::new(32, reads_per_source).unwrap_or_else(|_| panic!("reactor config")),
        )
        .unwrap_or_else(|_| panic!("reactor"))
    }

    #[test]
    fn configuration_enforces_individual_and_combined_bounds() {
        assert!(matches!(
            ReactorConfig::new(0, 1),
            Err(ReactorError::InvalidReadyEventLimit { .. })
        ));
        assert!(matches!(
            ReactorConfig::new(1, 0),
            Err(ReactorError::InvalidReadBudget { .. })
        ));
        assert!(ReactorConfig::new(MAX_READY_EVENTS, MAX_READS_PER_SOURCE).is_ok());
        let config = ReactorConfig::default();
        assert!(config.batch_events() <= MAX_BATCH_EVENTS);
    }

    #[test]
    fn duplicate_native_records_are_coalesced_without_reordering_keys() {
        let mut ready = vec![
            super::OsReady {
                key: 8,
                readable: true,
                writable: false,
                terminal: false,
            },
            super::OsReady {
                key: 3,
                readable: false,
                writable: true,
                terminal: false,
            },
            super::OsReady {
                key: 8,
                readable: false,
                writable: true,
                terminal: true,
            },
        ];
        coalesce_ready(&mut ready);
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].key, 3);
        assert_eq!(ready[1].key, 8);
        assert!(ready[1].readable);
        assert!(ready[1].writable);
        assert!(ready[1].terminal);
    }

    #[test]
    fn notifier_wakes_a_blocked_native_wait_without_fake_transport_work() {
        let mut reactor = reactor(4);
        let notifier = reactor
            .try_notifier()
            .unwrap_or_else(|_| panic!("notifier"));
        assert!(notifier.notify().is_ok());
        let batch = reactor
            .poll(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("poll"));
        assert!(batch.notified());
        assert!(batch.events().is_empty());
    }

    #[test]
    fn udp_rejection_isolated_from_following_valid_datagram() {
        let mut reactor = reactor(4);
        let sender =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("sender bind"));
        let target = reactor.service().udp_local_addr();
        assert!(sender.send_to(b"not SIP", target).is_ok());
        assert!(sender.send_to(UDP_REQUEST, target).is_ok());

        let first = reactor
            .poll(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("poll"));
        assert!(
            first
                .events()
                .iter()
                .any(|event| matches!(event, ReactorEvent::DatagramRejected(_)))
        );
        let first_ordered = first.iter().collect::<Vec<_>>();
        assert!(matches!(
            first_ordered.first(),
            Some(ReactorBatchItem::Event(ReactorEvent::DatagramRejected(_)))
        ));

        if first.inbound().is_empty() {
            let second = reactor
                .poll(Some(Duration::from_secs(1)))
                .unwrap_or_else(|_| panic!("second poll"));
            assert_eq!(second.inbound().len(), 1);
            assert!(matches!(
                second.iter().next(),
                Some(ReactorBatchItem::Inbound(_))
            ));
        } else {
            assert_eq!(first.inbound().len(), 1);
            assert!(matches!(
                first_ordered.as_slice(),
                [
                    ReactorBatchItem::Event(ReactorEvent::DatagramRejected(_)),
                    ReactorBatchItem::Inbound(_)
                ]
            ));
        }
    }

    #[test]
    fn reliable_pipeline_continues_without_waiting_for_new_socket_readiness() {
        let mut reactor = reactor(1);
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("listener"));
        let destination = Destination::tcp(
            listener
                .local_addr()
                .unwrap_or_else(|_| panic!("listener address")),
        )
        .unwrap_or_else(|_| panic!("destination"));
        let plan = reactor
            .plan_reliable(destination)
            .unwrap_or_else(|_| panic!("plan"));
        let driver = TcpDriver::connect(
            plan.destination(),
            plan.flow_id(),
            TcpDriverConfig::default(),
        )
        .unwrap_or_else(|_| panic!("connect"));
        let (mut peer, _) = listener.accept().unwrap_or_else(|_| panic!("accept"));
        reactor
            .attach_tcp(plan.id(), driver)
            .unwrap_or_else(|_| panic!("attach"));

        let mut pipelined = Vec::new();
        pipelined.extend_from_slice(TCP_REQUEST);
        pipelined.extend_from_slice(TCP_REQUEST);
        assert!(peer.write_all(&pipelined).is_ok());

        let first = reactor
            .poll(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("first poll"));
        assert_eq!(first.inbound().len(), 1);
        let second = reactor
            .poll(Some(Duration::ZERO))
            .unwrap_or_else(|_| panic!("continuation poll"));
        assert_eq!(second.inbound().len(), 1);

        let outbound: Arc<[u8]> = Arc::from(TCP_REQUEST);
        reactor
            .enqueue_reliable(plan.id(), Arc::clone(&outbound))
            .unwrap_or_else(|_| panic!("enqueue"));
        let committed = reactor
            .poll(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("write poll"));
        assert!(
            committed.events().iter().any(|event| matches!(
                event,
                ReactorEvent::ReliableCommitted {
                    connection_id,
                    messages
                } if *connection_id == plan.id() && messages.len() == 1
            )),
            "unexpected write batch: {committed:?}"
        );
        let mut received = vec![0_u8; outbound.len()];
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("read timeout"));
        assert!(peer.read_exact(&mut received).is_ok());
        assert_eq!(received.as_slice(), outbound.as_ref());

        reactor
            .begin_shutdown()
            .unwrap_or_else(|_| panic!("begin shutdown"));
        let closed = reactor
            .poll(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("shutdown poll"));
        assert!(closed.events().iter().any(|event| matches!(
            event,
            ReactorEvent::ReliableClosed { connection_id } if *connection_id == plan.id()
        )));
        assert!(reactor.service().is_drained());
    }
}
