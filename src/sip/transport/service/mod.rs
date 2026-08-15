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

//! Commit-aware bounded signaling transport orchestration.
//!
//! One signaling actor owns this service. It unifies UDP and established
//! TCP/TLS flows without adding locks or hiding blocking connection setup.
//! Reliable connection planning is separate from driver attachment so a
//! connector worker can perform DNS, TCP establishment, and TLS verification
//! without stalling the actor.
//!
//! Outbound reliable messages remain in bounded per-flow queues until the
//! socket driver accepts ownership. A completed poll returns the exact shared
//! message objects whose entire wire representation reached the kernel. This
//! lets transaction state distinguish `NotSent`, `Sent`, and ambiguous partial
//! failure without parsing logs or guessing from socket errors.

mod config;
mod connection;
mod error;
mod model;

pub use config::{MAX_WRITE_COMMITS_PER_POLL, ServiceConfig};
pub use error::ServiceError;
pub use model::{
    FailedConnection, ReliableConnectionPlan, RouteSendDisposition, ServiceShutdownProgress,
    WriteBatch,
};

use connection::{ActiveFlow, ReliableDriver, box_one, flow_id};

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;

use super::ReceivedMessage;
use super::connection::{ConnectionId, ConnectionState};
use super::destination::{Destination, Protocol};
use super::failover::WireCommitState;
use super::flow::{EgressRoute, FlowId};
use super::manager::TransportManager;
use super::tcp_driver::TcpDriver;
use super::tls_driver::TlsDriver;
use super::udp::OutboundDatagram;
use super::udp_driver::UdpDriver;

/// Actor-owned UDP and reliable signaling transport service.
pub struct TransportService {
    config: ServiceConfig,
    udp: UdpDriver,
    manager: TransportManager,
    active: HashMap<ConnectionId, ActiveFlow>,
}

impl TransportService {
    /// Creates an empty reliable registry around one explicitly bound UDP socket.
    ///
    /// # Errors
    ///
    /// Rejects invalid service/manager limits.
    pub fn new(udp: UdpDriver, config: ServiceConfig) -> Result<Self, ServiceError> {
        config.manager.validate().map_err(ServiceError::Manager)?;
        if config.write_commits_per_poll == 0
            || config.write_commits_per_poll > MAX_WRITE_COMMITS_PER_POLL
        {
            return Err(ServiceError::InvalidWriteCommitBudget {
                value: config.write_commits_per_poll,
                maximum: MAX_WRITE_COMMITS_PER_POLL,
            });
        }
        let manager = TransportManager::new(config.manager).map_err(ServiceError::Manager)?;
        Ok(Self {
            config,
            udp,
            manager,
            active: HashMap::new(),
        })
    }

    /// Returns UDP local endpoint.
    #[must_use]
    pub const fn udp_local_addr(&self) -> std::net::SocketAddr {
        self.udp.local_addr()
    }

    /// Returns whether the UDP driver is safe for readiness-driven polling.
    #[must_use]
    pub(crate) const fn udp_nonblocking(&self) -> bool {
        self.udp.config().nonblocking()
    }

    /// Duplicates the UDP handle for independent readiness registration.
    pub(crate) fn try_clone_udp_socket(&self) -> io::Result<UdpSocket> {
        self.udp.try_clone_socket()
    }

    /// Plans or reuses a concrete reliable destination without socket I/O.
    ///
    /// A newly created plan should be passed to a connector worker. The actor
    /// later calls [`Self::attach_tcp`] or [`Self::attach_tls`] with the exact
    /// connection and flow identities from this plan.
    ///
    /// # Errors
    ///
    /// Rejects UDP destinations, shutdown, capacity, or allocation failure.
    pub fn plan_reliable(
        &mut self,
        destination: Destination,
    ) -> Result<ReliableConnectionPlan, ServiceError> {
        if destination.protocol() == Protocol::Udp {
            return Err(ServiceError::DatagramReliablePlan);
        }
        let registration = self
            .manager
            .register(destination.clone())
            .map_err(ServiceError::Manager)?;
        let connection = self
            .manager
            .connection(registration.id())
            .ok_or(ServiceError::InternalConnectionInvariant)?;
        let flow_id = flow_id(registration.id())?;
        Ok(ReliableConnectionPlan {
            id: registration.id(),
            flow_id,
            destination,
            created: registration.created(),
            state: connection.state(),
        })
    }

    /// Attaches a verified established TCP driver to connecting state.
    ///
    /// # Errors
    ///
    /// Rejects unknown/duplicate/non-connecting state or driver protocol,
    /// endpoint, and flow mismatches without mutating service indexes.
    pub fn attach_tcp(&mut self, id: ConnectionId, driver: TcpDriver) -> Result<(), ServiceError> {
        self.attach(id, ReliableDriver::Tcp(box_one(driver)?))
    }

    /// Attaches a verified established TLS driver to connecting state.
    ///
    /// The authenticated TLS identity must equal the independently planned
    /// destination identity.
    ///
    /// # Errors
    ///
    /// Preserves all attachment invariants plus TLS identity mismatch.
    pub fn attach_tls(&mut self, id: ConnectionId, driver: TlsDriver) -> Result<(), ServiceError> {
        let connection = self
            .manager
            .connection(id)
            .ok_or(ServiceError::ConnectionNotPlanned)?;
        if connection.destination().tls_identity() != Some(driver.verified_peer_identity()) {
            return Err(ServiceError::DriverIdentityMismatch);
        }
        self.attach(id, ReliableDriver::Tls(box_one(driver)?))
    }

    /// Admits one immutable message to an established reliable flow.
    ///
    /// # Errors
    ///
    /// Preserves shutdown, state, size, queue-count, queue-byte, and allocation
    /// backpressure from the reliable connection manager.
    pub fn enqueue_reliable(
        &mut self,
        id: ConnectionId,
        message: Arc<[u8]>,
    ) -> Result<(), ServiceError> {
        if !self.active.contains_key(&id) {
            return Err(ServiceError::ConnectionNotAttached);
        }
        self.manager
            .enqueue(id, message)
            .map_err(ServiceError::Manager)
    }

    /// Advances one reliable flow under the configured fairness budget.
    ///
    /// Returned messages are proven fully committed and remain in original
    /// queue order. A socket error leaves the in-flight message owned by the
    /// service; call [`Self::fail_connection`] to recover it with conservative
    /// `Unknown` commitment.
    ///
    /// # Errors
    ///
    /// Rejects unknown/unattached state, internal ownership inconsistency,
    /// allocation failure, or driver I/O/TLS failure.
    pub fn poll_write(&mut self, id: ConnectionId) -> Result<WriteBatch, ServiceError> {
        let mut committed = Vec::new();
        committed
            .try_reserve_exact(self.config.write_commits_per_poll)
            .map_err(|_| ServiceError::AllocationFailed)?;

        let (manager, active) = (&mut self.manager, &mut self.active);
        let flow = active
            .get_mut(&id)
            .ok_or(ServiceError::ConnectionNotAttached)?;

        let transport_ready = if flow.driver.has_pending_write() {
            true
        } else {
            flow.driver.flush_transport()?
        };

        while transport_ready && committed.len() < self.config.write_commits_per_poll {
            if flow.driver.has_pending_write() {
                if !flow.driver.flush_send()? {
                    break;
                }
                let message = flow
                    .inflight
                    .take()
                    .ok_or(ServiceError::InternalWriteInvariant)?;
                committed.push(message);
                continue;
            }
            if flow.inflight.is_some() {
                return Err(ServiceError::InternalWriteInvariant);
            }

            let Some(message) = manager.pop_front(id).map_err(ServiceError::Manager)? else {
                break;
            };
            flow.inflight = Some(message);
            let driver_message = Arc::clone(
                flow.inflight
                    .as_ref()
                    .ok_or(ServiceError::InternalWriteInvariant)?,
            );
            if flow.driver.start_send(driver_message)? {
                let message = flow
                    .inflight
                    .take()
                    .ok_or(ServiceError::InternalWriteInvariant)?;
                committed.push(message);
            } else {
                break;
            }
        }

        let connection = manager
            .connection(id)
            .ok_or(ServiceError::InternalConnectionInvariant)?;
        Ok(WriteBatch {
            committed,
            write_pending: flow.inflight.is_some(),
            queued_messages: connection.queued_messages(),
            queued_bytes: connection.queued_bytes(),
        })
    }

    /// Receives one validated UDP SIP message.
    ///
    /// # Errors
    ///
    /// Rejects shutdown and preserves UDP socket/framing/validation failures.
    pub fn receive_udp(&mut self) -> Result<ReceivedMessage, ServiceError> {
        if self.manager.is_shutting_down() {
            return Err(ServiceError::ShuttingDown);
        }
        self.udp.receive().map_err(ServiceError::UdpDriver)
    }

    /// Receives one validated message from an attached reliable flow.
    ///
    /// # Errors
    ///
    /// Rejects unattached identity and preserves TCP/TLS failures.
    pub fn receive_reliable(&mut self, id: ConnectionId) -> Result<ReceivedMessage, ServiceError> {
        self.active
            .get_mut(&id)
            .ok_or(ServiceError::ConnectionNotAttached)?
            .driver
            .receive()
    }

    /// Sends one admitted UDP message immediately.
    ///
    /// Successful return proves the complete datagram was accepted by the
    /// kernel. UDP has no service-side queue.
    ///
    /// # Errors
    ///
    /// Rejects shutdown, unsafe UDP size/protocol, and socket send failure.
    pub fn send_udp(
        &self,
        destination: Destination,
        message: Arc<[u8]>,
    ) -> Result<WireCommitState, ServiceError> {
        if self.manager.is_shutting_down() {
            return Err(ServiceError::ShuttingDown);
        }
        let datagram = OutboundDatagram::new(destination, message, self.config.udp)
            .map_err(ServiceError::UdpAdmission)?;
        self.udp.send(&datagram).map_err(ServiceError::UdpDriver)?;
        Ok(WireCommitState::Sent)
    }

    /// Sends or queues a response using authoritative ingress routing.
    ///
    /// UDP routes target the observed source immediately. TCP/TLS routes reuse
    /// the exact established flow and never open a replacement connection.
    ///
    /// # Errors
    ///
    /// Rejects a stale reliable flow, invalid datagram route, shutdown, queue
    /// pressure, unsafe UDP size, or socket failure.
    pub fn send_route(
        &mut self,
        route: EgressRoute,
        message: Arc<[u8]>,
    ) -> Result<RouteSendDisposition, ServiceError> {
        match route {
            EgressRoute::Datagram(remote) => {
                let destination =
                    Destination::udp(remote).map_err(|_| ServiceError::InvalidDatagramRoute)?;
                self.send_udp(destination, message)?;
                Ok(RouteSendDisposition::DatagramCommitted)
            }
            EgressRoute::ExistingFlow(flow_id) => {
                let id = self
                    .connection_id_for_flow(flow_id)
                    .ok_or(ServiceError::StaleFlow)?;
                self.enqueue_reliable(id, message)?;
                Ok(RouteSendDisposition::ReliableQueued { connection_id: id })
            }
        }
    }

    /// Retires a failed/abandoned reliable connection and recovers its work.
    ///
    /// The in-flight message is conservatively `Unknown`; queued messages are
    /// provably `NotSent`. Payload bytes are not copied.
    ///
    /// # Errors
    ///
    /// Rejects an identity unknown to both manager and active-driver indexes.
    pub fn fail_connection(&mut self, id: ConnectionId) -> Result<FailedConnection, ServiceError> {
        let active = self.active.remove(&id);
        let connection = self.manager.take(id);
        if active.is_none() && connection.is_none() {
            return Err(ServiceError::ConnectionNotPlanned);
        }
        let inflight = active.and_then(|flow| flow.inflight);
        let queued = connection.map_or_else(VecDeque::new, |connection| {
            connection.into_queued_messages()
        });
        Ok(FailedConnection {
            id,
            inflight,
            queued,
        })
    }

    /// Fences new work and transitions established connections to draining.
    ///
    /// Unattached connecting plans are discarded immediately because they own
    /// no socket and cannot contain admitted writes.
    pub fn begin_shutdown(&mut self) {
        self.manager.begin_shutdown();
    }

    /// Gracefully closes one fully drained reliable flow.
    ///
    /// # Errors
    ///
    /// Rejects queued/in-flight work or unattached identity and preserves TCP
    /// shutdown or TLS `close_notify` failure.
    pub fn shutdown_connection(
        &mut self,
        id: ConnectionId,
    ) -> Result<ServiceShutdownProgress, ServiceError> {
        let connection = self
            .manager
            .connection(id)
            .ok_or(ServiceError::ConnectionNotPlanned)?;
        let flow = self
            .active
            .get_mut(&id)
            .ok_or(ServiceError::ConnectionNotAttached)?;
        if connection.queued_messages() != 0 || flow.inflight.is_some() {
            return Err(ServiceError::DrainIncomplete {
                queued_messages: connection.queued_messages(),
                inflight: flow.inflight.is_some(),
            });
        }
        let progress = flow.driver.shutdown()?;
        if progress == ServiceShutdownProgress::Complete {
            self.active.remove(&id);
            self.manager.remove(id);
        }
        Ok(progress)
    }

    /// Returns lifecycle state for a planned reliable identity.
    #[must_use]
    pub fn connection_state(&self, id: ConnectionId) -> Option<ConnectionState> {
        self.manager
            .connection(id)
            .map(super::connection::Connection::state)
    }

    /// Resolves an exact reliable flow generation to its active connection.
    ///
    /// Stale and unattached generations return `None`; numeric reuse cannot
    /// silently route to a different active flow because the driver identity is
    /// checked again.
    #[must_use]
    pub fn connection_id_for_flow(&self, flow_id: FlowId) -> Option<ConnectionId> {
        let id = ConnectionId::new(flow_id.get()).ok()?;
        let flow = self.active.get(&id)?;
        (flow.driver.flow_id() == flow_id).then_some(id)
    }

    /// Returns whether this flow currently needs socket writability.
    #[must_use]
    pub(crate) fn reliable_wants_write(&self, id: ConnectionId) -> bool {
        let Some(flow) = self.active.get(&id) else {
            return false;
        };
        if self.manager.is_shutting_down() {
            return true;
        }
        let queued = self
            .manager
            .connection(id)
            .is_some_and(|connection| connection.queued_messages() != 0);
        queued || flow.inflight.is_some() || flow.driver.wants_socket_write()
    }

    /// Returns whether the flow has no admitted or driver-owned application write.
    #[must_use]
    pub(crate) fn reliable_write_drained(&self, id: ConnectionId) -> bool {
        let Some(flow) = self.active.get(&id) else {
            return true;
        };
        self.manager
            .connection(id)
            .is_none_or(|connection| connection.queued_messages() == 0)
            && flow.inflight.is_none()
            && !flow.driver.has_pending_write()
    }

    /// Returns whether the attached driver is nonblocking.
    #[must_use]
    pub(crate) fn reliable_nonblocking(&self, id: ConnectionId) -> Option<bool> {
        self.active.get(&id).map(|flow| flow.driver.nonblocking())
    }

    /// Duplicates an attached reliable socket for readiness registration.
    pub(crate) fn try_clone_reliable_socket(&self, id: ConnectionId) -> io::Result<TcpStream> {
        self.active
            .get(&id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "connection not attached"))?
            .driver
            .try_clone_socket()
    }

    /// Returns planned reliable connection count.
    #[must_use]
    pub fn reliable_connection_count(&self) -> usize {
        self.manager.len()
    }

    /// Returns whether shutdown fencing is active.
    #[must_use]
    pub const fn is_shutting_down(&self) -> bool {
        self.manager.is_shutting_down()
    }

    /// Returns whether all reliable plans and drivers have retired.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.manager.is_empty() && self.active.is_empty()
    }

    fn attach(&mut self, id: ConnectionId, driver: ReliableDriver) -> Result<(), ServiceError> {
        if self.active.contains_key(&id) {
            return Err(ServiceError::ConnectionAlreadyAttached);
        }
        let connection = self
            .manager
            .connection(id)
            .ok_or(ServiceError::ConnectionNotPlanned)?;
        if connection.state() != ConnectionState::Connecting {
            return Err(ServiceError::ConnectionNotConnecting {
                state: connection.state(),
            });
        }
        if connection.destination().protocol() != driver.protocol() {
            return Err(ServiceError::DriverProtocolMismatch {
                expected: connection.destination().protocol(),
                actual: driver.protocol(),
            });
        }
        if connection.destination().remote() != driver.peer_addr() {
            return Err(ServiceError::DriverPeerMismatch);
        }
        if flow_id(id)? != driver.flow_id() {
            return Err(ServiceError::DriverFlowMismatch);
        }
        self.active
            .try_reserve(1)
            .map_err(|_| ServiceError::AllocationFailed)?;
        self.manager.establish(id).map_err(ServiceError::Manager)?;
        self.active.insert(
            id,
            ActiveFlow {
                driver,
                inflight: None,
            },
        );
        Ok(())
    }
}

impl fmt::Debug for TransportService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportService")
            .field("reliable_connections", &self.manager.len())
            .field("attached_drivers", &self.active.len())
            .field("shutting_down", &self.manager.is_shutting_down())
            .field(
                "udp_family",
                &if self.udp.local_addr().is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                },
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
    use std::sync::Arc;

    use super::{
        RouteSendDisposition, ServiceConfig, ServiceError, ServiceShutdownProgress,
        TransportService, WireCommitState,
    };
    use crate::sip::transport::InboundMessage;
    use crate::sip::transport::connection::QueueLimits;
    use crate::sip::transport::destination::{Destination, Protocol};
    use crate::sip::transport::flow::EgressRoute;
    use crate::sip::transport::manager::ManagerConfig;
    use crate::sip::transport::tcp_driver::{TcpDriver, TcpDriverConfig};
    use crate::sip::transport::udp::UdpConfig;
    use crate::sip::transport::udp_driver::{UdpDriver, UdpDriverConfig};

    const REQUEST: &[u8] = b"OPTIONS sip:runtime@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP caller.example.com;branch=z9hG4bK-one\r\n\
From: <sip:caller@example.com>;tag=a\r\n\
To: <sip:runtime@example.com>\r\n\
Call-ID: one@example.com\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n";

    fn service(write_budget: usize) -> TransportService {
        let udp = UdpDriver::bind(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            UdpDriverConfig::new(2_048)
                .unwrap_or_else(|_| panic!("UDP config"))
                .with_nonblocking(false),
        )
        .unwrap_or_else(|_| panic!("UDP bind"));
        let config = ServiceConfig::new(
            ManagerConfig {
                max_connections: 8,
                queue_limits: QueueLimits {
                    messages: 8,
                    bytes: 16 * 1024,
                },
            },
            UdpConfig::new(2_048).unwrap_or_else(|_| panic!("UDP admission")),
            write_budget,
        )
        .unwrap_or_else(|_| panic!("service config"));
        TransportService::new(udp, config).unwrap_or_else(|_| panic!("service"))
    }

    fn attach_tcp(
        service: &mut TransportService,
    ) -> (super::ReliableConnectionPlan, std::net::TcpStream) {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("listener"));
        let destination = Destination::tcp(
            listener
                .local_addr()
                .unwrap_or_else(|_| panic!("listener address")),
        )
        .unwrap_or_else(|_| panic!("destination"));
        let plan = service
            .plan_reliable(destination)
            .unwrap_or_else(|_| panic!("plan"));
        let driver = TcpDriver::connect(
            plan.destination(),
            plan.flow_id(),
            TcpDriverConfig::default().with_nonblocking(false),
        )
        .unwrap_or_else(|_| panic!("driver"));
        let (server, _) = listener.accept().unwrap_or_else(|_| panic!("accept"));
        service
            .attach_tcp(plan.id(), driver)
            .unwrap_or_else(|_| panic!("attach"));
        (plan, server)
    }

    #[test]
    fn udp_send_and_receive_preserve_commit_and_transport_truth() {
        let mut service = service(4);
        let receiver =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("receiver"));
        let destination = Destination::udp(
            receiver
                .local_addr()
                .unwrap_or_else(|_| panic!("receiver address")),
        )
        .unwrap_or_else(|_| panic!("destination"));
        assert!(matches!(
            service.send_udp(destination, Arc::from(REQUEST)),
            Ok(WireCommitState::Sent)
        ));
        let mut datagram_bytes = vec![0_u8; REQUEST.len()];
        let (length, _) = receiver
            .recv_from(&mut datagram_bytes)
            .unwrap_or_else(|_| panic!("receive"));
        assert_eq!(&datagram_bytes[..length], REQUEST);

        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("sender"));
        let mut udp_request = REQUEST.to_vec();
        let via = b"SIP/2.0/TCP";
        let replacement = b"SIP/2.0/UDP";
        let position = udp_request
            .windows(via.len())
            .position(|window| window == via)
            .unwrap_or_else(|| panic!("Via transport"));
        udp_request[position..position + replacement.len()].copy_from_slice(replacement);
        assert!(
            sender
                .send_to(&udp_request, service.udp_local_addr())
                .is_ok()
        );
        let inbound = service.receive_udp().unwrap_or_else(|_| panic!("inbound"));
        assert!(matches!(inbound.message(), InboundMessage::Request(_)));
        assert_eq!(inbound.ingress().protocol(), Protocol::Udp);
    }

    #[test]
    fn reliable_plan_attach_queue_commit_receive_and_shutdown() {
        let mut service = service(1);
        let (plan, mut server) = attach_tcp(&mut service);
        let duplicate = service
            .plan_reliable(plan.destination().clone())
            .unwrap_or_else(|_| panic!("duplicate"));
        assert_eq!(duplicate.id(), plan.id());
        assert!(!duplicate.created());

        assert!(matches!(
            service.send_route(
                EgressRoute::ExistingFlow(plan.flow_id()),
                Arc::from(REQUEST)
            ),
            Ok(RouteSendDisposition::ReliableQueued { connection_id })
                if connection_id == plan.id()
        ));
        assert!(
            service
                .enqueue_reliable(plan.id(), Arc::from(REQUEST))
                .is_ok()
        );
        let first_batch = service
            .poll_write(plan.id())
            .unwrap_or_else(|_| panic!("write poll"));
        assert_eq!(first_batch.committed().len(), 1);
        assert_eq!(first_batch.queued_messages(), 1);
        let second_batch = service
            .poll_write(plan.id())
            .unwrap_or_else(|_| panic!("second write poll"));
        assert_eq!(second_batch.committed().len(), 1);
        assert!(!second_batch.write_pending());
        assert_eq!(second_batch.queued_messages(), 0);
        assert!(!format!("{second_batch:?}").contains("one@example.com"));

        let mut outbound = vec![0_u8; REQUEST.len() * 2];
        server
            .read_exact(&mut outbound)
            .unwrap_or_else(|_| panic!("server read"));
        assert_eq!(&outbound[..REQUEST.len()], REQUEST);
        assert_eq!(&outbound[REQUEST.len()..], REQUEST);

        server
            .write_all(REQUEST)
            .unwrap_or_else(|_| panic!("server write"));
        let inbound = service
            .receive_reliable(plan.id())
            .unwrap_or_else(|_| panic!("inbound"));
        assert!(matches!(inbound.message(), InboundMessage::Request(_)));
        assert_eq!(inbound.ingress().flow_id(), Some(plan.flow_id()));

        service.begin_shutdown();
        assert!(matches!(
            service.shutdown_connection(plan.id()),
            Ok(ServiceShutdownProgress::Complete)
        ));
        assert!(service.is_drained());
    }

    #[test]
    fn failed_connection_returns_every_provably_unsent_message() {
        let mut service = service(4);
        let (plan, _server) = attach_tcp(&mut service);
        let first: Arc<[u8]> = Arc::from(REQUEST);
        let second: Arc<[u8]> = Arc::from(REQUEST);
        let first_pointer = first.as_ptr();
        assert!(service.enqueue_reliable(plan.id(), first).is_ok());
        assert!(service.enqueue_reliable(plan.id(), second).is_ok());

        let failed = service
            .fail_connection(plan.id())
            .unwrap_or_else(|_| panic!("failed"));
        assert!(failed.inflight().is_none());
        assert_eq!(failed.inflight_commitment(), None);
        assert_eq!(failed.queued().len(), 2);
        assert_eq!(failed.queued()[0].as_ptr(), first_pointer);
        assert!(service.is_drained());
        assert!(!format!("{failed:?}").contains("one@example.com"));
    }

    #[test]
    fn attachment_and_shutdown_invariants_fail_closed() {
        let mut service = service(1);
        let udp = Destination::udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 5060)))
            .unwrap_or_else(|_| panic!("UDP destination"));
        assert!(matches!(
            service.plan_reliable(udp),
            Err(ServiceError::DatagramReliablePlan)
        ));

        let (plan, _server) = attach_tcp(&mut service);
        assert!(
            service
                .enqueue_reliable(plan.id(), Arc::from(REQUEST))
                .is_ok()
        );
        service.begin_shutdown();
        assert!(matches!(
            service.shutdown_connection(plan.id()),
            Err(ServiceError::DrainIncomplete {
                queued_messages: 1,
                inflight: false
            })
        ));
        assert!(matches!(
            service.send_udp(
                Destination::udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 5060)))
                    .unwrap_or_else(|_| panic!("destination")),
                Arc::from(REQUEST)
            ),
            Err(ServiceError::ShuttingDown)
        ));
    }
}
