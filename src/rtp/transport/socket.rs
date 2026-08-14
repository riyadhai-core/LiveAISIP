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

//! Bounded runtime-neutral RTP/RTCP UDP sockets.
//!
//! A socket pair consumes one allocator lease and retains it for exactly the
//! lifetime of both bound sockets. Partial bind or configuration failure drops
//! every acquired operating-system resource and returns the lease to its pool.
//!
//! Receive storage is allocated once per loop, not once per packet. One extra
//! sentinel byte makes datagrams above the configured operational limit
//! detectable even though ordinary UDP receive APIs otherwise truncate them.
//! The hard limit remains the largest portable IPv4 UDP payload.
//!
//! This module owns socket binding and individual datagram admission. Polling,
//! batching, cancellation, queueing, and task lifecycle belong to the later
//! RTP UDP driver so this layer remains independent of a particular async
//! runtime.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use super::allocator::{PortLease, PortPair};

/// Largest portable IPv4 UDP payload.
pub const MAX_MEDIA_DATAGRAM_BYTES: usize = 65_507;

/// Default per-datagram operational limit for RTP and RTCP.
///
/// This comfortably holds ordinary Internet-path RTP/SRTP while rejecting
/// unexpectedly large traffic before it reaches packet parsing or media code.
pub const DEFAULT_MAX_MEDIA_DATAGRAM_BYTES: usize = 2_048;

/// RTP/RTCP socket component.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Component {
    /// Even-port media stream.
    Rtp,
    /// Following odd-port control stream.
    Rtcp,
}

/// Validated socket behavior shared by the RTP and RTCP sockets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketConfig {
    maximum_datagram_bytes: usize,
    nonblocking: bool,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl SocketConfig {
    /// Creates the production-default nonblocking socket policy.
    ///
    /// # Errors
    ///
    /// Rejects a zero datagram limit or one above the portable UDP maximum.
    pub const fn new(maximum_datagram_bytes: usize) -> Result<Self, SocketError> {
        if maximum_datagram_bytes == 0 || maximum_datagram_bytes > MAX_MEDIA_DATAGRAM_BYTES {
            return Err(SocketError::InvalidDatagramLimit {
                value: maximum_datagram_bytes,
                maximum: MAX_MEDIA_DATAGRAM_BYTES,
            });
        }
        Ok(Self {
            maximum_datagram_bytes,
            nonblocking: true,
            read_timeout: None,
            write_timeout: None,
        })
    }

    /// Selects blocking or nonblocking operation.
    ///
    /// # Errors
    ///
    /// Rejects nonblocking mode while a blocking timeout remains configured.
    pub fn with_nonblocking(mut self, nonblocking: bool) -> Result<Self, SocketError> {
        if nonblocking && (self.read_timeout.is_some() || self.write_timeout.is_some()) {
            return Err(SocketError::TimeoutOnNonblockingSocket);
        }
        self.nonblocking = nonblocking;
        Ok(self)
    }

    /// Sets the blocking receive timeout.
    ///
    /// # Errors
    ///
    /// Rejects a zero duration, which operating systems do not accept as a
    /// socket timeout. Timeouts are rejected for nonblocking configurations.
    pub fn with_read_timeout(mut self, timeout: Option<Duration>) -> Result<Self, SocketError> {
        validate_timeout(timeout, self.nonblocking)?;
        self.read_timeout = timeout;
        Ok(self)
    }

    /// Sets the blocking send timeout.
    ///
    /// # Errors
    ///
    /// Rejects zero and rejects timeouts for nonblocking configurations.
    pub fn with_write_timeout(mut self, timeout: Option<Duration>) -> Result<Self, SocketError> {
        validate_timeout(timeout, self.nonblocking)?;
        self.write_timeout = timeout;
        Ok(self)
    }

    /// Returns the admitted datagram size.
    #[must_use]
    pub const fn maximum_datagram_bytes(self) -> usize {
        self.maximum_datagram_bytes
    }

    /// Returns whether sockets use nonblocking operation.
    #[must_use]
    pub const fn nonblocking(self) -> bool {
        self.nonblocking
    }

    /// Returns the configured receive timeout.
    #[must_use]
    pub const fn read_timeout(self) -> Option<Duration> {
        self.read_timeout
    }

    /// Returns the configured send timeout.
    #[must_use]
    pub const fn write_timeout(self) -> Option<Duration> {
        self.write_timeout
    }
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            maximum_datagram_bytes: DEFAULT_MAX_MEDIA_DATAGRAM_BYTES,
            nonblocking: true,
            read_timeout: None,
            write_timeout: None,
        }
    }
}

const fn validate_timeout(timeout: Option<Duration>, nonblocking: bool) -> Result<(), SocketError> {
    if let Some(value) = timeout {
        if value.is_zero() {
            return Err(SocketError::ZeroTimeout);
        }
        if nonblocking {
            return Err(SocketError::TimeoutOnNonblockingSocket);
        }
    }
    Ok(())
}

/// Reusable exact-capacity storage for one receive loop.
pub struct DatagramBuffer {
    bytes: Box<[u8]>,
    maximum: usize,
}

/// Permanent per-call packet scratch storage for receive, RTP serialization,
/// and protected SRTP/SRTCP output.
///
/// The media worker allocates this once before entering its 10 ms loop. Hot
/// paths borrow fixed storage and never create per-packet vectors.
pub struct MediaPacketScratch {
    receive: DatagramBuffer,
    rtp_output: Box<[u8]>,
    protected_output: Box<[u8]>,
}

impl MediaPacketScratch {
    /// Allocates all packet storage transactionally at call setup.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds and allocation failure.
    pub fn new(maximum_datagram_bytes: usize) -> Result<Self, SocketError> {
        let receive = DatagramBuffer::new(maximum_datagram_bytes)?;
        let rtp_output = allocate_zeroed(maximum_datagram_bytes)?;
        let protected_output = allocate_zeroed(maximum_datagram_bytes)?;
        Ok(Self {
            receive,
            rtp_output,
            protected_output,
        })
    }

    /// Returns reusable receive storage.
    #[must_use]
    pub fn receive(&mut self) -> &mut DatagramBuffer {
        &mut self.receive
    }

    /// Returns reusable clear RTP/RTCP serialization storage.
    #[must_use]
    pub fn rtp_output(&mut self) -> &mut [u8] {
        &mut self.rtp_output
    }

    /// Returns reusable SRTP/SRTCP output storage.
    #[must_use]
    pub fn protected_output(&mut self) -> &mut [u8] {
        &mut self.protected_output
    }
}

impl fmt::Debug for MediaPacketScratch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MediaPacketScratch")
            .field("maximum", &self.receive.maximum())
            .finish_non_exhaustive()
    }
}

fn allocate_zeroed(length: usize) -> Result<Box<[u8]>, SocketError> {
    SocketConfig::new(length)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| SocketError::AllocationFailed)?;
    bytes.resize(length, 0);
    Ok(bytes.into_boxed_slice())
}

impl DatagramBuffer {
    /// Allocates one bounded receive buffer plus an oversize sentinel byte.
    ///
    /// # Errors
    ///
    /// Rejects an invalid limit or allocation failure.
    pub fn new(maximum: usize) -> Result<Self, SocketError> {
        SocketConfig::new(maximum)?;
        let storage_length = maximum
            .checked_add(1)
            .ok_or(SocketError::AllocationFailed)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(storage_length)
            .map_err(|_| SocketError::AllocationFailed)?;
        bytes.resize(storage_length, 0);
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            maximum,
        })
    }

    /// Returns the admitted payload limit, excluding the sentinel byte.
    #[must_use]
    pub const fn maximum(&self) -> usize {
        self.maximum
    }

    fn storage(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl fmt::Debug for DatagramBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatagramBuffer")
            .field("maximum", &self.maximum)
            .finish_non_exhaustive()
    }
}

/// One borrowed inbound UDP datagram.
pub struct InboundDatagram<'a> {
    component: Component,
    source: SocketAddr,
    payload: &'a [u8],
}

impl<'a> InboundDatagram<'a> {
    /// Returns the socket component that received the datagram.
    #[must_use]
    pub const fn component(&self) -> Component {
        self.component
    }

    /// Returns the observed network source for symmetric RTP learning.
    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    /// Returns the datagram bytes borrowed from reusable receive storage.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

impl fmt::Debug for InboundDatagram<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundDatagram")
            .field("component", &self.component)
            .field("address_family", &address_family(self.source))
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// One bound RTP/RTCP UDP socket pair holding its allocator lease.
pub struct MediaSocketPair {
    lease: PortLease,
    rtp: UdpSocket,
    rtcp: UdpSocket,
    config: SocketConfig,
}

impl MediaSocketPair {
    /// Binds both ports represented by one allocator lease.
    ///
    /// RTP is bound first and RTCP second. Any failure drops the first socket
    /// and the consumed lease before returning, so the allocator never leaks a
    /// pair that the operating system did not fully bind.
    ///
    /// # Errors
    ///
    /// Returns component-qualified bind or configuration errors.
    pub fn bind(
        lease: PortLease,
        bind_ip: IpAddr,
        config: SocketConfig,
    ) -> Result<Self, SocketError> {
        validate_config(config)?;
        let pair = lease.pair();
        let media_socket = bind_component(bind_ip, pair.rtp(), Component::Rtp, config)?;
        let control_socket = bind_component(bind_ip, pair.rtcp(), Component::Rtcp, config)?;
        Ok(Self {
            lease,
            rtp: media_socket,
            rtcp: control_socket,
            config,
        })
    }

    /// Returns the reserved even/odd port pair.
    #[must_use]
    pub const fn ports(&self) -> PortPair {
        self.lease.pair()
    }

    /// Returns the configured socket behavior.
    #[must_use]
    pub const fn config(&self) -> SocketConfig {
        self.config
    }

    /// Returns the operating-system local address for one component.
    ///
    /// # Errors
    ///
    /// Propagates local-address query failure without exposing endpoint data in
    /// the error value.
    pub fn local_addr(&self, component: Component) -> Result<SocketAddr, SocketError> {
        self.socket(component)
            .local_addr()
            .map_err(|source| SocketError::LocalAddress { component, source })
    }

    /// Creates correctly sized reusable receive storage for this pair.
    ///
    /// # Errors
    ///
    /// Returns allocation failure.
    pub fn receive_buffer(&self) -> Result<DatagramBuffer, SocketError> {
        DatagramBuffer::new(self.config.maximum_datagram_bytes)
    }

    /// Receives one datagram without per-packet allocation.
    ///
    /// Empty datagrams are preserved for the packet parser to classify.
    /// Datagrams over the configured limit are consumed and rejected. The
    /// reported observed size is a lower bound when the sender exceeded the
    /// sentinel capacity.
    ///
    /// # Errors
    ///
    /// Rejects a buffer configured for another socket policy, oversized input,
    /// or an operating-system receive failure such as `WouldBlock`.
    pub fn receive<'a>(
        &self,
        component: Component,
        buffer: &'a mut DatagramBuffer,
    ) -> Result<InboundDatagram<'a>, SocketError> {
        if buffer.maximum != self.config.maximum_datagram_bytes {
            return Err(SocketError::BufferLimitMismatch {
                buffer: buffer.maximum,
                socket: self.config.maximum_datagram_bytes,
            });
        }
        let (length, source) = self
            .socket(component)
            .recv_from(buffer.storage())
            .map_err(|source| SocketError::Receive { component, source })?;
        if length > self.config.maximum_datagram_bytes {
            return Err(SocketError::DatagramTooLarge {
                component,
                observed_at_least: length,
                maximum: self.config.maximum_datagram_bytes,
            });
        }
        Ok(InboundDatagram {
            component,
            source,
            payload: &buffer.bytes[..length],
        })
    }

    /// Sends one admitted datagram to an explicit remote endpoint.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized payloads, port zero, operating-system send
    /// failure, or an unexpected partial datagram write.
    pub fn send_to(
        &self,
        component: Component,
        payload: &[u8],
        destination: SocketAddr,
    ) -> Result<(), SocketError> {
        if payload.is_empty() {
            return Err(SocketError::EmptyDatagram { component });
        }
        if payload.len() > self.config.maximum_datagram_bytes {
            return Err(SocketError::DatagramTooLarge {
                component,
                observed_at_least: payload.len(),
                maximum: self.config.maximum_datagram_bytes,
            });
        }
        if destination.port() == 0 {
            return Err(SocketError::DestinationPortZero { component });
        }
        let written = self
            .socket(component)
            .send_to(payload, destination)
            .map_err(|source| SocketError::Send { component, source })?;
        if written != payload.len() {
            return Err(SocketError::PartialDatagram {
                component,
                expected: payload.len(),
                written,
            });
        }
        Ok(())
    }

    fn socket(&self, component: Component) -> &UdpSocket {
        match component {
            Component::Rtp => &self.rtp,
            Component::Rtcp => &self.rtcp,
        }
    }
}

impl fmt::Debug for MediaSocketPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MediaSocketPair")
            .field("ports", &self.ports())
            .field(
                "maximum_datagram_bytes",
                &self.config.maximum_datagram_bytes,
            )
            .field("nonblocking", &self.config.nonblocking)
            .finish_non_exhaustive()
    }
}

fn validate_config(config: SocketConfig) -> Result<(), SocketError> {
    SocketConfig::new(config.maximum_datagram_bytes)?;
    validate_timeout(config.read_timeout, config.nonblocking)?;
    validate_timeout(config.write_timeout, config.nonblocking)
}

fn bind_component(
    bind_ip: IpAddr,
    port: u16,
    component: Component,
    config: SocketConfig,
) -> Result<UdpSocket, SocketError> {
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, port))
        .map_err(|source| SocketError::Bind { component, source })?;
    socket
        .set_nonblocking(config.nonblocking)
        .map_err(|source| SocketError::Configure {
            component,
            operation: ConfigureOperation::Nonblocking,
            source,
        })?;
    socket
        .set_read_timeout(config.read_timeout)
        .map_err(|source| SocketError::Configure {
            component,
            operation: ConfigureOperation::ReadTimeout,
            source,
        })?;
    socket
        .set_write_timeout(config.write_timeout)
        .map_err(|source| SocketError::Configure {
            component,
            operation: ConfigureOperation::WriteTimeout,
            source,
        })?;
    Ok(socket)
}

const fn address_family(address: SocketAddr) -> &'static str {
    if address.is_ipv4() { "ipv4" } else { "ipv6" }
}

/// Socket option being configured when a system call failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigureOperation {
    /// Nonblocking mode.
    Nonblocking,
    /// Blocking receive timeout.
    ReadTimeout,
    /// Blocking send timeout.
    WriteTimeout,
}

/// RTP/RTCP socket configuration, binding, or datagram failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum SocketError {
    /// Datagram admission limit was outside the supported range.
    InvalidDatagramLimit {
        /// Configured value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// A socket timeout was zero.
    ZeroTimeout,
    /// Blocking timeout semantics were requested on a nonblocking socket.
    TimeoutOnNonblockingSocket,
    /// Reusable receive storage could not be allocated.
    AllocationFailed,
    /// A component could not bind its leased port.
    Bind {
        /// Component being bound.
        component: Component,
        /// Operating-system failure.
        source: io::Error,
    },
    /// A bound component could not apply one socket option.
    Configure {
        /// Component being configured.
        component: Component,
        /// Failed operation.
        operation: ConfigureOperation,
        /// Operating-system failure.
        source: io::Error,
    },
    /// Local-address lookup failed.
    LocalAddress {
        /// Component queried.
        component: Component,
        /// Operating-system failure.
        source: io::Error,
    },
    /// Receive storage used a different operational limit.
    BufferLimitMismatch {
        /// Receive-buffer limit.
        buffer: usize,
        /// Socket-pair limit.
        socket: usize,
    },
    /// Inbound or outbound datagram exceeded the operational limit.
    DatagramTooLarge {
        /// Affected component.
        component: Component,
        /// Exact outbound size or lower-bound inbound size.
        observed_at_least: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Outbound media datagram was empty.
    EmptyDatagram {
        /// Affected component.
        component: Component,
    },
    /// Outbound destination used reserved port zero.
    DestinationPortZero {
        /// Affected component.
        component: Component,
    },
    /// Datagram receive system call failed.
    Receive {
        /// Affected component.
        component: Component,
        /// Operating-system failure.
        source: io::Error,
    },
    /// Datagram send system call failed.
    Send {
        /// Affected component.
        component: Component,
        /// Operating-system failure.
        source: io::Error,
    },
    /// Operating system reported an unexpected partial datagram write.
    PartialDatagram {
        /// Affected component.
        component: Component,
        /// Payload length.
        expected: usize,
        /// Reported written bytes.
        written: usize,
    },
}

impl SocketError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::InvalidDatagramLimit { .. } => "invalid-datagram-limit",
            Self::ZeroTimeout => "zero-timeout",
            Self::TimeoutOnNonblockingSocket => "timeout-on-nonblocking",
            Self::AllocationFailed => "allocation-failed",
            Self::Bind { .. } => "bind",
            Self::Configure { .. } => "configure",
            Self::LocalAddress { .. } => "local-address",
            Self::BufferLimitMismatch { .. } => "buffer-limit-mismatch",
            Self::DatagramTooLarge { .. } => "datagram-too-large",
            Self::EmptyDatagram { .. } => "empty-datagram",
            Self::DestinationPortZero { .. } => "destination-port-zero",
            Self::Receive { .. } => "receive",
            Self::Send { .. } => "send",
            Self::PartialDatagram { .. } => "partial-datagram",
        }
    }

    /// Returns the affected component when one exists.
    #[must_use]
    pub const fn component(&self) -> Option<Component> {
        match self {
            Self::Bind { component, .. }
            | Self::Configure { component, .. }
            | Self::LocalAddress { component, .. }
            | Self::DatagramTooLarge { component, .. }
            | Self::EmptyDatagram { component }
            | Self::DestinationPortZero { component }
            | Self::Receive { component, .. }
            | Self::Send { component, .. }
            | Self::PartialDatagram { component, .. } => Some(*component),
            Self::InvalidDatagramLimit { .. }
            | Self::ZeroTimeout
            | Self::TimeoutOnNonblockingSocket
            | Self::AllocationFailed
            | Self::BufferLimitMismatch { .. } => None,
        }
    }

    /// Returns the underlying I/O kind without exposing endpoint data.
    #[must_use]
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Bind { source, .. }
            | Self::Configure { source, .. }
            | Self::LocalAddress { source, .. }
            | Self::Receive { source, .. }
            | Self::Send { source, .. } => Some(source.kind()),
            _ => None,
        }
    }
}

impl fmt::Display for SocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RTP socket error: {}", self.class())
    }
}

impl StdError for SocketError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Bind { source, .. }
            | Self::Configure { source, .. }
            | Self::LocalAddress { source, .. }
            | Self::Receive { source, .. }
            | Self::Send { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::{
        Component, DatagramBuffer, MAX_MEDIA_DATAGRAM_BYTES, MediaPacketScratch, MediaSocketPair,
        SocketConfig, SocketError,
    };
    use crate::rtp::transport::allocator::PortPool;

    static NEXT_TEST_PORT: AtomicUsize = AtomicUsize::new(42_000);

    fn next_even_port() -> u16 {
        let value = NEXT_TEST_PORT.fetch_add(2, Ordering::Relaxed);
        let bounded = 42_000 + (value.saturating_sub(42_000) % 20_000);
        u16::try_from(bounded & !1).unwrap_or(42_000)
    }

    fn blocking_config(maximum: usize) -> SocketConfig {
        let Ok(config) = SocketConfig::new(maximum) else {
            panic!("socket config")
        };
        let Ok(config) = config.with_nonblocking(false) else {
            panic!("blocking config")
        };
        let Ok(config) = config.with_read_timeout(Some(Duration::from_secs(1))) else {
            panic!("read timeout")
        };
        let Ok(config) = config.with_write_timeout(Some(Duration::from_secs(1))) else {
            panic!("write timeout")
        };
        config
    }

    fn bind_pair(config: SocketConfig) -> (PortPool, MediaSocketPair) {
        for _ in 0..10_000 {
            let port = next_even_port();
            let Ok(pool) = PortPool::new(port, port) else {
                continue;
            };
            let Some(lease) = pool.allocate() else {
                continue;
            };
            match MediaSocketPair::bind(lease, IpAddr::V4(Ipv4Addr::LOCALHOST), config) {
                Ok(pair) => return (pool, pair),
                Err(SocketError::Bind { .. }) => {}
                Err(error) => panic!("unexpected pair bind failure: {}", error.class()),
            }
        }
        panic!("no loopback RTP/RTCP test pair available")
    }

    #[test]
    fn validates_configuration_and_receive_storage() {
        assert!(matches!(
            SocketConfig::new(0),
            Err(SocketError::InvalidDatagramLimit { .. })
        ));
        assert!(matches!(
            SocketConfig::new(MAX_MEDIA_DATAGRAM_BYTES + 1),
            Err(SocketError::InvalidDatagramLimit { .. })
        ));
        assert!(matches!(
            SocketConfig::default().with_read_timeout(Some(Duration::from_secs(1))),
            Err(SocketError::TimeoutOnNonblockingSocket)
        ));
        let Ok(blocking) = SocketConfig::default().with_nonblocking(false) else {
            panic!("blocking config")
        };
        assert!(matches!(
            blocking.with_write_timeout(Some(Duration::ZERO)),
            Err(SocketError::ZeroTimeout)
        ));

        let Ok(buffer) = DatagramBuffer::new(64) else {
            panic!("buffer")
        };
        assert_eq!(buffer.maximum(), 64);
        assert_eq!(buffer.bytes.len(), 65);
    }

    #[test]
    fn binds_pair_holds_lease_and_releases_it_on_drop() {
        let (pool, pair) = bind_pair(SocketConfig::default());
        assert_eq!(pool.in_use(), 1);
        let Ok(media_address) = pair.local_addr(Component::Rtp) else {
            panic!("RTP address")
        };
        let Ok(control_address) = pair.local_addr(Component::Rtcp) else {
            panic!("RTCP address")
        };
        assert_eq!(media_address.port(), pair.ports().rtp());
        assert_eq!(control_address.port(), pair.ports().rtcp());
        assert_eq!(control_address.port(), media_address.port() + 1);
        drop(pair);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn receives_and_sends_both_components_without_packet_allocation() {
        let (_pool, pair) = bind_pair(blocking_config(256));
        let Ok(sender) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) else {
            panic!("sender")
        };
        let source = sender
            .local_addr()
            .unwrap_or_else(|_| panic!("sender address"));
        let destination = pair
            .local_addr(Component::Rtp)
            .unwrap_or_else(|_| panic!("RTP address"));
        assert_eq!(
            sender
                .send_to(b"private-media", destination)
                .unwrap_or_else(|_| panic!("send")),
            13
        );

        let mut buffer = pair
            .receive_buffer()
            .unwrap_or_else(|_| panic!("receive buffer"));
        let first_pointer = buffer.bytes.as_ptr();
        let inbound = pair
            .receive(Component::Rtp, &mut buffer)
            .unwrap_or_else(|_| panic!("receive"));
        assert_eq!(inbound.component(), Component::Rtp);
        assert_eq!(inbound.source(), source);
        assert_eq!(inbound.payload(), b"private-media");
        assert_eq!(inbound.payload().as_ptr(), first_pointer);

        let Ok(sink_socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) else {
            panic!("receiver")
        };
        assert!(
            sink_socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .is_ok()
        );
        let receiver_address = sink_socket
            .local_addr()
            .unwrap_or_else(|_| panic!("receiver address"));
        assert!(
            pair.send_to(Component::Rtcp, b"control", receiver_address)
                .is_ok()
        );
        let mut output = [0_u8; 32];
        let (length, source) = sink_socket
            .recv_from(&mut output)
            .unwrap_or_else(|_| panic!("receive control"));
        assert_eq!(&output[..length], b"control");
        assert_eq!(
            source,
            pair.local_addr(Component::Rtcp)
                .unwrap_or_else(|_| panic!("RTCP address"))
        );
    }

    #[test]
    fn rejects_oversized_inbound_and_outbound_datagrams() {
        let (_pool, pair) = bind_pair(blocking_config(8));
        let Ok(sender) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) else {
            panic!("sender")
        };
        let destination = pair
            .local_addr(Component::Rtp)
            .unwrap_or_else(|_| panic!("RTP address"));
        assert_eq!(
            sender
                .send_to(b"123456789", destination)
                .unwrap_or_else(|_| panic!("send")),
            9
        );
        let mut buffer = pair
            .receive_buffer()
            .unwrap_or_else(|_| panic!("receive buffer"));
        assert!(matches!(
            pair.receive(Component::Rtp, &mut buffer),
            Err(SocketError::DatagramTooLarge {
                observed_at_least: 9,
                maximum: 8,
                ..
            })
        ));

        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        assert!(matches!(
            pair.send_to(Component::Rtp, b"123456789", remote),
            Err(SocketError::DatagramTooLarge { .. })
        ));
        assert!(matches!(
            pair.send_to(Component::Rtp, b"", remote),
            Err(SocketError::EmptyDatagram { .. })
        ));
        assert!(matches!(
            pair.send_to(
                Component::Rtp,
                b"ok",
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
            ),
            Err(SocketError::DestinationPortZero { .. })
        ));
    }

    #[test]
    fn rejects_mismatched_buffer_before_consuming_network_data() {
        let (_pool, pair) = bind_pair(SocketConfig::default());
        let Ok(mut buffer) = DatagramBuffer::new(64) else {
            panic!("buffer")
        };
        assert!(matches!(
            pair.receive(Component::Rtp, &mut buffer),
            Err(SocketError::BufferLimitMismatch {
                buffer: 64,
                socket: 2_048
            })
        ));
    }

    #[test]
    fn nonblocking_receive_preserves_would_block_source() {
        let (_pool, pair) = bind_pair(SocketConfig::default());
        let mut buffer = pair
            .receive_buffer()
            .unwrap_or_else(|_| panic!("receive buffer"));
        let Err(error) = pair.receive(Component::Rtp, &mut buffer) else {
            panic!("empty nonblocking socket must not receive")
        };
        assert_eq!(error.class(), "receive");
        assert_eq!(error.component(), Some(Component::Rtp));
        assert_eq!(error.io_kind(), Some(std::io::ErrorKind::WouldBlock));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn partial_pair_bind_rolls_back_socket_and_allocator_lease() {
        for _ in 0..10_000 {
            let rtp_port = next_even_port();
            let media_address = SocketAddr::from((Ipv4Addr::LOCALHOST, rtp_port));
            let control_address = SocketAddr::from((Ipv4Addr::LOCALHOST, rtp_port + 1));
            let Ok(media_probe) = UdpSocket::bind(media_address) else {
                continue;
            };
            let Ok(control_blocker) = UdpSocket::bind(control_address) else {
                continue;
            };
            drop(media_probe);

            let Ok(pool) = PortPool::new(rtp_port, rtp_port) else {
                panic!("pool")
            };
            let Some(lease) = pool.allocate() else {
                panic!("lease")
            };
            let Err(error) = MediaSocketPair::bind(
                lease,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                SocketConfig::default(),
            ) else {
                panic!("occupied RTCP port must reject pair")
            };
            assert_eq!(error.class(), "bind");
            assert_eq!(error.component(), Some(Component::Rtcp));
            assert_eq!(pool.in_use(), 0);
            drop(control_blocker);
            return;
        }
        panic!("unable to reserve an RTCP rollback test port")
    }

    #[test]
    fn diagnostics_redact_payloads_and_ip_addresses() {
        let (_pool, pair) = bind_pair(blocking_config(64));
        let Ok(sender) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) else {
            panic!("sender")
        };
        let destination = pair
            .local_addr(Component::Rtp)
            .unwrap_or_else(|_| panic!("RTP address"));
        assert!(sender.send_to(b"secret-audio", destination).is_ok());
        let mut buffer = pair
            .receive_buffer()
            .unwrap_or_else(|_| panic!("receive buffer"));
        let datagram = pair
            .receive(Component::Rtp, &mut buffer)
            .unwrap_or_else(|_| panic!("receive"));

        let debug = format!("{datagram:?}");
        assert!(!debug.contains("secret-audio"));
        assert!(!debug.contains("127.0.0.1"));
        let pair_debug = format!("{pair:?}");
        assert!(!pair_debug.contains("127.0.0.1"));
    }

    #[test]
    fn permanent_packet_scratch_reuses_all_allocations() {
        let Ok(mut scratch) = MediaPacketScratch::new(2_048) else {
            panic!("scratch")
        };
        let receive_pointer = scratch.receive().bytes.as_ptr();
        let rtp_pointer = scratch.rtp_output().as_ptr();
        let protected_pointer = scratch.protected_output().as_ptr();

        for _ in 0..16 {
            assert_eq!(scratch.receive().bytes.as_ptr(), receive_pointer);
            assert_eq!(scratch.rtp_output().as_ptr(), rtp_pointer);
            assert_eq!(scratch.protected_output().as_ptr(), protected_pointer);
        }
    }
}
