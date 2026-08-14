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

//! Runtime-neutral configured UDP, TCP listener, and TCP connection ownership.
//!
//! This module owns operating-system socket creation and generic configuration.
//! SIP framing, RTP packet handling, TLS, readiness registration, retries, and
//! application state remain in their respective layers.
//!
//! Nonblocking operation and blocking timeouts are mutually exclusive by type
//! policy. Connect and I/O timeouts are independently bounded. Local and peer
//! endpoints are validated once when a TCP connection is created or accepted,
//! and diagnostics never disclose network addresses.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

use super::address::{AddressFamily, BindAddress, Endpoint, EndpointError};

/// Maximum generic blocking socket I/O timeout.
pub const MAX_IO_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum outbound TCP establishment timeout.
pub const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Generic socket I/O mode and timeout policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoConfig {
    nonblocking: bool,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl IoConfig {
    /// Creates production-default nonblocking I/O policy.
    #[must_use]
    pub const fn nonblocking() -> Self {
        Self {
            nonblocking: true,
            read_timeout: None,
            write_timeout: None,
        }
    }

    /// Creates blocking I/O policy without timeouts.
    #[must_use]
    pub const fn blocking() -> Self {
        Self {
            nonblocking: false,
            read_timeout: None,
            write_timeout: None,
        }
    }

    /// Selects blocking or nonblocking operation.
    ///
    /// # Errors
    ///
    /// Rejects nonblocking operation while a blocking timeout remains set.
    pub const fn with_nonblocking(mut self, nonblocking: bool) -> Result<Self, SocketError> {
        if nonblocking && (self.read_timeout.is_some() || self.write_timeout.is_some()) {
            return Err(SocketError::TimeoutOnNonblockingSocket);
        }
        self.nonblocking = nonblocking;
        Ok(self)
    }

    /// Sets a bounded blocking read timeout.
    ///
    /// # Errors
    ///
    /// Rejects timeouts on nonblocking sockets, zero, and durations above
    /// [`MAX_IO_TIMEOUT`].
    pub fn with_read_timeout(mut self, timeout: Option<Duration>) -> Result<Self, SocketError> {
        validate_io_timeout(timeout, self.nonblocking)?;
        self.read_timeout = timeout;
        Ok(self)
    }

    /// Sets a bounded blocking write timeout.
    ///
    /// # Errors
    ///
    /// Preserves [`Self::with_read_timeout`] policy.
    pub fn with_write_timeout(mut self, timeout: Option<Duration>) -> Result<Self, SocketError> {
        validate_io_timeout(timeout, self.nonblocking)?;
        self.write_timeout = timeout;
        Ok(self)
    }

    /// Returns whether operations are nonblocking.
    #[must_use]
    pub const fn is_nonblocking(self) -> bool {
        self.nonblocking
    }

    /// Returns the blocking read timeout.
    #[must_use]
    pub const fn read_timeout(self) -> Option<Duration> {
        self.read_timeout
    }

    /// Returns the blocking write timeout.
    #[must_use]
    pub const fn write_timeout(self) -> Option<Duration> {
        self.write_timeout
    }
}

impl Default for IoConfig {
    fn default() -> Self {
        Self::nonblocking()
    }
}

const fn validate_io_timeout(
    timeout: Option<Duration>,
    nonblocking: bool,
) -> Result<(), SocketError> {
    if let Some(timeout) = timeout {
        if nonblocking {
            return Err(SocketError::TimeoutOnNonblockingSocket);
        }
        if timeout.is_zero() {
            return Err(SocketError::ZeroIoTimeout);
        }
        if timeout.as_nanos() > MAX_IO_TIMEOUT.as_nanos() {
            return Err(SocketError::IoTimeoutTooLong {
                maximum: MAX_IO_TIMEOUT,
            });
        }
    }
    Ok(())
}

/// Validated outbound TCP connect deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectTimeout(Duration);

impl ConnectTimeout {
    /// Validates one establishment timeout.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above [`MAX_CONNECT_TIMEOUT`].
    pub const fn new(timeout: Duration) -> Result<Self, SocketError> {
        if timeout.is_zero() {
            return Err(SocketError::ZeroConnectTimeout);
        }
        if timeout.as_nanos() > MAX_CONNECT_TIMEOUT.as_nanos() {
            return Err(SocketError::ConnectTimeoutTooLong {
                maximum: MAX_CONNECT_TIMEOUT,
            });
        }
        Ok(Self(timeout))
    }

    /// Returns the validated duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

impl Default for ConnectTimeout {
    fn default() -> Self {
        Self(Duration::from_secs(10))
    }
}

/// Generic UDP socket configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpConfig {
    io: IoConfig,
    broadcast: bool,
    ttl: u32,
}

impl UdpConfig {
    /// Creates a UDP policy around explicit I/O behavior.
    #[must_use]
    pub const fn new(io: IoConfig) -> Self {
        Self {
            io,
            broadcast: false,
            ttl: 64,
        }
    }

    /// Selects IPv4 broadcast permission.
    #[must_use]
    pub const fn with_broadcast(mut self, broadcast: bool) -> Self {
        self.broadcast = broadcast;
        self
    }

    /// Sets the unicast hop limit.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above 255.
    pub fn with_ttl(mut self, ttl: u32) -> Result<Self, SocketError> {
        validate_ttl(ttl)?;
        self.ttl = ttl;
        Ok(self)
    }

    /// Returns generic I/O policy.
    #[must_use]
    pub const fn io(self) -> IoConfig {
        self.io
    }

    /// Returns whether IPv4 broadcast sends are enabled.
    #[must_use]
    pub const fn broadcast(self) -> bool {
        self.broadcast
    }

    /// Returns the unicast hop limit.
    #[must_use]
    pub const fn ttl(self) -> u32 {
        self.ttl
    }
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self::new(IoConfig::default())
    }
}

/// Generic connected TCP socket configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpConfig {
    io: IoConfig,
    no_delay: bool,
    ttl: u32,
}

impl TcpConfig {
    /// Creates a low-latency TCP policy around explicit I/O behavior.
    #[must_use]
    pub const fn new(io: IoConfig) -> Self {
        Self {
            io,
            no_delay: true,
            ttl: 64,
        }
    }

    /// Selects `TCP_NODELAY`.
    #[must_use]
    pub const fn with_no_delay(mut self, no_delay: bool) -> Self {
        self.no_delay = no_delay;
        self
    }

    /// Sets the unicast hop limit.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above 255.
    pub fn with_ttl(mut self, ttl: u32) -> Result<Self, SocketError> {
        validate_ttl(ttl)?;
        self.ttl = ttl;
        Ok(self)
    }

    /// Returns generic I/O policy.
    #[must_use]
    pub const fn io(self) -> IoConfig {
        self.io
    }

    /// Returns `TCP_NODELAY` policy.
    #[must_use]
    pub const fn no_delay(self) -> bool {
        self.no_delay
    }

    /// Returns the unicast hop limit.
    #[must_use]
    pub const fn ttl(self) -> u32 {
        self.ttl
    }
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self::new(IoConfig::default())
    }
}

const fn validate_ttl(ttl: u32) -> Result<(), SocketError> {
    if ttl == 0 || ttl > 255 {
        Err(SocketError::InvalidTtl { value: ttl })
    } else {
        Ok(())
    }
}

/// Configured owned UDP socket.
pub struct UdpBinding {
    socket: UdpSocket,
    requested: BindAddress,
    local: SocketAddr,
    config: UdpConfig,
}

impl UdpBinding {
    /// Binds and transactionally configures one UDP socket.
    ///
    /// # Errors
    ///
    /// Preserves bind, option, and local-address query failures.
    pub fn bind(requested: BindAddress, config: UdpConfig) -> Result<Self, SocketError> {
        let socket = UdpSocket::bind(requested.socket_addr()).map_err(SocketError::BindUdp)?;
        configure_udp(&socket, config)?;
        let local = socket.local_addr().map_err(SocketError::LocalAddress)?;
        Ok(Self {
            socket,
            requested,
            local,
            config,
        })
    }

    /// Returns the originally requested bind policy.
    #[must_use]
    pub const fn requested(&self) -> BindAddress {
        self.requested
    }

    /// Returns the actual bound socket address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Returns the applied configuration.
    #[must_use]
    pub const fn config(&self) -> UdpConfig {
        self.config
    }

    /// Returns the configured socket for protocol-specific datagram I/O.
    #[must_use]
    pub const fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Duplicates the socket handle while preserving the same underlying bind.
    ///
    /// # Errors
    ///
    /// Preserves operating-system handle duplication failure.
    pub fn try_clone_socket(&self) -> Result<UdpSocket, SocketError> {
        self.socket.try_clone().map_err(SocketError::Duplicate)
    }

    /// Consumes the wrapper into the configured socket.
    #[must_use]
    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

impl fmt::Debug for UdpBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpBinding")
            .field("family", &AddressFamily::of_socket(self.local))
            .field("wildcard", &self.requested.is_wildcard())
            .field("ephemeral", &self.requested.is_ephemeral())
            .field("nonblocking", &self.config.io.is_nonblocking())
            .finish_non_exhaustive()
    }
}

/// Configured owned TCP listener.
pub struct TcpAcceptor {
    listener: TcpListener,
    requested: BindAddress,
    local: SocketAddr,
    nonblocking: bool,
    ttl: u32,
}

impl TcpAcceptor {
    /// Binds and configures one TCP listener.
    ///
    /// # Errors
    ///
    /// Rejects invalid TTL and preserves bind/configuration/address failures.
    pub fn bind(requested: BindAddress, nonblocking: bool, ttl: u32) -> Result<Self, SocketError> {
        validate_ttl(ttl)?;
        let listener = TcpListener::bind(requested.socket_addr()).map_err(SocketError::BindTcp)?;
        listener
            .set_ttl(ttl)
            .map_err(|source| SocketError::Configure {
                option: SocketOption::Ttl,
                source,
            })?;
        listener
            .set_nonblocking(nonblocking)
            .map_err(|source| SocketError::Configure {
                option: SocketOption::Nonblocking,
                source,
            })?;
        let local = listener.local_addr().map_err(SocketError::LocalAddress)?;
        Ok(Self {
            listener,
            requested,
            local,
            nonblocking,
            ttl,
        })
    }

    /// Accepts and configures one TCP connection.
    ///
    /// # Errors
    ///
    /// Preserves accept, endpoint validation, and stream configuration errors,
    /// including `WouldBlock` on a nonblocking listener.
    pub fn accept(&self, config: TcpConfig) -> Result<TcpConnection, SocketError> {
        let (stream, observed_peer) = self.listener.accept().map_err(SocketError::Accept)?;
        TcpConnection::from_stream_with_peer(stream, observed_peer, config)
    }

    /// Returns the original bind policy.
    #[must_use]
    pub const fn requested(&self) -> BindAddress {
        self.requested
    }

    /// Returns the actual local listener address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Returns whether accept operations are nonblocking.
    #[must_use]
    pub const fn is_nonblocking(&self) -> bool {
        self.nonblocking
    }

    /// Returns the configured hop limit.
    #[must_use]
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }
}

impl fmt::Debug for TcpAcceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpAcceptor")
            .field("family", &AddressFamily::of_socket(self.local))
            .field("wildcard", &self.requested.is_wildcard())
            .field("ephemeral", &self.requested.is_ephemeral())
            .field("nonblocking", &self.nonblocking)
            .finish_non_exhaustive()
    }
}

/// Configured connected TCP stream with validated endpoint truth.
pub struct TcpConnection {
    stream: TcpStream,
    local: Endpoint,
    peer: Endpoint,
    config: TcpConfig,
}

impl TcpConnection {
    /// Establishes and configures one outbound TCP connection.
    ///
    /// # Errors
    ///
    /// Preserves bounded connect, endpoint query/validation, and configuration
    /// failures.
    pub fn connect(
        peer: Endpoint,
        timeout: ConnectTimeout,
        config: TcpConfig,
    ) -> Result<Self, SocketError> {
        let stream = TcpStream::connect_timeout(&peer.socket_addr(), timeout.get())
            .map_err(SocketError::Connect)?;
        Self::from_stream_with_peer(stream, peer.socket_addr(), config)
    }

    /// Adopts and configures one connected TCP stream.
    ///
    /// # Errors
    ///
    /// Preserves endpoint query/validation and configuration failures.
    pub fn from_stream(stream: TcpStream, config: TcpConfig) -> Result<Self, SocketError> {
        let peer = stream.peer_addr().map_err(SocketError::PeerAddress)?;
        Self::from_stream_with_peer(stream, peer, config)
    }

    fn from_stream_with_peer(
        stream: TcpStream,
        observed_peer: SocketAddr,
        config: TcpConfig,
    ) -> Result<Self, SocketError> {
        let local = stream.local_addr().map_err(SocketError::LocalAddress)?;
        let peer = stream.peer_addr().map_err(SocketError::PeerAddress)?;
        if peer != observed_peer {
            return Err(SocketError::PeerChangedDuringAdoption);
        }
        let local = Endpoint::new(local).map_err(SocketError::InvalidLocalEndpoint)?;
        let peer = Endpoint::new(peer).map_err(SocketError::InvalidPeerEndpoint)?;
        configure_tcp(&stream, config)?;
        Ok(Self {
            stream,
            local,
            peer,
            config,
        })
    }

    /// Returns the validated local endpoint.
    #[must_use]
    pub const fn local(&self) -> Endpoint {
        self.local
    }

    /// Returns the validated peer endpoint.
    #[must_use]
    pub const fn peer(&self) -> Endpoint {
        self.peer
    }

    /// Returns applied stream configuration.
    #[must_use]
    pub const fn config(&self) -> TcpConfig {
        self.config
    }

    /// Returns the stream for protocol-specific read/write operations.
    #[must_use]
    pub const fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Duplicates the stream handle for readiness-only ownership.
    ///
    /// # Errors
    ///
    /// Preserves operating-system handle duplication failure.
    pub fn try_clone_stream(&self) -> Result<TcpStream, SocketError> {
        self.stream.try_clone().map_err(SocketError::Duplicate)
    }

    /// Shuts down one or both stream directions.
    ///
    /// # Errors
    ///
    /// Preserves operating-system shutdown failure.
    pub fn shutdown(&self, how: Shutdown) -> Result<(), SocketError> {
        self.stream.shutdown(how).map_err(SocketError::Shutdown)
    }

    /// Consumes the wrapper into its configured stream.
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

impl fmt::Debug for TcpConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpConnection")
            .field("family", &self.peer.family())
            .field("nonblocking", &self.config.io.is_nonblocking())
            .field("no_delay", &self.config.no_delay)
            .finish_non_exhaustive()
    }
}

fn configure_udp(socket: &UdpSocket, config: UdpConfig) -> Result<(), SocketError> {
    socket
        .set_broadcast(config.broadcast)
        .map_err(|source| SocketError::Configure {
            option: SocketOption::Broadcast,
            source,
        })?;
    socket
        .set_ttl(config.ttl)
        .map_err(|source| SocketError::Configure {
            option: SocketOption::Ttl,
            source,
        })?;
    apply_udp_io(socket, config.io)
}

fn apply_udp_io(socket: &UdpSocket, config: IoConfig) -> Result<(), SocketError> {
    socket
        .set_read_timeout(config.read_timeout)
        .map_err(|source| SocketError::Configure {
            option: SocketOption::ReadTimeout,
            source,
        })?;
    socket
        .set_write_timeout(config.write_timeout)
        .map_err(|source| SocketError::Configure {
            option: SocketOption::WriteTimeout,
            source,
        })?;
    socket
        .set_nonblocking(config.nonblocking)
        .map_err(|source| SocketError::Configure {
            option: SocketOption::Nonblocking,
            source,
        })
}

fn configure_tcp(stream: &TcpStream, config: TcpConfig) -> Result<(), SocketError> {
    stream
        .set_nodelay(config.no_delay)
        .map_err(|source| SocketError::Configure {
            option: SocketOption::NoDelay,
            source,
        })?;
    stream
        .set_ttl(config.ttl)
        .map_err(|source| SocketError::Configure {
            option: SocketOption::Ttl,
            source,
        })?;
    stream
        .set_read_timeout(config.io.read_timeout)
        .map_err(|source| SocketError::Configure {
            option: SocketOption::ReadTimeout,
            source,
        })?;
    stream
        .set_write_timeout(config.io.write_timeout)
        .map_err(|source| SocketError::Configure {
            option: SocketOption::WriteTimeout,
            source,
        })?;
    stream
        .set_nonblocking(config.io.nonblocking)
        .map_err(|source| SocketError::Configure {
            option: SocketOption::Nonblocking,
            source,
        })
}

/// Low-cardinality socket option identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketOption {
    /// Blocking/nonblocking mode.
    Nonblocking,
    /// Blocking read timeout.
    ReadTimeout,
    /// Blocking write timeout.
    WriteTimeout,
    /// Unicast hop limit.
    Ttl,
    /// IPv4 broadcast permission.
    Broadcast,
    /// `TCP_NODELAY`.
    NoDelay,
}

/// Generic socket construction, configuration, or lifecycle failure.
#[non_exhaustive]
pub enum SocketError {
    /// Blocking timeout was configured on a nonblocking socket.
    TimeoutOnNonblockingSocket,
    /// A blocking I/O timeout was zero.
    ZeroIoTimeout,
    /// A blocking I/O timeout exceeded its hard bound.
    IoTimeoutTooLong {
        /// Hard maximum.
        maximum: Duration,
    },
    /// A TCP connect timeout was zero.
    ZeroConnectTimeout,
    /// A TCP connect timeout exceeded its hard bound.
    ConnectTimeoutTooLong {
        /// Hard maximum.
        maximum: Duration,
    },
    /// TTL/hop limit was outside `1..=255`.
    InvalidTtl {
        /// Rejected value.
        value: u32,
    },
    /// UDP bind failed.
    BindUdp(io::Error),
    /// TCP listener bind failed.
    BindTcp(io::Error),
    /// Outbound TCP establishment failed.
    Connect(io::Error),
    /// TCP accept failed, including nonblocking `WouldBlock`.
    Accept(io::Error),
    /// Socket option configuration failed.
    Configure {
        /// Option being configured.
        option: SocketOption,
        /// Operating-system failure.
        source: io::Error,
    },
    /// Local endpoint query failed.
    LocalAddress(io::Error),
    /// Peer endpoint query failed.
    PeerAddress(io::Error),
    /// Local endpoint was unusable as network truth.
    InvalidLocalEndpoint(EndpointError),
    /// Peer endpoint was unusable as network truth.
    InvalidPeerEndpoint(EndpointError),
    /// Peer endpoint changed between accept/query boundaries.
    PeerChangedDuringAdoption,
    /// Socket-handle duplication failed.
    Duplicate(io::Error),
    /// TCP shutdown failed.
    Shutdown(io::Error),
}

impl SocketError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::TimeoutOnNonblockingSocket => "timeout-on-nonblocking-socket",
            Self::ZeroIoTimeout => "zero-io-timeout",
            Self::IoTimeoutTooLong { .. } => "io-timeout-too-long",
            Self::ZeroConnectTimeout => "zero-connect-timeout",
            Self::ConnectTimeoutTooLong { .. } => "connect-timeout-too-long",
            Self::InvalidTtl { .. } => "invalid-ttl",
            Self::BindUdp(_) => "bind-udp",
            Self::BindTcp(_) => "bind-tcp",
            Self::Connect(_) => "connect",
            Self::Accept(_) => "accept",
            Self::Configure { .. } => "configure",
            Self::LocalAddress(_) => "local-address",
            Self::PeerAddress(_) => "peer-address",
            Self::InvalidLocalEndpoint(_) => "invalid-local-endpoint",
            Self::InvalidPeerEndpoint(_) => "invalid-peer-endpoint",
            Self::PeerChangedDuringAdoption => "peer-changed-during-adoption",
            Self::Duplicate(_) => "duplicate",
            Self::Shutdown(_) => "shutdown",
        }
    }

    /// Returns the operating-system error kind when present.
    #[must_use]
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::BindUdp(source)
            | Self::BindTcp(source)
            | Self::Connect(source)
            | Self::Accept(source)
            | Self::LocalAddress(source)
            | Self::PeerAddress(source)
            | Self::Duplicate(source)
            | Self::Shutdown(source)
            | Self::Configure { source, .. } => Some(source.kind()),
            _ => None,
        }
    }
}

impl fmt::Debug for SocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SocketError")
            .field("class", &self.class())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "network socket error: {}", self.class())
    }
}

impl StdError for SocketError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::BindUdp(source)
            | Self::BindTcp(source)
            | Self::Connect(source)
            | Self::Accept(source)
            | Self::Configure { source, .. }
            | Self::LocalAddress(source)
            | Self::PeerAddress(source)
            | Self::Duplicate(source)
            | Self::Shutdown(source) => Some(source),
            Self::InvalidLocalEndpoint(source) | Self::InvalidPeerEndpoint(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};
    use std::time::Duration;

    use super::{
        ConnectTimeout, IoConfig, MAX_CONNECT_TIMEOUT, MAX_IO_TIMEOUT, SocketError, TcpAcceptor,
        TcpConfig, TcpConnection, UdpBinding, UdpConfig,
    };
    use crate::net::address::{AddressFamily, BindAddress, BindHost, BindPort, Endpoint};

    fn local_ephemeral() -> BindAddress {
        BindAddress::new(
            BindHost::specific(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .unwrap_or_else(|_| panic!("bind host")),
            BindPort::Ephemeral,
        )
    }

    #[test]
    fn timeout_and_ttl_policy_is_bounded() {
        assert!(matches!(
            IoConfig::nonblocking().with_read_timeout(Some(Duration::from_secs(1))),
            Err(SocketError::TimeoutOnNonblockingSocket)
        ));
        assert!(matches!(
            IoConfig::blocking().with_read_timeout(Some(Duration::ZERO)),
            Err(SocketError::ZeroIoTimeout)
        ));
        assert!(matches!(
            IoConfig::blocking().with_write_timeout(Some(MAX_IO_TIMEOUT + Duration::from_nanos(1))),
            Err(SocketError::IoTimeoutTooLong { .. })
        ));
        assert!(matches!(
            ConnectTimeout::new(Duration::ZERO),
            Err(SocketError::ZeroConnectTimeout)
        ));
        assert!(matches!(
            ConnectTimeout::new(MAX_CONNECT_TIMEOUT + Duration::from_nanos(1)),
            Err(SocketError::ConnectTimeoutTooLong { .. })
        ));
        assert!(matches!(
            UdpConfig::default().with_ttl(0),
            Err(SocketError::InvalidTtl { value: 0 })
        ));
        assert!(matches!(
            TcpConfig::default().with_ttl(256),
            Err(SocketError::InvalidTtl { value: 256 })
        ));
    }

    #[test]
    fn udp_binding_applies_blocking_policy_and_round_trips() {
        let io = IoConfig::blocking()
            .with_read_timeout(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("read timeout"));
        let binding = UdpBinding::bind(local_ephemeral(), UdpConfig::new(io))
            .unwrap_or_else(|_| panic!("binding"));
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("sender"));
        assert!(sender.send_to(b"ping", binding.local_addr()).is_ok());
        let mut bytes = [0_u8; 8];
        let (length, _) = binding
            .socket()
            .recv_from(&mut bytes)
            .unwrap_or_else(|_| panic!("receive"));
        assert_eq!(&bytes[..length], b"ping");
        assert!(!binding.config().io().is_nonblocking());
    }

    #[test]
    fn tcp_connect_accept_validates_endpoints_and_applies_options() {
        let acceptor =
            TcpAcceptor::bind(local_ephemeral(), false, 64).unwrap_or_else(|_| panic!("acceptor"));
        let peer = Endpoint::new(acceptor.local_addr()).unwrap_or_else(|_| panic!("peer"));
        let client = TcpConnection::connect(
            peer,
            ConnectTimeout::default(),
            TcpConfig::new(IoConfig::blocking()),
        )
        .unwrap_or_else(|_| panic!("connect"));
        let server = acceptor
            .accept(TcpConfig::new(IoConfig::blocking()))
            .unwrap_or_else(|_| panic!("accept"));
        assert!(client.stream().nodelay().unwrap_or(false));
        assert_eq!(client.peer(), peer);
        assert!(client.local().same_family(server.peer()));

        assert!((&mut client.stream()).write_all(b"hello").is_ok());
        let mut bytes = [0_u8; 5];
        assert!((&mut server.stream()).read_exact(&mut bytes).is_ok());
        assert_eq!(&bytes, b"hello");
    }

    #[test]
    fn nonblocking_accept_preserves_would_block() {
        let acceptor =
            TcpAcceptor::bind(local_ephemeral(), true, 64).unwrap_or_else(|_| panic!("acceptor"));
        let error = acceptor
            .accept(TcpConfig::default())
            .err()
            .unwrap_or_else(|| panic!("accept must block"));
        assert_eq!(error.io_kind(), Some(std::io::ErrorKind::WouldBlock));
    }

    #[test]
    fn wildcard_binding_is_explicit_and_diagnostics_are_redacted() {
        let requested = BindAddress::new(BindHost::any(AddressFamily::Ipv4), BindPort::Ephemeral);
        let binding = UdpBinding::bind(requested, UdpConfig::default())
            .unwrap_or_else(|_| panic!("wildcard bind"));
        let debug = format!("{binding:?}");
        assert!(debug.contains("wildcard"));
        assert!(!debug.contains(&binding.local_addr().port().to_string()));

        let error = SocketError::Connect(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "203.0.113.88:45678",
        ));
        let debug = format!("{error:?}");
        assert!(!debug.contains("203.0.113.88"));
        assert!(!debug.contains("45678"));
    }
}
