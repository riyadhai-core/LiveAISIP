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

//! Runtime-neutral SIP-over-TCP socket driver.
//!
//! The driver owns one established TCP flow, permanent read storage, bounded
//! incremental SIP framing, and at most one partially written message. It
//! parses and semantically validates every complete inbound message before
//! attaching authoritative flow metadata. Connection pooling, outbound queue
//! admission, transaction routing, reconnect policy, and executor readiness
//! remain outside this operating-system boundary.

use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::sip::framing::MAX_MESSAGE_BYTES;
use crate::sip::parser::message::{self, ParseError};
use crate::sip::types::message::MessageKind;
use crate::sip::validation::{request, response};

use super::destination::{Destination, Protocol};
use super::flow::{FlowError, FlowId, IngressMeta};
use super::tcp::{DEFAULT_TCP_BUFFER_BYTES, MAX_TCP_BUFFER_BYTES, ReceiveBuffer, TcpError};
use super::{InboundMessage, ReceivedMessage};

/// Default bytes made available to each socket read.
pub const DEFAULT_READ_CHUNK_BYTES: usize = 16 * 1024;

/// Hard ceiling for one socket read allocation.
pub const MAX_READ_CHUNK_BYTES: usize = 64 * 1024;

/// Default bounded outbound TCP establishment deadline.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard ceiling for outbound TCP establishment.
pub const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Validated TCP socket-driver policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpDriverConfig {
    receive_buffer_bytes: usize,
    read_chunk_bytes: usize,
    connect_timeout: Duration,
    nonblocking: bool,
    no_delay: bool,
}

impl TcpDriverConfig {
    /// Creates a nonblocking low-latency driver configuration.
    ///
    /// # Errors
    ///
    /// Rejects receive/read limits outside their hard ceilings or a zero or
    /// excessive establishment deadline.
    pub const fn new(
        receive_buffer_bytes: usize,
        read_chunk_bytes: usize,
        connect_timeout: Duration,
    ) -> Result<Self, TcpDriverError> {
        if receive_buffer_bytes < MAX_MESSAGE_BYTES || receive_buffer_bytes > MAX_TCP_BUFFER_BYTES {
            return Err(TcpDriverError::InvalidReceiveBufferLimit {
                value: receive_buffer_bytes,
                minimum: MAX_MESSAGE_BYTES,
                maximum: MAX_TCP_BUFFER_BYTES,
            });
        }
        if read_chunk_bytes == 0 || read_chunk_bytes > MAX_READ_CHUNK_BYTES {
            return Err(TcpDriverError::InvalidReadChunkLimit {
                value: read_chunk_bytes,
                maximum: MAX_READ_CHUNK_BYTES,
            });
        }
        if connect_timeout.is_zero() || connect_timeout.as_nanos() > MAX_CONNECT_TIMEOUT.as_nanos()
        {
            return Err(TcpDriverError::InvalidConnectTimeout);
        }
        Ok(Self {
            receive_buffer_bytes,
            read_chunk_bytes,
            connect_timeout,
            nonblocking: true,
            no_delay: true,
        })
    }

    /// Selects blocking operation for a dedicated-thread integration.
    #[must_use]
    pub const fn with_nonblocking(mut self, nonblocking: bool) -> Self {
        self.nonblocking = nonblocking;
        self
    }

    /// Selects `TCP_NODELAY` behavior.
    #[must_use]
    pub const fn with_no_delay(mut self, no_delay: bool) -> Self {
        self.no_delay = no_delay;
        self
    }

    /// Returns the maximum unread framed bytes.
    #[must_use]
    pub const fn receive_buffer_bytes(self) -> usize {
        self.receive_buffer_bytes
    }

    /// Returns the permanent read-storage size.
    #[must_use]
    pub const fn read_chunk_bytes(self) -> usize {
        self.read_chunk_bytes
    }

    /// Returns the outbound establishment deadline.
    #[must_use]
    pub const fn connect_timeout(self) -> Duration {
        self.connect_timeout
    }

    /// Returns whether socket operations are nonblocking after establishment.
    #[must_use]
    pub const fn nonblocking(self) -> bool {
        self.nonblocking
    }

    /// Returns whether Nagle coalescing is disabled.
    #[must_use]
    pub const fn no_delay(self) -> bool {
        self.no_delay
    }
}

impl Default for TcpDriverConfig {
    fn default() -> Self {
        Self {
            receive_buffer_bytes: DEFAULT_TCP_BUFFER_BYTES,
            read_chunk_bytes: DEFAULT_READ_CHUNK_BYTES,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            nonblocking: true,
            no_delay: true,
        }
    }
}

/// Result of one bounded write attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteProgress {
    /// The complete message reached the kernel socket buffer.
    Complete,
    /// The socket would block with these bytes still retained by the driver.
    Pending {
        /// Bytes not yet accepted by the kernel.
        remaining_bytes: usize,
    },
}

struct PendingWrite {
    message: Arc<[u8]>,
    offset: usize,
}

/// One established bounded SIP-over-TCP flow.
pub struct TcpDriver {
    socket: TcpStream,
    local: SocketAddr,
    peer: SocketAddr,
    flow_id: FlowId,
    config: TcpDriverConfig,
    framed: ReceiveBuffer,
    read_storage: Box<[u8]>,
    pending_write: Option<PendingWrite>,
    peer_closed: bool,
}

impl TcpDriver {
    /// Establishes one outbound plaintext TCP flow to a validated destination.
    ///
    /// Connection establishment is bounded even when post-connect operation is
    /// configured as nonblocking.
    ///
    /// # Errors
    ///
    /// Rejects non-TCP destinations and preserves connect/configuration,
    /// endpoint-query, and bounded-allocation failures.
    pub fn connect(
        destination: &Destination,
        flow_id: FlowId,
        config: TcpDriverConfig,
    ) -> Result<Self, TcpDriverError> {
        if destination.protocol() != Protocol::Tcp {
            return Err(TcpDriverError::WrongProtocol {
                actual: destination.protocol(),
            });
        }
        let socket = TcpStream::connect_timeout(&destination.remote(), config.connect_timeout)
            .map_err(TcpDriverError::Connect)?;
        Self::from_stream(socket, flow_id, config)
    }

    /// Adopts an already established outbound or accepted TCP stream.
    ///
    /// # Errors
    ///
    /// Rejects invalid endpoints and preserves socket configuration, endpoint
    /// query, receive-buffer construction, and allocation failures.
    pub fn from_stream(
        socket: TcpStream,
        flow_id: FlowId,
        config: TcpDriverConfig,
    ) -> Result<Self, TcpDriverError> {
        let local = socket.local_addr().map_err(TcpDriverError::LocalAddress)?;
        let peer = socket.peer_addr().map_err(TcpDriverError::PeerAddress)?;
        validate_endpoint(local).map_err(|()| TcpDriverError::InvalidLocalAddress)?;
        validate_endpoint(peer).map_err(|()| TcpDriverError::InvalidPeerAddress)?;

        let framed = ReceiveBuffer::new(config.receive_buffer_bytes)
            .map_err(TcpDriverError::ReceiveBuffer)?;
        let mut read_storage = Vec::new();
        read_storage
            .try_reserve_exact(config.read_chunk_bytes)
            .map_err(|_| TcpDriverError::AllocationFailed)?;
        read_storage.resize(config.read_chunk_bytes, 0);

        socket
            .set_nodelay(config.no_delay)
            .map_err(TcpDriverError::ConfigureNoDelay)?;
        socket
            .set_nonblocking(config.nonblocking)
            .map_err(TcpDriverError::ConfigureNonblocking)?;

        Ok(Self {
            socket,
            local,
            peer,
            flow_id,
            config,
            framed,
            read_storage: read_storage.into_boxed_slice(),
            pending_write: None,
            peer_closed: false,
        })
    }

    /// Returns the actual local endpoint.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Returns the observed peer endpoint.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Returns the stable identity of this exact connection generation.
    #[must_use]
    pub const fn flow_id(&self) -> FlowId {
        self.flow_id
    }

    /// Returns driver configuration.
    #[must_use]
    pub const fn config(&self) -> TcpDriverConfig {
        self.config
    }

    /// Duplicates the connected socket handle for readiness registration.
    pub(crate) fn try_clone_socket(&self) -> io::Result<TcpStream> {
        self.socket.try_clone()
    }

    /// Returns unread bytes retained by incremental framing.
    #[must_use]
    pub fn buffered_receive_bytes(&self) -> usize {
        self.framed.len()
    }

    /// Returns bytes retained after a partial nonblocking write.
    #[must_use]
    pub fn pending_write_bytes(&self) -> usize {
        self.pending_write
            .as_ref()
            .map_or(0, |pending| pending.message.len() - pending.offset)
    }

    /// Receives the next complete, parsed, semantically validated SIP message.
    ///
    /// Pipelined messages already in the framing buffer are delivered before
    /// another system call. Partial reads remain buffered. In nonblocking mode
    /// `WouldBlock` is returned as an ordinary receive I/O error so an executor
    /// can re-arm readability without losing framing state.
    ///
    /// # Errors
    ///
    /// Preserves socket, framing, parser, validation, and flow-metadata errors.
    /// A clean peer close with incomplete bytes is reported distinctly.
    pub fn receive(&mut self) -> Result<ReceivedMessage, TcpDriverError> {
        loop {
            if let Some(bytes) = self
                .framed
                .next_message()
                .map_err(TcpDriverError::ReceiveBuffer)?
            {
                return self.validate_received(bytes);
            }
            if self.peer_closed {
                return if self.framed.is_empty() {
                    Err(TcpDriverError::PeerClosed)
                } else {
                    Err(TcpDriverError::TruncatedStream {
                        buffered_bytes: self.framed.len(),
                    })
                };
            }

            let length = match self.socket.read(&mut self.read_storage) {
                Ok(length) => length,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(TcpDriverError::Receive(source)),
            };
            if length == 0 {
                self.peer_closed = true;
                continue;
            }
            self.framed
                .append(&self.read_storage[..length])
                .map_err(TcpDriverError::ReceiveBuffer)?;
        }
    }

    /// Starts one complete serialized SIP write and performs one bounded flush.
    ///
    /// The caller should admit messages through the connection queue before
    /// this method. Only one message may be partially written at a time,
    /// preserving wire order without an unbounded socket-layer queue.
    ///
    /// # Errors
    ///
    /// Rejects an empty/oversized message or a second write while one remains
    /// pending, and preserves socket write errors.
    pub fn start_send(&mut self, message: Arc<[u8]>) -> Result<WriteProgress, TcpDriverError> {
        if self.pending_write.is_some() {
            return Err(TcpDriverError::WriteAlreadyPending);
        }
        if message.is_empty() {
            return Err(TcpDriverError::EmptyMessage);
        }
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(TcpDriverError::MessageTooLarge {
                length: message.len(),
                maximum: MAX_MESSAGE_BYTES,
            });
        }
        self.pending_write = Some(PendingWrite { message, offset: 0 });
        self.flush_send()
    }

    /// Performs one write attempt for the retained message.
    ///
    /// `WouldBlock` is represented as [`WriteProgress::Pending`], not failure.
    /// The immutable message remains owned until every byte reaches the kernel.
    ///
    /// # Errors
    ///
    /// Rejects calls with no pending message, zero-byte writes, and socket
    /// failures other than `WouldBlock`.
    pub fn flush_send(&mut self) -> Result<WriteProgress, TcpDriverError> {
        let Some(pending) = self.pending_write.as_mut() else {
            return Err(TcpDriverError::NoWritePending);
        };
        let remaining = &pending.message[pending.offset..];
        let written = loop {
            match self.socket.write(remaining) {
                Ok(written) => break written,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(WriteProgress::Pending {
                        remaining_bytes: remaining.len(),
                    });
                }
                Err(source) => return Err(TcpDriverError::Send(source)),
            }
        };
        if written == 0 {
            return Err(TcpDriverError::WriteZero);
        }
        pending.offset += written;
        let remaining_bytes = pending.message.len() - pending.offset;
        if remaining_bytes == 0 {
            self.pending_write = None;
            Ok(WriteProgress::Complete)
        } else {
            Ok(WriteProgress::Pending { remaining_bytes })
        }
    }

    /// Shuts down both directions of the TCP flow.
    ///
    /// # Errors
    ///
    /// Preserves the operating-system shutdown failure.
    pub fn shutdown(&self) -> Result<(), TcpDriverError> {
        self.socket
            .shutdown(Shutdown::Both)
            .map_err(TcpDriverError::Shutdown)
    }

    fn validate_received(&self, bytes: Arc<[u8]>) -> Result<ReceivedMessage, TcpDriverError> {
        let raw = message::parse(bytes).map_err(TcpDriverError::Parse)?;
        let message = match raw.kind() {
            MessageKind::Request => InboundMessage::Request(
                request::validate(raw).map_err(TcpDriverError::RequestValidation)?,
            ),
            MessageKind::Response => InboundMessage::Response(
                response::validate(raw).map_err(TcpDriverError::ResponseValidation)?,
            ),
        };
        let ingress = IngressMeta::new(
            self.peer,
            self.local,
            Protocol::Tcp,
            Some(self.flow_id),
            None,
        )
        .map_err(TcpDriverError::Ingress)?;
        Ok(ReceivedMessage::new(message, ingress, 0))
    }
}

impl fmt::Debug for TcpDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpDriver")
            .field(
                "address_family",
                &if self.local.is_ipv4() { "ipv4" } else { "ipv6" },
            )
            .field("flow_id", &self.flow_id)
            .field("buffered_receive_bytes", &self.framed.len())
            .field("pending_write_bytes", &self.pending_write_bytes())
            .field("peer_closed", &self.peer_closed)
            .field("nonblocking", &self.config.nonblocking)
            .finish_non_exhaustive()
    }
}

fn validate_endpoint(endpoint: SocketAddr) -> Result<(), ()> {
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() {
        Err(())
    } else {
        Ok(())
    }
}

/// TCP socket, framing, parsing, validation, or write-state failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum TcpDriverError {
    /// Receive-buffer ceiling was outside hard bounds.
    InvalidReceiveBufferLimit {
        /// Rejected value.
        value: usize,
        /// Required minimum.
        minimum: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Permanent read-storage size was zero or excessive.
    InvalidReadChunkLimit {
        /// Rejected value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Establishment deadline was zero or excessive.
    InvalidConnectTimeout,
    /// A non-TCP destination reached the plaintext TCP boundary.
    WrongProtocol {
        /// Destination protocol.
        actual: Protocol,
    },
    /// Outbound establishment failed.
    Connect(io::Error),
    /// Local endpoint query failed.
    LocalAddress(io::Error),
    /// Peer endpoint query failed.
    PeerAddress(io::Error),
    /// Established local endpoint was unusable as transport truth.
    InvalidLocalAddress,
    /// Established peer endpoint was unusable as transport truth.
    InvalidPeerAddress,
    /// `TCP_NODELAY` configuration failed.
    ConfigureNoDelay(io::Error),
    /// Nonblocking configuration failed.
    ConfigureNonblocking(io::Error),
    /// Permanent read storage allocation failed.
    AllocationFailed,
    /// Bounded stream framing/buffering failed.
    ReceiveBuffer(TcpError),
    /// Socket receive failed, including `WouldBlock`.
    Receive(io::Error),
    /// Peer closed after all complete messages were consumed.
    PeerClosed,
    /// Peer closed with an incomplete message retained.
    TruncatedStream {
        /// Incomplete retained byte count.
        buffered_bytes: usize,
    },
    /// Structural parsing rejected a complete frame.
    Parse(ParseError),
    /// Request semantic validation failed.
    RequestValidation(request::ValidationError),
    /// Response semantic validation failed.
    ResponseValidation(response::ValidationError),
    /// Transport-truth metadata validation failed.
    Ingress(FlowError),
    /// A socket-layer write was already partially pending.
    WriteAlreadyPending,
    /// No message was available to flush.
    NoWritePending,
    /// Empty serialized SIP messages are forbidden.
    EmptyMessage,
    /// Serialized message exceeded the framing hard limit.
    MessageTooLarge {
        /// Observed bytes.
        length: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Socket write failed.
    Send(io::Error),
    /// Socket accepted zero bytes for a nonempty write.
    WriteZero,
    /// Socket shutdown failed.
    Shutdown(io::Error),
}

impl TcpDriverError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::InvalidReceiveBufferLimit { .. } => "invalid-receive-buffer-limit",
            Self::InvalidReadChunkLimit { .. } => "invalid-read-chunk-limit",
            Self::InvalidConnectTimeout => "invalid-connect-timeout",
            Self::WrongProtocol { .. } => "wrong-protocol",
            Self::Connect(_) => "connect",
            Self::LocalAddress(_) => "local-address",
            Self::PeerAddress(_) => "peer-address",
            Self::InvalidLocalAddress => "invalid-local-address",
            Self::InvalidPeerAddress => "invalid-peer-address",
            Self::ConfigureNoDelay(_) => "configure-no-delay",
            Self::ConfigureNonblocking(_) => "configure-nonblocking",
            Self::AllocationFailed => "allocation-failed",
            Self::ReceiveBuffer(_) => "receive-buffer",
            Self::Receive(_) => "receive",
            Self::PeerClosed => "peer-closed",
            Self::TruncatedStream { .. } => "truncated-stream",
            Self::Parse(_) => "parse",
            Self::RequestValidation(_) => "request-validation",
            Self::ResponseValidation(_) => "response-validation",
            Self::Ingress(_) => "ingress",
            Self::WriteAlreadyPending => "write-already-pending",
            Self::NoWritePending => "no-write-pending",
            Self::EmptyMessage => "empty-message",
            Self::MessageTooLarge { .. } => "message-too-large",
            Self::Send(_) => "send",
            Self::WriteZero => "write-zero",
            Self::Shutdown(_) => "shutdown",
        }
    }

    /// Returns an operating-system error kind when applicable.
    #[must_use]
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Connect(source)
            | Self::LocalAddress(source)
            | Self::PeerAddress(source)
            | Self::ConfigureNoDelay(source)
            | Self::ConfigureNonblocking(source)
            | Self::Receive(source)
            | Self::Send(source)
            | Self::Shutdown(source) => Some(source.kind()),
            _ => None,
        }
    }
}

impl fmt::Display for TcpDriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP TCP driver error: {}", self.class())
    }
}

impl StdError for TcpDriverError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connect(source)
            | Self::LocalAddress(source)
            | Self::PeerAddress(source)
            | Self::ConfigureNoDelay(source)
            | Self::ConfigureNonblocking(source)
            | Self::Receive(source)
            | Self::Send(source)
            | Self::Shutdown(source) => Some(source),
            Self::ReceiveBuffer(source) => Some(source),
            Self::Parse(source) => Some(source),
            Self::RequestValidation(source) => Some(source),
            Self::ResponseValidation(source) => Some(source),
            Self::Ingress(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::time::Duration;

    use super::{TcpDriver, TcpDriverConfig, TcpDriverError, WriteProgress};
    use crate::sip::transport::InboundMessage;
    use crate::sip::transport::destination::{Destination, Protocol};
    use crate::sip::transport::flow::FlowId;

    const REQUEST: &[u8] = b"OPTIONS sip:runtime@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP caller.example.com;branch=z9hG4bK-one\r\n\
From: <sip:caller@example.com>;tag=a\r\n\
To: <sip:runtime@example.com>\r\n\
Call-ID: one@example.com\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n";

    fn pair() -> (TcpStream, TcpStream) {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("listener"));
        let address = listener.local_addr().unwrap_or_else(|_| panic!("address"));
        let client = TcpStream::connect(address).unwrap_or_else(|_| panic!("connect"));
        let (server, _) = listener.accept().unwrap_or_else(|_| panic!("accept"));
        (client, server)
    }

    fn blocking_config() -> TcpDriverConfig {
        TcpDriverConfig::default().with_nonblocking(false)
    }

    #[test]
    fn receives_partial_and_pipelined_messages_with_flow_truth() {
        let (mut client, server) = pair();
        let flow = FlowId::new(17).unwrap_or_else(|_| panic!("flow"));
        let mut driver = TcpDriver::from_stream(server, flow, blocking_config())
            .unwrap_or_else(|_| panic!("driver"));

        assert!(client.write_all(&REQUEST[..31]).is_ok());
        assert!(client.write_all(&REQUEST[31..]).is_ok());
        assert!(client.write_all(REQUEST).is_ok());

        let first = driver.receive().unwrap_or_else(|_| panic!("first"));
        let second = driver.receive().unwrap_or_else(|_| panic!("second"));
        assert!(matches!(first.message(), InboundMessage::Request(_)));
        assert!(matches!(second.message(), InboundMessage::Request(_)));
        assert_eq!(first.ingress().protocol(), Protocol::Tcp);
        assert_eq!(first.ingress().flow_id(), Some(flow));
        assert_eq!(first.ingress().source(), driver.peer_addr());
        assert_eq!(first.ingress().destination(), driver.local_addr());
        assert_eq!(first.discarded_trailing_bytes(), 0);
    }

    #[test]
    fn sends_one_immutable_message_and_tracks_write_state() {
        let (mut client, server) = pair();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap_or_else(|_| panic!("timeout"));
        let flow = FlowId::new(18).unwrap_or_else(|_| panic!("flow"));
        let mut driver = TcpDriver::from_stream(server, flow, blocking_config())
            .unwrap_or_else(|_| panic!("driver"));

        assert!(matches!(
            driver.start_send(Arc::from(REQUEST)),
            Ok(WriteProgress::Complete)
        ));
        assert_eq!(driver.pending_write_bytes(), 0);
        assert!(matches!(
            driver.flush_send(),
            Err(TcpDriverError::NoWritePending)
        ));

        let mut received = vec![0_u8; REQUEST.len()];
        assert!(client.read_exact(&mut received).is_ok());
        assert_eq!(received, REQUEST);
    }

    #[test]
    fn reports_clean_and_truncated_peer_close_distinctly() {
        let (mut client, server) = pair();
        let flow = FlowId::new(19).unwrap_or_else(|_| panic!("flow"));
        let mut driver = TcpDriver::from_stream(server, flow, blocking_config())
            .unwrap_or_else(|_| panic!("driver"));
        assert!(client.write_all(&REQUEST[..40]).is_ok());
        drop(client);
        assert!(matches!(
            driver.receive(),
            Err(TcpDriverError::TruncatedStream { buffered_bytes: 40 })
        ));

        let (client, server) = pair();
        let mut driver = TcpDriver::from_stream(server, flow, blocking_config())
            .unwrap_or_else(|_| panic!("driver"));
        drop(client);
        assert!(matches!(driver.receive(), Err(TcpDriverError::PeerClosed)));
    }

    #[test]
    fn connect_requires_tcp_and_debug_redacts_endpoints() {
        let udp = Destination::udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 5060)))
            .unwrap_or_else(|_| panic!("destination"));
        let flow = FlowId::new(20).unwrap_or_else(|_| panic!("flow"));
        assert!(matches!(
            TcpDriver::connect(&udp, flow, TcpDriverConfig::default()),
            Err(TcpDriverError::WrongProtocol {
                actual: Protocol::Udp
            })
        ));

        let (_client, server) = pair();
        let driver = TcpDriver::from_stream(server, flow, blocking_config())
            .unwrap_or_else(|_| panic!("driver"));
        let debug = format!("{driver:?}");
        assert!(!debug.contains("127.0.0.1"));
    }

    #[test]
    fn configuration_rejects_unbounded_values() {
        assert!(matches!(
            TcpDriverConfig::new(1, 1, Duration::from_secs(1)),
            Err(TcpDriverError::InvalidReceiveBufferLimit { .. })
        ));
        assert!(matches!(
            TcpDriverConfig::new(
                super::MAX_MESSAGE_BYTES,
                super::MAX_READ_CHUNK_BYTES + 1,
                Duration::from_secs(1)
            ),
            Err(TcpDriverError::InvalidReadChunkLimit { .. })
        ));
        assert!(matches!(
            TcpDriverConfig::new(super::MAX_MESSAGE_BYTES, 1, Duration::ZERO),
            Err(TcpDriverError::InvalidConnectTimeout)
        ));
    }
}
