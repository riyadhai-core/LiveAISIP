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

//! Runtime-neutral SIP-over-UDP socket driver.
//!
//! This is the operating-system boundary for UDP signaling. It owns one
//! explicitly bound socket and one reusable receive buffer, frames exactly one
//! datagram, copies only the admitted SIP message into immutable shared
//! storage, parses and validates it, and attaches transport-truth metadata.
//! Transaction and call state remain outside this driver.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use crate::sip::framing::{self, Mode, Status};
use crate::sip::parser::message::{self, ParseError};
use crate::sip::types::message::MessageKind;
use crate::sip::validation::{request, response};

use super::destination::Protocol;
use super::flow::{FlowError, IngressMeta};
use super::udp::{MAX_UDP_PAYLOAD_BYTES, OutboundDatagram};

/// Default admitted inbound SIP datagram size.
pub const DEFAULT_RECEIVE_DATAGRAM_BYTES: usize = MAX_UDP_PAYLOAD_BYTES;

/// Validated UDP driver limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpDriverConfig {
    maximum_datagram_bytes: usize,
    nonblocking: bool,
}

impl UdpDriverConfig {
    /// Creates a nonblocking configuration with an explicit receive ceiling.
    ///
    /// # Errors
    ///
    /// Rejects zero or values above the portable UDP payload maximum.
    pub const fn new(maximum_datagram_bytes: usize) -> Result<Self, UdpDriverError> {
        if maximum_datagram_bytes == 0 || maximum_datagram_bytes > MAX_UDP_PAYLOAD_BYTES {
            return Err(UdpDriverError::InvalidDatagramLimit {
                value: maximum_datagram_bytes,
                maximum: MAX_UDP_PAYLOAD_BYTES,
            });
        }
        Ok(Self {
            maximum_datagram_bytes,
            nonblocking: true,
        })
    }

    /// Selects blocking behavior for dedicated-thread deployments.
    #[must_use]
    pub const fn with_nonblocking(mut self, nonblocking: bool) -> Self {
        self.nonblocking = nonblocking;
        self
    }

    /// Returns the admitted receive ceiling.
    #[must_use]
    pub const fn maximum_datagram_bytes(self) -> usize {
        self.maximum_datagram_bytes
    }

    /// Returns whether the socket is nonblocking.
    #[must_use]
    pub const fn nonblocking(self) -> bool {
        self.nonblocking
    }
}

impl Default for UdpDriverConfig {
    fn default() -> Self {
        Self {
            maximum_datagram_bytes: DEFAULT_RECEIVE_DATAGRAM_BYTES,
            nonblocking: true,
        }
    }
}

/// Fully validated inbound UDP message.
pub enum InboundMessage {
    /// Request ready for server-transaction routing.
    Request(request::ValidatedRequest),
    /// Response ready for client-transaction routing.
    Response(response::ValidatedResponse),
}

impl InboundMessage {
    /// Returns the parsed message kind.
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::Request(_) => MessageKind::Request,
            Self::Response(_) => MessageKind::Response,
        }
    }

    /// Returns a validated request when this is a request.
    #[must_use]
    pub const fn as_request(&self) -> Option<&request::ValidatedRequest> {
        match self {
            Self::Request(value) => Some(value),
            Self::Response(_) => None,
        }
    }

    /// Returns a validated response when this is a response.
    #[must_use]
    pub const fn as_response(&self) -> Option<&response::ValidatedResponse> {
        match self {
            Self::Response(value) => Some(value),
            Self::Request(_) => None,
        }
    }
}

impl fmt::Debug for InboundMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundMessage")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// One received message plus authoritative network facts.
pub struct ReceivedMessage {
    message: InboundMessage,
    ingress: IngressMeta,
    discarded_trailing_bytes: usize,
}

impl ReceivedMessage {
    /// Creates a transport-neutral validated receive envelope.
    pub(crate) const fn new(
        message: InboundMessage,
        ingress: IngressMeta,
        discarded_trailing_bytes: usize,
    ) -> Self {
        Self {
            message,
            ingress,
            discarded_trailing_bytes,
        }
    }

    /// Returns the validated message.
    #[must_use]
    pub const fn message(&self) -> &InboundMessage {
        &self.message
    }

    /// Returns transport-truth metadata.
    #[must_use]
    pub const fn ingress(&self) -> &IngressMeta {
        &self.ingress
    }

    /// Returns bytes excluded after an authoritative `Content-Length` body.
    #[must_use]
    pub const fn discarded_trailing_bytes(&self) -> usize {
        self.discarded_trailing_bytes
    }

    /// Consumes the envelope into message and transport metadata.
    #[must_use]
    pub fn into_parts(self) -> (InboundMessage, IngressMeta) {
        (self.message, self.ingress)
    }
}

impl fmt::Debug for ReceivedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceivedMessage")
            .field("kind", &self.message.kind())
            .field("ingress", &self.ingress)
            .field("discarded_trailing_bytes", &self.discarded_trailing_bytes)
            .finish_non_exhaustive()
    }
}

/// Bound SIP-over-UDP driver with permanent receive storage.
pub struct UdpDriver {
    socket: UdpSocket,
    local: SocketAddr,
    config: UdpDriverConfig,
    receive: Box<[u8]>,
}

impl UdpDriver {
    /// Binds one explicit local interface and allocates receive storage once.
    ///
    /// Port zero is allowed for ephemeral test/client bindings. Wildcard IPs
    /// are rejected because portable `recv_from` cannot recover the exact
    /// destination address needed for truthful ingress metadata.
    ///
    /// # Errors
    ///
    /// Rejects wildcard binding, allocation failure, or operating-system bind,
    /// configuration, and local-address failures.
    pub fn bind(local: SocketAddr, config: UdpDriverConfig) -> Result<Self, UdpDriverError> {
        if local.ip().is_unspecified() {
            return Err(UdpDriverError::UnspecifiedBindAddress);
        }
        let storage_bytes = config
            .maximum_datagram_bytes
            .checked_add(1)
            .ok_or(UdpDriverError::AllocationFailed)?;
        let mut receive = Vec::new();
        receive
            .try_reserve_exact(storage_bytes)
            .map_err(|_| UdpDriverError::AllocationFailed)?;
        receive.resize(storage_bytes, 0);

        let socket = UdpSocket::bind(local).map_err(UdpDriverError::Bind)?;
        socket
            .set_nonblocking(config.nonblocking)
            .map_err(UdpDriverError::Configure)?;
        let local = socket.local_addr().map_err(UdpDriverError::LocalAddress)?;
        Ok(Self {
            socket,
            local,
            config,
            receive: receive.into_boxed_slice(),
        })
    }

    /// Returns the actual bound endpoint.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Returns driver configuration.
    #[must_use]
    pub const fn config(&self) -> UdpDriverConfig {
        self.config
    }

    /// Duplicates the socket handle for readiness registration.
    ///
    /// The duplicate observes readiness for the same underlying socket while
    /// keeping the reactor's registration lifetime independent from this
    /// driver's ownership lifetime.
    pub(crate) fn try_clone_socket(&self) -> io::Result<UdpSocket> {
        self.socket.try_clone()
    }

    /// Receives, frames, parses, validates, and annotates one SIP datagram.
    ///
    /// # Errors
    ///
    /// Preserves operating-system receive failure, size/framing/parser errors,
    /// semantic request/response validation, and ingress-metadata validation.
    pub fn receive(&mut self) -> Result<ReceivedMessage, UdpDriverError> {
        let (length, source) = self
            .socket
            .recv_from(&mut self.receive)
            .map_err(UdpDriverError::Receive)?;
        if length == 0 {
            return Err(UdpDriverError::EmptyDatagram);
        }
        if length > self.config.maximum_datagram_bytes {
            return Err(UdpDriverError::DatagramTooLarge {
                observed_at_least: length,
                maximum: self.config.maximum_datagram_bytes,
            });
        }
        let datagram = &self.receive[..length];
        let boundary =
            match framing::inspect(datagram, Mode::Datagram).map_err(UdpDriverError::Framing)? {
                Status::Complete(boundary) => boundary,
                Status::NeedMoreData { .. } => return Err(UdpDriverError::IncompleteDatagram),
            };
        let range = boundary.message_range();
        let bytes = datagram
            .get(range)
            .ok_or(UdpDriverError::InternalBoundary)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| UdpDriverError::AllocationFailed)?;
        owned.extend_from_slice(bytes);
        let raw =
            message::parse(Arc::from(owned.into_boxed_slice())).map_err(UdpDriverError::Parse)?;
        let message = match raw.kind() {
            MessageKind::Request => InboundMessage::Request(
                request::validate(raw).map_err(UdpDriverError::RequestValidation)?,
            ),
            MessageKind::Response => InboundMessage::Response(
                response::validate(raw).map_err(UdpDriverError::ResponseValidation)?,
            ),
        };
        let ingress = IngressMeta::new(source, self.local, Protocol::Udp, None, None)
            .map_err(UdpDriverError::Ingress)?;
        Ok(ReceivedMessage::new(
            message,
            ingress,
            boundary.discarded_trailing_bytes(),
        ))
    }

    /// Sends one previously admitted immutable UDP SIP message.
    ///
    /// # Errors
    ///
    /// Preserves operating-system failure and rejects partial datagram writes.
    pub fn send(&self, datagram: &OutboundDatagram) -> Result<(), UdpDriverError> {
        let payload = datagram.payload();
        let written = self
            .socket
            .send_to(payload, datagram.destination().remote())
            .map_err(UdpDriverError::Send)?;
        if written != payload.len() {
            return Err(UdpDriverError::PartialWrite {
                expected: payload.len(),
                written,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for UdpDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpDriver")
            .field(
                "address_family",
                &if self.local.is_ipv4() { "ipv4" } else { "ipv6" },
            )
            .field(
                "maximum_datagram_bytes",
                &self.config.maximum_datagram_bytes,
            )
            .field("nonblocking", &self.config.nonblocking)
            .finish_non_exhaustive()
    }
}

/// UDP socket, framing, parsing, or validation failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum UdpDriverError {
    /// Receive ceiling was zero or excessive.
    InvalidDatagramLimit {
        /// Rejected value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Exact destination metadata is unavailable for wildcard binds.
    UnspecifiedBindAddress,
    /// Permanent receive storage allocation failed.
    AllocationFailed,
    /// Socket bind failed.
    Bind(io::Error),
    /// Nonblocking configuration failed.
    Configure(io::Error),
    /// Bound local address query failed.
    LocalAddress(io::Error),
    /// Datagram receive failed, including `WouldBlock`.
    Receive(io::Error),
    /// Empty UDP payload is not a SIP message.
    EmptyDatagram,
    /// Datagram exceeded the operational receive ceiling.
    DatagramTooLarge {
        /// Exact or lower-bound observed bytes.
        observed_at_least: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Datagram framing unexpectedly requested more bytes.
    IncompleteDatagram,
    /// Framing rejected the message.
    Framing(framing::Error),
    /// Framing returned an impossible range.
    InternalBoundary,
    /// Structural parsing rejected the message.
    Parse(ParseError),
    /// Request semantic validation failed.
    RequestValidation(request::ValidationError),
    /// Response semantic validation failed.
    ResponseValidation(response::ValidationError),
    /// Transport-truth metadata validation failed.
    Ingress(FlowError),
    /// Datagram send failed.
    Send(io::Error),
    /// Operating system reported a partial UDP write.
    PartialWrite {
        /// Expected payload bytes.
        expected: usize,
        /// Reported bytes written.
        written: usize,
    },
}

impl UdpDriverError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::InvalidDatagramLimit { .. } => "invalid-datagram-limit",
            Self::UnspecifiedBindAddress => "unspecified-bind-address",
            Self::AllocationFailed => "allocation-failed",
            Self::Bind(_) => "bind",
            Self::Configure(_) => "configure",
            Self::LocalAddress(_) => "local-address",
            Self::Receive(_) => "receive",
            Self::EmptyDatagram => "empty-datagram",
            Self::DatagramTooLarge { .. } => "datagram-too-large",
            Self::IncompleteDatagram => "incomplete-datagram",
            Self::Framing(_) => "framing",
            Self::InternalBoundary => "internal-boundary",
            Self::Parse(_) => "parse",
            Self::RequestValidation(_) => "request-validation",
            Self::ResponseValidation(_) => "response-validation",
            Self::Ingress(_) => "ingress",
            Self::Send(_) => "send",
            Self::PartialWrite { .. } => "partial-write",
        }
    }

    /// Returns an operating-system error kind when applicable.
    #[must_use]
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Bind(source)
            | Self::Configure(source)
            | Self::LocalAddress(source)
            | Self::Receive(source)
            | Self::Send(source) => Some(source.kind()),
            _ => None,
        }
    }
}

impl fmt::Display for UdpDriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP UDP driver error: {}", self.class())
    }
}

impl StdError for UdpDriverError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Bind(source)
            | Self::Configure(source)
            | Self::LocalAddress(source)
            | Self::Receive(source)
            | Self::Send(source) => Some(source),
            Self::Framing(source) => Some(source),
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
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::sync::Arc;

    use super::{InboundMessage, UdpDriver, UdpDriverConfig, UdpDriverError};
    use crate::sip::transport::destination::Destination;
    use crate::sip::transport::udp::{OutboundDatagram, UdpConfig};

    fn request(extra: &[u8]) -> Vec<u8> {
        let mut bytes = b"OPTIONS sip:runtime@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP caller.example.com;branch=z9hG4bK-one;rport\r\n\
From: <sip:caller@example.com>;tag=a\r\n\
To: <sip:runtime@example.com>\r\n\
Call-ID: one@example.com\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
            .to_vec();
        bytes.extend_from_slice(extra);
        bytes
    }

    fn blocking_driver(limit: usize) -> UdpDriver {
        UdpDriver::bind(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            UdpDriverConfig::new(limit)
                .unwrap_or_else(|_| panic!("config"))
                .with_nonblocking(false),
        )
        .unwrap_or_else(|_| panic!("bind"))
    }

    #[test]
    fn receives_frames_validates_and_attaches_transport_truth() {
        let mut driver = blocking_driver(2_048);
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("sender"));
        let source = sender.local_addr().unwrap_or_else(|_| panic!("source"));
        assert!(
            sender
                .send_to(&request(b"trailing"), driver.local_addr())
                .is_ok()
        );
        let received = driver.receive().unwrap_or_else(|_| panic!("receive"));
        assert!(matches!(received.message(), InboundMessage::Request(_)));
        assert_eq!(received.ingress().source(), source);
        assert_eq!(received.ingress().destination(), driver.local_addr());
        assert_eq!(received.ingress().protocol(), super::Protocol::Udp);
        assert_eq!(received.discarded_trailing_bytes(), 8);
    }

    #[test]
    fn sends_an_admitted_immutable_datagram() {
        let driver = blocking_driver(2_048);
        let receiver =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("receiver"));
        let destination = Destination::udp(
            receiver
                .local_addr()
                .unwrap_or_else(|_| panic!("receiver address")),
        )
        .unwrap_or_else(|_| panic!("destination"));
        let datagram = OutboundDatagram::new(
            destination,
            Arc::from(request(&[]).into_boxed_slice()),
            UdpConfig::default(),
        )
        .unwrap_or_else(|_| panic!("datagram"));
        assert!(driver.send(&datagram).is_ok());
        let mut bytes = [0_u8; 2_048];
        let (length, _) = receiver
            .recv_from(&mut bytes)
            .unwrap_or_else(|_| panic!("receive"));
        assert_eq!(&bytes[..length], datagram.payload());
    }

    #[test]
    fn rejects_oversized_and_wildcard_inputs_without_disclosure() {
        assert!(matches!(
            UdpDriver::bind(
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                UdpDriverConfig::default()
            ),
            Err(UdpDriverError::UnspecifiedBindAddress)
        ));
        let mut driver = blocking_driver(64);
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("sender"));
        assert!(sender.send_to(&request(&[]), driver.local_addr()).is_ok());
        assert!(matches!(
            driver.receive(),
            Err(UdpDriverError::DatagramTooLarge { maximum: 64, .. })
        ));
        let debug = format!("{driver:?}");
        assert!(!debug.contains("127.0.0.1"));
    }
}
