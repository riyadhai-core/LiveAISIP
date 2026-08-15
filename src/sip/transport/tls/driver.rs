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

//! Verified outbound SIP-over-TLS socket driver.
//!
//! This is the cryptographic transport boundary for LiveAISIP Runtime. Every
//! flow verifies the peer chain and the destination's explicit DNS/IP identity;
//! there is no insecure verifier switch. TCP establishment and the TLS
//! handshake have independent deadlines. Peer-chain metadata, decrypted SIP
//! framing, Rustls buffering, and socket writes remain bounded.
//!
//! The driver accepts one partially committed outbound SIP message at a time.
//! A message is complete only after all resulting TLS records have reached the
//! kernel socket buffer, preserving the distinction between plaintext accepted
//! by Rustls and bytes committed to the wire.

#[path = "client.rs"]
mod client;
#[path = "error.rs"]
mod error;
#[path = "handshake.rs"]
mod handshake;
#[path = "write.rs"]
mod write_state;

pub use client::{MAX_TRUST_ROOT_BYTES, MAX_TRUST_ROOTS, TlsClientConfig};
pub use error::TlsDriverError;
pub use write_state::{TlsShutdownProgress, TlsWriteProgress};

use handshake::{
    allocate_zeroed, drive_handshake, flush_tls_once, map_negotiated_version, server_name,
    total_certificate_bytes, validate_endpoint,
};
use write_state::PendingWrite;

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;

use rustls::ClientConnection;

use crate::sip::framing::MAX_MESSAGE_BYTES;
use crate::sip::parser::message;
use crate::sip::types::message::MessageKind;
use crate::sip::validation::{request, response};

use super::destination::{Destination, Protocol, TlsIdentity};
use super::flow::{FlowId, IngressMeta};
use super::tcp::ReceiveBuffer;
use super::tcp_driver::TcpDriverConfig;
use super::tls::{Handshake, TlsVersion};
use super::{InboundMessage, ReceivedMessage};

/// One established, verified, bounded outbound SIP-over-TLS flow.
pub struct TlsDriver {
    connection: ClientConnection,
    socket: TcpStream,
    local: SocketAddr,
    peer: SocketAddr,
    flow_id: FlowId,
    verified_peer: TlsIdentity,
    negotiated_version: TlsVersion,
    tcp_config: TcpDriverConfig,
    framed: ReceiveBuffer,
    read_storage: Box<[u8]>,
    pending_write: Option<PendingWrite>,
    peer_closed: bool,
    close_notify_started: bool,
    write_shutdown: bool,
}

impl TlsDriver {
    /// Establishes TCP, performs a verified TLS handshake, and returns a flow.
    ///
    /// # Errors
    ///
    /// Rejects non-TLS destinations and preserves TCP, TLS, identity, chain,
    /// timeout, endpoint, configuration, and allocation failures.
    pub fn connect(
        destination: &Destination,
        flow_id: FlowId,
        tls_config: &TlsClientConfig,
        tcp_config: TcpDriverConfig,
    ) -> Result<Self, TlsDriverError> {
        if destination.protocol() != Protocol::Tls {
            return Err(TlsDriverError::WrongProtocol {
                actual: destination.protocol(),
            });
        }
        let socket =
            TcpStream::connect_timeout(&destination.remote(), tcp_config.connect_timeout())
                .map_err(TlsDriverError::Connect)?;
        Self::from_stream(socket, destination, flow_id, tls_config, tcp_config)
    }

    /// Performs a verified client handshake over an established TCP stream.
    ///
    /// This supports preconnected sockets while retaining the destination's
    /// independently resolved certificate identity.
    ///
    /// # Errors
    ///
    /// Preserves the same verification and resource failures as [`Self::connect`].
    pub fn from_stream(
        mut socket: TcpStream,
        destination: &Destination,
        flow_id: FlowId,
        tls_config: &TlsClientConfig,
        tcp_config: TcpDriverConfig,
    ) -> Result<Self, TlsDriverError> {
        if destination.protocol() != Protocol::Tls {
            return Err(TlsDriverError::WrongProtocol {
                actual: destination.protocol(),
            });
        }
        let verified_peer = destination
            .tls_identity()
            .cloned()
            .ok_or(TlsDriverError::MissingPeerIdentity)?;
        let local = socket.local_addr().map_err(TlsDriverError::LocalAddress)?;
        let peer = socket.peer_addr().map_err(TlsDriverError::PeerAddress)?;
        validate_endpoint(local).map_err(|()| TlsDriverError::InvalidLocalAddress)?;
        validate_endpoint(peer).map_err(|()| TlsDriverError::InvalidPeerAddress)?;
        if peer != destination.remote() {
            return Err(TlsDriverError::PeerDestinationMismatch);
        }

        let framed = ReceiveBuffer::new(tcp_config.receive_buffer_bytes())
            .map_err(TlsDriverError::ReceiveBuffer)?;
        let read_storage = allocate_zeroed(tcp_config.read_chunk_bytes())?;

        socket
            .set_nonblocking(false)
            .map_err(TlsDriverError::ConfigureBlockingHandshake)?;
        socket
            .set_nodelay(tcp_config.no_delay())
            .map_err(TlsDriverError::ConfigureNoDelay)?;

        let server_name = server_name(&verified_peer)?;
        let mut lifecycle = Handshake::new(destination.clone(), tls_config.policy)
            .map_err(TlsDriverError::Policy)?;
        lifecycle.start().map_err(TlsDriverError::Policy)?;

        let mut connection = ClientConnection::new(Arc::clone(&tls_config.backend), server_name)
            .map_err(TlsDriverError::TlsProtocol)?;
        connection.set_buffer_limit(Some(MAX_MESSAGE_BYTES));
        drive_handshake(
            &mut connection,
            &mut socket,
            tls_config.policy.handshake_timeout(),
        )?;

        let certificates = connection
            .peer_certificates()
            .ok_or(TlsDriverError::MissingPeerCertificates)?;
        let chain_bytes = total_certificate_bytes(certificates)?;
        lifecycle
            .admit_peer_chain(chain_bytes, certificates.len())
            .map_err(TlsDriverError::Policy)?;
        let negotiated_version = map_negotiated_version(connection.protocol_version())?;
        if negotiated_version < tls_config.policy.minimum_version() {
            return Err(TlsDriverError::NegotiatedVersionBelowMinimum);
        }
        lifecycle.establish().map_err(TlsDriverError::Policy)?;

        socket
            .set_read_timeout(None)
            .map_err(TlsDriverError::ConfigureReadTimeout)?;
        socket
            .set_write_timeout(None)
            .map_err(TlsDriverError::ConfigureWriteTimeout)?;
        socket
            .set_nonblocking(tcp_config.nonblocking())
            .map_err(TlsDriverError::ConfigureNonblocking)?;

        Ok(Self {
            connection,
            socket,
            local,
            peer,
            flow_id,
            verified_peer,
            negotiated_version,
            tcp_config,
            framed,
            read_storage,
            pending_write: None,
            peer_closed: false,
            close_notify_started: false,
            write_shutdown: false,
        })
    }

    /// Returns the actual local endpoint.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Returns the observed connected peer endpoint.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Returns the stable identity of this exact TLS connection generation.
    #[must_use]
    pub const fn flow_id(&self) -> FlowId {
        self.flow_id
    }

    /// Returns the verified destination identity without certificate details.
    #[must_use]
    pub const fn verified_peer_identity(&self) -> &TlsIdentity {
        &self.verified_peer
    }

    /// Returns the negotiated TLS protocol version.
    #[must_use]
    pub const fn negotiated_version(&self) -> TlsVersion {
        self.negotiated_version
    }

    /// Returns whether post-handshake socket operations are nonblocking.
    #[must_use]
    pub const fn nonblocking(&self) -> bool {
        self.tcp_config.nonblocking()
    }

    /// Duplicates the connected socket handle for readiness registration.
    pub(crate) fn try_clone_socket(&self) -> io::Result<TcpStream> {
        self.socket.try_clone()
    }

    /// Returns whether Rustls retains encrypted records for the socket.
    #[must_use]
    pub(crate) fn encrypted_write_pending(&self) -> bool {
        self.connection.wants_write()
    }

    /// Performs at most one encrypted transport write without requiring an
    /// application message to be in flight.
    pub(crate) fn flush_encrypted_once(&mut self) -> Result<bool, TlsDriverError> {
        flush_tls_once(&mut self.connection, &mut self.socket)
    }

    /// Returns unread decrypted bytes retained by SIP framing.
    #[must_use]
    pub fn buffered_receive_bytes(&self) -> usize {
        self.framed.len()
    }

    /// Returns message plaintext not yet accepted into bounded Rustls storage.
    #[must_use]
    pub fn pending_plaintext_bytes(&self) -> usize {
        self.pending_write
            .as_ref()
            .map_or(0, |pending| pending.message.len() - pending.offset)
    }

    /// Returns whether any application message still awaits wire commitment.
    #[must_use]
    pub const fn has_pending_write(&self) -> bool {
        self.pending_write.is_some()
    }

    /// Receives the next complete, decrypted, parsed, and validated SIP message.
    ///
    /// Pipelined plaintext is delivered before reading another TLS record.
    /// Nonblocking `WouldBlock` is preserved as a receive I/O error without
    /// losing TLS or SIP framing state.
    ///
    /// # Errors
    ///
    /// Preserves encrypted I/O, TLS protocol, SIP framing/parser/validation,
    /// flow metadata, clean close, and truncated plaintext failures.
    pub fn receive(&mut self) -> Result<ReceivedMessage, TlsDriverError> {
        loop {
            if let Some(bytes) = self
                .framed
                .next_message()
                .map_err(TlsDriverError::ReceiveBuffer)?
            {
                return self.validate_received(bytes);
            }
            if self.peer_closed {
                return if self.framed.is_empty() {
                    Err(TlsDriverError::PeerClosed)
                } else {
                    Err(TlsDriverError::TruncatedStream {
                        buffered_bytes: self.framed.len(),
                    })
                };
            }

            match self.connection.reader().read(&mut self.read_storage) {
                Ok(0) => {
                    self.peer_closed = true;
                    continue;
                }
                Ok(length) => {
                    self.framed
                        .append(&self.read_storage[..length])
                        .map_err(TlsDriverError::ReceiveBuffer)?;
                    continue;
                }
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {}
                Err(source) if source.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(TlsDriverError::UncleanPeerClose);
                }
                Err(source) => return Err(TlsDriverError::DecryptedRead(source)),
            }

            let _ = flush_tls_once(&mut self.connection, &mut self.socket)?;
            let encrypted = match self.connection.read_tls(&mut self.socket) {
                Ok(encrypted) => encrypted,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(TlsDriverError::Receive(source)),
            };
            if encrypted == 0 {
                continue;
            }
            self.connection
                .process_new_packets()
                .map_err(TlsDriverError::TlsProtocol)?;
        }
    }

    /// Starts one serialized SIP write and performs bounded progress.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized messages, concurrent writes, or writes after
    /// graceful shutdown begins, and preserves encrypted socket failures.
    pub fn start_send(&mut self, message: Arc<[u8]>) -> Result<TlsWriteProgress, TlsDriverError> {
        if self.close_notify_started {
            return Err(TlsDriverError::WriteSideClosing);
        }
        if self.pending_write.is_some() {
            return Err(TlsDriverError::WriteAlreadyPending);
        }
        if message.is_empty() {
            return Err(TlsDriverError::EmptyMessage);
        }
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(TlsDriverError::MessageTooLarge {
                length: message.len(),
                maximum: MAX_MESSAGE_BYTES,
            });
        }
        self.pending_write = Some(PendingWrite { message, offset: 0 });
        self.flush_send()
    }

    /// Advances one pending message toward encrypted wire commitment.
    ///
    /// At most one encrypted socket write is attempted before or after adding
    /// plaintext, preventing one flow from monopolizing an executor turn.
    ///
    /// # Errors
    ///
    /// Rejects calls without a pending message and preserves Rustls writer and
    /// encrypted socket failures.
    pub fn flush_send(&mut self) -> Result<TlsWriteProgress, TlsDriverError> {
        if self.pending_write.is_none() {
            return Err(TlsDriverError::NoWritePending);
        }

        if !flush_tls_once(&mut self.connection, &mut self.socket)? {
            return Ok(self.write_progress());
        }

        let pending = self
            .pending_write
            .as_mut()
            .ok_or(TlsDriverError::NoWritePending)?;
        if pending.offset < pending.message.len() {
            let remaining = &pending.message[pending.offset..];
            match self.connection.writer().write(remaining) {
                Ok(0) => return Err(TlsDriverError::PlaintextWriteZero),
                Ok(written) => pending.offset += written,
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(self.write_progress());
                }
                Err(source) => return Err(TlsDriverError::PlaintextWrite(source)),
            }
        }

        let encrypted_flushed = flush_tls_once(&mut self.connection, &mut self.socket)?;
        let plaintext_complete = self
            .pending_write
            .as_ref()
            .is_some_and(|pending| pending.offset == pending.message.len());
        if plaintext_complete && encrypted_flushed && !self.connection.wants_write() {
            self.pending_write = None;
            Ok(TlsWriteProgress::Complete)
        } else {
            Ok(self.write_progress())
        }
    }

    /// Starts graceful TLS shutdown or advances an earlier shutdown attempt.
    ///
    /// New messages are rejected once this begins. Existing application data
    /// must be fully committed first. On completion, `close_notify` is on the
    /// wire and the TCP write half is shut down; reads may continue until the
    /// peer closes.
    ///
    /// # Errors
    ///
    /// Rejects shutdown with an application write pending and preserves TLS
    /// record or TCP half-close failures.
    pub fn shutdown(&mut self) -> Result<TlsShutdownProgress, TlsDriverError> {
        if self.pending_write.is_some() {
            return Err(TlsDriverError::ApplicationWritePending);
        }
        if self.write_shutdown {
            return Ok(TlsShutdownProgress::Complete);
        }
        if !self.close_notify_started {
            self.connection.send_close_notify();
            self.close_notify_started = true;
        }
        if !flush_tls_once(&mut self.connection, &mut self.socket)? {
            return Ok(TlsShutdownProgress::Pending);
        }
        self.socket
            .shutdown(Shutdown::Write)
            .map_err(TlsDriverError::Shutdown)?;
        self.write_shutdown = true;
        Ok(TlsShutdownProgress::Complete)
    }

    fn write_progress(&self) -> TlsWriteProgress {
        TlsWriteProgress::Pending {
            remaining_plaintext_bytes: self.pending_plaintext_bytes(),
            encrypted_flush_pending: self.connection.wants_write(),
        }
    }

    fn validate_received(&self, bytes: Arc<[u8]>) -> Result<ReceivedMessage, TlsDriverError> {
        let raw = message::parse(bytes).map_err(TlsDriverError::Parse)?;
        let message = match raw.kind() {
            MessageKind::Request => InboundMessage::Request(
                request::validate(raw).map_err(TlsDriverError::RequestValidation)?,
            ),
            MessageKind::Response => InboundMessage::Response(
                response::validate(raw).map_err(TlsDriverError::ResponseValidation)?,
            ),
        };
        let ingress = IngressMeta::new(
            self.peer,
            self.local,
            Protocol::Tls,
            Some(self.flow_id),
            Some(self.verified_peer.clone()),
        )
        .map_err(TlsDriverError::Ingress)?;
        Ok(ReceivedMessage::new(message, ingress, 0))
    }
}

impl fmt::Debug for TlsDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsDriver")
            .field(
                "address_family",
                &if self.local.is_ipv4() { "ipv4" } else { "ipv6" },
            )
            .field("flow_id", &self.flow_id)
            .field("negotiated_version", &self.negotiated_version)
            .field("buffered_receive_bytes", &self.framed.len())
            .field("pending_plaintext_bytes", &self.pending_plaintext_bytes())
            .field("encrypted_flush_pending", &self.connection.wants_write())
            .field("peer_closed", &self.peer_closed)
            .field("close_notify_started", &self.close_notify_started)
            .field("write_shutdown", &self.write_shutdown)
            .field("nonblocking", &self.tcp_config.nonblocking())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::thread;

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};

    use super::{
        TlsClientConfig, TlsDriver, TlsDriverError, TlsShutdownProgress, TlsWriteProgress,
    };
    use crate::sip::transport::InboundMessage;
    use crate::sip::transport::destination::{Destination, Protocol, TlsIdentity};
    use crate::sip::transport::flow::FlowId;
    use crate::sip::transport::tcp_driver::TcpDriverConfig;
    use crate::sip::transport::tls::{TlsPolicy, TlsVersion};

    const REQUEST: &[u8] = b"OPTIONS sip:runtime@example.com SIP/2.0\r\n\
Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bK-one\r\n\
From: <sip:caller@example.com>;tag=a\r\n\
To: <sip:runtime@example.com>\r\n\
Call-ID: one@example.com\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n";

    fn certificate() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()])
                .unwrap_or_else(|_| panic!("certificate"));
        (
            cert.der().clone(),
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
        )
    }

    fn server_config(
        cert: CertificateDer<'static>,
        key: PrivatePkcs8KeyDer<'static>,
    ) -> Arc<ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|_| panic!("versions"));
        Arc::new(
            builder
                .with_no_client_auth()
                .with_single_cert(vec![cert], key.into())
                .unwrap_or_else(|_| panic!("server config")),
        )
    }

    fn blocking_tcp() -> TcpDriverConfig {
        TcpDriverConfig::default().with_nonblocking(false)
    }

    #[test]
    fn verified_tls_round_trip_preserves_flow_truth_and_pipeline() {
        let (cert, key) = certificate();
        let client_config = TlsClientConfig::from_der_roots(TlsPolicy::default(), [cert.as_ref()])
            .unwrap_or_else(|_| panic!("client config"));
        let server_config = server_config(cert, key);
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("listener"));
        let address = listener.local_addr().unwrap_or_else(|_| panic!("address"));
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap_or_else(|_| panic!("accept"));
            let connection = ServerConnection::new(server_config)
                .unwrap_or_else(|_| panic!("server connection"));
            let mut stream = StreamOwned::new(connection, socket);
            let mut request = vec![0_u8; REQUEST.len()];
            stream
                .read_exact(&mut request)
                .unwrap_or_else(|_| panic!("server read"));
            assert_eq!(request, REQUEST);
            stream
                .write_all(REQUEST)
                .unwrap_or_else(|_| panic!("server first write"));
            stream
                .write_all(REQUEST)
                .unwrap_or_else(|_| panic!("server second write"));
            stream.flush().unwrap_or_else(|_| panic!("server flush"));
        });

        let identity = TlsIdentity::dns("localhost").unwrap_or_else(|_| panic!("identity"));
        let destination =
            Destination::tls(address, identity).unwrap_or_else(|_| panic!("destination"));
        let flow = FlowId::new(31).unwrap_or_else(|_| panic!("flow"));
        let mut driver = TlsDriver::connect(&destination, flow, &client_config, blocking_tcp())
            .unwrap_or_else(|_| panic!("TLS connect"));

        let mut progress = driver
            .start_send(Arc::from(REQUEST))
            .unwrap_or_else(|_| panic!("start send"));
        while !matches!(progress, TlsWriteProgress::Complete) {
            progress = driver.flush_send().unwrap_or_else(|_| panic!("flush"));
        }

        let first = driver.receive().unwrap_or_else(|_| panic!("first"));
        let second = driver.receive().unwrap_or_else(|_| panic!("second"));
        assert!(matches!(first.message(), InboundMessage::Request(_)));
        assert!(matches!(second.message(), InboundMessage::Request(_)));
        assert_eq!(first.ingress().protocol(), Protocol::Tls);
        assert_eq!(first.ingress().flow_id(), Some(flow));
        assert!(first.ingress().tls_peer().is_some());
        assert!(matches!(
            driver.negotiated_version(),
            TlsVersion::Tls12 | TlsVersion::Tls13
        ));
        assert!(!format!("{driver:?}").contains("localhost"));
        server.join().unwrap_or_else(|_| panic!("server"));
    }

    #[test]
    fn wrong_identity_is_rejected_by_real_verification() {
        let (cert, key) = certificate();
        let client_config = TlsClientConfig::from_der_roots(TlsPolicy::default(), [cert.as_ref()])
            .unwrap_or_else(|_| panic!("client config"));
        let server_config = server_config(cert, key);
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("listener"));
        let address = listener.local_addr().unwrap_or_else(|_| panic!("address"));
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap_or_else(|_| panic!("accept"));
            let mut connection =
                ServerConnection::new(server_config).unwrap_or_else(|_| panic!("connection"));
            let _ = connection.complete_io(&mut socket);
        });
        let identity = TlsIdentity::dns("wrong.example").unwrap_or_else(|_| panic!("identity"));
        let destination =
            Destination::tls(address, identity).unwrap_or_else(|_| panic!("destination"));
        let flow = FlowId::new(32).unwrap_or_else(|_| panic!("flow"));
        assert!(matches!(
            TlsDriver::connect(&destination, flow, &client_config, blocking_tcp()),
            Err(TlsDriverError::TlsProtocol(_))
        ));
        server.join().unwrap_or_else(|_| panic!("server"));
    }

    #[test]
    fn graceful_shutdown_commits_close_notify() {
        let (cert, key) = certificate();
        let client_config = TlsClientConfig::from_der_roots(TlsPolicy::default(), [cert.as_ref()])
            .unwrap_or_else(|_| panic!("client config"));
        let server_config = server_config(cert, key);
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("listener"));
        let address = listener.local_addr().unwrap_or_else(|_| panic!("address"));
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap_or_else(|_| panic!("accept"));
            let mut connection =
                ServerConnection::new(server_config).unwrap_or_else(|_| panic!("connection"));
            while connection.is_handshaking() {
                connection
                    .complete_io(&mut socket)
                    .unwrap_or_else(|_| panic!("handshake"));
            }
            let mut byte = [0_u8; 1];
            loop {
                let read = connection.read_tls(&mut socket).unwrap_or(0);
                if read == 0 {
                    break;
                }
                let _ = connection.process_new_packets();
                if connection.reader().read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
            }
        });
        let identity = TlsIdentity::dns("localhost").unwrap_or_else(|_| panic!("identity"));
        let destination =
            Destination::tls(address, identity).unwrap_or_else(|_| panic!("destination"));
        let flow = FlowId::new(33).unwrap_or_else(|_| panic!("flow"));
        let mut driver = TlsDriver::connect(&destination, flow, &client_config, blocking_tcp())
            .unwrap_or_else(|_| panic!("connect"));
        assert!(matches!(
            driver.shutdown(),
            Ok(TlsShutdownProgress::Complete)
        ));
        server.join().unwrap_or_else(|_| panic!("server"));
    }

    #[test]
    fn tcp_eof_without_close_notify_is_not_clean_tls_shutdown() {
        let (cert, key) = certificate();
        let client_config = TlsClientConfig::from_der_roots(TlsPolicy::default(), [cert.as_ref()])
            .unwrap_or_else(|_| panic!("client config"));
        let server_config = server_config(cert, key);
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("listener"));
        let address = listener.local_addr().unwrap_or_else(|_| panic!("address"));
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap_or_else(|_| panic!("accept"));
            let mut connection =
                ServerConnection::new(server_config).unwrap_or_else(|_| panic!("connection"));
            while connection.is_handshaking() {
                connection
                    .complete_io(&mut socket)
                    .unwrap_or_else(|_| panic!("handshake"));
            }
        });
        let identity = TlsIdentity::dns("localhost").unwrap_or_else(|_| panic!("identity"));
        let destination =
            Destination::tls(address, identity).unwrap_or_else(|_| panic!("destination"));
        let flow = FlowId::new(35).unwrap_or_else(|_| panic!("flow"));
        let mut driver = TlsDriver::connect(&destination, flow, &client_config, blocking_tcp())
            .unwrap_or_else(|_| panic!("connect"));
        server.join().unwrap_or_else(|_| panic!("server"));
        assert!(matches!(
            driver.receive(),
            Err(TlsDriverError::UncleanPeerClose)
        ));
    }

    #[test]
    fn configuration_and_protocol_boundaries_are_strict() {
        assert!(matches!(
            TlsClientConfig::from_der_roots(TlsPolicy::default(), std::iter::empty::<&[u8]>()),
            Err(TlsDriverError::EmptyTrustStore)
        ));
        assert!(matches!(
            TlsClientConfig::from_der_roots(TlsPolicy::default(), [b"not a cert".as_slice()]),
            Err(TlsDriverError::InvalidTrustRoot(_))
        ));

        let (cert, _) = certificate();
        let client_config = TlsClientConfig::from_der_roots(TlsPolicy::default(), [cert.as_ref()])
            .unwrap_or_else(|_| panic!("config"));
        let destination = Destination::tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 5060)))
            .unwrap_or_else(|_| panic!("destination"));
        let flow = FlowId::new(34).unwrap_or_else(|_| panic!("flow"));
        assert!(matches!(
            TlsDriver::connect(&destination, flow, &client_config, blocking_tcp()),
            Err(TlsDriverError::WrongProtocol {
                actual: Protocol::Tcp
            })
        ));
    }
}
