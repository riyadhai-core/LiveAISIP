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

use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ProtocolVersion, RootCertStore};

use crate::sip::framing::MAX_MESSAGE_BYTES;
use crate::sip::parser::message::{self, ParseError};
use crate::sip::types::message::MessageKind;
use crate::sip::validation::{request, response};

use super::destination::{Destination, Protocol, TlsIdentity};
use super::flow::{FlowError, FlowId, IngressMeta};
use super::tcp::{ReceiveBuffer, TcpError};
use super::tcp_driver::TcpDriverConfig;
use super::tls::{Handshake, TlsError, TlsPolicy, TlsVersion};
use super::{InboundMessage, ReceivedMessage};

/// Maximum trust anchors accepted by one client configuration.
pub const MAX_TRUST_ROOTS: usize = 4_096;

/// Maximum aggregate DER bytes accepted for explicit trust anchors.
pub const MAX_TRUST_ROOT_BYTES: usize = 8 * 1024 * 1024;

/// Shared verified client configuration, intended to be built once at startup.
#[derive(Clone)]
pub struct TlsClientConfig {
    backend: Arc<ClientConfig>,
    policy: TlsPolicy,
    trust_roots: usize,
    ignored_native_roots: usize,
    native_load_errors: usize,
}

impl TlsClientConfig {
    /// Loads the operating-system trust store and builds a verified client.
    ///
    /// Invalid individual native roots are ignored as recommended by Rustls,
    /// but successful trust anchors are required. Counts remain observable
    /// without disclosing certificate subjects or filesystem details.
    ///
    /// # Errors
    ///
    /// Rejects an empty, excessive, or wholly unparseable native root set and
    /// preserves backend configuration failures.
    pub fn from_native_roots(policy: TlsPolicy) -> Result<Self, TlsDriverError> {
        let loaded = rustls_native_certs::load_native_certs();
        let native_load_errors = loaded.errors.len();
        if loaded.certs.len() > MAX_TRUST_ROOTS {
            return Err(TlsDriverError::TrustRootCountExceeded {
                attempted: loaded.certs.len(),
                maximum: MAX_TRUST_ROOTS,
            });
        }
        let total_bytes = total_certificate_bytes(&loaded.certs)?;
        if total_bytes > MAX_TRUST_ROOT_BYTES {
            return Err(TlsDriverError::TrustRootBytesExceeded {
                attempted: total_bytes,
                maximum: MAX_TRUST_ROOT_BYTES,
            });
        }

        let mut roots = RootCertStore::empty();
        let (trust_roots, ignored_native_roots) = roots.add_parsable_certificates(loaded.certs);
        if trust_roots == 0 {
            return Err(TlsDriverError::EmptyTrustStore);
        }
        Self::finish(
            policy,
            roots,
            trust_roots,
            ignored_native_roots,
            native_load_errors,
        )
    }

    /// Builds a verified client from explicit DER trust anchors.
    ///
    /// This supports private `FreeSWITCH` deployments without weakening normal
    /// certificate or destination-identity verification.
    ///
    /// # Errors
    ///
    /// Rejects empty, malformed, excessive, or allocation-failing root input
    /// and preserves backend configuration failures.
    pub fn from_der_roots<I, B>(policy: TlsPolicy, roots: I) -> Result<Self, TlsDriverError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut store = RootCertStore::empty();
        let mut count = 0_usize;
        let mut total_bytes = 0_usize;
        for root in roots {
            count = count
                .checked_add(1)
                .ok_or(TlsDriverError::TrustRootCountExceeded {
                    attempted: usize::MAX,
                    maximum: MAX_TRUST_ROOTS,
                })?;
            if count > MAX_TRUST_ROOTS {
                return Err(TlsDriverError::TrustRootCountExceeded {
                    attempted: count,
                    maximum: MAX_TRUST_ROOTS,
                });
            }
            let root = root.as_ref();
            total_bytes = total_bytes.checked_add(root.len()).ok_or(
                TlsDriverError::TrustRootBytesExceeded {
                    attempted: usize::MAX,
                    maximum: MAX_TRUST_ROOT_BYTES,
                },
            )?;
            if total_bytes > MAX_TRUST_ROOT_BYTES {
                return Err(TlsDriverError::TrustRootBytesExceeded {
                    attempted: total_bytes,
                    maximum: MAX_TRUST_ROOT_BYTES,
                });
            }
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(root.len())
                .map_err(|_| TlsDriverError::AllocationFailed)?;
            owned.extend_from_slice(root);
            store
                .add(CertificateDer::from(owned))
                .map_err(TlsDriverError::InvalidTrustRoot)?;
        }
        if count == 0 {
            return Err(TlsDriverError::EmptyTrustStore);
        }
        Self::finish(policy, store, count, 0, 0)
    }

    fn finish(
        policy: TlsPolicy,
        roots: RootCertStore,
        trust_roots: usize,
        ignored_native_roots: usize,
        native_load_errors: usize,
    ) -> Result<Self, TlsDriverError> {
        let versions = match policy.minimum_version() {
            TlsVersion::Tls12 => &[&rustls::version::TLS13, &rustls::version::TLS12][..],
            TlsVersion::Tls13 => &[&rustls::version::TLS13][..],
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let backend = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(TlsDriverError::BackendConfiguration)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            backend: Arc::new(backend),
            policy,
            trust_roots,
            ignored_native_roots,
            native_load_errors,
        })
    }

    /// Returns the TLS security policy encoded by this configuration.
    #[must_use]
    pub const fn policy(&self) -> TlsPolicy {
        self.policy
    }

    /// Returns successfully parsed trust-anchor count.
    #[must_use]
    pub const fn trust_root_count(&self) -> usize {
        self.trust_roots
    }

    /// Returns native certificates ignored as unparseable by Rustls.
    #[must_use]
    pub const fn ignored_native_root_count(&self) -> usize {
        self.ignored_native_roots
    }

    /// Returns native-store loading errors encountered beside usable roots.
    #[must_use]
    pub const fn native_load_error_count(&self) -> usize {
        self.native_load_errors
    }
}

impl fmt::Debug for TlsClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsClientConfig")
            .field("minimum_version", &self.policy.minimum_version())
            .field("trust_roots", &self.trust_roots)
            .field("ignored_native_roots", &self.ignored_native_roots)
            .field("native_load_errors", &self.native_load_errors)
            .finish_non_exhaustive()
    }
}

/// Result of one bounded TLS message-write attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsWriteProgress {
    /// All encrypted records for the message reached the kernel socket buffer.
    Complete,
    /// Plaintext or encrypted records remain retained by the driver.
    Pending {
        /// Message bytes not yet accepted by Rustls.
        remaining_plaintext_bytes: usize,
        /// Rustls still has encrypted records not accepted by the socket.
        encrypted_flush_pending: bool,
    },
}

/// Result of graceful TLS write shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsShutdownProgress {
    /// `close_notify` was committed and the TCP write half was closed.
    Complete,
    /// Encrypted shutdown records remain blocked on socket writability.
    Pending,
}

struct PendingWrite {
    message: Arc<[u8]>,
    offset: usize,
}

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

fn server_name(identity: &TlsIdentity) -> Result<ServerName<'static>, TlsDriverError> {
    match identity {
        TlsIdentity::Dns(name) => {
            ServerName::try_from(name.to_string()).map_err(|_| TlsDriverError::InvalidServerName)
        }
        TlsIdentity::Ip(address) => Ok(ServerName::from(*address)),
    }
}

fn drive_handshake(
    connection: &mut ClientConnection,
    socket: &mut TcpStream,
    timeout: Duration,
) -> Result<(), TlsDriverError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(TlsDriverError::HandshakeTimedOut)?;
    while connection.is_handshaking() || connection.wants_write() {
        let mut progressed = false;
        while connection.wants_write() {
            set_remaining_timeout(socket, deadline, false)?;
            match connection.write_tls(socket) {
                Ok(0) => return Err(TlsDriverError::HandshakeWriteZero),
                Ok(_) => progressed = true,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                Err(source) if is_timeout(&source) => {
                    return Err(TlsDriverError::HandshakeTimedOut);
                }
                Err(source) => return Err(TlsDriverError::HandshakeIo(source)),
            }
        }
        if connection.is_handshaking() && connection.wants_read() {
            set_remaining_timeout(socket, deadline, true)?;
            let read = match connection.read_tls(socket) {
                Ok(read) => read,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) if is_timeout(&source) => {
                    return Err(TlsDriverError::HandshakeTimedOut);
                }
                Err(source) => return Err(TlsDriverError::HandshakeIo(source)),
            };
            if read == 0 {
                return Err(TlsDriverError::HandshakeEof);
            }
            progressed = true;
            connection
                .process_new_packets()
                .map_err(TlsDriverError::TlsProtocol)?;
        }
        if !progressed && (connection.is_handshaking() || connection.wants_write()) {
            return Err(TlsDriverError::HandshakeStalled);
        }
    }
    Ok(())
}

fn set_remaining_timeout(
    socket: &TcpStream,
    deadline: Instant,
    read: bool,
) -> Result<(), TlsDriverError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(TlsDriverError::HandshakeTimedOut)?;
    let remaining = remaining.max(Duration::from_millis(1));
    if read {
        socket
            .set_read_timeout(Some(remaining))
            .map_err(TlsDriverError::ConfigureReadTimeout)
    } else {
        socket
            .set_write_timeout(Some(remaining))
            .map_err(TlsDriverError::ConfigureWriteTimeout)
    }
}

fn flush_tls_once(
    connection: &mut ClientConnection,
    socket: &mut TcpStream,
) -> Result<bool, TlsDriverError> {
    if !connection.wants_write() {
        return Ok(true);
    }
    match connection.write_tls(socket) {
        Ok(0) => Err(TlsDriverError::EncryptedWriteZero),
        Ok(_) => Ok(!connection.wants_write()),
        Err(source) if source.kind() == io::ErrorKind::Interrupted => Ok(false),
        Err(source) if source.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(source) => Err(TlsDriverError::Send(source)),
    }
}

fn map_negotiated_version(version: Option<ProtocolVersion>) -> Result<TlsVersion, TlsDriverError> {
    match version {
        Some(ProtocolVersion::TLSv1_2) => Ok(TlsVersion::Tls12),
        Some(ProtocolVersion::TLSv1_3) => Ok(TlsVersion::Tls13),
        _ => Err(TlsDriverError::UnsupportedNegotiatedVersion),
    }
}

fn total_certificate_bytes(certificates: &[CertificateDer<'_>]) -> Result<usize, TlsDriverError> {
    certificates.iter().try_fold(0_usize, |total, cert| {
        total
            .checked_add(cert.as_ref().len())
            .ok_or(TlsDriverError::CertificateByteCountOverflow)
    })
}

fn allocate_zeroed(length: usize) -> Result<Box<[u8]>, TlsDriverError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| TlsDriverError::AllocationFailed)?;
    bytes.resize(length, 0);
    Ok(bytes.into_boxed_slice())
}

fn validate_endpoint(endpoint: SocketAddr) -> Result<(), ()> {
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() {
        Err(())
    } else {
        Ok(())
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// TLS configuration, handshake, socket, framing, or validation failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum TlsDriverError {
    /// No usable trust anchor was supplied.
    EmptyTrustStore,
    /// Trust-anchor count exceeded its hard startup bound.
    TrustRootCountExceeded {
        /// Attempted count.
        attempted: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Aggregate trust-anchor bytes exceeded their hard startup bound.
    TrustRootBytesExceeded {
        /// Attempted bytes.
        attempted: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// An explicit DER trust anchor was malformed.
    InvalidTrustRoot(rustls::Error),
    /// Rustls provider/version configuration failed.
    BackendConfiguration(rustls::Error),
    /// Bounded allocation failed.
    AllocationFailed,
    /// Certificate-byte accounting overflowed.
    CertificateByteCountOverflow,
    /// A non-TLS destination reached the TLS boundary.
    WrongProtocol {
        /// Destination protocol.
        actual: Protocol,
    },
    /// TLS destination unexpectedly lacked an identity.
    MissingPeerIdentity,
    /// Destination identity could not become a Rustls server name.
    InvalidServerName,
    /// Outbound TCP establishment failed.
    Connect(io::Error),
    /// Local endpoint query failed.
    LocalAddress(io::Error),
    /// Peer endpoint query failed.
    PeerAddress(io::Error),
    /// Established local endpoint was unusable.
    InvalidLocalAddress,
    /// Established peer endpoint was unusable.
    InvalidPeerAddress,
    /// Preconnected stream peer differed from the resolved destination.
    PeerDestinationMismatch,
    /// Blocking handshake-mode configuration failed.
    ConfigureBlockingHandshake(io::Error),
    /// `TCP_NODELAY` configuration failed.
    ConfigureNoDelay(io::Error),
    /// Read-timeout configuration failed.
    ConfigureReadTimeout(io::Error),
    /// Write-timeout configuration failed.
    ConfigureWriteTimeout(io::Error),
    /// Post-handshake nonblocking configuration failed.
    ConfigureNonblocking(io::Error),
    /// Backend-neutral TLS policy/lifecycle failed.
    Policy(TlsError),
    /// Hard TLS handshake deadline elapsed.
    HandshakeTimedOut,
    /// Peer closed TCP before completing TLS.
    HandshakeEof,
    /// TLS handshake made no readable or writable progress.
    HandshakeStalled,
    /// Handshake encrypted writer unexpectedly accepted zero bytes.
    HandshakeWriteZero,
    /// Handshake socket I/O failed.
    HandshakeIo(io::Error),
    /// TLS protocol or certificate/identity verification failed.
    TlsProtocol(rustls::Error),
    /// Verified handshake exposed no peer certificate chain.
    MissingPeerCertificates,
    /// Backend negotiated a protocol version outside supported policy.
    UnsupportedNegotiatedVersion,
    /// Backend negotiated below the configured minimum.
    NegotiatedVersionBelowMinimum,
    /// Bounded decrypted SIP stream framing failed.
    ReceiveBuffer(TcpError),
    /// Encrypted socket receive failed, including `WouldBlock`.
    Receive(io::Error),
    /// Reading already decrypted application bytes failed.
    DecryptedRead(io::Error),
    /// TCP ended without an authenticated TLS `close_notify` alert.
    UncleanPeerClose,
    /// Peer closed after complete messages were consumed.
    PeerClosed,
    /// Peer closed with an incomplete decrypted SIP message retained.
    TruncatedStream {
        /// Incomplete retained plaintext bytes.
        buffered_bytes: usize,
    },
    /// Structural SIP parsing rejected a complete decrypted frame.
    Parse(ParseError),
    /// Request semantic validation failed.
    RequestValidation(request::ValidationError),
    /// Response semantic validation failed.
    ResponseValidation(response::ValidationError),
    /// Transport-truth metadata validation failed.
    Ingress(FlowError),
    /// A message was already partially committed.
    WriteAlreadyPending,
    /// No message was available to flush.
    NoWritePending,
    /// Graceful TLS write shutdown already began.
    WriteSideClosing,
    /// Empty serialized SIP messages are forbidden.
    EmptyMessage,
    /// Serialized SIP message exceeded the hard framing maximum.
    MessageTooLarge {
        /// Observed bytes.
        length: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Rustls plaintext writer failed.
    PlaintextWrite(io::Error),
    /// Rustls plaintext writer unexpectedly accepted zero bytes.
    PlaintextWriteZero,
    /// Encrypted socket write failed.
    Send(io::Error),
    /// Encrypted writer unexpectedly accepted zero bytes.
    EncryptedWriteZero,
    /// Graceful shutdown was requested before message commitment.
    ApplicationWritePending,
    /// TCP write-half shutdown failed.
    Shutdown(io::Error),
}

impl TlsDriverError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::EmptyTrustStore => "empty-trust-store",
            Self::TrustRootCountExceeded { .. } => "trust-root-count-exceeded",
            Self::TrustRootBytesExceeded { .. } => "trust-root-bytes-exceeded",
            Self::InvalidTrustRoot(_) => "invalid-trust-root",
            Self::BackendConfiguration(_) => "backend-configuration",
            Self::AllocationFailed => "allocation-failed",
            Self::CertificateByteCountOverflow => "certificate-byte-count-overflow",
            Self::WrongProtocol { .. } => "wrong-protocol",
            Self::MissingPeerIdentity => "missing-peer-identity",
            Self::InvalidServerName => "invalid-server-name",
            Self::Connect(_) => "connect",
            Self::LocalAddress(_) => "local-address",
            Self::PeerAddress(_) => "peer-address",
            Self::InvalidLocalAddress => "invalid-local-address",
            Self::InvalidPeerAddress => "invalid-peer-address",
            Self::PeerDestinationMismatch => "peer-destination-mismatch",
            Self::ConfigureBlockingHandshake(_) => "configure-blocking-handshake",
            Self::ConfigureNoDelay(_) => "configure-no-delay",
            Self::ConfigureReadTimeout(_) => "configure-read-timeout",
            Self::ConfigureWriteTimeout(_) => "configure-write-timeout",
            Self::ConfigureNonblocking(_) => "configure-nonblocking",
            Self::Policy(_) => "policy",
            Self::HandshakeTimedOut => "handshake-timeout",
            Self::HandshakeEof => "handshake-eof",
            Self::HandshakeStalled => "handshake-stalled",
            Self::HandshakeWriteZero => "handshake-write-zero",
            Self::HandshakeIo(_) => "handshake-io",
            Self::TlsProtocol(_) => "tls-protocol",
            Self::MissingPeerCertificates => "missing-peer-certificates",
            Self::UnsupportedNegotiatedVersion => "unsupported-negotiated-version",
            Self::NegotiatedVersionBelowMinimum => "negotiated-version-below-minimum",
            Self::ReceiveBuffer(_) => "receive-buffer",
            Self::Receive(_) => "receive",
            Self::DecryptedRead(_) => "decrypted-read",
            Self::UncleanPeerClose => "unclean-peer-close",
            Self::PeerClosed => "peer-closed",
            Self::TruncatedStream { .. } => "truncated-stream",
            Self::Parse(_) => "parse",
            Self::RequestValidation(_) => "request-validation",
            Self::ResponseValidation(_) => "response-validation",
            Self::Ingress(_) => "ingress",
            Self::WriteAlreadyPending => "write-already-pending",
            Self::NoWritePending => "no-write-pending",
            Self::WriteSideClosing => "write-side-closing",
            Self::EmptyMessage => "empty-message",
            Self::MessageTooLarge { .. } => "message-too-large",
            Self::PlaintextWrite(_) => "plaintext-write",
            Self::PlaintextWriteZero => "plaintext-write-zero",
            Self::Send(_) => "send",
            Self::EncryptedWriteZero => "encrypted-write-zero",
            Self::ApplicationWritePending => "application-write-pending",
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
            | Self::ConfigureBlockingHandshake(source)
            | Self::ConfigureNoDelay(source)
            | Self::ConfigureReadTimeout(source)
            | Self::ConfigureWriteTimeout(source)
            | Self::ConfigureNonblocking(source)
            | Self::HandshakeIo(source)
            | Self::Receive(source)
            | Self::DecryptedRead(source)
            | Self::PlaintextWrite(source)
            | Self::Send(source)
            | Self::Shutdown(source) => Some(source.kind()),
            _ => None,
        }
    }
}

impl fmt::Display for TlsDriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP TLS driver error: {}", self.class())
    }
}

impl StdError for TlsDriverError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidTrustRoot(source)
            | Self::BackendConfiguration(source)
            | Self::TlsProtocol(source) => Some(source),
            Self::Connect(source)
            | Self::LocalAddress(source)
            | Self::PeerAddress(source)
            | Self::ConfigureBlockingHandshake(source)
            | Self::ConfigureNoDelay(source)
            | Self::ConfigureReadTimeout(source)
            | Self::ConfigureWriteTimeout(source)
            | Self::ConfigureNonblocking(source)
            | Self::HandshakeIo(source)
            | Self::Receive(source)
            | Self::DecryptedRead(source)
            | Self::PlaintextWrite(source)
            | Self::Send(source)
            | Self::Shutdown(source) => Some(source),
            Self::Policy(source) => Some(source),
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
