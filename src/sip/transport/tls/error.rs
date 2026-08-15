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

//! TLS configuration, handshake, socket, framing, and validation failures.

use std::error::Error as StdError;
use std::fmt;
use std::io;

use crate::sip::parser::message::ParseError;
use crate::sip::transport::destination::Protocol;
use crate::sip::transport::flow::FlowError;
use crate::sip::transport::tcp::TcpError;
use crate::sip::transport::tls::TlsError;
use crate::sip::validation::{request, response};

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
