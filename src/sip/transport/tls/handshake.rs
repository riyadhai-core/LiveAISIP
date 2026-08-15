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

//! Bounded verified TLS handshake helpers.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConnection, ProtocolVersion};

use crate::sip::transport::destination::TlsIdentity;
use crate::sip::transport::tls::TlsVersion;

use super::error::TlsDriverError;

pub(super) fn server_name(identity: &TlsIdentity) -> Result<ServerName<'static>, TlsDriverError> {
    match identity {
        TlsIdentity::Dns(name) => {
            ServerName::try_from(name.to_string()).map_err(|_| TlsDriverError::InvalidServerName)
        }
        TlsIdentity::Ip(address) => Ok(ServerName::from(*address)),
    }
}

pub(super) fn drive_handshake(
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

pub(super) fn flush_tls_once(
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

pub(super) fn map_negotiated_version(
    version: Option<ProtocolVersion>,
) -> Result<TlsVersion, TlsDriverError> {
    match version {
        Some(ProtocolVersion::TLSv1_2) => Ok(TlsVersion::Tls12),
        Some(ProtocolVersion::TLSv1_3) => Ok(TlsVersion::Tls13),
        _ => Err(TlsDriverError::UnsupportedNegotiatedVersion),
    }
}

pub(super) fn total_certificate_bytes(
    certificates: &[CertificateDer<'_>],
) -> Result<usize, TlsDriverError> {
    certificates.iter().try_fold(0_usize, |total, cert| {
        total
            .checked_add(cert.as_ref().len())
            .ok_or(TlsDriverError::CertificateByteCountOverflow)
    })
}

pub(super) fn allocate_zeroed(length: usize) -> Result<Box<[u8]>, TlsDriverError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| TlsDriverError::AllocationFailed)?;
    bytes.resize(length, 0);
    Ok(bytes.into_boxed_slice())
}

pub(super) fn validate_endpoint(endpoint: SocketAddr) -> Result<(), ()> {
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() {
        Err(())
    } else {
        Ok(())
    }
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

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}
