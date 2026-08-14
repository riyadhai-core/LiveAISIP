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

//! Validated resolved SIP transport destinations.
//!
//! A destination is the concrete result of later RFC 3263 resolution. It binds
//! a non-wildcard socket endpoint to UDP, TCP, or TLS and carries an explicit,
//! independently validated certificate identity for TLS.

use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::net::address::{Endpoint, EndpointError};

/// Maximum accepted DNS certificate identity length.
pub const MAX_TLS_DNS_NAME_BYTES: usize = 253;

/// SIP signaling transport protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Protocol {
    /// UDP datagrams.
    Udp,
    /// TCP stream.
    Tcp,
    /// TLS over TCP.
    Tls,
}

impl Protocol {
    /// Returns the canonical lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
        }
    }

    /// Returns whether delivery uses a reliable stream.
    #[must_use]
    pub const fn is_reliable(self) -> bool {
        matches!(self, Self::Tcp | Self::Tls)
    }

    /// Returns whether TLS is required.
    #[must_use]
    pub const fn is_secure(self) -> bool {
        matches!(self, Self::Tls)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Certificate identity for an outbound TLS connection.
#[derive(Clone, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum TlsIdentity {
    /// Validated lowercase ASCII DNS name.
    Dns(Box<str>),
    /// Exact IP certificate identity.
    Ip(IpAddr),
}

impl TlsIdentity {
    /// Creates a DNS identity, removing one optional trailing root dot.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-ASCII, empty-label, underscore, and
    /// leading/trailing-hyphen names.
    pub fn dns(name: &str) -> Result<Self, DestinationError> {
        let name = name.strip_suffix('.').unwrap_or(name);
        validate_dns(name)?;
        Ok(Self::Dns(name.to_ascii_lowercase().into_boxed_str()))
    }

    /// Creates an exact IP identity.
    #[must_use]
    pub const fn ip(address: IpAddr) -> Self {
        Self::Ip(address)
    }

    /// Returns the DNS identity when present.
    #[must_use]
    pub fn as_dns(&self) -> Option<&str> {
        match self {
            Self::Dns(name) => Some(name),
            Self::Ip(_) => None,
        }
    }

    /// Returns the IP identity when present.
    #[must_use]
    pub const fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(address) => Some(*address),
            Self::Dns(_) => None,
        }
    }
}

impl fmt::Debug for TlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Dns(_) => "TlsIdentity::Dns([redacted])",
            Self::Ip(_) => "TlsIdentity::Ip([redacted])",
        })
    }
}

/// Concrete validated outbound SIP destination.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Destination {
    protocol: Protocol,
    remote: Endpoint,
    tls_identity: Option<TlsIdentity>,
}

impl Destination {
    /// Creates a UDP destination.
    ///
    /// # Errors
    ///
    /// Rejects port zero and unspecified addresses.
    pub fn udp(remote: SocketAddr) -> Result<Self, DestinationError> {
        Self::plain(Protocol::Udp, remote)
    }

    /// Creates a TCP destination.
    ///
    /// # Errors
    ///
    /// Rejects port zero and unspecified addresses.
    pub fn tcp(remote: SocketAddr) -> Result<Self, DestinationError> {
        Self::plain(Protocol::Tcp, remote)
    }

    /// Creates a TLS destination with explicit certificate identity.
    ///
    /// # Errors
    ///
    /// Rejects port zero and unspecified addresses.
    pub fn tls(remote: SocketAddr, identity: TlsIdentity) -> Result<Self, DestinationError> {
        let remote = validate_remote(remote)?;
        Ok(Self {
            protocol: Protocol::Tls,
            remote,
            tls_identity: Some(identity),
        })
    }

    fn plain(protocol: Protocol, remote: SocketAddr) -> Result<Self, DestinationError> {
        let remote = validate_remote(remote)?;
        Ok(Self {
            protocol,
            remote,
            tls_identity: None,
        })
    }

    /// Returns the protocol.
    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the resolved remote endpoint.
    #[must_use]
    pub const fn remote(&self) -> SocketAddr {
        self.remote.socket_addr()
    }

    /// Returns the TLS identity when required.
    #[must_use]
    pub const fn tls_identity(&self) -> Option<&TlsIdentity> {
        self.tls_identity.as_ref()
    }
}

impl fmt::Debug for Destination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Destination")
            .field("protocol", &self.protocol)
            .field("family", &self.remote.family().as_str())
            .field("tls_identity", &self.tls_identity.is_some())
            .finish_non_exhaustive()
    }
}

fn validate_remote(remote: SocketAddr) -> Result<Endpoint, DestinationError> {
    Endpoint::new(remote).map_err(|error| match error {
        EndpointError::ZeroPort => DestinationError::ZeroPort,
        EndpointError::UnspecifiedAddress => DestinationError::UnspecifiedAddress,
    })
}

fn validate_dns(name: &str) -> Result<(), DestinationError> {
    if name.is_empty() {
        return Err(DestinationError::EmptyTlsDnsName);
    }
    if name.len() > MAX_TLS_DNS_NAME_BYTES {
        return Err(DestinationError::TlsDnsNameTooLong {
            length: name.len(),
            maximum: MAX_TLS_DNS_NAME_BYTES,
        });
    }
    for (index, label) in name.split('.').enumerate() {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(DestinationError::InvalidTlsDnsLabel { index });
        }
    }
    Ok(())
}

/// Failure to construct a SIP destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DestinationError {
    /// Remote port was zero.
    ZeroPort,
    /// Remote address was a wildcard.
    UnspecifiedAddress,
    /// TLS DNS identity was empty.
    EmptyTlsDnsName,
    /// TLS DNS identity exceeded its bound.
    TlsDnsNameTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum byte length.
        maximum: usize,
    },
    /// A DNS label was invalid.
    InvalidTlsDnsLabel {
        /// Zero-based label position.
        index: usize,
    },
}

impl DestinationError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::ZeroPort => "zero-port",
            Self::UnspecifiedAddress => "unspecified-address",
            Self::EmptyTlsDnsName => "empty-tls-dns-name",
            Self::TlsDnsNameTooLong { .. } => "tls-dns-name-too-long",
            Self::InvalidTlsDnsLabel { .. } => "invalid-tls-dns-label",
        }
    }
}

impl fmt::Display for DestinationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPort => formatter.write_str("SIP destination port is zero"),
            Self::UnspecifiedAddress => formatter.write_str("SIP destination is unspecified"),
            Self::EmptyTlsDnsName => formatter.write_str("TLS DNS identity is empty"),
            Self::TlsDnsNameTooLong { length, maximum } => {
                write!(
                    formatter,
                    "TLS DNS length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidTlsDnsLabel { index } => {
                write!(formatter, "TLS DNS label {index} is invalid")
            }
        }
    }
}

impl StdError for DestinationError {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{Destination, DestinationError, Protocol, TlsIdentity};

    #[test]
    fn constructs_all_protocols_and_normalizes_dns() {
        let remote = SocketAddr::from(([192, 0, 2, 10], 5060));
        assert_eq!(
            Destination::udp(remote).map(|d| d.protocol()),
            Ok(Protocol::Udp)
        );
        assert_eq!(
            Destination::tcp(remote).map(|d| d.protocol()),
            Ok(Protocol::Tcp)
        );
        let Ok(identity) = TlsIdentity::dns("SIP.Example.COM.") else {
            panic!("valid identity");
        };
        let Ok(tls) = Destination::tls(SocketAddr::from(([192, 0, 2, 10], 5061)), identity) else {
            panic!("valid TLS");
        };
        assert_eq!(
            tls.tls_identity().and_then(TlsIdentity::as_dns),
            Some("sip.example.com")
        );
        assert!(Protocol::Tcp.is_reliable());
        assert!(Protocol::Tls.is_secure());
    }

    #[test]
    fn rejects_zero_port_wildcards_and_invalid_dns() {
        assert!(matches!(
            Destination::udp(SocketAddr::from(([192, 0, 2, 1], 0))),
            Err(DestinationError::ZeroPort)
        ));
        assert!(matches!(
            Destination::tcp(SocketAddr::from(([0, 0, 0, 0], 5060))),
            Err(DestinationError::UnspecifiedAddress)
        ));
        for invalid in [
            "",
            ".example",
            "a..b",
            "-bad.example",
            "bad-.example",
            "bad_name",
        ] {
            assert!(TlsIdentity::dns(invalid).is_err());
        }
    }

    #[test]
    fn supports_ip_identity_and_redacts_debug() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55));
        let identity = TlsIdentity::ip(address);
        assert_eq!(identity.as_ip(), Some(address));
        let Ok(destination) = Destination::tls(SocketAddr::new(address, 5061), identity) else {
            panic!("valid destination");
        };
        let debug = format!("{destination:?}");
        assert!(!debug.contains("203.0.113.55"));
        assert!(debug.contains("ipv4"));
    }
}
