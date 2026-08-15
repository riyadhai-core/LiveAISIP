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

//! SIP TLS security policy and handshake lifecycle.
//!
//! Peer certificate and destination-identity verification are mandatory and
//! cannot be disabled through this API. Only TLS 1.2 and TLS 1.3 are modeled.
//! Handshake time, certificate-chain bytes, and certificate count are bounded
//! before the cryptographic backend exposes an established flow. The concrete
//! verified Rustls integration lives in [`crate::sip::transport::tls_driver`].

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use super::destination::{Destination, Protocol, TlsIdentity};

/// Maximum accepted peer certificate-chain bytes.
pub const MAX_CERTIFICATE_CHAIN_BYTES: usize = 256 * 1024;

/// Maximum accepted peer certificate count.
pub const MAX_CERTIFICATE_COUNT: usize = 16;

/// Maximum configurable TLS handshake timeout.
pub const MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Permitted TLS protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum TlsVersion {
    /// TLS version 1.2.
    Tls12,
    /// TLS version 1.3.
    Tls13,
}

/// Non-bypassable outbound TLS policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsPolicy {
    minimum_version: TlsVersion,
    handshake_timeout: Duration,
    max_chain_bytes: usize,
    max_certificates: usize,
}

impl TlsPolicy {
    /// Creates a production default requiring TLS 1.2 or newer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            minimum_version: TlsVersion::Tls12,
            handshake_timeout: Duration::from_secs(10),
            max_chain_bytes: MAX_CERTIFICATE_CHAIN_BYTES,
            max_certificates: MAX_CERTIFICATE_COUNT,
        }
    }

    /// Creates and validates an explicit policy.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive timeout and zero/excessive certificate limits.
    pub const fn with_limits(
        minimum_version: TlsVersion,
        handshake_timeout: Duration,
        max_chain_bytes: usize,
        max_certificates: usize,
    ) -> Result<Self, TlsError> {
        if handshake_timeout.is_zero()
            || handshake_timeout.as_nanos() > MAX_HANDSHAKE_TIMEOUT.as_nanos()
        {
            return Err(TlsError::InvalidHandshakeTimeout);
        }
        if max_chain_bytes == 0 || max_chain_bytes > MAX_CERTIFICATE_CHAIN_BYTES {
            return Err(TlsError::InvalidChainByteLimit);
        }
        if max_certificates == 0 || max_certificates > MAX_CERTIFICATE_COUNT {
            return Err(TlsError::InvalidCertificateLimit);
        }
        Ok(Self {
            minimum_version,
            handshake_timeout,
            max_chain_bytes,
            max_certificates,
        })
    }

    /// Returns the minimum protocol version.
    #[must_use]
    pub const fn minimum_version(self) -> TlsVersion {
        self.minimum_version
    }

    /// Returns the handshake timeout.
    #[must_use]
    pub const fn handshake_timeout(self) -> Duration {
        self.handshake_timeout
    }

    /// Returns maximum certificate-chain bytes.
    #[must_use]
    pub const fn max_chain_bytes(self) -> usize {
        self.max_chain_bytes
    }

    /// Returns maximum peer certificate count.
    #[must_use]
    pub const fn max_certificates(self) -> usize {
        self.max_certificates
    }
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS handshake lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HandshakeState {
    /// No backend handshake has started.
    Pending,
    /// Backend handshake is in progress.
    Handshaking,
    /// Protocol, chain, and identity checks all succeeded.
    Established,
    /// Handshake failed terminally.
    Failed,
}

/// Backend-neutral outbound TLS handshake state.
pub struct Handshake {
    destination: Destination,
    policy: TlsPolicy,
    state: HandshakeState,
}

impl Handshake {
    /// Creates pending state for a validated TLS destination.
    ///
    /// # Errors
    ///
    /// Rejects UDP/TCP destinations or a TLS destination lacking identity.
    pub fn new(destination: Destination, policy: TlsPolicy) -> Result<Self, TlsError> {
        if destination.protocol() != Protocol::Tls {
            return Err(TlsError::NonTlsDestination);
        }
        if destination.tls_identity().is_none() {
            return Err(TlsError::MissingPeerIdentity);
        }
        Ok(Self {
            destination,
            policy,
            state: HandshakeState::Pending,
        })
    }

    /// Starts backend handshake work.
    ///
    /// # Errors
    ///
    /// Only pending state may start.
    pub fn start(&mut self) -> Result<(), TlsError> {
        self.transition(HandshakeState::Handshaking)
    }

    /// Records verified backend success.
    ///
    /// The backend must call this only after protocol, certificate chain, and
    /// destination identity verification all succeed.
    ///
    /// # Errors
    ///
    /// Only handshaking state may become established.
    pub fn establish(&mut self) -> Result<(), TlsError> {
        self.transition(HandshakeState::Established)
    }

    /// Records terminal handshake failure.
    ///
    /// # Errors
    ///
    /// Established or already failed state cannot transition to failure.
    pub fn fail(&mut self) -> Result<(), TlsError> {
        self.transition(HandshakeState::Failed)
    }

    fn transition(&mut self, next: HandshakeState) -> Result<(), TlsError> {
        let valid = matches!(
            (self.state, next),
            (
                HandshakeState::Pending,
                HandshakeState::Handshaking | HandshakeState::Failed
            ) | (
                HandshakeState::Handshaking,
                HandshakeState::Established | HandshakeState::Failed
            )
        );
        if !valid {
            return Err(TlsError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        Ok(())
    }

    /// Validates peer-chain resource counts before backend parsing.
    ///
    /// # Errors
    ///
    /// Rejects empty or policy-exceeding chain metadata.
    pub const fn admit_peer_chain(
        &self,
        chain_bytes: usize,
        certificates: usize,
    ) -> Result<(), TlsError> {
        if chain_bytes == 0 || certificates == 0 {
            return Err(TlsError::EmptyPeerChain);
        }
        if chain_bytes > self.policy.max_chain_bytes {
            return Err(TlsError::PeerChainTooLarge);
        }
        if certificates > self.policy.max_certificates {
            return Err(TlsError::TooManyPeerCertificates);
        }
        Ok(())
    }

    /// Returns handshake state.
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    /// Returns required peer identity.
    #[must_use]
    pub const fn peer_identity(&self) -> &TlsIdentity {
        match self.destination.tls_identity() {
            Some(identity) => identity,
            None => unreachable!(),
        }
    }

    /// Returns policy.
    #[must_use]
    pub const fn policy(&self) -> TlsPolicy {
        self.policy
    }
}

impl fmt::Debug for Handshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Handshake")
            .field("state", &self.state)
            .field("minimum_version", &self.policy.minimum_version)
            .finish_non_exhaustive()
    }
}

/// TLS policy or lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TlsError {
    /// Handshake timeout was invalid.
    InvalidHandshakeTimeout,
    /// Certificate-chain byte limit was invalid.
    InvalidChainByteLimit,
    /// Certificate count limit was invalid.
    InvalidCertificateLimit,
    /// Destination did not select TLS.
    NonTlsDestination,
    /// Destination lacked a verification identity.
    MissingPeerIdentity,
    /// Lifecycle transition was invalid.
    InvalidTransition {
        /// Current state.
        from: HandshakeState,
        /// Requested state.
        to: HandshakeState,
    },
    /// Peer chain metadata was empty.
    EmptyPeerChain,
    /// Peer chain exceeded byte policy.
    PeerChainTooLarge,
    /// Peer chain exceeded count policy.
    TooManyPeerCertificates,
}

impl TlsError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::InvalidHandshakeTimeout => "invalid-handshake-timeout",
            Self::InvalidChainByteLimit => "invalid-chain-byte-limit",
            Self::InvalidCertificateLimit => "invalid-certificate-limit",
            Self::NonTlsDestination => "non-tls-destination",
            Self::MissingPeerIdentity => "missing-peer-identity",
            Self::InvalidTransition { .. } => "invalid-transition",
            Self::EmptyPeerChain => "empty-peer-chain",
            Self::PeerChainTooLarge => "peer-chain-too-large",
            Self::TooManyPeerCertificates => "too-many-peer-certificates",
        }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP TLS error: {}", self.class())
    }
}

impl StdError for TlsError {}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::{Handshake, HandshakeState, TlsError, TlsPolicy, TlsVersion};
    use crate::sip::transport::destination::{Destination, TlsIdentity};

    fn handshake() -> Handshake {
        let Ok(identity) = TlsIdentity::dns("sip.example.com") else {
            panic!("identity")
        };
        let Ok(destination) = Destination::tls(SocketAddr::from(([192, 0, 2, 10], 5061)), identity)
        else {
            panic!("destination")
        };
        let Ok(handshake) = Handshake::new(destination, TlsPolicy::default()) else {
            panic!("handshake")
        };
        handshake
    }

    #[test]
    fn verified_lifecycle_is_monotonic() {
        let mut handshake = handshake();
        assert!(handshake.start().is_ok());
        assert!(handshake.establish().is_ok());
        assert_eq!(handshake.state(), HandshakeState::Established);
        assert!(matches!(
            handshake.fail(),
            Err(TlsError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn validates_policy_and_chain_boundaries() {
        assert!(TlsPolicy::with_limits(TlsVersion::Tls13, Duration::from_secs(5), 1024, 2).is_ok());
        assert!(TlsPolicy::with_limits(TlsVersion::Tls12, Duration::ZERO, 1024, 2).is_err());
        assert!(
            TlsPolicy::with_limits(
                TlsVersion::Tls12,
                Duration::from_secs(60) + Duration::from_nanos(1),
                1024,
                2,
            )
            .is_err()
        );
        let handshake = handshake();
        assert!(handshake.admit_peer_chain(1, 1).is_ok());
        assert!(matches!(
            handshake.admit_peer_chain(0, 1),
            Err(TlsError::EmptyPeerChain)
        ));
    }

    #[test]
    fn rejects_non_tls_and_redacts_identity() {
        let Ok(destination) = Destination::tcp(SocketAddr::from(([192, 0, 2, 10], 5060))) else {
            panic!("destination")
        };
        assert!(matches!(
            Handshake::new(destination, TlsPolicy::default()),
            Err(TlsError::NonTlsDestination)
        ));
        let debug = format!("{:?}", handshake());
        assert!(!debug.contains("sip.example.com"));
        assert!(!debug.contains("192.0.2.10"));
    }
}
