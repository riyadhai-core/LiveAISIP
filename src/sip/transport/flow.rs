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

//! Transport-truth ingress metadata and reliable-flow response routing.

use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU64;

use super::destination::{Protocol, TlsIdentity};
use crate::sip::headers::via::{ParseError as ViaError, Via};

/// Opaque identity of one established TCP/TLS connection.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FlowId(NonZeroU64);

impl FlowId {
    /// Creates a flow identity from a nonzero runtime generation.
    ///
    /// # Errors
    ///
    /// Rejects zero, which is reserved as an invalid identity.
    pub const fn new(value: u64) -> Result<Self, FlowError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(FlowError::ZeroFlowId),
        }
    }

    /// Returns the opaque numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for FlowId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("FlowId").field(&self.get()).finish()
    }
}

/// Network facts attached to one parsed inbound SIP message.
#[derive(Clone, Eq, PartialEq)]
pub struct IngressMeta {
    source: SocketAddr,
    destination: SocketAddr,
    protocol: Protocol,
    flow_id: Option<FlowId>,
    tls_peer: Option<TlsIdentity>,
}

impl IngressMeta {
    /// Validates transport metadata at the receive boundary.
    ///
    /// Stream transports require exact flow identity. UDP must not invent one,
    /// and authenticated TLS identity cannot be attached to plaintext traffic.
    ///
    /// # Errors
    ///
    /// Rejects invalid endpoints or metadata inconsistent with the transport.
    pub fn new(
        source: SocketAddr,
        destination: SocketAddr,
        protocol: Protocol,
        flow_id: Option<FlowId>,
        tls_peer: Option<TlsIdentity>,
    ) -> Result<Self, FlowError> {
        if source.port() == 0 || source.ip().is_unspecified() {
            return Err(FlowError::InvalidSource);
        }
        if destination.port() == 0 || destination.ip().is_unspecified() {
            return Err(FlowError::InvalidDestination);
        }
        match protocol {
            Protocol::Udp if flow_id.is_some() => return Err(FlowError::UnexpectedFlowId),
            Protocol::Tcp | Protocol::Tls if flow_id.is_none() => {
                return Err(FlowError::MissingFlowId);
            }
            _ => {}
        }
        if protocol != Protocol::Tls && tls_peer.is_some() {
            return Err(FlowError::UnexpectedTlsPeer);
        }
        Ok(Self {
            source,
            destination,
            protocol,
            flow_id,
            tls_peer,
        })
    }

    /// Returns the observed peer endpoint.
    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    /// Returns the local endpoint that received the message.
    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// Returns the actual transport protocol.
    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the exact reliable flow when applicable.
    #[must_use]
    pub const fn flow_id(&self) -> Option<FlowId> {
        self.flow_id
    }

    /// Returns authenticated TLS peer identity when supplied by the handshake.
    #[must_use]
    pub const fn tls_peer(&self) -> Option<&TlsIdentity> {
        self.tls_peer.as_ref()
    }

    /// Selects the response route from transport truth.
    #[must_use]
    pub const fn response_route(&self) -> EgressRoute {
        match self.flow_id {
            Some(flow_id) => EgressRoute::ExistingFlow(flow_id),
            None => EgressRoute::Datagram(self.source),
        }
    }

    /// Restamps only the top Via from the observed source.
    ///
    /// # Errors
    ///
    /// Preserves bounded `Via` parameter mutation failures.
    pub fn response_via(&self, request_via: &Via) -> Result<Via, FlowError> {
        let mut via = request_via.clone();
        via.first_mut()
            .stamp_response_source(self.source)
            .map_err(FlowError::Via)?;
        Ok(via)
    }
}

impl fmt::Debug for IngressMeta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressMeta")
            .field("protocol", &self.protocol)
            .field(
                "source_family",
                &if self.source.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                },
            )
            .field(
                "destination_family",
                &if self.destination.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                },
            )
            .field("flow_id", &self.flow_id)
            .field("authenticated_tls_peer", &self.tls_peer.is_some())
            .finish_non_exhaustive()
    }
}

/// Exact transport route for a SIP response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressRoute {
    /// Send a UDP datagram to the observed source.
    Datagram(SocketAddr),
    /// Reuse the TCP/TLS flow that carried the request.
    ExistingFlow(FlowId),
}

/// Transport metadata validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowError {
    /// Flow generations reserve zero as invalid.
    ZeroFlowId,
    /// Peer endpoint was wildcard or port zero.
    InvalidSource,
    /// Local endpoint was wildcard or port zero.
    InvalidDestination,
    /// UDP metadata incorrectly carried stream identity.
    UnexpectedFlowId,
    /// TCP/TLS metadata omitted exact connection identity.
    MissingFlowId,
    /// Plain transport metadata carried TLS authentication state.
    UnexpectedTlsPeer,
    /// Top Via could not be restamped within its bounds.
    Via(ViaError),
}

impl fmt::Display for FlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP transport flow metadata rejected")
    }
}

impl StdError for FlowError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Via(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{EgressRoute, FlowError, FlowId, IngressMeta};
    use crate::sip::headers::via::{RPort, Via};
    use crate::sip::transport::destination::Protocol;

    #[test]
    fn reliable_response_reuses_exact_flow() {
        let flow = FlowId::new(9).unwrap_or_else(|_| panic!("flow"));
        let metadata = IngressMeta::new(
            SocketAddr::from(([192, 0, 2, 1], 5060)),
            SocketAddr::from(([192, 0, 2, 2], 5060)),
            Protocol::Tcp,
            Some(flow),
            None,
        )
        .unwrap_or_else(|_| panic!("metadata"));
        assert_eq!(metadata.response_route(), EgressRoute::ExistingFlow(flow));
    }

    #[test]
    fn udp_response_stamps_received_and_requested_rport() {
        let metadata = IngressMeta::new(
            SocketAddr::from(([198, 51, 100, 7], 33_000)),
            SocketAddr::from(([192, 0, 2, 2], 5060)),
            Protocol::Udp,
            None,
            None,
        )
        .unwrap_or_else(|_| panic!("metadata"));
        let via = Via::from_bytes(b"SIP/2.0/UDP 10.0.0.5:5060;rport;branch=z9hG4bK-one")
            .unwrap_or_else(|_| panic!("via"));
        let stamped = metadata
            .response_via(&via)
            .unwrap_or_else(|_| panic!("stamp"));
        assert_eq!(stamped.first().received(), Some(metadata.source().ip()));
        assert_eq!(stamped.first().rport(), Some(RPort::Value(33_000)));
        assert_eq!(
            metadata.response_route(),
            EgressRoute::Datagram(metadata.source())
        );
    }

    #[test]
    fn impossible_protocol_metadata_is_rejected() {
        let source = SocketAddr::from(([192, 0, 2, 1], 5060));
        let local = SocketAddr::from(([192, 0, 2, 2], 5060));
        assert_eq!(
            IngressMeta::new(source, local, Protocol::Tcp, None, None),
            Err(FlowError::MissingFlowId)
        );
        assert_eq!(
            IngressMeta::new(
                source,
                local,
                Protocol::Udp,
                Some(FlowId::new(1).unwrap_or_else(|_| panic!("flow"))),
                None,
            ),
            Err(FlowError::UnexpectedFlowId)
        );
    }
}
