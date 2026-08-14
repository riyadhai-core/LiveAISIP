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

//! Bounded SIP-over-UDP datagram preparation.
//!
//! This module is the admission boundary before socket I/O. It accepts only a
//! complete nonempty SIP message, a validated UDP destination, and a payload
//! that fits the configured path-safe threshold. Oversized signaling is
//! rejected with an explicit reliable-transport recommendation instead of
//! relying on IP fragmentation.
//!
//! Socket ownership, receive loops, batching, and operating-system buffer
//! configuration belong to the later UDP driver.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use crate::sip::framing::MAX_MESSAGE_BYTES;

use super::destination::{Destination, Protocol};

/// Largest legal IPv4 UDP payload.
pub const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;

/// Conservative default avoiding common Internet-path fragmentation.
pub const DEFAULT_SAFE_UDP_PAYLOAD_BYTES: usize = 1_300;

/// UDP signaling admission configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpConfig {
    max_payload_bytes: usize,
}

impl UdpConfig {
    /// Creates and validates a UDP payload policy.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above the hard UDP payload maximum.
    pub const fn new(max_payload_bytes: usize) -> Result<Self, UdpError> {
        if max_payload_bytes == 0 || max_payload_bytes > MAX_UDP_PAYLOAD_BYTES {
            return Err(UdpError::InvalidPayloadLimit {
                value: max_payload_bytes,
                maximum: MAX_UDP_PAYLOAD_BYTES,
            });
        }
        Ok(Self { max_payload_bytes })
    }

    /// Returns the configured admission threshold.
    #[must_use]
    pub const fn max_payload_bytes(self) -> usize {
        self.max_payload_bytes
    }
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_SAFE_UDP_PAYLOAD_BYTES,
        }
    }
}

/// One immutable admitted outbound UDP datagram.
pub struct OutboundDatagram {
    destination: Destination,
    payload: Arc<[u8]>,
}

impl OutboundDatagram {
    /// Admits a complete SIP message for UDP transmission.
    ///
    /// # Errors
    ///
    /// Rejects non-UDP destinations, empty messages, SIP framing overflow, and
    /// payloads above the configured safe UDP threshold.
    pub fn new(
        destination: Destination,
        payload: Arc<[u8]>,
        config: UdpConfig,
    ) -> Result<Self, UdpError> {
        if destination.protocol() != Protocol::Udp {
            return Err(UdpError::NonUdpDestination);
        }
        if payload.is_empty() {
            return Err(UdpError::EmptyPayload);
        }
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(UdpError::SipMessageTooLarge {
                length: payload.len(),
                maximum: MAX_MESSAGE_BYTES,
            });
        }
        if payload.len() > config.max_payload_bytes {
            return Err(UdpError::ReliableTransportRequired {
                length: payload.len(),
                maximum: config.max_payload_bytes,
            });
        }
        Ok(Self {
            destination,
            payload,
        })
    }

    /// Returns the validated UDP destination.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Returns the immutable datagram payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns shared ownership of the payload without copying.
    #[must_use]
    pub fn payload_arc(&self) -> Arc<[u8]> {
        Arc::clone(&self.payload)
    }

    /// Consumes the datagram into destination and payload.
    #[must_use]
    pub fn into_parts(self) -> (Destination, Arc<[u8]>) {
        (self.destination, self.payload)
    }
}

impl fmt::Debug for OutboundDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundDatagram")
            .field("payload_bytes", &self.payload.len())
            .field(
                "address_family",
                &if self.destination.remote().is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                },
            )
            .finish_non_exhaustive()
    }
}

/// Failure to configure or admit a SIP UDP datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UdpError {
    /// Configured payload threshold was zero or excessive.
    InvalidPayloadLimit {
        /// Configured value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Destination was TCP or TLS.
    NonUdpDestination,
    /// Payload was empty.
    EmptyPayload,
    /// Payload exceeded the complete SIP message limit.
    SipMessageTooLarge {
        /// Actual payload length.
        length: usize,
        /// SIP message maximum.
        maximum: usize,
    },
    /// Payload should be retried using TCP or TLS.
    ReliableTransportRequired {
        /// Actual payload length.
        length: usize,
        /// Configured UDP threshold.
        maximum: usize,
    },
}

impl UdpError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::InvalidPayloadLimit { .. } => "invalid-payload-limit",
            Self::NonUdpDestination => "non-udp-destination",
            Self::EmptyPayload => "empty-payload",
            Self::SipMessageTooLarge { .. } => "sip-message-too-large",
            Self::ReliableTransportRequired { .. } => "reliable-transport-required",
        }
    }

    /// Returns whether the same SIP message should be attempted over TCP/TLS.
    #[must_use]
    pub const fn should_retry_reliable(self) -> bool {
        matches!(self, Self::ReliableTransportRequired { .. })
    }
}

impl fmt::Display for UdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPayloadLimit { value, maximum } => {
                write!(
                    formatter,
                    "UDP payload limit {value} is outside 1..={maximum}"
                )
            }
            Self::NonUdpDestination => formatter.write_str("destination is not UDP"),
            Self::EmptyPayload => formatter.write_str("UDP SIP payload is empty"),
            Self::SipMessageTooLarge { length, maximum } => {
                write!(formatter, "SIP payload {length} exceeds maximum {maximum}")
            }
            Self::ReliableTransportRequired { length, maximum } => write!(
                formatter,
                "SIP payload {length} exceeds UDP threshold {maximum}; use reliable transport"
            ),
        }
    }
}

impl StdError for UdpError {}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use super::{
        DEFAULT_SAFE_UDP_PAYLOAD_BYTES, MAX_UDP_PAYLOAD_BYTES, OutboundDatagram, UdpConfig,
        UdpError,
    };
    use crate::sip::transport::destination::Destination;

    fn udp() -> Destination {
        let Ok(destination) = Destination::udp(SocketAddr::from(([192, 0, 2, 10], 5060))) else {
            panic!("valid UDP")
        };
        destination
    }

    #[test]
    fn admits_at_exact_limit_without_copying() {
        let Ok(config) = UdpConfig::new(64) else {
            panic!("valid config")
        };
        let payload: Arc<[u8]> = Arc::from(vec![b'a'; 64]);
        let pointer = payload.as_ptr();
        let Ok(datagram) = OutboundDatagram::new(udp(), payload, config) else {
            panic!("admitted datagram")
        };
        assert_eq!(datagram.payload().as_ptr(), pointer);
        assert_eq!(datagram.payload().len(), 64);
    }

    #[test]
    fn requests_reliable_transport_above_threshold() {
        let Ok(config) = UdpConfig::new(64) else {
            panic!("valid config")
        };
        let Err(error) = OutboundDatagram::new(udp(), Arc::from(vec![0_u8; 65]), config) else {
            panic!("expected rejection")
        };
        assert!(error.should_retry_reliable());
        assert_eq!(error.class(), "reliable-transport-required");
    }

    #[test]
    fn rejects_invalid_configuration_and_non_udp_target() {
        assert!(UdpConfig::new(0).is_err());
        assert!(UdpConfig::new(MAX_UDP_PAYLOAD_BYTES + 1).is_err());
        assert_eq!(
            UdpConfig::default().max_payload_bytes(),
            DEFAULT_SAFE_UDP_PAYLOAD_BYTES
        );
        let Ok(tcp) = Destination::tcp(SocketAddr::from(([192, 0, 2, 10], 5060))) else {
            panic!("valid TCP")
        };
        assert!(matches!(
            OutboundDatagram::new(tcp, Arc::from(&b"message"[..]), UdpConfig::default()),
            Err(UdpError::NonUdpDestination)
        ));
    }

    #[test]
    fn debug_redacts_payload_and_endpoint() {
        let Ok(datagram) = OutboundDatagram::new(
            udp(),
            Arc::from(&b"private-call-id@example.com"[..]),
            UdpConfig::default(),
        ) else {
            panic!("valid datagram")
        };
        let debug = format!("{datagram:?}");
        assert!(!debug.contains("private-call-id"));
        assert!(!debug.contains("192.0.2.10"));
    }
}
