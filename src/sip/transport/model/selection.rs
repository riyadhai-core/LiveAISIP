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

//! Encoded-size-aware SIP transport selection.

use std::error::Error as StdError;
use std::fmt;

use super::destination::{Destination, Protocol};

/// Conservative UDP threshold when path MTU is unknown.
pub const UNKNOWN_PATH_MTU_UDP_LIMIT: usize = 1_300;
/// Allowance below a known path MTU.
pub const PATH_MTU_SAFETY_MARGIN: usize = 200;
/// Maximum resolver candidates examined per request.
pub const MAX_TRANSPORT_CANDIDATES: usize = 32;

/// Chosen destination and size-policy result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportSelection {
    destination: Destination,
    udp_limit: usize,
    reliable_required: bool,
}

impl TransportSelection {
    /// Returns selected resolved target.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }
    /// Returns effective maximum encoded UDP size.
    #[must_use]
    pub const fn udp_limit(&self) -> usize {
        self.udp_limit
    }
    /// Returns whether size prohibited UDP.
    #[must_use]
    pub const fn reliable_required(&self) -> bool {
        self.reliable_required
    }
}

/// Stateless request transport selector.
pub struct MessageTransportSelector;

impl MessageTransportSelector {
    /// Chooses first compatible resolved candidate after serialization.
    ///
    /// # Errors
    ///
    /// Rejects empty messages, unsafe candidate counts, absent secure targets,
    /// or missing reliable fallback for an oversized request.
    pub fn select(
        encoded_bytes: usize,
        candidates: &[Destination],
        path_mtu: Option<usize>,
        require_secure: bool,
    ) -> Result<TransportSelection, SelectionError> {
        if encoded_bytes == 0 {
            return Err(SelectionError::EmptyMessage);
        }
        if candidates.is_empty() || candidates.len() > MAX_TRANSPORT_CANDIDATES {
            return Err(SelectionError::InvalidCandidateCount);
        }
        let udp_limit = path_mtu.map_or(UNKNOWN_PATH_MTU_UDP_LIMIT, |mtu| {
            mtu.saturating_sub(PATH_MTU_SAFETY_MARGIN)
        });
        let reliable_required = encoded_bytes > udp_limit;
        candidates
            .iter()
            .find(|candidate| {
                (!require_secure || candidate.protocol() == Protocol::Tls)
                    && (!reliable_required || candidate.protocol().is_reliable())
            })
            .cloned()
            .map(|destination| TransportSelection {
                destination,
                udp_limit,
                reliable_required,
            })
            .ok_or(if require_secure {
                SelectionError::NoSecureTarget
            } else if reliable_required {
                SelectionError::NoReliableFallback
            } else {
                SelectionError::NoUsableTarget
            })
    }
}

/// Transport selection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionError {
    /// Serialized message was empty.
    EmptyMessage,
    /// Candidate list was empty or excessive.
    InvalidCandidateCount,
    /// No candidate met general policy.
    NoUsableTarget,
    /// Large request lacked TCP/TLS candidate.
    NoReliableFallback,
    /// Secure policy lacked TLS candidate.
    NoSecureTarget,
}

impl fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP transport selection failed")
    }
}
impl StdError for SelectionError {}

#[cfg(test)]
mod tests {
    use super::{MessageTransportSelector, SelectionError};
    use crate::sip::transport::destination::{Destination, Protocol, TlsIdentity};
    use std::net::SocketAddr;

    fn targets() -> Vec<Destination> {
        let remote = SocketAddr::from(([192, 0, 2, 1], 5060));
        vec![
            Destination::udp(remote).unwrap_or_else(|_| panic!("udp")),
            Destination::tcp(remote).unwrap_or_else(|_| panic!("tcp")),
            Destination::tls(
                SocketAddr::from(([192, 0, 2, 1], 5061)),
                TlsIdentity::dns("sip.example").unwrap_or_else(|_| panic!("identity")),
            )
            .unwrap_or_else(|_| panic!("tls")),
        ]
    }

    #[test]
    fn size_drives_udp_to_tcp_fallback() {
        let small = MessageTransportSelector::select(1_000, &targets(), None, false)
            .unwrap_or_else(|_| panic!("selection"));
        assert_eq!(small.destination().protocol(), Protocol::Udp);
        let large = MessageTransportSelector::select(1_301, &targets(), None, false)
            .unwrap_or_else(|_| panic!("selection"));
        assert_eq!(large.destination().protocol(), Protocol::Tcp);
    }

    #[test]
    fn secure_policy_never_downgrades() {
        let selection = MessageTransportSelector::select(500, &targets(), None, true)
            .unwrap_or_else(|_| panic!("selection"));
        assert_eq!(selection.destination().protocol(), Protocol::Tls);
        assert_eq!(
            MessageTransportSelector::select(2_000, &targets()[..1], None, false),
            Err(SelectionError::NoReliableFallback)
        );
    }
}
