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

//! Transactional local-media preparation for one outbound call.
//!
//! This layer reserves an RTP/RTCP pair, binds both sockets, allocates reusable
//! packet storage, creates randomized RTP sender state, and derives the local
//! PCMU offer as one operation. Failure drops every partially acquired
//! resource and returns the port lease to its pool.
//!
//! It deliberately does not construct an
//! [`crate::rtp::session::RtpSession`]. Remote endpoints, payload policy, and
//! security mode are authoritative only after a validated SDP answer; the call
//! signaling/media controller activates that session later.

use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::ParseIntError;

use crate::rtp::session::send::{RtpSendConfig, RtpSendError, RtpSendState};
use crate::rtp::session::wire::RtpWireSender;
use crate::rtp::transport::{
    Component, MediaPacketScratch, MediaSocketPair, PortPool, SocketConfig, SocketError,
};
use crate::runtime::media_offer::{MediaOfferConfig, MediaOfferError};
use crate::sip::identifier::{WireTokenError, generate_wire_token};
use crate::sip::sdp::Direction;

/// Immutable local-media resources and advertisement policy for one call.
#[derive(Clone)]
pub struct MediaSessionConfig {
    ports: PortPool,
    bind_ip: IpAddr,
    advertised_ip: Option<IpAddr>,
    socket: SocketConfig,
    direction: Direction,
    telephone_event_payload_type: Option<u8>,
}

impl MediaSessionConfig {
    /// Creates the initial bidirectional 20 ms PCMU media profile.
    ///
    /// A wildcard bind address is allowed only when a concrete advertised IP
    /// is supplied with [`Self::with_advertised_ip`].
    #[must_use]
    pub fn pcmu(ports: PortPool, bind_ip: IpAddr) -> Self {
        Self {
            ports,
            bind_ip,
            advertised_ip: None,
            socket: SocketConfig::default(),
            direction: Direction::SendRecv,
            telephone_event_payload_type: Some(
                crate::runtime::media_offer::DEFAULT_TELEPHONE_EVENT_PAYLOAD_TYPE,
            ),
        }
    }

    /// Uses a concrete address in generated SDP while retaining the configured
    /// local bind interface and allocated port.
    ///
    /// # Errors
    ///
    /// Rejects unspecified addresses and an address-family mismatch with a
    /// concrete bind address.
    pub fn with_advertised_ip(mut self, address: IpAddr) -> Result<Self, MediaSessionError> {
        if address.is_unspecified() {
            return Err(MediaSessionError::InvalidAdvertisedAddress);
        }
        if !self.bind_ip.is_unspecified() && address.is_ipv4() != self.bind_ip.is_ipv4() {
            return Err(MediaSessionError::AddressFamilyMismatch);
        }
        self.advertised_ip = Some(address);
        Ok(self)
    }

    /// Replaces the generated SDP direction.
    #[must_use]
    pub const fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// Replaces or disables RFC 4733 telephone-event advertisement.
    ///
    /// # Errors
    ///
    /// Preserves typed media-offer payload validation.
    pub fn with_telephone_event(
        mut self,
        payload_type: Option<u8>,
    ) -> Result<Self, MediaSessionError> {
        // Validate through the authoritative offer type without depending on
        // a real call port. The result is discarded; preparation rebuilds the
        // offer with the leased endpoint.
        let validation_address = match self.bind_ip {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 9),
        };
        MediaOfferConfig::pcmu(validation_address)
            .and_then(|offer| offer.with_telephone_event(payload_type))
            .map_err(MediaSessionError::Offer)?;
        self.telephone_event_payload_type = payload_type;
        Ok(self)
    }

    /// Replaces bounded RTP/RTCP socket policy.
    #[must_use]
    pub const fn with_socket_config(mut self, socket: SocketConfig) -> Self {
        self.socket = socket;
        self
    }

    /// Acquires and prepares all local resources atomically.
    ///
    /// # Errors
    ///
    /// Reports exhausted ports, invalid advertisement, socket/allocation
    /// failures, entropy failure, or an internally inconsistent RTP profile.
    pub fn prepare(self) -> Result<PreparedMediaSession, MediaSessionError> {
        if self.bind_ip.is_unspecified() && self.advertised_ip.is_none() {
            return Err(MediaSessionError::AdvertisedAddressRequired);
        }
        let lease = self
            .ports
            .allocate()
            .ok_or(MediaSessionError::PortRangeExhausted)?;
        let sockets = MediaSocketPair::bind(lease, self.bind_ip, self.socket)
            .map_err(MediaSessionError::Socket)?;
        let media_address = sockets
            .local_addr(Component::Rtp)
            .map_err(MediaSessionError::Socket)?;
        let control_address = sockets
            .local_addr(Component::Rtcp)
            .map_err(MediaSessionError::Socket)?;
        let advertised_ip = self.advertised_ip.unwrap_or(media_address.ip());
        if advertised_ip.is_unspecified() {
            return Err(MediaSessionError::AdvertisedAddressRequired);
        }
        if advertised_ip.is_ipv4() != media_address.is_ipv4() {
            return Err(MediaSessionError::AddressFamilyMismatch);
        }
        let advertised_media = SocketAddr::new(advertised_ip, media_address.port());
        let advertised_control = SocketAddr::new(advertised_ip, control_address.port());
        let offer = MediaOfferConfig::pcmu(advertised_media)
            .and_then(|offer| offer.with_telephone_event(self.telephone_event_payload_type))
            .map(|offer| offer.with_direction(self.direction))
            .map_err(MediaSessionError::Offer)?;
        let scratch = MediaPacketScratch::new(self.socket.maximum_datagram_bytes())
            .map_err(MediaSessionError::Socket)?;
        let sender = randomized_pcmu_sender()?;
        Ok(PreparedMediaSession {
            offer,
            sockets,
            scratch,
            sender,
            local_rtp: media_address,
            local_rtcp: control_address,
            advertised_rtp: advertised_media,
            advertised_rtcp: advertised_control,
        })
    }
}

impl fmt::Debug for MediaSessionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MediaSessionConfig")
            .field(
                "bind_family",
                &if self.bind_ip.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                },
            )
            .field("has_explicit_advertisement", &self.advertised_ip.is_some())
            .field("direction", &self.direction)
            .field(
                "telephone_event_enabled",
                &self.telephone_event_payload_type.is_some(),
            )
            .field(
                "maximum_datagram_bytes",
                &self.socket.maximum_datagram_bytes(),
            )
            .finish_non_exhaustive()
    }
}

/// Fully prepared local media, not yet activated against a remote SDP answer.
pub struct PreparedMediaSession {
    offer: MediaOfferConfig,
    sockets: MediaSocketPair,
    scratch: MediaPacketScratch,
    sender: RtpWireSender,
    local_rtp: SocketAddr,
    local_rtcp: SocketAddr,
    advertised_rtp: SocketAddr,
    advertised_rtcp: SocketAddr,
}

impl PreparedMediaSession {
    /// Returns the typed local SDP offer.
    #[must_use]
    pub const fn offer(&self) -> MediaOfferConfig {
        self.offer
    }

    /// Returns the actual bound RTP endpoint.
    #[must_use]
    pub const fn local_rtp_addr(&self) -> SocketAddr {
        self.local_rtp
    }

    /// Returns the actual bound RTCP endpoint.
    #[must_use]
    pub const fn local_rtcp_addr(&self) -> SocketAddr {
        self.local_rtcp
    }

    /// Returns the RTP endpoint serialized into SDP.
    #[must_use]
    pub const fn advertised_rtp_addr(&self) -> SocketAddr {
        self.advertised_rtp
    }

    /// Returns the corresponding advertised RTCP endpoint.
    #[must_use]
    pub const fn advertised_rtcp_addr(&self) -> SocketAddr {
        self.advertised_rtcp
    }

    pub(crate) fn into_runtime_parts(self) -> (MediaSocketPair, MediaPacketScratch, RtpWireSender) {
        (self.sockets, self.scratch, self.sender)
    }
}

impl fmt::Debug for PreparedMediaSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedMediaSession")
            .field(
                "address_family",
                &if self.local_rtp.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                },
            )
            .field(
                "uses_address_translation",
                &(self.local_rtp != self.advertised_rtp),
            )
            .finish_non_exhaustive()
    }
}

/// Transactional local-media setup failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum MediaSessionError {
    /// No RTP/RTCP pair remained in the configured worker pool.
    PortRangeExhausted,
    /// The advertised address was unspecified.
    InvalidAdvertisedAddress,
    /// A wildcard bind requires an explicit routable advertised IP.
    AdvertisedAddressRequired,
    /// Bind and advertised addresses used different IP families.
    AddressFamilyMismatch,
    /// RTP/RTCP socket or packet scratch preparation failed.
    Socket(SocketError),
    /// Typed SDP offer construction failed.
    Offer(MediaOfferError),
    /// Operating-system entropy was unavailable.
    WireToken(WireTokenError),
    /// Random hexadecimal RTP state could not be decoded.
    RandomState(ParseIntError),
    /// Initial RTP send configuration was inconsistent.
    Sender(RtpSendError),
}

impl MediaSessionError {
    /// Returns a stable low-cardinality diagnostic class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::PortRangeExhausted => "port-range-exhausted",
            Self::InvalidAdvertisedAddress => "invalid-advertised-address",
            Self::AdvertisedAddressRequired => "advertised-address-required",
            Self::AddressFamilyMismatch => "address-family-mismatch",
            Self::Socket(_) => "socket",
            Self::Offer(_) => "offer",
            Self::WireToken(_) => "wire-token",
            Self::RandomState(_) => "random-state",
            Self::Sender(_) => "sender",
        }
    }
}

impl fmt::Display for MediaSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "media-session preparation failed: {}",
            self.class()
        )
    }
}

impl StdError for MediaSessionError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Socket(error) => Some(error),
            Self::Offer(error) => Some(error),
            Self::WireToken(error) => Some(error),
            Self::RandomState(error) => Some(error),
            Self::Sender(error) => Some(error),
            Self::PortRangeExhausted
            | Self::InvalidAdvertisedAddress
            | Self::AdvertisedAddressRequired
            | Self::AddressFamilyMismatch => None,
        }
    }
}

fn randomized_pcmu_sender() -> Result<RtpWireSender, MediaSessionError> {
    let token = generate_wire_token().map_err(MediaSessionError::WireToken)?;
    let ssrc = u32::from_str_radix(&token[0..8], 16).map_err(MediaSessionError::RandomState)?;
    let sequence =
        u16::from_str_radix(&token[8..12], 16).map_err(MediaSessionError::RandomState)?;
    let timestamp =
        u32::from_str_radix(&token[12..20], 16).map_err(MediaSessionError::RandomState)?;
    let config = RtpSendConfig::pcmu_20ms(ssrc).map_err(MediaSessionError::Sender)?;
    Ok(RtpWireSender::new(RtpSendState::new(
        config, sequence, timestamp,
    )))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{MediaSessionConfig, MediaSessionError, PreparedMediaSession};
    use crate::rtp::transport::PortPool;

    fn prepare_free_pair() -> (PortPool, PreparedMediaSession) {
        for port in (42_000_u16..60_000).step_by(2) {
            let pool = PortPool::new(port, port).unwrap_or_else(|_| panic!("port pool"));
            let config = MediaSessionConfig::pcmu(pool.clone(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            if let Ok(prepared) = config.prepare() {
                return (pool, prepared);
            }
        }
        panic!("free media pair")
    }

    #[test]
    fn prepares_offer_sockets_scratch_and_random_sender_under_one_lease() {
        let (pool, prepared) = prepare_free_pair();
        assert_eq!(pool.in_use(), 1);
        assert_eq!(
            prepared.offer().rtp_address(),
            prepared.advertised_rtp_addr()
        );
        assert_eq!(
            prepared.local_rtp_addr().port() + 1,
            prepared.local_rtcp_addr().port()
        );
        assert_eq!(
            prepared.advertised_rtp_addr().port() + 1,
            prepared.advertised_rtcp_addr().port()
        );
        let debug = format!("{prepared:?}");
        assert!(!debug.contains("127.0.0.1"));
        drop(prepared);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn requires_concrete_advertisement_for_wildcard_binding() {
        let pool = PortPool::new(40_000, 40_000).unwrap_or_else(|_| panic!("pool"));
        let result =
            MediaSessionConfig::pcmu(pool.clone(), IpAddr::V4(Ipv4Addr::UNSPECIFIED)).prepare();
        assert!(matches!(
            result,
            Err(MediaSessionError::AdvertisedAddressRequired)
        ));
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn rejects_exhausted_pool_and_releases_failed_setup() {
        let (pool, prepared) = prepare_free_pair();
        let error = MediaSessionConfig::pcmu(pool.clone(), IpAddr::V4(Ipv4Addr::LOCALHOST))
            .prepare()
            .err()
            .unwrap_or_else(|| panic!("exhaustion"));
        assert!(matches!(error, MediaSessionError::PortRangeExhausted));
        drop(prepared);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn config_debug_redacts_addresses_and_port_range() {
        let pool = PortPool::new(40_000, 40_000).unwrap_or_else(|_| panic!("pool"));
        let config = MediaSessionConfig::pcmu(pool, IpAddr::V4(Ipv4Addr::LOCALHOST));
        let debug = format!("{config:?}");
        assert!(!debug.contains("127.0.0.1"));
        assert!(!debug.contains("40000"));
    }
}
