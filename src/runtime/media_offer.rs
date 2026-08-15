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

//! Typed bounded media offers for outbound calls.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;
use std::net::SocketAddr;

use crate::sip::framing::MAX_BODY_BYTES;
use crate::sip::sdp::Direction;

/// Default RTP packetization for the initial PCMU profile.
pub const DEFAULT_PACKET_TIME_MS: u16 = 20;
/// Operational packetization ceiling accepted by the offer builder.
pub const MAX_PACKET_TIME_MS: u16 = 1_000;
/// Standard dynamic payload type used for RFC 4733 telephone events.
pub const DEFAULT_TELEPHONE_EVENT_PAYLOAD_TYPE: u8 = 101;

/// Codec profile advertised by a generated media offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MediaCodec {
    /// G.711 mu-law, 8 kHz, mono, static RTP payload type 0.
    Pcmu,
}

/// Validated inputs from which `LiveAISIP` generates SDP.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MediaOfferConfig {
    codec: MediaCodec,
    rtp_address: SocketAddr,
    direction: Direction,
    packet_time_ms: u16,
    maximum_packet_time_ms: u16,
    telephone_event_payload_type: Option<u8>,
}

impl MediaOfferConfig {
    /// Creates the initial production PCMU offer profile.
    ///
    /// The default is bidirectional 20 ms PCMU plus telephone-event/8000 on
    /// dynamic payload type 101.
    ///
    /// # Errors
    ///
    /// Rejects an unspecified media address or port zero.
    pub fn pcmu(rtp_address: SocketAddr) -> Result<Self, MediaOfferError> {
        if rtp_address.ip().is_unspecified() || rtp_address.port() == 0 {
            return Err(MediaOfferError::InvalidRtpAddress);
        }
        Ok(Self {
            codec: MediaCodec::Pcmu,
            rtp_address,
            direction: Direction::SendRecv,
            packet_time_ms: DEFAULT_PACKET_TIME_MS,
            maximum_packet_time_ms: DEFAULT_PACKET_TIME_MS,
            telephone_event_payload_type: Some(DEFAULT_TELEPHONE_EVENT_PAYLOAD_TYPE),
        })
    }

    /// Replaces media direction.
    #[must_use]
    pub const fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// Replaces preferred and maximum RTP packetization.
    ///
    /// # Errors
    ///
    /// Rejects zero, excessive, or inverted packetization bounds.
    pub const fn with_packetization(
        mut self,
        packet_time_ms: u16,
        maximum_packet_time_ms: u16,
    ) -> Result<Self, MediaOfferError> {
        if packet_time_ms == 0
            || maximum_packet_time_ms == 0
            || packet_time_ms > maximum_packet_time_ms
            || maximum_packet_time_ms > MAX_PACKET_TIME_MS
        {
            return Err(MediaOfferError::InvalidPacketization);
        }
        self.packet_time_ms = packet_time_ms;
        self.maximum_packet_time_ms = maximum_packet_time_ms;
        Ok(self)
    }

    /// Replaces or disables RFC 4733 telephone-event advertisement.
    ///
    /// # Errors
    ///
    /// Rejects payload type 0, which is already occupied by PCMU, and values
    /// outside RTP's seven-bit payload-type space.
    pub const fn with_telephone_event(
        mut self,
        payload_type: Option<u8>,
    ) -> Result<Self, MediaOfferError> {
        if let Some(payload_type) = payload_type
            && (payload_type == 0 || payload_type > 127)
        {
            return Err(MediaOfferError::InvalidTelephoneEventPayloadType);
        }
        self.telephone_event_payload_type = payload_type;
        Ok(self)
    }

    /// Returns advertised codec profile.
    #[must_use]
    pub const fn codec(self) -> MediaCodec {
        self.codec
    }

    /// Returns advertised RTP endpoint.
    #[must_use]
    pub const fn rtp_address(self) -> SocketAddr {
        self.rtp_address
    }

    /// Returns advertised media direction.
    #[must_use]
    pub const fn direction(self) -> Direction {
        self.direction
    }

    /// Returns preferred RTP packet duration.
    #[must_use]
    pub const fn packet_time_ms(self) -> u16 {
        self.packet_time_ms
    }

    /// Returns maximum RTP packet duration.
    #[must_use]
    pub const fn maximum_packet_time_ms(self) -> u16 {
        self.maximum_packet_time_ms
    }

    /// Returns the configured telephone-event payload type.
    #[must_use]
    pub const fn telephone_event_payload_type(self) -> Option<u8> {
        self.telephone_event_payload_type
    }

    /// Returns the exact maximum encoded audio payload implied by this offer.
    ///
    /// PCMU carries one byte per 8 kHz sample, so 20 ms requires 160 bytes.
    #[must_use]
    pub fn maximum_encoded_payload_bytes(self) -> usize {
        match self.codec {
            MediaCodec::Pcmu => usize::from(self.maximum_packet_time_ms) * 8,
        }
    }

    pub(crate) fn render(self, session_id: u64) -> Result<Box<[u8]>, MediaOfferError> {
        let address_type = if self.rtp_address.is_ipv4() {
            "IP4"
        } else {
            "IP6"
        };
        let mut output = String::new();
        output
            .try_reserve(768)
            .map_err(|_| MediaOfferError::AllocationFailed)?;
        write!(
            output,
            "v=0\r\no=liveaisip {session_id} {session_id} IN {address_type} {}\r\n\
             s=LiveAISIP call\r\nc=IN {address_type} {}\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0",
            self.rtp_address.ip(),
            self.rtp_address.ip(),
            self.rtp_address.port()
        )
        .map_err(|_| MediaOfferError::FormattingFailed)?;
        if let Some(payload_type) = self.telephone_event_payload_type {
            write!(output, " {payload_type}").map_err(|_| MediaOfferError::FormattingFailed)?;
        }
        output.push_str("\r\na=rtpmap:0 PCMU/8000\r\n");
        if let Some(payload_type) = self.telephone_event_payload_type {
            write!(
                output,
                "a=rtpmap:{payload_type} telephone-event/8000\r\n\
                 a=fmtp:{payload_type} 0-16\r\n"
            )
            .map_err(|_| MediaOfferError::FormattingFailed)?;
        }
        write!(
            output,
            "a=ptime:{}\r\na=maxptime:{}\r\na={}\r\n",
            self.packet_time_ms, self.maximum_packet_time_ms, self.direction
        )
        .map_err(|_| MediaOfferError::FormattingFailed)?;
        if output.len() > MAX_BODY_BYTES {
            return Err(MediaOfferError::TooLarge);
        }
        Ok(output.into_bytes().into_boxed_slice())
    }
}

impl fmt::Debug for MediaOfferConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MediaOfferConfig")
            .field("codec", &self.codec)
            .field(
                "address_family",
                &if self.rtp_address.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                },
            )
            .field("direction", &self.direction)
            .field("packet_time_ms", &self.packet_time_ms)
            .field("maximum_packet_time_ms", &self.maximum_packet_time_ms)
            .field(
                "telephone_event_enabled",
                &self.telephone_event_payload_type.is_some(),
            )
            .finish_non_exhaustive()
    }
}

/// Generated media-offer validation or serialization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MediaOfferError {
    /// Advertised RTP address was unspecified or used port zero.
    InvalidRtpAddress,
    /// Packetization was zero, inverted, or exceeded the operational ceiling.
    InvalidPacketization,
    /// Telephone-event collided with PCMU or exceeded seven bits.
    InvalidTelephoneEventPayloadType,
    /// Exact bounded allocation failed.
    AllocationFailed,
    /// In-memory formatting unexpectedly failed.
    FormattingFailed,
    /// Generated SDP exceeded the SIP body bound.
    TooLarge,
}

impl fmt::Display for MediaOfferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid outbound media offer")
    }
}

impl StdError for MediaOfferError {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{MediaOfferConfig, MediaOfferError};
    use crate::sip::sdp::{Direction, RtpMediaOffer, parse};

    fn address(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn generates_valid_bounded_pcmu_offer_from_typed_inputs() {
        let offer = MediaOfferConfig::pcmu(address(40_000))
            .and_then(|offer| offer.with_packetization(20, 20))
            .unwrap_or_else(|_| panic!("offer"));
        assert_eq!(offer.maximum_encoded_payload_bytes(), 160);
        let bytes = offer.render(7).unwrap_or_else(|_| panic!("render"));
        let document = parse(&bytes).unwrap_or_else(|_| panic!("parse"));
        let media = RtpMediaOffer::from_section(&document.media_sections()[0], Direction::SendRecv)
            .unwrap_or_else(|_| panic!("media"));
        assert_eq!(media.packetization().packet_time_ms(), 20);
        assert_eq!(media.packetization().maximum_packet_time_ms(), Some(20));
        assert!(media.codecs()[0].name().is("PCMU"));
        assert_eq!(
            media
                .telephone_event()
                .unwrap_or_else(|| panic!("telephone event"))
                .payload_type()
                .get(),
            101
        );
    }

    #[test]
    fn rejects_unsafe_endpoints_packetization_and_payload_collisions() {
        assert!(matches!(
            MediaOfferConfig::pcmu(address(0)),
            Err(MediaOfferError::InvalidRtpAddress)
        ));
        let offer = MediaOfferConfig::pcmu(address(40_000)).unwrap_or_else(|_| panic!("offer"));
        assert!(matches!(
            offer.with_packetization(30, 20),
            Err(MediaOfferError::InvalidPacketization)
        ));
        assert!(matches!(
            offer.with_telephone_event(Some(0)),
            Err(MediaOfferError::InvalidTelephoneEventPayloadType)
        ));
    }

    #[test]
    fn debug_redacts_media_endpoint() {
        let offer = MediaOfferConfig::pcmu(address(40_000)).unwrap_or_else(|_| panic!("offer"));
        let debug = format!("{offer:?}");
        assert!(!debug.contains("127.0.0.1"));
        assert!(!debug.contains("40000"));
    }
}
