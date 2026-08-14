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

//! Deterministic SDP RTP media negotiation.
//!
//! Offered payload mappings are resolved in `m=` order, with static RTP/AVP
//! mappings filled only where standardized. Dynamic payloads require explicit
//! `rtpmap`. Selection follows local preference order while retaining the
//! remote payload number used on the wire.

use std::error::Error as StdError;
use std::fmt;

use super::codec::{Codec, CodecError, PayloadType};
use super::direction::{Direction, DirectionParseError};
use super::media::{MediaError, MediaType, TransportProtocol};
use super::parser::MediaSection;
use super::types::SdpField;

/// A validated RTP media offer extracted from one SDP media section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpMediaOffer {
    media_type: MediaType,
    protocol: TransportProtocol,
    port: u16,
    codecs: Vec<Codec>,
    direction: Direction,
}

impl RtpMediaOffer {
    /// Extracts an RTP offer from a media section.
    ///
    /// `inherited_direction` is the session-level direction, or `sendrecv`
    /// when no session attribute was present.
    ///
    /// # Errors
    ///
    /// Rejects non-RTP media, malformed or duplicate payload mappings,
    /// unmapped dynamic payloads, and conflicting media directions.
    pub fn from_section(
        section: &MediaSection,
        inherited_direction: Direction,
    ) -> Result<Self, NegotiationError> {
        let media = section.media();
        if !media.protocol().is_rtp() {
            return Err(NegotiationError::NotRtp);
        }

        let mut offered_payloads = Vec::new();
        offered_payloads
            .try_reserve_exact(media.formats().len())
            .map_err(|_| NegotiationError::AllocationFailed)?;
        for payload in media.payload_types() {
            let payload = payload.map_err(NegotiationError::Media)?;
            if offered_payloads.contains(&payload) {
                return Err(NegotiationError::DuplicatePayload(payload));
            }
            offered_payloads.push(payload);
        }

        let mut mappings = Vec::new();
        let mut media_direction = None;
        for line in section.lines() {
            if line.field() != SdpField::Attribute {
                continue;
            }
            if let Ok(direction) = Direction::from_bytes(line.value().as_bytes()) {
                if media_direction.replace(direction).is_some() {
                    return Err(NegotiationError::DuplicateDirection);
                }
                continue;
            }
            let Some(value) = line.value().strip_prefix("rtpmap:") else {
                continue;
            };
            let mapping = Codec::from_bytes(value.as_bytes()).map_err(NegotiationError::Codec)?;
            if !offered_payloads.contains(&mapping.payload_type()) {
                return Err(NegotiationError::MappingForUnofferedPayload(
                    mapping.payload_type(),
                ));
            }
            if mappings
                .iter()
                .any(|existing: &Codec| existing.payload_type() == mapping.payload_type())
            {
                return Err(NegotiationError::DuplicateMapping(mapping.payload_type()));
            }
            mappings.push(mapping);
        }

        let mut codecs = Vec::new();
        codecs
            .try_reserve_exact(offered_payloads.len())
            .map_err(|_| NegotiationError::AllocationFailed)?;
        for payload in offered_payloads {
            if let Some(mapping) = mappings
                .iter()
                .find(|mapping| mapping.payload_type() == payload)
            {
                codecs.push(mapping.clone());
            } else if let Some(mapping) = Codec::from_static_payload(payload) {
                codecs.push(mapping);
            } else {
                return Err(NegotiationError::MissingPayloadMapping(payload));
            }
        }

        Ok(Self {
            media_type: media.media().clone(),
            protocol: media.protocol().clone(),
            port: media.port(),
            codecs,
            direction: media_direction.unwrap_or(inherited_direction),
        })
    }

    /// Returns offered media type.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }

    /// Returns offered transport protocol.
    #[must_use]
    pub const fn protocol(&self) -> &TransportProtocol {
        &self.protocol
    }

    /// Returns offered RTP port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns resolved codecs in remote preference order.
    #[must_use]
    pub fn codecs(&self) -> &[Codec] {
        &self.codecs
    }

    /// Returns direction from the remote SDP owner's perspective.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Selects a codec using local preference order.
    ///
    /// The selected mapping retains the offered payload type. When
    /// `require_secure` is true, clear RTP profiles are rejected.
    ///
    /// # Errors
    ///
    /// Rejects port-zero media, insecure transport policy, an empty local
    /// capability list, or no compatible codec.
    pub fn negotiate(
        &self,
        local_preference: &[Codec],
        local_can_send: bool,
        local_can_receive: bool,
        require_secure: bool,
    ) -> Result<NegotiatedMedia, NegotiationError> {
        if self.port == 0 {
            return Err(NegotiationError::RejectedMedia);
        }
        if require_secure && !self.protocol.is_secure() {
            return Err(NegotiationError::SecureTransportRequired);
        }
        if local_preference.is_empty() {
            return Err(NegotiationError::NoLocalCodecs);
        }
        for local in local_preference {
            if let Some(offered) = self
                .codecs
                .iter()
                .find(|offered| offered.is_compatible_with(local))
            {
                return Ok(NegotiatedMedia {
                    codec: offered.clone(),
                    direction: self.direction.answer(local_can_send, local_can_receive),
                    protocol: self.protocol.clone(),
                    remote_port: self.port,
                });
            }
        }
        Err(NegotiationError::NoCompatibleCodec)
    }
}

/// Successfully negotiated RTP media parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedMedia {
    codec: Codec,
    direction: Direction,
    protocol: TransportProtocol,
    remote_port: u16,
}

impl NegotiatedMedia {
    /// Returns selected remote payload mapping.
    #[must_use]
    pub const fn codec(&self) -> &Codec {
        &self.codec
    }

    /// Returns local media direction.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Returns negotiated transport profile.
    #[must_use]
    pub const fn protocol(&self) -> &TransportProtocol {
        &self.protocol
    }

    /// Returns remote RTP port.
    #[must_use]
    pub const fn remote_port(&self) -> u16 {
        self.remote_port
    }
}

/// RTP media negotiation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NegotiationError {
    /// Media transport was not a recognized RTP profile.
    NotRtp,
    /// Media-format parsing failed.
    Media(MediaError),
    /// An `rtpmap` attribute was malformed.
    Codec(CodecError),
    /// Payload appeared more than once in `m=`.
    DuplicatePayload(PayloadType),
    /// `rtpmap` referred to a payload absent from `m=`.
    MappingForUnofferedPayload(PayloadType),
    /// Multiple mappings targeted one payload.
    DuplicateMapping(PayloadType),
    /// Payload had neither explicit nor standardized static mapping.
    MissingPayloadMapping(PayloadType),
    /// More than one media-level direction attribute appeared.
    DuplicateDirection,
    /// Media was rejected with port zero.
    RejectedMedia,
    /// Policy required a secure RTP profile.
    SecureTransportRequired,
    /// No local codecs were configured.
    NoLocalCodecs,
    /// No offered codec matched local capabilities.
    NoCompatibleCodec,
    /// Bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SDP RTP media negotiation failed")
    }
}

impl StdError for NegotiationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Media(error) => Some(error),
            Self::Codec(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DirectionParseError> for NegotiationError {
    fn from(_: DirectionParseError) -> Self {
        Self::DuplicateDirection
    }
}

#[cfg(test)]
mod tests {
    use super::{NegotiationError, RtpMediaOffer};
    use crate::sip::sdp::codec::Codec;
    use crate::sip::sdp::direction::Direction;
    use crate::sip::sdp::parser::parse;

    fn offer(media: &str, attributes: &str) -> RtpMediaOffer {
        let body =
            format!("v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0\r\nm={media}\r\n{attributes}");
        let document = parse(body.as_bytes()).unwrap_or_else(|_| panic!("SDP"));
        RtpMediaOffer::from_section(&document.media_sections()[0], Direction::SendRecv)
            .unwrap_or_else(|_| panic!("offer"))
    }

    #[test]
    fn resolves_static_and_dynamic_codecs_in_offer_order() {
        let offer = offer(
            "audio 40000 RTP/AVP 0 8 111",
            "a=rtpmap:111 opus/48000/2\r\n",
        );
        assert_eq!(offer.codecs().len(), 3);
        assert!(offer.codecs()[0].name().is("PCMU"));
        assert!(offer.codecs()[1].name().is("PCMA"));
        assert!(offer.codecs()[2].name().is("opus"));
    }

    #[test]
    fn local_preference_selects_remote_payload_and_answer_direction() {
        let offer = offer(
            "audio 40000 RTP/SAVP 0 111",
            "a=rtpmap:111 opus/48000/2\r\na=sendonly\r\n",
        );
        let opus = Codec::from_bytes(b"96 OPUS/48000/2").unwrap_or_else(|_| panic!("codec"));
        let pcmu = Codec::from_bytes(b"0 PCMU/8000").unwrap_or_else(|_| panic!("codec"));
        let negotiated = offer
            .negotiate(&[opus, pcmu], true, true, true)
            .unwrap_or_else(|_| panic!("negotiated"));
        assert_eq!(negotiated.codec().payload_type().get(), 111);
        assert_eq!(negotiated.direction(), Direction::RecvOnly);
        assert_eq!(negotiated.remote_port(), 40_000);
    }

    #[test]
    fn dynamic_payload_requires_rtpmap() {
        let body = b"v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0\r\n\
m=audio 40000 RTP/AVP 111\r\n";
        let document = parse(body).unwrap_or_else(|_| panic!("SDP"));
        assert!(matches!(
            RtpMediaOffer::from_section(&document.media_sections()[0], Direction::SendRecv),
            Err(NegotiationError::MissingPayloadMapping(_))
        ));
    }

    #[test]
    fn rejects_unoffered_mapping_and_duplicate_direction() {
        let unoffered = b"v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0\r\n\
m=audio 40000 RTP/AVP 0\r\na=rtpmap:111 opus/48000/2\r\n";
        let document = parse(unoffered).unwrap_or_else(|_| panic!("SDP"));
        assert!(matches!(
            RtpMediaOffer::from_section(&document.media_sections()[0], Direction::SendRecv),
            Err(NegotiationError::MappingForUnofferedPayload(_))
        ));

        let duplicate = b"v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0\r\n\
m=audio 40000 RTP/AVP 0\r\na=sendonly\r\na=recvonly\r\n";
        let document = parse(duplicate).unwrap_or_else(|_| panic!("SDP"));
        assert_eq!(
            RtpMediaOffer::from_section(&document.media_sections()[0], Direction::SendRecv),
            Err(NegotiationError::DuplicateDirection)
        );
    }

    #[test]
    fn secure_policy_rejects_clear_rtp() {
        let offer = offer("audio 40000 RTP/AVP 0", "");
        let pcmu = Codec::from_bytes(b"0 PCMU/8000").unwrap_or_else(|_| panic!("codec"));
        assert_eq!(
            offer.negotiate(&[pcmu], true, true, true),
            Err(NegotiationError::SecureTransportRequired)
        );
    }
}
