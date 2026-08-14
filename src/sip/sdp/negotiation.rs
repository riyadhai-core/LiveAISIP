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
    packetization: Packetization,
    telephone_event: Option<NegotiatedTelephoneEvent>,
}

/// Negotiated RFC 4733 telephone-event mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedTelephoneEvent {
    payload_type: PayloadType,
    clock_rate: u32,
    allowed_events: [u64; 4],
}

impl NegotiatedTelephoneEvent {
    /// Returns dynamically negotiated payload type.
    #[must_use]
    pub const fn payload_type(&self) -> PayloadType {
        self.payload_type
    }

    /// Returns RTP event clock rate.
    #[must_use]
    pub const fn clock_rate(&self) -> u32 {
        self.clock_rate
    }

    /// Returns whether one event code was offered by the remote endpoint.
    #[must_use]
    pub const fn allows(&self, event: u8) -> bool {
        let word = event as usize / 64;
        let bit = event as usize % 64;
        self.allowed_events[word] & (1_u64 << bit) != 0
    }
}

/// Negotiated network packetization, independent of 10 ms AI frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Packetization {
    packet_time_ms: u16,
    maximum_packet_time_ms: Option<u16>,
}

impl Packetization {
    /// Returns selected network packet duration.
    #[must_use]
    pub const fn packet_time_ms(self) -> u16 {
        self.packet_time_ms
    }

    /// Returns remote maximum packet duration when advertised.
    #[must_use]
    pub const fn maximum_packet_time_ms(self) -> Option<u16> {
        self.maximum_packet_time_ms
    }
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
        let mut packet_time_ms = None;
        let mut maximum_packet_time_ms = None;
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
            if let Some(value) = line.value().strip_prefix("ptime:") {
                if packet_time_ms.replace(parse_packet_time(value)?).is_some() {
                    return Err(NegotiationError::DuplicatePacketTime);
                }
                continue;
            }
            if let Some(value) = line.value().strip_prefix("maxptime:") {
                if maximum_packet_time_ms
                    .replace(parse_packet_time(value)?)
                    .is_some()
                {
                    return Err(NegotiationError::DuplicateMaximumPacketTime);
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

        let packet_time_ms = packet_time_ms.unwrap_or(20);
        if maximum_packet_time_ms.is_some_and(|maximum| packet_time_ms > maximum) {
            return Err(NegotiationError::PacketTimeExceedsMaximum);
        }
        let telephone_event = codecs
            .iter()
            .find(|codec| codec.name().is("telephone-event"))
            .map(|codec| {
                let mut allowed_events = standard_telephone_events();
                let mut found = false;
                for line in section.lines() {
                    if line.field() != SdpField::Attribute {
                        continue;
                    }
                    let Some(value) = line.value().strip_prefix("fmtp:") else {
                        continue;
                    };
                    let Some((payload, parameters)) = value.split_once([' ', '\t']) else {
                        continue;
                    };
                    if payload.parse::<u8>().ok() != Some(codec.payload_type().get()) {
                        continue;
                    }
                    if found {
                        return Err(NegotiationError::DuplicateTelephoneEventFormat);
                    }
                    allowed_events = parse_telephone_events(parameters.trim())?;
                    found = true;
                }
                Ok(NegotiatedTelephoneEvent {
                    payload_type: codec.payload_type(),
                    clock_rate: codec.clock_rate(),
                    allowed_events,
                })
            })
            .transpose()?;

        Ok(Self {
            media_type: media.media().clone(),
            protocol: media.protocol().clone(),
            port: media.port(),
            codecs,
            direction: media_direction.unwrap_or(inherited_direction),
            packetization: Packetization {
                packet_time_ms,
                maximum_packet_time_ms,
            },
            telephone_event,
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

    /// Returns network packetization attributes.
    #[must_use]
    pub const fn packetization(&self) -> Packetization {
        self.packetization
    }

    /// Returns the offered telephone-event mapping when present.
    #[must_use]
    pub const fn telephone_event(&self) -> Option<&NegotiatedTelephoneEvent> {
        self.telephone_event.as_ref()
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
            if local.name().is("telephone-event") {
                continue;
            }
            if let Some(offered) = self.codecs.iter().find(|offered| {
                !offered.name().is("telephone-event") && offered.is_compatible_with(local)
            }) {
                return Ok(NegotiatedMedia {
                    codec: offered.clone(),
                    direction: self.direction.answer(local_can_send, local_can_receive),
                    protocol: self.protocol.clone(),
                    remote_port: self.port,
                    packetization: self.packetization,
                    telephone_event: self
                        .telephone_event
                        .as_ref()
                        .filter(|event| event.clock_rate == offered.clock_rate())
                        .cloned(),
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
    packetization: Packetization,
    telephone_event: Option<NegotiatedTelephoneEvent>,
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

    /// Returns negotiated network packetization.
    #[must_use]
    pub const fn packetization(&self) -> Packetization {
        self.packetization
    }

    /// Returns negotiated RFC 4733 event stream when compatible with audio clock.
    #[must_use]
    pub const fn telephone_event(&self) -> Option<&NegotiatedTelephoneEvent> {
        self.telephone_event.as_ref()
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
    /// Multiple `ptime` attributes appeared.
    DuplicatePacketTime,
    /// Multiple `maxptime` attributes appeared.
    DuplicateMaximumPacketTime,
    /// Packet-time attribute was malformed or outside 1..=1000 ms.
    InvalidPacketTime,
    /// `ptime` exceeded advertised `maxptime`.
    PacketTimeExceedsMaximum,
    /// More than one `fmtp` described the negotiated telephone-event payload.
    DuplicateTelephoneEventFormat,
    /// Telephone-event `fmtp` contained malformed or empty event ranges.
    InvalidTelephoneEventFormat,
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

const fn standard_telephone_events() -> [u64; 4] {
    [0xffff, 0, 0, 0]
}

fn parse_telephone_events(input: &str) -> Result<[u64; 4], NegotiationError> {
    if input.is_empty() {
        return Err(NegotiationError::InvalidTelephoneEventFormat);
    }
    let mut allowed = [0_u64; 4];
    for item in input.split(',') {
        if item.is_empty() {
            return Err(NegotiationError::InvalidTelephoneEventFormat);
        }
        let (first, last) = match item.split_once('-') {
            Some((first, last)) => (
                first
                    .parse::<u8>()
                    .map_err(|_| NegotiationError::InvalidTelephoneEventFormat)?,
                last.parse::<u8>()
                    .map_err(|_| NegotiationError::InvalidTelephoneEventFormat)?,
            ),
            None => {
                let value = item
                    .parse::<u8>()
                    .map_err(|_| NegotiationError::InvalidTelephoneEventFormat)?;
                (value, value)
            }
        };
        if first > last {
            return Err(NegotiationError::InvalidTelephoneEventFormat);
        }
        for event in first..=last {
            let word = event as usize / 64;
            let bit = event as usize % 64;
            allowed[word] |= 1_u64 << bit;
        }
    }
    Ok(allowed)
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

fn parse_packet_time(value: &str) -> Result<u16, NegotiationError> {
    if value.is_empty() || value.len() > 4 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NegotiationError::InvalidPacketTime);
    }
    let parsed = value
        .parse::<u16>()
        .map_err(|_| NegotiationError::InvalidPacketTime)?;
    if parsed == 0 || parsed > 1_000 {
        return Err(NegotiationError::InvalidPacketTime);
    }
    Ok(parsed)
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
    fn negotiates_dynamic_telephone_event_without_selecting_it_as_audio() {
        let document = parse(
            b"v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0\r\n\
m=audio 4000 RTP/AVP 101 0\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-11,15\r\n",
        )
        .unwrap_or_else(|_| panic!("SDP"));
        let offer = RtpMediaOffer::from_section(&document.media_sections()[0], Direction::SendRecv)
            .unwrap_or_else(|_| panic!("offer"));
        let local = Codec::from_bytes(b"0 PCMU/8000").unwrap_or_else(|_| panic!("codec"));
        let negotiated = offer
            .negotiate(&[local], true, true, false)
            .unwrap_or_else(|_| panic!("negotiate"));
        assert_eq!(negotiated.codec().payload_type().get(), 0);
        let event = negotiated
            .telephone_event()
            .unwrap_or_else(|| panic!("telephone-event"));
        assert_eq!(event.payload_type().get(), 101);
        assert!(event.allows(5));
        assert!(!event.allows(12));
        assert!(event.allows(15));
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
