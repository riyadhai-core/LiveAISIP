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

//! Transactional construction of one negotiated RTP session generation.
//!
//! SDP negotiation and endpoint authorization happen before this layer. This
//! module verifies that their results still agree, derives bounded RTP/RTCP
//! state, and publishes a direction-gated session only after every allocation
//! and policy check succeeds. It performs no network I/O and owns no socket.

use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use super::controller::ActiveMedia;
use crate::media::pcmu::MAX_PCMU_PACKET_TIME_MS;
use crate::rtp::clock::{RtpClockError, RtpClockRate};
use crate::rtp::liveness::{MediaLiveness, MediaLivenessError};
use crate::rtp::packet::rtcp::CompoundPolicy;
use crate::rtp::security::MediaSecurityPolicy;
use crate::rtp::session::receive::{RtpReceiveConfig, RtpStateError};
use crate::rtp::session::rtcp::RtcpScheduleConfig;
use crate::rtp::session::{
    DEFAULT_INGRESS_QUEUE_PACKETS, RtpSession, RtpSessionError, TelephoneEventConfig,
};
use crate::rtp::source::SourcePolicy;
use crate::rtp::transport::symmetric::{SymmetricConfig, SymmetricEndpoints, SymmetricError};
use crate::sip::identifier::{WireTokenError, generate_wire_token};
use crate::sip::sdp::Direction;

/// Default silence before inbound media is considered timed out.
pub const DEFAULT_RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Default silence before all media activity is considered inactive.
pub const DEFAULT_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(15);

/// Immutable policy used to materialize negotiated RTP generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaSessionPolicy {
    source: SourcePolicy,
    symmetric: SymmetricConfig,
    ingress_capacity: usize,
    receive_timeout: Duration,
    inactivity_timeout: Duration,
    rtcp: RtcpScheduleConfig,
}

impl MediaSessionPolicy {
    /// Creates an explicit bounded activation policy.
    ///
    /// Queue and payload-pool bounds are authoritatively checked by
    /// [`RtpSession`] during activation.
    #[must_use]
    pub const fn new(
        source: SourcePolicy,
        symmetric: SymmetricConfig,
        ingress_capacity: usize,
        receive_timeout: Duration,
        inactivity_timeout: Duration,
        rtcp: RtcpScheduleConfig,
    ) -> Self {
        Self {
            source,
            symmetric,
            ingress_capacity,
            receive_timeout,
            inactivity_timeout,
            rtcp,
        }
    }

    /// Returns encoded packets reserved at the playout ingress boundary.
    #[must_use]
    pub const fn ingress_capacity(self) -> usize {
        self.ingress_capacity
    }

    /// Builds one generation from an already committed media controller state.
    ///
    /// `local_ssrc` must be the SSRC owned by this generation's RTP sender.
    /// The RTCP CNAME is generated as an opaque random token and never derives
    /// from a SIP identity, hostname, or tenant value.
    ///
    /// # Errors
    ///
    /// Rejects stale endpoint/SDP disagreement, unsupported media, excessive
    /// packetization, invalid control-port derivation, clock/liveness/endpoint
    /// policy failure, entropy failure, or bounded session allocation failure.
    pub fn activate(
        self,
        media: &ActiveMedia,
        local_ssrc: u32,
        now: Duration,
    ) -> Result<MediaSessionActivation, MediaSessionBuildError> {
        let direction = media.negotiated().direction();
        if direction == Direction::Inactive {
            return Ok(MediaSessionActivation {
                generation: media.generation(),
                active: None,
            });
        }
        validate_remote_endpoint(media)?;
        validate_pcmu(media)?;

        let media_destination = media.remote_rtp();
        let control_port = media_destination
            .port()
            .checked_add(1)
            .ok_or(MediaSessionBuildError::ControlPortOverflow)?;
        let control_destination = SocketAddr::new(media_destination.ip(), control_port);
        let endpoints =
            SymmetricEndpoints::new(media_destination, control_destination, self.symmetric)
                .map_err(MediaSessionBuildError::Endpoint)?;
        let clock_rate = RtpClockRate::new(media.negotiated().codec().clock_rate())
            .map_err(MediaSessionBuildError::Clock)?;
        let receive = RtpReceiveConfig::new(
            media.negotiated().codec().payload_type().get(),
            clock_rate,
            None,
        )
        .map_err(MediaSessionBuildError::Receive)?;
        let liveness = MediaLiveness::new(now, self.receive_timeout, self.inactivity_timeout)
            .map_err(MediaSessionBuildError::Liveness)?;
        let security = if media.negotiated().protocol().is_secure() {
            MediaSecurityPolicy::SecureRequired
        } else {
            MediaSecurityPolicy::PlainAllowed
        };
        let maximum_payload_bytes = pcmu_payload_limit(media)?;
        let mut session = RtpSession::new_with_payload_limit(
            receive,
            self.source,
            endpoints,
            security,
            liveness,
            self.ingress_capacity,
            maximum_payload_bytes,
        )
        .map_err(MediaSessionBuildError::Session)?;
        if let Some(event) = media.negotiated().telephone_event() {
            let config = TelephoneEventConfig::new(
                event.payload_type().get(),
                event.clock_rate(),
                negotiated_event_bits(event),
            )
            .map_err(MediaSessionBuildError::Session)?;
            session
                .configure_telephone_event(config)
                .map_err(MediaSessionBuildError::Session)?;
        }
        let cname = generate_wire_token().map_err(MediaSessionBuildError::WireToken)?;
        session
            .configure_rtcp(
                self.rtcp,
                local_ssrc,
                cname.as_bytes(),
                CompoundPolicy::Strict,
                now,
            )
            .map_err(MediaSessionBuildError::Session)?;

        Ok(MediaSessionActivation {
            generation: media.generation(),
            active: Some(ActiveRtpSession {
                generation: media.generation(),
                direction,
                remote_rtp: media_destination,
                remote_rtcp: control_destination,
                session,
            }),
        })
    }
}

impl Default for MediaSessionPolicy {
    fn default() -> Self {
        Self {
            source: SourcePolicy::default(),
            symmetric: SymmetricConfig::default(),
            ingress_capacity: DEFAULT_INGRESS_QUEUE_PACKETS,
            receive_timeout: DEFAULT_RECEIVE_TIMEOUT,
            inactivity_timeout: DEFAULT_INACTIVITY_TIMEOUT,
            rtcp: RtcpScheduleConfig::default(),
        }
    }
}

/// Result of applying one negotiated media generation.
pub struct MediaSessionActivation {
    generation: u64,
    active: Option<ActiveRtpSession>,
}

impl MediaSessionActivation {
    /// Returns the media-controller generation represented by this result.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether active RTP state was created.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active.is_some()
    }

    /// Consumes the result and returns active state when media is enabled.
    #[must_use]
    pub fn into_active(self) -> Option<ActiveRtpSession> {
        self.active
    }
}

impl fmt::Debug for MediaSessionActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MediaSessionActivation")
            .field("generation", &self.generation())
            .field("active", &self.is_active())
            .finish()
    }
}

/// One direction-gated, generation-fenced RTP session.
pub struct ActiveRtpSession {
    generation: u64,
    direction: Direction,
    remote_rtp: SocketAddr,
    remote_rtcp: SocketAddr,
    session: RtpSession,
}

impl ActiveRtpSession {
    /// Wraps an already constructed bidirectional session for compatibility
    /// with low-level callers that prepared transport state directly.
    pub(crate) fn from_prebuilt(session: RtpSession) -> Result<Self, MediaSessionBuildError> {
        let media_destination = session.remote_rtp_destination();
        let control_destination = SocketAddr::new(
            media_destination.ip(),
            media_destination
                .port()
                .checked_add(1)
                .ok_or(MediaSessionBuildError::ControlPortOverflow)?,
        );
        Ok(Self {
            generation: 0,
            direction: Direction::SendRecv,
            remote_rtp: media_destination,
            remote_rtcp: control_destination,
            session,
        })
    }

    /// Returns the media generation that exclusively owns this state.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns negotiated local media direction.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Returns whether outbound RTP effects are allowed.
    #[must_use]
    pub const fn can_send(&self) -> bool {
        self.direction.sends()
    }

    /// Returns whether inbound RTP may enter playout.
    #[must_use]
    pub const fn can_receive(&self) -> bool {
        self.direction.receives()
    }

    /// Returns the signaling-authorized RTP endpoint.
    #[must_use]
    pub const fn remote_rtp_addr(&self) -> SocketAddr {
        self.remote_rtp
    }

    /// Returns the derived baseline RTCP endpoint.
    #[must_use]
    pub const fn remote_rtcp_addr(&self) -> SocketAddr {
        self.remote_rtcp
    }

    /// Borrows the RTP session only when inbound media is negotiated.
    #[must_use]
    pub fn receive_session(&mut self) -> Option<&mut RtpSession> {
        self.can_receive().then_some(&mut self.session)
    }

    /// Borrows the RTP session only when outbound media is negotiated.
    #[must_use]
    pub fn send_session(&mut self) -> Option<&mut RtpSession> {
        self.can_send().then_some(&mut self.session)
    }

    /// Borrows session state for direction-neutral RTCP processing.
    pub(crate) const fn session_mut(&mut self) -> &mut RtpSession {
        &mut self.session
    }
}

impl fmt::Debug for ActiveRtpSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveRtpSession")
            .field("generation", &self.generation)
            .field("direction", &self.direction)
            .field(
                "address_family",
                &if self.remote_rtp.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                },
            )
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

/// Negotiated-media to RTP-session construction failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum MediaSessionBuildError {
    /// Authorized endpoint port did not equal negotiated SDP media port.
    RemotePortMismatch,
    /// Baseline RTP+1 control port could not be represented.
    ControlPortOverflow,
    /// The current live engine supports only PCMU/8000/mono.
    UnsupportedCodec,
    /// Negotiated PCMU packetization exceeded the live operational ceiling.
    PacketizationTooLarge {
        /// Negotiated maximum packet duration.
        milliseconds: u16,
        /// Live operational maximum.
        maximum: u16,
    },
    /// PCMU payload-size arithmetic failed.
    PayloadLimitOverflow,
    /// RTP clock configuration was invalid.
    Clock(RtpClockError),
    /// RTP receive configuration was invalid.
    Receive(RtpStateError),
    /// Media liveness policy was invalid.
    Liveness(MediaLivenessError),
    /// RTP/RTCP endpoint policy rejected the destination.
    Endpoint(SymmetricError),
    /// RTP session allocation or configuration failed.
    Session(RtpSessionError),
    /// Opaque RTCP identity generation failed.
    WireToken(WireTokenError),
}

impl MediaSessionBuildError {
    /// Returns a stable low-cardinality privacy-safe error class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::RemotePortMismatch => "remote-port-mismatch",
            Self::ControlPortOverflow => "control-port-overflow",
            Self::UnsupportedCodec => "unsupported-codec",
            Self::PacketizationTooLarge { .. } => "packetization-too-large",
            Self::PayloadLimitOverflow => "payload-limit-overflow",
            Self::Clock(_) => "clock",
            Self::Receive(_) => "receive",
            Self::Liveness(_) => "liveness",
            Self::Endpoint(_) => "endpoint",
            Self::Session(_) => "session",
            Self::WireToken(_) => "wire-token",
        }
    }
}

impl fmt::Display for MediaSessionBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RTP session activation failed: {}", self.class())
    }
}

impl StdError for MediaSessionBuildError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Clock(error) => Some(error),
            Self::Receive(error) => Some(error),
            Self::Liveness(error) => Some(error),
            Self::Endpoint(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::WireToken(error) => Some(error),
            Self::RemotePortMismatch
            | Self::ControlPortOverflow
            | Self::UnsupportedCodec
            | Self::PacketizationTooLarge { .. }
            | Self::PayloadLimitOverflow => None,
        }
    }
}

fn validate_remote_endpoint(media: &ActiveMedia) -> Result<(), MediaSessionBuildError> {
    if media.remote_rtp().port() != media.negotiated().remote_port() {
        return Err(MediaSessionBuildError::RemotePortMismatch);
    }
    Ok(())
}

fn validate_pcmu(media: &ActiveMedia) -> Result<(), MediaSessionBuildError> {
    let codec = media.negotiated().codec();
    if !codec.name().is("PCMU") || codec.clock_rate() != 8_000 || codec.channels() != 1 {
        return Err(MediaSessionBuildError::UnsupportedCodec);
    }
    Ok(())
}

fn pcmu_payload_limit(media: &ActiveMedia) -> Result<usize, MediaSessionBuildError> {
    let packetization = media.negotiated().packetization();
    let maximum = packetization
        .maximum_packet_time_ms()
        .unwrap_or(packetization.packet_time_ms());
    if maximum > MAX_PCMU_PACKET_TIME_MS {
        return Err(MediaSessionBuildError::PacketizationTooLarge {
            milliseconds: maximum,
            maximum: MAX_PCMU_PACKET_TIME_MS,
        });
    }
    usize::from(maximum)
        .checked_mul(8)
        .ok_or(MediaSessionBuildError::PayloadLimitOverflow)
}

fn negotiated_event_bits(event: &crate::sip::sdp::NegotiatedTelephoneEvent) -> [u64; 4] {
    let mut bits = [0_u64; 4];
    for code in 0_u8..=u8::MAX {
        if event.allows(code) {
            let word = usize::from(code) / 64;
            let bit = usize::from(code) % 64;
            bits[word] |= 1_u64 << bit;
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::{MAX_PCMU_PACKET_TIME_MS, MediaSessionBuildError, MediaSessionPolicy};
    use crate::call::media::controller::{ActiveMedia, MediaController};
    use crate::sip::sdp::codec::{Codec, CodecName, PayloadType};
    use crate::sip::sdp::parser::parse;
    use crate::sip::sdp::{Direction, RtpMediaOffer};

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn active_media(
        codec: Codec,
        direction: Direction,
        port: u16,
        packet_time_ms: u16,
        maximum_packet_time_ms: u16,
    ) -> ActiveMedia {
        let body = format!(
            "v=0\r\no=test 1 1 IN IP4 127.0.0.1\r\ns=test\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP {} 101\r\n\
             a=rtpmap:{} {}/{}\r\n\
             a=rtpmap:101 telephone-event/8000\r\n\
             a=fmtp:101 0-16\r\n\
             a=ptime:{packet_time_ms}\r\na=maxptime:{maximum_packet_time_ms}\r\na={}\r\n",
            codec.payload_type(),
            codec.payload_type(),
            codec.name(),
            codec.clock_rate(),
            direction.reversed(),
        );
        let document = parse(body.as_bytes()).unwrap_or_else(|_| panic!("SDP"));
        let offer = RtpMediaOffer::from_section(
            document
                .media_sections()
                .first()
                .unwrap_or_else(|| panic!("media")),
            Direction::SendRecv,
        )
        .unwrap_or_else(|_| panic!("offer"));
        let negotiated = offer
            .negotiate(&[codec], true, true, false)
            .unwrap_or_else(|_| panic!("negotiated"));
        let mut controller = MediaController::new(false);
        let token = controller
            .begin_local_offer()
            .unwrap_or_else(|_| panic!("token"));
        controller
            .apply_remote_answer(token, negotiated, localhost(port))
            .unwrap_or_else(|_| panic!("answer"));
        controller
            .active()
            .cloned()
            .unwrap_or_else(|| panic!("active"))
    }

    fn pcmu(direction: Direction, port: u16, ptime: u16, maxptime: u16) -> ActiveMedia {
        let codec =
            Codec::from_static_payload(PayloadType::new(0).unwrap_or_else(|_| panic!("payload")))
                .unwrap_or_else(|| panic!("PCMU"));
        active_media(codec, direction, port, ptime, maxptime)
    }

    #[test]
    fn activates_bounded_pcmu_rtp_rtcp_and_direction_state() {
        let media = pcmu(Direction::SendRecv, 40_000, 20, 20);
        let activation = MediaSessionPolicy::default()
            .activate(&media, 0x0102_0304, Duration::ZERO)
            .unwrap_or_else(|_| panic!("activation"));
        let mut active = activation.into_active().unwrap_or_else(|| panic!("active"));
        assert_eq!(active.generation(), media.generation());
        assert!(active.can_send());
        assert!(active.can_receive());
        assert_eq!(active.remote_rtp_addr(), localhost(40_000));
        assert_eq!(active.remote_rtcp_addr(), localhost(40_001));
        let session = active
            .receive_session()
            .unwrap_or_else(|| panic!("receive"));
        assert_eq!(session.playout_payload_capacity(), 160);
        assert_eq!(
            session.playout_payload_pool_bytes(),
            (MediaSessionPolicy::default().ingress_capacity() + 1) * 160
        );
    }

    #[test]
    fn inactive_negotiation_allocates_no_rtp_session() {
        let media = pcmu(Direction::Inactive, 40_000, 20, 20);
        let activation = MediaSessionPolicy::default()
            .activate(&media, 1, Duration::ZERO)
            .unwrap_or_else(|_| panic!("activation"));
        assert_eq!(activation.generation(), 1);
        assert!(!activation.is_active());
        assert!(activation.into_active().is_none());
    }

    #[test]
    fn direction_gates_send_and_receive_borrows() {
        let media = pcmu(Direction::RecvOnly, 40_000, 20, 20);
        let mut active = MediaSessionPolicy::default()
            .activate(&media, 1, Duration::ZERO)
            .unwrap_or_else(|_| panic!("activation"))
            .into_active()
            .unwrap_or_else(|| panic!("active"));
        assert!(!active.can_send());
        assert!(active.can_receive());
        assert!(active.send_session().is_none());
        assert!(active.receive_session().is_some());
    }

    #[test]
    fn rejects_endpoint_mismatch_control_overflow_and_large_packetization() {
        let mut media = pcmu(Direction::SendRecv, 40_000, 20, 20);
        let mut controller = MediaController::new(false);
        let token = controller
            .begin_local_offer()
            .unwrap_or_else(|_| panic!("token"));
        let mismatch =
            controller.apply_remote_answer(token, media.negotiated().clone(), localhost(40_002));
        assert!(mismatch.is_ok());
        media = controller
            .active()
            .cloned()
            .unwrap_or_else(|| panic!("active"));
        assert!(matches!(
            MediaSessionPolicy::default().activate(&media, 1, Duration::ZERO),
            Err(MediaSessionBuildError::RemotePortMismatch)
        ));

        let overflow = pcmu(Direction::SendRecv, u16::MAX, 20, 20);
        assert!(matches!(
            MediaSessionPolicy::default().activate(&overflow, 1, Duration::ZERO),
            Err(MediaSessionBuildError::ControlPortOverflow)
        ));

        let excessive = pcmu(
            Direction::SendRecv,
            40_000,
            MAX_PCMU_PACKET_TIME_MS,
            MAX_PCMU_PACKET_TIME_MS + 1,
        );
        assert!(matches!(
            MediaSessionPolicy::default().activate(&excessive, 1, Duration::ZERO),
            Err(MediaSessionBuildError::PacketizationTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_non_pcmu_live_codec_and_redacts_endpoints() {
        let codec = Codec::new(
            PayloadType::new(8).unwrap_or_else(|_| panic!("payload")),
            CodecName::new("PCMA").unwrap_or_else(|_| panic!("name")),
            8_000,
            1,
        )
        .unwrap_or_else(|_| panic!("codec"));
        let media = active_media(codec, Direction::SendRecv, 40_000, 20, 20);
        assert!(matches!(
            MediaSessionPolicy::default().activate(&media, 1, Duration::ZERO),
            Err(MediaSessionBuildError::UnsupportedCodec)
        ));

        let media = pcmu(Direction::SendRecv, 40_000, 20, 20);
        let activation = MediaSessionPolicy::default()
            .activate(&media, 0x0102_0304, Duration::ZERO)
            .unwrap_or_else(|_| panic!("activation"));
        let debug = format!("{activation:?}");
        assert!(!debug.contains("127.0.0.1"));
        assert!(!debug.contains("40000"));
        assert!(!debug.contains("16909060"));
    }
}
