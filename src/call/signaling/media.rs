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

//! Fork-bound SDP answer validation for call-owned signaling.
//!
//! The network source of a SIP response is never reused as an RTP destination.
//! Active media endpoints come only from strict SDP `c=` connection data and
//! the negotiated `m=audio` port. The immutable response backing storage is
//! cloned by reference, preserving the exact SDP bytes without copying them.

use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::call::model::branch::{DialogBranchId, ForkError};
use crate::sip::headers::content_type::ContentType;
use crate::sip::sdp::codec::{Codec, CodecError, PayloadType};
use crate::sip::sdp::media::MediaType;
use crate::sip::sdp::{
    Direction, NegotiatedMedia, NegotiationError, RtpMediaOffer, SdpDocument, SdpField,
    SdpParseError, parse,
};
use crate::sip::types::message::RawMessage;
use crate::sip::types::method::Method;
use crate::sip::validation::response::ValidatedResponse;

/// Local capabilities and security policy applied to remote SDP answers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaAnswerPolicy {
    pcmu: Codec,
    local_can_send: bool,
    local_can_receive: bool,
    require_secure: bool,
}

impl MediaAnswerPolicy {
    /// Creates the initial PCMU/8000/mono policy.
    ///
    /// # Errors
    ///
    /// Reports an internally inconsistent static RTP payload registry.
    pub fn pcmu(require_secure: bool) -> Result<Self, MediaAnswerError> {
        let payload = PayloadType::new(0).map_err(MediaAnswerError::Codec)?;
        let pcmu = Codec::from_static_payload(payload)
            .ok_or(MediaAnswerError::MissingStaticPcmuMapping)?;
        Ok(Self {
            pcmu,
            local_can_send: true,
            local_can_receive: true,
            require_secure,
        })
    }

    /// Restricts local send and receive capabilities.
    #[must_use]
    pub const fn with_direction_capabilities(
        mut self,
        local_can_send: bool,
        local_can_receive: bool,
    ) -> Self {
        self.local_can_send = local_can_send;
        self.local_can_receive = local_can_receive;
        self
    }

    /// Parses and negotiates one INVITE provisional or success response.
    ///
    /// An empty response body returns `Ok(None)`. A non-empty body must be
    /// typed as `application/sdp`, belong to an INVITE response in 101..=299,
    /// and carry a branch-forming To tag.
    ///
    /// # Errors
    ///
    /// Rejects invalid response role, media type, SDP, connection ambiguity,
    /// unsupported/multiple audio sections, or incompatible negotiation.
    pub fn negotiate_response(
        &self,
        response: &ValidatedResponse,
    ) -> Result<Option<RemoteMediaAnswer>, MediaAnswerError> {
        let body = response.message().body();
        if body.is_empty() {
            return Ok(None);
        }
        let status = response.response_line().status().as_u16();
        if response.core_headers().cseq().method() != &Method::Invite
            || !(101..=299).contains(&status)
        {
            return Err(MediaAnswerError::NotInviteMediaResponse);
        }
        if !response
            .core_headers()
            .content_type()
            .is_some_and(ContentType::is_application_sdp)
        {
            return Err(MediaAnswerError::NotApplicationSdp);
        }
        let tag = response
            .core_headers()
            .to_header()
            .tag()
            .ok_or(MediaAnswerError::MissingBranchTag)?;
        let branch = DialogBranchId::new(tag).map_err(MediaAnswerError::Branch)?;
        let document = parse(body).map_err(MediaAnswerError::Sdp)?;
        let inherited_direction = session_direction(&document)?;
        let section = one_audio_section(&document)?;

        if section.media().port() == 0 {
            return Ok(Some(RemoteMediaAnswer {
                response: response.message().clone(),
                branch,
                status,
                disposition: RemoteMediaDisposition::Rejected,
                negotiated: None,
                remote_rtp: None,
            }));
        }

        let offer = RtpMediaOffer::from_section(section, inherited_direction)
            .map_err(MediaAnswerError::Negotiation)?;
        let negotiated = offer
            .negotiate(
                std::slice::from_ref(&self.pcmu),
                self.local_can_send,
                self.local_can_receive,
                self.require_secure,
            )
            .map_err(MediaAnswerError::Negotiation)?;
        let connection = effective_connection(&document, section)?;
        let held =
            connection.address.is_unspecified() || negotiated.direction() == Direction::Inactive;
        let remote_rtp =
            (!held).then(|| SocketAddr::new(connection.address, negotiated.remote_port()));
        let disposition = if held {
            RemoteMediaDisposition::Held
        } else {
            RemoteMediaDisposition::Active
        };
        Ok(Some(RemoteMediaAnswer {
            response: response.message().clone(),
            branch,
            status,
            disposition,
            negotiated: Some(negotiated),
            remote_rtp,
        }))
    }
}

/// Semantic result of a valid SDP media answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMediaDisposition {
    /// Media is negotiated with one concrete signaling-authorized endpoint.
    Active,
    /// Media is on hold or locally inactive; no RTP destination is usable.
    Held,
    /// The remote endpoint explicitly rejected audio with port zero.
    Rejected,
}

/// One exact fork's validated and negotiated SDP answer.
pub struct RemoteMediaAnswer {
    response: RawMessage,
    branch: DialogBranchId,
    status: u16,
    disposition: RemoteMediaDisposition,
    negotiated: Option<NegotiatedMedia>,
    remote_rtp: Option<SocketAddr>,
}

impl RemoteMediaAnswer {
    /// Returns the dialog fork that supplied this answer.
    #[must_use]
    pub const fn branch(&self) -> &DialogBranchId {
        &self.branch
    }

    /// Returns provisional or successful SIP status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns semantic media disposition.
    #[must_use]
    pub const fn disposition(&self) -> RemoteMediaDisposition {
        self.disposition
    }

    /// Returns negotiated parameters for active or held media.
    #[must_use]
    pub const fn negotiated(&self) -> Option<&NegotiatedMedia> {
        self.negotiated.as_ref()
    }

    /// Returns a destination only for active media.
    #[must_use]
    pub const fn remote_rtp_addr(&self) -> Option<SocketAddr> {
        self.remote_rtp
    }

    /// Returns the exact immutable SDP body retained from the SIP response.
    #[must_use]
    pub fn sdp_body(&self) -> &[u8] {
        self.response.body()
    }
}

impl fmt::Debug for RemoteMediaAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteMediaAnswer")
            .field("status", &self.status)
            .field("disposition", &self.disposition)
            .field("has_negotiated_media", &self.negotiated.is_some())
            .field("has_remote_endpoint", &self.remote_rtp.is_some())
            .field("sdp_bytes", &self.response.body().len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct ConnectionData {
    address: IpAddr,
}

/// SIP response SDP validation or negotiation failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum MediaAnswerError {
    /// A non-INVITE or non-101..=299 response carried media.
    NotInviteMediaResponse,
    /// A non-empty body was not declared as application/sdp.
    NotApplicationSdp,
    /// The media response lacked a dialog-forming To tag.
    MissingBranchTag,
    /// The To tag could not form a bounded branch identity.
    Branch(ForkError),
    /// Static PCMU policy construction failed.
    Codec(CodecError),
    /// The internal static payload registry omitted PCMU payload zero.
    MissingStaticPcmuMapping,
    /// SDP document parsing failed.
    Sdp(SdpParseError),
    /// Session-level direction occurred more than once.
    DuplicateSessionDirection,
    /// SDP did not contain an audio media section.
    MissingAudioSection,
    /// SDP contained more than one audio section and was ambiguous.
    MultipleAudioSections,
    /// Neither the audio section nor session supplied connection data.
    MissingConnection,
    /// A connection scope contained multiple `c=` fields.
    DuplicateConnection,
    /// Connection syntax, network type, address type, or literal was invalid.
    InvalidConnection,
    /// Multicast or broadcast media is outside the unicast runtime profile.
    NonUnicastUnsupported,
    /// Codec, packetization, direction, or security negotiation failed.
    Negotiation(NegotiationError),
}

impl MediaAnswerError {
    /// Returns a stable low-cardinality privacy-safe error class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::NotInviteMediaResponse => "not-invite-media-response",
            Self::NotApplicationSdp => "not-application-sdp",
            Self::MissingBranchTag => "missing-branch-tag",
            Self::Branch(_) => "branch",
            Self::Codec(_) => "codec",
            Self::MissingStaticPcmuMapping => "missing-static-pcmu",
            Self::Sdp(_) => "sdp",
            Self::DuplicateSessionDirection => "duplicate-session-direction",
            Self::MissingAudioSection => "missing-audio-section",
            Self::MultipleAudioSections => "multiple-audio-sections",
            Self::MissingConnection => "missing-connection",
            Self::DuplicateConnection => "duplicate-connection",
            Self::InvalidConnection => "invalid-connection",
            Self::NonUnicastUnsupported => "non-unicast-unsupported",
            Self::Negotiation(_) => "negotiation",
        }
    }
}

impl fmt::Display for MediaAnswerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP media answer rejected: {}", self.class())
    }
}

impl StdError for MediaAnswerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Branch(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Sdp(error) => Some(error),
            Self::Negotiation(error) => Some(error),
            Self::NotInviteMediaResponse
            | Self::NotApplicationSdp
            | Self::MissingBranchTag
            | Self::MissingStaticPcmuMapping
            | Self::DuplicateSessionDirection
            | Self::MissingAudioSection
            | Self::MultipleAudioSections
            | Self::MissingConnection
            | Self::DuplicateConnection
            | Self::InvalidConnection
            | Self::NonUnicastUnsupported => None,
        }
    }
}

fn session_direction(document: &SdpDocument) -> Result<Direction, MediaAnswerError> {
    let mut direction = None;
    for line in document.session_lines() {
        if line.field() != SdpField::Attribute {
            continue;
        }
        if let Ok(value) = Direction::from_bytes(line.value().as_bytes())
            && direction.replace(value).is_some()
        {
            return Err(MediaAnswerError::DuplicateSessionDirection);
        }
    }
    Ok(direction.unwrap_or(Direction::SendRecv))
}

fn one_audio_section(
    document: &SdpDocument,
) -> Result<&crate::sip::sdp::MediaSection, MediaAnswerError> {
    let mut audio = document
        .media_sections()
        .iter()
        .filter(|section| section.media().media() == &MediaType::Audio);
    let first = audio.next().ok_or(MediaAnswerError::MissingAudioSection)?;
    if audio.next().is_some() {
        return Err(MediaAnswerError::MultipleAudioSections);
    }
    Ok(first)
}

fn effective_connection(
    document: &SdpDocument,
    section: &crate::sip::sdp::MediaSection,
) -> Result<ConnectionData, MediaAnswerError> {
    let session = one_connection(
        document
            .session_lines()
            .iter()
            .filter(|line| line.field() == SdpField::Connection),
    )?;
    let media = one_connection(
        section
            .lines()
            .iter()
            .filter(|line| line.field() == SdpField::Connection),
    )?;
    media.or(session).ok_or(MediaAnswerError::MissingConnection)
}

fn one_connection<'a>(
    mut lines: impl Iterator<Item = &'a crate::sip::sdp::SdpLine>,
) -> Result<Option<ConnectionData>, MediaAnswerError> {
    let Some(first) = lines.next() else {
        return Ok(None);
    };
    if lines.next().is_some() {
        return Err(MediaAnswerError::DuplicateConnection);
    }
    parse_connection(first.value()).map(Some)
}

fn parse_connection(value: &str) -> Result<ConnectionData, MediaAnswerError> {
    let mut parts = value.split_ascii_whitespace();
    let network = parts.next().ok_or(MediaAnswerError::InvalidConnection)?;
    let address_type = parts.next().ok_or(MediaAnswerError::InvalidConnection)?;
    let literal = parts.next().ok_or(MediaAnswerError::InvalidConnection)?;
    if parts.next().is_some() || network != "IN" || literal.contains('/') {
        return Err(MediaAnswerError::InvalidConnection);
    }
    let address: IpAddr = literal
        .parse()
        .map_err(|_| MediaAnswerError::InvalidConnection)?;
    if (address_type == "IP4") != address.is_ipv4() || !matches!(address_type, "IP4" | "IP6") {
        return Err(MediaAnswerError::InvalidConnection);
    }
    let broadcast = matches!(address, IpAddr::V4(value) if value.octets() == [255; 4]);
    if address.is_multicast() || broadcast {
        return Err(MediaAnswerError::NonUnicastUnsupported);
    }
    Ok(ConnectionData { address })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{MediaAnswerError, MediaAnswerPolicy, RemoteMediaDisposition};
    use crate::sip::parser::message;
    use crate::sip::validation::response::{ValidatedResponse, validate};

    fn response(status: u16, content_type: &str, body: &str) -> ValidatedResponse {
        let bytes = format!(
            "SIP/2.0 {status} Answer\r\n\
             Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-test\r\n\
             From: <sip:caller@example.invalid>;tag=local\r\n\
             To: <sip:callee@example.invalid>;tag=fork-one\r\n\
             Call-ID: private-call-id\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let raw = message::parse(Arc::from(bytes.into_bytes().into_boxed_slice()))
            .unwrap_or_else(|_| panic!("parse"));
        validate(raw).unwrap_or_else(|_| panic!("validate"))
    }

    fn sdp(connection: &str, media_connection: &str, port: u16, direction: &str) -> String {
        format!(
            "v=0\r\no=fs 1 1 IN IP4 198.51.100.20\r\ns=call\r\n\
             {connection}t=0 0\r\nm=audio {port} RTP/AVP 0 101\r\n\
             {media_connection}a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\n\
             a=ptime:20\r\na=maxptime:20\r\na={direction}\r\n"
        )
    }

    #[test]
    fn negotiates_active_fork_and_retains_exact_response_body_without_copy() {
        let body = sdp("c=IN IP4 198.51.100.20\r\n", "", 40_000, "sendrecv");
        let response = response(200, "application/sdp", &body);
        let original = response.message().body().as_ptr();
        let answer = MediaAnswerPolicy::pcmu(false)
            .and_then(|policy| policy.negotiate_response(&response))
            .unwrap_or_else(|_| panic!("answer"))
            .unwrap_or_else(|| panic!("media"));
        assert_eq!(answer.disposition(), RemoteMediaDisposition::Active);
        assert_eq!(
            answer.remote_rtp_addr().map(|address| address.to_string()),
            Some("198.51.100.20:40000".to_owned())
        );
        assert_eq!(answer.sdp_body(), body.as_bytes());
        assert_eq!(answer.sdp_body().as_ptr(), original);
        assert_eq!(answer.branch().as_str(), "fork-one");
        let debug = format!("{answer:?}");
        assert!(!debug.contains("198.51.100.20"));
        assert!(!debug.contains("private-call-id"));
    }

    #[test]
    fn media_connection_overrides_session_connection() {
        let body = sdp(
            "c=IN IP4 198.51.100.20\r\n",
            "c=IN IP4 203.0.113.30\r\n",
            40_000,
            "sendrecv",
        );
        let response = response(183, "application/sdp;charset=utf-8", &body);
        let answer = MediaAnswerPolicy::pcmu(false)
            .and_then(|policy| policy.negotiate_response(&response))
            .unwrap_or_else(|_| panic!("answer"))
            .unwrap_or_else(|| panic!("media"));
        assert_eq!(
            answer.remote_rtp_addr().map(|address| address.ip()),
            "203.0.113.30".parse().ok()
        );
        assert_eq!(answer.status(), 183);
    }

    #[test]
    fn distinguishes_hold_and_explicit_media_rejection() {
        let held_body = sdp("c=IN IP4 0.0.0.0\r\n", "", 40_000, "sendrecv");
        let held = response(200, "application/sdp", &held_body);
        let held = MediaAnswerPolicy::pcmu(false)
            .and_then(|policy| policy.negotiate_response(&held))
            .unwrap_or_else(|_| panic!("held"))
            .unwrap_or_else(|| panic!("media"));
        assert_eq!(held.disposition(), RemoteMediaDisposition::Held);
        assert!(held.negotiated().is_some());
        assert_eq!(held.remote_rtp_addr(), None);

        let rejected_body = sdp("", "", 0, "inactive");
        let rejected = response(200, "application/sdp", &rejected_body);
        let rejected = MediaAnswerPolicy::pcmu(false)
            .and_then(|policy| policy.negotiate_response(&rejected))
            .unwrap_or_else(|_| panic!("rejected"))
            .unwrap_or_else(|| panic!("media"));
        assert_eq!(rejected.disposition(), RemoteMediaDisposition::Rejected);
        assert_eq!(rejected.negotiated(), None);
    }

    #[test]
    fn rejects_wrong_type_missing_connection_and_ambiguous_audio() {
        let body = sdp("c=IN IP4 198.51.100.20\r\n", "", 40_000, "sendrecv");
        let wrong_type = response(200, "text/plain", &body);
        assert!(matches!(
            MediaAnswerPolicy::pcmu(false)
                .and_then(|policy| policy.negotiate_response(&wrong_type)),
            Err(MediaAnswerError::NotApplicationSdp)
        ));

        let missing = response(200, "application/sdp", &sdp("", "", 40_000, "sendrecv"));
        assert!(matches!(
            MediaAnswerPolicy::pcmu(false).and_then(|policy| policy.negotiate_response(&missing)),
            Err(MediaAnswerError::MissingConnection)
        ));

        let mut multiple = body.clone();
        multiple.push_str("m=audio 40002 RTP/AVP 0\r\na=sendrecv\r\n");
        let multiple = response(200, "application/sdp", &multiple);
        assert!(matches!(
            MediaAnswerPolicy::pcmu(false).and_then(|policy| policy.negotiate_response(&multiple)),
            Err(MediaAnswerError::MultipleAudioSections)
        ));
    }

    #[test]
    fn secure_policy_and_connection_parser_fail_closed() {
        let body = sdp("c=IN IP4 198.51.100.20\r\n", "", 40_000, "sendrecv");
        let clear_response = response(200, "application/sdp", &body);
        assert!(matches!(
            MediaAnswerPolicy::pcmu(true)
                .and_then(|policy| policy.negotiate_response(&clear_response)),
            Err(MediaAnswerError::Negotiation(_))
        ));

        let duplicate = sdp(
            "c=IN IP4 198.51.100.20\r\nc=IN IP4 203.0.113.1\r\n",
            "",
            40_000,
            "sendrecv",
        );
        let duplicate = response(200, "application/sdp", &duplicate);
        assert!(matches!(
            MediaAnswerPolicy::pcmu(false).and_then(|policy| policy.negotiate_response(&duplicate)),
            Err(MediaAnswerError::DuplicateConnection)
        ));

        let multicast = sdp("c=IN IP4 239.1.1.1\r\n", "", 40_000, "sendrecv");
        let multicast = response(200, "application/sdp", &multicast);
        assert!(matches!(
            MediaAnswerPolicy::pcmu(false).and_then(|policy| policy.negotiate_response(&multicast)),
            Err(MediaAnswerError::NonUnicastUnsupported)
        ));
    }
}
