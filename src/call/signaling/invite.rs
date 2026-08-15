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

//! Validated construction of an initial outbound INVITE.

use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::sip::builder::request::{BuildError, RequestBuilder};
use crate::sip::framing::MAX_BODY_BYTES;
use crate::sip::headers::call_id::{CallId, ParseError as CallIdError};
use crate::sip::headers::contact::{Contact, ParseError as ContactError};
use crate::sip::headers::content_type::ContentType;
use crate::sip::headers::cseq::{CSeq, ParseError as CSeqError};
use crate::sip::headers::from::{FromHeader, ParseError as FromError};
use crate::sip::headers::max_forwards::MaxForwards;
use crate::sip::headers::to::{ParseError as ToError, ToHeader};
use crate::sip::headers::via::{ParseError as ViaError, Via};
use crate::sip::identifier::{WireTokenError, generate_wire_token};
use crate::sip::parser::message::{self, ParseError as MessageParseError};
use crate::sip::serializer::message::SerializeError;
use crate::sip::types::header::HeaderKind;
use crate::sip::types::method::Method;
use crate::sip::types::uri::Uri;
use crate::sip::validation::request::{self, ValidatedRequest};

/// Immutable inputs used to generate one initial outbound INVITE.
pub struct OutboundInviteConfig {
    caller: Uri,
    target: Uri,
    advertised_addr: SocketAddr,
    max_forwards: MaxForwards,
    sdp: Option<Box<[u8]>>,
}

impl OutboundInviteConfig {
    /// Creates an offerless outbound INVITE configuration.
    ///
    /// # Errors
    ///
    /// Rejects non-SIP identities and unspecified or zero-port advertised
    /// addresses before any wire identifier is generated.
    pub fn new(
        caller: Uri,
        target: Uri,
        advertised_addr: SocketAddr,
    ) -> Result<Self, OutboundInviteError> {
        if !caller.is_sip() {
            return Err(OutboundInviteError::CallerNotSip);
        }
        if !target.is_sip() {
            return Err(OutboundInviteError::TargetNotSip);
        }
        if advertised_addr.ip().is_unspecified() || advertised_addr.port() == 0 {
            return Err(OutboundInviteError::InvalidAdvertisedAddress);
        }
        Ok(Self {
            caller,
            target,
            advertised_addr,
            max_forwards: MaxForwards::new(70),
            sdp: None,
        })
    }

    /// Installs one bounded SDP offer or inactive signaling-test description.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized body and allocation failure.
    pub fn with_sdp(mut self, sdp: &[u8]) -> Result<Self, OutboundInviteError> {
        if sdp.is_empty() {
            return Err(OutboundInviteError::EmptySdp);
        }
        if sdp.len() > MAX_BODY_BYTES {
            return Err(OutboundInviteError::SdpTooLarge {
                attempted: sdp.len(),
                maximum: MAX_BODY_BYTES,
            });
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(sdp.len())
            .map_err(|_| OutboundInviteError::AllocationFailed)?;
        owned.extend_from_slice(sdp);
        self.sdp = Some(owned.into_boxed_slice());
        Ok(self)
    }

    /// Replaces the default Max-Forwards value.
    #[must_use]
    pub const fn with_max_forwards(mut self, max_forwards: MaxForwards) -> Self {
        self.max_forwards = max_forwards;
        self
    }

    /// Generates identifiers and returns a parsed, semantically validated
    /// initial INVITE ready for installation into [`super::UdpSignaling`].
    ///
    /// # Errors
    ///
    /// Preserves cryptographic token generation, typed-header construction,
    /// canonical serialization, parsing, and request validation failures.
    pub fn build(self) -> Result<ValidatedRequest, OutboundInviteError> {
        let tag = generate_wire_token().map_err(OutboundInviteError::WireToken)?;
        let call_token = generate_wire_token().map_err(OutboundInviteError::WireToken)?;
        let branch = generate_wire_token().map_err(OutboundInviteError::WireToken)?;
        let from = FromHeader::from_bytes(format!("<{}>;tag={tag}", self.caller).as_bytes())
            .map_err(OutboundInviteError::From)?;
        let to = ToHeader::from_bytes(format!("<{}>", self.target).as_bytes())
            .map_err(OutboundInviteError::To)?;
        let call_id = CallId::new(format!("{call_token}@{}", self.advertised_addr.ip()))
            .map_err(OutboundInviteError::CallId)?;
        let cseq = CSeq::new(1, Method::Invite).map_err(OutboundInviteError::CSeq)?;
        let via = Via::from_bytes(
            format!(
                "SIP/2.0/UDP {};rport;branch=z9hG4bK-{branch}",
                self.advertised_addr
            )
            .as_bytes(),
        )
        .map_err(OutboundInviteError::Via)?;
        let contact =
            Contact::from_bytes(format!("<sip:liveaisip@{}>", self.advertised_addr).as_bytes())
                .map_err(OutboundInviteError::Contact)?;
        let mut builder = RequestBuilder::new(
            Method::Invite,
            self.target,
            &via,
            &from,
            &to,
            &call_id,
            &cseq,
            self.max_forwards,
        )
        .map_err(OutboundInviteError::Build)?;
        builder
            .push_typed(HeaderKind::Contact, &contact)
            .map_err(OutboundInviteError::Build)?;
        if let Some(sdp) = self.sdp {
            builder = builder
                .with_body(&ContentType::application_sdp(), &sdp)
                .map_err(OutboundInviteError::Build)?;
        }
        let bytes = builder
            .build()
            .serialize()
            .map_err(OutboundInviteError::Serialize)?;
        let raw = message::parse(Arc::from(bytes.into_boxed_slice()))
            .map_err(OutboundInviteError::Parse)?;
        request::validate(raw).map_err(OutboundInviteError::Validate)
    }
}

impl fmt::Debug for OutboundInviteConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundInviteConfig")
            .field("caller_scheme", &self.caller.scheme())
            .field("target_scheme", &self.target.scheme())
            .field("address_family", &address_family(self.advertised_addr))
            .field("has_sdp", &self.sdp.is_some())
            .field("sdp_bytes", &self.sdp.as_deref().map_or(0, <[u8]>::len))
            .finish_non_exhaustive()
    }
}

const fn address_family(address: SocketAddr) -> &'static str {
    if address.is_ipv4() { "ipv4" } else { "ipv6" }
}

/// Initial outbound INVITE configuration or construction failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundInviteError {
    /// Caller identity was not a SIP or SIPS URI.
    CallerNotSip,
    /// Request target was not a SIP or SIPS URI.
    TargetNotSip,
    /// Advertised address was unspecified or used port zero.
    InvalidAdvertisedAddress,
    /// SDP was empty.
    EmptySdp,
    /// SDP exceeded the SIP body bound.
    SdpTooLarge {
        /// Attempted bytes.
        attempted: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Required setup allocation failed.
    AllocationFailed,
    /// Secure wire-token generation failed.
    WireToken(WireTokenError),
    /// Generated From header was invalid.
    From(FromError),
    /// Generated To header was invalid.
    To(ToError),
    /// Generated Call-ID was invalid.
    CallId(CallIdError),
    /// Generated `CSeq` was invalid.
    CSeq(CSeqError),
    /// Generated Via was invalid.
    Via(ViaError),
    /// Generated Contact was invalid.
    Contact(ContactError),
    /// Request builder rejected generated fields.
    Build(BuildError),
    /// Canonical request serialization failed.
    Serialize(SerializeError),
    /// Generated bytes failed message parsing.
    Parse(MessageParseError),
    /// Generated request failed semantic validation.
    Validate(request::ValidationError),
}

impl fmt::Display for OutboundInviteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("initial outbound INVITE construction failed")
    }
}

impl StdError for OutboundInviteError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::WireToken(error) => Some(error),
            Self::From(error) => Some(error),
            Self::To(error) => Some(error),
            Self::CallId(error) => Some(error),
            Self::CSeq(error) => Some(error),
            Self::Via(error) => Some(error),
            Self::Contact(error) => Some(error),
            Self::Build(error) => Some(error),
            Self::Serialize(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::Validate(error) => Some(error),
            Self::CallerNotSip
            | Self::TargetNotSip
            | Self::InvalidAdvertisedAddress
            | Self::EmptySdp
            | Self::SdpTooLarge { .. }
            | Self::AllocationFailed => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{OutboundInviteConfig, OutboundInviteError};
    use crate::sip::parser::uri;

    fn address() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 50_600)
    }

    #[test]
    fn builds_validated_nat_safe_invite_with_bounded_sdp() {
        const SDP: &[u8] =
            b"v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 9 RTP/AVP 0\r\na=inactive\r\n";
        let caller =
            uri::parse_str("sip:runtime@example.invalid").unwrap_or_else(|_| panic!("caller"));
        let target =
            uri::parse_str("sip:1000@pbx.example.invalid").unwrap_or_else(|_| panic!("target"));
        let request = OutboundInviteConfig::new(caller, target, address())
            .and_then(|config| config.with_sdp(SDP))
            .and_then(OutboundInviteConfig::build)
            .unwrap_or_else(|_| panic!("INVITE"));
        assert_eq!(request.request_line().method().as_str(), "INVITE");
        assert_eq!(request.core_headers().cseq().sequence(), 1);
        assert_eq!(request.message().body().len(), SDP.len());
        let via = request.core_headers().via().to_string();
        assert!(via.contains(";rport;"));
    }

    #[test]
    fn rejects_non_sip_identity_and_unusable_advertised_endpoint() {
        let absolute = uri::parse_str("https://example.invalid").unwrap_or_else(|_| panic!("URI"));
        let sip = uri::parse_str("sip:1000@example.invalid").unwrap_or_else(|_| panic!("SIP"));
        assert!(matches!(
            OutboundInviteConfig::new(absolute, sip.clone(), address()),
            Err(OutboundInviteError::CallerNotSip)
        ));
        assert!(matches!(
            OutboundInviteConfig::new(
                sip.clone(),
                sip,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 50_600)
            ),
            Err(OutboundInviteError::InvalidAdvertisedAddress)
        ));
    }

    #[test]
    fn debug_redacts_identities_and_endpoint() {
        let caller =
            uri::parse_str("sip:private-user@example.invalid").unwrap_or_else(|_| panic!("caller"));
        let target = uri::parse_str("sip:secret-target@pbx.example.invalid")
            .unwrap_or_else(|_| panic!("target"));
        let config = OutboundInviteConfig::new(caller, target, address())
            .unwrap_or_else(|_| panic!("config"));
        let debug = format!("{config:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("secret-target"));
        assert!(!debug.contains("192.0.2.10"));
    }
}
