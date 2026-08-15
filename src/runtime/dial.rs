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

//! Atomic preparation of one outbound UDP call runtime.
//!
//! This boundary acquires no process-global capacity by itself. Callers pass
//! already acquired admission leases, which are released automatically if any
//! socket, INVITE, or runtime construction step fails.

use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::ParseIntError;
use std::time::Duration;

use crate::call::execution::runtime::{CallRuntime, CallRuntimeConfig, CallRuntimeError};
use crate::call::model::context::{CallContext, CallContextError, DEFAULT_CALL_TIMELINE_CAPACITY};
use crate::call::signaling::{
    OutboundInviteConfig, OutboundInviteError, SignalingError, UdpSignaling,
};
use crate::runtime::admission::AdmissionLeaseGroup;
use crate::runtime::media_offer::{MediaOfferConfig, MediaOfferError};
use crate::sip::auth::DigestCredentials;
use crate::sip::framing::MAX_BODY_BYTES;
use crate::sip::identifier::{WireTokenError, generate_wire_token};
use crate::sip::transport::udp::UdpConfig;
use crate::sip::transport::udp_driver::UdpDriverConfig;
use crate::sip::types::uri::Uri;

enum AdvertisedEndpoint {
    Ip(IpAddr),
    Address(SocketAddr),
}

enum InviteBody {
    Offerless,
    Sdp(Box<[u8]>),
    MediaOffer(MediaOfferConfig),
    InactivePcmu,
}

/// Immutable inputs needed to prepare one outbound UDP call.
pub struct OutboundDialConfig {
    caller: Uri,
    target: Uri,
    bind: SocketAddr,
    destination: SocketAddr,
    advertised: Option<AdvertisedEndpoint>,
    credentials: Option<DigestCredentials>,
    body: InviteBody,
    timeline_capacity: usize,
    runtime: CallRuntimeConfig,
    driver: UdpDriverConfig,
    udp: UdpConfig,
}

impl OutboundDialConfig {
    /// Creates an offerless outbound UDP dial configuration.
    ///
    /// # Errors
    ///
    /// Rejects non-SIP caller and target identities. Socket endpoint policy is
    /// validated atomically during [`Self::prepare`].
    pub fn new(
        caller: Uri,
        target: Uri,
        bind: SocketAddr,
        destination: SocketAddr,
    ) -> Result<Self, OutboundDialError> {
        if !caller.is_sip() {
            return Err(OutboundDialError::CallerNotSip);
        }
        if !target.is_sip() {
            return Err(OutboundDialError::TargetNotSip);
        }
        Ok(Self {
            caller,
            target,
            bind,
            destination,
            advertised: None,
            credentials: None,
            body: InviteBody::Offerless,
            timeline_capacity: DEFAULT_CALL_TIMELINE_CAPACITY,
            runtime: CallRuntimeConfig::default(),
            driver: UdpDriverConfig::default(),
            udp: UdpConfig::default(),
        })
    }

    /// Uses this public IP with the actual bound socket port in Via and
    /// Contact. This is appropriate for one-to-one address translation.
    ///
    /// # Errors
    ///
    /// Rejects an unspecified IP address.
    pub fn with_advertised_ip(mut self, address: IpAddr) -> Result<Self, OutboundDialError> {
        if address.is_unspecified() {
            return Err(OutboundDialError::InvalidAdvertisedAddress);
        }
        self.advertised = Some(AdvertisedEndpoint::Ip(address));
        Ok(self)
    }

    /// Uses an explicit stable public NAT mapping in Via and Contact.
    ///
    /// # Errors
    ///
    /// Rejects an unspecified address or port zero. Address-family agreement
    /// with the selected local route is checked during preparation.
    pub fn with_advertised_addr(mut self, address: SocketAddr) -> Result<Self, OutboundDialError> {
        if address.ip().is_unspecified() || address.port() == 0 {
            return Err(OutboundDialError::InvalidAdvertisedAddress);
        }
        self.advertised = Some(AdvertisedEndpoint::Address(address));
        Ok(self)
    }

    /// Installs bounded Digest credentials for 401/407 retry handling.
    #[must_use]
    pub fn with_credentials(mut self, credentials: DigestCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Installs a complete bounded raw SDP body as an advanced escape hatch.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized body and allocation failure.
    pub fn with_sdp(mut self, sdp: &[u8]) -> Result<Self, OutboundDialError> {
        if sdp.is_empty() {
            return Err(OutboundDialError::EmptySdp);
        }
        if sdp.len() > MAX_BODY_BYTES {
            return Err(OutboundDialError::SdpTooLarge {
                attempted: sdp.len(),
                maximum: MAX_BODY_BYTES,
            });
        }
        let mut body = Vec::new();
        body.try_reserve_exact(sdp.len())
            .map_err(|_| OutboundDialError::AllocationFailed)?;
        body.extend_from_slice(sdp);
        self.body = InviteBody::Sdp(body.into_boxed_slice());
        Ok(self)
    }

    /// Installs a typed media offer whose SDP is generated by LiveAISIP.
    #[must_use]
    pub fn with_media_offer(mut self, offer: MediaOfferConfig) -> Self {
        self.body = InviteBody::MediaOffer(offer);
        self
    }

    /// Generates the inactive PCMU offer used by signaling-only interop tests.
    ///
    /// The media port is the RFC discard port and the direction is inactive;
    /// this mode never claims that an RTP receiver exists.
    #[must_use]
    pub fn with_inactive_pcmu_sdp(mut self) -> Self {
        self.body = InviteBody::InactivePcmu;
        self
    }

    /// Replaces the per-call timeline capacity.
    #[must_use]
    pub const fn with_timeline_capacity(mut self, capacity: usize) -> Self {
        self.timeline_capacity = capacity;
        self
    }

    /// Replaces immutable call-runtime capacities and teardown policy.
    #[must_use]
    pub const fn with_runtime_config(mut self, config: CallRuntimeConfig) -> Self {
        self.runtime = config;
        self
    }

    /// Replaces bounded UDP receive and transmit policies.
    #[must_use]
    pub const fn with_udp_config(mut self, driver: UdpDriverConfig, udp: UdpConfig) -> Self {
        self.driver = driver;
        self.udp = udp;
        self
    }

    /// Binds signaling, builds and installs the INVITE, and returns a runtime
    /// ready to move into exactly one call thread.
    ///
    /// # Errors
    ///
    /// Preserves signaling, identifier, INVITE, context, and runtime failures.
    /// All supplied admission leases unwind on every failure path.
    pub fn prepare(
        self,
        started_at: Duration,
        admission: AdmissionLeaseGroup,
    ) -> Result<PreparedOutboundCall, OutboundDialError> {
        let mut signaling = UdpSignaling::bind(self.bind, self.destination, self.driver, self.udp)
            .map_err(OutboundDialError::Signaling)?;
        let local_addr = signaling.local_addr();
        let advertised_addr = match self.advertised {
            None => local_addr,
            Some(AdvertisedEndpoint::Ip(address)) => SocketAddr::new(address, local_addr.port()),
            Some(AdvertisedEndpoint::Address(address)) => address,
        };
        signaling = signaling
            .with_advertised_addr(advertised_addr)
            .map_err(OutboundDialError::Signaling)?;
        if let Some(credentials) = self.credentials {
            signaling = signaling.with_credentials(credentials);
        }

        let mut invite = OutboundInviteConfig::new(self.caller, self.target, advertised_addr)
            .map_err(OutboundDialError::Invite)?;
        match self.body {
            InviteBody::Offerless => {}
            InviteBody::Sdp(body) => {
                invite = invite.with_sdp(&body).map_err(OutboundDialError::Invite)?;
            }
            InviteBody::MediaOffer(offer) => {
                let body = render_media_offer(offer)?;
                invite = invite.with_sdp(&body).map_err(OutboundDialError::Invite)?;
            }
            InviteBody::InactivePcmu => {
                let offer = MediaOfferConfig::pcmu(SocketAddr::new(advertised_addr.ip(), 9))?
                    .with_direction(crate::sip::sdp::Direction::Inactive)
                    .with_telephone_event(None)?;
                let body = render_media_offer(offer)?;
                invite = invite.with_sdp(&body).map_err(OutboundDialError::Invite)?;
            }
        }
        signaling
            .install_initial_invite(invite.build().map_err(OutboundDialError::Invite)?)
            .map_err(OutboundDialError::Signaling)?;
        let context = CallContext::new(started_at, self.timeline_capacity)
            .map_err(OutboundDialError::Context)?;
        let runtime = CallRuntime::new(context, admission, self.runtime)
            .map_err(OutboundDialError::Runtime)?
            .with_udp_signaling(signaling)
            .map_err(OutboundDialError::Runtime)?;
        Ok(PreparedOutboundCall {
            runtime,
            local_addr,
            advertised_addr,
        })
    }
}

impl fmt::Debug for OutboundDialConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundDialConfig")
            .field("bind_family", &address_family(self.bind))
            .field("destination_family", &address_family(self.destination))
            .field("has_explicit_advertisement", &self.advertised.is_some())
            .field("has_credentials", &self.credentials.is_some())
            .field("body_kind", &body_kind(&self.body))
            .field("timeline_capacity", &self.timeline_capacity)
            .finish_non_exhaustive()
    }
}

/// Fully prepared runtime and its resolved signaling endpoints.
pub struct PreparedOutboundCall {
    runtime: CallRuntime,
    local_addr: SocketAddr,
    advertised_addr: SocketAddr,
}

impl PreparedOutboundCall {
    /// Returns the actual bound call-owned UDP endpoint.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the endpoint serialized into initial Via and Contact fields.
    #[must_use]
    pub const fn advertised_addr(&self) -> SocketAddr {
        self.advertised_addr
    }

    /// Moves the completely prepared runtime into its dedicated call thread.
    #[must_use]
    pub fn into_runtime(self) -> CallRuntime {
        self.runtime
    }
}

impl fmt::Debug for PreparedOutboundCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedOutboundCall")
            .field("address_family", &address_family(self.local_addr))
            .field(
                "uses_address_translation",
                &(self.local_addr != self.advertised_addr),
            )
            .finish_non_exhaustive()
    }
}

/// Outbound call preparation failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundDialError {
    /// Caller identity was not a SIP or SIPS URI.
    CallerNotSip,
    /// Target identity was not a SIP or SIPS URI.
    TargetNotSip,
    /// Explicit advertised address was unspecified or used port zero.
    InvalidAdvertisedAddress,
    /// SDP was empty.
    EmptySdp,
    /// SDP exceeded the SIP body limit.
    SdpTooLarge {
        /// Attempted body bytes.
        attempted: usize,
        /// Maximum body bytes.
        maximum: usize,
    },
    /// Required bounded allocation failed.
    AllocationFailed,
    /// Signaling socket or installation failed.
    Signaling(SignalingError),
    /// Initial INVITE construction failed.
    Invite(OutboundInviteError),
    /// Per-call context construction failed.
    Context(CallContextError),
    /// Per-call runtime construction failed.
    Runtime(CallRuntimeError),
    /// Signaling-test SDP identifier generation failed.
    WireToken(WireTokenError),
    /// Internally generated hexadecimal SDP session identifier was invalid.
    SessionId(ParseIntError),
    /// Typed media offer was invalid or could not be rendered.
    MediaOffer(MediaOfferError),
}

impl fmt::Display for OutboundDialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("outbound call preparation failed")
    }
}

impl StdError for OutboundDialError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Signaling(error) => Some(error),
            Self::Invite(error) => Some(error),
            Self::Context(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::WireToken(error) => Some(error),
            Self::SessionId(error) => Some(error),
            Self::MediaOffer(error) => Some(error),
            Self::CallerNotSip
            | Self::TargetNotSip
            | Self::InvalidAdvertisedAddress
            | Self::EmptySdp
            | Self::SdpTooLarge { .. }
            | Self::AllocationFailed => None,
        }
    }
}

impl From<MediaOfferError> for OutboundDialError {
    fn from(error: MediaOfferError) -> Self {
        Self::MediaOffer(error)
    }
}

fn render_media_offer(offer: MediaOfferConfig) -> Result<Box<[u8]>, OutboundDialError> {
    let token = generate_wire_token().map_err(OutboundDialError::WireToken)?;
    let session_id = u64::from_str_radix(&token[..16], 16).map_err(OutboundDialError::SessionId)?;
    offer
        .render(session_id)
        .map_err(OutboundDialError::MediaOffer)
}

const fn address_family(address: SocketAddr) -> &'static str {
    if address.is_ipv4() { "ipv4" } else { "ipv6" }
}

const fn body_kind(body: &InviteBody) -> &'static str {
    match body {
        InviteBody::Offerless => "offerless",
        InviteBody::Sdp(_) => "sdp",
        InviteBody::MediaOffer(_) => "media-offer",
        InviteBody::InactivePcmu => "inactive-pcmu",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::Duration;

    use super::{OutboundDialConfig, OutboundDialError};
    use crate::runtime::admission::AdmissionLeaseGroup;
    use crate::runtime::media_offer::MediaOfferConfig;
    use crate::sip::parser::uri;

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn config(destination: SocketAddr) -> OutboundDialConfig {
        let caller =
            uri::parse_str("sip:private-user@example.invalid").unwrap_or_else(|_| panic!("caller"));
        let target = uri::parse_str("sip:secret-target@example.invalid")
            .unwrap_or_else(|_| panic!("target"));
        OutboundDialConfig::new(caller, target, localhost(0), destination)
            .unwrap_or_else(|_| panic!("config"))
    }

    #[test]
    fn prepares_one_call_owned_socket_invite_and_runtime_atomically() {
        let peer = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("peer"));
        let remote = peer.local_addr().unwrap_or_else(|_| panic!("remote"));
        let prepared = config(remote)
            .with_inactive_pcmu_sdp()
            .prepare(Duration::ZERO, AdmissionLeaseGroup::new())
            .unwrap_or_else(|_| panic!("prepared call"));
        assert_ne!(prepared.local_addr().port(), 0);
        assert_eq!(prepared.local_addr(), prepared.advertised_addr());
        let debug = format!("{prepared:?}");
        assert!(!debug.contains("127.0.0.1"));
        drop(prepared.into_runtime());
    }

    #[test]
    fn supports_explicit_stable_nat_mapping_without_disclosing_it() {
        let peer = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("peer"));
        let remote = peer.local_addr().unwrap_or_else(|_| panic!("remote"));
        let mapped = "198.51.100.20:62000"
            .parse()
            .unwrap_or_else(|_| panic!("mapped"));
        let prepared = config(remote)
            .with_advertised_addr(mapped)
            .and_then(|config| config.prepare(Duration::ZERO, AdmissionLeaseGroup::new()))
            .unwrap_or_else(|_| panic!("prepared call"));
        assert_eq!(prepared.advertised_addr(), mapped);
        assert_ne!(prepared.local_addr(), mapped);
        assert!(!format!("{prepared:?}").contains("198.51.100.20"));
    }

    #[test]
    fn typed_media_offer_is_installed_without_caller_authored_sdp() {
        let offer = MediaOfferConfig::pcmu(localhost(40_000)).unwrap_or_else(|_| panic!("offer"));
        let dial = config(localhost(5_060)).with_media_offer(offer);
        let debug = format!("{dial:?}");
        assert!(debug.contains("media-offer"));
        assert!(!debug.contains("40000"));
    }

    #[test]
    fn rejects_invalid_identity_advertisement_and_sdp_before_socket_binding() {
        let absolute =
            uri::parse_str("https://example.invalid").unwrap_or_else(|_| panic!("absolute"));
        let sip = uri::parse_str("sip:1000@example.invalid").unwrap_or_else(|_| panic!("sip"));
        assert!(matches!(
            OutboundDialConfig::new(absolute, sip, localhost(0), localhost(5060)),
            Err(OutboundDialError::CallerNotSip)
        ));
        assert!(matches!(
            config(localhost(5060)).with_advertised_addr(localhost(0)),
            Err(OutboundDialError::InvalidAdvertisedAddress)
        ));
        assert!(matches!(
            config(localhost(5060)).with_sdp(&[]),
            Err(OutboundDialError::EmptySdp)
        ));
    }

    #[test]
    fn configuration_debug_redacts_identities_endpoints_and_credentials() {
        let config = config(localhost(5060));
        let debug = format!("{config:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("secret-target"));
        assert!(!debug.contains("127.0.0.1"));
    }
}
