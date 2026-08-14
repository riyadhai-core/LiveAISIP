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

//! Validation-gated symmetric RTP and RTCP endpoint learning.
//!
//! SDP supplies the initial send destinations, but NAT may cause valid media
//! to arrive from different UDP ports or public addresses. This module learns
//! those observed endpoints without inspecting packets or performing I/O.
//!
//! Learning is deliberately not driven by arbitrary UDP datagrams. Callers
//! must invoke [`SymmetricEndpoints::observe_validated_source`] only after all
//! applicable authentication and stream checks have passed: SRTP/SRTCP
//! authentication when enabled, RTP or RTCP parsing, negotiated payload type,
//! and expected source identity. This boundary prevents unauthenticated noise
//! from redirecting outbound media.
//!
//! Each component uses fixed-size state and consecutive-packet probation.
//! Initial NAT discovery may change address and port. Once latched, automatic
//! rebinding is restricted to the same IP address; an address change requires
//! an explicit signaling reset. RTP and RTCP remain independent because NAT
//! mappings for their sockets need not be adjacent.

use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::socket::Component;

/// Default consecutive validated packets required for initial NAT latching.
pub const DEFAULT_INITIAL_LATCH_PACKETS: u8 = 2;

/// Default consecutive validated packets required for same-address rebinding.
pub const DEFAULT_PORT_REBIND_PACKETS: u8 = 3;

/// Bounded symmetric endpoint policy shared by RTP and RTCP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymmetricConfig {
    initial_latch_packets: u8,
    port_rebind_packets: u8,
    allow_port_rebinding: bool,
}

impl SymmetricConfig {
    /// Creates a symmetric endpoint policy.
    ///
    /// # Errors
    ///
    /// Rejects either zero probation threshold. Port rebinding may be disabled,
    /// but its threshold must remain valid so later policy changes are safe.
    pub const fn new(
        initial_latch_packets: u8,
        port_rebind_packets: u8,
        allow_port_rebinding: bool,
    ) -> Result<Self, SymmetricError> {
        if initial_latch_packets == 0 {
            return Err(SymmetricError::ZeroInitialLatchThreshold);
        }
        if port_rebind_packets == 0 {
            return Err(SymmetricError::ZeroPortRebindThreshold);
        }
        Ok(Self {
            initial_latch_packets,
            port_rebind_packets,
            allow_port_rebinding,
        })
    }

    /// Returns the initial consecutive-packet threshold.
    #[must_use]
    pub const fn initial_latch_packets(self) -> u8 {
        self.initial_latch_packets
    }

    /// Returns the same-address port-rebinding threshold.
    #[must_use]
    pub const fn port_rebind_packets(self) -> u8 {
        self.port_rebind_packets
    }

    /// Returns whether an established endpoint may change UDP port.
    #[must_use]
    pub const fn allows_port_rebinding(self) -> bool {
        self.allow_port_rebinding
    }
}

impl Default for SymmetricConfig {
    fn default() -> Self {
        Self {
            initial_latch_packets: DEFAULT_INITIAL_LATCH_PACKETS,
            port_rebind_packets: DEFAULT_PORT_REBIND_PACKETS,
            allow_port_rebinding: true,
        }
    }
}

/// A valid source that policy refused to learn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceRejection {
    /// An established endpoint attempted to change IP address.
    AddressChange,
    /// An established endpoint attempted to change port while rebinding was disabled.
    PortRebindingDisabled,
}

/// Result of observing one validated network source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SymmetricObservation {
    /// Packet arrived from the currently selected destination.
    Current,
    /// Packet arrived from the signaling-advertised endpoint before latching.
    Advertised,
    /// A possible endpoint has not yet completed consecutive-packet probation.
    Candidate {
        /// Validated consecutive packets observed from this candidate.
        observed: u8,
        /// Packets required before selection.
        required: u8,
    },
    /// Initial endpoint probation completed and the destination changed.
    Latched,
    /// Same-address port-rebinding probation completed.
    Rebound,
    /// Source was valid but forbidden by the established endpoint policy.
    Rejected(SourceRejection),
}

/// Independent symmetric destinations for one RTP/RTCP socket pair.
pub struct SymmetricEndpoints {
    config: SymmetricConfig,
    rtp: EndpointState,
    rtcp: EndpointState,
}

impl SymmetricEndpoints {
    /// Creates endpoint state from signaling-advertised destinations.
    ///
    /// # Errors
    ///
    /// Rejects unusable endpoints and mixed address families. A media section
    /// placed on hold must not create active transport state until signaling
    /// supplies routable destinations.
    pub fn new(
        media_destination: SocketAddr,
        control_destination: SocketAddr,
        config: SymmetricConfig,
    ) -> Result<Self, SymmetricError> {
        validate_endpoint(media_destination, Component::Rtp)?;
        validate_endpoint(control_destination, Component::Rtcp)?;
        if media_destination.is_ipv4() != control_destination.is_ipv4() {
            return Err(SymmetricError::MixedAddressFamilies);
        }
        Ok(Self {
            config,
            rtp: EndpointState::new(media_destination),
            rtcp: EndpointState::new(control_destination),
        })
    }

    /// Returns the immutable endpoint policy.
    #[must_use]
    pub const fn config(&self) -> SymmetricConfig {
        self.config
    }

    /// Returns the destination currently selected for a component.
    #[must_use]
    pub const fn destination(&self, component: Component) -> SocketAddr {
        self.state(component).destination()
    }

    /// Returns the original signaling-advertised destination.
    #[must_use]
    pub const fn advertised_destination(&self, component: Component) -> SocketAddr {
        self.state(component).advertised
    }

    /// Returns the learned endpoint, if initial probation completed.
    #[must_use]
    pub const fn learned_destination(&self, component: Component) -> Option<SocketAddr> {
        self.state(component).learned
    }

    /// Observes a source only after packet authentication and stream validation.
    ///
    /// Initial learning requires consecutive validated packets. After latching,
    /// packets from the active endpoint cancel any pending rebind. A different
    /// IP address is never learned automatically; signaling must authorize it
    /// through [`Self::reset_component`].
    ///
    /// # Errors
    ///
    /// Rejects unusable sources and address-family mismatch without changing
    /// either component's state.
    pub fn observe_validated_source(
        &mut self,
        component: Component,
        source: SocketAddr,
    ) -> Result<SymmetricObservation, SymmetricError> {
        validate_endpoint(source, component)?;
        let config = self.config;
        let state = self.state_mut(component);
        if source.is_ipv4() != state.advertised.is_ipv4() {
            return Err(SymmetricError::SourceAddressFamilyMismatch { component });
        }
        Ok(state.observe(source, config))
    }

    /// Replaces one signaling destination and clears all learned state for it.
    ///
    /// This is the explicit authorization path for re-INVITE/UPDATE address
    /// changes. The other component is unchanged.
    ///
    /// # Errors
    ///
    /// Rejects an unusable destination or a family different from the other
    /// component, preserving all prior state on failure.
    pub fn reset_component(
        &mut self,
        component: Component,
        advertised: SocketAddr,
    ) -> Result<(), SymmetricError> {
        validate_endpoint(advertised, component)?;
        let other = self.state(other_component(component)).advertised;
        if advertised.is_ipv4() != other.is_ipv4() {
            return Err(SymmetricError::MixedAddressFamilies);
        }
        *self.state_mut(component) = EndpointState::new(advertised);
        Ok(())
    }

    /// Atomically replaces both signaling destinations and clears learned state.
    ///
    /// # Errors
    ///
    /// Rejects either endpoint or mixed families before mutating existing state.
    pub fn reset(
        &mut self,
        media_destination: SocketAddr,
        control_destination: SocketAddr,
    ) -> Result<(), SymmetricError> {
        let replacement = Self::new(media_destination, control_destination, self.config)?;
        self.rtp = replacement.rtp;
        self.rtcp = replacement.rtcp;
        Ok(())
    }

    const fn state(&self, component: Component) -> &EndpointState {
        match component {
            Component::Rtp => &self.rtp,
            Component::Rtcp => &self.rtcp,
        }
    }

    fn state_mut(&mut self, component: Component) -> &mut EndpointState {
        match component {
            Component::Rtp => &mut self.rtp,
            Component::Rtcp => &mut self.rtcp,
        }
    }
}

impl fmt::Debug for SymmetricEndpoints {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SymmetricEndpoints")
            .field("config", &self.config)
            .field("address_family", &address_family(self.rtp.advertised))
            .field("rtp_learned", &self.rtp.learned.is_some())
            .field("rtp_has_candidate", &self.rtp.candidate.is_some())
            .field("rtcp_learned", &self.rtcp.learned.is_some())
            .field("rtcp_has_candidate", &self.rtcp.candidate.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Candidate {
    source: SocketAddr,
    consecutive: u8,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct EndpointState {
    advertised: SocketAddr,
    learned: Option<SocketAddr>,
    candidate: Option<Candidate>,
}

impl EndpointState {
    const fn new(advertised: SocketAddr) -> Self {
        Self {
            advertised,
            learned: None,
            candidate: None,
        }
    }

    const fn destination(&self) -> SocketAddr {
        match self.learned {
            Some(learned) => learned,
            None => self.advertised,
        }
    }

    fn observe(&mut self, source: SocketAddr, config: SymmetricConfig) -> SymmetricObservation {
        if source == self.destination() {
            self.candidate = None;
            return if self.learned.is_some() {
                SymmetricObservation::Current
            } else {
                SymmetricObservation::Advertised
            };
        }

        let (required, completed) = if let Some(current) = self.learned {
            if source.ip() != current.ip() {
                return SymmetricObservation::Rejected(SourceRejection::AddressChange);
            }
            if !config.allow_port_rebinding {
                return SymmetricObservation::Rejected(SourceRejection::PortRebindingDisabled);
            }
            (config.port_rebind_packets, SymmetricObservation::Rebound)
        } else {
            (config.initial_latch_packets, SymmetricObservation::Latched)
        };

        let observed = match self.candidate {
            Some(candidate) if candidate.source == source => {
                candidate.consecutive.saturating_add(1).min(required)
            }
            _ => 1,
        };
        if observed < required {
            self.candidate = Some(Candidate {
                source,
                consecutive: observed,
            });
            return SymmetricObservation::Candidate { observed, required };
        }

        self.learned = Some(source);
        self.candidate = None;
        completed
    }
}

const fn other_component(component: Component) -> Component {
    match component {
        Component::Rtp => Component::Rtcp,
        Component::Rtcp => Component::Rtp,
    }
}

fn validate_endpoint(endpoint: SocketAddr, component: Component) -> Result<(), SymmetricError> {
    if endpoint.port() == 0 {
        return Err(SymmetricError::PortZero { component });
    }
    let ip = endpoint.ip();
    if ip.is_unspecified() {
        return Err(SymmetricError::UnspecifiedAddress { component });
    }
    if ip.is_multicast() {
        return Err(SymmetricError::MulticastAddress { component });
    }
    if ip == IpAddr::V4(Ipv4Addr::BROADCAST) {
        return Err(SymmetricError::BroadcastAddress { component });
    }
    Ok(())
}

const fn address_family(address: SocketAddr) -> &'static str {
    if address.is_ipv4() { "ipv4" } else { "ipv6" }
}

/// Symmetric endpoint configuration or source-admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SymmetricError {
    /// Initial latching was configured with no probation.
    ZeroInitialLatchThreshold,
    /// Port rebinding was configured with no probation.
    ZeroPortRebindThreshold,
    /// RTP and RTCP signaling destinations use different address families.
    MixedAddressFamilies,
    /// An endpoint used reserved UDP port zero.
    PortZero {
        /// Affected component.
        component: Component,
    },
    /// An endpoint used an unspecified address.
    UnspecifiedAddress {
        /// Affected component.
        component: Component,
    },
    /// An endpoint used a multicast address.
    MulticastAddress {
        /// Affected component.
        component: Component,
    },
    /// An endpoint used the limited IPv4 broadcast address.
    BroadcastAddress {
        /// Affected component.
        component: Component,
    },
    /// An observed source differs from its configured component family.
    SourceAddressFamilyMismatch {
        /// Affected component.
        component: Component,
    },
}

impl SymmetricError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::ZeroInitialLatchThreshold => "zero-initial-latch-threshold",
            Self::ZeroPortRebindThreshold => "zero-port-rebind-threshold",
            Self::MixedAddressFamilies => "mixed-address-families",
            Self::PortZero { .. } => "port-zero",
            Self::UnspecifiedAddress { .. } => "unspecified-address",
            Self::MulticastAddress { .. } => "multicast-address",
            Self::BroadcastAddress { .. } => "broadcast-address",
            Self::SourceAddressFamilyMismatch { .. } => "source-address-family-mismatch",
        }
    }

    /// Returns the affected component when one exists.
    #[must_use]
    pub const fn component(&self) -> Option<Component> {
        match self {
            Self::PortZero { component }
            | Self::UnspecifiedAddress { component }
            | Self::MulticastAddress { component }
            | Self::BroadcastAddress { component }
            | Self::SourceAddressFamilyMismatch { component } => Some(*component),
            Self::ZeroInitialLatchThreshold
            | Self::ZeroPortRebindThreshold
            | Self::MixedAddressFamilies => None,
        }
    }
}

impl fmt::Display for SymmetricError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "symmetric endpoint rejected ({})", self.class())
    }
}

impl StdError for SymmetricError {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{
        SourceRejection, SymmetricConfig, SymmetricEndpoints, SymmetricError, SymmetricObservation,
    };
    use crate::rtp::transport::Component;

    const fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    fn endpoints(config: SymmetricConfig) -> SymmetricEndpoints {
        let Ok(endpoints) =
            SymmetricEndpoints::new(v4(192, 0, 2, 10, 10_000), v4(192, 0, 2, 10, 10_001), config)
        else {
            panic!("valid endpoints")
        };
        endpoints
    }

    #[test]
    fn configuration_rejects_zero_thresholds() {
        assert_eq!(
            SymmetricConfig::new(0, 3, true),
            Err(SymmetricError::ZeroInitialLatchThreshold)
        );
        assert_eq!(
            SymmetricConfig::new(2, 0, true),
            Err(SymmetricError::ZeroPortRebindThreshold)
        );
    }

    #[test]
    fn initial_learning_requires_consecutive_validated_sources() {
        let mut endpoints = endpoints(SymmetricConfig::default());
        let nat = v4(198, 51, 100, 7, 40_000);

        assert_eq!(
            endpoints.observe_validated_source(Component::Rtp, nat),
            Ok(SymmetricObservation::Candidate {
                observed: 1,
                required: 2,
            })
        );
        assert_eq!(
            endpoints.destination(Component::Rtp),
            v4(192, 0, 2, 10, 10_000)
        );
        assert_eq!(
            endpoints.observe_validated_source(Component::Rtp, nat),
            Ok(SymmetricObservation::Latched)
        );
        assert_eq!(endpoints.destination(Component::Rtp), nat);
        assert_eq!(endpoints.learned_destination(Component::Rtp), Some(nat));
    }

    #[test]
    fn competing_candidate_restarts_probation() {
        let Ok(config) = SymmetricConfig::new(3, 3, true) else {
            panic!("config")
        };
        let mut endpoints = endpoints(config);
        let first = v4(198, 51, 100, 1, 40_000);
        let second = v4(198, 51, 100, 2, 40_002);

        assert!(matches!(
            endpoints.observe_validated_source(Component::Rtp, first),
            Ok(SymmetricObservation::Candidate { observed: 1, .. })
        ));
        assert!(matches!(
            endpoints.observe_validated_source(Component::Rtp, second),
            Ok(SymmetricObservation::Candidate { observed: 1, .. })
        ));
        assert!(matches!(
            endpoints.observe_validated_source(Component::Rtp, second),
            Ok(SymmetricObservation::Candidate { observed: 2, .. })
        ));
        assert_eq!(
            endpoints.observe_validated_source(Component::Rtp, first),
            Ok(SymmetricObservation::Candidate {
                observed: 1,
                required: 3,
            })
        );
    }

    #[test]
    fn advertised_and_current_packets_cancel_candidates() {
        let mut endpoints = endpoints(SymmetricConfig::default());
        let advertised = endpoints.destination(Component::Rtp);
        let nat = v4(198, 51, 100, 3, 40_000);
        assert!(matches!(
            endpoints.observe_validated_source(Component::Rtp, nat),
            Ok(SymmetricObservation::Candidate { .. })
        ));
        assert_eq!(
            endpoints.observe_validated_source(Component::Rtp, advertised),
            Ok(SymmetricObservation::Advertised)
        );
        assert!(matches!(
            endpoints.observe_validated_source(Component::Rtp, nat),
            Ok(SymmetricObservation::Candidate { observed: 1, .. })
        ));
        assert!(
            endpoints
                .observe_validated_source(Component::Rtp, nat)
                .is_ok()
        );

        let rebound = v4(198, 51, 100, 3, 41_000);
        assert!(matches!(
            endpoints.observe_validated_source(Component::Rtp, rebound),
            Ok(SymmetricObservation::Candidate { .. })
        ));
        assert_eq!(
            endpoints.observe_validated_source(Component::Rtp, nat),
            Ok(SymmetricObservation::Current)
        );
    }

    #[test]
    fn established_endpoint_allows_probationary_same_ip_port_rebind() {
        let Ok(config) = SymmetricConfig::new(1, 2, true) else {
            panic!("config")
        };
        let mut endpoints = endpoints(config);
        let original = v4(198, 51, 100, 9, 40_000);
        let rebound = v4(198, 51, 100, 9, 40_002);
        assert_eq!(
            endpoints.observe_validated_source(Component::Rtp, original),
            Ok(SymmetricObservation::Latched)
        );
        assert!(matches!(
            endpoints.observe_validated_source(Component::Rtp, rebound),
            Ok(SymmetricObservation::Candidate {
                observed: 1,
                required: 2
            })
        ));
        assert_eq!(endpoints.destination(Component::Rtp), original);
        assert_eq!(
            endpoints.observe_validated_source(Component::Rtp, rebound),
            Ok(SymmetricObservation::Rebound)
        );
        assert_eq!(endpoints.destination(Component::Rtp), rebound);
    }

    #[test]
    fn established_endpoint_never_learns_new_ip_implicitly() {
        let Ok(config) = SymmetricConfig::new(1, 1, true) else {
            panic!("config")
        };
        let mut endpoints = endpoints(config);
        let original = v4(198, 51, 100, 9, 40_000);
        let attacker = v4(203, 0, 113, 4, 40_000);
        assert!(
            endpoints
                .observe_validated_source(Component::Rtp, original)
                .is_ok()
        );
        assert_eq!(
            endpoints.observe_validated_source(Component::Rtp, attacker),
            Ok(SymmetricObservation::Rejected(
                SourceRejection::AddressChange
            ))
        );
        assert_eq!(endpoints.destination(Component::Rtp), original);
    }

    #[test]
    fn port_rebinding_can_be_disabled() {
        let Ok(config) = SymmetricConfig::new(1, 2, false) else {
            panic!("config")
        };
        let mut endpoints = endpoints(config);
        let original = v4(198, 51, 100, 9, 40_000);
        let changed = v4(198, 51, 100, 9, 40_002);
        assert!(
            endpoints
                .observe_validated_source(Component::Rtp, original)
                .is_ok()
        );
        assert_eq!(
            endpoints.observe_validated_source(Component::Rtp, changed),
            Ok(SymmetricObservation::Rejected(
                SourceRejection::PortRebindingDisabled
            ))
        );
    }

    #[test]
    fn rtp_and_rtcp_learning_are_independent() {
        let Ok(config) = SymmetricConfig::new(1, 1, true) else {
            panic!("config")
        };
        let mut endpoints = endpoints(config);
        let learned_media = v4(198, 51, 100, 1, 50_000);
        let learned_control = v4(198, 51, 100, 1, 60_000);
        assert!(
            endpoints
                .observe_validated_source(Component::Rtp, learned_media)
                .is_ok()
        );
        assert_eq!(endpoints.destination(Component::Rtp), learned_media);
        assert_eq!(
            endpoints.destination(Component::Rtcp),
            v4(192, 0, 2, 10, 10_001)
        );
        assert!(
            endpoints
                .observe_validated_source(Component::Rtcp, learned_control)
                .is_ok()
        );
        assert_eq!(endpoints.destination(Component::Rtcp), learned_control);
    }

    #[test]
    fn resets_are_validated_and_atomic() {
        let Ok(config) = SymmetricConfig::new(1, 1, true) else {
            panic!("config")
        };
        let mut endpoints = endpoints(config);
        let learned = v4(198, 51, 100, 1, 50_000);
        assert!(
            endpoints
                .observe_validated_source(Component::Rtp, learned)
                .is_ok()
        );

        let invalid_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 12_000);
        assert_eq!(
            endpoints.reset(invalid_v6, v4(203, 0, 113, 1, 12_001)),
            Err(SymmetricError::MixedAddressFamilies)
        );
        assert_eq!(endpoints.destination(Component::Rtp), learned);

        let new_rtp = v4(203, 0, 113, 8, 20_000);
        assert!(endpoints.reset_component(Component::Rtp, new_rtp).is_ok());
        assert_eq!(endpoints.destination(Component::Rtp), new_rtp);
        assert_eq!(endpoints.learned_destination(Component::Rtp), None);
    }

    #[test]
    fn invalid_endpoints_and_sources_never_mutate_state() {
        let valid_rtcp = v4(192, 0, 2, 1, 10_001);
        assert!(matches!(
            SymmetricEndpoints::new(
                v4(0, 0, 0, 0, 10_000),
                valid_rtcp,
                SymmetricConfig::default()
            ),
            Err(SymmetricError::UnspecifiedAddress {
                component: Component::Rtp
            })
        ));
        assert!(matches!(
            SymmetricEndpoints::new(
                v4(224, 0, 0, 1, 10_000),
                valid_rtcp,
                SymmetricConfig::default()
            ),
            Err(SymmetricError::MulticastAddress {
                component: Component::Rtp
            })
        ));
        assert!(matches!(
            SymmetricEndpoints::new(
                v4(255, 255, 255, 255, 10_000),
                valid_rtcp,
                SymmetricConfig::default()
            ),
            Err(SymmetricError::BroadcastAddress {
                component: Component::Rtp
            })
        ));

        let mut endpoints = endpoints(SymmetricConfig::default());
        let before = endpoints.destination(Component::Rtp);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 30_000);
        assert_eq!(
            endpoints.observe_validated_source(Component::Rtp, v6),
            Err(SymmetricError::SourceAddressFamilyMismatch {
                component: Component::Rtp
            })
        );
        assert_eq!(endpoints.destination(Component::Rtp), before);
    }

    #[test]
    fn debug_and_errors_do_not_disclose_network_endpoints() {
        let endpoints = endpoints(SymmetricConfig::default());
        let debug = format!("{endpoints:?}");
        assert!(!debug.contains("192.0.2.10"));
        assert!(!debug.contains("10000"));

        let error = SymmetricError::PortZero {
            component: Component::Rtp,
        };
        assert_eq!(error.class(), "port-zero");
        assert_eq!(error.component(), Some(Component::Rtp));
        assert!(!error.to_string().contains("192.0.2.10"));
    }
}
