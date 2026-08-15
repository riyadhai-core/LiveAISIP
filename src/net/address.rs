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

//! Validated network endpoint and explicit bind-address primitives.
//!
//! Untrusted, resolved, observed, and configured addresses must not flow into
//! signaling or media state as unchecked `SocketAddr` values. [`Endpoint`]
//! proves that an address is concrete and has a nonzero port. [`BindAddress`]
//! separately represents local binding, where wildcard hosts and ephemeral
//! ports are legitimate only when selected explicitly.
//!
//! IPv4-mapped IPv6 endpoints are canonicalized to IPv4. This prevents one
//! peer from occupying two connection, backoff, admission, or source-validation
//! identities through equivalent textual address forms.
//!
//! Network addresses are sensitive operational data. `Debug` and errors expose
//! only low-cardinality family and policy information; callers must explicitly
//! request the underlying socket address when performing I/O.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::num::NonZeroU16;

/// Internet protocol address family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AddressFamily {
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
}

impl AddressFamily {
    /// Returns the family of an IP address.
    #[must_use]
    pub const fn of_ip(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }

    /// Returns the family of a socket address.
    #[must_use]
    pub const fn of_socket(address: SocketAddr) -> Self {
        if address.is_ipv4() {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }

    /// Returns this family's wildcard IP address.
    #[must_use]
    pub const fn unspecified_ip(self) -> IpAddr {
        match self {
            Self::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Self::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }

    /// Returns a stable lowercase diagnostic name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A canonical concrete network endpoint.
///
/// The IP address is never unspecified and the port is never zero.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Endpoint(SocketAddr);

impl Endpoint {
    /// Validates and canonicalizes a concrete endpoint.
    ///
    /// IPv4-mapped IPv6 values become native IPv4 endpoints before validation.
    /// Loopback, private, documentation, and link-local addresses remain valid;
    /// whether they are allowed is deployment or subsystem policy rather than
    /// universal endpoint syntax.
    ///
    /// # Errors
    ///
    /// Rejects port zero and unspecified addresses.
    pub fn new(address: SocketAddr) -> Result<Self, EndpointError> {
        let address = canonicalize(address);
        if address.port() == 0 {
            return Err(EndpointError::ZeroPort);
        }
        if address.ip().is_unspecified() {
            return Err(EndpointError::UnspecifiedAddress);
        }
        Ok(Self(address))
    }

    /// Validates an IP address and port as one concrete endpoint.
    ///
    /// # Errors
    ///
    /// Preserves [`Self::new`] validation.
    pub fn from_parts(address: IpAddr, port: u16) -> Result<Self, EndpointError> {
        Self::new(SocketAddr::new(address, port))
    }

    /// Returns the canonical socket address for explicit network I/O.
    #[must_use]
    pub const fn socket_addr(self) -> SocketAddr {
        self.0
    }

    /// Returns the canonical IP address.
    #[must_use]
    pub const fn ip(self) -> IpAddr {
        self.0.ip()
    }

    /// Returns the nonzero port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.0.port()
    }

    /// Returns the address family.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        AddressFamily::of_socket(self.0)
    }

    /// Returns whether both endpoints identify the same host, ignoring port.
    #[must_use]
    pub fn same_host(self, other: Self) -> bool {
        self.ip() == other.ip()
    }

    /// Returns whether both endpoints use the same address family.
    #[must_use]
    pub const fn same_family(self, other: Self) -> bool {
        matches!(
            (self.family(), other.family()),
            (AddressFamily::Ipv4, AddressFamily::Ipv4) | (AddressFamily::Ipv6, AddressFamily::Ipv6)
        )
    }
}

impl TryFrom<SocketAddr> for Endpoint {
    type Error = EndpointError;

    fn try_from(address: SocketAddr) -> Result<Self, Self::Error> {
        Self::new(address)
    }
}

impl From<Endpoint> for SocketAddr {
    fn from(endpoint: Endpoint) -> Self {
        endpoint.socket_addr()
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Endpoint")
            .field("family", &self.family())
            .finish_non_exhaustive()
    }
}

/// Explicit local bind host selection.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum BindHost {
    /// Bind one concrete local interface address.
    Specific(IpAddr),
    /// Bind all local interfaces in one address family.
    Any(AddressFamily),
}

impl BindHost {
    /// Creates a concrete bind-host selection.
    ///
    /// IPv4-mapped IPv6 addresses are canonicalized to IPv4.
    ///
    /// # Errors
    ///
    /// Rejects an unspecified address because wildcard selection must use
    /// [`Self::Any`] explicitly.
    pub fn specific(address: IpAddr) -> Result<Self, BindAddressError> {
        let address = canonicalize_ip(address);
        if address.is_unspecified() {
            return Err(BindAddressError::UnspecifiedSpecificAddress);
        }
        Ok(Self::Specific(address))
    }

    /// Creates an explicit wildcard bind for one family.
    #[must_use]
    pub const fn any(family: AddressFamily) -> Self {
        Self::Any(family)
    }

    /// Returns the selected IP address.
    #[must_use]
    pub const fn ip(self) -> IpAddr {
        match self {
            Self::Specific(address) => address,
            Self::Any(family) => family.unspecified_ip(),
        }
    }

    /// Returns the selected address family.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        match self {
            Self::Specific(address) => AddressFamily::of_ip(address),
            Self::Any(family) => family,
        }
    }

    /// Returns whether all local interfaces are selected.
    #[must_use]
    pub const fn is_wildcard(self) -> bool {
        matches!(self, Self::Any(_))
    }
}

impl fmt::Debug for BindHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindHost")
            .field("family", &self.family())
            .field("wildcard", &self.is_wildcard())
            .finish_non_exhaustive()
    }
}

/// Explicit local bind-port selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BindPort {
    /// Bind one configured nonzero port.
    Fixed(NonZeroU16),
    /// Ask the operating system for an ephemeral port.
    Ephemeral,
}

impl BindPort {
    /// Creates a fixed port selection.
    ///
    /// # Errors
    ///
    /// Rejects zero because ephemeral selection must use [`Self::Ephemeral`].
    pub const fn fixed(port: u16) -> Result<Self, BindAddressError> {
        match NonZeroU16::new(port) {
            Some(port) => Ok(Self::Fixed(port)),
            None => Err(BindAddressError::ZeroFixedPort),
        }
    }

    /// Returns the socket-level port (`0` for ephemeral selection).
    #[must_use]
    pub const fn value(self) -> u16 {
        match self {
            Self::Fixed(port) => port.get(),
            Self::Ephemeral => 0,
        }
    }

    /// Returns whether the operating system chooses the port.
    #[must_use]
    pub const fn is_ephemeral(self) -> bool {
        matches!(self, Self::Ephemeral)
    }
}

/// Explicitly configured local bind address.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BindAddress {
    host: BindHost,
    port: BindPort,
}

impl BindAddress {
    /// Combines explicit host and port selections.
    #[must_use]
    pub const fn new(host: BindHost, port: BindPort) -> Self {
        Self { host, port }
    }

    /// Returns the bind host policy.
    #[must_use]
    pub const fn host(self) -> BindHost {
        self.host
    }

    /// Returns the bind port policy.
    #[must_use]
    pub const fn port(self) -> BindPort {
        self.port
    }

    /// Returns the address family.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        self.host.family()
    }

    /// Returns the socket address passed to the operating system.
    #[must_use]
    pub const fn socket_addr(self) -> SocketAddr {
        SocketAddr::new(self.host.ip(), self.port.value())
    }

    /// Returns whether all local interfaces are selected.
    #[must_use]
    pub const fn is_wildcard(self) -> bool {
        self.host.is_wildcard()
    }

    /// Returns whether the operating system chooses the port.
    #[must_use]
    pub const fn is_ephemeral(self) -> bool {
        self.port.is_ephemeral()
    }
}

impl fmt::Debug for BindAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindAddress")
            .field("family", &self.family())
            .field("wildcard", &self.is_wildcard())
            .field("ephemeral", &self.is_ephemeral())
            .finish_non_exhaustive()
    }
}

/// Failure to validate a concrete endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EndpointError {
    /// A concrete endpoint used port zero.
    ZeroPort,
    /// A concrete endpoint used a wildcard IP address.
    UnspecifiedAddress,
}

impl EndpointError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::ZeroPort => "zero-port",
            Self::UnspecifiedAddress => "unspecified-address",
        }
    }
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "network endpoint error: {}", self.class())
    }
}

impl StdError for EndpointError {}

/// Failure to construct an explicit local bind selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BindAddressError {
    /// A specific host used a wildcard address instead of [`BindHost::Any`].
    UnspecifiedSpecificAddress,
    /// A fixed port used zero instead of [`BindPort::Ephemeral`].
    ZeroFixedPort,
}

impl BindAddressError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::UnspecifiedSpecificAddress => "unspecified-specific-address",
            Self::ZeroFixedPort => "zero-fixed-port",
        }
    }
}

impl fmt::Display for BindAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "network bind-address error: {}", self.class())
    }
}

impl StdError for BindAddressError {}

/// Resolves a wildcard outbound UDP bind to the concrete source IP selected by
/// the operating-system routing table.
///
/// Concrete configured addresses pass through unchanged. For a wildcard bind,
/// this function creates a short-lived connected UDP probe in the destination
/// family. Connecting a UDP socket does not send a packet; it only asks the
/// kernel to select the route and source address. The configured port is
/// preserved, including zero for an ephemeral real socket binding.
///
/// This is intentionally an outbound-only operation. A general SIP listener
/// bound to all interfaces still needs packet-info support to recover the
/// actual destination address for each received datagram.
///
/// # Errors
///
/// Rejects a wildcard destination and preserves probe bind, connect, and local
/// address discovery failures without disclosing either endpoint in display or
/// debug output.
pub fn resolve_outbound_udp_bind(
    configured: SocketAddr,
    destination: SocketAddr,
) -> Result<SocketAddr, OutboundBindError> {
    let configured = canonicalize(configured);
    if !configured.ip().is_unspecified() {
        return Ok(configured);
    }
    let destination = canonicalize(destination);
    if destination.ip().is_unspecified() || destination.port() == 0 {
        return Err(OutboundBindError::InvalidDestination);
    }
    let probe_address = SocketAddr::new(AddressFamily::of_socket(destination).unspecified_ip(), 0);
    let probe = UdpSocket::bind(probe_address).map_err(OutboundBindError::Bind)?;
    probe
        .connect(destination)
        .map_err(OutboundBindError::Connect)?;
    let selected = probe
        .local_addr()
        .map_err(OutboundBindError::LocalAddress)?;
    if selected.ip().is_unspecified() {
        return Err(OutboundBindError::UnspecifiedSelection);
    }
    Ok(SocketAddr::new(selected.ip(), configured.port()))
}

/// Failure to select a concrete outbound UDP source address.
pub enum OutboundBindError {
    /// The destination was not a concrete nonzero endpoint.
    InvalidDestination,
    /// The route-selection probe could not bind.
    Bind(io::Error),
    /// The kernel could not select a route to the destination.
    Connect(io::Error),
    /// The selected local address could not be queried.
    LocalAddress(io::Error),
    /// The kernel unexpectedly retained a wildcard local address.
    UnspecifiedSelection,
}

impl OutboundBindError {
    /// Returns a stable privacy-safe diagnostic class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::InvalidDestination => "invalid-destination",
            Self::Bind(_) => "probe-bind",
            Self::Connect(_) => "probe-connect",
            Self::LocalAddress(_) => "probe-local-address",
            Self::UnspecifiedSelection => "unspecified-selection",
        }
    }
}

impl fmt::Debug for OutboundBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundBindError")
            .field("class", &self.class())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for OutboundBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "outbound UDP bind error: {}", self.class())
    }
}

impl StdError for OutboundBindError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Bind(source) | Self::Connect(source) | Self::LocalAddress(source) => Some(source),
            Self::InvalidDestination | Self::UnspecifiedSelection => None,
        }
    }
}

fn canonicalize(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(value) => match value.ip().to_ipv4_mapped() {
            Some(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), value.port()),
            None => SocketAddr::V6(value),
        },
        SocketAddr::V4(_) => address,
    }
}

fn canonicalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(value) => value.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

    use super::{
        AddressFamily, BindAddress, BindAddressError, BindHost, BindPort, Endpoint, EndpointError,
        OutboundBindError, resolve_outbound_udp_bind,
    };

    #[test]
    fn concrete_endpoint_rejects_wildcard_and_zero_port() {
        assert_eq!(
            Endpoint::new(SocketAddr::from(([0, 0, 0, 0], 5060))),
            Err(EndpointError::UnspecifiedAddress)
        );
        assert_eq!(
            Endpoint::new(SocketAddr::from(([192, 0, 2, 10], 0))),
            Err(EndpointError::ZeroPort)
        );
    }

    #[test]
    fn mapped_ipv6_is_canonicalized_before_identity_and_hashing() {
        let ipv4 = Endpoint::new(SocketAddr::from(([192, 0, 2, 10], 5060)))
            .unwrap_or_else(|_| panic!("IPv4 endpoint"));
        let IpAddr::V4(ipv4_address) = ipv4.ip() else {
            panic!("expected IPv4");
        };
        let mapped = ipv4_address.to_ipv6_mapped();
        let mapped = Endpoint::new(SocketAddr::V6(SocketAddrV6::new(mapped, 5060, 0, 0)))
            .unwrap_or_else(|_| panic!("mapped endpoint"));
        assert_eq!(mapped, ipv4);
        assert_eq!(mapped.family(), AddressFamily::Ipv4);

        let mut identities = HashSet::new();
        identities.insert(ipv4);
        identities.insert(mapped);
        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn endpoint_host_and_family_comparisons_are_explicit() {
        let first = Endpoint::from_parts(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060)
            .unwrap_or_else(|_| panic!("first"));
        let second = Endpoint::from_parts(IpAddr::V4(Ipv4Addr::LOCALHOST), 5061)
            .unwrap_or_else(|_| panic!("second"));
        let ipv6 = Endpoint::from_parts(IpAddr::V6(Ipv6Addr::LOCALHOST), 5060)
            .unwrap_or_else(|_| panic!("IPv6"));
        assert!(first.same_host(second));
        assert!(first.same_family(second));
        assert!(!first.same_family(ipv6));
    }

    #[test]
    fn wildcard_and_ephemeral_binding_require_explicit_variants() {
        assert_eq!(
            BindHost::specific(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Err(BindAddressError::UnspecifiedSpecificAddress)
        );
        assert_eq!(BindPort::fixed(0), Err(BindAddressError::ZeroFixedPort));

        let bind = BindAddress::new(BindHost::any(AddressFamily::Ipv6), BindPort::Ephemeral);
        assert!(bind.is_wildcard());
        assert!(bind.is_ephemeral());
        assert_eq!(bind.socket_addr(), SocketAddr::from(([0_u16; 8], 0)));
    }

    #[test]
    fn fixed_specific_binding_preserves_explicit_selection() {
        let host =
            BindHost::specific(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap_or_else(|_| panic!("host"));
        let port = BindPort::fixed(5060).unwrap_or_else(|_| panic!("port"));
        let bind = BindAddress::new(host, port);
        assert!(!bind.is_wildcard());
        assert!(!bind.is_ephemeral());
        assert_eq!(bind.socket_addr(), SocketAddr::from(([127, 0, 0, 1], 5060)));
    }

    #[test]
    fn diagnostics_do_not_disclose_ip_addresses_or_ports() {
        let endpoint = Endpoint::new(SocketAddr::from(([203, 0, 113, 77], 45_678)))
            .unwrap_or_else(|_| panic!("endpoint"));
        let debug = format!("{endpoint:?}");
        assert!(!debug.contains("203"));
        assert!(!debug.contains("45678"));
        assert!(debug.contains("Ipv4"));

        let Err(error) = Endpoint::new(SocketAddr::from(([0, 0, 0, 0], 5060))) else {
            panic!("wildcard endpoint must fail");
        };
        let error = error.to_string();
        assert!(!error.contains("0.0.0.0"));
        assert!(!error.contains("5060"));
    }

    #[test]
    fn wildcard_outbound_bind_selects_a_concrete_route_address() {
        let selected = resolve_outbound_udp_bind(
            SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::from(([127, 0, 0, 1], 5060)),
        )
        .unwrap_or_else(|_| panic!("route selection"));
        assert_eq!(selected.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(selected.port(), 0);
    }

    #[test]
    fn outbound_bind_rejects_nonconcrete_destination_privately() {
        let Err(error) = resolve_outbound_udp_bind(
            SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::from(([0, 0, 0, 0], 5060)),
        ) else {
            panic!("wildcard destination must fail");
        };
        assert!(matches!(error, OutboundBindError::InvalidDestination));
        assert!(!format!("{error:?}").contains("5060"));
    }
}
