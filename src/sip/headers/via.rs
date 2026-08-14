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

//! SIP `Via` header.
//!
//! This module provides the strongly typed representation and parser for SIP
//! `Via` field values.
//!
//! One field value can contain multiple comma-separated Via entries. Each
//! entry contains a sent protocol, sent-by host and optional port, followed by
//! zero or more parameters.
//!
//! Standard `SIP/2.0` protocol components and standard SIP transports use
//! allocation-free enum variants. Extension protocol tokens and parameter
//! values are retained only after successful validation.
//!
//! Parameter order is preserved. Known Via parameters receive dedicated typed
//! representations while unknown valid extension parameters remain available
//! to higher protocol layers.
//!
//! Transaction-level requirements such as requiring an RFC 3261 branch magic
//! cookie on generated requests belong to SIP transaction and message
//! validation rather than this standalone field-value parser.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::sip::types::uri::Host;

/// Maximum accepted SIP `Via` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_VIA_BYTES: usize = 8 * 1024;

/// Maximum number of comma-separated entries accepted in one `Via` field.
pub const MAX_VIA_ENTRIES: usize = 64;

/// Maximum number of parameters accepted on one Via entry.
pub const MAX_VIA_PARAMETERS: usize = 64;

/// Maximum accepted sent-protocol token size in bytes.
pub const MAX_VIA_PROTOCOL_TOKEN_BYTES: usize = 64;

/// Maximum accepted Via branch size in bytes.
pub const MAX_VIA_BRANCH_BYTES: usize = 256;

/// Maximum accepted extension parameter-name size in bytes.
pub const MAX_VIA_PARAMETER_NAME_BYTES: usize = 256;

/// Maximum accepted extension parameter-value size in bytes.
pub const MAX_VIA_PARAMETER_VALUE_BYTES: usize = 1024;

/// RFC 3261 branch magic cookie.
pub const RFC3261_BRANCH_MAGIC_COOKIE: &str = "z9hG4bK";

/// A complete SIP `Via` field value.
///
/// Entries are retained in wire order. The first entry is the topmost Via hop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Via {
    entries: Vec<ViaEntry>,
}

impl Via {
    /// Creates a `Via` value containing one entry.
    #[must_use]
    pub fn new(entry: ViaEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }

    /// Creates a `Via` value from a non-empty entry vector.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Empty`] when no entries are supplied or
    /// [`ParseError::TooManyEntries`] when the configured entry bound is
    /// exceeded.
    pub fn from_entries(entries: Vec<ViaEntry>) -> Result<Self, ParseError> {
        if entries.is_empty() {
            return Err(ParseError::Empty);
        }

        if entries.len() > MAX_VIA_ENTRIES {
            return Err(ParseError::TooManyEntries {
                maximum: MAX_VIA_ENTRIES,
            });
        }

        Ok(Self { entries })
    }

    /// Parses a SIP `Via` field value from wire bytes.
    ///
    /// Header-name and `HCOLON` parsing are outside this function. The input is
    /// the field value only.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when any Via entry, protocol component, sent-by
    /// address, port, parameter, or operational bound is invalid.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns all Via entries in wire order.
    #[must_use]
    pub fn entries(&self) -> &[ViaEntry] {
        &self.entries
    }

    /// Returns mutable access to all Via entries.
    #[must_use]
    pub fn entries_mut(&mut self) -> &mut [ViaEntry] {
        &mut self.entries
    }

    /// Returns the topmost Via entry.
    #[must_use]
    pub fn first(&self) -> &ViaEntry {
        &self.entries[0]
    }

    /// Returns mutable access to the topmost Via entry.
    #[must_use]
    pub fn first_mut(&mut self) -> &mut ViaEntry {
        &mut self.entries[0]
    }

    /// Returns the topmost branch parameter when present.
    #[must_use]
    pub fn branch(&self) -> Option<&str> {
        self.first().branch()
    }

    /// Returns the number of Via entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the Via list contains no entries.
    ///
    /// A successfully constructed [`Via`] is never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds another Via entry.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyEntries`] when the bounded capacity has
    /// been reached.
    pub fn push_entry(&mut self, entry: ViaEntry) -> Result<(), ParseError> {
        if self.entries.len() >= MAX_VIA_ENTRIES {
            return Err(ParseError::TooManyEntries {
                maximum: MAX_VIA_ENTRIES,
            });
        }

        self.entries.push(entry);
        Ok(())
    }

    /// Consumes the value into its ordered Via entries.
    #[must_use]
    pub fn into_entries(self) -> Vec<ViaEntry> {
        self.entries
    }
}

impl fmt::Display for Via {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, entry) in self.entries.iter().enumerate() {
            if index != 0 {
                formatter.write_str(", ")?;
            }

            write!(formatter, "{entry}")?;
        }

        Ok(())
    }
}

impl FromStr for Via {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// One SIP Via hop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViaEntry {
    sent_protocol: SentProtocol,
    sent_by_host: Host,
    sent_by_port: Option<u16>,
    parameters: Vec<ViaParameter>,
}

impl ViaEntry {
    /// Creates a Via entry without parameters.
    #[must_use]
    pub fn new(sent_protocol: SentProtocol, sent_by_host: Host, sent_by_port: Option<u16>) -> Self {
        Self {
            sent_protocol,
            sent_by_host,
            sent_by_port,
            parameters: Vec::new(),
        }
    }

    /// Returns the sent protocol.
    #[must_use]
    pub const fn sent_protocol(&self) -> &SentProtocol {
        &self.sent_protocol
    }

    /// Returns the sent-by host.
    #[must_use]
    pub const fn sent_by_host(&self) -> &Host {
        &self.sent_by_host
    }

    /// Returns the optional sent-by port.
    #[must_use]
    pub const fn sent_by_port(&self) -> Option<u16> {
        self.sent_by_port
    }

    /// Replaces the sent-by host.
    pub fn set_sent_by_host(&mut self, host: Host) {
        self.sent_by_host = host;
    }

    /// Replaces the optional sent-by port.
    pub fn set_sent_by_port(&mut self, port: Option<u16>) {
        self.sent_by_port = port;
    }

    /// Returns all Via parameters in wire order.
    #[must_use]
    pub fn parameters(&self) -> &[ViaParameter] {
        &self.parameters
    }

    /// Returns the branch parameter when present.
    #[must_use]
    pub fn branch(&self) -> Option<&str> {
        self.parameters
            .iter()
            .find_map(|parameter| match parameter {
                ViaParameter::Branch(value) => Some(value.as_ref()),
                _ => None,
            })
    }

    /// Returns whether the branch begins with the RFC 3261 magic cookie.
    #[must_use]
    pub fn has_rfc3261_branch_cookie(&self) -> bool {
        self.branch()
            .is_some_and(|branch| branch.starts_with(RFC3261_BRANCH_MAGIC_COOKIE))
    }

    /// Returns the `received` parameter when present.
    #[must_use]
    pub fn received(&self) -> Option<IpAddr> {
        self.parameters
            .iter()
            .find_map(|parameter| match parameter {
                ViaParameter::Received(address) => Some(*address),
                _ => None,
            })
    }

    /// Returns the `rport` parameter when present.
    #[must_use]
    pub fn rport(&self) -> Option<RPort> {
        self.parameters
            .iter()
            .find_map(|parameter| match parameter {
                ViaParameter::RPort(value) => Some(*value),
                _ => None,
            })
    }

    /// Returns the `maddr` parameter when present.
    #[must_use]
    pub fn maddr(&self) -> Option<&Host> {
        self.parameters
            .iter()
            .find_map(|parameter| match parameter {
                ViaParameter::Maddr(host) => Some(host),
                _ => None,
            })
    }

    /// Returns the multicast TTL when present.
    #[must_use]
    pub fn ttl(&self) -> Option<u8> {
        self.parameters
            .iter()
            .find_map(|parameter| match parameter {
                ViaParameter::Ttl(value) => Some(*value),
                _ => None,
            })
    }

    /// Returns the first extension parameter with the requested
    /// case-insensitive name.
    #[must_use]
    pub fn extension_parameter(&self, name: &str) -> Option<&ViaExtensionParameter> {
        self.parameters
            .iter()
            .find_map(|parameter| match parameter {
                ViaParameter::Extension(extension)
                    if extension.name().eq_ignore_ascii_case(name) =>
                {
                    Some(extension)
                }
                _ => None,
            })
    }

    /// Adds a Via parameter.
    ///
    /// Parameter names are unique case-insensitively.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::DuplicateParameter`] when the parameter already
    /// exists or [`ParseError::TooManyParameters`] when the bounded parameter
    /// capacity has been reached.
    pub fn push_parameter(&mut self, parameter: ViaParameter) -> Result<(), ParseError> {
        if self.parameters.len() >= MAX_VIA_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_VIA_PARAMETERS,
            });
        }

        let name = parameter.name();

        if self
            .parameters
            .iter()
            .any(|existing| existing.name().eq_ignore_ascii_case(name))
        {
            return Err(ParseError::DuplicateParameter);
        }

        self.parameters.push(parameter);
        Ok(())
    }

    /// Returns the number of Via parameters.
    #[must_use]
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Consumes the entry into its components.
    #[must_use]
    pub fn into_parts(self) -> (SentProtocol, Host, Option<u16>, Vec<ViaParameter>) {
        (
            self.sent_protocol,
            self.sent_by_host,
            self.sent_by_port,
            self.parameters,
        )
    }
}

impl fmt::Display for ViaEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.sent_protocol, self.sent_by_host)?;

        if let Some(port) = self.sent_by_port {
            write!(formatter, ":{port}")?;
        }

        for parameter in &self.parameters {
            write!(formatter, ";{parameter}")?;
        }

        Ok(())
    }
}

/// A SIP Via sent protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentProtocol {
    name: ProtocolName,
    version: ProtocolVersion,
    transport: ViaTransport,
}

impl SentProtocol {
    /// Creates a sent protocol from validated protocol components.
    #[must_use]
    pub const fn from_parts(
        name: ProtocolName,
        version: ProtocolVersion,
        transport: ViaTransport,
    ) -> Self {
        Self {
            name,
            version,
            transport,
        }
    }

    /// Creates the standard `SIP/2.0` sent protocol for a transport.
    #[must_use]
    pub const fn sip_2_0(transport: ViaTransport) -> Self {
        Self {
            name: ProtocolName::Sip,
            version: ProtocolVersion::Sip2,
            transport,
        }
    }

    /// Creates a sent protocol from textual components.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when any component violates the SIP token grammar
    /// or exceeds the configured component bound.
    pub fn new(name: &str, version: &str, transport: &str) -> Result<Self, ParseError> {
        Ok(Self {
            name: ProtocolName::from_bytes(name.as_bytes())?,
            version: ProtocolVersion::from_bytes(version.as_bytes())?,
            transport: ViaTransport::from_bytes(transport.as_bytes())?,
        })
    }

    /// Returns the protocol name.
    #[must_use]
    pub const fn name(&self) -> &ProtocolName {
        &self.name
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(&self) -> &ProtocolVersion {
        &self.version
    }

    /// Returns the transport.
    #[must_use]
    pub const fn transport(&self) -> &ViaTransport {
        &self.transport
    }

    /// Returns whether this is the standard SIP protocol/version pair.
    #[must_use]
    pub const fn is_sip_2_0(&self) -> bool {
        matches!(self.name, ProtocolName::Sip) && matches!(self.version, ProtocolVersion::Sip2)
    }
}

impl fmt::Display for SentProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}/{}/{}",
            self.name, self.version, self.transport
        )
    }
}

/// Via protocol name.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProtocolName {
    /// Standard `SIP`.
    Sip,

    /// Valid extension protocol name.
    Extension(Box<str>),
}

impl ProtocolName {
    /// Parses a Via protocol name.
    ///
    /// `SIP` is recognized case-insensitively and normalized to the
    /// allocation-free standard variant.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] for an empty, oversized, or invalid token.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        validate_protocol_token(input, ProtocolComponent::Name)?;

        if input.eq_ignore_ascii_case(b"SIP") {
            return Ok(Self::Sip);
        }

        let value = std::str::from_utf8(input).map_err(|_| ParseError::InvalidProtocolName {
            index: 0,
            byte: input[0],
        })?;

        Ok(Self::Extension(value.into()))
    }

    /// Returns the canonical textual value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sip => "SIP",
            Self::Extension(value) => value,
        }
    }
}

impl fmt::Display for ProtocolName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Via protocol version.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProtocolVersion {
    /// Standard SIP version `2.0`.
    Sip2,

    /// Valid extension protocol version.
    Extension(Box<str>),
}

impl ProtocolVersion {
    /// Parses a Via protocol version.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] for an empty, oversized, or invalid token.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        validate_protocol_token(input, ProtocolComponent::Version)?;

        if input == b"2.0" {
            return Ok(Self::Sip2);
        }

        let value = std::str::from_utf8(input).map_err(|_| ParseError::InvalidProtocolVersion {
            index: 0,
            byte: input[0],
        })?;

        Ok(Self::Extension(value.into()))
    }

    /// Returns the textual version value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sip2 => "2.0",
            Self::Extension(value) => value,
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// SIP Via transport token.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ViaTransport {
    /// UDP transport.
    Udp,

    /// TCP transport.
    Tcp,

    /// TLS transport.
    Tls,

    /// SCTP transport.
    Sctp,

    /// Valid extension transport token.
    Extension(Box<str>),
}

impl ViaTransport {
    /// Parses a Via transport token.
    ///
    /// Standard transport names are recognized case-insensitively and
    /// normalized to allocation-free variants.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] for an empty, oversized, or invalid token.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        validate_protocol_token(input, ProtocolComponent::Transport)?;

        if input.eq_ignore_ascii_case(b"UDP") {
            Ok(Self::Udp)
        } else if input.eq_ignore_ascii_case(b"TCP") {
            Ok(Self::Tcp)
        } else if input.eq_ignore_ascii_case(b"TLS") {
            Ok(Self::Tls)
        } else if input.eq_ignore_ascii_case(b"SCTP") {
            Ok(Self::Sctp)
        } else {
            let value = std::str::from_utf8(input).map_err(|_| ParseError::InvalidTransport {
                index: 0,
                byte: input[0],
            })?;

            Ok(Self::Extension(value.into()))
        }
    }

    /// Returns the canonical transport token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
            Self::Sctp => "SCTP",
            Self::Extension(value) => value,
        }
    }

    /// Returns whether this is UDP.
    #[must_use]
    pub const fn is_udp(&self) -> bool {
        matches!(self, Self::Udp)
    }
}

impl fmt::Display for ViaTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A typed Via parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ViaParameter {
    /// Transaction branch identifier.
    Branch(Box<str>),

    /// Source IP address observed by a receiver.
    Received(IpAddr),

    /// RFC 3581 response-port parameter.
    RPort(RPort),

    /// Multicast address.
    Maddr(Host),

    /// Multicast time-to-live.
    Ttl(u8),

    /// Generic extension parameter.
    Extension(ViaExtensionParameter),
}

impl ViaParameter {
    /// Creates a validated branch parameter.
    ///
    /// This validates the token grammar but deliberately does not require the
    /// RFC 3261 magic cookie. That requirement depends on transaction context.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the branch is empty, oversized, or not a
    /// valid SIP token.
    pub fn branch(value: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let value = value.into();
        validate_branch(value.as_bytes())?;

        Ok(Self::Branch(value))
    }

    /// Returns the case-insensitive Via parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Branch(_) => "branch",
            Self::Received(_) => "received",
            Self::RPort(_) => "rport",
            Self::Maddr(_) => "maddr",
            Self::Ttl(_) => "ttl",
            Self::Extension(parameter) => parameter.name(),
        }
    }
}

impl fmt::Display for ViaParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Branch(value) => write!(formatter, "branch={value}"),
            Self::Received(address) => write!(formatter, "received={address}"),
            Self::RPort(RPort::Requested) => formatter.write_str("rport"),
            Self::RPort(RPort::Value(port)) => write!(formatter, "rport={port}"),
            Self::Maddr(host) => write!(formatter, "maddr={host}"),
            Self::Ttl(ttl) => write!(formatter, "ttl={ttl}"),
            Self::Extension(parameter) => fmt::Display::fmt(parameter, formatter),
        }
    }
}

/// RFC 3581 `rport` state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RPort {
    /// Valueless `rport` request.
    Requested,

    /// Response port supplied as `rport=<port>`.
    Value(u16),
}

/// A validated generic Via extension parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViaExtensionParameter {
    name: Box<str>,
    value: Option<ViaExtensionValue>,
}

impl ViaExtensionParameter {
    /// Creates a valueless extension parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name is invalid, reserved, or exceeds
    /// its operational limit.
    pub fn flag(name: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let name = name.into();
        validate_extension_name(name.as_bytes())?;

        Ok(Self { name, value: None })
    }

    /// Creates an extension parameter containing an unquoted SIP token.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or value is invalid or exceeds an
    /// operational bound.
    pub fn token(
        name: impl Into<Box<str>>,
        value: impl Into<Box<str>>,
    ) -> Result<Self, ParseError> {
        let name = name.into();
        let value = value.into();

        validate_extension_name(name.as_bytes())?;
        validate_extension_token_value(value.as_bytes())?;

        Ok(Self {
            name,
            value: Some(ViaExtensionValue::Token(value)),
        })
    }

    /// Creates an extension parameter containing a host value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name is invalid or reserved.
    pub fn host(name: impl Into<Box<str>>, host: Host) -> Result<Self, ParseError> {
        let name = name.into();
        validate_extension_name(name.as_bytes())?;

        Ok(Self {
            name,
            value: Some(ViaExtensionValue::Host(host)),
        })
    }

    /// Creates an extension parameter containing a logical quoted-string
    /// value without surrounding quotation marks.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or value is invalid or exceeds an
    /// operational bound.
    pub fn quoted(
        name: impl Into<Box<str>>,
        value: impl Into<Box<str>>,
    ) -> Result<Self, ParseError> {
        let name = name.into();
        let value = value.into();

        validate_extension_name(name.as_bytes())?;
        validate_quoted_extension_value(value.as_bytes())?;

        Ok(Self {
            name,
            value: Some(ViaExtensionValue::Quoted(value)),
        })
    }

    /// Returns the parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional typed extension value.
    #[must_use]
    pub const fn value(&self) -> Option<&ViaExtensionValue> {
        self.value.as_ref()
    }

    /// Returns whether this is a valueless extension parameter.
    #[must_use]
    pub const fn is_flag(&self) -> bool {
        self.value.is_none()
    }
}

impl fmt::Display for ViaExtensionParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)?;

        let Some(value) = &self.value else {
            return Ok(());
        };

        formatter.write_char('=')?;
        fmt::Display::fmt(value, formatter)
    }
}

/// Typed generic Via extension value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ViaExtensionValue {
    /// SIP token value.
    Token(Box<str>),

    /// SIP host value.
    Host(Host),

    /// Logical quoted-string value.
    Quoted(Box<str>),
}

impl ViaExtensionValue {
    /// Returns the logical textual value.
    ///
    /// Host values do not return a borrowed string because IP addresses are
    /// stored structurally.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Token(value) | Self::Quoted(value) => Some(value),
            Self::Host(_) => None,
        }
    }

    /// Returns whether this value uses quoted-string serialization.
    #[must_use]
    pub const fn is_quoted(&self) -> bool {
        matches!(self, Self::Quoted(_))
    }
}

impl fmt::Display for ViaExtensionValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(value) => formatter.write_str(value),
            Self::Host(host) => fmt::Display::fmt(host, formatter),
            Self::Quoted(value) => {
                formatter.write_char('"')?;

                for character in value.chars() {
                    match character {
                        '"' => formatter.write_str("\\\"")?,
                        '\\' => formatter.write_str("\\\\")?,
                        _ => formatter.write_char(character)?,
                    }
                }

                formatter.write_char('"')
            }
        }
    }
}

/// Failure returned by the crate-internal aggregate-budget parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BudgetedParseError {
    /// The field violated normal Via grammar or a field-local limit.
    Parse(ParseError),

    /// Parsing the next entry would exceed the caller's remaining entry
    /// capacity.
    EntryBudgetExceeded {
        /// Entry count that the current field attempted to reach.
        attempted: usize,

        /// Entry capacity supplied by the caller for the current field.
        maximum: usize,
    },

    /// Parsing the next parameter would exceed the caller's remaining total
    /// parameter capacity.
    TotalParameterBudgetExceeded {
        /// Parameter count that the current field attempted to reach.
        attempted: usize,

        /// Total parameter capacity supplied by the caller for the field.
        maximum: usize,
    },
}

impl From<ParseError> for BudgetedParseError {
    fn from(source: ParseError) -> Self {
        Self::Parse(source)
    }
}

#[derive(Clone, Copy, Debug)]
struct ParseBudget {
    remaining_entries: usize,
    remaining_parameters: usize,
    parsed_parameters: usize,
}

impl ParseBudget {
    const fn new(remaining_entries: usize, remaining_parameters: usize) -> Self {
        Self {
            remaining_entries,
            remaining_parameters,
            parsed_parameters: 0,
        }
    }

    fn check_entry(self, existing_entries: usize) -> Result<(), BudgetedParseError> {
        let attempted = existing_entries.saturating_add(1);

        if attempted > self.remaining_entries {
            return Err(BudgetedParseError::EntryBudgetExceeded {
                attempted,
                maximum: self.remaining_entries,
            });
        }

        Ok(())
    }

    fn consume_parameter(&mut self) -> Result<(), BudgetedParseError> {
        let attempted = self.parsed_parameters.saturating_add(1);

        if attempted > self.remaining_parameters {
            return Err(BudgetedParseError::TotalParameterBudgetExceeded {
                attempted,
                maximum: self.remaining_parameters,
            });
        }

        self.parsed_parameters = attempted;
        Ok(())
    }
}

/// Parses a SIP `Via` field value.
///
/// # Errors
///
/// Returns [`ParseError`] when the field value violates Via syntax or an
/// operational bound.
pub fn parse(input: &[u8]) -> Result<Via, ParseError> {
    parse_with_budget(input, usize::MAX, usize::MAX).map_err(|error| match error {
        BudgetedParseError::Parse(source) => source,
        BudgetedParseError::EntryBudgetExceeded { .. } => ParseError::TooManyEntries {
            maximum: MAX_VIA_ENTRIES,
        },
        BudgetedParseError::TotalParameterBudgetExceeded { .. } => ParseError::TooManyParameters {
            maximum: MAX_VIA_PARAMETERS,
        },
    })
}

/// Parses one Via field while enforcing caller-supplied remaining budgets.
///
/// `remaining_entries` and `remaining_parameters` are the capacities left in
/// the enclosing message before this field is parsed. The parser checks each
/// budget before parsing or allocating the entry or parameter that would
/// exceed it. Field-local limits such as [`MAX_VIA_ENTRIES`] and
/// [`MAX_VIA_PARAMETERS`] remain independently enforced as normal
/// [`ParseError`] values.
///
/// This API is crate-visible because message validation owns aggregate limits;
/// standalone users continue to use [`parse`] or [`Via::from_bytes`].
pub(crate) fn parse_with_budget(
    input: &[u8],
    remaining_entries: usize,
    remaining_parameters: usize,
) -> Result<Via, BudgetedParseError> {
    if input.len() > MAX_VIA_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_VIA_BYTES,
        }
        .into());
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::Empty.into());
    }

    let mut entries = Vec::new();
    let mut budget = ParseBudget::new(remaining_entries, remaining_parameters);
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;

    for (index, byte) in input.iter().copied().enumerate() {
        if in_quotes {
            if escaped {
                if matches!(byte, b'\r' | b'\n') {
                    return Err(ParseError::InvalidQuotedString.into());
                }

                escaped = false;
                continue;
            }

            match byte {
                b'\\' => escaped = true,
                b'"' => in_quotes = false,
                b'\r' | b'\n' => return Err(ParseError::InvalidQuotedString.into()),
                _ => {}
            }

            continue;
        }

        match byte {
            b'"' => in_quotes = true,
            b',' => {
                push_parsed_entry(&mut entries, &input[start..index], &mut budget)?;
                start = index + 1;
            }
            _ => {}
        }
    }

    if in_quotes || escaped {
        return Err(ParseError::InvalidQuotedString.into());
    }

    push_parsed_entry(&mut entries, &input[start..], &mut budget)?;

    Via::from_entries(entries).map_err(BudgetedParseError::Parse)
}

fn push_parsed_entry(
    entries: &mut Vec<ViaEntry>,
    input: &[u8],
    budget: &mut ParseBudget,
) -> Result<(), BudgetedParseError> {
    if entries.len() >= MAX_VIA_ENTRIES {
        return Err(ParseError::TooManyEntries {
            maximum: MAX_VIA_ENTRIES,
        }
        .into());
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::EmptyEntry.into());
    }

    budget.check_entry(entries.len())?;
    entries.push(parse_entry(input, budget)?);
    Ok(())
}

fn parse_entry(input: &[u8], budget: &mut ParseBudget) -> Result<ViaEntry, BudgetedParseError> {
    let Some(protocol_end) = input.iter().position(|byte| is_lws(*byte)) else {
        return Err(ParseError::MissingSentBy.into());
    };

    if protocol_end == 0 {
        return Err(ParseError::MissingSentProtocol.into());
    }

    let sent_protocol = parse_sent_protocol(&input[..protocol_end])?;
    let remaining = trim_lws_start(&input[protocol_end..]);

    if remaining.is_empty() {
        return Err(ParseError::MissingSentBy.into());
    }

    let parameter_start = remaining.iter().position(|byte| *byte == b';');
    let sent_by_end = parameter_start.unwrap_or(remaining.len());

    let sent_by = trim_lws(&remaining[..sent_by_end]);

    if sent_by.is_empty() {
        return Err(ParseError::MissingSentBy.into());
    }

    let (host, port) = parse_sent_by(sent_by)?;
    let mut entry = ViaEntry::new(sent_protocol, host, port);

    if let Some(parameter_start) = parameter_start {
        parse_parameters(&mut entry, &remaining[parameter_start..], budget)?;
    }

    Ok(entry)
}

fn parse_sent_protocol(input: &[u8]) -> Result<SentProtocol, ParseError> {
    let Some(first_slash) = input.iter().position(|byte| *byte == b'/') else {
        return Err(ParseError::InvalidSentProtocol);
    };

    let Some(relative_second_slash) = input[first_slash + 1..]
        .iter()
        .position(|byte| *byte == b'/')
    else {
        return Err(ParseError::InvalidSentProtocol);
    };

    let second_slash = first_slash + 1 + relative_second_slash;

    if input[second_slash + 1..].contains(&b'/') {
        return Err(ParseError::InvalidSentProtocol);
    }

    let name = ProtocolName::from_bytes(&input[..first_slash])?;
    let version = ProtocolVersion::from_bytes(&input[first_slash + 1..second_slash])?;
    let transport = ViaTransport::from_bytes(&input[second_slash + 1..])?;

    Ok(SentProtocol::from_parts(name, version, transport))
}

fn parse_sent_by(input: &[u8]) -> Result<(Host, Option<u16>), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingSentBy);
    }

    if input[0] == b'[' {
        return parse_ipv6_sent_by(input);
    }

    if input.contains(&b'[') || input.contains(&b']') {
        return Err(ParseError::InvalidSentByHost);
    }

    let (host_input, port) = match input.iter().position(|byte| *byte == b':') {
        Some(colon) => {
            let host = &input[..colon];
            let port = &input[colon + 1..];

            if port.contains(&b':') {
                return Err(ParseError::InvalidSentByHost);
            }

            (host, Some(parse_port(port)?))
        }
        None => (input, None),
    };

    let host = parse_host(host_input).map_err(|()| ParseError::InvalidSentByHost)?;

    Ok((host, port))
}

fn parse_ipv6_sent_by(input: &[u8]) -> Result<(Host, Option<u16>), ParseError> {
    let Some(close) = input.iter().position(|byte| *byte == b']') else {
        return Err(ParseError::InvalidSentByHost);
    };

    if close <= 1 {
        return Err(ParseError::InvalidSentByHost);
    }

    let address = std::str::from_utf8(&input[1..close])
        .map_err(|_| ParseError::InvalidSentByHost)?
        .parse::<Ipv6Addr>()
        .map_err(|_| ParseError::InvalidSentByHost)?;

    let suffix = &input[close + 1..];

    let port = if suffix.is_empty() {
        None
    } else {
        if suffix[0] != b':' {
            return Err(ParseError::InvalidSentByHost);
        }

        Some(parse_port(&suffix[1..])?)
    };

    Ok((Host::from(address), port))
}

fn parse_host(input: &[u8]) -> Result<Host, ()> {
    if input.is_empty() {
        return Err(());
    }

    if input.first() == Some(&b'[') {
        if input.last() != Some(&b']') || input.len() < 3 {
            return Err(());
        }

        let address = std::str::from_utf8(&input[1..input.len() - 1])
            .map_err(|_| ())?
            .parse::<Ipv6Addr>()
            .map_err(|_| ())?;

        return Ok(Host::from(address));
    }

    let host = std::str::from_utf8(input).map_err(|_| ())?;

    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return Ok(Host::from(address));
    }

    Host::domain(host).map_err(|_| ())
}

fn parse_port(input: &[u8]) -> Result<u16, ParseError> {
    if input.is_empty() {
        return Err(ParseError::InvalidPort);
    }

    let mut value = 0_u32;

    for byte in input.iter().copied() {
        if !byte.is_ascii_digit() {
            return Err(ParseError::InvalidPort);
        }

        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u32::from(byte - b'0')))
            .ok_or(ParseError::PortOutOfRange)?;

        if value > u32::from(u16::MAX) {
            return Err(ParseError::PortOutOfRange);
        }
    }

    u16::try_from(value).map_err(|_| ParseError::PortOutOfRange)
}

fn parse_parameters(
    entry: &mut ViaEntry,
    mut input: &[u8],
    budget: &mut ParseBudget,
) -> Result<(), BudgetedParseError> {
    loop {
        input = trim_lws_start(input);

        if input.is_empty() {
            return Ok(());
        }

        if input[0] != b';' {
            return Err(ParseError::UnexpectedTrailingData.into());
        }

        input = trim_lws_start(&input[1..]);

        if input.is_empty() {
            return Err(ParseError::EmptyParameter.into());
        }

        if entry.parameter_count() >= MAX_VIA_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_VIA_PARAMETERS,
            }
            .into());
        }

        budget.consume_parameter()?;

        let (name, remaining) = parse_parameter_name(input)?;
        input = trim_lws_start(remaining);

        let (parameter, remaining) = parse_parameter(name, input)?;
        entry.push_parameter(parameter)?;
        input = remaining;
    }
}

fn parse_parameter_name(input: &[u8]) -> Result<(&str, &[u8]), ParseError> {
    let mut end = 0;

    while end < input.len() && is_token_byte(input[end]) {
        end += 1;
    }

    if end == 0 {
        return Err(ParseError::InvalidParameterName {
            index: 0,
            byte: input[0],
        });
    }

    if end > MAX_VIA_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: end,
            maximum: MAX_VIA_PARAMETER_NAME_BYTES,
        });
    }

    let name =
        std::str::from_utf8(&input[..end]).map_err(|_| ParseError::InvalidParameterName {
            index: 0,
            byte: input[0],
        })?;

    Ok((name, &input[end..]))
}

fn parse_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(ViaParameter, &'a [u8]), ParseError> {
    if name.eq_ignore_ascii_case("branch") {
        return parse_branch_parameter(input);
    }

    if name.eq_ignore_ascii_case("received") {
        return parse_received_parameter(input);
    }

    if name.eq_ignore_ascii_case("rport") {
        return parse_rport_parameter(input);
    }

    if name.eq_ignore_ascii_case("maddr") {
        return parse_maddr_parameter(input);
    }

    if name.eq_ignore_ascii_case("ttl") {
        return parse_ttl_parameter(input);
    }

    parse_extension_parameter(name, input)
}

fn parse_branch_parameter(input: &[u8]) -> Result<(ViaParameter, &[u8]), ParseError> {
    let value = require_parameter_value(input)?;
    let (value, remaining) = take_unquoted_value(value)?;

    validate_branch(value)?;

    let branch = std::str::from_utf8(value)
        .map_err(|_| ParseError::InvalidBranch {
            index: 0,
            byte: value[0],
        })?
        .into();

    Ok((ViaParameter::Branch(branch), remaining))
}

fn parse_received_parameter(input: &[u8]) -> Result<(ViaParameter, &[u8]), ParseError> {
    let value = require_parameter_value(input)?;
    let (value, remaining) = take_unquoted_value(value)?;

    let value = std::str::from_utf8(value).map_err(|_| ParseError::InvalidReceived)?;
    let address = value
        .parse::<IpAddr>()
        .map_err(|_| ParseError::InvalidReceived)?;

    Ok((ViaParameter::Received(address), remaining))
}

fn parse_rport_parameter(input: &[u8]) -> Result<(ViaParameter, &[u8]), ParseError> {
    let input = trim_lws_start(input);

    if input.is_empty() || input[0] == b';' {
        return Ok((ViaParameter::RPort(RPort::Requested), input));
    }

    if input[0] != b'=' {
        return Err(ParseError::InvalidParameterSeparator { byte: input[0] });
    }

    let value = trim_lws_start(&input[1..]);

    if value.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    let (value, remaining) = take_unquoted_value(value)?;
    let port = parse_port(value).map_err(|_| ParseError::InvalidRPort)?;

    Ok((ViaParameter::RPort(RPort::Value(port)), remaining))
}

fn parse_maddr_parameter(input: &[u8]) -> Result<(ViaParameter, &[u8]), ParseError> {
    let value = require_parameter_value(input)?;
    let (value, remaining) = take_unquoted_value(value)?;
    let host = parse_host(value).map_err(|()| ParseError::InvalidMaddr)?;

    Ok((ViaParameter::Maddr(host), remaining))
}

fn parse_ttl_parameter(input: &[u8]) -> Result<(ViaParameter, &[u8]), ParseError> {
    let value = require_parameter_value(input)?;
    let (value, remaining) = take_unquoted_value(value)?;
    let ttl = parse_ttl(value)?;

    Ok((ViaParameter::Ttl(ttl), remaining))
}

fn parse_extension_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(ViaParameter, &'a [u8]), ParseError> {
    validate_extension_name(name.as_bytes())?;

    let input = trim_lws_start(input);

    if input.is_empty() || input[0] == b';' {
        let parameter = ViaExtensionParameter::flag(name)?;

        return Ok((ViaParameter::Extension(parameter), input));
    }

    if input[0] != b'=' {
        return Err(ParseError::InvalidParameterSeparator { byte: input[0] });
    }

    let input = trim_lws_start(&input[1..]);

    if input.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    if input[0] == b'"' {
        let (value, consumed) = parse_quoted_value(input)?;
        let remaining = trim_lws_start(&input[consumed..]);

        if !remaining.is_empty() && remaining[0] != b';' {
            return Err(ParseError::UnexpectedTrailingData);
        }

        let parameter = ViaExtensionParameter::quoted(name, value)?;

        return Ok((ViaParameter::Extension(parameter), remaining));
    }

    let (value, remaining) = take_unquoted_value(input)?;

    if value.iter().copied().all(is_token_byte) {
        let value = std::str::from_utf8(value).map_err(|_| ParseError::InvalidExtensionValue {
            index: 0,
            byte: value[0],
        })?;

        let parameter = ViaExtensionParameter::token(name, value)?;

        return Ok((ViaParameter::Extension(parameter), remaining));
    }

    if let Ok(host) = parse_host(value) {
        let parameter = ViaExtensionParameter::host(name, host)?;

        return Ok((ViaParameter::Extension(parameter), remaining));
    }

    let (index, byte) = value
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| !is_token_byte(*byte))
        .unwrap_or((0, value[0]));

    Err(ParseError::InvalidExtensionValue { index, byte })
}

fn require_parameter_value(input: &[u8]) -> Result<&[u8], ParseError> {
    let input = trim_lws_start(input);

    if input.first() != Some(&b'=') {
        return Err(ParseError::MissingParameterValue);
    }

    let value = trim_lws_start(&input[1..]);

    if value.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    Ok(value)
}

fn take_unquoted_value(input: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let end = input
        .iter()
        .position(|byte| *byte == b';')
        .unwrap_or(input.len());

    let value = trim_lws(&input[..end]);

    if value.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    Ok((value, &input[end..]))
}

fn parse_quoted_value(input: &[u8]) -> Result<(String, usize), ParseError> {
    if input.first() != Some(&b'"') {
        return Err(ParseError::InvalidQuotedString);
    }

    let mut decoded = Vec::with_capacity(input.len().saturating_sub(2));
    let mut index = 1;

    while index < input.len() {
        let byte = input[index];

        match byte {
            b'"' => {
                let value =
                    String::from_utf8(decoded).map_err(|_| ParseError::InvalidQuotedString)?;

                return Ok((value, index + 1));
            }
            b'\\' => {
                let Some(escaped) = input.get(index + 1).copied() else {
                    return Err(ParseError::InvalidQuotedString);
                };

                if matches!(escaped, b'\r' | b'\n') || escaped.is_ascii_control() {
                    return Err(ParseError::InvalidQuotedString);
                }

                decoded.push(escaped);
                index += 2;
            }
            b'\t' => {
                decoded.push(b' ');
                index += 1;
            }
            b'\r' | b'\n' => return Err(ParseError::InvalidQuotedString),
            byte if byte.is_ascii_control() => return Err(ParseError::InvalidQuotedString),
            _ => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    Err(ParseError::InvalidQuotedString)
}

fn parse_ttl(input: &[u8]) -> Result<u8, ParseError> {
    if input.is_empty() || input.len() > 3 {
        return Err(ParseError::InvalidTtl);
    }

    let mut value = 0_u16;

    for byte in input.iter().copied() {
        if !byte.is_ascii_digit() {
            return Err(ParseError::InvalidTtl);
        }

        value = value * 10 + u16::from(byte - b'0');
    }

    u8::try_from(value).map_err(|_| ParseError::InvalidTtl)
}

fn validate_protocol_token(input: &[u8], component: ProtocolComponent) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(match component {
            ProtocolComponent::Name => ParseError::EmptyProtocolName,
            ProtocolComponent::Version => ParseError::EmptyProtocolVersion,
            ProtocolComponent::Transport => ParseError::EmptyTransport,
        });
    }

    if input.len() > MAX_VIA_PROTOCOL_TOKEN_BYTES {
        return Err(ParseError::ProtocolTokenTooLong {
            length: input.len(),
            maximum: MAX_VIA_PROTOCOL_TOKEN_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(match component {
                ProtocolComponent::Name => ParseError::InvalidProtocolName { index, byte },
                ProtocolComponent::Version => ParseError::InvalidProtocolVersion { index, byte },
                ProtocolComponent::Transport => ParseError::InvalidTransport { index, byte },
            });
        }
    }

    Ok(())
}

fn validate_branch(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    if input.len() > MAX_VIA_BRANCH_BYTES {
        return Err(ParseError::BranchTooLong {
            length: input.len(),
            maximum: MAX_VIA_BRANCH_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidBranch { index, byte });
        }
    }

    Ok(())
}

fn validate_extension_name(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyParameter);
    }

    if input.len() > MAX_VIA_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: input.len(),
            maximum: MAX_VIA_PARAMETER_NAME_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidParameterName { index, byte });
        }
    }

    if is_reserved_parameter_name(input) {
        return Err(ParseError::ReservedParameterName);
    }

    Ok(())
}

fn validate_extension_token_value(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    if input.len() > MAX_VIA_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_VIA_PARAMETER_VALUE_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidExtensionValue { index, byte });
        }
    }

    Ok(())
}

fn validate_quoted_extension_value(input: &[u8]) -> Result<(), ParseError> {
    if input.len() > MAX_VIA_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_VIA_PARAMETER_VALUE_BYTES,
        });
    }

    if std::str::from_utf8(input).is_err() {
        return Err(ParseError::InvalidQuotedString);
    }

    if input.iter().copied().any(|byte| byte.is_ascii_control()) {
        return Err(ParseError::InvalidQuotedString);
    }

    Ok(())
}

fn is_reserved_parameter_name(input: &[u8]) -> bool {
    input.eq_ignore_ascii_case(b"branch")
        || input.eq_ignore_ascii_case(b"received")
        || input.eq_ignore_ascii_case(b"rport")
        || input.eq_ignore_ascii_case(b"maddr")
        || input.eq_ignore_ascii_case(b"ttl")
}

fn trim_lws(mut input: &[u8]) -> &[u8] {
    input = trim_lws_start(input);

    while input.last().is_some_and(|byte| is_lws(*byte)) {
        input = &input[..input.len() - 1];
    }

    input
}

fn trim_lws_start(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(|byte| is_lws(*byte)) {
        input = &input[1..];
    }

    input
}

const fn is_lws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

#[derive(Clone, Copy)]
enum ProtocolComponent {
    Name,
    Version,
    Transport,
}

/// Failure to parse or construct a SIP `Via` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The field value was empty.
    Empty,

    /// The field value exceeded the configured operational size limit.
    TooLong {
        /// Actual field-value length in bytes.
        length: usize,

        /// Maximum accepted field-value length in bytes.
        maximum: usize,
    },

    /// A comma-separated Via entry was empty.
    EmptyEntry,

    /// The number of Via entries exceeded the configured bound.
    TooManyEntries {
        /// Maximum accepted Via entry count.
        maximum: usize,
    },

    /// The sent-protocol portion was missing.
    MissingSentProtocol,

    /// The sent-protocol structure was malformed.
    InvalidSentProtocol,

    /// The protocol name was empty.
    EmptyProtocolName,

    /// The protocol version was empty.
    EmptyProtocolVersion,

    /// The transport token was empty.
    EmptyTransport,

    /// A protocol component exceeded the configured token-size limit.
    ProtocolTokenTooLong {
        /// Actual token length in bytes.
        length: usize,

        /// Maximum accepted token length in bytes.
        maximum: usize,
    },

    /// The protocol name violated the SIP token grammar.
    InvalidProtocolName {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// The protocol version violated the SIP token grammar.
    InvalidProtocolVersion {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// The transport violated the SIP token grammar.
    InvalidTransport {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// The sent-by component was missing.
    MissingSentBy,

    /// The sent-by host was invalid.
    InvalidSentByHost,

    /// The sent-by port was syntactically invalid.
    InvalidPort,

    /// The sent-by or `rport` port exceeded the valid `u16` range.
    PortOutOfRange,

    /// A quoted extension parameter was malformed.
    InvalidQuotedString,

    /// Unexpected data followed a parsed Via component.
    UnexpectedTrailingData,

    /// A Via parameter was empty.
    EmptyParameter,

    /// A parameter name was invalid.
    InvalidParameterName {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A parameter name exceeded its configured operational limit.
    ParameterNameTooLong {
        /// Actual name length in bytes.
        length: usize,

        /// Maximum accepted name length in bytes.
        maximum: usize,
    },

    /// A known Via parameter name was supplied through the extension API.
    ReservedParameterName,

    /// A parameter separator was invalid.
    InvalidParameterSeparator {
        /// Unexpected byte.
        byte: u8,
    },

    /// A parameter requiring a value did not contain one.
    MissingParameterValue,

    /// A branch value violated the SIP token grammar.
    InvalidBranch {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A branch exceeded the configured operational limit.
    BranchTooLong {
        /// Actual branch length in bytes.
        length: usize,

        /// Maximum accepted branch length in bytes.
        maximum: usize,
    },

    /// A `received` value was not a valid IP address.
    InvalidReceived,

    /// An `rport` value was invalid.
    InvalidRPort,

    /// An `maddr` value was not a valid SIP host.
    InvalidMaddr,

    /// A `ttl` value was not a valid value in the range `0..=255`.
    InvalidTtl,

    /// A generic extension parameter value was invalid.
    InvalidExtensionValue {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A generic extension parameter value exceeded its operational limit.
    ParameterValueTooLong {
        /// Actual value length in bytes.
        length: usize,

        /// Maximum accepted value length in bytes.
        maximum: usize,
    },

    /// A parameter name appeared more than once within one Via entry.
    DuplicateParameter,

    /// A Via entry exceeded the configured parameter count.
    TooManyParameters {
        /// Maximum accepted parameter count.
        maximum: usize,
    },
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong { .. } => "too-long",
            Self::EmptyEntry => "empty-entry",
            Self::TooManyEntries { .. } => "too-many-entries",
            Self::MissingSentProtocol => "missing-sent-protocol",
            Self::InvalidSentProtocol => "invalid-sent-protocol",
            Self::EmptyProtocolName => "empty-protocol-name",
            Self::EmptyProtocolVersion => "empty-protocol-version",
            Self::EmptyTransport => "empty-transport",
            Self::ProtocolTokenTooLong { .. } => "protocol-token-too-long",
            Self::InvalidProtocolName { .. } => "invalid-protocol-name",
            Self::InvalidProtocolVersion { .. } => "invalid-protocol-version",
            Self::InvalidTransport { .. } => "invalid-transport",
            Self::MissingSentBy => "missing-sent-by",
            Self::InvalidSentByHost => "invalid-sent-by-host",
            Self::InvalidPort => "invalid-port",
            Self::PortOutOfRange => "port-out-of-range",
            Self::InvalidQuotedString => "invalid-quoted-string",
            Self::UnexpectedTrailingData => "unexpected-trailing-data",
            Self::EmptyParameter => "empty-parameter",
            Self::InvalidParameterName { .. } => "invalid-parameter-name",
            Self::ParameterNameTooLong { .. } => "parameter-name-too-long",
            Self::ReservedParameterName => "reserved-parameter-name",
            Self::InvalidParameterSeparator { .. } => "invalid-parameter-separator",
            Self::MissingParameterValue => "missing-parameter-value",
            Self::InvalidBranch { .. } => "invalid-branch",
            Self::BranchTooLong { .. } => "branch-too-long",
            Self::InvalidReceived => "invalid-received",
            Self::InvalidRPort => "invalid-rport",
            Self::InvalidMaddr => "invalid-maddr",
            Self::InvalidTtl => "invalid-ttl",
            Self::InvalidExtensionValue { .. } => "invalid-extension-value",
            Self::ParameterValueTooLong { .. } => "parameter-value-too-long",
            Self::DuplicateParameter => "duplicate-parameter",
            Self::TooManyParameters { .. } => "too-many-parameters",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP Via field value is empty"),
            Self::TooLong { length, maximum } => {
                write_limit(formatter, "SIP Via field-value", *length, *maximum)
            }
            Self::EmptyEntry => formatter.write_str("SIP Via contains an empty entry"),
            Self::TooManyEntries { maximum } => {
                write!(formatter, "SIP Via contains more than {maximum} entries")
            }
            Self::MissingSentProtocol => formatter.write_str("SIP Via sent protocol is missing"),
            Self::InvalidSentProtocol => formatter.write_str("SIP Via sent protocol is invalid"),
            Self::EmptyProtocolName => formatter.write_str("SIP Via protocol name is empty"),
            Self::EmptyProtocolVersion => formatter.write_str("SIP Via protocol version is empty"),
            Self::EmptyTransport => formatter.write_str("SIP Via transport is empty"),
            Self::ProtocolTokenTooLong { length, maximum } => {
                write_limit(formatter, "SIP Via protocol token", *length, *maximum)
            }
            Self::InvalidProtocolName { index, byte } => {
                write_invalid_byte(formatter, "SIP Via protocol-name", *index, *byte)
            }
            Self::InvalidProtocolVersion { index, byte } => {
                write_invalid_byte(formatter, "SIP Via protocol-version", *index, *byte)
            }
            Self::InvalidTransport { index, byte } => {
                write_invalid_byte(formatter, "SIP Via transport", *index, *byte)
            }
            Self::MissingSentBy => formatter.write_str("SIP Via sent-by value is missing"),
            Self::InvalidSentByHost => formatter.write_str("SIP Via sent-by host is invalid"),
            Self::InvalidPort => formatter.write_str("SIP Via port is invalid"),
            Self::PortOutOfRange => formatter.write_str("SIP Via port is out of range"),
            Self::InvalidQuotedString => formatter.write_str("SIP Via quoted string is invalid"),
            Self::UnexpectedTrailingData => {
                formatter.write_str("unexpected data follows SIP Via content")
            }
            Self::EmptyParameter => formatter.write_str("SIP Via parameter is empty"),
            Self::InvalidParameterName { index, byte } => {
                write_invalid_byte(formatter, "SIP Via parameter-name", *index, *byte)
            }
            Self::ParameterNameTooLong { length, maximum } => {
                write_limit(formatter, "SIP Via parameter-name", *length, *maximum)
            }
            Self::ReservedParameterName => {
                formatter.write_str("SIP Via parameter name is reserved")
            }
            Self::InvalidParameterSeparator { byte } => {
                write!(
                    formatter,
                    "invalid SIP Via parameter separator byte 0x{byte:02x}"
                )
            }
            Self::MissingParameterValue => {
                formatter.write_str("SIP Via parameter value is missing")
            }
            Self::InvalidBranch { index, byte } => {
                write_invalid_byte(formatter, "SIP Via branch", *index, *byte)
            }
            Self::BranchTooLong { length, maximum } => {
                write_limit(formatter, "SIP Via branch", *length, *maximum)
            }
            Self::InvalidReceived => formatter.write_str("SIP Via received parameter is invalid"),
            Self::InvalidRPort => formatter.write_str("SIP Via rport parameter is invalid"),
            Self::InvalidMaddr => formatter.write_str("SIP Via maddr parameter is invalid"),
            Self::InvalidTtl => formatter.write_str("SIP Via ttl parameter is invalid"),
            Self::InvalidExtensionValue { index, byte } => {
                write_invalid_byte(formatter, "SIP Via extension value", *index, *byte)
            }
            Self::ParameterValueTooLong { length, maximum } => {
                write_limit(formatter, "SIP Via parameter-value", *length, *maximum)
            }
            Self::DuplicateParameter => formatter.write_str("SIP Via parameter name is duplicated"),
            Self::TooManyParameters { maximum } => {
                write!(
                    formatter,
                    "SIP Via entry contains more than {maximum} parameters"
                )
            }
        }
    }
}

fn write_invalid_byte(
    formatter: &mut fmt::Formatter<'_>,
    subject: &str,
    index: usize,
    byte: u8,
) -> fmt::Result {
    write!(
        formatter,
        "invalid {subject} byte 0x{byte:02x} at offset {index}"
    )
}

fn write_limit(
    formatter: &mut fmt::Formatter<'_>,
    subject: &str,
    length: usize,
    maximum: usize,
) -> fmt::Result {
    write!(
        formatter,
        "{subject} length {length} exceeds maximum {maximum}"
    )
}

impl StdError for ParseError {}

#[cfg(test)]
mod tests {
    use super::{
        BudgetedParseError, MAX_VIA_BRANCH_BYTES, MAX_VIA_BYTES, MAX_VIA_ENTRIES,
        MAX_VIA_PARAMETER_NAME_BYTES, MAX_VIA_PARAMETER_VALUE_BYTES, MAX_VIA_PARAMETERS,
        ParseError, ProtocolName, ProtocolVersion, RFC3261_BRANCH_MAGIC_COOKIE, RPort,
        SentProtocol, Via, ViaEntry, ViaExtensionParameter, ViaExtensionValue, ViaParameter,
        ViaTransport, parse, parse_with_budget,
    };
    use crate::sip::types::uri::Host;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    #[test]
    fn parses_basic_udp_via() {
        let Ok(via) = parse(b"SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds") else {
            panic!("expected valid Via");
        };

        assert_eq!(via.len(), 1);
        assert!(via.first().sent_protocol().is_sip_2_0());
        assert_eq!(via.first().sent_protocol().transport(), &ViaTransport::Udp);
        assert_eq!(
            via.first().sent_by_host().as_domain(),
            Some("pc33.atlanta.com")
        );
        assert_eq!(via.first().sent_by_port(), None);
        assert_eq!(via.branch(), Some("z9hG4bK776asdhds"));
    }

    #[test]
    fn standard_sent_protocol_is_canonicalized() {
        let Ok(via) = parse(b"sip/2.0/udp example.com") else {
            panic!("expected case-insensitive standard Via components");
        };

        assert_eq!(via.to_string(), "SIP/2.0/UDP example.com");
    }

    #[test]
    fn parses_tcp_transport() {
        let Ok(via) = parse(b"SIP/2.0/TCP example.com:5060") else {
            panic!("expected TCP Via");
        };

        assert_eq!(via.first().sent_protocol().transport(), &ViaTransport::Tcp);
        assert_eq!(via.first().sent_by_port(), Some(5060));
    }

    #[test]
    fn parses_tls_transport() {
        let Ok(via) = parse(b"SIP/2.0/TLS example.com") else {
            panic!("expected TLS Via");
        };

        assert_eq!(via.first().sent_protocol().transport(), &ViaTransport::Tls);
    }

    #[test]
    fn parses_sctp_transport() {
        let Ok(via) = parse(b"SIP/2.0/SCTP example.com") else {
            panic!("expected SCTP Via");
        };

        assert_eq!(via.first().sent_protocol().transport(), &ViaTransport::Sctp);
    }

    #[test]
    fn preserves_extension_transport() {
        let Ok(via) = parse(b"SIP/2.0/X-TRANSPORT example.com") else {
            panic!("expected extension transport");
        };

        assert_eq!(
            via.first().sent_protocol().transport().as_str(),
            "X-TRANSPORT"
        );
    }

    #[test]
    fn preserves_extension_protocol_name_and_version() {
        let Ok(via) = parse(b"CUSTOM/1.0/UDP example.com") else {
            panic!("expected extension sent protocol");
        };

        assert_eq!(via.first().sent_protocol().name().as_str(), "CUSTOM");
        assert_eq!(via.first().sent_protocol().version().as_str(), "1.0");
        assert!(!via.first().sent_protocol().is_sip_2_0());
    }

    #[test]
    fn parses_ipv4_sent_by() {
        let Ok(via) = parse(b"SIP/2.0/UDP 192.0.2.10:5070") else {
            panic!("expected IPv4 sent-by");
        };

        assert!(matches!(via.first().sent_by_host(), Host::Ipv4(_)));
        assert_eq!(via.first().sent_by_port(), Some(5070));
    }

    #[test]
    fn parses_ipv6_sent_by() {
        let Ok(via) = parse(b"SIP/2.0/UDP [2001:db8::1]:5070") else {
            panic!("expected IPv6 sent-by");
        };

        assert!(matches!(via.first().sent_by_host(), Host::Ipv6(_)));
        assert_eq!(via.first().sent_by_port(), Some(5070));
        assert_eq!(via.to_string(), "SIP/2.0/UDP [2001:db8::1]:5070");
    }

    #[test]
    fn parses_multiple_via_entries() {
        let Ok(via) = parse(
            b"SIP/2.0/UDP first.example.com;branch=z9hG4bKone, SIP/2.0/TCP second.example.com:5070;branch=z9hG4bKtwo",
        ) else {
            panic!("expected multiple Via entries");
        };

        assert_eq!(via.len(), 2);
        assert_eq!(via.entries()[0].branch(), Some("z9hG4bKone"));
        assert_eq!(via.entries()[1].branch(), Some("z9hG4bKtwo"));
    }

    #[test]
    fn topmost_branch_comes_from_first_entry() {
        let Ok(via) = parse(
            b"SIP/2.0/UDP one.example.com;branch=z9hG4bKone, SIP/2.0/UDP two.example.com;branch=z9hG4bKtwo",
        ) else {
            panic!("expected multiple Via entries");
        };

        assert_eq!(via.branch(), Some("z9hG4bKone"));
    }

    #[test]
    fn detects_rfc3261_branch_magic_cookie() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;branch=z9hG4bK776asdhds") else {
            panic!("expected valid branch");
        };

        assert!(via.first().has_rfc3261_branch_cookie());
        assert_eq!(RFC3261_BRANCH_MAGIC_COOKIE, "z9hG4bK");
    }

    #[test]
    fn parser_does_not_require_magic_cookie() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;branch=legacy-branch") else {
            panic!("expected syntactically valid legacy branch");
        };

        assert_eq!(via.branch(), Some("legacy-branch"));
        assert!(!via.first().has_rfc3261_branch_cookie());
    }

    #[test]
    fn parser_does_not_require_branch_parameter() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com") else {
            panic!("expected syntactically valid Via without branch");
        };

        assert_eq!(via.branch(), None);
    }

    #[test]
    fn parses_received_parameter() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;received=203.0.113.5") else {
            panic!("expected received parameter");
        };

        assert_eq!(
            via.first().received(),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)))
        );
    }

    #[test]
    fn parses_ipv6_received_parameter() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;received=2001:db8::10") else {
            panic!("expected IPv6 received parameter");
        };

        let Some(address) = via.first().received() else {
            panic!("expected received address");
        };

        assert!(address.is_ipv6());
    }

    #[test]
    fn parses_valueless_rport() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;rport") else {
            panic!("expected rport request");
        };

        assert_eq!(via.first().rport(), Some(RPort::Requested));
        assert_eq!(via.to_string(), "SIP/2.0/UDP example.com;rport");
    }

    #[test]
    fn parses_rport_value() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;rport=5088") else {
            panic!("expected rport value");
        };

        assert_eq!(via.first().rport(), Some(RPort::Value(5088)));
    }

    #[test]
    fn parses_maddr_parameter() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;maddr=239.255.255.1") else {
            panic!("expected maddr parameter");
        };

        assert!(matches!(via.first().maddr(), Some(Host::Ipv4(_))));
    }

    #[test]
    fn parses_ipv6_maddr_parameter() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;maddr=[2001:db8::20]") else {
            panic!("expected IPv6 maddr");
        };

        assert!(matches!(via.first().maddr(), Some(Host::Ipv6(_))));
    }

    #[test]
    fn parses_ttl_parameter() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;ttl=64") else {
            panic!("expected TTL");
        };

        assert_eq!(via.first().ttl(), Some(64));
    }

    #[test]
    fn accepts_maximum_ttl() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;ttl=255") else {
            panic!("expected maximum TTL");
        };

        assert_eq!(via.first().ttl(), Some(255));
    }

    #[test]
    fn parses_extension_flag_parameter() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;x-feature") else {
            panic!("expected extension flag");
        };

        let Some(parameter) = via.first().extension_parameter("x-feature") else {
            panic!("expected extension parameter");
        };

        assert!(parameter.is_flag());
    }

    #[test]
    fn parses_extension_token_parameter() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;x-mode=fast") else {
            panic!("expected token extension");
        };

        let Some(parameter) = via.first().extension_parameter("X-MODE") else {
            panic!("expected extension parameter");
        };

        let Some(ViaExtensionValue::Token(value)) = parameter.value() else {
            panic!("expected token extension value");
        };

        assert_eq!(value.as_ref(), "fast");
    }

    #[test]
    fn parses_extension_host_parameter() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;x-host=[2001:db8::5]") else {
            panic!("expected host extension");
        };

        let Some(parameter) = via.first().extension_parameter("x-host") else {
            panic!("expected extension parameter");
        };

        assert!(matches!(
            parameter.value(),
            Some(ViaExtensionValue::Host(Host::Ipv6(_)))
        ));
    }

    #[test]
    fn parses_quoted_extension_parameter() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;comment=\"voice gateway\"") else {
            panic!("expected quoted extension");
        };

        let Some(parameter) = via.first().extension_parameter("comment") else {
            panic!("expected extension parameter");
        };

        let Some(value) = parameter.value() else {
            panic!("expected extension value");
        };

        assert_eq!(value.as_str(), Some("voice gateway"));
        assert!(value.is_quoted());
    }

    #[test]
    fn quoted_extension_may_contain_comma() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;comment=\"one,two\";branch=z9hG4bKabc")
        else {
            panic!("expected quoted comma");
        };

        assert_eq!(via.len(), 1);
        assert_eq!(
            via.first()
                .extension_parameter("comment")
                .and_then(ViaExtensionParameter::value)
                .and_then(ViaExtensionValue::as_str),
            Some("one,two")
        );
    }

    #[test]
    fn quoted_extension_may_contain_semicolon() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;comment=\"one;two\";branch=z9hG4bKabc")
        else {
            panic!("expected quoted semicolon");
        };

        assert_eq!(
            via.first()
                .extension_parameter("comment")
                .and_then(ViaExtensionParameter::value)
                .and_then(ViaExtensionValue::as_str),
            Some("one;two")
        );
    }

    #[test]
    fn quoted_extension_unescapes_quote_and_backslash() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;comment=\"A \\\"B\\\" \\\\ C\"") else {
            panic!("expected escaped quoted value");
        };

        assert_eq!(
            via.first()
                .extension_parameter("comment")
                .and_then(ViaExtensionParameter::value)
                .and_then(ViaExtensionValue::as_str),
            Some("A \"B\" \\ C")
        );
    }

    #[test]
    fn parameter_names_are_case_insensitive() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com;BRANCH=z9hG4bKabc;RPORT") else {
            panic!("expected case-insensitive parameter names");
        };

        assert_eq!(via.branch(), Some("z9hG4bKabc"));
        assert_eq!(via.first().rport(), Some(RPort::Requested));
    }

    #[test]
    fn preserves_parameter_order() {
        let Ok(via) =
            parse(b"SIP/2.0/UDP example.com;rport;branch=z9hG4bKabc;received=192.0.2.1;ttl=10")
        else {
            panic!("expected ordered parameters");
        };

        assert!(matches!(
            via.first().parameters()[0],
            ViaParameter::RPort(_)
        ));
        assert!(matches!(
            via.first().parameters()[1],
            ViaParameter::Branch(_)
        ));
        assert!(matches!(
            via.first().parameters()[2],
            ViaParameter::Received(_)
        ));
        assert!(matches!(via.first().parameters()[3], ViaParameter::Ttl(_)));
    }

    #[test]
    fn rejects_empty_field() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b" \t "), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_field_above_size_limit() {
        let input = vec![b'A'; MAX_VIA_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_VIA_BYTES + 1,
                maximum: MAX_VIA_BYTES,
            })
        );
    }

    #[test]
    fn rejects_empty_comma_entry() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com, ,SIP/2.0/TCP other.example.com"),
            Err(ParseError::EmptyEntry)
        );
    }

    #[test]
    fn rejects_trailing_comma() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com,"),
            Err(ParseError::EmptyEntry)
        );
    }

    #[test]
    fn rejects_missing_sent_by() {
        assert_eq!(parse(b"SIP/2.0/UDP"), Err(ParseError::MissingSentBy));
    }

    #[test]
    fn rejects_malformed_sent_protocol() {
        assert_eq!(
            parse(b"SIP/2.0 example.com"),
            Err(ParseError::InvalidSentProtocol)
        );
    }

    #[test]
    fn rejects_empty_protocol_version() {
        assert_eq!(
            parse(b"SIP//UDP example.com"),
            Err(ParseError::EmptyProtocolVersion)
        );
    }

    #[test]
    fn rejects_invalid_transport_token() {
        assert_eq!(
            parse(b"SIP/2.0/UD:P example.com"),
            Err(ParseError::InvalidTransport {
                index: 2,
                byte: b':',
            })
        );
    }

    #[test]
    fn rejects_invalid_sent_by_host() {
        assert_eq!(
            parse(b"SIP/2.0/UDP -bad.example.com"),
            Err(ParseError::InvalidSentByHost)
        );
    }

    #[test]
    fn rejects_unbracketed_ipv6_sent_by() {
        assert_eq!(
            parse(b"SIP/2.0/UDP 2001:db8::1"),
            Err(ParseError::InvalidSentByHost)
        );
    }

    #[test]
    fn rejects_invalid_port() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com:abc"),
            Err(ParseError::InvalidPort)
        );
    }

    #[test]
    fn rejects_port_above_u16_range() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com:65536"),
            Err(ParseError::PortOutOfRange)
        );
    }

    #[test]
    fn accepts_maximum_port() {
        let Ok(via) = parse(b"SIP/2.0/UDP example.com:65535") else {
            panic!("expected maximum port");
        };

        assert_eq!(via.first().sent_by_port(), Some(65535));
    }

    #[test]
    fn rejects_empty_parameter() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;"),
            Err(ParseError::EmptyParameter)
        );
    }

    #[test]
    fn rejects_duplicate_branch() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;branch=one;BRANCH=two"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn rejects_duplicate_extension_parameter_case_insensitively() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;X-Mode=one;x-mode=two"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn rejects_branch_without_value() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;branch"),
            Err(ParseError::MissingParameterValue)
        );
    }

    #[test]
    fn rejects_invalid_branch() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;branch=bad:value"),
            Err(ParseError::InvalidBranch {
                index: 3,
                byte: b':',
            })
        );
    }

    #[test]
    fn rejects_invalid_received_value() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;received=not-an-ip"),
            Err(ParseError::InvalidReceived)
        );
    }

    #[test]
    fn rejects_empty_rport_value() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;rport="),
            Err(ParseError::MissingParameterValue)
        );
    }

    #[test]
    fn rejects_invalid_rport_value() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;rport=abc"),
            Err(ParseError::InvalidRPort)
        );
    }

    #[test]
    fn rejects_invalid_maddr() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;maddr=-bad.example.com"),
            Err(ParseError::InvalidMaddr)
        );
    }

    #[test]
    fn rejects_ttl_above_255() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;ttl=256"),
            Err(ParseError::InvalidTtl)
        );
    }

    #[test]
    fn rejects_non_decimal_ttl() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;ttl=abc"),
            Err(ParseError::InvalidTtl)
        );
    }

    #[test]
    fn rejects_unterminated_quoted_extension() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;comment=\"unfinished"),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn rejects_crlf_inside_quoted_extension() {
        assert_eq!(
            parse(b"SIP/2.0/UDP example.com;comment=\"one\r\ntwo\""),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn creates_standard_sent_protocol_without_extensions() {
        let protocol = SentProtocol::sip_2_0(ViaTransport::Udp);

        assert_eq!(protocol.name(), &ProtocolName::Sip);
        assert_eq!(protocol.version(), &ProtocolVersion::Sip2);
        assert_eq!(protocol.transport(), &ViaTransport::Udp);
        assert_eq!(protocol.to_string(), "SIP/2.0/UDP");
    }

    #[test]
    fn creates_extension_sent_protocol() {
        let Ok(protocol) = SentProtocol::new("CUSTOM", "1.0", "X-TRANSPORT") else {
            panic!("expected extension sent protocol");
        };

        assert_eq!(protocol.to_string(), "CUSTOM/1.0/X-TRANSPORT");
    }

    #[test]
    fn creates_branch_parameter() {
        let Ok(parameter) = ViaParameter::branch("z9hG4bKabc") else {
            panic!("expected valid branch");
        };

        assert_eq!(parameter.to_string(), "branch=z9hG4bKabc");
    }

    #[test]
    fn creates_extension_flag() {
        let Ok(parameter) = ViaExtensionParameter::flag("x-feature") else {
            panic!("expected valid extension parameter");
        };

        assert!(parameter.is_flag());
        assert_eq!(parameter.to_string(), "x-feature");
    }

    #[test]
    fn creates_extension_token() {
        let Ok(parameter) = ViaExtensionParameter::token("x-mode", "fast") else {
            panic!("expected valid extension parameter");
        };

        assert_eq!(parameter.to_string(), "x-mode=fast");
    }

    #[test]
    fn creates_extension_quoted_value() {
        let Ok(parameter) = ViaExtensionParameter::quoted("comment", "Voice Gateway") else {
            panic!("expected quoted extension parameter");
        };

        assert_eq!(parameter.to_string(), "comment=\"Voice Gateway\"");
    }

    #[test]
    fn extension_api_rejects_reserved_parameter_name() {
        assert_eq!(
            ViaExtensionParameter::flag("branch"),
            Err(ParseError::ReservedParameterName)
        );

        assert_eq!(
            ViaExtensionParameter::flag("RPORT"),
            Err(ParseError::ReservedParameterName)
        );
    }

    #[test]
    fn rejects_branch_above_size_limit() {
        let branch = "A".repeat(MAX_VIA_BRANCH_BYTES + 1);

        assert_eq!(
            ViaParameter::branch(branch),
            Err(ParseError::BranchTooLong {
                length: MAX_VIA_BRANCH_BYTES + 1,
                maximum: MAX_VIA_BRANCH_BYTES,
            })
        );
    }

    #[test]
    fn rejects_extension_name_above_size_limit() {
        let name = "A".repeat(MAX_VIA_PARAMETER_NAME_BYTES + 1);

        assert_eq!(
            ViaExtensionParameter::flag(name),
            Err(ParseError::ParameterNameTooLong {
                length: MAX_VIA_PARAMETER_NAME_BYTES + 1,
                maximum: MAX_VIA_PARAMETER_NAME_BYTES,
            })
        );
    }

    #[test]
    fn rejects_extension_value_above_size_limit() {
        let value = "A".repeat(MAX_VIA_PARAMETER_VALUE_BYTES + 1);

        assert_eq!(
            ViaExtensionParameter::token("x-value", value),
            Err(ParseError::ParameterValueTooLong {
                length: MAX_VIA_PARAMETER_VALUE_BYTES + 1,
                maximum: MAX_VIA_PARAMETER_VALUE_BYTES,
            })
        );
    }

    #[test]
    fn enforces_parameter_count() {
        let protocol = SentProtocol::sip_2_0(ViaTransport::Udp);

        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid host");
        };

        let mut entry = ViaEntry::new(protocol, host, None);

        for index in 0..MAX_VIA_PARAMETERS {
            let name = format!("x-{index}");
            let Ok(extension) = ViaExtensionParameter::flag(name) else {
                panic!("expected extension parameter");
            };

            assert!(
                entry
                    .push_parameter(ViaParameter::Extension(extension))
                    .is_ok()
            );
        }

        let Ok(extra) = ViaExtensionParameter::flag("x-extra") else {
            panic!("expected extension parameter");
        };

        assert_eq!(
            entry.push_parameter(ViaParameter::Extension(extra)),
            Err(ParseError::TooManyParameters {
                maximum: MAX_VIA_PARAMETERS,
            })
        );
    }

    #[test]
    fn enforces_entry_count() {
        let protocol = SentProtocol::sip_2_0(ViaTransport::Udp);

        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid host");
        };

        let first = ViaEntry::new(protocol.clone(), host.clone(), None);
        let mut via = Via::new(first);

        for _ in 1..MAX_VIA_ENTRIES {
            let entry = ViaEntry::new(protocol.clone(), host.clone(), None);
            assert!(via.push_entry(entry).is_ok());
        }

        let extra = ViaEntry::new(protocol, host, None);

        assert_eq!(
            via.push_entry(extra),
            Err(ParseError::TooManyEntries {
                maximum: MAX_VIA_ENTRIES,
            })
        );
    }

    #[test]
    fn budgeted_parser_accepts_exact_entry_and_total_parameter_limits() {
        let input = b"SIP/2.0/UDP one.example.com;p0=x, \
                      SIP/2.0/TCP two.example.com;p1=y";

        let Ok(via) = parse_with_budget(input, 2, 2) else {
            panic!("expected exact aggregate budgets to validate");
        };

        assert_eq!(via.len(), 2);
        assert_eq!(
            via.entries()
                .iter()
                .map(ViaEntry::parameter_count)
                .sum::<usize>(),
            2
        );
    }

    #[test]
    fn budgeted_parser_refuses_an_entry_before_parsing_it() {
        let input = b"SIP/2.0/UDP one.example.com, not-a-valid-via";

        assert_eq!(
            parse_with_budget(input, 1, usize::MAX),
            Err(BudgetedParseError::EntryBudgetExceeded {
                attempted: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn budgeted_parser_refuses_a_parameter_before_parsing_it() {
        let input = b"SIP/2.0/UDP one.example.com;p0=x;=not-parsed";

        assert_eq!(
            parse_with_budget(input, 1, 1),
            Err(BudgetedParseError::TotalParameterBudgetExceeded {
                attempted: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn budgeted_parser_counts_parameters_across_entries() {
        let input = b"SIP/2.0/UDP one.example.com;p0=x, \
                      SIP/2.0/TCP two.example.com;=not-parsed";

        assert_eq!(
            parse_with_budget(input, 2, 1),
            Err(BudgetedParseError::TotalParameterBudgetExceeded {
                attempted: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn public_parser_preserves_field_local_entry_error() {
        let mut input = String::new();

        for index in 0..=MAX_VIA_ENTRIES {
            if index != 0 {
                input.push_str(", ");
            }

            input.push_str("SIP/2.0/UDP h");
            input.push_str(&index.to_string());
            input.push_str(".example.com");
        }

        assert_eq!(
            parse(input.as_bytes()),
            Err(ParseError::TooManyEntries {
                maximum: MAX_VIA_ENTRIES,
            })
        );
    }

    #[test]
    fn display_preserves_semantics_and_canonicalizes_known_names() {
        let Ok(via) =
            parse(b"sip/2.0/udp example.com:5060;RPORT;BRANCH=z9hG4bKabc;RECEIVED=192.0.2.10")
        else {
            panic!("expected valid Via");
        };

        assert_eq!(
            via.to_string(),
            "SIP/2.0/UDP example.com:5060;rport;branch=z9hG4bKabc;received=192.0.2.10"
        );
    }

    #[test]
    fn parses_from_str() {
        let Ok(via) = Via::from_str("SIP/2.0/UDP example.com") else {
            panic!("expected valid Via");
        };

        assert_eq!(via.len(), 1);
    }

    #[test]
    fn consumes_into_entries() {
        let Ok(via) = parse(b"SIP/2.0/UDP one.example.com, SIP/2.0/TCP two.example.com") else {
            panic!("expected multiple Via entries");
        };

        let entries = via.into_entries();

        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");
        assert_eq!(ParseError::EmptyEntry.class(), "empty-entry");
        assert_eq!(
            ParseError::InvalidSentProtocol.class(),
            "invalid-sent-protocol"
        );
        assert_eq!(
            ParseError::InvalidSentByHost.class(),
            "invalid-sent-by-host"
        );
        assert_eq!(
            ParseError::DuplicateParameter.class(),
            "duplicate-parameter"
        );
        assert_eq!(ParseError::InvalidRPort.class(), "invalid-rport");
        assert_eq!(ParseError::InvalidTtl.class(), "invalid-ttl");
        assert_eq!(
            ParseError::TooManyParameters {
                maximum: MAX_VIA_PARAMETERS,
            }
            .class(),
            "too-many-parameters"
        );
    }
}
