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

//! SIP URI types.
//!
//! This module defines owned protocol types for SIP, SIPS, and other absolute
//! URIs accepted by SIP message syntax.
//!
//! Full wire parsing is owned by the SIP parser subsystem. Constructors in
//! this module validate programmatically created URI components so invalid
//! values are not silently introduced into protocol messages.

use std::error::Error as StdError;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Maximum number of URI parameters accepted by a programmatically constructed
/// SIP or SIPS URI.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_URI_PARAMETERS: usize = 64;

/// Maximum number of URI headers accepted by a programmatically constructed
/// SIP or SIPS URI.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_URI_HEADERS: usize = 64;

/// A URI accepted by SIP message syntax.
#[derive(Clone, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Uri {
    /// A structured SIP or SIPS URI.
    Sip(SipUri),

    /// A non-SIP absolute URI.
    Absolute(AbsoluteUri),
}

impl Uri {
    /// Returns the URI scheme.
    #[must_use]
    pub fn scheme(&self) -> &str {
        match self {
            Self::Sip(uri) => uri.scheme().as_str(),
            Self::Absolute(uri) => uri.scheme(),
        }
    }

    /// Returns whether this is a SIP or SIPS URI.
    #[must_use]
    pub const fn is_sip(&self) -> bool {
        matches!(self, Self::Sip(_))
    }

    /// Returns the structured SIP URI when this URI uses SIP or SIPS.
    #[must_use]
    pub const fn as_sip(&self) -> Option<&SipUri> {
        match self {
            Self::Sip(uri) => Some(uri),
            Self::Absolute(_) => None,
        }
    }
}

impl fmt::Debug for Uri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sip(uri) => formatter.debug_tuple("Sip").field(uri).finish(),
            Self::Absolute(uri) => formatter.debug_tuple("Absolute").field(uri).finish(),
        }
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sip(uri) => uri.fmt(formatter),
            Self::Absolute(uri) => uri.fmt(formatter),
        }
    }
}

impl From<SipUri> for Uri {
    fn from(uri: SipUri) -> Self {
        Self::Sip(uri)
    }
}

impl From<AbsoluteUri> for Uri {
    fn from(uri: AbsoluteUri) -> Self {
        Self::Absolute(uri)
    }
}

/// SIP URI scheme.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SipScheme {
    /// The `sip` URI scheme.
    Sip,

    /// The `sips` URI scheme.
    Sips,
}

impl SipScheme {
    /// Returns the canonical lowercase scheme.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sip => "sip",
            Self::Sips => "sips",
        }
    }

    /// Returns whether this is the SIPS scheme.
    #[must_use]
    pub const fn is_secure(self) -> bool {
        matches!(self, Self::Sips)
    }
}

impl fmt::Display for SipScheme {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Host component of a SIP or SIPS URI.
#[derive(Clone, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Host {
    /// DNS hostname.
    Domain(Box<str>),

    /// IPv4 address.
    Ipv4(Ipv4Addr),

    /// IPv6 address.
    Ipv6(Ipv6Addr),
}

impl Host {
    /// Creates a hostname value.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::InvalidDomain`] when the hostname does not match
    /// the hostname grammar accepted by SIP.
    pub fn domain(domain: impl Into<Box<str>>) -> Result<Self, BuildError> {
        let domain = domain.into();

        if !is_valid_hostname(&domain) {
            return Err(BuildError::InvalidDomain);
        }

        Ok(Self::Domain(domain))
    }

    /// Returns the hostname when this is a DNS host.
    #[must_use]
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Self::Domain(domain) => Some(domain),
            Self::Ipv4(_) | Self::Ipv6(_) => None,
        }
    }

    /// Returns whether this host is an IP address.
    #[must_use]
    pub const fn is_ip(&self) -> bool {
        matches!(self, Self::Ipv4(_) | Self::Ipv6(_))
    }
}

impl fmt::Debug for Host {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(domain) => formatter.debug_tuple("Domain").field(domain).finish(),
            Self::Ipv4(address) => formatter.debug_tuple("Ipv4").field(address).finish(),
            Self::Ipv6(address) => formatter.debug_tuple("Ipv6").field(address).finish(),
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(domain) => formatter.write_str(domain),
            Self::Ipv4(address) => write!(formatter, "{address}"),
            Self::Ipv6(address) => write!(formatter, "[{address}]"),
        }
    }
}

impl From<Ipv4Addr> for Host {
    fn from(address: Ipv4Addr) -> Self {
        Self::Ipv4(address)
    }
}

impl From<Ipv6Addr> for Host {
    fn from(address: Ipv6Addr) -> Self {
        Self::Ipv6(address)
    }
}

/// A structured SIP or SIPS URI.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SipUri {
    scheme: SipScheme,
    user: Option<Box<str>>,
    password: Option<Box<str>>,
    host: Host,
    port: Option<u16>,
    parameters: Vec<UriParameter>,
    headers: Vec<UriHeader>,
}

impl SipUri {
    /// Creates a SIP or SIPS URI containing only its required components.
    #[must_use]
    pub const fn new(scheme: SipScheme, host: Host) -> Self {
        Self {
            scheme,
            user: None,
            password: None,
            host,
            port: None,
            parameters: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Creates a SIP URI.
    #[must_use]
    pub const fn sip(host: Host) -> Self {
        Self::new(SipScheme::Sip, host)
    }

    /// Creates a SIPS URI.
    #[must_use]
    pub const fn sips(host: Host) -> Self {
        Self::new(SipScheme::Sips, host)
    }

    /// Returns the URI scheme.
    #[must_use]
    pub const fn scheme(&self) -> SipScheme {
        self.scheme
    }

    /// Returns the optional user component.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Returns whether a password component is present.
    ///
    /// The password itself is intentionally not exposed through `Debug`.
    #[must_use]
    pub const fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Returns the optional password component.
    #[must_use]
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Returns the URI host.
    #[must_use]
    pub const fn host(&self) -> &Host {
        &self.host
    }

    /// Returns the optional explicit port.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns the URI parameters in wire order.
    #[must_use]
    pub fn parameters(&self) -> &[UriParameter] {
        &self.parameters
    }

    /// Returns the URI headers in wire order.
    #[must_use]
    pub fn headers(&self) -> &[UriHeader] {
        &self.headers
    }

    /// Sets the user component.
    ///
    /// The value must already use SIP URI escaping where required.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when the value is empty or contains an invalid
    /// user-component byte or escape sequence.
    pub fn set_user(&mut self, user: impl Into<Box<str>>) -> Result<(), BuildError> {
        let user = user.into();
        validate_user(&user)?;
        self.user = Some(user);
        Ok(())
    }

    /// Removes the user and password components.
    pub fn clear_user(&mut self) {
        self.user = None;
        self.password = None;
    }

    /// Sets the password component.
    ///
    /// An empty password is syntactically valid, but a password cannot exist
    /// without a user component.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when no user is present or when the password
    /// contains invalid bytes or escape sequences.
    pub fn set_password(&mut self, password: impl Into<Box<str>>) -> Result<(), BuildError> {
        if self.user.is_none() {
            return Err(BuildError::PasswordWithoutUser);
        }

        let password = password.into();
        validate_password(&password)?;
        self.password = Some(password);
        Ok(())
    }

    /// Removes the password component.
    pub fn clear_password(&mut self) {
        self.password = None;
    }

    /// Sets the explicit URI port.
    pub const fn set_port(&mut self, port: u16) {
        self.port = Some(port);
    }

    /// Removes the explicit URI port.
    pub const fn clear_port(&mut self) {
        self.port = None;
    }

    /// Adds a URI parameter.
    ///
    /// Parameter names are checked case-insensitively for duplicates.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::TooManyParameters`] when the operational limit is
    /// reached or [`BuildError::DuplicateParameter`] when the parameter name
    /// already exists.
    pub fn push_parameter(&mut self, parameter: UriParameter) -> Result<(), BuildError> {
        if self.parameters.len() >= MAX_URI_PARAMETERS {
            return Err(BuildError::TooManyParameters);
        }

        if self
            .parameters
            .iter()
            .any(|existing| existing.name.eq_ignore_ascii_case(&parameter.name))
        {
            return Err(BuildError::DuplicateParameter);
        }

        self.parameters.push(parameter);
        Ok(())
    }

    /// Adds a URI header.
    ///
    /// URI header order is preserved.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::TooManyHeaders`] when the operational limit is
    /// reached.
    pub fn push_header(&mut self, header: UriHeader) -> Result<(), BuildError> {
        if self.headers.len() >= MAX_URI_HEADERS {
            return Err(BuildError::TooManyHeaders);
        }

        self.headers.push(header);
        Ok(())
    }

    /// Returns the first URI parameter with the requested name.
    ///
    /// Parameter-name matching is case-insensitive.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&UriParameter> {
        self.parameters
            .iter()
            .find(|parameter| parameter.name.eq_ignore_ascii_case(name))
    }
}

impl fmt::Debug for SipUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SipUri")
            .field("scheme", &self.scheme)
            .field("user", &self.user)
            .field("password_present", &self.password.is_some())
            .field("host", &self.host)
            .field("port", &self.port)
            .field("parameter_count", &self.parameters.len())
            .field("header_count", &self.headers.len())
            .finish()
    }
}

impl fmt::Display for SipUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:", self.scheme)?;

        if let Some(user) = &self.user {
            formatter.write_str(user)?;

            if let Some(password) = &self.password {
                write!(formatter, ":{password}")?;
            }

            formatter.write_str("@")?;
        }

        write!(formatter, "{}", self.host)?;

        if let Some(port) = self.port {
            write!(formatter, ":{port}")?;
        }

        for parameter in &self.parameters {
            write!(formatter, ";{parameter}")?;
        }

        if let Some((first, remaining)) = self.headers.split_first() {
            write!(formatter, "?{first}")?;

            for header in remaining {
                write!(formatter, "&{header}")?;
            }
        }

        Ok(())
    }
}

/// SIP or SIPS URI parameter.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UriParameter {
    name: Box<str>,
    value: Option<Box<str>>,
}

impl UriParameter {
    /// Creates a URI parameter.
    ///
    /// A parameter without a value is valid. When a value is supplied, it
    /// must not be empty.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when the name or value violates SIP URI
    /// parameter syntax.
    pub fn new(name: impl Into<Box<str>>, value: Option<Box<str>>) -> Result<Self, BuildError> {
        let name = name.into();
        validate_parameter_name(&name)?;

        if let Some(value) = value.as_deref() {
            validate_parameter_value(value)?;
        }

        Ok(Self { name, value })
    }

    /// Creates a valueless URI parameter.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when the name violates SIP URI parameter syntax.
    pub fn flag(name: impl Into<Box<str>>) -> Result<Self, BuildError> {
        Self::new(name, None)
    }

    /// Returns the parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional parameter value.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl fmt::Display for UriParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)?;

        if let Some(value) = &self.value {
            write!(formatter, "={value}")?;
        }

        Ok(())
    }
}

/// Header encoded inside a SIP or SIPS URI.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UriHeader {
    name: Box<str>,
    value: Box<str>,
}

impl UriHeader {
    /// Creates a URI header.
    ///
    /// URI header values may be empty.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when the header name or value violates SIP URI
    /// header syntax.
    pub fn new(name: impl Into<Box<str>>, value: impl Into<Box<str>>) -> Result<Self, BuildError> {
        let name = name.into();
        let value = value.into();

        validate_header_name(&name)?;
        validate_header_value(&value)?;

        Ok(Self { name, value })
    }

    /// Returns the URI header name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the URI header value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for UriHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}={}", self.name, self.value)
    }
}

/// A non-SIP absolute URI preserved for use in SIP message fields that permit
/// arbitrary URI schemes.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct AbsoluteUri {
    scheme: Box<str>,
    value: Box<str>,
}

impl AbsoluteUri {
    /// Creates a non-SIP absolute URI from its scheme and scheme-specific
    /// value.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when the scheme is invalid, when the value is
    /// empty, or when `sip` or `sips` is supplied instead of using
    /// [`SipUri`].
    pub fn new(
        scheme: impl Into<Box<str>>,
        value: impl Into<Box<str>>,
    ) -> Result<Self, BuildError> {
        let scheme = scheme.into();
        let value = value.into();

        validate_scheme(&scheme)?;

        if scheme.eq_ignore_ascii_case("sip") || scheme.eq_ignore_ascii_case("sips") {
            return Err(BuildError::ReservedSipScheme);
        }

        if value.is_empty() {
            return Err(BuildError::EmptyAbsoluteValue);
        }

        Ok(Self { scheme, value })
    }

    /// Returns the URI scheme exactly as provided.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns the scheme-specific URI value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for AbsoluteUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AbsoluteUri")
            .field("scheme", &self.scheme)
            .field("value_bytes", &self.value.len())
            .finish()
    }
}

impl fmt::Display for AbsoluteUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.scheme, self.value)
    }
}

/// Failure to construct a valid URI component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    /// The user component was empty.
    EmptyUser,

    /// The user component contained invalid syntax.
    InvalidUser,

    /// A password was supplied without a user component.
    PasswordWithoutUser,

    /// The password component contained invalid syntax.
    InvalidPassword,

    /// The hostname was invalid.
    InvalidDomain,

    /// A URI parameter name was invalid.
    InvalidParameterName,

    /// A URI parameter value was invalid.
    InvalidParameterValue,

    /// A URI parameter name appeared more than once.
    DuplicateParameter,

    /// The URI contains too many parameters.
    TooManyParameters,

    /// A URI header name was invalid.
    InvalidHeaderName,

    /// A URI header value was invalid.
    InvalidHeaderValue,

    /// The URI contains too many headers.
    TooManyHeaders,

    /// The absolute-URI scheme was invalid.
    InvalidScheme,

    /// SIP or SIPS was passed to the generic absolute-URI representation.
    ReservedSipScheme,

    /// The scheme-specific portion of an absolute URI was empty.
    EmptyAbsoluteValue,
}

impl BuildError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::EmptyUser => "empty-user",
            Self::InvalidUser => "invalid-user",
            Self::PasswordWithoutUser => "password-without-user",
            Self::InvalidPassword => "invalid-password",
            Self::InvalidDomain => "invalid-domain",
            Self::InvalidParameterName => "invalid-parameter-name",
            Self::InvalidParameterValue => "invalid-parameter-value",
            Self::DuplicateParameter => "duplicate-parameter",
            Self::TooManyParameters => "too-many-parameters",
            Self::InvalidHeaderName => "invalid-header-name",
            Self::InvalidHeaderValue => "invalid-header-value",
            Self::TooManyHeaders => "too-many-headers",
            Self::InvalidScheme => "invalid-scheme",
            Self::ReservedSipScheme => "reserved-sip-scheme",
            Self::EmptyAbsoluteValue => "empty-absolute-value",
        }
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyUser => "SIP URI user is empty",
            Self::InvalidUser => "SIP URI user contains invalid syntax",
            Self::PasswordWithoutUser => "SIP URI password requires a user component",
            Self::InvalidPassword => "SIP URI password contains invalid syntax",
            Self::InvalidDomain => "SIP URI hostname is invalid",
            Self::InvalidParameterName => "SIP URI parameter name is invalid",
            Self::InvalidParameterValue => "SIP URI parameter value is invalid",
            Self::DuplicateParameter => "SIP URI parameter name is duplicated",
            Self::TooManyParameters => "SIP URI contains too many parameters",
            Self::InvalidHeaderName => "SIP URI header name is invalid",
            Self::InvalidHeaderValue => "SIP URI header value is invalid",
            Self::TooManyHeaders => "SIP URI contains too many headers",
            Self::InvalidScheme => "absolute URI scheme is invalid",
            Self::ReservedSipScheme => {
                "SIP and SIPS schemes must use the structured SIP URI representation"
            }
            Self::EmptyAbsoluteValue => "absolute URI scheme-specific value is empty",
        };

        formatter.write_str(message)
    }
}

impl StdError for BuildError {}

fn validate_user(user: &str) -> Result<(), BuildError> {
    if user.is_empty() {
        return Err(BuildError::EmptyUser);
    }

    if !validate_escaped_component(user.as_bytes(), is_user_byte) {
        return Err(BuildError::InvalidUser);
    }

    Ok(())
}

fn validate_password(password: &str) -> Result<(), BuildError> {
    if !validate_escaped_component(password.as_bytes(), is_password_byte) {
        return Err(BuildError::InvalidPassword);
    }

    Ok(())
}

fn validate_parameter_name(name: &str) -> Result<(), BuildError> {
    if name.is_empty() || !validate_escaped_component(name.as_bytes(), is_parameter_byte) {
        return Err(BuildError::InvalidParameterName);
    }

    Ok(())
}

fn validate_parameter_value(value: &str) -> Result<(), BuildError> {
    if value.is_empty() || !validate_escaped_component(value.as_bytes(), is_parameter_byte) {
        return Err(BuildError::InvalidParameterValue);
    }

    Ok(())
}

fn validate_header_name(name: &str) -> Result<(), BuildError> {
    if name.is_empty() || !validate_escaped_component(name.as_bytes(), is_header_byte) {
        return Err(BuildError::InvalidHeaderName);
    }

    Ok(())
}

fn validate_header_value(value: &str) -> Result<(), BuildError> {
    if !validate_escaped_component(value.as_bytes(), is_header_byte) {
        return Err(BuildError::InvalidHeaderValue);
    }

    Ok(())
}

fn validate_scheme(scheme: &str) -> Result<(), BuildError> {
    let bytes = scheme.as_bytes();

    let Some(first) = bytes.first() else {
        return Err(BuildError::InvalidScheme);
    };

    if !first.is_ascii_alphabetic() {
        return Err(BuildError::InvalidScheme);
    }

    if !bytes
        .iter()
        .copied()
        .skip(1)
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return Err(BuildError::InvalidScheme);
    }

    Ok(())
}

fn validate_escaped_component(input: &[u8], allowed: fn(u8) -> bool) -> bool {
    let mut index = 0;

    while index < input.len() {
        let byte = input[index];

        if byte == b'%' {
            let Some(high) = input.get(index + 1) else {
                return false;
            };
            let Some(low) = input.get(index + 2) else {
                return false;
            };

            if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                return false;
            }

            index += 3;
            continue;
        }

        if !allowed(byte) {
            return false;
        }

        index += 1;
    }

    true
}

const fn is_unreserved_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
        )
}

const fn is_user_byte(byte: u8) -> bool {
    is_unreserved_byte(byte)
        || matches!(byte, b'&' | b'=' | b'+' | b'$' | b',' | b';' | b'?' | b'/')
}

const fn is_password_byte(byte: u8) -> bool {
    is_unreserved_byte(byte) || matches!(byte, b'&' | b'=' | b'+' | b'$' | b',')
}

const fn is_parameter_byte(byte: u8) -> bool {
    is_unreserved_byte(byte) || matches!(byte, b'[' | b']' | b'/' | b':' | b'&' | b'+' | b'$')
}

const fn is_header_byte(byte: u8) -> bool {
    is_unreserved_byte(byte) || matches!(byte, b'[' | b']' | b'/' | b'?' | b':' | b'+' | b'$')
}

fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || !hostname.is_ascii() {
        return false;
    }

    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);

    if hostname.is_empty() {
        return false;
    }

    let mut labels = hostname.split('.').peekable();

    while let Some(label) = labels.next() {
        if label.is_empty() || !is_valid_domain_label(label.as_bytes()) {
            return false;
        }

        if labels.peek().is_none() && !label.as_bytes()[0].is_ascii_alphabetic() {
            return false;
        }
    }

    true
}

fn is_valid_domain_label(label: &[u8]) -> bool {
    let Some(first) = label.first() else {
        return false;
    };
    let Some(last) = label.last() else {
        return false;
    };

    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return false;
    }

    label
        .iter()
        .copied()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::{AbsoluteUri, BuildError, Host, SipScheme, SipUri, Uri, UriHeader, UriParameter};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn creates_basic_sip_uri() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };

        let uri = SipUri::sip(host);

        assert_eq!(uri.to_string(), "sip:example.com");
        assert_eq!(uri.scheme(), SipScheme::Sip);
        assert_eq!(uri.user(), None);
        assert_eq!(uri.port(), None);
    }

    #[test]
    fn creates_sips_uri() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };

        let uri = SipUri::sips(host);

        assert_eq!(uri.to_string(), "sips:example.com");
        assert!(uri.scheme().is_secure());
    }

    #[test]
    fn creates_uri_with_user_password_and_port() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };

        let mut uri = SipUri::sip(host);

        assert!(uri.set_user("alice").is_ok());
        assert!(uri.set_password("secret").is_ok());
        uri.set_port(5060);

        assert_eq!(uri.user(), Some("alice"));
        assert_eq!(uri.password(), Some("secret"));
        assert_eq!(uri.port(), Some(5060));
        assert_eq!(uri.to_string(), "sip:alice:secret@example.com:5060");
    }

    #[test]
    fn password_requires_user() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };

        let mut uri = SipUri::sip(host);

        assert_eq!(
            uri.set_password("secret"),
            Err(BuildError::PasswordWithoutUser)
        );
    }

    #[test]
    fn clearing_user_also_clears_password() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };

        let mut uri = SipUri::sip(host);

        assert!(uri.set_user("alice").is_ok());
        assert!(uri.set_password("secret").is_ok());

        uri.clear_user();

        assert_eq!(uri.user(), None);
        assert!(!uri.has_password());
    }

    #[test]
    fn accepts_escaped_user_component() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };

        let mut uri = SipUri::sip(host);

        assert!(uri.set_user("alice%40voice").is_ok());
        assert_eq!(uri.user(), Some("alice%40voice"));
    }

    #[test]
    fn rejects_invalid_user_escape() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };

        let mut uri = SipUri::sip(host);

        assert_eq!(uri.set_user("alice%4"), Err(BuildError::InvalidUser));
    }

    #[test]
    fn creates_ipv4_host() {
        let address = Ipv4Addr::new(192, 0, 2, 10);
        let uri = SipUri::sip(Host::from(address));

        assert_eq!(uri.to_string(), "sip:192.0.2.10");
        assert!(uri.host().is_ip());
    }

    #[test]
    fn creates_bracketed_ipv6_host() {
        let address = Ipv6Addr::LOCALHOST;
        let uri = SipUri::sip(Host::from(address));

        assert_eq!(uri.to_string(), "sip:[::1]");
        assert!(uri.host().is_ip());
    }

    #[test]
    fn accepts_valid_hostname_with_trailing_dot() {
        let Ok(host) = Host::domain("sip.example.com.") else {
            panic!("expected valid domain");
        };

        assert_eq!(host.to_string(), "sip.example.com.");
    }

    #[test]
    fn rejects_invalid_hostname() {
        assert_eq!(Host::domain("-example.com"), Err(BuildError::InvalidDomain));
        assert_eq!(Host::domain("example..com"), Err(BuildError::InvalidDomain));
        assert_eq!(Host::domain("example.123"), Err(BuildError::InvalidDomain));
    }

    #[test]
    fn adds_uri_parameters_in_order() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };
        let Ok(transport) = UriParameter::new("transport", Some("udp".into())) else {
            panic!("expected valid transport parameter");
        };
        let Ok(lr) = UriParameter::flag("lr") else {
            panic!("expected valid lr parameter");
        };

        let mut uri = SipUri::sip(host);

        assert!(uri.push_parameter(transport).is_ok());
        assert!(uri.push_parameter(lr).is_ok());

        assert_eq!(uri.to_string(), "sip:example.com;transport=udp;lr");
        assert_eq!(uri.parameters().len(), 2);
    }

    #[test]
    fn rejects_duplicate_parameter_case_insensitively() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };
        let Ok(first) = UriParameter::new("transport", Some("udp".into())) else {
            panic!("expected valid parameter");
        };
        let Ok(second) = UriParameter::new("TrAnSpOrT", Some("tcp".into())) else {
            panic!("expected valid parameter");
        };

        let mut uri = SipUri::sip(host);

        assert!(uri.push_parameter(first).is_ok());
        assert_eq!(
            uri.push_parameter(second),
            Err(BuildError::DuplicateParameter)
        );
    }

    #[test]
    fn finds_parameter_case_insensitively() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };
        let Ok(parameter) = UriParameter::new("Transport", Some("tcp".into())) else {
            panic!("expected valid parameter");
        };

        let mut uri = SipUri::sip(host);
        assert!(uri.push_parameter(parameter).is_ok());

        let Some(found) = uri.parameter("transport") else {
            panic!("expected parameter");
        };

        assert_eq!(found.value(), Some("tcp"));
    }

    #[test]
    fn parameter_value_cannot_be_empty_when_present() {
        assert_eq!(
            UriParameter::new("transport", Some("".into())),
            Err(BuildError::InvalidParameterValue)
        );
    }

    #[test]
    fn adds_uri_headers_in_order() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };
        let Ok(subject) = UriHeader::new("subject", "project%20x") else {
            panic!("expected valid URI header");
        };
        let Ok(priority) = UriHeader::new("priority", "urgent") else {
            panic!("expected valid URI header");
        };

        let mut uri = SipUri::sips(host);

        assert!(uri.push_header(subject).is_ok());
        assert!(uri.push_header(priority).is_ok());

        assert_eq!(
            uri.to_string(),
            "sips:example.com?subject=project%20x&priority=urgent"
        );
    }

    #[test]
    fn uri_header_value_may_be_empty() {
        let Ok(header) = UriHeader::new("subject", "") else {
            panic!("expected empty URI header value to be valid");
        };

        assert_eq!(header.name(), "subject");
        assert_eq!(header.value(), "");
        assert_eq!(header.to_string(), "subject=");
    }

    #[test]
    fn creates_non_sip_absolute_uri() {
        let Ok(uri) = AbsoluteUri::new("tel", "+966555123456") else {
            panic!("expected valid absolute URI");
        };

        assert_eq!(uri.scheme(), "tel");
        assert_eq!(uri.value(), "+966555123456");
        assert_eq!(uri.to_string(), "tel:+966555123456");
    }

    #[test]
    fn absolute_uri_rejects_sip_scheme() {
        assert_eq!(
            AbsoluteUri::new("sip", "alice@example.com"),
            Err(BuildError::ReservedSipScheme)
        );
        assert_eq!(
            AbsoluteUri::new("SIPS", "alice@example.com"),
            Err(BuildError::ReservedSipScheme)
        );
    }

    #[test]
    fn absolute_uri_rejects_invalid_scheme() {
        assert_eq!(
            AbsoluteUri::new("1tel", "+966555123456"),
            Err(BuildError::InvalidScheme)
        );
        assert_eq!(
            AbsoluteUri::new("te l", "+966555123456"),
            Err(BuildError::InvalidScheme)
        );
    }

    #[test]
    fn uri_enum_reports_scheme() {
        let Ok(host) = Host::domain("example.com") else {
            panic!("expected valid domain");
        };

        let sip = Uri::from(SipUri::sip(host));

        assert!(sip.is_sip());
        assert_eq!(sip.scheme(), "sip");

        let Ok(absolute) = AbsoluteUri::new("tel", "+966555123456") else {
            panic!("expected valid absolute URI");
        };

        let absolute = Uri::from(absolute);

        assert!(!absolute.is_sip());
        assert_eq!(absolute.scheme(), "tel");
    }

    #[test]
    fn build_error_classes_are_stable() {
        assert_eq!(BuildError::EmptyUser.class(), "empty-user");
        assert_eq!(BuildError::InvalidDomain.class(), "invalid-domain");
        assert_eq!(
            BuildError::DuplicateParameter.class(),
            "duplicate-parameter"
        );
        assert_eq!(BuildError::InvalidScheme.class(), "invalid-scheme");
    }
}
