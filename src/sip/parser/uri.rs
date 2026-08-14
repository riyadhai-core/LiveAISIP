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

//! SIP URI wire parser.
//!
//! This module parses SIP, SIPS, and other absolute URI forms from wire bytes
//! into the owned URI types defined by the SIP type subsystem.
//!
//! Parsing is performed without parser-framework dependencies. Component
//! boundaries are located directly on the input buffer and allocations occur
//! only when validated components are transferred into the owned URI model.

use std::error::Error as StdError;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::sip::types::method::Method;
use crate::sip::types::uri::{
    AbsoluteUri, BuildError, Host, SipScheme, SipUri, Uri, UriHeader, UriParameter,
};

/// Maximum accepted URI size in bytes.
///
/// This is a `LiveAISIP` operational bound rather than a SIP protocol limit.
pub const MAX_URI_BYTES: usize = 8 * 1024;

/// Parses a SIP, SIPS, or other absolute URI from wire bytes.
///
/// # Errors
///
/// Returns [`ParseError`] when the URI is empty, exceeds the configured size
/// bound, violates URI syntax, contains invalid SIP URI components, or exceeds
/// bounded parameter/header capacities.
pub fn parse(input: &[u8]) -> Result<Uri, ParseError> {
    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    if input.len() > MAX_URI_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_URI_BYTES,
        });
    }

    let Some(colon) = input.iter().position(|byte| *byte == b':') else {
        return Err(ParseError::MissingScheme);
    };

    let scheme = &input[..colon];
    validate_scheme(scheme)?;

    let value = &input[colon + 1..];

    if scheme.eq_ignore_ascii_case(b"sip") {
        return parse_sip_uri(SipScheme::Sip, value).map(Uri::from);
    }

    if scheme.eq_ignore_ascii_case(b"sips") {
        return parse_sip_uri(SipScheme::Sips, value).map(Uri::from);
    }

    parse_absolute_uri(scheme, value).map(Uri::from)
}

/// Parses a URI from an already validated UTF-8 string.
///
/// # Errors
///
/// Returns the same errors as [`parse`].
pub fn parse_str(input: &str) -> Result<Uri, ParseError> {
    parse(input.as_bytes())
}

fn parse_sip_uri(scheme: SipScheme, input: &[u8]) -> Result<SipUri, ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingHost);
    }

    let (userinfo, remainder) = split_userinfo(input)?;
    let host_end = remainder
        .iter()
        .position(|byte| matches!(byte, b';' | b'?'))
        .unwrap_or(remainder.len());

    let hostport = &remainder[..host_end];
    let tail = &remainder[host_end..];

    let (host, port) = parse_hostport(hostport)?;
    let mut uri = SipUri::new(scheme, host);

    if let Some(userinfo) = userinfo {
        apply_userinfo(&mut uri, userinfo)?;
    }

    if let Some(port) = port {
        uri.set_port(port);
    }

    parse_tail(&mut uri, tail)?;

    Ok(uri)
}

fn split_userinfo(input: &[u8]) -> Result<(Option<&[u8]>, &[u8]), ParseError> {
    let Some(at) = input.iter().position(|byte| *byte == b'@') else {
        return Ok((None, input));
    };

    if input[at + 1..].contains(&b'@') {
        return Err(ParseError::InvalidUserInfo);
    }

    let userinfo = &input[..at];

    if userinfo.is_empty() {
        return Err(ParseError::InvalidUserInfo);
    }

    Ok((Some(userinfo), &input[at + 1..]))
}

fn apply_userinfo(uri: &mut SipUri, input: &[u8]) -> Result<(), ParseError> {
    let (user, password) = match input.iter().position(|byte| *byte == b':') {
        Some(colon) => (&input[..colon], Some(&input[colon + 1..])),
        None => (input, None),
    };

    let user = std::str::from_utf8(user).map_err(|_| ParseError::InvalidUserInfo)?;

    uri.set_user(user)
        .map_err(|_| ParseError::InvalidUserInfo)?;

    if let Some(password) = password {
        let password = std::str::from_utf8(password).map_err(|_| ParseError::InvalidUserInfo)?;

        uri.set_password(password)
            .map_err(|_| ParseError::InvalidUserInfo)?;
    }

    Ok(())
}

fn parse_hostport(input: &[u8]) -> Result<(Host, Option<u16>), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingHost);
    }

    if input[0] == b'[' {
        return parse_ipv6_hostport(input);
    }

    if input.contains(&b'[') || input.contains(&b']') {
        return Err(ParseError::InvalidHost);
    }

    let (host, port) = match input.iter().position(|byte| *byte == b':') {
        Some(colon) => {
            let host = &input[..colon];
            let port = &input[colon + 1..];

            if port.contains(&b':') {
                return Err(ParseError::InvalidPort);
            }

            (host, Some(parse_port(port)?))
        }
        None => (input, None),
    };

    Ok((parse_host(host)?, port))
}

fn parse_ipv6_hostport(input: &[u8]) -> Result<(Host, Option<u16>), ParseError> {
    let Some(close) = input.iter().position(|byte| *byte == b']') else {
        return Err(ParseError::InvalidHost);
    };

    if close <= 1 {
        return Err(ParseError::InvalidHost);
    }

    let address = std::str::from_utf8(&input[1..close])
        .map_err(|_| ParseError::InvalidHost)?
        .parse::<Ipv6Addr>()
        .map_err(|_| ParseError::InvalidHost)?;

    let suffix = &input[close + 1..];

    let port = if suffix.is_empty() {
        None
    } else {
        if suffix[0] != b':' {
            return Err(ParseError::InvalidHost);
        }

        Some(parse_port(&suffix[1..])?)
    };

    Ok((Host::from(address), port))
}

fn parse_host(input: &[u8]) -> Result<Host, ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingHost);
    }

    let host = std::str::from_utf8(input).map_err(|_| ParseError::InvalidHost)?;

    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return Ok(Host::from(address));
    }

    Host::domain(host).map_err(|_| ParseError::InvalidHost)
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

fn parse_tail(uri: &mut SipUri, input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Ok(());
    }

    let (parameters, headers) = match input.iter().position(|byte| *byte == b'?') {
        Some(question) => (&input[..question], Some(&input[question + 1..])),
        None => (input, None),
    };

    if !parameters.is_empty() {
        parse_parameters(uri, parameters)?;
    }

    if let Some(headers) = headers {
        parse_headers(uri, headers)?;
    }

    Ok(())
}

fn parse_parameters(uri: &mut SipUri, input: &[u8]) -> Result<(), ParseError> {
    if input.first() != Some(&b';') {
        return Err(ParseError::InvalidParameter);
    }

    let parameters = &input[1..];

    if parameters.is_empty() {
        return Err(ParseError::InvalidParameter);
    }

    for raw_parameter in parameters.split(|byte| *byte == b';') {
        if raw_parameter.is_empty() {
            return Err(ParseError::InvalidParameter);
        }

        let parameter = parse_parameter(raw_parameter)?;

        if uri
            .parameters()
            .iter()
            .any(|existing| parameter_names_equal(existing.name(), parameter.name()))
        {
            return Err(ParseError::DuplicateParameter);
        }

        uri.push_parameter(parameter).map_err(map_build_error)?;
    }

    Ok(())
}

fn parse_parameter(input: &[u8]) -> Result<UriParameter, ParseError> {
    let (name, value) = match input.iter().position(|byte| *byte == b'=') {
        Some(equal) => (&input[..equal], Some(&input[equal + 1..])),
        None => (input, None),
    };

    let name = std::str::from_utf8(name).map_err(|_| ParseError::InvalidParameter)?;

    let value = match value {
        Some(value) => Some(
            std::str::from_utf8(value)
                .map_err(|_| ParseError::InvalidParameter)?
                .into(),
        ),
        None => None,
    };

    let parameter = UriParameter::new(name, value).map_err(|_| ParseError::InvalidParameter)?;

    validate_standard_parameter(&parameter)?;

    Ok(parameter)
}

fn validate_standard_parameter(parameter: &UriParameter) -> Result<(), ParseError> {
    let name = parameter.name();
    let value = parameter.value();

    if name.eq_ignore_ascii_case("transport") || name.eq_ignore_ascii_case("user") {
        let Some(value) = value else {
            return Err(ParseError::InvalidParameter);
        };

        if !is_token(value.as_bytes()) {
            return Err(ParseError::InvalidParameter);
        }

        return Ok(());
    }

    if name.eq_ignore_ascii_case("method") {
        let Some(value) = value else {
            return Err(ParseError::InvalidParameter);
        };

        Method::from_bytes(value.as_bytes()).map_err(|_| ParseError::InvalidParameter)?;

        return Ok(());
    }

    if name.eq_ignore_ascii_case("ttl") {
        let Some(value) = value else {
            return Err(ParseError::InvalidParameter);
        };

        validate_ttl(value.as_bytes())?;
        return Ok(());
    }

    if name.eq_ignore_ascii_case("maddr") {
        let Some(value) = value else {
            return Err(ParseError::InvalidParameter);
        };

        parse_parameter_host(value.as_bytes())?;
        return Ok(());
    }

    if name.eq_ignore_ascii_case("lr") && value.is_some() {
        return Err(ParseError::InvalidParameter);
    }

    Ok(())
}

fn validate_ttl(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() || input.len() > 3 {
        return Err(ParseError::InvalidParameter);
    }

    let mut value = 0_u16;

    for byte in input.iter().copied() {
        if !byte.is_ascii_digit() {
            return Err(ParseError::InvalidParameter);
        }

        value = value * 10 + u16::from(byte - b'0');
    }

    if value > 255 {
        return Err(ParseError::InvalidParameter);
    }

    Ok(())
}

fn parse_parameter_host(input: &[u8]) -> Result<(), ParseError> {
    if input.first() == Some(&b'[') {
        let Some(close) = input.iter().position(|byte| *byte == b']') else {
            return Err(ParseError::InvalidParameter);
        };

        if close != input.len() - 1 || close <= 1 {
            return Err(ParseError::InvalidParameter);
        }

        std::str::from_utf8(&input[1..close])
            .map_err(|_| ParseError::InvalidParameter)?
            .parse::<Ipv6Addr>()
            .map_err(|_| ParseError::InvalidParameter)?;

        return Ok(());
    }

    parse_host(input)
        .map(|_| ())
        .map_err(|_| ParseError::InvalidParameter)
}

fn parse_headers(uri: &mut SipUri, input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::InvalidHeader);
    }

    for raw_header in input.split(|byte| *byte == b'&') {
        if raw_header.is_empty() {
            return Err(ParseError::InvalidHeader);
        }

        let header = parse_header(raw_header)?;
        uri.push_header(header).map_err(map_build_error)?;
    }

    Ok(())
}

fn parse_header(input: &[u8]) -> Result<UriHeader, ParseError> {
    let Some(equal) = input.iter().position(|byte| *byte == b'=') else {
        return Err(ParseError::InvalidHeader);
    };

    let name = std::str::from_utf8(&input[..equal]).map_err(|_| ParseError::InvalidHeader)?;

    let value = std::str::from_utf8(&input[equal + 1..]).map_err(|_| ParseError::InvalidHeader)?;

    UriHeader::new(name, value).map_err(|_| ParseError::InvalidHeader)
}

fn parse_absolute_uri(scheme: &[u8], value: &[u8]) -> Result<AbsoluteUri, ParseError> {
    if value.is_empty() {
        return Err(ParseError::InvalidAbsoluteUri);
    }

    if !validate_absolute_value(value) {
        return Err(ParseError::InvalidAbsoluteUri);
    }

    let scheme = std::str::from_utf8(scheme).map_err(|_| ParseError::InvalidScheme)?;
    let value = std::str::from_utf8(value).map_err(|_| ParseError::InvalidAbsoluteUri)?;

    AbsoluteUri::new(scheme, value).map_err(|_| ParseError::InvalidAbsoluteUri)
}

fn validate_scheme(input: &[u8]) -> Result<(), ParseError> {
    let Some(first) = input.first() else {
        return Err(ParseError::InvalidScheme);
    };

    if !first.is_ascii_alphabetic() {
        return Err(ParseError::InvalidScheme);
    }

    if !input
        .iter()
        .copied()
        .skip(1)
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return Err(ParseError::InvalidScheme);
    }

    Ok(())
}

fn validate_absolute_value(input: &[u8]) -> bool {
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

        if !is_absolute_uri_byte(byte) {
            return false;
        }

        index += 1;
    }

    true
}

fn parameter_names_equal(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();

    let mut left_index = 0;
    let mut right_index = 0;

    loop {
        let left_byte = next_component_byte(left, &mut left_index);
        let right_byte = next_component_byte(right, &mut right_index);

        match (left_byte, right_byte) {
            (None, None) => return left_index == left.len() && right_index == right.len(),
            (Some(left), Some(right)) if left.eq_ignore_ascii_case(&right) => {}
            _ => return false,
        }
    }
}

fn next_component_byte(input: &[u8], index: &mut usize) -> Option<u8> {
    let byte = *input.get(*index)?;

    if byte != b'%' {
        *index += 1;
        return Some(byte);
    }

    let high = hex_value(*input.get(*index + 1)?)?;
    let low = hex_value(*input.get(*index + 2)?)?;

    *index += 3;

    Some((high << 4) | low)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_token(input: &[u8]) -> bool {
    !input.is_empty() && input.iter().copied().all(is_token_byte)
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

const fn is_absolute_uri_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_'
                | b'.'
                | b'!'
                | b'~'
                | b'*'
                | b'\''
                | b'('
                | b')'
                | b';'
                | b'/'
                | b'?'
                | b':'
                | b'@'
                | b'&'
                | b'='
                | b'+'
                | b'$'
                | b','
                | b'['
                | b']'
        )
}

fn map_build_error(error: BuildError) -> ParseError {
    match error {
        BuildError::DuplicateParameter => ParseError::DuplicateParameter,
        BuildError::TooManyParameters => ParseError::TooManyParameters,
        BuildError::TooManyHeaders => ParseError::TooManyHeaders,
        BuildError::InvalidHeaderName | BuildError::InvalidHeaderValue => ParseError::InvalidHeader,
        BuildError::EmptyUser
        | BuildError::InvalidUser
        | BuildError::PasswordWithoutUser
        | BuildError::InvalidPassword => ParseError::InvalidUserInfo,
        BuildError::InvalidDomain => ParseError::InvalidHost,
        BuildError::InvalidParameterName | BuildError::InvalidParameterValue => {
            ParseError::InvalidParameter
        }
        BuildError::InvalidScheme
        | BuildError::ReservedSipScheme
        | BuildError::EmptyAbsoluteValue => ParseError::InvalidAbsoluteUri,
    }
}

/// Failure to parse a SIP URI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The URI was empty.
    Empty,

    /// The URI exceeded the configured size bound.
    TooLong {
        /// Actual URI length in bytes.
        length: usize,

        /// Maximum accepted URI length in bytes.
        maximum: usize,
    },

    /// The URI did not contain a scheme separator.
    MissingScheme,

    /// The URI scheme was malformed.
    InvalidScheme,

    /// A SIP or SIPS URI did not contain a host.
    MissingHost,

    /// The SIP userinfo component was malformed.
    InvalidUserInfo,

    /// The SIP host component was malformed.
    InvalidHost,

    /// The SIP port component was malformed.
    InvalidPort,

    /// The SIP port exceeded the valid `u16` range.
    PortOutOfRange,

    /// A URI parameter was malformed.
    InvalidParameter,

    /// A URI parameter name appeared more than once.
    DuplicateParameter,

    /// The URI exceeded the configured parameter count.
    TooManyParameters,

    /// A URI header was malformed.
    InvalidHeader,

    /// The URI exceeded the configured URI-header count.
    TooManyHeaders,

    /// A non-SIP absolute URI was malformed.
    InvalidAbsoluteUri,
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong { .. } => "too-long",
            Self::MissingScheme => "missing-scheme",
            Self::InvalidScheme => "invalid-scheme",
            Self::MissingHost => "missing-host",
            Self::InvalidUserInfo => "invalid-userinfo",
            Self::InvalidHost => "invalid-host",
            Self::InvalidPort => "invalid-port",
            Self::PortOutOfRange => "port-out-of-range",
            Self::InvalidParameter => "invalid-parameter",
            Self::DuplicateParameter => "duplicate-parameter",
            Self::TooManyParameters => "too-many-parameters",
            Self::InvalidHeader => "invalid-header",
            Self::TooManyHeaders => "too-many-headers",
            Self::InvalidAbsoluteUri => "invalid-absolute-uri",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP URI is empty"),
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP URI length {length} exceeds maximum {maximum}"
                )
            }
            Self::MissingScheme => formatter.write_str("URI scheme is missing"),
            Self::InvalidScheme => formatter.write_str("URI scheme is invalid"),
            Self::MissingHost => formatter.write_str("SIP URI host is missing"),
            Self::InvalidUserInfo => formatter.write_str("SIP URI userinfo is invalid"),
            Self::InvalidHost => formatter.write_str("SIP URI host is invalid"),
            Self::InvalidPort => formatter.write_str("SIP URI port is invalid"),
            Self::PortOutOfRange => formatter.write_str("SIP URI port is out of range"),
            Self::InvalidParameter => formatter.write_str("SIP URI parameter is invalid"),
            Self::DuplicateParameter => formatter.write_str("SIP URI parameter name is duplicated"),
            Self::TooManyParameters => formatter.write_str("SIP URI contains too many parameters"),
            Self::InvalidHeader => formatter.write_str("SIP URI header is invalid"),
            Self::TooManyHeaders => formatter.write_str("SIP URI contains too many URI headers"),
            Self::InvalidAbsoluteUri => formatter.write_str("absolute URI is invalid"),
        }
    }
}

impl StdError for ParseError {}

#[cfg(test)]
mod tests {
    use super::{MAX_URI_BYTES, ParseError, parse, parse_str};
    use crate::sip::types::uri::{Host, SipScheme, Uri};

    #[test]
    fn parses_basic_sip_uri() {
        let Ok(uri) = parse(b"sip:alice@example.com") else {
            panic!("expected valid SIP URI");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert_eq!(uri.scheme(), SipScheme::Sip);
        assert_eq!(uri.user(), Some("alice"));
        assert_eq!(uri.host().as_domain(), Some("example.com"));
        assert_eq!(uri.port(), None);
    }

    #[test]
    fn sip_scheme_is_case_insensitive() {
        let Ok(uri) = parse(b"SIP:alice@example.com") else {
            panic!("expected valid SIP URI");
        };

        assert_eq!(uri.to_string(), "sip:alice@example.com");
    }

    #[test]
    fn parses_sips_uri() {
        let Ok(uri) = parse(b"sips:alice@example.com") else {
            panic!("expected valid SIPS URI");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert_eq!(uri.scheme(), SipScheme::Sips);
        assert!(uri.scheme().is_secure());
    }

    #[test]
    fn parses_user_password_and_port() {
        let Ok(uri) = parse(b"sip:alice:secret@example.com:5060") else {
            panic!("expected valid SIP URI");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert_eq!(uri.user(), Some("alice"));
        assert_eq!(uri.password(), Some("secret"));
        assert_eq!(uri.port(), Some(5060));
    }

    #[test]
    fn semicolon_in_user_is_not_a_uri_parameter() {
        let Ok(uri) = parse(b"sip:alice;day=tuesday@atlanta.com") else {
            panic!("expected valid SIP URI");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert_eq!(uri.user(), Some("alice;day=tuesday"));
        assert!(uri.parameters().is_empty());
    }

    #[test]
    fn parses_escaped_at_sign_in_user() {
        let Ok(uri) = parse(b"sip:j%40s0n@example.com") else {
            panic!("expected valid escaped user");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert_eq!(uri.user(), Some("j%40s0n"));
    }

    #[test]
    fn parses_ipv4_host() {
        let Ok(uri) = parse(b"sip:alice@192.0.2.4") else {
            panic!("expected valid IPv4 SIP URI");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert!(matches!(uri.host(), Host::Ipv4(_)));
    }

    #[test]
    fn parses_ipv6_host_and_port() {
        let Ok(uri) = parse(b"sip:alice@[2001:db8::1]:5070") else {
            panic!("expected valid IPv6 SIP URI");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert!(matches!(uri.host(), Host::Ipv6(_)));
        assert_eq!(uri.port(), Some(5070));
        assert_eq!(uri.to_string(), "sip:alice@[2001:db8::1]:5070");
    }

    #[test]
    fn parses_parameters_in_wire_order() {
        let Ok(uri) = parse(b"sip:example.com;transport=tcp;lr") else {
            panic!("expected valid URI parameters");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert_eq!(uri.parameters().len(), 2);
        assert_eq!(uri.parameters()[0].name(), "transport");
        assert_eq!(uri.parameters()[0].value(), Some("tcp"));
        assert_eq!(uri.parameters()[1].name(), "lr");
        assert_eq!(uri.parameters()[1].value(), None);
    }

    #[test]
    fn parses_uri_headers_in_wire_order() {
        let Ok(uri) = parse(b"sips:alice@atlanta.com?subject=project%20x&priority=urgent") else {
            panic!("expected valid URI headers");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert_eq!(uri.headers().len(), 2);
        assert_eq!(uri.headers()[0].name(), "subject");
        assert_eq!(uri.headers()[0].value(), "project%20x");
        assert_eq!(uri.headers()[1].name(), "priority");
        assert_eq!(uri.headers()[1].value(), "urgent");
    }

    #[test]
    fn parses_method_parameter() {
        let Ok(uri) = parse(b"sip:atlanta.com;method=REGISTER") else {
            panic!("expected valid method parameter");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        let Some(method) = uri.parameter("method") else {
            panic!("expected method parameter");
        };

        assert_eq!(method.value(), Some("REGISTER"));
    }

    #[test]
    fn parses_multicast_parameters() {
        let Ok(uri) = parse(b"sip:alice@atlanta.com;maddr=239.255.255.1;ttl=15") else {
            panic!("expected valid multicast parameters");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert_eq!(
            uri.parameter("maddr").and_then(|value| value.value()),
            Some("239.255.255.1")
        );
        assert_eq!(
            uri.parameter("ttl").and_then(|value| value.value()),
            Some("15")
        );
    }

    #[test]
    fn rejects_empty_uri() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_uri_without_scheme() {
        assert_eq!(parse(b"alice@example.com"), Err(ParseError::MissingScheme));
    }

    #[test]
    fn rejects_invalid_scheme() {
        assert_eq!(
            parse(b"1sip:alice@example.com"),
            Err(ParseError::InvalidScheme)
        );
    }

    #[test]
    fn rejects_missing_host() {
        assert_eq!(parse(b"sip:"), Err(ParseError::MissingHost));
        assert_eq!(parse(b"sip:alice@"), Err(ParseError::MissingHost));
    }

    #[test]
    fn rejects_empty_user_before_at_sign() {
        assert_eq!(parse(b"sip:@example.com"), Err(ParseError::InvalidUserInfo));
    }

    #[test]
    fn rejects_multiple_at_signs() {
        assert_eq!(
            parse(b"sip:alice@example.com@other.example.com"),
            Err(ParseError::InvalidUserInfo)
        );
    }

    #[test]
    fn rejects_invalid_user_escape() {
        assert_eq!(
            parse(b"sip:alice%4@example.com"),
            Err(ParseError::InvalidUserInfo)
        );
    }

    #[test]
    fn rejects_unbracketed_ipv6_host() {
        assert!(matches!(
            parse(b"sip:2001:db8::1"),
            Err(ParseError::InvalidPort | ParseError::InvalidHost)
        ));
    }

    #[test]
    fn rejects_unclosed_ipv6_reference() {
        assert_eq!(parse(b"sip:[2001:db8::1"), Err(ParseError::InvalidHost));
    }

    #[test]
    fn rejects_invalid_port() {
        assert_eq!(parse(b"sip:example.com:abc"), Err(ParseError::InvalidPort));
    }

    #[test]
    fn rejects_empty_port() {
        assert_eq!(parse(b"sip:example.com:"), Err(ParseError::InvalidPort));
    }

    #[test]
    fn rejects_port_above_u16_range() {
        assert_eq!(
            parse(b"sip:example.com:65536"),
            Err(ParseError::PortOutOfRange)
        );
    }

    #[test]
    fn accepts_maximum_port() {
        let Ok(uri) = parse(b"sip:example.com:65535") else {
            panic!("expected valid maximum port");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert_eq!(uri.port(), Some(65535));
    }

    #[test]
    fn rejects_duplicate_parameter_names_case_insensitively() {
        assert_eq!(
            parse(b"sip:example.com;transport=udp;TrAnSpOrT=tcp"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn rejects_percent_encoded_duplicate_parameter_name() {
        assert_eq!(
            parse(b"sip:example.com;transport=udp;%74ransport=tcp"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn rejects_invalid_lr_parameter_value() {
        assert_eq!(
            parse(b"sip:example.com;lr=true"),
            Err(ParseError::InvalidParameter)
        );
    }

    #[test]
    fn rejects_invalid_ttl() {
        assert_eq!(
            parse(b"sip:example.com;ttl=256"),
            Err(ParseError::InvalidParameter)
        );

        assert_eq!(
            parse(b"sip:example.com;ttl=abc"),
            Err(ParseError::InvalidParameter)
        );
    }

    #[test]
    fn rejects_invalid_method_parameter() {
        assert_eq!(
            parse(b"sip:example.com;method=INVITE:bad"),
            Err(ParseError::InvalidParameter)
        );
    }

    #[test]
    fn rejects_invalid_maddr_parameter() {
        assert_eq!(
            parse(b"sip:example.com;maddr=-bad.example.com"),
            Err(ParseError::InvalidParameter)
        );
    }

    #[test]
    fn rejects_empty_parameter() {
        assert_eq!(
            parse(b"sip:example.com;"),
            Err(ParseError::InvalidParameter)
        );

        assert_eq!(
            parse(b"sip:example.com;;lr"),
            Err(ParseError::InvalidParameter)
        );
    }

    #[test]
    fn rejects_empty_uri_header_section() {
        assert_eq!(parse(b"sip:example.com?"), Err(ParseError::InvalidHeader));
    }

    #[test]
    fn rejects_uri_header_without_equal_sign() {
        assert_eq!(
            parse(b"sip:example.com?subject"),
            Err(ParseError::InvalidHeader)
        );
    }

    #[test]
    fn accepts_empty_uri_header_value() {
        let Ok(uri) = parse(b"sip:example.com?subject=") else {
            panic!("expected empty URI header value to be valid");
        };

        let Some(uri) = uri.as_sip() else {
            panic!("expected structured SIP URI");
        };

        assert_eq!(uri.headers()[0].name(), "subject");
        assert_eq!(uri.headers()[0].value(), "");
    }

    #[test]
    fn parses_absolute_tel_uri() {
        let Ok(uri) = parse(b"tel:+966555123456") else {
            panic!("expected valid absolute URI");
        };

        assert!(!uri.is_sip());
        assert_eq!(uri.scheme(), "tel");
        assert_eq!(uri.to_string(), "tel:+966555123456");
    }

    #[test]
    fn parses_hierarchical_absolute_uri() {
        let Ok(uri) = parse(b"https://example.com/path?x=1") else {
            panic!("expected valid hierarchical absolute URI");
        };

        assert_eq!(uri.scheme(), "https");
        assert_eq!(uri.to_string(), "https://example.com/path?x=1");
    }

    #[test]
    fn parses_absolute_uri_with_ipv6_reference() {
        let Ok(uri) = parse(b"https://[2001:db8::1]/voice") else {
            panic!("expected valid IPv6 absolute URI");
        };

        assert_eq!(uri.to_string(), "https://[2001:db8::1]/voice");
    }

    #[test]
    fn rejects_absolute_uri_with_space() {
        assert_eq!(parse(b"tel:+966 555"), Err(ParseError::InvalidAbsoluteUri));
    }

    #[test]
    fn rejects_absolute_uri_with_bad_escape() {
        assert_eq!(parse(b"tel:+966%4"), Err(ParseError::InvalidAbsoluteUri));
    }

    #[test]
    fn rejects_uri_above_size_limit() {
        let input = vec![b'a'; MAX_URI_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_URI_BYTES + 1,
                maximum: MAX_URI_BYTES,
            })
        );
    }

    #[test]
    fn parses_from_str() {
        let Ok(uri) = parse_str("sip:alice@example.com") else {
            panic!("expected valid SIP URI");
        };

        assert_eq!(uri.to_string(), "sip:alice@example.com");
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");
        assert_eq!(ParseError::MissingHost.class(), "missing-host");
        assert_eq!(ParseError::InvalidUserInfo.class(), "invalid-userinfo");
        assert_eq!(ParseError::InvalidPort.class(), "invalid-port");
        assert_eq!(
            ParseError::DuplicateParameter.class(),
            "duplicate-parameter"
        );
        assert_eq!(
            ParseError::InvalidAbsoluteUri.class(),
            "invalid-absolute-uri"
        );
    }

    #[test]
    fn rfc_example_round_trips() {
        let input = "sips:alice@atlanta.com?subject=project%20x&priority=urgent";

        let Ok(uri) = parse_str(input) else {
            panic!("expected RFC-style URI to parse");
        };

        assert_eq!(uri.to_string(), input);
    }

    #[test]
    fn user_parameter_example_round_trips() {
        let input = "sip:+1-212-555-1212:1234@gateway.com;user=phone";

        let Ok(uri) = parse_str(input) else {
            panic!("expected telephone-style SIP URI");
        };

        assert_eq!(uri.to_string(), input);
    }

    #[test]
    fn host_only_uri_with_method_and_header_round_trips() {
        let input = "sip:atlanta.com;method=REGISTER?to=alice%40atlanta.com";

        let Ok(uri) = parse_str(input) else {
            panic!("expected host-only SIP URI");
        };

        assert_eq!(uri.to_string(), input);
    }

    #[test]
    fn uri_enum_variant_is_correct() {
        let Ok(sip) = parse(b"sip:example.com") else {
            panic!("expected SIP URI");
        };

        let Ok(absolute) = parse(b"tel:+966555123456") else {
            panic!("expected absolute URI");
        };

        assert!(matches!(sip, Uri::Sip(_)));
        assert!(matches!(absolute, Uri::Absolute(_)));
    }
}
