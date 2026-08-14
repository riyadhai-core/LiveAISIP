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

//! SIP `Session-Expires` header.
//!
//! This module provides strongly typed parsing and serialization for SIP
//! `Session-Expires` field values.
//!
//! A Session-Expires value contains a decimal session interval followed by
//! zero or more semicolon-delimited parameters. The standard `refresher`
//! parameter identifies whether the UAC or UAS is responsible for refreshing
//! the session.
//!
//! Generic parameters preserve wire order and validated logical values.
//! Parameter names are unique case-insensitively to prevent ambiguous
//! interpretation.
//!
//! The standalone parser validates field-value syntax. Session-timer policy,
//! request/response placement, negotiated minimums, and refresh scheduling
//! belong to higher SIP dialog and transaction layers.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::sip::types::uri::Host;

/// Maximum accepted SIP `Session-Expires` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_SESSION_EXPIRES_BYTES: usize = 8 * 1024;

/// Maximum number of parameters accepted in one Session-Expires field value.
pub const MAX_SESSION_EXPIRES_PARAMETERS: usize = 64;

/// Maximum accepted generic parameter-name size in bytes.
pub const MAX_SESSION_EXPIRES_PARAMETER_NAME_BYTES: usize = 256;

/// Maximum accepted generic parameter-value size in bytes.
pub const MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES: usize = 1024;

/// Absolute protocol minimum session interval in seconds.
pub const MIN_SESSION_INTERVAL_SECONDS: u32 = 90;

/// Recommended session interval in seconds.
pub const RECOMMENDED_SESSION_INTERVAL_SECONDS: u32 = 1800;

/// A validated SIP `Session-Expires` field value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionExpires {
    delta_seconds: u32,
    parameters: Vec<SessionExpiresParameter>,
}

impl SessionExpires {
    /// Creates a Session-Expires value without parameters.
    ///
    /// This constructor accepts the full syntactic `u32` range. Protocol
    /// policy requiring at least [`MIN_SESSION_INTERVAL_SECONDS`] belongs to
    /// session-timer validation.
    #[must_use]
    pub const fn new(delta_seconds: u32) -> Self {
        Self {
            delta_seconds,
            parameters: Vec::new(),
        }
    }

    /// Creates a Session-Expires value with a `refresher` parameter.
    #[must_use]
    pub fn with_refresher(delta_seconds: u32, refresher: Refresher) -> Self {
        Self {
            delta_seconds,
            parameters: vec![SessionExpiresParameter::Refresher(refresher)],
        }
    }

    /// Creates a Session-Expires value from validated components.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when parameters are duplicated, the parameter
    /// count exceeds its bound, or the canonical serialized value exceeds the
    /// field-value size bound.
    pub fn from_parts(
        delta_seconds: u32,
        parameters: Vec<SessionExpiresParameter>,
    ) -> Result<Self, ParseError> {
        let mut value = Self::new(delta_seconds);

        for parameter in parameters {
            value.push_parameter(parameter)?;
        }

        Ok(value)
    }

    /// Parses a SIP `Session-Expires` field value from wire bytes.
    ///
    /// Header-name and `HCOLON` parsing are outside this function.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the interval, parameter syntax, refresher
    /// value, quoted text, or an operational bound is invalid.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns the session interval in seconds.
    #[must_use]
    pub const fn delta_seconds(&self) -> u32 {
        self.delta_seconds
    }

    /// Replaces the session interval.
    ///
    /// The update is transactional: if the resulting canonical field value
    /// would exceed [`MAX_SESSION_EXPIRES_BYTES`], the existing interval
    /// remains unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooLong`] when changing the interval would cause
    /// the serialized Session-Expires value to exceed its operational size
    /// bound.
    pub fn set_delta_seconds(&mut self, delta_seconds: u32) -> Result<(), ParseError> {
        let current_length = self.to_string().len();
        let current_delta_length = decimal_length(self.delta_seconds);
        let new_delta_length = decimal_length(delta_seconds);

        let length = current_length
            .saturating_sub(current_delta_length)
            .saturating_add(new_delta_length);

        if length > MAX_SESSION_EXPIRES_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_SESSION_EXPIRES_BYTES,
            });
        }

        self.delta_seconds = delta_seconds;
        Ok(())
    }

    /// Returns whether the interval satisfies the protocol minimum.
    #[must_use]
    pub const fn meets_protocol_minimum(&self) -> bool {
        self.delta_seconds >= MIN_SESSION_INTERVAL_SECONDS
    }

    /// Returns whether the interval is at least the recommended value.
    #[must_use]
    pub const fn meets_recommended_interval(&self) -> bool {
        self.delta_seconds >= RECOMMENDED_SESSION_INTERVAL_SECONDS
    }

    /// Returns all Session-Expires parameters in wire order.
    #[must_use]
    pub fn parameters(&self) -> &[SessionExpiresParameter] {
        &self.parameters
    }

    /// Returns the `refresher` parameter when present.
    #[must_use]
    pub fn refresher(&self) -> Option<Refresher> {
        self.parameters
            .iter()
            .find_map(|parameter| match parameter {
                SessionExpiresParameter::Refresher(refresher) => Some(*refresher),
                SessionExpiresParameter::Extension(_) => None,
            })
    }

    /// Returns the first generic parameter with the requested
    /// case-insensitive name.
    #[must_use]
    pub fn extension_parameter(&self, name: &str) -> Option<&SessionExpiresExtensionParameter> {
        self.parameters
            .iter()
            .find_map(|parameter| match parameter {
                SessionExpiresParameter::Extension(extension)
                    if extension.name().eq_ignore_ascii_case(name) =>
                {
                    Some(extension)
                }
                _ => None,
            })
    }

    /// Replaces or adds the `refresher` parameter.
    ///
    /// Existing parameter ordering is preserved when replacing the value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyParameters`] or [`ParseError::TooLong`]
    /// when adding a new refresher would violate an operational bound.
    pub fn set_refresher(&mut self, refresher: Refresher) -> Result<(), ParseError> {
        if let Some(parameter) = self
            .parameters
            .iter_mut()
            .find(|parameter| matches!(parameter, SessionExpiresParameter::Refresher(_)))
        {
            *parameter = SessionExpiresParameter::Refresher(refresher);
            return Ok(());
        }

        self.push_parameter(SessionExpiresParameter::Refresher(refresher))
    }

    /// Removes the `refresher` parameter when present.
    pub fn clear_refresher(&mut self) {
        self.parameters
            .retain(|parameter| !matches!(parameter, SessionExpiresParameter::Refresher(_)));
    }

    /// Adds a Session-Expires parameter.
    ///
    /// Parameter names are unique case-insensitively.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::DuplicateParameter`] when the parameter already
    /// exists, [`ParseError::TooManyParameters`] when the parameter-count
    /// bound is reached, or [`ParseError::TooLong`] when the resulting
    /// canonical field value would exceed its size bound.
    pub fn push_parameter(&mut self, parameter: SessionExpiresParameter) -> Result<(), ParseError> {
        if self.parameters.len() >= MAX_SESSION_EXPIRES_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_SESSION_EXPIRES_PARAMETERS,
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

        let parameter_length = parameter.to_string().len();
        let length = self
            .to_string()
            .len()
            .saturating_add(1)
            .saturating_add(parameter_length);

        if length > MAX_SESSION_EXPIRES_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_SESSION_EXPIRES_BYTES,
            });
        }

        self.parameters.push(parameter);
        Ok(())
    }

    /// Returns the number of Session-Expires parameters.
    #[must_use]
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Consumes the value into its interval and ordered parameters.
    #[must_use]
    pub fn into_parts(self) -> (u32, Vec<SessionExpiresParameter>) {
        (self.delta_seconds, self.parameters)
    }
}

impl fmt::Display for SessionExpires {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.delta_seconds)?;

        for parameter in &self.parameters {
            write!(formatter, ";{parameter}")?;
        }

        Ok(())
    }
}

impl FromStr for SessionExpires {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// Entity responsible for refreshing a SIP session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Refresher {
    /// User Agent Client refreshes the session.
    Uac,

    /// User Agent Server refreshes the session.
    Uas,
}

impl Refresher {
    /// Parses a Session-Expires refresher value.
    ///
    /// Parsing is ASCII case-insensitive.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidRefresher`] unless the value is `uac` or
    /// `uas`.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.eq_ignore_ascii_case(b"uac") {
            Ok(Self::Uac)
        } else if input.eq_ignore_ascii_case(b"uas") {
            Ok(Self::Uas)
        } else {
            Err(ParseError::InvalidRefresher)
        }
    }

    /// Returns the canonical lowercase refresher value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uac => "uac",
            Self::Uas => "uas",
        }
    }

    /// Returns whether the UAC is responsible for refreshing.
    #[must_use]
    pub const fn is_uac(self) -> bool {
        matches!(self, Self::Uac)
    }

    /// Returns whether the UAS is responsible for refreshing.
    #[must_use]
    pub const fn is_uas(self) -> bool {
        matches!(self, Self::Uas)
    }
}

impl fmt::Display for Refresher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Refresher {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// A typed Session-Expires parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SessionExpiresParameter {
    /// Standard `refresher=uac|uas` parameter.
    Refresher(Refresher),

    /// Generic Session-Expires extension parameter.
    Extension(SessionExpiresExtensionParameter),
}

impl SessionExpiresParameter {
    /// Returns the case-insensitive parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Refresher(_) => "refresher",
            Self::Extension(parameter) => parameter.name(),
        }
    }
}

impl fmt::Display for SessionExpiresParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refresher(refresher) => write!(formatter, "refresher={refresher}"),
            Self::Extension(parameter) => fmt::Display::fmt(parameter, formatter),
        }
    }
}

/// A validated generic Session-Expires parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionExpiresExtensionParameter {
    name: Box<str>,
    value: Option<SessionExpiresExtensionValue>,
}

impl SessionExpiresExtensionParameter {
    /// Creates a valueless extension parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the parameter name is invalid, reserved, or
    /// exceeds its operational size limit.
    pub fn flag(name: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let name = name.into();
        validate_extension_name(name.as_bytes())?;

        Ok(Self { name, value: None })
    }

    /// Creates a token-valued extension parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or value is invalid or exceeds an
    /// operational size limit.
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
            value: Some(SessionExpiresExtensionValue::Token(value)),
        })
    }

    /// Creates a host-valued extension parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the parameter name is invalid, reserved, or
    /// exceeds its operational size limit.
    pub fn host(name: impl Into<Box<str>>, host: Host) -> Result<Self, ParseError> {
        let name = name.into();
        validate_extension_name(name.as_bytes())?;

        Ok(Self {
            name,
            value: Some(SessionExpiresExtensionValue::Host(host)),
        })
    }

    /// Creates a quoted extension parameter.
    ///
    /// The supplied value is logical text without surrounding quotation marks.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or value is invalid or exceeds an
    /// operational size limit.
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
            value: Some(SessionExpiresExtensionValue::Quoted(value)),
        })
    }

    /// Returns the parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional typed parameter value.
    #[must_use]
    pub const fn value(&self) -> Option<&SessionExpiresExtensionValue> {
        self.value.as_ref()
    }

    /// Returns whether this is a valueless parameter.
    #[must_use]
    pub const fn is_flag(&self) -> bool {
        self.value.is_none()
    }
}

impl fmt::Display for SessionExpiresExtensionParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)?;

        let Some(value) = &self.value else {
            return Ok(());
        };

        formatter.write_char('=')?;
        fmt::Display::fmt(value, formatter)
    }
}

/// Typed generic Session-Expires extension value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SessionExpiresExtensionValue {
    /// SIP token value.
    Token(Box<str>),

    /// SIP host value.
    Host(Host),

    /// Logical quoted-string value.
    Quoted(Box<str>),
}

impl SessionExpiresExtensionValue {
    /// Returns a borrowed textual value when directly available.
    ///
    /// Structurally stored host values return `None`.
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

impl fmt::Display for SessionExpiresExtensionValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(value) => formatter.write_str(value),
            Self::Host(host) => fmt::Display::fmt(host, formatter),
            Self::Quoted(value) => write_quoted(formatter, value),
        }
    }
}

/// Parses a SIP `Session-Expires` field value.
///
/// # Errors
///
/// Returns [`ParseError`] when the field value violates Session-Expires syntax
/// or an operational bound.
pub fn parse(input: &[u8]) -> Result<SessionExpires, ParseError> {
    if input.len() > MAX_SESSION_EXPIRES_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_SESSION_EXPIRES_BYTES,
        });
    }

    if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ParseError::InvalidLineBreak);
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    let (delta_seconds, remaining) = parse_delta_seconds(input)?;
    let mut session_expires = SessionExpires::new(delta_seconds);

    parse_parameters(&mut session_expires, remaining)?;

    Ok(session_expires)
}

fn parse_delta_seconds(input: &[u8]) -> Result<(u32, &[u8]), ParseError> {
    let digit_count = input
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();

    if digit_count == 0 {
        return Err(ParseError::InvalidDeltaSeconds);
    }

    let mut value = 0_u32;

    for byte in input[..digit_count].iter().copied() {
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u32::from(byte - b'0')))
            .ok_or(ParseError::DeltaSecondsOverflow)?;
    }

    Ok((value, &input[digit_count..]))
}

fn parse_parameters(
    session_expires: &mut SessionExpires,
    mut input: &[u8],
) -> Result<(), ParseError> {
    loop {
        input = trim_lws_start(input);

        if input.is_empty() {
            return Ok(());
        }

        if input[0] != b';' {
            return Err(ParseError::UnexpectedTrailingData { byte: input[0] });
        }

        input = trim_lws_start(&input[1..]);

        if input.is_empty() {
            return Err(ParseError::EmptyParameter);
        }

        if session_expires.parameter_count() >= MAX_SESSION_EXPIRES_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_SESSION_EXPIRES_PARAMETERS,
            });
        }

        let (name, remaining) = parse_parameter_name(input)?;
        input = trim_lws_start(remaining);

        let (parameter, remaining) = parse_parameter(name, input)?;
        session_expires.push_parameter(parameter)?;
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

    if end > MAX_SESSION_EXPIRES_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: end,
            maximum: MAX_SESSION_EXPIRES_PARAMETER_NAME_BYTES,
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
) -> Result<(SessionExpiresParameter, &'a [u8]), ParseError> {
    if name.eq_ignore_ascii_case("refresher") {
        return parse_refresher_parameter(input);
    }

    parse_extension_parameter(name, input)
}

fn parse_refresher_parameter(input: &[u8]) -> Result<(SessionExpiresParameter, &[u8]), ParseError> {
    let value = require_parameter_value(input)?;
    let (value, remaining) = take_unquoted_value(value)?;
    let refresher = Refresher::from_bytes(value)?;

    Ok((SessionExpiresParameter::Refresher(refresher), remaining))
}

fn parse_extension_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(SessionExpiresParameter, &'a [u8]), ParseError> {
    validate_extension_name(name.as_bytes())?;

    let input = trim_lws_start(input);

    if input.is_empty() || input[0] == b';' {
        let parameter = SessionExpiresExtensionParameter::flag(name)?;

        return Ok((SessionExpiresParameter::Extension(parameter), input));
    }

    if input[0] != b'=' {
        return Err(ParseError::InvalidParameterSeparator { byte: input[0] });
    }

    let input = trim_lws_start(&input[1..]);

    if input.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    if input[0] == b'"' {
        return parse_quoted_extension_parameter(name, input);
    }

    parse_unquoted_extension_parameter(name, input)
}

fn parse_quoted_extension_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(SessionExpiresParameter, &'a [u8]), ParseError> {
    let (value, consumed) = parse_quoted_value(input)?;
    let remaining = trim_lws_start(&input[consumed..]);

    if !remaining.is_empty() && remaining[0] != b';' {
        return Err(ParseError::UnexpectedTrailingData { byte: remaining[0] });
    }

    let parameter = SessionExpiresExtensionParameter::quoted(name, value)?;

    Ok((SessionExpiresParameter::Extension(parameter), remaining))
}

fn parse_unquoted_extension_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(SessionExpiresParameter, &'a [u8]), ParseError> {
    let (value, remaining) = take_unquoted_value(input)?;

    if value.iter().copied().all(is_token_byte) {
        let value = std::str::from_utf8(value).map_err(|_| ParseError::InvalidExtensionValue {
            index: 0,
            byte: value[0],
        })?;

        let parameter = SessionExpiresExtensionParameter::token(name, value)?;

        return Ok((SessionExpiresParameter::Extension(parameter), remaining));
    }

    if let Ok(host) = parse_host(value) {
        let parameter = SessionExpiresExtensionParameter::host(name, host)?;

        return Ok((SessionExpiresParameter::Extension(parameter), remaining));
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

        if decoded.len() > MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES {
            return Err(ParseError::ParameterValueTooLong {
                length: decoded.len(),
                maximum: MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES,
            });
        }
    }

    Err(ParseError::InvalidQuotedString)
}

fn parse_host(input: &[u8]) -> Result<Host, ()> {
    if input.is_empty() {
        return Err(());
    }

    if input.first() == Some(&b'[') {
        if input.len() < 3 || input.last() != Some(&b']') {
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

fn validate_extension_name(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyParameter);
    }

    if input.len() > MAX_SESSION_EXPIRES_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: input.len(),
            maximum: MAX_SESSION_EXPIRES_PARAMETER_NAME_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidParameterName { index, byte });
        }
    }

    if input.eq_ignore_ascii_case(b"refresher") {
        return Err(ParseError::ReservedParameterName);
    }

    Ok(())
}

fn validate_extension_token_value(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    if input.len() > MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES,
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
    if input.len() > MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES,
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

fn write_quoted(formatter: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
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

const fn decimal_length(value: u32) -> usize {
    match value {
        0..=9 => 1,
        10..=99 => 2,
        100..=999 => 3,
        1_000..=9_999 => 4,
        10_000..=99_999 => 5,
        100_000..=999_999 => 6,
        1_000_000..=9_999_999 => 7,
        10_000_000..=99_999_999 => 8,
        100_000_000..=999_999_999 => 9,
        _ => 10,
    }
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

/// Failure to parse or construct a SIP `Session-Expires` value.
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

    /// A CR or LF appeared inside the field value.
    InvalidLineBreak,

    /// The session interval was missing or was not decimal.
    InvalidDeltaSeconds,

    /// The session interval exceeded `u32`.
    DeltaSecondsOverflow,

    /// Unexpected data followed a valid Session-Expires component.
    UnexpectedTrailingData {
        /// First unexpected byte.
        byte: u8,
    },

    /// A Session-Expires parameter was empty.
    EmptyParameter,

    /// A parameter name was invalid.
    InvalidParameterName {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A parameter name exceeded its operational size limit.
    ParameterNameTooLong {
        /// Actual parameter-name length in bytes.
        length: usize,

        /// Maximum accepted parameter-name length in bytes.
        maximum: usize,
    },

    /// The special `refresher` name was supplied through the extension API.
    ReservedParameterName,

    /// A parameter separator was invalid.
    InvalidParameterSeparator {
        /// Unexpected byte.
        byte: u8,
    },

    /// A parameter requiring a value did not contain one.
    MissingParameterValue,

    /// The `refresher` value was neither `uac` nor `uas`.
    InvalidRefresher,

    /// A generic extension parameter value was invalid.
    InvalidExtensionValue {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A quoted-string parameter was malformed.
    InvalidQuotedString,

    /// A generic parameter value exceeded its operational size limit.
    ParameterValueTooLong {
        /// Actual value length in bytes.
        length: usize,

        /// Maximum accepted value length in bytes.
        maximum: usize,
    },

    /// A parameter name appeared more than once.
    DuplicateParameter,

    /// The field exceeded the bounded parameter count.
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
            Self::InvalidLineBreak => "invalid-line-break",
            Self::InvalidDeltaSeconds => "invalid-delta-seconds",
            Self::DeltaSecondsOverflow => "delta-seconds-overflow",
            Self::UnexpectedTrailingData { .. } => "unexpected-trailing-data",
            Self::EmptyParameter => "empty-parameter",
            Self::InvalidParameterName { .. } => "invalid-parameter-name",
            Self::ParameterNameTooLong { .. } => "parameter-name-too-long",
            Self::ReservedParameterName => "reserved-parameter-name",
            Self::InvalidParameterSeparator { .. } => "invalid-parameter-separator",
            Self::MissingParameterValue => "missing-parameter-value",
            Self::InvalidRefresher => "invalid-refresher",
            Self::InvalidExtensionValue { .. } => "invalid-extension-value",
            Self::InvalidQuotedString => "invalid-quoted-string",
            Self::ParameterValueTooLong { .. } => "parameter-value-too-long",
            Self::DuplicateParameter => "duplicate-parameter",
            Self::TooManyParameters { .. } => "too-many-parameters",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP Session-Expires field value is empty"),
            Self::TooLong { length, maximum } => write_limit(
                formatter,
                "SIP Session-Expires field-value",
                *length,
                *maximum,
            ),
            Self::InvalidLineBreak => {
                formatter.write_str("SIP Session-Expires contains an invalid line break")
            }
            Self::InvalidDeltaSeconds => {
                formatter.write_str("SIP Session-Expires delta-seconds value is invalid")
            }
            Self::DeltaSecondsOverflow => {
                formatter.write_str("SIP Session-Expires delta-seconds value exceeds u32")
            }
            Self::UnexpectedTrailingData { byte } => write!(
                formatter,
                "unexpected byte 0x{byte:02x} follows SIP Session-Expires content"
            ),
            Self::EmptyParameter => formatter.write_str("SIP Session-Expires parameter is empty"),
            Self::InvalidParameterName { index, byte } => write_invalid_byte(
                formatter,
                "SIP Session-Expires parameter-name",
                *index,
                *byte,
            ),
            Self::ParameterNameTooLong { length, maximum } => write_limit(
                formatter,
                "SIP Session-Expires parameter-name",
                *length,
                *maximum,
            ),
            Self::ReservedParameterName => {
                formatter.write_str("SIP Session-Expires parameter name is reserved")
            }
            Self::InvalidParameterSeparator { byte } => write!(
                formatter,
                "invalid SIP Session-Expires parameter separator byte 0x{byte:02x}"
            ),
            Self::MissingParameterValue => {
                formatter.write_str("SIP Session-Expires parameter value is missing")
            }
            Self::InvalidRefresher => {
                formatter.write_str("SIP Session-Expires refresher value is invalid")
            }
            Self::InvalidExtensionValue { index, byte } => write_invalid_byte(
                formatter,
                "SIP Session-Expires extension value",
                *index,
                *byte,
            ),
            Self::InvalidQuotedString => {
                formatter.write_str("SIP Session-Expires quoted string is invalid")
            }
            Self::ParameterValueTooLong { length, maximum } => write_limit(
                formatter,
                "SIP Session-Expires parameter-value",
                *length,
                *maximum,
            ),
            Self::DuplicateParameter => {
                formatter.write_str("SIP Session-Expires parameter name is duplicated")
            }
            Self::TooManyParameters { maximum } => write!(
                formatter,
                "SIP Session-Expires contains more than {maximum} parameters"
            ),
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
        MAX_SESSION_EXPIRES_BYTES, MAX_SESSION_EXPIRES_PARAMETER_NAME_BYTES,
        MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES, MAX_SESSION_EXPIRES_PARAMETERS,
        MIN_SESSION_INTERVAL_SECONDS, ParseError, RECOMMENDED_SESSION_INTERVAL_SECONDS, Refresher,
        SessionExpires, SessionExpiresExtensionParameter, SessionExpiresExtensionValue,
        SessionExpiresParameter, parse,
    };
    use std::str::FromStr;

    #[test]
    fn parses_basic_session_interval() {
        let Ok(value) = parse(b"3600") else {
            panic!("expected valid Session-Expires");
        };

        assert_eq!(value.delta_seconds(), 3600);
        assert_eq!(value.refresher(), None);
        assert!(value.parameters().is_empty());
    }

    #[test]
    fn parses_zero_syntactically() {
        let Ok(value) = parse(b"0") else {
            panic!("expected syntactically valid zero interval");
        };

        assert_eq!(value.delta_seconds(), 0);
        assert!(!value.meets_protocol_minimum());
    }

    #[test]
    fn parses_protocol_minimum() {
        let Ok(value) = parse(b"90") else {
            panic!("expected protocol-minimum interval");
        };

        assert_eq!(value.delta_seconds(), MIN_SESSION_INTERVAL_SECONDS);
        assert!(value.meets_protocol_minimum());
    }

    #[test]
    fn recommended_interval_constant_is_1800_seconds() {
        assert_eq!(RECOMMENDED_SESSION_INTERVAL_SECONDS, 1800);

        let value = SessionExpires::new(RECOMMENDED_SESSION_INTERVAL_SECONDS);

        assert!(value.meets_recommended_interval());
    }

    #[test]
    fn accepts_maximum_u32_interval() {
        let Ok(value) = parse(b"4294967295") else {
            panic!("expected maximum u32 interval");
        };

        assert_eq!(value.delta_seconds(), u32::MAX);
    }

    #[test]
    fn canonicalizes_leading_zeroes() {
        let Ok(value) = parse(b"00003600") else {
            panic!("expected interval with leading zeroes");
        };

        assert_eq!(value.delta_seconds(), 3600);
        assert_eq!(value.to_string(), "3600");
    }

    #[test]
    fn parses_uac_refresher() {
        let Ok(value) = parse(b"3600;refresher=uac") else {
            panic!("expected UAC refresher");
        };

        assert_eq!(value.refresher(), Some(Refresher::Uac));
        assert!(value.refresher().is_some_and(Refresher::is_uac));
    }

    #[test]
    fn parses_uas_refresher() {
        let Ok(value) = parse(b"3600;refresher=uas") else {
            panic!("expected UAS refresher");
        };

        assert_eq!(value.refresher(), Some(Refresher::Uas));
        assert!(value.refresher().is_some_and(Refresher::is_uas));
    }

    #[test]
    fn refresher_name_and_value_are_case_insensitive() {
        let Ok(first) = parse(b"3600;REFRESHER=UaC") else {
            panic!("expected case-insensitive UAC refresher");
        };

        let Ok(second) = parse(b"3600;ReFrEsHeR=UaS") else {
            panic!("expected case-insensitive UAS refresher");
        };

        assert_eq!(first.refresher(), Some(Refresher::Uac));
        assert_eq!(second.refresher(), Some(Refresher::Uas));
        assert_eq!(first.to_string(), "3600;refresher=uac");
        assert_eq!(second.to_string(), "3600;refresher=uas");
    }

    #[test]
    fn parses_generic_flag_parameter() {
        let Ok(value) = parse(b"3600;x-feature") else {
            panic!("expected generic flag parameter");
        };

        let Some(parameter) = value.extension_parameter("x-feature") else {
            panic!("expected extension parameter");
        };

        assert!(parameter.is_flag());
    }

    #[test]
    fn parses_generic_token_parameter() {
        let Ok(value) = parse(b"3600;x-mode=active") else {
            panic!("expected token extension parameter");
        };

        assert_eq!(
            value
                .extension_parameter("x-mode")
                .and_then(SessionExpiresExtensionParameter::value)
                .and_then(SessionExpiresExtensionValue::as_str),
            Some("active")
        );
    }

    #[test]
    fn parses_generic_ipv6_host_parameter() {
        let Ok(value) = parse(b"3600;x-host=[2001:db8::1]") else {
            panic!("expected IPv6 host extension parameter");
        };

        assert!(matches!(
            value
                .extension_parameter("x-host")
                .and_then(SessionExpiresExtensionParameter::value),
            Some(SessionExpiresExtensionValue::Host(_))
        ));
    }

    #[test]
    fn parses_quoted_parameter() {
        let Ok(value) = parse(b"3600;x-note=\"voice gateway\"") else {
            panic!("expected quoted parameter");
        };

        assert_eq!(
            value
                .extension_parameter("x-note")
                .and_then(SessionExpiresExtensionParameter::value)
                .and_then(SessionExpiresExtensionValue::as_str),
            Some("voice gateway")
        );
    }

    #[test]
    fn quoted_parameter_may_contain_semicolon() {
        let Ok(value) = parse(b"3600;x-note=\"one;two\";refresher=uac") else {
            panic!("expected semicolon inside quoted value");
        };

        assert_eq!(
            value
                .extension_parameter("x-note")
                .and_then(SessionExpiresExtensionParameter::value)
                .and_then(SessionExpiresExtensionValue::as_str),
            Some("one;two")
        );

        assert_eq!(value.refresher(), Some(Refresher::Uac));
    }

    #[test]
    fn quoted_parameter_unescapes_quote_and_backslash() {
        let Ok(value) = parse(b"3600;x-note=\"A \\\"B\\\" \\\\ C\"") else {
            panic!("expected quoted escapes");
        };

        assert_eq!(
            value
                .extension_parameter("x-note")
                .and_then(SessionExpiresExtensionParameter::value)
                .and_then(SessionExpiresExtensionValue::as_str),
            Some("A \"B\" \\ C")
        );
    }

    #[test]
    fn accepts_whitespace_around_parameter_delimiters() {
        let Ok(value) = parse(b"3600 \t; \trefresher \t= \tUaC \t; x-mode = active") else {
            panic!("expected delimiter whitespace");
        };

        assert_eq!(value.refresher(), Some(Refresher::Uac));

        assert_eq!(
            value
                .extension_parameter("x-mode")
                .and_then(SessionExpiresExtensionParameter::value)
                .and_then(SessionExpiresExtensionValue::as_str),
            Some("active")
        );

        assert_eq!(value.to_string(), "3600;refresher=uac;x-mode=active");
    }

    #[test]
    fn preserves_parameter_order() {
        let Ok(value) = parse(b"3600;x-first=1;refresher=uas;x-last=2") else {
            panic!("expected ordered parameters");
        };

        assert_eq!(value.parameters().len(), 3);

        assert!(matches!(
            value.parameters()[0],
            SessionExpiresParameter::Extension(_)
        ));

        assert!(matches!(
            value.parameters()[1],
            SessionExpiresParameter::Refresher(Refresher::Uas)
        ));

        assert!(matches!(
            value.parameters()[2],
            SessionExpiresParameter::Extension(_)
        ));
    }

    #[test]
    fn rejects_duplicate_refresher() {
        assert_eq!(
            parse(b"3600;refresher=uac;REFRESHER=uas"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn rejects_duplicate_extension_parameter_case_insensitively() {
        assert_eq!(
            parse(b"3600;X-Mode=one;x-mode=two"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn rejects_empty_field() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b" \t "), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_non_decimal_interval() {
        assert_eq!(parse(b"abc"), Err(ParseError::InvalidDeltaSeconds));
    }

    #[test]
    fn rejects_negative_interval() {
        assert_eq!(parse(b"-1"), Err(ParseError::InvalidDeltaSeconds));
    }

    #[test]
    fn rejects_delta_seconds_overflow() {
        assert_eq!(parse(b"4294967296"), Err(ParseError::DeltaSecondsOverflow));
    }

    #[test]
    fn rejects_unexpected_data_after_interval() {
        assert_eq!(
            parse(b"3600x"),
            Err(ParseError::UnexpectedTrailingData { byte: b'x' })
        );
    }

    #[test]
    fn rejects_empty_parameter() {
        assert_eq!(parse(b"3600;"), Err(ParseError::EmptyParameter));
    }

    #[test]
    fn rejects_invalid_parameter_name() {
        assert_eq!(
            parse(b"3600;@bad=value"),
            Err(ParseError::InvalidParameterName {
                index: 0,
                byte: b'@',
            })
        );
    }

    #[test]
    fn rejects_invalid_parameter_separator() {
        assert_eq!(
            parse(b"3600;x-mode active"),
            Err(ParseError::InvalidParameterSeparator { byte: b'a' })
        );
    }

    #[test]
    fn rejects_refresher_without_value() {
        assert_eq!(
            parse(b"3600;refresher"),
            Err(ParseError::MissingParameterValue)
        );
    }

    #[test]
    fn rejects_invalid_refresher() {
        assert_eq!(
            parse(b"3600;refresher=invalid"),
            Err(ParseError::InvalidRefresher)
        );
    }

    #[test]
    fn rejects_quoted_refresher() {
        assert_eq!(
            parse(b"3600;refresher=\"uac\""),
            Err(ParseError::InvalidRefresher)
        );
    }

    #[test]
    fn rejects_unterminated_quoted_parameter() {
        assert_eq!(
            parse(b"3600;x-note=\"unfinished"),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn rejects_crlf_in_field() {
        assert_eq!(
            parse(b"3600;\r\nrefresher=uac"),
            Err(ParseError::InvalidLineBreak)
        );
    }

    #[test]
    fn rejects_field_above_size_limit() {
        let input = vec![b'a'; MAX_SESSION_EXPIRES_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_SESSION_EXPIRES_BYTES + 1,
                maximum: MAX_SESSION_EXPIRES_BYTES,
            })
        );
    }

    #[test]
    fn refresher_parses_from_str() {
        let Ok(uac) = Refresher::from_str("UAC") else {
            panic!("expected UAC refresher");
        };

        let Ok(uas) = Refresher::from_str("uas") else {
            panic!("expected UAS refresher");
        };

        assert_eq!(uac, Refresher::Uac);
        assert_eq!(uas, Refresher::Uas);
    }

    #[test]
    fn constructor_creates_value_without_parameters() {
        let value = SessionExpires::new(3600);

        assert_eq!(value.delta_seconds(), 3600);
        assert!(value.parameters().is_empty());
    }

    #[test]
    fn refresher_constructor_creates_typed_parameter() {
        let value = SessionExpires::with_refresher(3600, Refresher::Uac);

        assert_eq!(value.refresher(), Some(Refresher::Uac));
        assert_eq!(value.to_string(), "3600;refresher=uac");
    }

    #[test]
    fn set_delta_seconds_replaces_interval() {
        let mut value = SessionExpires::new(1800);

        assert!(value.set_delta_seconds(3600).is_ok());

        assert_eq!(value.delta_seconds(), 3600);
    }

    #[test]
    fn set_delta_seconds_accepts_larger_value_within_size_limit() {
        let mut value = SessionExpires::new(90);

        assert!(value.set_delta_seconds(u32::MAX).is_ok());

        assert_eq!(value.delta_seconds(), u32::MAX);
        assert_eq!(value.to_string(), "4294967295");
    }

    #[test]
    fn set_delta_seconds_rejects_serialized_size_overflow() {
        let mut parameters = Vec::new();

        for index in 0..7 {
            let name = format!("x{index}");
            let parameter_value = "a".repeat(MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES);

            let Ok(parameter) = SessionExpiresExtensionParameter::token(name, parameter_value)
            else {
                panic!("expected valid maximum-sized extension parameter");
            };

            parameters.push(SessionExpiresParameter::Extension(parameter));
        }

        let final_value = "a".repeat(983);

        let Ok(final_parameter) = SessionExpiresExtensionParameter::token("x7", final_value) else {
            panic!("expected valid final extension parameter");
        };

        parameters.push(SessionExpiresParameter::Extension(final_parameter));

        let Ok(mut value) = SessionExpires::from_parts(0, parameters) else {
            panic!("expected valid Session-Expires value near field-size limit");
        };

        assert_eq!(value.to_string().len(), MAX_SESSION_EXPIRES_BYTES - 8);

        assert_eq!(
            value.set_delta_seconds(u32::MAX),
            Err(ParseError::TooLong {
                length: MAX_SESSION_EXPIRES_BYTES + 1,
                maximum: MAX_SESSION_EXPIRES_BYTES,
            })
        );

        assert_eq!(value.delta_seconds(), 0);
        assert_eq!(value.to_string().len(), MAX_SESSION_EXPIRES_BYTES - 8);
    }

    #[test]
    fn set_refresher_adds_and_replaces_without_duplication() {
        let mut value = SessionExpires::new(3600);

        assert!(value.set_refresher(Refresher::Uac).is_ok());
        assert!(value.set_refresher(Refresher::Uas).is_ok());

        assert_eq!(value.refresher(), Some(Refresher::Uas));
        assert_eq!(value.parameter_count(), 1);
    }

    #[test]
    fn clear_refresher_removes_only_refresher() {
        let Ok(extension) = SessionExpiresExtensionParameter::token("x-mode", "active") else {
            panic!("expected extension parameter");
        };

        let mut value = SessionExpires::with_refresher(3600, Refresher::Uac);

        assert!(
            value
                .push_parameter(SessionExpiresParameter::Extension(extension))
                .is_ok()
        );

        value.clear_refresher();

        assert_eq!(value.refresher(), None);
        assert_eq!(value.parameter_count(), 1);
        assert!(value.extension_parameter("x-mode").is_some());
    }

    #[test]
    fn creates_extension_flag() {
        let Ok(parameter) = SessionExpiresExtensionParameter::flag("x-feature") else {
            panic!("expected extension flag");
        };

        assert!(parameter.is_flag());
        assert_eq!(parameter.to_string(), "x-feature");
    }

    #[test]
    fn creates_extension_token() {
        let Ok(parameter) = SessionExpiresExtensionParameter::token("x-mode", "active") else {
            panic!("expected extension token");
        };

        assert_eq!(parameter.to_string(), "x-mode=active");
    }

    #[test]
    fn creates_extension_quoted_value() {
        let Ok(parameter) = SessionExpiresExtensionParameter::quoted("x-note", "voice gateway")
        else {
            panic!("expected quoted extension");
        };

        assert_eq!(parameter.to_string(), "x-note=\"voice gateway\"");
    }

    #[test]
    fn extension_api_rejects_reserved_refresher_name() {
        assert_eq!(
            SessionExpiresExtensionParameter::flag("REFRESHER"),
            Err(ParseError::ReservedParameterName)
        );
    }

    #[test]
    fn rejects_extension_name_above_size_limit() {
        let name = "a".repeat(MAX_SESSION_EXPIRES_PARAMETER_NAME_BYTES + 1);

        assert_eq!(
            SessionExpiresExtensionParameter::flag(name),
            Err(ParseError::ParameterNameTooLong {
                length: MAX_SESSION_EXPIRES_PARAMETER_NAME_BYTES + 1,
                maximum: MAX_SESSION_EXPIRES_PARAMETER_NAME_BYTES,
            })
        );
    }

    #[test]
    fn rejects_extension_value_above_size_limit() {
        let value = "a".repeat(MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES + 1);

        assert_eq!(
            SessionExpiresExtensionParameter::token("x-value", value),
            Err(ParseError::ParameterValueTooLong {
                length: MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES + 1,
                maximum: MAX_SESSION_EXPIRES_PARAMETER_VALUE_BYTES,
            })
        );
    }

    #[test]
    fn from_parts_rejects_duplicate_names() {
        let Ok(first) = SessionExpiresExtensionParameter::flag("X-Feature") else {
            panic!("expected first extension parameter");
        };

        let Ok(second) = SessionExpiresExtensionParameter::flag("x-feature") else {
            panic!("expected second extension parameter");
        };

        assert_eq!(
            SessionExpires::from_parts(
                3600,
                vec![
                    SessionExpiresParameter::Extension(first),
                    SessionExpiresParameter::Extension(second),
                ],
            ),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn enforces_parameter_count() {
        let mut value = SessionExpires::new(3600);

        for index in 0..MAX_SESSION_EXPIRES_PARAMETERS {
            let name = format!("x-{index}");

            let Ok(extension) = SessionExpiresExtensionParameter::flag(name) else {
                panic!("expected extension parameter");
            };

            assert!(
                value
                    .push_parameter(SessionExpiresParameter::Extension(extension))
                    .is_ok()
            );
        }

        let Ok(extra) = SessionExpiresExtensionParameter::flag("x-extra") else {
            panic!("expected extension parameter");
        };

        assert_eq!(
            value.push_parameter(SessionExpiresParameter::Extension(extra)),
            Err(ParseError::TooManyParameters {
                maximum: MAX_SESSION_EXPIRES_PARAMETERS,
            })
        );
    }

    #[test]
    fn parses_from_str() {
        let Ok(value) = SessionExpires::from_str("3600;refresher=uac;x-mode=active") else {
            panic!("expected valid Session-Expires");
        };

        assert_eq!(value.delta_seconds(), 3600);
        assert_eq!(value.refresher(), Some(Refresher::Uac));
    }

    #[test]
    fn consumes_into_parts() {
        let Ok(value) = parse(b"3600;refresher=uas;x-mode=active") else {
            panic!("expected valid Session-Expires");
        };

        let (delta_seconds, parameters) = value.into_parts();

        assert_eq!(delta_seconds, 3600);
        assert_eq!(parameters.len(), 2);
    }

    #[test]
    fn display_is_canonical() {
        let Ok(value) = parse(b"003600;REFRESHER=UaC;x-note=\"voice gateway\"") else {
            panic!("expected valid Session-Expires");
        };

        assert_eq!(
            value.to_string(),
            "3600;refresher=uac;x-note=\"voice gateway\""
        );
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");

        assert_eq!(
            ParseError::InvalidDeltaSeconds.class(),
            "invalid-delta-seconds"
        );

        assert_eq!(
            ParseError::DeltaSecondsOverflow.class(),
            "delta-seconds-overflow"
        );

        assert_eq!(ParseError::InvalidRefresher.class(), "invalid-refresher");

        assert_eq!(
            ParseError::DuplicateParameter.class(),
            "duplicate-parameter"
        );

        assert_eq!(
            ParseError::TooManyParameters {
                maximum: MAX_SESSION_EXPIRES_PARAMETERS,
            }
            .class(),
            "too-many-parameters"
        );
    }
}
