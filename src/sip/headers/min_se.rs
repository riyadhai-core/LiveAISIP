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

//! SIP `Min-SE` header.
//!
//! This module provides strongly typed parsing and serialization for SIP
//! `Min-SE` field values.
//!
//! A Min-SE value contains a decimal minimum session interval followed by
//! zero or more semicolon-delimited generic parameters.
//!
//! Valid Min-SE values are never lower than the RFC-defined absolute minimum
//! of 90 seconds. Generic parameters preserve wire order and validated logical
//! values. Parameter names are unique case-insensitively to prevent ambiguous
//! interpretation.
//!
//! The standalone parser validates field-value syntax and protocol-level
//! Min-SE bounds. Request/response placement, 422 processing, proxy behavior,
//! and session-timer negotiation belong to higher SIP layers.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::sip::types::uri::Host;

/// Maximum accepted SIP `Min-SE` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_MIN_SE_BYTES: usize = 8 * 1024;

/// Maximum number of generic parameters accepted in one Min-SE field value.
pub const MAX_MIN_SE_PARAMETERS: usize = 64;

/// Maximum accepted Min-SE generic parameter-name size in bytes.
pub const MAX_MIN_SE_PARAMETER_NAME_BYTES: usize = 256;

/// Maximum accepted Min-SE generic parameter-value size in bytes.
pub const MAX_MIN_SE_PARAMETER_VALUE_BYTES: usize = 1024;

/// Absolute minimum valid Min-SE value in seconds.
pub const ABSOLUTE_MIN_SE_SECONDS: u32 = 90;

/// Default minimum session interval when a Min-SE header is absent.
pub const DEFAULT_MIN_SE_SECONDS: u32 = ABSOLUTE_MIN_SE_SECONDS;

/// A validated SIP `Min-SE` field value.
///
/// Every successfully constructed value is at least
/// [`ABSOLUTE_MIN_SE_SECONDS`] and serializes to no more than
/// [`MAX_MIN_SE_BYTES`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinSe {
    delta_seconds: u32,
    parameters: Vec<MinSeParameter>,
}

impl MinSe {
    /// Creates a Min-SE value without generic parameters.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::BelowMinimum`] when `delta_seconds` is below
    /// [`ABSOLUTE_MIN_SE_SECONDS`].
    pub const fn new(delta_seconds: u32) -> Result<Self, ParseError> {
        if delta_seconds < ABSOLUTE_MIN_SE_SECONDS {
            return Err(ParseError::BelowMinimum {
                value: delta_seconds,
                minimum: ABSOLUTE_MIN_SE_SECONDS,
            });
        }

        Ok(Self {
            delta_seconds,
            parameters: Vec::new(),
        })
    }

    /// Creates the RFC default Min-SE value of 90 seconds.
    #[must_use]
    pub const fn protocol_default() -> Self {
        Self {
            delta_seconds: DEFAULT_MIN_SE_SECONDS,
            parameters: Vec::new(),
        }
    }

    /// Creates a Min-SE value from validated components.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the interval is below the protocol minimum,
    /// parameters are duplicated, an operational bound is exceeded, or the
    /// canonical serialized value would exceed [`MAX_MIN_SE_BYTES`].
    pub fn from_parts(
        delta_seconds: u32,
        parameters: Vec<MinSeParameter>,
    ) -> Result<Self, ParseError> {
        let mut value = Self::new(delta_seconds)?;

        for parameter in parameters {
            value.push_parameter(parameter)?;
        }

        Ok(value)
    }

    /// Parses a SIP `Min-SE` field value from wire bytes.
    ///
    /// Header-name and `HCOLON` parsing are outside this function.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the interval or generic parameter syntax
    /// is invalid, the interval is below the protocol minimum, or an
    /// operational bound is exceeded.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns the minimum session interval in seconds.
    #[must_use]
    pub const fn delta_seconds(&self) -> u32 {
        self.delta_seconds
    }

    /// Replaces the minimum session interval.
    ///
    /// The update is transactional. On failure the existing interval remains
    /// unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::BelowMinimum`] when `delta_seconds` is below the
    /// protocol minimum or [`ParseError::TooLong`] when the resulting
    /// canonical field value would exceed [`MAX_MIN_SE_BYTES`].
    pub fn set_delta_seconds(&mut self, delta_seconds: u32) -> Result<(), ParseError> {
        if delta_seconds < ABSOLUTE_MIN_SE_SECONDS {
            return Err(ParseError::BelowMinimum {
                value: delta_seconds,
                minimum: ABSOLUTE_MIN_SE_SECONDS,
            });
        }

        let current_length = self.to_string().len();
        let current_delta_length = decimal_length(self.delta_seconds);
        let new_delta_length = decimal_length(delta_seconds);

        let length = current_length
            .saturating_sub(current_delta_length)
            .saturating_add(new_delta_length);

        if length > MAX_MIN_SE_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_MIN_SE_BYTES,
            });
        }

        self.delta_seconds = delta_seconds;
        Ok(())
    }

    /// Returns whether this value equals the RFC default minimum.
    #[must_use]
    pub const fn is_protocol_default(&self) -> bool {
        self.delta_seconds == DEFAULT_MIN_SE_SECONDS
    }

    /// Returns all generic Min-SE parameters in wire order.
    #[must_use]
    pub fn parameters(&self) -> &[MinSeParameter] {
        &self.parameters
    }

    /// Returns the first parameter with the requested case-insensitive name.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&MinSeParameter> {
        self.parameters
            .iter()
            .find(|parameter| parameter.name().eq_ignore_ascii_case(name))
    }

    /// Adds a generic Min-SE parameter.
    ///
    /// Parameter names are unique case-insensitively.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::DuplicateParameter`] when the parameter name is
    /// already present, [`ParseError::TooManyParameters`] when the configured
    /// count bound has been reached, or [`ParseError::TooLong`] when the
    /// resulting canonical value would exceed the field-size bound.
    pub fn push_parameter(&mut self, parameter: MinSeParameter) -> Result<(), ParseError> {
        if self.parameters.len() >= MAX_MIN_SE_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_MIN_SE_PARAMETERS,
            });
        }

        if self
            .parameters
            .iter()
            .any(|existing| existing.name().eq_ignore_ascii_case(parameter.name()))
        {
            return Err(ParseError::DuplicateParameter);
        }

        let parameter_length = parameter.to_string().len();
        let length = self
            .to_string()
            .len()
            .saturating_add(1)
            .saturating_add(parameter_length);

        if length > MAX_MIN_SE_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_MIN_SE_BYTES,
            });
        }

        self.parameters.push(parameter);
        Ok(())
    }

    /// Returns the number of generic Min-SE parameters.
    #[must_use]
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Consumes the value into its interval and ordered parameters.
    #[must_use]
    pub fn into_parts(self) -> (u32, Vec<MinSeParameter>) {
        (self.delta_seconds, self.parameters)
    }
}

impl fmt::Display for MinSe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.delta_seconds)?;

        for parameter in &self.parameters {
            write!(formatter, ";{parameter}")?;
        }

        Ok(())
    }
}

impl FromStr for MinSe {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// A validated generic SIP `Min-SE` parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinSeParameter {
    name: Box<str>,
    value: Option<MinSeParameterValue>,
}

impl MinSeParameter {
    /// Creates a valueless Min-SE parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the parameter name violates SIP token
    /// syntax or its operational size limit.
    pub fn flag(name: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let name = name.into();
        validate_parameter_name(name.as_bytes())?;

        Ok(Self { name, value: None })
    }

    /// Creates a token-valued Min-SE parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the parameter name or value is invalid or
    /// exceeds its operational size limit.
    pub fn token(
        name: impl Into<Box<str>>,
        value: impl Into<Box<str>>,
    ) -> Result<Self, ParseError> {
        let name = name.into();
        let value = value.into();

        validate_parameter_name(name.as_bytes())?;
        validate_token_value(value.as_bytes())?;

        Ok(Self {
            name,
            value: Some(MinSeParameterValue::Token(value)),
        })
    }

    /// Creates a host-valued Min-SE parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the parameter name violates SIP token
    /// syntax or its operational size limit.
    pub fn host(name: impl Into<Box<str>>, host: Host) -> Result<Self, ParseError> {
        let name = name.into();
        validate_parameter_name(name.as_bytes())?;

        Ok(Self {
            name,
            value: Some(MinSeParameterValue::Host(host)),
        })
    }

    /// Creates a quoted Min-SE parameter.
    ///
    /// The supplied value is logical text without surrounding quotation
    /// marks.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or quoted value is invalid or
    /// exceeds an operational size limit.
    pub fn quoted(
        name: impl Into<Box<str>>,
        value: impl Into<Box<str>>,
    ) -> Result<Self, ParseError> {
        let name = name.into();
        let value = value.into();

        validate_parameter_name(name.as_bytes())?;
        validate_quoted_value(value.as_bytes())?;

        Ok(Self {
            name,
            value: Some(MinSeParameterValue::Quoted(value)),
        })
    }

    /// Returns the parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional typed parameter value.
    #[must_use]
    pub const fn value(&self) -> Option<&MinSeParameterValue> {
        self.value.as_ref()
    }

    /// Returns whether this parameter has no value.
    #[must_use]
    pub const fn is_flag(&self) -> bool {
        self.value.is_none()
    }

    /// Consumes the parameter into its name and optional value.
    #[must_use]
    pub fn into_parts(self) -> (Box<str>, Option<MinSeParameterValue>) {
        (self.name, self.value)
    }
}

impl fmt::Display for MinSeParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)?;

        let Some(value) = &self.value else {
            return Ok(());
        };

        formatter.write_char('=')?;
        fmt::Display::fmt(value, formatter)
    }
}

/// Typed generic Min-SE parameter value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MinSeParameterValue {
    /// SIP token value.
    Token(Box<str>),

    /// SIP host value.
    Host(Host),

    /// Logical SIP quoted-string value.
    Quoted(Box<str>),
}

impl MinSeParameterValue {
    /// Returns a borrowed textual value when directly stored.
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

    /// Returns whether this is a structurally stored SIP host value.
    #[must_use]
    pub const fn is_host(&self) -> bool {
        matches!(self, Self::Host(_))
    }
}

impl fmt::Display for MinSeParameterValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(value) => formatter.write_str(value),
            Self::Host(host) => fmt::Display::fmt(host, formatter),
            Self::Quoted(value) => write_quoted(formatter, value),
        }
    }
}

/// Parses a SIP `Min-SE` field value.
///
/// # Errors
///
/// Returns [`ParseError`] when the field value violates Min-SE syntax,
/// contains an interval below the protocol minimum, or exceeds an operational
/// bound.
pub fn parse(input: &[u8]) -> Result<MinSe, ParseError> {
    if input.len() > MAX_MIN_SE_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_MIN_SE_BYTES,
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
    let mut min_se = MinSe::new(delta_seconds)?;

    parse_parameters(&mut min_se, remaining)?;

    Ok(min_se)
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

fn parse_parameters(min_se: &mut MinSe, mut input: &[u8]) -> Result<(), ParseError> {
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

        if min_se.parameter_count() >= MAX_MIN_SE_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_MIN_SE_PARAMETERS,
            });
        }

        let (name, remaining) = parse_parameter_name(input)?;
        input = trim_lws_start(remaining);

        let (parameter, remaining) = parse_parameter(name, input)?;
        min_se.push_parameter(parameter)?;
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

    if end > MAX_MIN_SE_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: end,
            maximum: MAX_MIN_SE_PARAMETER_NAME_BYTES,
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
) -> Result<(MinSeParameter, &'a [u8]), ParseError> {
    validate_parameter_name(name.as_bytes())?;

    let input = trim_lws_start(input);

    if input.is_empty() || input[0] == b';' {
        return Ok((MinSeParameter::flag(name)?, input));
    }

    if input[0] != b'=' {
        return Err(ParseError::InvalidParameterSeparator { byte: input[0] });
    }

    let input = trim_lws_start(&input[1..]);

    if input.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    if input[0] == b'"' {
        return parse_quoted_parameter(name, input);
    }

    parse_unquoted_parameter(name, input)
}

fn parse_quoted_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(MinSeParameter, &'a [u8]), ParseError> {
    let (value, consumed) = parse_quoted_text(input)?;
    let remaining = trim_lws_start(&input[consumed..]);

    if !remaining.is_empty() && remaining[0] != b';' {
        return Err(ParseError::UnexpectedTrailingData { byte: remaining[0] });
    }

    Ok((MinSeParameter::quoted(name, value)?, remaining))
}

fn parse_unquoted_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(MinSeParameter, &'a [u8]), ParseError> {
    let (value, remaining) = take_unquoted_value(input)?;

    if value.iter().copied().all(is_token_byte) {
        let text = std::str::from_utf8(value).map_err(|_| ParseError::InvalidParameterValue {
            index: 0,
            byte: value[0],
        })?;

        return Ok((MinSeParameter::token(name, text)?, remaining));
    }

    if let Ok(host) = parse_host(value) {
        return Ok((MinSeParameter::host(name, host)?, remaining));
    }

    let (index, byte) = value
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| !is_token_byte(*byte))
        .unwrap_or((0, value[0]));

    Err(ParseError::InvalidParameterValue { index, byte })
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

    if value.len() > MAX_MIN_SE_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: value.len(),
            maximum: MAX_MIN_SE_PARAMETER_VALUE_BYTES,
        });
    }

    Ok((value, &input[end..]))
}

fn parse_quoted_text(input: &[u8]) -> Result<(String, usize), ParseError> {
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

        if decoded.len() > MAX_MIN_SE_PARAMETER_VALUE_BYTES {
            return Err(ParseError::ParameterValueTooLong {
                length: decoded.len(),
                maximum: MAX_MIN_SE_PARAMETER_VALUE_BYTES,
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

fn validate_parameter_name(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyParameter);
    }

    if input.len() > MAX_MIN_SE_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: input.len(),
            maximum: MAX_MIN_SE_PARAMETER_NAME_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidParameterName { index, byte });
        }
    }

    Ok(())
}

fn validate_token_value(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    if input.len() > MAX_MIN_SE_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_MIN_SE_PARAMETER_VALUE_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidParameterValue { index, byte });
        }
    }

    Ok(())
}

fn validate_quoted_value(input: &[u8]) -> Result<(), ParseError> {
    if input.len() > MAX_MIN_SE_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_MIN_SE_PARAMETER_VALUE_BYTES,
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

/// Failure to parse or construct a SIP `Min-SE` field value.
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

    /// The delta-seconds component was missing or was not decimal.
    InvalidDeltaSeconds,

    /// The delta-seconds component exceeded `u32`.
    DeltaSecondsOverflow,

    /// The Min-SE interval was below the protocol minimum.
    BelowMinimum {
        /// Supplied interval in seconds.
        value: u32,

        /// Minimum permitted interval in seconds.
        minimum: u32,
    },

    /// Unexpected data followed a valid Min-SE component.
    UnexpectedTrailingData {
        /// First unexpected byte.
        byte: u8,
    },

    /// A generic parameter was empty.
    EmptyParameter,

    /// A generic parameter name was invalid.
    InvalidParameterName {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A generic parameter name exceeded its operational size limit.
    ParameterNameTooLong {
        /// Actual parameter-name length in bytes.
        length: usize,

        /// Maximum accepted parameter-name length in bytes.
        maximum: usize,
    },

    /// A generic parameter separator was invalid.
    InvalidParameterSeparator {
        /// Unexpected byte.
        byte: u8,
    },

    /// A parameter requiring a value did not contain one.
    MissingParameterValue,

    /// A generic parameter value was invalid.
    InvalidParameterValue {
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

    /// A generic parameter name appeared more than once.
    DuplicateParameter,

    /// The field exceeded the bounded generic parameter count.
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
            Self::BelowMinimum { .. } => "below-minimum",
            Self::UnexpectedTrailingData { .. } => "unexpected-trailing-data",
            Self::EmptyParameter => "empty-parameter",
            Self::InvalidParameterName { .. } => "invalid-parameter-name",
            Self::ParameterNameTooLong { .. } => "parameter-name-too-long",
            Self::InvalidParameterSeparator { .. } => "invalid-parameter-separator",
            Self::MissingParameterValue => "missing-parameter-value",
            Self::InvalidParameterValue { .. } => "invalid-parameter-value",
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
            Self::Empty => formatter.write_str("SIP Min-SE field value is empty"),
            Self::TooLong { length, maximum } => {
                write_limit(formatter, "SIP Min-SE field-value", *length, *maximum)
            }
            Self::InvalidLineBreak => {
                formatter.write_str("SIP Min-SE contains an invalid line break")
            }
            Self::InvalidDeltaSeconds => {
                formatter.write_str("SIP Min-SE delta-seconds value is invalid")
            }
            Self::DeltaSecondsOverflow => {
                formatter.write_str("SIP Min-SE delta-seconds value exceeds u32")
            }
            Self::BelowMinimum { value, minimum } => {
                write!(
                    formatter,
                    "SIP Min-SE value {value} is below minimum {minimum}"
                )
            }
            Self::UnexpectedTrailingData { byte } => {
                write!(
                    formatter,
                    "unexpected byte 0x{byte:02x} follows SIP Min-SE content"
                )
            }
            Self::EmptyParameter => formatter.write_str("SIP Min-SE parameter is empty"),
            Self::InvalidParameterName { index, byte } => {
                write_invalid_byte(formatter, "SIP Min-SE parameter-name", *index, *byte)
            }
            Self::ParameterNameTooLong { length, maximum } => {
                write_limit(formatter, "SIP Min-SE parameter-name", *length, *maximum)
            }
            Self::InvalidParameterSeparator { byte } => {
                write!(
                    formatter,
                    "invalid SIP Min-SE parameter separator byte 0x{byte:02x}"
                )
            }
            Self::MissingParameterValue => {
                formatter.write_str("SIP Min-SE parameter value is missing")
            }
            Self::InvalidParameterValue { index, byte } => {
                write_invalid_byte(formatter, "SIP Min-SE parameter value", *index, *byte)
            }
            Self::InvalidQuotedString => formatter.write_str("SIP Min-SE quoted string is invalid"),
            Self::ParameterValueTooLong { length, maximum } => {
                write_limit(formatter, "SIP Min-SE parameter-value", *length, *maximum)
            }
            Self::DuplicateParameter => {
                formatter.write_str("SIP Min-SE parameter name is duplicated")
            }
            Self::TooManyParameters { maximum } => {
                write!(
                    formatter,
                    "SIP Min-SE contains more than {maximum} parameters"
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
        ABSOLUTE_MIN_SE_SECONDS, DEFAULT_MIN_SE_SECONDS, MAX_MIN_SE_BYTES,
        MAX_MIN_SE_PARAMETER_NAME_BYTES, MAX_MIN_SE_PARAMETER_VALUE_BYTES, MAX_MIN_SE_PARAMETERS,
        MinSe, MinSeParameter, MinSeParameterValue, ParseError, parse,
    };
    use std::str::FromStr;

    #[test]
    fn parses_absolute_minimum() {
        let Ok(value) = parse(b"90") else {
            panic!("expected valid Min-SE");
        };

        assert_eq!(value.delta_seconds(), ABSOLUTE_MIN_SE_SECONDS);
        assert!(value.is_protocol_default());
    }

    #[test]
    fn parses_larger_interval() {
        let Ok(value) = parse(b"1800") else {
            panic!("expected valid Min-SE");
        };

        assert_eq!(value.delta_seconds(), 1800);
        assert!(!value.is_protocol_default());
    }

    #[test]
    fn rejects_value_below_absolute_minimum() {
        assert_eq!(
            parse(b"89"),
            Err(ParseError::BelowMinimum {
                value: 89,
                minimum: ABSOLUTE_MIN_SE_SECONDS,
            })
        );

        assert_eq!(
            parse(b"0"),
            Err(ParseError::BelowMinimum {
                value: 0,
                minimum: ABSOLUTE_MIN_SE_SECONDS,
            })
        );
    }

    #[test]
    fn default_constant_is_90_seconds() {
        assert_eq!(DEFAULT_MIN_SE_SECONDS, 90);
        assert_eq!(DEFAULT_MIN_SE_SECONDS, ABSOLUTE_MIN_SE_SECONDS);
    }

    #[test]
    fn protocol_default_constructs_90_seconds() {
        let value = MinSe::protocol_default();

        assert_eq!(value.delta_seconds(), 90);
        assert!(value.parameters().is_empty());
        assert_eq!(value.to_string(), "90");
    }

    #[test]
    fn accepts_maximum_u32_interval() {
        let Ok(value) = parse(b"4294967295") else {
            panic!("expected maximum u32 Min-SE");
        };

        assert_eq!(value.delta_seconds(), u32::MAX);
    }

    #[test]
    fn canonicalizes_leading_zeroes() {
        let Ok(value) = parse(b"0000090") else {
            panic!("expected valid Min-SE");
        };

        assert_eq!(value.delta_seconds(), 90);
        assert_eq!(value.to_string(), "90");
    }

    #[test]
    fn parses_generic_flag_parameter() {
        let Ok(value) = parse(b"120;x-feature") else {
            panic!("expected generic flag parameter");
        };

        let Some(parameter) = value.parameter("x-feature") else {
            panic!("expected generic parameter");
        };

        assert!(parameter.is_flag());
    }

    #[test]
    fn parses_generic_token_parameter() {
        let Ok(value) = parse(b"120;x-mode=active") else {
            panic!("expected generic token parameter");
        };

        assert_eq!(
            value
                .parameter("x-mode")
                .and_then(MinSeParameter::value)
                .and_then(MinSeParameterValue::as_str),
            Some("active")
        );
    }

    #[test]
    fn parses_generic_ipv6_host_parameter() {
        let Ok(value) = parse(b"120;x-host=[2001:db8::1]") else {
            panic!("expected IPv6 host parameter");
        };

        assert!(matches!(
            value.parameter("x-host").and_then(MinSeParameter::value),
            Some(MinSeParameterValue::Host(_))
        ));
    }

    #[test]
    fn parses_quoted_parameter() {
        let Ok(value) = parse(b"120;x-note=\"voice gateway\"") else {
            panic!("expected quoted parameter");
        };

        assert_eq!(
            value
                .parameter("x-note")
                .and_then(MinSeParameter::value)
                .and_then(MinSeParameterValue::as_str),
            Some("voice gateway")
        );
    }

    #[test]
    fn quoted_parameter_may_contain_semicolon() {
        let Ok(value) = parse(b"120;x-note=\"one;two\";x-mode=active") else {
            panic!("expected quoted semicolon");
        };

        assert_eq!(
            value
                .parameter("x-note")
                .and_then(MinSeParameter::value)
                .and_then(MinSeParameterValue::as_str),
            Some("one;two")
        );

        assert_eq!(
            value
                .parameter("x-mode")
                .and_then(MinSeParameter::value)
                .and_then(MinSeParameterValue::as_str),
            Some("active")
        );
    }

    #[test]
    fn quoted_parameter_unescapes_quote_and_backslash() {
        let Ok(value) = parse(b"120;x-note=\"A \\\"B\\\" \\\\ C\"") else {
            panic!("expected quoted escapes");
        };

        assert_eq!(
            value
                .parameter("x-note")
                .and_then(MinSeParameter::value)
                .and_then(MinSeParameterValue::as_str),
            Some("A \"B\" \\ C")
        );
    }

    #[test]
    fn accepts_whitespace_around_parameter_delimiters() {
        let Ok(value) = parse(b"120 \t; \tx-mode \t= \tactive \t; x-flag") else {
            panic!("expected delimiter whitespace");
        };

        assert_eq!(
            value
                .parameter("x-mode")
                .and_then(MinSeParameter::value)
                .and_then(MinSeParameterValue::as_str),
            Some("active")
        );

        assert!(
            value
                .parameter("x-flag")
                .is_some_and(MinSeParameter::is_flag)
        );

        assert_eq!(value.to_string(), "120;x-mode=active;x-flag");
    }

    #[test]
    fn parameter_lookup_is_case_insensitive() {
        let Ok(value) = parse(b"120;X-Mode=active") else {
            panic!("expected generic parameter");
        };

        assert!(value.parameter("x-mode").is_some());
        assert!(value.parameter("X-MODE").is_some());
    }

    #[test]
    fn preserves_parameter_order() {
        let Ok(value) = parse(b"120;x-first=1;x-second=2;x-third=3") else {
            panic!("expected ordered parameters");
        };

        assert_eq!(value.parameters().len(), 3);
        assert_eq!(value.parameters()[0].name(), "x-first");
        assert_eq!(value.parameters()[1].name(), "x-second");
        assert_eq!(value.parameters()[2].name(), "x-third");
    }

    #[test]
    fn rejects_duplicate_parameter_case_insensitively() {
        assert_eq!(
            parse(b"120;X-Mode=one;x-mode=two"),
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
        assert_eq!(parse(b"-90"), Err(ParseError::InvalidDeltaSeconds));
    }

    #[test]
    fn rejects_delta_seconds_overflow() {
        assert_eq!(parse(b"4294967296"), Err(ParseError::DeltaSecondsOverflow));
    }

    #[test]
    fn rejects_unexpected_data_after_interval() {
        assert_eq!(
            parse(b"120x"),
            Err(ParseError::UnexpectedTrailingData { byte: b'x' })
        );
    }

    #[test]
    fn rejects_empty_parameter() {
        assert_eq!(parse(b"120;"), Err(ParseError::EmptyParameter));
    }

    #[test]
    fn rejects_invalid_parameter_name() {
        assert_eq!(
            parse(b"120;@bad=value"),
            Err(ParseError::InvalidParameterName {
                index: 0,
                byte: b'@',
            })
        );
    }

    #[test]
    fn rejects_invalid_parameter_separator() {
        assert_eq!(
            parse(b"120;x-mode active"),
            Err(ParseError::InvalidParameterSeparator { byte: b'a' })
        );
    }

    #[test]
    fn rejects_missing_parameter_value() {
        assert_eq!(
            parse(b"120;x-mode="),
            Err(ParseError::MissingParameterValue)
        );
    }

    #[test]
    fn rejects_invalid_parameter_value() {
        assert_eq!(
            parse(b"120;x-mode=a@b"),
            Err(ParseError::InvalidParameterValue {
                index: 1,
                byte: b'@',
            })
        );
    }

    #[test]
    fn rejects_unterminated_quoted_parameter() {
        assert_eq!(
            parse(b"120;x-note=\"unfinished"),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn rejects_crlf_in_field() {
        assert_eq!(
            parse(b"120;\r\nx-mode=active"),
            Err(ParseError::InvalidLineBreak)
        );
    }

    #[test]
    fn rejects_field_above_size_limit() {
        let input = vec![b'a'; MAX_MIN_SE_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_MIN_SE_BYTES + 1,
                maximum: MAX_MIN_SE_BYTES,
            })
        );
    }

    #[test]
    fn constructor_rejects_value_below_minimum() {
        assert_eq!(
            MinSe::new(89),
            Err(ParseError::BelowMinimum {
                value: 89,
                minimum: ABSOLUTE_MIN_SE_SECONDS,
            })
        );
    }

    #[test]
    fn constructor_accepts_absolute_minimum() {
        let Ok(value) = MinSe::new(90) else {
            panic!("expected valid minimum Min-SE");
        };

        assert_eq!(value.delta_seconds(), 90);
    }

    #[test]
    fn set_delta_seconds_replaces_interval() {
        let Ok(mut value) = MinSe::new(120) else {
            panic!("expected valid Min-SE");
        };

        assert!(value.set_delta_seconds(3600).is_ok());

        assert_eq!(value.delta_seconds(), 3600);
    }

    #[test]
    fn set_delta_seconds_rejects_value_below_minimum_transactionally() {
        let Ok(mut value) = MinSe::new(120) else {
            panic!("expected valid Min-SE");
        };

        assert_eq!(
            value.set_delta_seconds(89),
            Err(ParseError::BelowMinimum {
                value: 89,
                minimum: ABSOLUTE_MIN_SE_SECONDS,
            })
        );

        assert_eq!(value.delta_seconds(), 120);
    }

    #[test]
    fn set_delta_seconds_accepts_u32_max_when_size_allows() {
        let Ok(mut value) = MinSe::new(90) else {
            panic!("expected valid Min-SE");
        };

        assert!(value.set_delta_seconds(u32::MAX).is_ok());

        assert_eq!(value.delta_seconds(), u32::MAX);
        assert_eq!(value.to_string(), "4294967295");
    }

    #[test]
    fn set_delta_seconds_preserves_serialized_size_invariant() {
        let mut parameters = Vec::new();

        for index in 0..7 {
            let name = format!("x{index}");
            let parameter_value = "a".repeat(MAX_MIN_SE_PARAMETER_VALUE_BYTES);

            let Ok(parameter) = MinSeParameter::token(name, parameter_value) else {
                panic!("expected maximum-sized parameter");
            };

            parameters.push(parameter);
        }

        let final_value = "a".repeat(983);

        let Ok(final_parameter) = MinSeParameter::token("x7", final_value) else {
            panic!("expected final parameter");
        };

        parameters.push(final_parameter);

        let Ok(mut value) = MinSe::from_parts(90, parameters) else {
            panic!("expected Min-SE near serialized-size limit");
        };

        assert_eq!(value.to_string().len(), MAX_MIN_SE_BYTES - 7);

        assert_eq!(
            value.set_delta_seconds(u32::MAX),
            Err(ParseError::TooLong {
                length: MAX_MIN_SE_BYTES + 1,
                maximum: MAX_MIN_SE_BYTES,
            })
        );

        assert_eq!(value.delta_seconds(), 90);
        assert_eq!(value.to_string().len(), MAX_MIN_SE_BYTES - 7);
    }

    #[test]
    fn creates_parameter_flag() {
        let Ok(parameter) = MinSeParameter::flag("x-feature") else {
            panic!("expected parameter flag");
        };

        assert!(parameter.is_flag());
        assert_eq!(parameter.to_string(), "x-feature");
    }

    #[test]
    fn creates_parameter_token() {
        let Ok(parameter) = MinSeParameter::token("x-mode", "active") else {
            panic!("expected token parameter");
        };

        assert_eq!(parameter.to_string(), "x-mode=active");
    }

    #[test]
    fn creates_parameter_quoted_value() {
        let Ok(parameter) = MinSeParameter::quoted("x-note", "voice gateway") else {
            panic!("expected quoted parameter");
        };

        assert_eq!(parameter.to_string(), "x-note=\"voice gateway\"");
    }

    #[test]
    fn quoted_constructor_escapes_output() {
        let Ok(parameter) = MinSeParameter::quoted("x-note", "A \"B\" \\ C") else {
            panic!("expected quoted parameter");
        };

        assert_eq!(parameter.to_string(), "x-note=\"A \\\"B\\\" \\\\ C\"");
    }

    #[test]
    fn rejects_parameter_name_above_size_limit() {
        let name = "a".repeat(MAX_MIN_SE_PARAMETER_NAME_BYTES + 1);

        assert_eq!(
            MinSeParameter::flag(name),
            Err(ParseError::ParameterNameTooLong {
                length: MAX_MIN_SE_PARAMETER_NAME_BYTES + 1,
                maximum: MAX_MIN_SE_PARAMETER_NAME_BYTES,
            })
        );
    }

    #[test]
    fn rejects_parameter_value_above_size_limit() {
        let value = "a".repeat(MAX_MIN_SE_PARAMETER_VALUE_BYTES + 1);

        assert_eq!(
            MinSeParameter::token("x-value", value),
            Err(ParseError::ParameterValueTooLong {
                length: MAX_MIN_SE_PARAMETER_VALUE_BYTES + 1,
                maximum: MAX_MIN_SE_PARAMETER_VALUE_BYTES,
            })
        );
    }

    #[test]
    fn from_parts_rejects_interval_below_minimum() {
        assert_eq!(
            MinSe::from_parts(89, Vec::new()),
            Err(ParseError::BelowMinimum {
                value: 89,
                minimum: ABSOLUTE_MIN_SE_SECONDS,
            })
        );
    }

    #[test]
    fn from_parts_rejects_duplicate_parameter_names() {
        let Ok(first) = MinSeParameter::flag("X-Feature") else {
            panic!("expected first parameter");
        };

        let Ok(second) = MinSeParameter::flag("x-feature") else {
            panic!("expected second parameter");
        };

        assert_eq!(
            MinSe::from_parts(120, vec![first, second]),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn enforces_parameter_count() {
        let Ok(mut value) = MinSe::new(120) else {
            panic!("expected valid Min-SE");
        };

        for index in 0..MAX_MIN_SE_PARAMETERS {
            let name = format!("x-{index}");

            let Ok(parameter) = MinSeParameter::flag(name) else {
                panic!("expected generic parameter");
            };

            assert!(value.push_parameter(parameter).is_ok());
        }

        let Ok(extra) = MinSeParameter::flag("x-extra") else {
            panic!("expected extra generic parameter");
        };

        assert_eq!(
            value.push_parameter(extra),
            Err(ParseError::TooManyParameters {
                maximum: MAX_MIN_SE_PARAMETERS,
            })
        );
    }

    #[test]
    fn parses_from_str() {
        let Ok(value) = MinSe::from_str("120;x-mode=active") else {
            panic!("expected valid Min-SE");
        };

        assert_eq!(value.delta_seconds(), 120);
        assert!(value.parameter("x-mode").is_some());
    }

    #[test]
    fn consumes_value_into_parts() {
        let Ok(value) = parse(b"120;x-mode=active;x-flag") else {
            panic!("expected valid Min-SE");
        };

        let (delta_seconds, parameters) = value.into_parts();

        assert_eq!(delta_seconds, 120);
        assert_eq!(parameters.len(), 2);
    }

    #[test]
    fn consumes_parameter_into_parts() {
        let Ok(parameter) = MinSeParameter::token("x-mode", "active") else {
            panic!("expected generic parameter");
        };

        let (name, value) = parameter.into_parts();

        assert_eq!(&*name, "x-mode");

        assert!(matches!(
            value,
            Some(MinSeParameterValue::Token(ref value)) if &**value == "active"
        ));
    }

    #[test]
    fn display_is_canonical() {
        let Ok(value) = parse(b"000120;X-Mode=active;x-note=\"voice gateway\"") else {
            panic!("expected valid Min-SE");
        };

        assert_eq!(
            value.to_string(),
            "120;X-Mode=active;x-note=\"voice gateway\""
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

        assert_eq!(
            ParseError::BelowMinimum {
                value: 89,
                minimum: ABSOLUTE_MIN_SE_SECONDS,
            }
            .class(),
            "below-minimum"
        );

        assert_eq!(
            ParseError::DuplicateParameter.class(),
            "duplicate-parameter"
        );

        assert_eq!(
            ParseError::TooManyParameters {
                maximum: MAX_MIN_SE_PARAMETERS,
            }
            .class(),
            "too-many-parameters"
        );
    }
}
