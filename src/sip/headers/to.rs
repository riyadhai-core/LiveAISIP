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

//! SIP `To` header.
//!
//! This module provides the strongly typed representation and parser for the
//! SIP `To` field value.
//!
//! The address and header-parameter namespaces remain deliberately separate.
//! URI parameters belong inside a bracketed `name-addr`. For a bare
//! `addr-spec`, semicolon-delimited parameters are interpreted as `To` header
//! parameters.
//!
//! The `tag` parameter receives dedicated representation because it
//! participates in SIP dialog identification. Unknown valid extension
//! parameters are preserved in wire order.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;
use std::net::Ipv6Addr;

use crate::sip::parser::address;
use crate::sip::types::address::Address;

/// Maximum accepted SIP `To` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_TO_BYTES: usize = 8 * 1024;

/// Maximum number of parameters accepted on one `To` field value.
pub const MAX_TO_PARAMETERS: usize = 64;

/// Maximum accepted `tag` value size in bytes.
///
/// SIP does not prescribe this operational ceiling.
pub const MAX_TO_TAG_BYTES: usize = 256;

/// Maximum accepted extension parameter-name size in bytes.
pub const MAX_TO_PARAMETER_NAME_BYTES: usize = 256;

/// Maximum accepted extension parameter-value size in bytes.
pub const MAX_TO_PARAMETER_VALUE_BYTES: usize = 1024;

/// A validated SIP `To` field value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToHeader {
    address: Address,
    tag: Option<Box<str>>,
    parameters: Vec<ToParameter>,
}

impl ToHeader {
    /// Creates a `To` value without a `tag` or extension parameters.
    #[must_use]
    pub const fn new(address: Address) -> Self {
        Self {
            address,
            tag: None,
            parameters: Vec::new(),
        }
    }

    /// Parses a SIP `To` field value from wire bytes.
    ///
    /// Header-name parsing and `HCOLON` handling are intentionally outside
    /// this function. The input is the field value only.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the address, `tag`, extension parameters,
    /// quoting, or field-value structure is invalid, or when an operational
    /// size/count limit is exceeded.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns the address carried by this `To` value.
    #[must_use]
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// Returns mutable access to the address.
    #[must_use]
    pub const fn address_mut(&mut self) -> &mut Address {
        &mut self.address
    }

    /// Replaces the address.
    pub fn set_address(&mut self, address: Address) {
        self.address = address;
    }

    /// Returns the optional dialog tag.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// Sets the dialog tag.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidTag`] when the value is not a SIP token,
    /// [`ParseError::TagTooLong`] when it exceeds the operational bound, or
    /// [`ParseError::TooManyParameters`] when adding a previously absent tag
    /// would exceed the total parameter limit.
    pub fn set_tag(&mut self, tag: impl Into<Box<str>>) -> Result<(), ParseError> {
        let tag = tag.into();
        validate_tag(tag.as_bytes())?;

        if self.tag.is_none() && self.parameter_count() >= MAX_TO_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_TO_PARAMETERS,
            });
        }

        self.tag = Some(tag);
        Ok(())
    }

    /// Removes the dialog tag.
    pub fn clear_tag(&mut self) {
        self.tag = None;
    }

    /// Returns extension parameters in wire order.
    #[must_use]
    pub fn parameters(&self) -> &[ToParameter] {
        &self.parameters
    }

    /// Returns the first extension parameter with the specified
    /// case-insensitive name.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&ToParameter> {
        self.parameters
            .iter()
            .find(|parameter| parameter.name().eq_ignore_ascii_case(name))
    }

    /// Adds an extension parameter.
    ///
    /// Parameter names are unique case-insensitively. The reserved `tag`
    /// parameter must be managed through [`ToHeader::set_tag`].
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::DuplicateParameter`] for a repeated parameter or
    /// [`ParseError::TooManyParameters`] when the bounded parameter capacity
    /// has been reached.
    pub fn push_parameter(&mut self, parameter: ToParameter) -> Result<(), ParseError> {
        if self.parameter_count() >= MAX_TO_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_TO_PARAMETERS,
            });
        }

        if self
            .parameters
            .iter()
            .any(|existing| existing.name().eq_ignore_ascii_case(parameter.name()))
        {
            return Err(ParseError::DuplicateParameter);
        }

        self.parameters.push(parameter);
        Ok(())
    }

    /// Returns the total number of `To` header parameters, including `tag`.
    #[must_use]
    pub fn parameter_count(&self) -> usize {
        self.parameters.len() + usize::from(self.tag.is_some())
    }

    /// Consumes the value into its address, tag, and extension parameters.
    #[must_use]
    pub fn into_parts(self) -> (Address, Option<Box<str>>, Vec<ToParameter>) {
        (self.address, self.tag, self.parameters)
    }
}

impl fmt::Display for ToHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.address)?;

        if let Some(tag) = &self.tag {
            write!(formatter, ";tag={tag}")?;
        }

        for parameter in &self.parameters {
            write!(formatter, ";{parameter}")?;
        }

        Ok(())
    }
}

/// A validated generic `To` header parameter.
///
/// The reserved `tag` parameter is not representable through this type and is
/// stored separately by [`ToHeader`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToParameter {
    name: Box<str>,
    value: Option<Box<str>>,
    quoted: bool,
}

impl ToParameter {
    /// Creates a valueless generic parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name is invalid, reserved, or exceeds
    /// its operational size limit.
    pub fn flag(name: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let name = name.into();
        validate_extension_parameter_name(name.as_bytes())?;

        Ok(Self {
            name,
            value: None,
            quoted: false,
        })
    }

    /// Creates an unquoted generic parameter.
    ///
    /// The value must satisfy either the SIP `token` grammar or the
    /// non-token IPv6-reference form permitted by the SIP `host` grammar.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or value is invalid, reserved, or
    /// exceeds an operational size limit.
    pub fn unquoted(
        name: impl Into<Box<str>>,
        value: impl Into<Box<str>>,
    ) -> Result<Self, ParseError> {
        let name = name.into();
        let value = value.into();

        validate_extension_parameter_name(name.as_bytes())?;
        validate_unquoted_parameter_value(value.as_bytes())?;

        Ok(Self {
            name,
            value: Some(value),
            quoted: false,
        })
    }

    /// Creates a quoted generic parameter.
    ///
    /// The supplied value is logical text without surrounding quotation
    /// marks. Serialization adds quotes and escapes embedded quote and
    /// backslash characters.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or quoted value is invalid,
    /// reserved, or exceeds an operational size limit.
    pub fn quoted(
        name: impl Into<Box<str>>,
        value: impl Into<Box<str>>,
    ) -> Result<Self, ParseError> {
        let name = name.into();
        let value = value.into();

        validate_extension_parameter_name(name.as_bytes())?;
        validate_quoted_parameter_value(value.as_bytes())?;

        Ok(Self {
            name,
            value: Some(value),
            quoted: true,
        })
    }

    /// Returns the parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional logical parameter value.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Returns whether the value uses quoted-string serialization.
    #[must_use]
    pub const fn is_quoted(&self) -> bool {
        self.quoted
    }

    /// Returns whether this is a valueless parameter.
    #[must_use]
    pub const fn is_flag(&self) -> bool {
        self.value.is_none()
    }
}

impl fmt::Display for ToParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)?;

        let Some(value) = &self.value else {
            return Ok(());
        };

        formatter.write_char('=')?;

        if !self.quoted {
            return formatter.write_str(value);
        }

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

/// Parses a SIP `To` field value.
///
/// # Errors
///
/// Returns [`ParseError`] when the field value violates SIP syntax or an
/// operational bound.
pub fn parse(input: &[u8]) -> Result<ToHeader, ParseError> {
    if input.len() > MAX_TO_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_TO_BYTES,
        });
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    let (address, parameters) = split_address_and_parameters(input)?;
    let mut header = ToHeader::new(address);

    parse_parameters(&mut header, parameters)?;

    Ok(header)
}

fn split_address_and_parameters(input: &[u8]) -> Result<(Address, &[u8]), ParseError> {
    if let Some(open) = find_open_angle(input)? {
        let close = find_close_angle(input, open)?;
        let address_input = trim_lws(&input[..=close]);
        let parameters = &input[close + 1..];

        let address = address::parse(address_input).map_err(ParseError::InvalidAddress)?;

        return Ok((address, parameters));
    }

    let parameter_start = input.iter().position(|byte| *byte == b';');
    let address_end = parameter_start.unwrap_or(input.len());

    let address_input = trim_lws(&input[..address_end]);

    if address_input.is_empty() {
        return Err(ParseError::MissingAddress);
    }

    if let Some((index, byte)) = address_input
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| matches!(byte, b',' | b'?'))
    {
        return Err(ParseError::BareUriRequiresNameAddr { index, byte });
    }

    let address = address::parse(address_input).map_err(ParseError::InvalidAddress)?;
    let parameters = parameter_start.map_or(&input[input.len()..], |index| &input[index..]);

    Ok((address, parameters))
}

fn find_open_angle(input: &[u8]) -> Result<Option<usize>, ParseError> {
    let mut in_quotes = false;
    let mut escaped = false;

    for (index, byte) in input.iter().copied().enumerate() {
        if in_quotes {
            if escaped {
                if matches!(byte, b'\r' | b'\n') {
                    return Err(ParseError::InvalidQuotedString);
                }

                escaped = false;
                continue;
            }

            match byte {
                b'\\' => escaped = true,
                b'"' => in_quotes = false,
                b'\r' | b'\n' => return Err(ParseError::InvalidQuotedString),
                _ => {}
            }

            continue;
        }

        match byte {
            b'"' => in_quotes = true,
            b'<' => return Ok(Some(index)),
            b'>' => return Err(ParseError::InvalidAddressStructure),
            _ => {}
        }
    }

    if in_quotes || escaped {
        return Err(ParseError::InvalidQuotedString);
    }

    Ok(None)
}

fn find_close_angle(input: &[u8], open: usize) -> Result<usize, ParseError> {
    let Some(relative) = input[open + 1..].iter().position(|byte| *byte == b'>') else {
        return Err(ParseError::MissingClosingAngle);
    };

    let close = open + 1 + relative;

    if input[open + 1..close].contains(&b'<') {
        return Err(ParseError::InvalidAddressStructure);
    }

    Ok(close)
}

fn parse_parameters(header: &mut ToHeader, mut input: &[u8]) -> Result<(), ParseError> {
    loop {
        input = trim_lws_start(input);

        if input.is_empty() {
            return Ok(());
        }

        if input[0] != b';' {
            return Err(ParseError::UnexpectedTrailingData);
        }

        input = &input[1..];
        input = trim_lws_start(input);

        if input.is_empty() {
            return Err(ParseError::EmptyParameter);
        }

        if header.parameter_count() >= MAX_TO_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_TO_PARAMETERS,
            });
        }

        let (name, after_name) = parse_parameter_name(input)?;
        input = trim_lws_start(after_name);

        if name.eq_ignore_ascii_case("tag") {
            let (tag, remaining) = parse_tag_parameter(input)?;

            if header.tag().is_some() {
                return Err(ParseError::DuplicateParameter);
            }

            header.set_tag(tag)?;
            input = remaining;
            continue;
        }

        if header.parameter(name).is_some() {
            return Err(ParseError::DuplicateParameter);
        }

        let (parameter, remaining) = parse_extension_parameter(name, input)?;
        header.push_parameter(parameter)?;
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

    if end > MAX_TO_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: end,
            maximum: MAX_TO_PARAMETER_NAME_BYTES,
        });
    }

    let name =
        std::str::from_utf8(&input[..end]).map_err(|_| ParseError::InvalidParameterName {
            index: 0,
            byte: input[0],
        })?;

    Ok((name, &input[end..]))
}

fn parse_tag_parameter(input: &[u8]) -> Result<(Box<str>, &[u8]), ParseError> {
    let input = trim_lws_start(input);

    if input.first() != Some(&b'=') {
        return Err(ParseError::MissingTagValue);
    }

    let input = trim_lws_start(&input[1..]);

    if input.is_empty() {
        return Err(ParseError::MissingTagValue);
    }

    let mut end = 0;

    while end < input.len() && is_token_byte(input[end]) {
        end += 1;
    }

    if end == 0 {
        return Err(ParseError::InvalidTag {
            index: 0,
            byte: input[0],
        });
    }

    validate_tag(&input[..end])?;

    let remaining = trim_lws_start(&input[end..]);

    if !remaining.is_empty() && remaining[0] != b';' {
        return Err(ParseError::InvalidTag {
            index: end,
            byte: remaining[0],
        });
    }

    let tag = std::str::from_utf8(&input[..end])
        .map_err(|_| ParseError::InvalidTag {
            index: 0,
            byte: input[0],
        })?
        .into();

    Ok((tag, remaining))
}

fn parse_extension_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(ToParameter, &'a [u8]), ParseError> {
    validate_extension_parameter_name(name.as_bytes())?;

    let input = trim_lws_start(input);

    if input.is_empty() || input[0] == b';' {
        return Ok((ToParameter::flag(name)?, input));
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

fn parse_unquoted_extension_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(ToParameter, &'a [u8]), ParseError> {
    let end = input
        .iter()
        .position(|byte| *byte == b';')
        .unwrap_or(input.len());

    let value_input = trim_lws(&input[..end]);

    if value_input.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    validate_unquoted_parameter_value(value_input)?;

    let value =
        std::str::from_utf8(value_input).map_err(|_| ParseError::InvalidParameterValue {
            index: 0,
            byte: value_input[0],
        })?;

    let parameter = ToParameter::unquoted(name, value)?;

    Ok((parameter, &input[end..]))
}

fn parse_quoted_extension_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(ToParameter, &'a [u8]), ParseError> {
    let (value, consumed) = parse_quoted_value(input)?;
    let remaining = trim_lws_start(&input[consumed..]);

    if !remaining.is_empty() && remaining[0] != b';' {
        return Err(ParseError::UnexpectedTrailingData);
    }

    let parameter = ToParameter::quoted(name, value)?;

    Ok((parameter, remaining))
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
            byte if byte.is_ascii_control() => {
                return Err(ParseError::InvalidQuotedString);
            }
            _ => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    Err(ParseError::InvalidQuotedString)
}

fn validate_tag(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingTagValue);
    }

    if input.len() > MAX_TO_TAG_BYTES {
        return Err(ParseError::TagTooLong {
            length: input.len(),
            maximum: MAX_TO_TAG_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidTag { index, byte });
        }
    }

    Ok(())
}

fn validate_extension_parameter_name(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyParameter);
    }

    if input.len() > MAX_TO_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: input.len(),
            maximum: MAX_TO_PARAMETER_NAME_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidParameterName { index, byte });
        }
    }

    if input.eq_ignore_ascii_case(b"tag") {
        return Err(ParseError::ReservedParameterName);
    }

    Ok(())
}

fn validate_unquoted_parameter_value(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    if input.len() > MAX_TO_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_TO_PARAMETER_VALUE_BYTES,
        });
    }

    if input.iter().copied().all(is_token_byte) {
        return Ok(());
    }

    if is_ipv6_reference(input) {
        return Ok(());
    }

    let (index, byte) = input
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| !is_token_byte(*byte))
        .unwrap_or((0, input[0]));

    Err(ParseError::InvalidParameterValue { index, byte })
}

fn validate_quoted_parameter_value(input: &[u8]) -> Result<(), ParseError> {
    if input.len() > MAX_TO_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_TO_PARAMETER_VALUE_BYTES,
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

fn is_ipv6_reference(input: &[u8]) -> bool {
    if input.len() < 3 || input.first() != Some(&b'[') || input.last() != Some(&b']') {
        return false;
    }

    let Ok(address) = std::str::from_utf8(&input[1..input.len() - 1]) else {
        return false;
    };

    address.parse::<Ipv6Addr>().is_ok()
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

/// Failure to parse or construct a SIP `To` value.
#[derive(Clone, Debug, Eq, PartialEq)]
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

    /// The address portion was missing.
    MissingAddress,

    /// The address could not be parsed.
    InvalidAddress(address::ParseError),

    /// The surrounding `name-addr` structure was malformed.
    InvalidAddressStructure,

    /// A bracketed address was missing its closing `>`.
    MissingClosingAngle,

    /// A bare URI used syntax that requires the `name-addr` form.
    BareUriRequiresNameAddr {
        /// Offset of the character requiring brackets.
        index: usize,

        /// Character requiring brackets.
        byte: u8,
    },

    /// A quoted string was malformed.
    InvalidQuotedString,

    /// Unexpected non-parameter data followed the address or parameter.
    UnexpectedTrailingData,

    /// A parameter contained no name.
    EmptyParameter,

    /// A parameter name was invalid.
    InvalidParameterName {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A parameter name exceeded the configured operational limit.
    ParameterNameTooLong {
        /// Actual parameter-name length in bytes.
        length: usize,

        /// Maximum accepted parameter-name length in bytes.
        maximum: usize,
    },

    /// `tag` was supplied through the generic extension-parameter API.
    ReservedParameterName,

    /// A parameter separator was invalid.
    InvalidParameterSeparator {
        /// Unexpected byte.
        byte: u8,
    },

    /// A parameter used `=` without providing a value.
    MissingParameterValue,

    /// An unquoted generic parameter value was invalid.
    InvalidParameterValue {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A parameter value exceeded the configured operational limit.
    ParameterValueTooLong {
        /// Actual parameter-value length in bytes.
        length: usize,

        /// Maximum accepted parameter-value length in bytes.
        maximum: usize,
    },

    /// A `tag` parameter did not contain a value.
    MissingTagValue,

    /// A `tag` value violated the SIP token grammar.
    InvalidTag {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A `tag` exceeded the configured operational limit.
    TagTooLong {
        /// Actual tag length in bytes.
        length: usize,

        /// Maximum accepted tag length in bytes.
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
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong { .. } => "too-long",
            Self::MissingAddress => "missing-address",
            Self::InvalidAddress(_) => "invalid-address",
            Self::InvalidAddressStructure => "invalid-address-structure",
            Self::MissingClosingAngle => "missing-closing-angle",
            Self::BareUriRequiresNameAddr { .. } => "bare-uri-requires-name-addr",
            Self::InvalidQuotedString => "invalid-quoted-string",
            Self::UnexpectedTrailingData => "unexpected-trailing-data",
            Self::EmptyParameter => "empty-parameter",
            Self::InvalidParameterName { .. } => "invalid-parameter-name",
            Self::ParameterNameTooLong { .. } => "parameter-name-too-long",
            Self::ReservedParameterName => "reserved-parameter-name",
            Self::InvalidParameterSeparator { .. } => "invalid-parameter-separator",
            Self::MissingParameterValue => "missing-parameter-value",
            Self::InvalidParameterValue { .. } => "invalid-parameter-value",
            Self::ParameterValueTooLong { .. } => "parameter-value-too-long",
            Self::MissingTagValue => "missing-tag-value",
            Self::InvalidTag { .. } => "invalid-tag",
            Self::TagTooLong { .. } => "tag-too-long",
            Self::DuplicateParameter => "duplicate-parameter",
            Self::TooManyParameters { .. } => "too-many-parameters",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP To field value is empty"),
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP To field-value length {length} exceeds maximum {maximum}"
                )
            }
            Self::MissingAddress => formatter.write_str("SIP To address is missing"),
            Self::InvalidAddress(error) => {
                write!(formatter, "invalid SIP To address: {error}")
            }
            Self::InvalidAddressStructure => {
                formatter.write_str("SIP To name-addr structure is invalid")
            }
            Self::MissingClosingAngle => {
                formatter.write_str("SIP To name-addr is missing its closing angle bracket")
            }
            Self::BareUriRequiresNameAddr { index, byte } => {
                write!(
                    formatter,
                    "SIP To bare URI contains byte 0x{byte:02x} at offset {index} requiring name-addr form"
                )
            }
            Self::InvalidQuotedString => formatter.write_str("SIP To quoted string is invalid"),
            Self::UnexpectedTrailingData => {
                formatter.write_str("unexpected data follows SIP To field content")
            }
            Self::EmptyParameter => formatter.write_str("SIP To parameter is empty"),
            Self::InvalidParameterName { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP To parameter-name byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::ParameterNameTooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP To parameter-name length {length} exceeds maximum {maximum}"
                )
            }
            Self::ReservedParameterName => {
                formatter.write_str("SIP To tag must use the dedicated tag parameter")
            }
            Self::InvalidParameterSeparator { byte } => {
                write!(
                    formatter,
                    "invalid SIP To parameter separator byte 0x{byte:02x}"
                )
            }
            Self::MissingParameterValue => formatter.write_str("SIP To parameter value is missing"),
            Self::InvalidParameterValue { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP To parameter-value byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::ParameterValueTooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP To parameter-value length {length} exceeds maximum {maximum}"
                )
            }
            Self::MissingTagValue => formatter.write_str("SIP To tag value is missing"),
            Self::InvalidTag { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP To tag byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::TagTooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP To tag length {length} exceeds maximum {maximum}"
                )
            }
            Self::DuplicateParameter => formatter.write_str("SIP To parameter name is duplicated"),
            Self::TooManyParameters { maximum } => {
                write!(formatter, "SIP To contains more than {maximum} parameters")
            }
        }
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidAddress(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_TO_BYTES, MAX_TO_PARAMETER_NAME_BYTES, MAX_TO_PARAMETER_VALUE_BYTES, MAX_TO_PARAMETERS,
        MAX_TO_TAG_BYTES, ParseError, ToHeader, ToParameter, parse,
    };
    use crate::sip::parser::address;
    use crate::sip::types::address::Address;

    #[test]
    fn parses_basic_name_addr() {
        let Ok(header) = parse(b"<sip:bob@example.com>") else {
            panic!("expected valid To value");
        };

        assert!(header.address().is_name_addr());
        assert_eq!(header.tag(), None);
        assert!(header.parameters().is_empty());
    }

    #[test]
    fn parses_name_addr_with_tag() {
        let Ok(header) = parse(b"<sip:bob@example.com>;tag=a6c85cf") else {
            panic!("expected valid To value");
        };

        assert_eq!(header.tag(), Some("a6c85cf"));
        assert_eq!(header.parameter_count(), 1);
    }

    #[test]
    fn parses_display_name() {
        let Ok(header) = parse(b"\"Bob Smith\" <sip:bob@example.com>") else {
            panic!("expected valid To value");
        };

        assert_eq!(header.address().display_name(), Some("Bob Smith"));
        assert_eq!(header.tag(), None);
    }

    #[test]
    fn parses_unquoted_multi_token_display_name() {
        let Ok(header) = parse(b"Bob Smith <sip:bob@example.com>") else {
            panic!("expected valid To display name");
        };

        assert_eq!(header.address().display_name(), Some("Bob Smith"));
    }

    #[test]
    fn tag_name_is_case_insensitive() {
        let Ok(header) = parse(b"<sip:bob@example.com>;TAG=abc123") else {
            panic!("expected case-insensitive tag name");
        };

        assert_eq!(header.tag(), Some("abc123"));
    }

    #[test]
    fn tag_value_case_is_preserved() {
        let Ok(header) = parse(b"<sip:bob@example.com>;tag=AbC123") else {
            panic!("expected valid tag");
        };

        assert_eq!(header.tag(), Some("AbC123"));
        assert_eq!(header.to_string(), "<sip:bob@example.com>;tag=AbC123");
    }

    #[test]
    fn parses_bare_addr_spec_without_tag() {
        let Ok(header) = parse(b"sip:+12125551212@phone2net.com") else {
            panic!("expected valid bare To address");
        };

        assert!(header.address().is_addr_spec());
        assert_eq!(header.tag(), None);
        assert_eq!(
            header.address().uri().to_string(),
            "sip:+12125551212@phone2net.com"
        );
    }

    #[test]
    fn parses_bare_addr_spec_with_tag() {
        let Ok(header) = parse(b"sip:bob@example.com;tag=xyz") else {
            panic!("expected valid bare To address");
        };

        assert!(header.address().is_addr_spec());
        assert_eq!(header.address().uri().to_string(), "sip:bob@example.com");
        assert_eq!(header.tag(), Some("xyz"));
    }

    #[test]
    fn bare_semicolon_parameter_is_header_parameter() {
        let Ok(header) = parse(b"sip:bob@example.com;transport=tcp") else {
            panic!("expected generic To parameter");
        };

        let Some(uri) = header.address().uri().as_sip() else {
            panic!("expected SIP URI");
        };

        assert!(uri.parameters().is_empty());

        let Some(parameter) = header.parameter("transport") else {
            panic!("expected To header parameter");
        };

        assert_eq!(parameter.value(), Some("tcp"));
    }

    #[test]
    fn bracketed_semicolon_parameter_remains_uri_parameter() {
        let Ok(header) = parse(b"<sip:bob@example.com;transport=tcp>;tag=abc") else {
            panic!("expected bracketed URI parameter");
        };

        let Some(uri) = header.address().uri().as_sip() else {
            panic!("expected SIP URI");
        };

        assert_eq!(
            uri.parameter("transport")
                .and_then(|parameter| parameter.value()),
            Some("tcp")
        );

        assert!(header.parameter("transport").is_none());
        assert_eq!(header.tag(), Some("abc"));
    }

    #[test]
    fn parses_flag_extension_parameter() {
        let Ok(header) = parse(b"<sip:bob@example.com>;x-feature") else {
            panic!("expected flag parameter");
        };

        let Some(parameter) = header.parameter("x-feature") else {
            panic!("expected extension parameter");
        };

        assert!(parameter.is_flag());
        assert_eq!(parameter.value(), None);
    }

    #[test]
    fn parses_token_extension_parameter() {
        let Ok(header) = parse(b"<sip:bob@example.com>;x-mode=fast") else {
            panic!("expected token parameter");
        };

        let Some(parameter) = header.parameter("x-mode") else {
            panic!("expected extension parameter");
        };

        assert_eq!(parameter.value(), Some("fast"));
        assert!(!parameter.is_quoted());
    }

    #[test]
    fn parses_quoted_extension_parameter() {
        let Ok(header) = parse(b"<sip:bob@example.com>;x-label=\"Voice Gateway\"") else {
            panic!("expected quoted parameter");
        };

        let Some(parameter) = header.parameter("x-label") else {
            panic!("expected extension parameter");
        };

        assert_eq!(parameter.value(), Some("Voice Gateway"));
        assert!(parameter.is_quoted());
    }

    #[test]
    fn quoted_parameter_may_contain_semicolon() {
        let Ok(header) = parse(b"<sip:bob@example.com>;x-label=\"one;two\";tag=abc") else {
            panic!("expected quoted semicolon");
        };

        assert_eq!(
            header.parameter("x-label").and_then(ToParameter::value),
            Some("one;two")
        );
        assert_eq!(header.tag(), Some("abc"));
    }

    #[test]
    fn quoted_parameter_unescapes_quote() {
        let Ok(header) = parse(b"<sip:bob@example.com>;x-label=\"Bob \\\"Voice\\\"\"") else {
            panic!("expected escaped quote");
        };

        assert_eq!(
            header.parameter("x-label").and_then(ToParameter::value),
            Some("Bob \"Voice\"")
        );
    }

    #[test]
    fn quoted_parameter_unescapes_backslash() {
        let Ok(header) = parse(b"<sip:bob@example.com>;x-path=\"one\\\\two\"") else {
            panic!("expected escaped backslash");
        };

        assert_eq!(
            header.parameter("x-path").and_then(ToParameter::value),
            Some("one\\two")
        );
    }

    #[test]
    fn parses_ipv6_reference_generic_value() {
        let Ok(header) = parse(b"<sip:bob@example.com>;x-host=[2001:db8::1]") else {
            panic!("expected IPv6-reference generic value");
        };

        assert_eq!(
            header.parameter("x-host").and_then(ToParameter::value),
            Some("[2001:db8::1]")
        );
    }

    #[test]
    fn preserves_extension_parameter_order() {
        let Ok(header) = parse(b"<sip:bob@example.com>;first=1;second=2;third=3") else {
            panic!("expected extension parameters");
        };

        assert_eq!(header.parameters().len(), 3);
        assert_eq!(header.parameters()[0].name(), "first");
        assert_eq!(header.parameters()[1].name(), "second");
        assert_eq!(header.parameters()[2].name(), "third");
    }

    #[test]
    fn extension_parameter_lookup_is_case_insensitive() {
        let Ok(header) = parse(b"<sip:bob@example.com>;X-Mode=fast") else {
            panic!("expected extension parameter");
        };

        assert!(header.parameter("x-mode").is_some());
        assert!(header.parameter("X-MODE").is_some());
    }

    #[test]
    fn allows_whitespace_around_parameter_separators() {
        let Ok(header) = parse(b"<sip:bob@example.com> ; tag = abc ; x-mode = fast") else {
            panic!("expected separator whitespace");
        };

        assert_eq!(header.tag(), Some("abc"));
        assert_eq!(
            header.parameter("x-mode").and_then(ToParameter::value),
            Some("fast")
        );
    }

    #[test]
    fn trims_surrounding_field_whitespace() {
        let Ok(header) = parse(b" \t<sip:bob@example.com>;tag=abc \t") else {
            panic!("expected surrounding whitespace");
        };

        assert_eq!(header.tag(), Some("abc"));
    }

    #[test]
    fn parses_ipv4_address() {
        let Ok(header) = parse(b"<sip:bob@192.0.2.10>") else {
            panic!("expected IPv4 To address");
        };

        assert_eq!(header.address().uri().to_string(), "sip:bob@192.0.2.10");
    }

    #[test]
    fn parses_ipv6_address() {
        let Ok(header) = parse(b"<sip:bob@[2001:db8::1]>") else {
            panic!("expected IPv6 To address");
        };

        assert_eq!(header.address().uri().to_string(), "sip:bob@[2001:db8::1]");
    }

    #[test]
    fn parses_address_with_port() {
        let Ok(header) = parse(b"<sip:bob@example.com:5070>") else {
            panic!("expected To address with port");
        };

        let Some(uri) = header.address().uri().as_sip() else {
            panic!("expected SIP URI");
        };

        assert_eq!(uri.port(), Some(5070));
    }

    #[test]
    fn parses_absolute_uri() {
        let Ok(header) = parse(b"<tel:+12125551212>") else {
            panic!("expected absolute URI");
        };

        assert_eq!(header.address().uri().to_string(), "tel:+12125551212");
    }

    #[test]
    fn rejects_empty_field_value() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b" \t "), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_field_above_size_limit() {
        let input = vec![b'A'; MAX_TO_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_TO_BYTES + 1,
                maximum: MAX_TO_BYTES,
            })
        );
    }

    #[test]
    fn rejects_bare_uri_with_question_mark() {
        assert_eq!(
            parse(b"sip:bob@example.com?subject=test"),
            Err(ParseError::BareUriRequiresNameAddr {
                index: 19,
                byte: b'?',
            })
        );
    }

    #[test]
    fn rejects_bare_uri_with_comma() {
        assert_eq!(
            parse(b"sip:bob@example.com,other"),
            Err(ParseError::BareUriRequiresNameAddr {
                index: 19,
                byte: b',',
            })
        );
    }

    #[test]
    fn rejects_missing_closing_angle() {
        assert_eq!(
            parse(b"<sip:bob@example.com;tag=abc"),
            Err(ParseError::MissingClosingAngle)
        );
    }

    #[test]
    fn rejects_trailing_non_parameter_data() {
        assert_eq!(
            parse(b"<sip:bob@example.com> garbage"),
            Err(ParseError::UnexpectedTrailingData)
        );
    }

    #[test]
    fn rejects_empty_parameter() {
        assert_eq!(
            parse(b"<sip:bob@example.com>;"),
            Err(ParseError::EmptyParameter)
        );
    }

    #[test]
    fn rejects_empty_parameter_between_semicolons() {
        assert_eq!(
            parse(b"<sip:bob@example.com>;x=1;;y=2"),
            Err(ParseError::InvalidParameterName {
                index: 0,
                byte: b';',
            })
        );
    }

    #[test]
    fn rejects_tag_without_equal_sign() {
        assert_eq!(
            parse(b"<sip:bob@example.com>;tag"),
            Err(ParseError::MissingTagValue)
        );
    }

    #[test]
    fn rejects_empty_tag_value() {
        assert_eq!(
            parse(b"<sip:bob@example.com>;tag="),
            Err(ParseError::MissingTagValue)
        );
    }

    #[test]
    fn rejects_invalid_tag_value() {
        assert_eq!(
            parse(b"<sip:bob@example.com>;tag=bad:value"),
            Err(ParseError::InvalidTag {
                index: 3,
                byte: b':',
            })
        );
    }

    #[test]
    fn rejects_duplicate_tag() {
        assert_eq!(
            parse(b"<sip:bob@example.com>;tag=one;TAG=two"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn rejects_duplicate_extension_parameter_case_insensitively() {
        assert_eq!(
            parse(b"<sip:bob@example.com>;X-Mode=one;x-mode=two"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn rejects_empty_unquoted_parameter_value() {
        assert_eq!(
            parse(b"<sip:bob@example.com>;x-mode="),
            Err(ParseError::MissingParameterValue)
        );
    }

    #[test]
    fn rejects_invalid_unquoted_parameter_value() {
        assert_eq!(
            parse(b"<sip:bob@example.com>;x-mode=bad:value"),
            Err(ParseError::InvalidParameterValue {
                index: 3,
                byte: b':',
            })
        );
    }

    #[test]
    fn rejects_unterminated_quoted_parameter_value() {
        assert_eq!(
            parse(b"<sip:bob@example.com>;x-label=\"unfinished"),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn rejects_crlf_in_quoted_parameter_value() {
        assert_eq!(
            parse(b"<sip:bob@example.com>;x-label=\"one\r\ntwo\""),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn constructor_sets_tag() {
        let Ok(address) = address::parse(b"<sip:bob@example.com>") else {
            panic!("expected valid address");
        };

        let mut header = ToHeader::new(address);

        assert!(header.set_tag("abc123").is_ok());
        assert_eq!(header.tag(), Some("abc123"));
    }

    #[test]
    fn constructor_rejects_invalid_tag() {
        let Ok(address) = address::parse(b"<sip:bob@example.com>") else {
            panic!("expected valid address");
        };

        let mut header = ToHeader::new(address);

        assert_eq!(
            header.set_tag("bad:value"),
            Err(ParseError::InvalidTag {
                index: 3,
                byte: b':',
            })
        );
    }

    #[test]
    fn tag_can_be_cleared() {
        let Ok(address) = address::parse(b"<sip:bob@example.com>") else {
            panic!("expected valid address");
        };

        let mut header = ToHeader::new(address);

        assert!(header.set_tag("abc").is_ok());
        header.clear_tag();

        assert_eq!(header.tag(), None);
    }

    #[test]
    fn creates_flag_extension_parameter() {
        let Ok(parameter) = ToParameter::flag("x-feature") else {
            panic!("expected valid flag parameter");
        };

        assert_eq!(parameter.name(), "x-feature");
        assert!(parameter.is_flag());
        assert_eq!(parameter.to_string(), "x-feature");
    }

    #[test]
    fn creates_unquoted_extension_parameter() {
        let Ok(parameter) = ToParameter::unquoted("x-mode", "fast") else {
            panic!("expected valid unquoted parameter");
        };

        assert_eq!(parameter.value(), Some("fast"));
        assert!(!parameter.is_quoted());
        assert_eq!(parameter.to_string(), "x-mode=fast");
    }

    #[test]
    fn creates_quoted_extension_parameter() {
        let Ok(parameter) = ToParameter::quoted("x-label", "Voice Gateway") else {
            panic!("expected valid quoted parameter");
        };

        assert_eq!(parameter.value(), Some("Voice Gateway"));
        assert!(parameter.is_quoted());
        assert_eq!(parameter.to_string(), "x-label=\"Voice Gateway\"");
    }

    #[test]
    fn quoted_parameter_serialization_escapes_special_characters() {
        let Ok(parameter) = ToParameter::quoted("x-label", "A \"B\" \\ C") else {
            panic!("expected valid quoted parameter");
        };

        assert_eq!(parameter.to_string(), "x-label=\"A \\\"B\\\" \\\\ C\"");
    }

    #[test]
    fn generic_parameter_api_rejects_reserved_tag_name() {
        assert_eq!(
            ToParameter::flag("TAG"),
            Err(ParseError::ReservedParameterName)
        );
    }

    #[test]
    fn rejects_parameter_name_above_size_limit() {
        let name = "A".repeat(MAX_TO_PARAMETER_NAME_BYTES + 1);

        assert_eq!(
            ToParameter::flag(name),
            Err(ParseError::ParameterNameTooLong {
                length: MAX_TO_PARAMETER_NAME_BYTES + 1,
                maximum: MAX_TO_PARAMETER_NAME_BYTES,
            })
        );
    }

    #[test]
    fn rejects_parameter_value_above_size_limit() {
        let value = "A".repeat(MAX_TO_PARAMETER_VALUE_BYTES + 1);

        assert_eq!(
            ToParameter::unquoted("x-value", value),
            Err(ParseError::ParameterValueTooLong {
                length: MAX_TO_PARAMETER_VALUE_BYTES + 1,
                maximum: MAX_TO_PARAMETER_VALUE_BYTES,
            })
        );
    }

    #[test]
    fn rejects_tag_above_size_limit() {
        let Ok(address) = address::parse(b"<sip:bob@example.com>") else {
            panic!("expected valid address");
        };

        let mut header = ToHeader::new(address);
        let tag = "A".repeat(MAX_TO_TAG_BYTES + 1);

        assert_eq!(
            header.set_tag(tag),
            Err(ParseError::TagTooLong {
                length: MAX_TO_TAG_BYTES + 1,
                maximum: MAX_TO_TAG_BYTES,
            })
        );
    }

    #[test]
    fn enforces_total_parameter_count() {
        let Ok(address) = address::parse(b"<sip:bob@example.com>") else {
            panic!("expected valid address");
        };

        let mut header = ToHeader::new(address);

        for index in 0..MAX_TO_PARAMETERS {
            let name = format!("x-{index}");
            let Ok(parameter) = ToParameter::flag(name) else {
                panic!("expected valid extension parameter");
            };

            assert!(header.push_parameter(parameter).is_ok());
        }

        let Ok(extra) = ToParameter::flag("x-extra") else {
            panic!("expected valid extension parameter");
        };

        assert_eq!(
            header.push_parameter(extra),
            Err(ParseError::TooManyParameters {
                maximum: MAX_TO_PARAMETERS,
            })
        );
    }

    #[test]
    fn tag_counts_toward_total_parameter_limit() {
        let Ok(address) = address::parse(b"<sip:bob@example.com>") else {
            panic!("expected valid address");
        };

        let mut header = ToHeader::new(address);

        for index in 0..MAX_TO_PARAMETERS - 1 {
            let name = format!("x-{index}");
            let Ok(parameter) = ToParameter::flag(name) else {
                panic!("expected valid extension parameter");
            };

            assert!(header.push_parameter(parameter).is_ok());
        }

        assert!(header.set_tag("abc").is_ok());

        let Ok(extra) = ToParameter::flag("x-extra") else {
            panic!("expected valid extension parameter");
        };

        assert_eq!(
            header.push_parameter(extra),
            Err(ParseError::TooManyParameters {
                maximum: MAX_TO_PARAMETERS,
            })
        );
    }

    #[test]
    fn display_serializes_canonical_value() {
        let Ok(header) = parse(b"\"Bob\" <sip:bob@example.com>;TAG=AbC;x-mode=\"fast mode\"")
        else {
            panic!("expected valid To value");
        };

        assert_eq!(
            header.to_string(),
            "\"Bob\" <sip:bob@example.com>;tag=AbC;x-mode=\"fast mode\""
        );
    }

    #[test]
    fn consumes_into_parts() {
        let Ok(header) = parse(b"<sip:bob@example.com>;tag=abc;x-mode=fast") else {
            panic!("expected valid To value");
        };

        let (address, tag, parameters) = header.into_parts();

        assert!(matches!(address, Address::NameAddr(_)));
        assert_eq!(tag.as_deref(), Some("abc"));
        assert_eq!(parameters.len(), 1);
        assert_eq!(parameters[0].name(), "x-mode");
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");
        assert_eq!(ParseError::MissingAddress.class(), "missing-address");
        assert_eq!(
            ParseError::InvalidAddressStructure.class(),
            "invalid-address-structure"
        );
        assert_eq!(
            ParseError::BareUriRequiresNameAddr {
                index: 0,
                byte: b'?',
            }
            .class(),
            "bare-uri-requires-name-addr"
        );
        assert_eq!(
            ParseError::InvalidQuotedString.class(),
            "invalid-quoted-string"
        );
        assert_eq!(
            ParseError::DuplicateParameter.class(),
            "duplicate-parameter"
        );
        assert_eq!(
            ParseError::TooManyParameters {
                maximum: MAX_TO_PARAMETERS,
            }
            .class(),
            "too-many-parameters"
        );
    }
}
