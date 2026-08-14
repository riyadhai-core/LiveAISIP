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

//! SIP `Contact` header.
//!
//! This module provides strongly typed parsing and serialization for SIP
//! `Contact` field values.
//!
//! A Contact field is either a standalone wildcard or a non-empty ordered list
//! of contact entries. Each normal entry contains an address followed by
//! Contact-specific parameters.
//!
//! `q` values use exact integer thousandths rather than floating point.
//! `expires` values use checked unsigned integer seconds. Unknown valid
//! extension parameters are preserved in wire order.
//!
//! URI parameters and Contact header parameters remain separate. A URI that
//! needs semicolon parameters should use the bracketed `name-addr` form so the
//! parameter boundary remains unambiguous.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::sip::parser::address;
use crate::sip::types::address::Address;
use crate::sip::types::uri::Host;

/// Maximum accepted SIP `Contact` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_CONTACT_BYTES: usize = 16 * 1024;

/// Maximum number of comma-separated entries accepted in one Contact field.
pub const MAX_CONTACT_ENTRIES: usize = 64;

/// Maximum number of parameters accepted on one Contact entry.
pub const MAX_CONTACT_PARAMETERS: usize = 64;

/// Maximum accepted Contact extension parameter-name size in bytes.
pub const MAX_CONTACT_PARAMETER_NAME_BYTES: usize = 256;

/// Maximum accepted Contact extension parameter-value size in bytes.
pub const MAX_CONTACT_PARAMETER_VALUE_BYTES: usize = 2048;

/// Maximum accepted decimal digit count for an `expires` value.
///
/// A `u32` can contain at most ten decimal digits.
const MAX_EXPIRES_DIGITS: usize = 10;

/// A validated SIP `Contact` field value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Contact {
    /// Standalone wildcard Contact value.
    Wildcard,

    /// One or more ordered Contact entries.
    Entries(Vec<ContactEntry>),
}

impl Contact {
    /// Creates a wildcard Contact value.
    #[must_use]
    pub const fn wildcard() -> Self {
        Self::Wildcard
    }

    /// Creates a Contact field from a non-empty vector of entries.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::EmptyEntryList`] when `entries` is empty or
    /// [`ParseError::TooManyEntries`] when the configured entry bound is
    /// exceeded.
    pub fn from_entries(entries: Vec<ContactEntry>) -> Result<Self, ParseError> {
        if entries.is_empty() {
            return Err(ParseError::EmptyEntryList);
        }

        if entries.len() > MAX_CONTACT_ENTRIES {
            return Err(ParseError::TooManyEntries {
                maximum: MAX_CONTACT_ENTRIES,
            });
        }

        Ok(Self::Entries(entries))
    }

    /// Parses a Contact field value from wire bytes.
    ///
    /// Header-name and `HCOLON` parsing are outside this function. The input is
    /// the field value only.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the Contact field violates SIP syntax or an
    /// operational size/count bound.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns whether this is the standalone wildcard form.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard)
    }

    /// Returns the normal Contact entries.
    ///
    /// Wildcard Contact values return `None`.
    #[must_use]
    pub fn entries(&self) -> Option<&[ContactEntry]> {
        match self {
            Self::Wildcard => None,
            Self::Entries(entries) => Some(entries),
        }
    }

    /// Returns mutable access to the normal Contact entries.
    ///
    /// Wildcard Contact values return `None`.
    #[must_use]
    pub fn entries_mut(&mut self) -> Option<&mut [ContactEntry]> {
        match self {
            Self::Wildcard => None,
            Self::Entries(entries) => Some(entries),
        }
    }

    /// Consumes the Contact field into its entries.
    ///
    /// Wildcard Contact values return `None`.
    #[must_use]
    pub fn into_entries(self) -> Option<Vec<ContactEntry>> {
        match self {
            Self::Wildcard => None,
            Self::Entries(entries) => Some(entries),
        }
    }
}

impl fmt::Display for Contact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wildcard => formatter.write_char('*'),
            Self::Entries(entries) => {
                for (index, entry) in entries.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(", ")?;
                    }

                    write!(formatter, "{entry}")?;
                }

                Ok(())
            }
        }
    }
}

impl FromStr for Contact {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// One normal Contact entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactEntry {
    address: Address,
    parameters: Vec<ContactParameter>,
}

impl ContactEntry {
    /// Creates a Contact entry without header parameters.
    #[must_use]
    pub const fn new(address: Address) -> Self {
        Self {
            address,
            parameters: Vec::new(),
        }
    }

    /// Returns the Contact address.
    #[must_use]
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// Returns mutable access to the Contact address.
    #[must_use]
    pub const fn address_mut(&mut self) -> &mut Address {
        &mut self.address
    }

    /// Replaces the Contact address.
    pub fn set_address(&mut self, address: Address) {
        self.address = address;
    }

    /// Returns all Contact header parameters in wire order.
    #[must_use]
    pub fn parameters(&self) -> &[ContactParameter] {
        &self.parameters
    }

    /// Returns the Contact preference value when present.
    #[must_use]
    pub fn q(&self) -> Option<QValue> {
        self.parameters
            .iter()
            .find_map(|parameter| match parameter {
                ContactParameter::Q(value) => Some(*value),
                _ => None,
            })
    }

    /// Returns the Contact expiration interval in seconds when present.
    #[must_use]
    pub fn expires(&self) -> Option<u32> {
        self.parameters
            .iter()
            .find_map(|parameter| match parameter {
                ContactParameter::Expires(value) => Some(*value),
                _ => None,
            })
    }

    /// Returns the first extension parameter with the requested
    /// case-insensitive name.
    #[must_use]
    pub fn extension_parameter(&self, name: &str) -> Option<&ContactExtensionParameter> {
        self.parameters
            .iter()
            .find_map(|parameter| match parameter {
                ContactParameter::Extension(extension)
                    if extension.name().eq_ignore_ascii_case(name) =>
                {
                    Some(extension)
                }
                _ => None,
            })
    }

    /// Adds a Contact parameter.
    ///
    /// Parameter names are unique case-insensitively.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::DuplicateParameter`] when the parameter name
    /// already exists or [`ParseError::TooManyParameters`] when the bounded
    /// parameter count has been reached.
    pub fn push_parameter(&mut self, parameter: ContactParameter) -> Result<(), ParseError> {
        if self.parameters.len() >= MAX_CONTACT_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_CONTACT_PARAMETERS,
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

    /// Replaces or adds the `q` parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyParameters`] if no `q` parameter exists
    /// and the parameter capacity has already been reached.
    pub fn set_q(&mut self, value: QValue) -> Result<(), ParseError> {
        if let Some(parameter) = self
            .parameters
            .iter_mut()
            .find(|parameter| matches!(parameter, ContactParameter::Q(_)))
        {
            *parameter = ContactParameter::Q(value);
            return Ok(());
        }

        self.push_parameter(ContactParameter::Q(value))
    }

    /// Replaces or adds the `expires` parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyParameters`] if no `expires` parameter
    /// exists and the parameter capacity has already been reached.
    pub fn set_expires(&mut self, seconds: u32) -> Result<(), ParseError> {
        if let Some(parameter) = self
            .parameters
            .iter_mut()
            .find(|parameter| matches!(parameter, ContactParameter::Expires(_)))
        {
            *parameter = ContactParameter::Expires(seconds);
            return Ok(());
        }

        self.push_parameter(ContactParameter::Expires(seconds))
    }

    /// Returns the number of Contact header parameters.
    #[must_use]
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Consumes the entry into its address and parameters.
    #[must_use]
    pub fn into_parts(self) -> (Address, Vec<ContactParameter>) {
        (self.address, self.parameters)
    }
}

impl fmt::Display for ContactEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.address)?;

        for parameter in &self.parameters {
            write!(formatter, ";{parameter}")?;
        }

        Ok(())
    }
}

/// A typed Contact header parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContactParameter {
    /// Contact preference value.
    Q(QValue),

    /// Contact expiration interval in seconds.
    Expires(u32),

    /// Generic Contact extension parameter.
    Extension(ContactExtensionParameter),
}

impl ContactParameter {
    /// Returns the case-insensitive Contact parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Q(_) => "q",
            Self::Expires(_) => "expires",
            Self::Extension(parameter) => parameter.name(),
        }
    }
}

impl fmt::Display for ContactParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Q(value) => write!(formatter, "q={value}"),
            Self::Expires(seconds) => write!(formatter, "expires={seconds}"),
            Self::Extension(parameter) => fmt::Display::fmt(parameter, formatter),
        }
    }
}

/// Exact SIP Contact `q` value represented in thousandths.
///
/// Valid values range from `0.000` through `1.000`. The integer
/// representation avoids floating-point comparison and serialization issues.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct QValue(u16);

impl QValue {
    /// Smallest valid Contact `q` value.
    pub const MIN: Self = Self(0);

    /// Largest valid Contact `q` value.
    pub const MAX: Self = Self(1000);

    /// Creates a `q` value from exact thousandths.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidQValue`] when `thousandths` exceeds
    /// `1000`.
    pub const fn from_thousandths(thousandths: u16) -> Result<Self, ParseError> {
        if thousandths > 1000 {
            return Err(ParseError::InvalidQValue);
        }

        Ok(Self(thousandths))
    }

    /// Parses a SIP Contact `q` value.
    ///
    /// Accepted grammar is equivalent to:
    ///
    /// ```text
    /// 0 [ "." 0*3DIGIT ]
    /// 1 [ "." 0*3("0") ]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidQValue`] when the value is outside the
    /// valid range or does not satisfy the SIP grammar.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        match input.first().copied() {
            Some(b'0') => parse_zero_q_value(input),
            Some(b'1') => parse_one_q_value(input),
            _ => Err(ParseError::InvalidQValue),
        }
    }

    /// Returns the exact value in thousandths.
    #[must_use]
    pub const fn thousandths(self) -> u16 {
        self.0
    }

    /// Returns whether this value is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns whether this value is exactly one.
    #[must_use]
    pub const fn is_one(self) -> bool {
        self.0 == 1000
    }
}

impl fmt::Display for QValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => formatter.write_char('0'),
            1000 => formatter.write_char('1'),
            value if value % 100 == 0 => write!(formatter, "0.{}", value / 100),
            value if value % 10 == 0 => write!(formatter, "0.{:02}", value / 10),
            value => write!(formatter, "0.{value:03}"),
        }
    }
}

impl FromStr for QValue {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// A validated generic Contact extension parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactExtensionParameter {
    name: Box<str>,
    value: Option<ContactExtensionValue>,
}

impl ContactExtensionParameter {
    /// Creates a valueless Contact extension parameter.
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

    /// Creates an unquoted token-valued Contact extension parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or value is invalid, reserved, or
    /// exceeds an operational size limit.
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
            value: Some(ContactExtensionValue::Token(value)),
        })
    }

    /// Creates a host-valued Contact extension parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name is invalid, reserved, or exceeds
    /// its operational size limit.
    pub fn host(name: impl Into<Box<str>>, host: Host) -> Result<Self, ParseError> {
        let name = name.into();
        validate_extension_name(name.as_bytes())?;

        Ok(Self {
            name,
            value: Some(ContactExtensionValue::Host(host)),
        })
    }

    /// Creates a quoted Contact extension parameter.
    ///
    /// The supplied value is logical text without surrounding quotation marks.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or value is invalid, reserved, or
    /// exceeds an operational size limit.
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
            value: Some(ContactExtensionValue::Quoted(value)),
        })
    }

    /// Returns the parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional typed parameter value.
    #[must_use]
    pub const fn value(&self) -> Option<&ContactExtensionValue> {
        self.value.as_ref()
    }

    /// Returns whether this is a valueless extension parameter.
    #[must_use]
    pub const fn is_flag(&self) -> bool {
        self.value.is_none()
    }
}

impl fmt::Display for ContactExtensionParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)?;

        let Some(value) = &self.value else {
            return Ok(());
        };

        formatter.write_char('=')?;
        fmt::Display::fmt(value, formatter)
    }
}

/// Typed generic Contact extension value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContactExtensionValue {
    /// SIP token value.
    Token(Box<str>),

    /// SIP host value.
    Host(Host),

    /// Logical quoted-string value.
    Quoted(Box<str>),
}

impl ContactExtensionValue {
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

impl fmt::Display for ContactExtensionValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(value) => formatter.write_str(value),
            Self::Host(host) => fmt::Display::fmt(host, formatter),
            Self::Quoted(value) => write_quoted(formatter, value),
        }
    }
}

/// Parses a SIP `Contact` field value.
///
/// # Errors
///
/// Returns [`ParseError`] when the field value violates Contact syntax or an
/// operational bound.
pub fn parse(input: &[u8]) -> Result<Contact, ParseError> {
    if input.len() > MAX_CONTACT_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_CONTACT_BYTES,
        });
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    if input == b"*" {
        return Ok(Contact::Wildcard);
    }

    let entries = parse_entry_list(input)?;

    Contact::from_entries(entries)
}

fn parse_entry_list(input: &[u8]) -> Result<Vec<ContactEntry>, ParseError> {
    let mut entries = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    let mut angle_depth = 0_usize;

    for (index, byte) in input.iter().copied().enumerate() {
        if in_quotes {
            update_quoted_state(byte, &mut in_quotes, &mut escaped)?;
            continue;
        }

        match byte {
            b'"' => in_quotes = true,
            b'<' => {
                angle_depth = angle_depth
                    .checked_add(1)
                    .ok_or(ParseError::InvalidAddressStructure)?;

                if angle_depth > 1 {
                    return Err(ParseError::InvalidAddressStructure);
                }
            }
            b'>' => {
                if angle_depth == 0 {
                    return Err(ParseError::InvalidAddressStructure);
                }

                angle_depth -= 1;
            }
            b',' if angle_depth == 0 => {
                push_entry(&mut entries, &input[start..index])?;
                start = index + 1;
            }
            b'\r' | b'\n' => return Err(ParseError::InvalidLineBreak),
            _ => {}
        }
    }

    if in_quotes || escaped {
        return Err(ParseError::InvalidQuotedString);
    }

    if angle_depth != 0 {
        return Err(ParseError::MissingClosingAngle);
    }

    push_entry(&mut entries, &input[start..])?;

    Ok(entries)
}

fn update_quoted_state(
    byte: u8,
    in_quotes: &mut bool,
    escaped: &mut bool,
) -> Result<(), ParseError> {
    if *escaped {
        if matches!(byte, b'\r' | b'\n') || byte.is_ascii_control() {
            return Err(ParseError::InvalidQuotedString);
        }

        *escaped = false;
        return Ok(());
    }

    match byte {
        b'\\' => *escaped = true,
        b'"' => *in_quotes = false,
        b'\r' | b'\n' => return Err(ParseError::InvalidQuotedString),
        _ => {}
    }

    Ok(())
}

fn push_entry(entries: &mut Vec<ContactEntry>, input: &[u8]) -> Result<(), ParseError> {
    if entries.len() >= MAX_CONTACT_ENTRIES {
        return Err(ParseError::TooManyEntries {
            maximum: MAX_CONTACT_ENTRIES,
        });
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::EmptyEntry);
    }

    if input == b"*" {
        return Err(ParseError::WildcardMustBeAlone);
    }

    entries.push(parse_entry(input)?);
    Ok(())
}

fn parse_entry(input: &[u8]) -> Result<ContactEntry, ParseError> {
    let (address, parameters) = split_address_and_parameters(input)?;
    let mut entry = ContactEntry::new(address);

    parse_parameters(&mut entry, parameters)?;

    Ok(entry)
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
        .find(|(_, byte)| *byte == b'?')
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
            update_quoted_state(byte, &mut in_quotes, &mut escaped)?;
            continue;
        }

        match byte {
            b'"' => in_quotes = true,
            b'<' => return Ok(Some(index)),
            b'>' => return Err(ParseError::InvalidAddressStructure),
            b'\r' | b'\n' => return Err(ParseError::InvalidLineBreak),
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

fn parse_parameters(entry: &mut ContactEntry, mut input: &[u8]) -> Result<(), ParseError> {
    loop {
        input = trim_lws_start(input);

        if input.is_empty() {
            return Ok(());
        }

        if input[0] != b';' {
            return Err(ParseError::UnexpectedTrailingData);
        }

        input = trim_lws_start(&input[1..]);

        if input.is_empty() {
            return Err(ParseError::EmptyParameter);
        }

        if entry.parameter_count() >= MAX_CONTACT_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_CONTACT_PARAMETERS,
            });
        }

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

    if end > MAX_CONTACT_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: end,
            maximum: MAX_CONTACT_PARAMETER_NAME_BYTES,
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
) -> Result<(ContactParameter, &'a [u8]), ParseError> {
    if name.eq_ignore_ascii_case("q") {
        return parse_q_parameter(input);
    }

    if name.eq_ignore_ascii_case("expires") {
        return parse_expires_parameter(input);
    }

    parse_extension_parameter(name, input)
}

fn parse_q_parameter(input: &[u8]) -> Result<(ContactParameter, &[u8]), ParseError> {
    let value = require_parameter_value(input)?;
    let (value, remaining) = take_unquoted_value(value)?;
    let q = QValue::from_bytes(value)?;

    Ok((ContactParameter::Q(q), remaining))
}

fn parse_expires_parameter(input: &[u8]) -> Result<(ContactParameter, &[u8]), ParseError> {
    let value = require_parameter_value(input)?;
    let (value, remaining) = take_unquoted_value(value)?;
    let expires = parse_expires(value)?;

    Ok((ContactParameter::Expires(expires), remaining))
}

fn parse_extension_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(ContactParameter, &'a [u8]), ParseError> {
    validate_extension_name(name.as_bytes())?;

    let input = trim_lws_start(input);

    if input.is_empty() || input[0] == b';' {
        let parameter = ContactExtensionParameter::flag(name)?;

        return Ok((ContactParameter::Extension(parameter), input));
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
) -> Result<(ContactParameter, &'a [u8]), ParseError> {
    let (value, consumed) = parse_quoted_value(input)?;
    let remaining = trim_lws_start(&input[consumed..]);

    if !remaining.is_empty() && remaining[0] != b';' {
        return Err(ParseError::UnexpectedTrailingData);
    }

    let parameter = ContactExtensionParameter::quoted(name, value)?;

    Ok((ContactParameter::Extension(parameter), remaining))
}

fn parse_unquoted_extension_parameter<'a>(
    name: &str,
    input: &'a [u8],
) -> Result<(ContactParameter, &'a [u8]), ParseError> {
    let (value, remaining) = take_unquoted_value(input)?;

    if value.iter().copied().all(is_token_byte) {
        let value = std::str::from_utf8(value).map_err(|_| ParseError::InvalidExtensionValue {
            index: 0,
            byte: value[0],
        })?;

        let parameter = ContactExtensionParameter::token(name, value)?;

        return Ok((ContactParameter::Extension(parameter), remaining));
    }

    if let Ok(host) = parse_host(value) {
        let parameter = ContactExtensionParameter::host(name, host)?;

        return Ok((ContactParameter::Extension(parameter), remaining));
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

fn parse_expires(input: &[u8]) -> Result<u32, ParseError> {
    if input.is_empty() {
        return Err(ParseError::InvalidExpires);
    }

    if input.len() > MAX_EXPIRES_DIGITS {
        return Err(ParseError::ExpiresOverflow);
    }

    let mut value = 0_u32;

    for byte in input.iter().copied() {
        if !byte.is_ascii_digit() {
            return Err(ParseError::InvalidExpires);
        }

        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u32::from(byte - b'0')))
            .ok_or(ParseError::ExpiresOverflow)?;
    }

    Ok(value)
}

fn parse_zero_q_value(input: &[u8]) -> Result<QValue, ParseError> {
    if input == b"0" {
        return Ok(QValue::MIN);
    }

    if input.get(1) != Some(&b'.') {
        return Err(ParseError::InvalidQValue);
    }

    let fraction = &input[2..];

    if fraction.len() > 3 || !fraction.iter().all(u8::is_ascii_digit) {
        return Err(ParseError::InvalidQValue);
    }

    let thousandths = parse_q_fraction(fraction)?;

    Ok(QValue(thousandths))
}

fn parse_one_q_value(input: &[u8]) -> Result<QValue, ParseError> {
    if input == b"1" {
        return Ok(QValue::MAX);
    }

    if input.get(1) != Some(&b'.') {
        return Err(ParseError::InvalidQValue);
    }

    let fraction = &input[2..];

    if fraction.len() > 3 || fraction.iter().any(|byte| *byte != b'0') {
        return Err(ParseError::InvalidQValue);
    }

    Ok(QValue::MAX)
}

fn parse_q_fraction(input: &[u8]) -> Result<u16, ParseError> {
    let mut value = 0_u16;

    for byte in input.iter().copied() {
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u16::from(byte - b'0')))
            .ok_or(ParseError::InvalidQValue)?;
    }

    let multiplier = match input.len() {
        0 => 0,
        1 => 100,
        2 => 10,
        3 => 1,
        _ => return Err(ParseError::InvalidQValue),
    };

    Ok(value * multiplier)
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

    if input.len() > MAX_CONTACT_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: input.len(),
            maximum: MAX_CONTACT_PARAMETER_NAME_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidParameterName { index, byte });
        }
    }

    if input.eq_ignore_ascii_case(b"q") || input.eq_ignore_ascii_case(b"expires") {
        return Err(ParseError::ReservedParameterName);
    }

    Ok(())
}

fn validate_extension_token_value(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    if input.len() > MAX_CONTACT_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_CONTACT_PARAMETER_VALUE_BYTES,
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
    if input.len() > MAX_CONTACT_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_CONTACT_PARAMETER_VALUE_BYTES,
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

/// Failure to parse or construct a SIP `Contact` value.
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

    /// A wildcard appeared as a top-level Contact entry alongside other
    /// Contact content.
    WildcardMustBeAlone,

    /// A normal Contact value was constructed with no entries.
    EmptyEntryList,

    /// A comma-separated Contact entry was empty.
    EmptyEntry,

    /// The Contact field exceeded the configured entry count.
    TooManyEntries {
        /// Maximum accepted Contact entry count.
        maximum: usize,
    },

    /// The Contact address was missing.
    MissingAddress,

    /// The Contact address could not be parsed.
    InvalidAddress(address::ParseError),

    /// The surrounding address structure was malformed.
    InvalidAddressStructure,

    /// A bracketed address was missing its closing `>`.
    MissingClosingAngle,

    /// A bare URI used syntax requiring the `name-addr` form.
    BareUriRequiresNameAddr {
        /// Offset of the byte requiring brackets.
        index: usize,

        /// Byte requiring brackets.
        byte: u8,
    },

    /// A CR or LF appeared inside the field value.
    InvalidLineBreak,

    /// A quoted string was malformed.
    InvalidQuotedString,

    /// Unexpected data followed parsed Contact content.
    UnexpectedTrailingData,

    /// A Contact parameter was empty.
    EmptyParameter,

    /// A Contact parameter name was invalid.
    InvalidParameterName {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A Contact parameter name exceeded its operational size limit.
    ParameterNameTooLong {
        /// Actual parameter-name length in bytes.
        length: usize,

        /// Maximum accepted parameter-name length in bytes.
        maximum: usize,
    },

    /// A known Contact parameter name was supplied through the extension API.
    ReservedParameterName,

    /// A Contact parameter separator was invalid.
    InvalidParameterSeparator {
        /// Unexpected byte.
        byte: u8,
    },

    /// A Contact parameter requiring a value did not contain one.
    MissingParameterValue,

    /// A Contact `q` value was invalid.
    InvalidQValue,

    /// A Contact `expires` value was syntactically invalid.
    InvalidExpires,

    /// A Contact `expires` value exceeded `u32`.
    ExpiresOverflow,

    /// A Contact extension parameter value was invalid.
    InvalidExtensionValue {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A Contact extension parameter value exceeded its operational limit.
    ParameterValueTooLong {
        /// Actual value length in bytes.
        length: usize,

        /// Maximum accepted value length in bytes.
        maximum: usize,
    },

    /// A Contact parameter name appeared more than once.
    DuplicateParameter,

    /// A Contact entry exceeded the configured parameter count.
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
            Self::WildcardMustBeAlone => "wildcard-must-be-alone",
            Self::EmptyEntryList => "empty-entry-list",
            Self::EmptyEntry => "empty-entry",
            Self::TooManyEntries { .. } => "too-many-entries",
            Self::MissingAddress => "missing-address",
            Self::InvalidAddress(_) => "invalid-address",
            Self::InvalidAddressStructure => "invalid-address-structure",
            Self::MissingClosingAngle => "missing-closing-angle",
            Self::BareUriRequiresNameAddr { .. } => "bare-uri-requires-name-addr",
            Self::InvalidLineBreak => "invalid-line-break",
            Self::InvalidQuotedString => "invalid-quoted-string",
            Self::UnexpectedTrailingData => "unexpected-trailing-data",
            Self::EmptyParameter => "empty-parameter",
            Self::InvalidParameterName { .. } => "invalid-parameter-name",
            Self::ParameterNameTooLong { .. } => "parameter-name-too-long",
            Self::ReservedParameterName => "reserved-parameter-name",
            Self::InvalidParameterSeparator { .. } => "invalid-parameter-separator",
            Self::MissingParameterValue => "missing-parameter-value",
            Self::InvalidQValue => "invalid-q-value",
            Self::InvalidExpires => "invalid-expires",
            Self::ExpiresOverflow => "expires-overflow",
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
            Self::Empty => formatter.write_str("SIP Contact field value is empty"),
            Self::TooLong { length, maximum } => {
                write_limit(formatter, "SIP Contact field-value", *length, *maximum)
            }
            Self::WildcardMustBeAlone => {
                formatter.write_str("SIP Contact wildcard must be the only field value")
            }
            Self::EmptyEntryList => formatter.write_str("SIP Contact entry list is empty"),
            Self::EmptyEntry => formatter.write_str("SIP Contact contains an empty entry"),
            Self::TooManyEntries { maximum } => {
                write!(
                    formatter,
                    "SIP Contact contains more than {maximum} entries"
                )
            }
            Self::MissingAddress => formatter.write_str("SIP Contact address is missing"),
            Self::InvalidAddress(error) => {
                write!(formatter, "invalid SIP Contact address: {error}")
            }
            Self::InvalidAddressStructure => {
                formatter.write_str("SIP Contact address structure is invalid")
            }
            Self::MissingClosingAngle => {
                formatter.write_str("SIP Contact name-addr is missing its closing angle bracket")
            }
            Self::BareUriRequiresNameAddr { index, byte } => write!(
                formatter,
                "SIP Contact bare URI contains byte 0x{byte:02x} at offset {index} requiring name-addr form"
            ),
            Self::InvalidLineBreak => {
                formatter.write_str("SIP Contact contains an invalid line break")
            }
            Self::InvalidQuotedString => {
                formatter.write_str("SIP Contact quoted string is invalid")
            }
            Self::UnexpectedTrailingData => {
                formatter.write_str("unexpected data follows SIP Contact content")
            }
            Self::EmptyParameter => formatter.write_str("SIP Contact parameter is empty"),
            Self::InvalidParameterName { index, byte } => {
                write_invalid_byte(formatter, "SIP Contact parameter-name", *index, *byte)
            }
            Self::ParameterNameTooLong { length, maximum } => {
                write_limit(formatter, "SIP Contact parameter-name", *length, *maximum)
            }
            Self::ReservedParameterName => {
                formatter.write_str("SIP Contact parameter name is reserved")
            }
            Self::InvalidParameterSeparator { byte } => {
                write!(
                    formatter,
                    "invalid SIP Contact parameter separator byte 0x{byte:02x}"
                )
            }
            Self::MissingParameterValue => {
                formatter.write_str("SIP Contact parameter value is missing")
            }
            Self::InvalidQValue => formatter.write_str("SIP Contact q value is invalid"),
            Self::InvalidExpires => formatter.write_str("SIP Contact expires value is invalid"),
            Self::ExpiresOverflow => {
                formatter.write_str("SIP Contact expires value exceeds the supported range")
            }
            Self::InvalidExtensionValue { index, byte } => {
                write_invalid_byte(formatter, "SIP Contact extension value", *index, *byte)
            }
            Self::ParameterValueTooLong { length, maximum } => {
                write_limit(formatter, "SIP Contact parameter-value", *length, *maximum)
            }
            Self::DuplicateParameter => {
                formatter.write_str("SIP Contact parameter name is duplicated")
            }
            Self::TooManyParameters { maximum } => {
                write!(
                    formatter,
                    "SIP Contact entry contains more than {maximum} parameters"
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
        Contact, ContactEntry, ContactExtensionParameter, ContactExtensionValue, ContactParameter,
        MAX_CONTACT_BYTES, MAX_CONTACT_ENTRIES, MAX_CONTACT_PARAMETER_NAME_BYTES,
        MAX_CONTACT_PARAMETER_VALUE_BYTES, MAX_CONTACT_PARAMETERS, ParseError, QValue, parse,
    };
    use crate::sip::parser::address;
    use crate::sip::types::address::Address;
    use std::str::FromStr;

    #[test]
    fn parses_wildcard() {
        let Ok(contact) = parse(b"*") else {
            panic!("expected wildcard Contact");
        };

        assert!(contact.is_wildcard());
        assert_eq!(contact.entries(), None);
        assert_eq!(contact.to_string(), "*");
    }

    #[test]
    fn parses_wildcard_with_surrounding_whitespace() {
        let Ok(contact) = parse(b" \t* \t") else {
            panic!("expected wildcard Contact");
        };

        assert!(contact.is_wildcard());
    }

    #[test]
    fn rejects_wildcard_before_normal_contact() {
        assert_eq!(
            parse(b"*, <sip:alice@example.com>"),
            Err(ParseError::WildcardMustBeAlone)
        );
    }

    #[test]
    fn rejects_wildcard_after_normal_contact() {
        assert_eq!(
            parse(b"<sip:alice@example.com>, *"),
            Err(ParseError::WildcardMustBeAlone)
        );
    }

    #[test]
    fn wildcard_with_parameters_is_not_wildcard_form() {
        assert!(matches!(
            parse(b"*;expires=0"),
            Err(ParseError::InvalidAddress(_))
        ));
    }

    #[test]
    fn accepts_star_in_sip_uri_user() {
        let Ok(contact) = parse(b"<sip:*@example.com>") else {
            panic!("expected star in SIP URI user component");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address().uri().to_string(), "sip:*@example.com");
    }

    #[test]
    fn accepts_star_as_quoted_display_name() {
        let Ok(contact) = parse(b"\"*\" <sip:alice@example.com>") else {
            panic!("expected star in quoted display name");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address().display_name(), Some("*"));
    }

    #[test]
    fn accepts_star_as_extension_parameter_value() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;x-value=*") else {
            panic!("expected star extension parameter value");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(
            entries[0]
                .extension_parameter("x-value")
                .and_then(ContactExtensionParameter::value)
                .and_then(ContactExtensionValue::as_str),
            Some("*")
        );
    }

    #[test]
    fn parses_single_name_addr() {
        let Ok(contact) = parse(b"<sip:alice@example.com>") else {
            panic!("expected valid Contact");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries.len(), 1);
        assert!(entries[0].address().is_name_addr());
        assert!(entries[0].parameters().is_empty());
    }

    #[test]
    fn parses_display_name() {
        let Ok(contact) = parse(b"\"Alice Smith\" <sip:alice@example.com>") else {
            panic!("expected valid Contact");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries[0].address().display_name(), Some("Alice Smith"));
    }

    #[test]
    fn parses_bare_addr_spec() {
        let Ok(contact) = parse(b"sip:alice@example.com") else {
            panic!("expected bare Contact address");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert!(entries[0].address().is_addr_spec());
        assert_eq!(
            entries[0].address().uri().to_string(),
            "sip:alice@example.com"
        );
    }

    #[test]
    fn bracketed_uri_parameters_remain_uri_parameters() {
        let Ok(contact) = parse(b"<sip:alice@example.com;transport=tcp>;expires=3600") else {
            panic!("expected Contact with URI parameter");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        let Some(uri) = entries[0].address().uri().as_sip() else {
            panic!("expected SIP URI");
        };

        assert_eq!(
            uri.parameter("transport")
                .and_then(|parameter| parameter.value()),
            Some("tcp")
        );
        assert_eq!(entries[0].expires(), Some(3600));
    }

    #[test]
    fn bare_semicolon_parameter_is_contact_parameter() {
        let Ok(contact) = parse(b"sip:alice@example.com;expires=3600") else {
            panic!("expected bare Contact with header parameter");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        let Some(uri) = entries[0].address().uri().as_sip() else {
            panic!("expected SIP URI");
        };

        assert!(uri.parameters().is_empty());
        assert_eq!(entries[0].expires(), Some(3600));
    }

    #[test]
    fn parses_multiple_contacts() {
        let Ok(contact) = parse(b"<sip:alice@example.com>, \"Bob\" <sip:bob@example.net>;q=0.5")
        else {
            panic!("expected multiple Contacts");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].address().display_name(), Some("Bob"));
        assert_eq!(entries[1].q().map(QValue::thousandths), Some(500));
    }

    #[test]
    fn comma_inside_display_name_does_not_split_contact() {
        let Ok(contact) = parse(b"\"Smith, Alice\" <sip:alice@example.com>, <sip:bob@example.com>")
        else {
            panic!("expected quoted comma");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].address().display_name(), Some("Smith, Alice"));
    }

    #[test]
    fn comma_inside_quoted_extension_does_not_split_contact() {
        let Ok(contact) =
            parse(b"<sip:alice@example.com>;methods=\"INVITE,BYE\", <sip:bob@example.com>")
        else {
            panic!("expected quoted comma");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries.len(), 2);

        assert_eq!(
            entries[0]
                .extension_parameter("methods")
                .and_then(ContactExtensionParameter::value)
                .and_then(ContactExtensionValue::as_str),
            Some("INVITE,BYE")
        );
    }

    #[test]
    fn parses_q_zero() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;q=0") else {
            panic!("expected q=0");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries[0].q(), Some(QValue::MIN));
    }

    #[test]
    fn parses_q_one() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;q=1") else {
            panic!("expected q=1");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries[0].q(), Some(QValue::MAX));
    }

    #[test]
    fn parses_q_fraction() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;q=0.725") else {
            panic!("expected fractional q");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries[0].q().map(QValue::thousandths), Some(725));
    }

    #[test]
    fn q_value_accepts_zero_with_empty_fraction() {
        let Ok(value) = QValue::from_str("0.") else {
            panic!("expected valid q value");
        };

        assert_eq!(value, QValue::MIN);
    }

    #[test]
    fn q_value_accepts_one_with_zero_fraction() {
        let Ok(value) = QValue::from_str("1.000") else {
            panic!("expected valid q value");
        };

        assert_eq!(value, QValue::MAX);
    }

    #[test]
    fn q_value_preserves_leading_fraction_zeroes() {
        let Ok(value) = QValue::from_str("0.007") else {
            panic!("expected valid q value");
        };

        assert_eq!(value.thousandths(), 7);
        assert_eq!(value.to_string(), "0.007");
    }

    #[test]
    fn q_value_serialization_is_canonical() {
        let Ok(first) = QValue::from_thousandths(700) else {
            panic!("expected valid q value");
        };
        let Ok(second) = QValue::from_thousandths(70) else {
            panic!("expected valid q value");
        };
        let Ok(third) = QValue::from_thousandths(7) else {
            panic!("expected valid q value");
        };

        assert_eq!(first.to_string(), "0.7");
        assert_eq!(second.to_string(), "0.07");
        assert_eq!(third.to_string(), "0.007");
    }

    #[test]
    fn rejects_q_above_one() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;q=1.001"),
            Err(ParseError::InvalidQValue)
        );

        assert_eq!(
            parse(b"<sip:alice@example.com>;q=2"),
            Err(ParseError::InvalidQValue)
        );
    }

    #[test]
    fn rejects_q_with_too_many_fraction_digits() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;q=0.1234"),
            Err(ParseError::InvalidQValue)
        );
    }

    #[test]
    fn rejects_malformed_q_value() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;q=.5"),
            Err(ParseError::InvalidQValue)
        );

        assert_eq!(
            parse(b"<sip:alice@example.com>;q=00.5"),
            Err(ParseError::InvalidQValue)
        );
    }

    #[test]
    fn parses_expires() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;expires=3600") else {
            panic!("expected expires parameter");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries[0].expires(), Some(3600));
    }

    #[test]
    fn parses_zero_expires() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;expires=0") else {
            panic!("expected zero expires");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries[0].expires(), Some(0));
    }

    #[test]
    fn accepts_maximum_u32_expires() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;expires=4294967295") else {
            panic!("expected maximum expires value");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries[0].expires(), Some(u32::MAX));
    }

    #[test]
    fn rejects_expires_overflow() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;expires=4294967296"),
            Err(ParseError::ExpiresOverflow)
        );
    }

    #[test]
    fn rejects_non_decimal_expires() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;expires=1h"),
            Err(ParseError::InvalidExpires)
        );
    }

    #[test]
    fn parses_extension_flag() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;ob") else {
            panic!("expected extension flag");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        let Some(parameter) = entries[0].extension_parameter("ob") else {
            panic!("expected extension parameter");
        };

        assert!(parameter.is_flag());
    }

    #[test]
    fn parses_extension_token_value() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;x-mode=active") else {
            panic!("expected extension token");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(
            entries[0]
                .extension_parameter("x-mode")
                .and_then(ContactExtensionParameter::value)
                .and_then(ContactExtensionValue::as_str),
            Some("active")
        );
    }

    #[test]
    fn parses_quoted_sip_instance_extension() {
        let Ok(contact) = parse(
            b"<sip:alice@example.com>;+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-000A95A0E128>\"",
        ) else {
            panic!("expected quoted extension");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(
            entries[0]
                .extension_parameter("+sip.instance")
                .and_then(ContactExtensionParameter::value)
                .and_then(ContactExtensionValue::as_str),
            Some("<urn:uuid:00000000-0000-1000-8000-000A95A0E128>")
        );
    }

    #[test]
    fn quoted_extension_unescapes_quote_and_backslash() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;x-note=\"A \\\"B\\\" \\\\ C\"") else {
            panic!("expected quoted extension");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(
            entries[0]
                .extension_parameter("x-note")
                .and_then(ContactExtensionParameter::value)
                .and_then(ContactExtensionValue::as_str),
            Some("A \"B\" \\ C")
        );
    }

    #[test]
    fn parameter_names_are_case_insensitive() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;Q=0.5;ExPiReS=120") else {
            panic!("expected case-insensitive parameter names");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries[0].q().map(QValue::thousandths), Some(500));
        assert_eq!(entries[0].expires(), Some(120));
    }

    #[test]
    fn extension_lookup_is_case_insensitive() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;X-Mode=active") else {
            panic!("expected extension parameter");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert!(entries[0].extension_parameter("x-mode").is_some());
        assert!(entries[0].extension_parameter("X-MODE").is_some());
    }

    #[test]
    fn preserves_parameter_order() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;x-first=1;q=0.8;expires=60;x-last=2")
        else {
            panic!("expected ordered Contact parameters");
        };

        let Some(entries) = contact.entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries[0].parameters().len(), 4);

        assert!(matches!(
            entries[0].parameters()[0],
            ContactParameter::Extension(_)
        ));
        assert!(matches!(entries[0].parameters()[1], ContactParameter::Q(_)));
        assert!(matches!(
            entries[0].parameters()[2],
            ContactParameter::Expires(_)
        ));
        assert!(matches!(
            entries[0].parameters()[3],
            ContactParameter::Extension(_)
        ));
    }

    #[test]
    fn rejects_duplicate_q() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;q=0.5;Q=0.7"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn rejects_duplicate_expires() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;expires=60;EXPIRES=120"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn rejects_duplicate_extension_parameter_case_insensitively() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;X-Mode=one;x-mode=two"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn extension_api_rejects_reserved_q_name() {
        assert_eq!(
            ContactExtensionParameter::flag("Q"),
            Err(ParseError::ReservedParameterName)
        );
    }

    #[test]
    fn extension_api_rejects_reserved_expires_name() {
        assert_eq!(
            ContactExtensionParameter::flag("Expires"),
            Err(ParseError::ReservedParameterName)
        );
    }

    #[test]
    fn rejects_empty_field() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b" \t "), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_field_above_size_limit() {
        let input = vec![b'A'; MAX_CONTACT_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_CONTACT_BYTES + 1,
                maximum: MAX_CONTACT_BYTES,
            })
        );
    }

    #[test]
    fn rejects_empty_comma_entry() {
        assert_eq!(
            parse(b"<sip:alice@example.com>, ,<sip:bob@example.com>"),
            Err(ParseError::EmptyEntry)
        );
    }

    #[test]
    fn rejects_trailing_comma() {
        assert_eq!(
            parse(b"<sip:alice@example.com>,"),
            Err(ParseError::EmptyEntry)
        );
    }

    #[test]
    fn rejects_missing_closing_angle() {
        assert_eq!(
            parse(b"<sip:alice@example.com"),
            Err(ParseError::MissingClosingAngle)
        );
    }

    #[test]
    fn rejects_unmatched_closing_angle() {
        assert_eq!(
            parse(b"sip:alice@example.com>"),
            Err(ParseError::InvalidAddressStructure)
        );
    }

    #[test]
    fn rejects_bare_uri_with_query_section() {
        assert_eq!(
            parse(b"sip:alice@example.com?subject=test"),
            Err(ParseError::BareUriRequiresNameAddr {
                index: 21,
                byte: b'?',
            })
        );
    }

    #[test]
    fn rejects_empty_parameter() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;"),
            Err(ParseError::EmptyParameter)
        );
    }

    #[test]
    fn rejects_parameter_without_valid_separator() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;x-mode active"),
            Err(ParseError::InvalidParameterSeparator { byte: b'a' })
        );
    }

    #[test]
    fn rejects_q_without_value() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;q"),
            Err(ParseError::MissingParameterValue)
        );
    }

    #[test]
    fn rejects_expires_without_value() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;expires"),
            Err(ParseError::MissingParameterValue)
        );
    }

    #[test]
    fn rejects_unterminated_quoted_extension() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;x-note=\"unfinished"),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn rejects_crlf_in_quoted_extension() {
        assert_eq!(
            parse(b"<sip:alice@example.com>;x-note=\"one\r\ntwo\""),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn rejects_crlf_in_field() {
        assert_eq!(
            parse(b"<sip:alice@example.com>\r\n"),
            Err(ParseError::InvalidLineBreak)
        );
    }

    #[test]
    fn creates_q_from_thousandths() {
        let Ok(value) = QValue::from_thousandths(875) else {
            panic!("expected valid q value");
        };

        assert_eq!(value.thousandths(), 875);
    }

    #[test]
    fn rejects_q_thousandths_above_maximum() {
        assert_eq!(
            QValue::from_thousandths(1001),
            Err(ParseError::InvalidQValue)
        );
    }

    #[test]
    fn contact_entry_sets_q() {
        let Ok(address) = address::parse(b"<sip:alice@example.com>") else {
            panic!("expected valid address");
        };

        let mut entry = ContactEntry::new(address);

        let Ok(first) = QValue::from_thousandths(500) else {
            panic!("expected valid q value");
        };
        let Ok(second) = QValue::from_thousandths(800) else {
            panic!("expected valid q value");
        };

        assert!(entry.set_q(first).is_ok());
        assert!(entry.set_q(second).is_ok());

        assert_eq!(entry.q().map(QValue::thousandths), Some(800));
        assert_eq!(entry.parameter_count(), 1);
    }

    #[test]
    fn contact_entry_sets_expires() {
        let Ok(address) = address::parse(b"<sip:alice@example.com>") else {
            panic!("expected valid address");
        };

        let mut entry = ContactEntry::new(address);

        assert!(entry.set_expires(60).is_ok());
        assert!(entry.set_expires(120).is_ok());

        assert_eq!(entry.expires(), Some(120));
        assert_eq!(entry.parameter_count(), 1);
    }

    #[test]
    fn creates_extension_flag() {
        let Ok(parameter) = ContactExtensionParameter::flag("ob") else {
            panic!("expected extension flag");
        };

        assert!(parameter.is_flag());
        assert_eq!(parameter.to_string(), "ob");
    }

    #[test]
    fn creates_extension_token() {
        let Ok(parameter) = ContactExtensionParameter::token("x-mode", "active") else {
            panic!("expected extension token");
        };

        assert_eq!(parameter.to_string(), "x-mode=active");
    }

    #[test]
    fn creates_extension_quoted_value() {
        let Ok(parameter) = ContactExtensionParameter::quoted("methods", "INVITE,BYE") else {
            panic!("expected extension quoted value");
        };

        assert_eq!(parameter.to_string(), "methods=\"INVITE,BYE\"");
    }

    #[test]
    fn rejects_extension_name_above_size_limit() {
        let name = "A".repeat(MAX_CONTACT_PARAMETER_NAME_BYTES + 1);

        assert_eq!(
            ContactExtensionParameter::flag(name),
            Err(ParseError::ParameterNameTooLong {
                length: MAX_CONTACT_PARAMETER_NAME_BYTES + 1,
                maximum: MAX_CONTACT_PARAMETER_NAME_BYTES,
            })
        );
    }

    #[test]
    fn rejects_extension_value_above_size_limit() {
        let value = "A".repeat(MAX_CONTACT_PARAMETER_VALUE_BYTES + 1);

        assert_eq!(
            ContactExtensionParameter::token("x-value", value),
            Err(ParseError::ParameterValueTooLong {
                length: MAX_CONTACT_PARAMETER_VALUE_BYTES + 1,
                maximum: MAX_CONTACT_PARAMETER_VALUE_BYTES,
            })
        );
    }

    #[test]
    fn enforces_parameter_count() {
        let Ok(address) = address::parse(b"<sip:alice@example.com>") else {
            panic!("expected valid address");
        };

        let mut entry = ContactEntry::new(address);

        for index in 0..MAX_CONTACT_PARAMETERS {
            let name = format!("x-{index}");
            let Ok(extension) = ContactExtensionParameter::flag(name) else {
                panic!("expected extension parameter");
            };

            assert!(
                entry
                    .push_parameter(ContactParameter::Extension(extension))
                    .is_ok()
            );
        }

        let Ok(extra) = ContactExtensionParameter::flag("x-extra") else {
            panic!("expected extension parameter");
        };

        assert_eq!(
            entry.push_parameter(ContactParameter::Extension(extra)),
            Err(ParseError::TooManyParameters {
                maximum: MAX_CONTACT_PARAMETERS,
            })
        );
    }

    #[test]
    fn enforces_entry_count() {
        let Ok(address) = address::parse(b"<sip:alice@example.com>") else {
            panic!("expected valid address");
        };

        let entries = (0..MAX_CONTACT_ENTRIES)
            .map(|_| ContactEntry::new(address.clone()))
            .collect::<Vec<_>>();

        assert!(Contact::from_entries(entries).is_ok());

        let too_many = (0..=MAX_CONTACT_ENTRIES)
            .map(|_| ContactEntry::new(address.clone()))
            .collect::<Vec<_>>();

        assert_eq!(
            Contact::from_entries(too_many),
            Err(ParseError::TooManyEntries {
                maximum: MAX_CONTACT_ENTRIES,
            })
        );
    }

    #[test]
    fn rejects_empty_entry_vector() {
        assert_eq!(
            Contact::from_entries(Vec::new()),
            Err(ParseError::EmptyEntryList)
        );
    }

    #[test]
    fn display_canonicalizes_known_parameters() {
        let Ok(contact) = parse(
            b"\"Alice\" <sip:alice@example.com>;Q=0.700;EXPIRES=060;x-mode=\"voice gateway\"",
        ) else {
            panic!("expected valid Contact");
        };

        assert_eq!(
            contact.to_string(),
            "\"Alice\" <sip:alice@example.com>;q=0.7;expires=60;x-mode=\"voice gateway\""
        );
    }

    #[test]
    fn parses_from_str() {
        let Ok(contact) = Contact::from_str("<sip:alice@example.com>;q=0.5") else {
            panic!("expected valid Contact");
        };

        assert!(!contact.is_wildcard());
    }

    #[test]
    fn consumes_normal_contact_into_entries() {
        let Ok(contact) = parse(b"<sip:alice@example.com>, <sip:bob@example.com>") else {
            panic!("expected valid Contact");
        };

        let Some(entries) = contact.into_entries() else {
            panic!("expected normal Contact entries");
        };

        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn wildcard_into_entries_returns_none() {
        assert_eq!(Contact::wildcard().into_entries(), None);
    }

    #[test]
    fn consumes_entry_into_parts() {
        let Ok(contact) = parse(b"<sip:alice@example.com>;expires=60") else {
            panic!("expected valid Contact");
        };

        let Some(mut entries) = contact.into_entries() else {
            panic!("expected normal Contact entries");
        };

        let entry = entries.remove(0);
        let (address, parameters) = entry.into_parts();

        assert!(matches!(address, Address::NameAddr(_)));
        assert_eq!(parameters.len(), 1);
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");
        assert_eq!(
            ParseError::WildcardMustBeAlone.class(),
            "wildcard-must-be-alone"
        );
        assert_eq!(ParseError::EmptyEntry.class(), "empty-entry");
        assert_eq!(
            ParseError::InvalidAddressStructure.class(),
            "invalid-address-structure"
        );
        assert_eq!(ParseError::InvalidQValue.class(), "invalid-q-value");
        assert_eq!(ParseError::InvalidExpires.class(), "invalid-expires");
        assert_eq!(ParseError::ExpiresOverflow.class(), "expires-overflow");
        assert_eq!(
            ParseError::DuplicateParameter.class(),
            "duplicate-parameter"
        );
        assert_eq!(
            ParseError::TooManyParameters {
                maximum: MAX_CONTACT_PARAMETERS,
            }
            .class(),
            "too-many-parameters"
        );
    }
}
