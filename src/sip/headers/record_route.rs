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

//! SIP `Record-Route` header.
//!
//! Values are retained as an ordered, bounded list of mandatory `name-addr`
//! entries. URI parameters remain inside each address URI, while generic
//! header parameters are preserved separately and in wire order. Parsing is
//! quote- and angle-aware, so commas inside quoted display names or URIs are
//! never mistaken for list separators.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

use crate::sip::parser::address;
use crate::sip::types::address::Address;
use crate::sip::types::uri::Uri;

/// Maximum accepted `Record-Route` field-value size.
pub const MAX_RECORD_ROUTE_BYTES: usize = 16 * 1024;
/// Maximum entries accepted in one field value.
pub const MAX_RECORD_ROUTE_ENTRIES: usize = 64;
/// Maximum header parameters accepted on one entry.
pub const MAX_RECORD_ROUTE_PARAMETERS: usize = 64;
/// Maximum parameter-name size.
pub const MAX_RECORD_ROUTE_PARAMETER_NAME_BYTES: usize = 256;
/// Maximum parameter-value size.
pub const MAX_RECORD_ROUTE_PARAMETER_VALUE_BYTES: usize = 2048;

/// A validated ordered `Record-Route` field value.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordRoute {
    entries: Vec<RecordRouteEntry>,
}

impl RecordRoute {
    /// Parses a field value from wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] for invalid syntax or an exceeded bound.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Creates a non-empty bounded field from entries.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized entry list.
    pub fn from_entries(entries: Vec<RecordRouteEntry>) -> Result<Self, ParseError> {
        check_entry_count(entries.len())?;
        Ok(Self { entries })
    }

    /// Returns entries in wire order.
    #[must_use]
    pub fn entries(&self) -> &[RecordRouteEntry] {
        &self.entries
    }

    /// Consumes the field into its entries.
    #[must_use]
    pub fn into_entries(self) -> Vec<RecordRouteEntry> {
        self.entries
    }
}

impl fmt::Debug for RecordRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordRoute")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RecordRoute {
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

impl FromStr for RecordRoute {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// One `Record-Route` entry.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordRouteEntry {
    address: Address,
    parameters: Vec<RecordRouteParameter>,
}

impl RecordRouteEntry {
    /// Creates an entry from a bracketed `name-addr`.
    ///
    /// # Errors
    ///
    /// Rejects the bare `addr-spec` form required to be bracketed by the
    /// `Record-Route` grammar.
    pub fn new(address: Address) -> Result<Self, ParseError> {
        if !address.is_name_addr() {
            return Err(ParseError::NameAddrRequired);
        }
        Ok(Self {
            address,
            parameters: Vec::new(),
        })
    }

    /// Returns the route address.
    #[must_use]
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the route URI.
    #[must_use]
    pub const fn uri(&self) -> &Uri {
        self.address.uri()
    }

    /// Returns generic header parameters in wire order.
    #[must_use]
    pub fn parameters(&self) -> &[RecordRouteParameter] {
        &self.parameters
    }

    /// Adds a bounded parameter.
    ///
    /// # Errors
    ///
    /// Rejects capacity and duplicate case-insensitive names.
    pub fn push_parameter(&mut self, parameter: RecordRouteParameter) -> Result<(), ParseError> {
        if self.parameters.len() >= MAX_RECORD_ROUTE_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_RECORD_ROUTE_PARAMETERS,
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
}

impl fmt::Debug for RecordRouteEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordRouteEntry")
            .field("scheme", &self.uri().scheme())
            .field("parameter_count", &self.parameters.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RecordRouteEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.address)?;
        for parameter in &self.parameters {
            write!(formatter, ";{parameter}")?;
        }
        Ok(())
    }
}

/// A generic `Record-Route` header parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordRouteParameter {
    name: Box<str>,
    value: Option<Box<str>>,
    quoted: bool,
}

impl RecordRouteParameter {
    /// Creates a validated parameter.
    ///
    /// The value is logical text; `quoted` selects quoted serialization.
    ///
    /// # Errors
    ///
    /// Rejects invalid or oversized names and values.
    pub fn new(
        name: impl Into<Box<str>>,
        value: Option<Box<str>>,
        quoted: bool,
    ) -> Result<Self, ParseError> {
        let name = name.into();
        validate_name(name.as_bytes())?;
        if let Some(value) = value.as_deref() {
            validate_value(value.as_bytes(), quoted)?;
        } else if quoted {
            return Err(ParseError::InvalidParameterValue);
        }
        Ok(Self {
            name,
            value,
            quoted,
        })
    }

    /// Returns the case-insensitive parameter name.
    #[must_use]
    pub const fn name(&self) -> &str {
        &self.name
    }

    /// Returns the logical parameter value.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Returns whether the value uses quoted serialization.
    #[must_use]
    pub const fn is_quoted(&self) -> bool {
        self.quoted
    }
}

impl fmt::Display for RecordRouteParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)?;
        if let Some(value) = &self.value {
            formatter.write_char('=')?;
            if self.quoted {
                formatter.write_char('"')?;
                for character in value.chars() {
                    if matches!(character, '"' | '\\') {
                        formatter.write_char('\\')?;
                    }
                    formatter.write_char(character)?;
                }
                formatter.write_char('"')
            } else {
                formatter.write_str(value)
            }
        } else {
            Ok(())
        }
    }
}

/// Parses a `Record-Route` field value.
///
/// # Errors
///
/// Returns [`ParseError`] for invalid syntax or an exceeded operational bound.
pub fn parse(input: &[u8]) -> Result<RecordRoute, ParseError> {
    if input.len() > MAX_RECORD_ROUTE_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_RECORD_ROUTE_BYTES,
        });
    }
    let input = trim(input);
    if input.is_empty() {
        return Err(ParseError::Empty);
    }
    if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ParseError::InvalidControl);
    }

    let ranges = split_entries(input)?;
    check_entry_count(ranges.len())?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(ranges.len())
        .map_err(|_| ParseError::AllocationFailed)?;
    for (start, end) in ranges {
        entries.push(parse_entry(trim(&input[start..end]))?);
    }
    Ok(RecordRoute { entries })
}

fn parse_entry(input: &[u8]) -> Result<RecordRouteEntry, ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyEntry);
    }
    let close = find_closing_angle(input)?;
    let address_bytes = trim(&input[..=close]);
    let parsed = address::parse(address_bytes).map_err(ParseError::InvalidAddress)?;
    let mut entry = RecordRouteEntry::new(parsed)?;
    parse_parameters(&input[close + 1..], &mut entry)?;
    Ok(entry)
}

fn find_closing_angle(input: &[u8]) -> Result<usize, ParseError> {
    let mut quoted = false;
    let mut escaped = false;
    let mut opened = false;
    for (index, byte) in input.iter().copied().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'<' if !opened => opened = true,
            b'>' if opened => return Ok(index),
            b'<' | b'>' => return Err(ParseError::InvalidAddressLayout),
            _ => {}
        }
    }
    Err(ParseError::NameAddrRequired)
}

fn split_entries(input: &[u8]) -> Result<Vec<(usize, usize)>, ParseError> {
    let mut ranges = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut angle_depth = 0_u8;
    for (index, byte) in input.iter().copied().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'<' if angle_depth == 0 => angle_depth = 1,
            b'>' if angle_depth == 1 => angle_depth = 0,
            b'<' | b'>' => return Err(ParseError::InvalidAddressLayout),
            b',' if angle_depth == 0 => {
                if trim(&input[start..index]).is_empty() {
                    return Err(ParseError::EmptyEntry);
                }
                ranges.push((start, index));
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted || escaped || angle_depth != 0 {
        return Err(ParseError::InvalidAddressLayout);
    }
    if trim(&input[start..]).is_empty() {
        return Err(ParseError::EmptyEntry);
    }
    ranges.push((start, input.len()));
    Ok(ranges)
}

fn parse_parameters(input: &[u8], entry: &mut RecordRouteEntry) -> Result<(), ParseError> {
    let mut input = trim(input);
    while !input.is_empty() {
        if input[0] != b';' {
            return Err(ParseError::InvalidParameterLayout);
        }
        input = trim_start(&input[1..]);
        let name_end = input
            .iter()
            .position(|byte| matches!(byte, b'=' | b';' | b' ' | b'\t'))
            .unwrap_or(input.len());
        let name = &input[..name_end];
        validate_name(name)?;
        input = trim_start(&input[name_end..]);

        let (value, quoted, remaining) = if input.first() == Some(&b'=') {
            input = trim_start(&input[1..]);
            if input.first() == Some(&b'"') {
                parse_quoted_value(input)?
            } else {
                let end = input
                    .iter()
                    .position(|byte| *byte == b';')
                    .unwrap_or(input.len());
                let raw = trim(&input[..end]);
                validate_value(raw, false)?;
                (Some(decode_ascii(raw)?), false, &input[end..])
            }
        } else {
            (None, false, input)
        };

        let parameter = RecordRouteParameter::new(decode_ascii(name)?, value, quoted)?;
        entry.push_parameter(parameter)?;
        input = trim_start(remaining);
    }
    Ok(())
}

fn parse_quoted_value(input: &[u8]) -> Result<(Option<Box<str>>, bool, &[u8]), ParseError> {
    let mut decoded = Vec::new();
    let mut escaped = false;
    for index in 1..input.len() {
        let byte = input[index];
        if escaped {
            if byte.is_ascii_control() {
                return Err(ParseError::InvalidParameterValue);
            }
            decoded.push(byte);
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            validate_value(&decoded, true)?;
            let value = String::from_utf8(decoded)
                .map_err(|_| ParseError::InvalidParameterValue)?
                .into_boxed_str();
            return Ok((Some(value), true, &input[index + 1..]));
        } else {
            decoded.push(byte);
        }
    }
    Err(ParseError::InvalidParameterValue)
}

fn validate_name(name: &[u8]) -> Result<(), ParseError> {
    if name.is_empty()
        || name.len() > MAX_RECORD_ROUTE_PARAMETER_NAME_BYTES
        || !name.iter().copied().all(is_token)
    {
        return Err(ParseError::InvalidParameterName);
    }
    Ok(())
}

fn validate_value(value: &[u8], quoted: bool) -> Result<(), ParseError> {
    if value.is_empty() || value.len() > MAX_RECORD_ROUTE_PARAMETER_VALUE_BYTES {
        return Err(ParseError::InvalidParameterValue);
    }
    let valid = if quoted {
        value
            .iter()
            .all(|byte| *byte == b'\t' || (*byte >= 0x20 && *byte != 0x7f))
    } else {
        value.iter().copied().all(is_gen_value)
    };
    if !valid {
        return Err(ParseError::InvalidParameterValue);
    }
    Ok(())
}

fn decode_ascii(input: &[u8]) -> Result<Box<str>, ParseError> {
    std::str::from_utf8(input)
        .map(Into::into)
        .map_err(|_| ParseError::InvalidParameterValue)
}

fn check_entry_count(count: usize) -> Result<(), ParseError> {
    if count == 0 {
        Err(ParseError::Empty)
    } else if count > MAX_RECORD_ROUTE_ENTRIES {
        Err(ParseError::TooManyEntries {
            maximum: MAX_RECORD_ROUTE_ENTRIES,
        })
    } else {
        Ok(())
    }
}

const fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

const fn is_gen_value(byte: u8) -> bool {
    is_token(byte) || matches!(byte, b':' | b'[' | b']')
}

fn trim(input: &[u8]) -> &[u8] {
    let input = trim_start(input);
    let end = input
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(0, |index| index + 1);
    &input[..end]
}

fn trim_start(input: &[u8]) -> &[u8] {
    let start = input
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(input.len());
    &input[start..]
}

/// Failure to parse or construct `Record-Route`.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// Field value was empty.
    Empty,
    /// Field exceeded its byte bound.
    TooLong {
        /// Observed byte length.
        length: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// A list element was empty.
    EmptyEntry,
    /// Too many list entries were supplied.
    TooManyEntries {
        /// Maximum accepted entry count.
        maximum: usize,
    },
    /// The mandatory bracketed address form was absent.
    NameAddrRequired,
    /// Quote or angle boundaries were malformed.
    InvalidAddressLayout,
    /// Address parsing failed.
    InvalidAddress(address::ParseError),
    /// A control byte was present.
    InvalidControl,
    /// Parameter separators were malformed.
    InvalidParameterLayout,
    /// Parameter name was invalid.
    InvalidParameterName,
    /// Parameter value was invalid.
    InvalidParameterValue,
    /// Parameter name was duplicated.
    DuplicateParameter,
    /// Too many parameters were supplied.
    TooManyParameters {
        /// Maximum accepted parameter count.
        maximum: usize,
    },
    /// Bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SIP Record-Route field value")
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
    use super::{ParseError, RecordRoute};

    #[test]
    fn parses_ordered_routes_and_parameters() {
        let Ok(value) = RecordRoute::from_bytes(
            br#"<sip:a.example;lr>;x=token, "Proxy, East" <sips:b.example>;note="a,b""#,
        ) else {
            panic!("valid Record-Route")
        };
        assert_eq!(value.entries().len(), 2);
        assert_eq!(value.entries()[0].uri().to_string(), "sip:a.example;lr");
        assert_eq!(value.entries()[0].parameters()[0].value(), Some("token"));
        assert_eq!(value.entries()[1].parameters()[0].value(), Some("a,b"));
    }

    #[test]
    fn requires_name_addr_and_nonempty_entries() {
        assert!(matches!(
            RecordRoute::from_bytes(b"sip:a.example"),
            Err(ParseError::NameAddrRequired)
        ));
        assert!(matches!(
            RecordRoute::from_bytes(b"<sip:a.example>,"),
            Err(ParseError::EmptyEntry)
        ));
    }

    #[test]
    fn rejects_duplicate_parameters_case_insensitively() {
        assert!(matches!(
            RecordRoute::from_bytes(b"<sip:a.example>;x=1;X=2"),
            Err(ParseError::DuplicateParameter)
        ));
    }

    #[test]
    fn canonical_serialization_round_trips() {
        let input = br#"<sip:a.example;lr>;note="a\\\"b", <sip:b.example>"#;
        let value = RecordRoute::from_bytes(input).unwrap_or_else(|_| panic!("parse"));
        let serialized = value.to_string();
        assert!(RecordRoute::from_bytes(serialized.as_bytes()).is_ok());
    }

    #[test]
    fn debug_is_redacted() {
        let value = RecordRoute::from_bytes(b"<sip:private-user@secret.example;lr>")
            .unwrap_or_else(|_| panic!("parse"));
        let debug = format!("{value:?} {:?}", value.entries()[0]);
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("secret.example"));
    }
}
