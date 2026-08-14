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

//! SIP address wire parser.
//!
//! This module parses isolated SIP `name-addr` and `addr-spec` values into the
//! owned address types used by the protocol layer.
//!
//! Header-specific parameters are intentionally outside this parser. From,
//! To, Contact, Route, Record-Route, and other header parsers are responsible
//! for separating their own parameters before invoking this module when the
//! address uses the bare `addr-spec` form.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::parser::uri;
use crate::sip::types::address::{Address, BuildError as AddressBuildError, DisplayName, NameAddr};

/// Maximum accepted size of an isolated SIP address in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_ADDRESS_BYTES: usize = 8 * 1024;

/// Parses an isolated SIP `name-addr` or `addr-spec`.
///
/// Leading and trailing spaces and horizontal tabs surrounding the complete
/// address are ignored.
///
/// # Errors
///
/// Returns [`ParseError`] when the address is empty, exceeds the configured
/// size bound, contains malformed `name-addr` syntax, contains an invalid
/// display name, or contains an invalid URI.
pub fn parse(input: &[u8]) -> Result<Address, ParseError> {
    let input = trim_space(input);

    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    if input.len() > MAX_ADDRESS_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_ADDRESS_BYTES,
        });
    }

    match find_open_angle(input)? {
        Some(open) => parse_name_addr(input, open),
        None => parse_addr_spec(input),
    }
}

/// Parses an isolated SIP address from UTF-8 text.
///
/// # Errors
///
/// Returns the same errors as [`parse`].
pub fn parse_str(input: &str) -> Result<Address, ParseError> {
    parse(input.as_bytes())
}

fn parse_addr_spec(input: &[u8]) -> Result<Address, ParseError> {
    if input.contains(&b'>') {
        return Err(ParseError::InvalidNameAddr);
    }

    let uri = uri::parse(input)?;

    Ok(Address::addr_spec(uri))
}

fn parse_name_addr(input: &[u8], open: usize) -> Result<Address, ParseError> {
    let Some(relative_close) = input[open + 1..].iter().position(|byte| *byte == b'>') else {
        return Err(ParseError::MissingClosingAngle);
    };

    let close = open + 1 + relative_close;

    if input[open + 1..close].contains(&b'<') {
        return Err(ParseError::InvalidNameAddr);
    }

    let trailing = trim_space(&input[close + 1..]);

    if !trailing.is_empty() {
        return Err(ParseError::TrailingData);
    }

    let uri_input = trim_space(&input[open + 1..close]);

    if uri_input.is_empty() {
        return Err(ParseError::EmptyUri);
    }

    let uri = uri::parse(uri_input)?;

    let display_input = trim_space(&input[..open]);

    let name_addr = if display_input.is_empty() {
        NameAddr::new(uri)
    } else {
        let display_name = parse_display_name(display_input)?;
        NameAddr::with_display_name(uri, display_name)
    };

    Ok(Address::from(name_addr))
}

fn find_open_angle(input: &[u8]) -> Result<Option<usize>, ParseError> {
    let mut in_quotes = false;
    let mut escaped = false;
    let mut open = None;

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
            b'"' => {
                if open.is_some() {
                    return Err(ParseError::InvalidNameAddr);
                }

                in_quotes = true;
            }
            b'<' => {
                if open.replace(index).is_some() {
                    return Err(ParseError::InvalidNameAddr);
                }
            }
            b'>' if open.is_none() => return Err(ParseError::InvalidNameAddr),
            _ => {}
        }
    }

    if in_quotes || escaped {
        return Err(ParseError::InvalidQuotedString);
    }

    Ok(open)
}

fn parse_display_name(input: &[u8]) -> Result<DisplayName, ParseError> {
    if input.first() == Some(&b'"') {
        return parse_quoted_display_name(input);
    }

    parse_token_display_name(input)
}

fn parse_quoted_display_name(input: &[u8]) -> Result<DisplayName, ParseError> {
    if input.len() < 2 || input.last() != Some(&b'"') {
        return Err(ParseError::InvalidQuotedString);
    }

    let inner = &input[1..input.len() - 1];

    if !inner.contains(&b'\\') && !inner.contains(&b'\t') {
        validate_qdtext(inner)?;

        let value = std::str::from_utf8(inner).map_err(|_| ParseError::InvalidDisplayName)?;

        return DisplayName::new(value).map_err(map_display_name_error);
    }

    let mut decoded = Vec::with_capacity(inner.len());
    let mut index = 0;

    while index < inner.len() {
        let byte = inner[index];

        if byte == b'\\' {
            let Some(escaped) = inner.get(index + 1).copied() else {
                return Err(ParseError::InvalidQuotedString);
            };

            if matches!(escaped, b'\r' | b'\n') || !escaped.is_ascii() {
                return Err(ParseError::InvalidQuotedString);
            }

            if escaped.is_ascii_control() {
                if escaped == b'\t' {
                    decoded.push(b' ');
                    index += 2;
                    continue;
                }

                return Err(ParseError::InvalidDisplayName);
            }

            decoded.push(escaped);
            index += 2;
            continue;
        }

        if byte == b'\t' {
            decoded.push(b' ');
            index += 1;
            continue;
        }

        if !is_qdtext_byte(byte) {
            return Err(ParseError::InvalidQuotedString);
        }

        decoded.push(byte);
        index += 1;
    }

    let value = String::from_utf8(decoded).map_err(|_| ParseError::InvalidDisplayName)?;

    DisplayName::new(value).map_err(map_display_name_error)
}

fn parse_token_display_name(input: &[u8]) -> Result<DisplayName, ParseError> {
    let mut normalized = String::with_capacity(input.len());
    let mut index = 0;
    let mut token_count = 0;

    while index < input.len() {
        if is_space(input[index]) {
            if token_count == 0 {
                return Err(ParseError::InvalidDisplayName);
            }

            while index < input.len() && is_space(input[index]) {
                index += 1;
            }

            if index == input.len() {
                return Err(ParseError::InvalidDisplayName);
            }

            normalized.push(' ');
            continue;
        }

        let token_start = index;

        while index < input.len() && !is_space(input[index]) {
            if !is_token_byte(input[index]) {
                return Err(ParseError::InvalidDisplayName);
            }

            index += 1;
        }

        if index == token_start {
            return Err(ParseError::InvalidDisplayName);
        }

        let token = std::str::from_utf8(&input[token_start..index])
            .map_err(|_| ParseError::InvalidDisplayName)?;

        normalized.push_str(token);
        token_count += 1;
    }

    if token_count == 0 {
        return Err(ParseError::InvalidDisplayName);
    }

    DisplayName::new(normalized).map_err(map_display_name_error)
}

fn validate_qdtext(input: &[u8]) -> Result<(), ParseError> {
    let mut index = 0;

    while index < input.len() {
        let byte = input[index];

        if byte.is_ascii() {
            if byte == b'\t' {
                index += 1;
                continue;
            }

            if !is_qdtext_byte(byte) {
                return Err(ParseError::InvalidQuotedString);
            }

            index += 1;
            continue;
        }

        let remainder = &input[index..];
        let text = std::str::from_utf8(remainder).map_err(|_| ParseError::InvalidDisplayName)?;

        if text.chars().any(char::is_control) {
            return Err(ParseError::InvalidDisplayName);
        }

        return Ok(());
    }

    Ok(())
}

const fn is_qdtext_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~') || !byte.is_ascii()
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

fn trim_space(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(|byte| is_space(*byte)) {
        input = &input[1..];
    }

    while input.last().is_some_and(|byte| is_space(*byte)) {
        input = &input[..input.len() - 1];
    }

    input
}

const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn map_display_name_error(error: AddressBuildError) -> ParseError {
    match error {
        AddressBuildError::DisplayNameTooLong { length, maximum } => {
            ParseError::DisplayNameTooLong { length, maximum }
        }
        AddressBuildError::InvalidDisplayName => ParseError::InvalidDisplayName,
    }
}

/// Failure to parse a SIP address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The address contained no data.
    Empty,

    /// The address exceeded the configured size bound.
    TooLong {
        /// Actual address size in bytes.
        length: usize,

        /// Maximum accepted address size in bytes.
        maximum: usize,
    },

    /// The `name-addr` structure was malformed.
    InvalidNameAddr,

    /// A `name-addr` was missing its closing angle bracket.
    MissingClosingAngle,

    /// Data remained after a complete `name-addr`.
    TrailingData,

    /// The angle brackets contained no URI.
    EmptyUri,

    /// The display name was malformed or unsafe to represent.
    InvalidDisplayName,

    /// The quoted display-name syntax was malformed.
    InvalidQuotedString,

    /// The display name exceeded the configured size bound.
    DisplayNameTooLong {
        /// Actual display-name size in bytes.
        length: usize,

        /// Maximum accepted display-name size in bytes.
        maximum: usize,
    },

    /// The contained URI was invalid.
    InvalidUri(uri::ParseError),
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong { .. } => "too-long",
            Self::InvalidNameAddr => "invalid-name-addr",
            Self::MissingClosingAngle => "missing-closing-angle",
            Self::TrailingData => "trailing-data",
            Self::EmptyUri => "empty-uri",
            Self::InvalidDisplayName => "invalid-display-name",
            Self::InvalidQuotedString => "invalid-quoted-string",
            Self::DisplayNameTooLong { .. } => "display-name-too-long",
            Self::InvalidUri(_) => "invalid-uri",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP address is empty"),
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP address length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidNameAddr => formatter.write_str("SIP name-addr syntax is invalid"),
            Self::MissingClosingAngle => {
                formatter.write_str("SIP name-addr is missing its closing angle bracket")
            }
            Self::TrailingData => formatter.write_str("unexpected data follows the SIP name-addr"),
            Self::EmptyUri => formatter.write_str("SIP name-addr contains an empty URI"),
            Self::InvalidDisplayName => formatter.write_str("SIP display name is invalid"),
            Self::InvalidQuotedString => {
                formatter.write_str("SIP quoted display-name syntax is invalid")
            }
            Self::DisplayNameTooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP display-name length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidUri(error) => write!(formatter, "invalid SIP address URI: {error}"),
        }
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidUri(error) => Some(error),
            _ => None,
        }
    }
}

impl From<uri::ParseError> for ParseError {
    fn from(error: uri::ParseError) -> Self {
        Self::InvalidUri(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_ADDRESS_BYTES, ParseError, parse, parse_str};
    use crate::sip::parser::uri;
    use crate::sip::types::address::Address;

    #[test]
    fn parses_bare_addr_spec() {
        let Ok(address) = parse(b"sip:alice@example.com") else {
            panic!("expected valid addr-spec");
        };

        assert!(address.is_addr_spec());
        assert_eq!(address.display_name(), None);
        assert_eq!(address.to_string(), "sip:alice@example.com");
    }

    #[test]
    fn parses_name_addr_without_display_name() {
        let Ok(address) = parse(b"<sip:alice@example.com>") else {
            panic!("expected valid name-addr");
        };

        assert!(address.is_name_addr());
        assert_eq!(address.display_name(), None);
        assert_eq!(address.to_string(), "<sip:alice@example.com>");
    }

    #[test]
    fn parses_token_display_name() {
        let Ok(address) = parse(b"Alice <sip:alice@example.com>") else {
            panic!("expected valid display name");
        };

        assert_eq!(address.display_name(), Some("Alice"));
        assert_eq!(address.to_string(), "\"Alice\" <sip:alice@example.com>");
    }

    #[test]
    fn parses_multiple_token_display_name() {
        let Ok(address) = parse(b"Alice Smith <sip:alice@example.com>") else {
            panic!("expected valid display name");
        };

        assert_eq!(address.display_name(), Some("Alice Smith"));
        assert_eq!(
            address.to_string(),
            "\"Alice Smith\" <sip:alice@example.com>"
        );
    }

    #[test]
    fn allows_no_space_before_open_angle() {
        let Ok(address) = parse(b"Alice<sip:alice@example.com>") else {
            panic!("expected valid name-addr");
        };

        assert_eq!(address.display_name(), Some("Alice"));
    }

    #[test]
    fn normalizes_horizontal_whitespace_between_tokens() {
        let Ok(address) = parse(b"Alice\t\tSmith <sip:alice@example.com>") else {
            panic!("expected valid token display name");
        };

        assert_eq!(address.display_name(), Some("Alice Smith"));
    }

    #[test]
    fn parses_quoted_display_name() {
        let Ok(address) = parse(br#""Alice Smith" <sip:alice@example.com>"#) else {
            panic!("expected valid quoted display name");
        };

        assert_eq!(address.display_name(), Some("Alice Smith"));
    }

    #[test]
    fn parses_empty_quoted_display_name() {
        let Ok(address) = parse(br#""" <sip:alice@example.com>"#) else {
            panic!("expected valid empty display name");
        };

        assert_eq!(address.display_name(), Some(""));
        assert_eq!(address.to_string(), "\"\" <sip:alice@example.com>");
    }

    #[test]
    fn unescapes_quoted_double_quote() {
        let Ok(address) = parse(br#""Alice \"Voice\"" <sip:alice@example.com>"#) else {
            panic!("expected escaped quote");
        };

        assert_eq!(address.display_name(), Some("Alice \"Voice\""));
        assert_eq!(
            address.to_string(),
            "\"Alice \\\"Voice\\\"\" <sip:alice@example.com>"
        );
    }

    #[test]
    fn unescapes_quoted_backslash() {
        let Ok(address) = parse(br#""Alice\\Voice" <sip:alice@example.com>"#) else {
            panic!("expected escaped backslash");
        };

        assert_eq!(address.display_name(), Some(r"Alice\Voice"));
    }

    #[test]
    fn angle_brackets_inside_quoted_display_name_do_not_end_name() {
        let Ok(address) = parse(br#""Alice <Voice>" <sip:alice@example.com>"#) else {
            panic!("expected quoted angle brackets");
        };

        assert_eq!(address.display_name(), Some("Alice <Voice>"));
    }

    #[test]
    fn parses_quoted_unicode_display_name() {
        let Ok(address) = parse_str("\"الرياض\" <sip:voice@example.com>") else {
            panic!("expected valid UTF-8 display name");
        };

        assert_eq!(address.display_name(), Some("الرياض"));
    }

    #[test]
    fn trims_surrounding_space() {
        let Ok(address) = parse(b" \t Alice <sip:alice@example.com> \t ") else {
            panic!("expected surrounding whitespace");
        };

        assert_eq!(address.display_name(), Some("Alice"));
    }

    #[test]
    fn trims_space_inside_angle_brackets() {
        let Ok(address) = parse(b"< \tsip:alice@example.com\t >") else {
            panic!("expected valid name-addr");
        };

        assert_eq!(address.uri().to_string(), "sip:alice@example.com");
    }

    #[test]
    fn parses_absolute_uri_addr_spec() {
        let Ok(address) = parse(b"tel:+966555123456") else {
            panic!("expected absolute URI addr-spec");
        };

        assert!(address.is_addr_spec());
        assert_eq!(address.to_string(), "tel:+966555123456");
    }

    #[test]
    fn parses_absolute_uri_inside_name_addr() {
        let Ok(address) = parse(b"<tel:+966555123456>") else {
            panic!("expected absolute URI name-addr");
        };

        assert!(address.is_name_addr());
        assert_eq!(address.to_string(), "<tel:+966555123456>");
    }

    #[test]
    fn bare_uri_retains_uri_parameters() {
        let Ok(address) = parse(b"sip:alice@example.com;transport=tcp") else {
            panic!("expected URI parameter");
        };

        let Some(uri) = address.uri().as_sip() else {
            panic!("expected SIP URI");
        };

        assert_eq!(
            uri.parameter("transport")
                .and_then(|parameter| parameter.value()),
            Some("tcp")
        );
    }

    #[test]
    fn name_addr_retains_uri_parameters() {
        let Ok(address) = parse(b"<sip:alice@example.com;transport=tcp;lr>") else {
            panic!("expected URI parameters");
        };

        let Some(uri) = address.uri().as_sip() else {
            panic!("expected SIP URI");
        };

        assert_eq!(uri.parameters().len(), 2);
    }

    #[test]
    fn rejects_empty_address() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b" \t "), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_address_above_size_limit() {
        let input = vec![b'A'; MAX_ADDRESS_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_ADDRESS_BYTES + 1,
                maximum: MAX_ADDRESS_BYTES,
            })
        );
    }

    #[test]
    fn rejects_missing_closing_angle() {
        assert_eq!(
            parse(b"Alice <sip:alice@example.com"),
            Err(ParseError::MissingClosingAngle)
        );
    }

    #[test]
    fn rejects_unmatched_closing_angle() {
        assert_eq!(
            parse(b"sip:alice@example.com>"),
            Err(ParseError::InvalidNameAddr)
        );
    }

    #[test]
    fn rejects_multiple_open_angles() {
        assert_eq!(
            parse(b"Alice <<sip:alice@example.com>"),
            Err(ParseError::InvalidNameAddr)
        );
    }

    #[test]
    fn rejects_trailing_data_after_name_addr() {
        assert_eq!(
            parse(b"<sip:alice@example.com>garbage"),
            Err(ParseError::TrailingData)
        );
    }

    #[test]
    fn rejects_empty_uri_inside_angles() {
        assert_eq!(parse(b"<>"), Err(ParseError::EmptyUri));
    }

    #[test]
    fn rejects_unterminated_quoted_display_name() {
        assert_eq!(
            parse(br#""Alice <sip:alice@example.com>"#),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn rejects_unescaped_quote_inside_quoted_display_name() {
        assert_eq!(
            parse(br#""Alice "Voice"" <sip:alice@example.com>"#),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn rejects_backslash_at_end_of_quoted_display_name() {
        assert_eq!(
            parse(b"\"Alice\\<sip:alice@example.com>"),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn rejects_crlf_in_quoted_display_name() {
        assert_eq!(
            parse(b"\"Alice\r\nInjected\" <sip:alice@example.com>"),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn rejects_special_character_in_unquoted_display_name() {
        assert_eq!(
            parse(b"Alice:Smith <sip:alice@example.com>"),
            Err(ParseError::InvalidDisplayName)
        );
    }

    #[test]
    fn rejects_unquoted_unicode_display_name() {
        assert_eq!(
            parse("الرياض <sip:voice@example.com>".as_bytes()),
            Err(ParseError::InvalidDisplayName)
        );
    }

    #[test]
    fn propagates_uri_error() {
        assert!(matches!(
            parse(b"<sip:alice@>"),
            Err(ParseError::InvalidUri(uri::ParseError::MissingHost))
        ));
    }

    #[test]
    fn parses_from_str() {
        let Ok(address) = parse_str("\"Alice\" <sip:alice@example.com>") else {
            panic!("expected valid address");
        };

        assert_eq!(address.display_name(), Some("Alice"));
    }

    #[test]
    fn produces_expected_address_variant() {
        let Ok(name_addr) = parse(b"<sip:alice@example.com>") else {
            panic!("expected name-addr");
        };

        let Ok(addr_spec) = parse(b"sip:alice@example.com") else {
            panic!("expected addr-spec");
        };

        assert!(matches!(name_addr, Address::NameAddr(_)));
        assert!(matches!(addr_spec, Address::AddrSpec(_)));
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");
        assert_eq!(ParseError::InvalidNameAddr.class(), "invalid-name-addr");
        assert_eq!(
            ParseError::InvalidDisplayName.class(),
            "invalid-display-name"
        );
        assert_eq!(
            ParseError::InvalidQuotedString.class(),
            "invalid-quoted-string"
        );
        assert_eq!(
            ParseError::InvalidUri(uri::ParseError::MissingHost).class(),
            "invalid-uri"
        );
    }
}
