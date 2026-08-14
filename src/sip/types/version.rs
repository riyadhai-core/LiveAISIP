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

//! SIP protocol version.
//!
//! `LiveAISIP` currently supports SIP version 2.0. Incoming version strings
//! are parsed case-insensitively as required by SIP, while serialization always
//! emits the canonical uppercase `SIP/2.0` representation.
//!
//! Syntactically valid but unsupported SIP versions are distinguished from
//! malformed version strings so higher protocol layers can respond correctly.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

/// Maximum accepted size of a SIP version token in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_VERSION_BYTES: usize = 32;

/// SIP protocol version supported by `LiveAISIP`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Version {
    /// SIP version 2.0.
    #[default]
    Sip2,
}

impl Version {
    /// Parses a SIP protocol version from its wire representation.
    ///
    /// The `SIP` protocol name is matched case-insensitively. The supported
    /// version number itself must be the literal `2.0`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooLong`] when the token exceeds the configured
    /// bound, [`ParseError::InvalidSyntax`] when the token does not match the
    /// SIP version grammar, or [`ParseError::Unsupported`] when the token is
    /// syntactically valid but is not `SIP/2.0`.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() > MAX_VERSION_BYTES {
            return Err(ParseError::TooLong {
                length: input.len(),
                maximum: MAX_VERSION_BYTES,
            });
        }

        validate_syntax(input)?;

        if input.eq_ignore_ascii_case(b"SIP/2.0") {
            return Ok(Self::Sip2);
        }

        Err(ParseError::Unsupported)
    }

    /// Returns the canonical SIP wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sip2 => "SIP/2.0",
        }
    }

    /// Returns the canonical SIP wire representation as bytes.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Sip2 => b"SIP/2.0",
        }
    }

    /// Returns the SIP major version number.
    #[must_use]
    pub const fn major(self) -> u8 {
        match self {
            Self::Sip2 => 2,
        }
    }

    /// Returns the SIP minor version number.
    #[must_use]
    pub const fn minor(self) -> u8 {
        match self {
            Self::Sip2 => 0,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Version {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// Failure to parse or support a SIP protocol version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The version token exceeded the configured size bound.
    TooLong {
        /// Actual version-token length in bytes.
        length: usize,

        /// Maximum accepted version-token length in bytes.
        maximum: usize,
    },

    /// The value did not match the SIP version grammar.
    InvalidSyntax,

    /// The value was syntactically valid but is not supported by `LiveAISIP`.
    Unsupported,
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::TooLong { .. } => "too-long",
            Self::InvalidSyntax => "invalid-syntax",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP version length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidSyntax => formatter.write_str("invalid SIP version syntax"),
            Self::Unsupported => formatter.write_str("unsupported SIP version"),
        }
    }
}

impl StdError for ParseError {}

fn validate_syntax(input: &[u8]) -> Result<(), ParseError> {
    let Some(prefix) = input.get(..4) else {
        return Err(ParseError::InvalidSyntax);
    };

    if !prefix.eq_ignore_ascii_case(b"SIP/") {
        return Err(ParseError::InvalidSyntax);
    }

    let version = &input[4..];

    let Some(dot_index) = version.iter().position(|byte| *byte == b'.') else {
        return Err(ParseError::InvalidSyntax);
    };

    let major = &version[..dot_index];
    let minor = &version[dot_index + 1..];

    if major.is_empty() || minor.is_empty() {
        return Err(ParseError::InvalidSyntax);
    }

    if !major.iter().all(u8::is_ascii_digit) || !minor.iter().all(u8::is_ascii_digit) {
        return Err(ParseError::InvalidSyntax);
    }

    if minor.contains(&b'.') {
        return Err(ParseError::InvalidSyntax);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_VERSION_BYTES, ParseError, Version};
    use std::str::FromStr;

    #[test]
    fn parses_sip_2_0() {
        assert_eq!(Version::from_bytes(b"SIP/2.0"), Ok(Version::Sip2));
    }

    #[test]
    fn protocol_name_is_case_insensitive() {
        assert_eq!(Version::from_bytes(b"sip/2.0"), Ok(Version::Sip2));
        assert_eq!(Version::from_bytes(b"SiP/2.0"), Ok(Version::Sip2));
    }

    #[test]
    fn serialization_is_canonical_uppercase() {
        assert_eq!(Version::Sip2.as_str(), "SIP/2.0");
        assert_eq!(Version::Sip2.as_bytes(), b"SIP/2.0");
        assert_eq!(Version::Sip2.to_string(), "SIP/2.0");
    }

    #[test]
    fn exposes_supported_version_numbers() {
        assert_eq!(Version::Sip2.major(), 2);
        assert_eq!(Version::Sip2.minor(), 0);
    }

    #[test]
    fn default_is_sip_2_0() {
        assert_eq!(Version::default(), Version::Sip2);
    }

    #[test]
    fn syntactically_valid_other_version_is_unsupported() {
        assert_eq!(
            Version::from_bytes(b"SIP/3.0"),
            Err(ParseError::Unsupported)
        );
        assert_eq!(
            Version::from_bytes(b"SIP/2.1"),
            Err(ParseError::Unsupported)
        );
    }

    #[test]
    fn version_number_is_treated_literally() {
        assert_eq!(
            Version::from_bytes(b"SIP/02.0"),
            Err(ParseError::Unsupported)
        );
        assert_eq!(
            Version::from_bytes(b"SIP/2.00"),
            Err(ParseError::Unsupported)
        );
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(Version::from_bytes(b""), Err(ParseError::InvalidSyntax));
    }

    #[test]
    fn rejects_wrong_protocol_name() {
        assert_eq!(
            Version::from_bytes(b"HTTP/2.0"),
            Err(ParseError::InvalidSyntax)
        );
    }

    #[test]
    fn rejects_missing_separator() {
        assert_eq!(
            Version::from_bytes(b"SIP2.0"),
            Err(ParseError::InvalidSyntax)
        );
    }

    #[test]
    fn rejects_missing_major_version() {
        assert_eq!(
            Version::from_bytes(b"SIP/.0"),
            Err(ParseError::InvalidSyntax)
        );
    }

    #[test]
    fn rejects_missing_minor_version() {
        assert_eq!(
            Version::from_bytes(b"SIP/2."),
            Err(ParseError::InvalidSyntax)
        );
    }

    #[test]
    fn rejects_non_digit_version_components() {
        assert_eq!(
            Version::from_bytes(b"SIP/two.0"),
            Err(ParseError::InvalidSyntax)
        );
        assert_eq!(
            Version::from_bytes(b"SIP/2.zero"),
            Err(ParseError::InvalidSyntax)
        );
    }

    #[test]
    fn rejects_multiple_dots() {
        assert_eq!(
            Version::from_bytes(b"SIP/2.0.1"),
            Err(ParseError::InvalidSyntax)
        );
    }

    #[test]
    fn rejects_whitespace() {
        assert_eq!(
            Version::from_bytes(b"SIP /2.0"),
            Err(ParseError::InvalidSyntax)
        );
        assert_eq!(
            Version::from_bytes(b"SIP/2.0 "),
            Err(ParseError::InvalidSyntax)
        );
    }

    #[test]
    fn rejects_value_above_size_limit() {
        let input = vec![b'1'; MAX_VERSION_BYTES + 1];

        assert_eq!(
            Version::from_bytes(&input),
            Err(ParseError::TooLong {
                length: MAX_VERSION_BYTES + 1,
                maximum: MAX_VERSION_BYTES,
            })
        );
    }

    #[test]
    fn parses_from_str() {
        assert_eq!(Version::from_str("SIP/2.0"), Ok(Version::Sip2));
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(
            ParseError::TooLong {
                length: 33,
                maximum: 32,
            }
            .class(),
            "too-long"
        );
        assert_eq!(ParseError::InvalidSyntax.class(), "invalid-syntax");
        assert_eq!(ParseError::Unsupported.class(), "unsupported");
    }
}
