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

//! Bounded SIP authentication-challenge grammar.
//!
//! This module parses one authentication scheme followed by ordered
//! `auth-param` values. Quoted-string escaping is decoded into logical text
//! and serialized canonically. Parameter lookup is case-insensitive, while
//! values such as nonce and realm retain exact case. Diagnostic formatting
//! never exposes credentials, realms, nonces, or opaque challenge data.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;

/// Maximum accepted size of one authentication challenge.
pub const MAX_AUTH_CHALLENGE_BYTES: usize = 16 * 1024;
/// Maximum authentication parameters in one challenge.
pub const MAX_AUTH_PARAMETERS: usize = 64;
/// Maximum authentication scheme or parameter-name size.
pub const MAX_AUTH_NAME_BYTES: usize = 256;
/// Maximum logical authentication parameter-value size.
pub const MAX_AUTH_VALUE_BYTES: usize = 4096;

/// One validated authentication challenge.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthChallenge {
    scheme: Box<str>,
    parameters: Vec<AuthParameter>,
}

impl AuthChallenge {
    /// Creates a challenge with no parameters.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or oversized authentication scheme token.
    pub fn new(scheme: impl Into<Box<str>>) -> Result<Self, ChallengeParseError> {
        let scheme = scheme.into();
        validate_name(scheme.as_bytes(), NameRole::Scheme)?;
        Ok(Self {
            scheme,
            parameters: Vec::new(),
        })
    }

    /// Parses one complete challenge.
    ///
    /// # Errors
    ///
    /// Returns [`ChallengeParseError`] for malformed syntax, duplicates, or
    /// an exceeded operational bound.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ChallengeParseError> {
        parse(input)
    }

    /// Returns the case-insensitive authentication scheme.
    #[must_use]
    pub const fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns parameters in wire order.
    #[must_use]
    pub fn parameters(&self) -> &[AuthParameter] {
        &self.parameters
    }

    /// Consumes the challenge into its ordered parameters.
    #[must_use]
    pub fn into_parameters(self) -> Vec<AuthParameter> {
        self.parameters
    }

    /// Returns the first parameter matching a case-insensitive name.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&AuthParameter> {
        self.parameters
            .iter()
            .find(|parameter| parameter.name.eq_ignore_ascii_case(name))
    }

    /// Adds a parameter while enforcing capacity and unique names.
    ///
    /// # Errors
    ///
    /// Rejects duplicate names and parameter-count exhaustion.
    pub fn push_parameter(&mut self, parameter: AuthParameter) -> Result<(), ChallengeParseError> {
        if self.parameters.len() >= MAX_AUTH_PARAMETERS {
            return Err(ChallengeParseError::TooManyParameters {
                maximum: MAX_AUTH_PARAMETERS,
            });
        }
        if self
            .parameters
            .iter()
            .any(|existing| existing.name.eq_ignore_ascii_case(&parameter.name))
        {
            return Err(ChallengeParseError::DuplicateParameter);
        }
        self.parameters.push(parameter);
        Ok(())
    }
}

impl fmt::Debug for AuthChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthChallenge")
            .field("scheme", &self.scheme)
            .field("parameter_count", &self.parameters.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AuthChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.scheme)?;
        if !self.parameters.is_empty() {
            formatter.write_char(' ')?;
        }
        for (index, parameter) in self.parameters.iter().enumerate() {
            if index != 0 {
                formatter.write_str(", ")?;
            }
            write!(formatter, "{parameter}")?;
        }
        Ok(())
    }
}

/// One ordered authentication parameter.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthParameter {
    name: Box<str>,
    value: Box<str>,
    quoted: bool,
}

impl AuthParameter {
    /// Creates a validated authentication parameter.
    ///
    /// # Errors
    ///
    /// Rejects invalid names and values. Unquoted values must be SIP tokens;
    /// quoted values accept visible UTF-8 text and horizontal tabs.
    pub fn new(
        name: impl Into<Box<str>>,
        value: impl Into<Box<str>>,
        quoted: bool,
    ) -> Result<Self, ChallengeParseError> {
        let name = name.into();
        let value = value.into();
        validate_name(name.as_bytes(), NameRole::Parameter)?;
        validate_value(value.as_bytes(), quoted)?;
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

    /// Returns the exact logical value.
    #[must_use]
    pub const fn value(&self) -> &str {
        &self.value
    }

    /// Returns whether canonical serialization quotes the value.
    #[must_use]
    pub const fn is_quoted(&self) -> bool {
        self.quoted
    }
}

impl fmt::Debug for AuthParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthParameter")
            .field("name", &self.name)
            .field("value_bytes", &self.value.len())
            .field("quoted", &self.quoted)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AuthParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}=", self.name)?;
        if !self.quoted {
            return formatter.write_str(&self.value);
        }
        formatter.write_char('"')?;
        for character in self.value.chars() {
            if matches!(character, '"' | '\\') {
                formatter.write_char('\\')?;
            }
            formatter.write_char(character)?;
        }
        formatter.write_char('"')
    }
}

/// Parses one authentication challenge.
///
/// # Errors
///
/// Returns [`ChallengeParseError`] for malformed syntax, duplicates, or an
/// exceeded operational bound.
pub fn parse(input: &[u8]) -> Result<AuthChallenge, ChallengeParseError> {
    if input.len() > MAX_AUTH_CHALLENGE_BYTES {
        return Err(ChallengeParseError::TooLong {
            length: input.len(),
            maximum: MAX_AUTH_CHALLENGE_BYTES,
        });
    }
    let input = trim(input);
    if input.is_empty() {
        return Err(ChallengeParseError::Empty);
    }
    if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ChallengeParseError::InvalidControl);
    }

    let scheme_end = input
        .iter()
        .position(|byte| matches!(byte, b' ' | b'\t'))
        .unwrap_or(input.len());
    let scheme = &input[..scheme_end];
    validate_name(scheme, NameRole::Scheme)?;
    let mut challenge = AuthChallenge::new(decode(scheme)?)?;
    let mut remaining = trim_start(&input[scheme_end..]);
    if remaining.is_empty() {
        return Ok(challenge);
    }

    loop {
        let name_end = remaining
            .iter()
            .position(|byte| matches!(byte, b'=' | b' ' | b'\t' | b','))
            .unwrap_or(remaining.len());
        let name = &remaining[..name_end];
        validate_name(name, NameRole::Parameter)?;
        remaining = trim_start(&remaining[name_end..]);
        if remaining.first() != Some(&b'=') {
            return Err(ChallengeParseError::MissingEquals);
        }
        remaining = trim_start(&remaining[1..]);
        let (value, quoted, tail) = if remaining.first() == Some(&b'"') {
            parse_quoted(remaining)?
        } else {
            let end = remaining
                .iter()
                .position(|byte| matches!(byte, b',' | b' ' | b'\t'))
                .unwrap_or(remaining.len());
            let raw = &remaining[..end];
            validate_value(raw, false)?;
            (decode(raw)?, false, &remaining[end..])
        };
        challenge.push_parameter(AuthParameter::new(decode(name)?, value, quoted)?)?;
        remaining = trim_start(tail);
        if remaining.is_empty() {
            break;
        }
        if remaining.first() != Some(&b',') {
            return Err(ChallengeParseError::MissingComma);
        }
        remaining = trim_start(&remaining[1..]);
        if remaining.is_empty() {
            return Err(ChallengeParseError::TrailingComma);
        }
    }
    Ok(challenge)
}

fn parse_quoted(input: &[u8]) -> Result<(Box<str>, bool, &[u8]), ChallengeParseError> {
    let mut decoded = Vec::new();
    decoded
        .try_reserve(input.len().min(MAX_AUTH_VALUE_BYTES))
        .map_err(|_| ChallengeParseError::AllocationFailed)?;
    let mut escaped = false;
    for index in 1..input.len() {
        let byte = input[index];
        if escaped {
            if byte.is_ascii_control() {
                return Err(ChallengeParseError::InvalidValue);
            }
            decoded.push(byte);
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            validate_value(&decoded, true)?;
            let value = String::from_utf8(decoded)
                .map_err(|_| ChallengeParseError::InvalidValue)?
                .into_boxed_str();
            return Ok((value, true, &input[index + 1..]));
        } else {
            if decoded.len() >= MAX_AUTH_VALUE_BYTES {
                return Err(ChallengeParseError::ValueTooLong {
                    maximum: MAX_AUTH_VALUE_BYTES,
                });
            }
            decoded.push(byte);
        }
    }
    Err(ChallengeParseError::UnterminatedQuotedValue)
}

#[derive(Clone, Copy)]
enum NameRole {
    Scheme,
    Parameter,
}

fn validate_name(input: &[u8], role: NameRole) -> Result<(), ChallengeParseError> {
    if input.is_empty() || input.len() > MAX_AUTH_NAME_BYTES || !input.iter().copied().all(is_token)
    {
        return Err(match role {
            NameRole::Scheme => ChallengeParseError::InvalidScheme,
            NameRole::Parameter => ChallengeParseError::InvalidParameterName,
        });
    }
    Ok(())
}

fn validate_value(input: &[u8], quoted: bool) -> Result<(), ChallengeParseError> {
    if input.is_empty() {
        return Err(ChallengeParseError::EmptyValue);
    }
    if input.len() > MAX_AUTH_VALUE_BYTES {
        return Err(ChallengeParseError::ValueTooLong {
            maximum: MAX_AUTH_VALUE_BYTES,
        });
    }
    let valid = if quoted {
        input
            .iter()
            .all(|byte| *byte == b'\t' || (*byte >= 0x20 && *byte != 0x7f))
    } else {
        input.iter().copied().all(is_token)
    };
    if !valid {
        return Err(ChallengeParseError::InvalidValue);
    }
    Ok(())
}

fn decode(input: &[u8]) -> Result<Box<str>, ChallengeParseError> {
    std::str::from_utf8(input)
        .map(Into::into)
        .map_err(|_| ChallengeParseError::InvalidValue)
}

const fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
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

/// Authentication challenge parse failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ChallengeParseError {
    /// Challenge was empty.
    Empty,
    /// Challenge exceeded its byte bound.
    TooLong {
        /// Observed byte length.
        length: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// Authentication scheme was invalid.
    InvalidScheme,
    /// Parameter name was invalid.
    InvalidParameterName,
    /// Parameter lacked the required equals delimiter.
    MissingEquals,
    /// Parameter separator was absent.
    MissingComma,
    /// Challenge ended after a comma.
    TrailingComma,
    /// Parameter value was empty.
    EmptyValue,
    /// Parameter value exceeded its bound.
    ValueTooLong {
        /// Maximum accepted logical byte length.
        maximum: usize,
    },
    /// Parameter value syntax was invalid.
    InvalidValue,
    /// Quoted value did not terminate.
    UnterminatedQuotedValue,
    /// Parameter name appeared more than once.
    DuplicateParameter,
    /// Parameter count exceeded its bound.
    TooManyParameters {
        /// Maximum accepted parameter count.
        maximum: usize,
    },
    /// CR or LF appeared inside the value.
    InvalidControl,
    /// Bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for ChallengeParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SIP authentication challenge")
    }
}

impl StdError for ChallengeParseError {}

#[cfg(test)]
mod tests {
    use super::{AuthChallenge, AuthParameter, ChallengeParseError};

    #[test]
    fn parses_digest_challenge_and_case_insensitive_names() {
        let value = AuthChallenge::from_bytes(
            br#"Digest realm="router.example", nonce="abc\"123", algorithm=SHA-256, qop="auth""#,
        )
        .unwrap_or_else(|_| panic!("valid challenge"));
        assert!(value.scheme().eq_ignore_ascii_case("digest"));
        assert_eq!(
            value.parameter("REALM").map(AuthParameter::value),
            Some("router.example")
        );
        assert_eq!(
            value.parameter("nonce").map(AuthParameter::value),
            Some("abc\"123")
        );
        assert_eq!(value.parameters().len(), 4);
    }

    #[test]
    fn canonical_serialization_round_trips() {
        let value =
            AuthChallenge::from_bytes(br#"Digest realm="edge",nonce="n",algorithm=SHA-256"#)
                .unwrap_or_else(|_| panic!("valid challenge"));
        assert!(AuthChallenge::from_bytes(value.to_string().as_bytes()).is_ok());
    }

    #[test]
    fn rejects_duplicates_and_malformed_separators() {
        assert_eq!(
            AuthChallenge::from_bytes(br#"Digest realm="a", REALM="b""#),
            Err(ChallengeParseError::DuplicateParameter)
        );
        assert_eq!(
            AuthChallenge::from_bytes(br#"Digest realm="a" nonce="b""#),
            Err(ChallengeParseError::MissingComma)
        );
    }

    #[test]
    fn rejects_controls_and_trailing_comma() {
        assert_eq!(
            AuthChallenge::from_bytes(b"Digest realm=bad\rvalue"),
            Err(ChallengeParseError::InvalidControl)
        );
        assert_eq!(
            AuthChallenge::from_bytes(b"Digest realm=edge,"),
            Err(ChallengeParseError::TrailingComma)
        );
    }

    #[test]
    fn diagnostics_are_redacted() {
        let value =
            AuthChallenge::from_bytes(br#"Digest realm="private.example", nonce="secret-nonce""#)
                .unwrap_or_else(|_| panic!("valid challenge"));
        let debug = format!("{value:?} {:?}", value.parameters()[0]);
        assert!(!debug.contains("private.example"));
        assert!(!debug.contains("secret-nonce"));
    }
}
