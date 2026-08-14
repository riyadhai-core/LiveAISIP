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

//! SIP `Authentication-Info` header.
//!
//! The field is a non-empty ordered list of authentication parameters without
//! a leading scheme token. It carries values such as `nextnonce`, `rspauth`,
//! `qop`, `cnonce`, and `nc` after successful Digest authentication. Values
//! reuse the same bounded, quote-aware parameter grammar as challenges.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use crate::sip::auth::challenge::{
    AuthChallenge, AuthParameter, ChallengeParseError, MAX_AUTH_CHALLENGE_BYTES,
};

const INTERNAL_SCHEME: &[u8] = b"Digest ";

/// A validated SIP `Authentication-Info` field value.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticationInfo {
    parameters: Vec<AuthParameter>,
}

impl AuthenticationInfo {
    /// Creates a non-empty bounded parameter list.
    ///
    /// # Errors
    ///
    /// Rejects an empty list, duplicate names, or excess parameters.
    pub fn new(parameters: Vec<AuthParameter>) -> Result<Self, ParseError> {
        if parameters.is_empty() {
            return Err(ParseError::Empty);
        }
        let mut challenge = AuthChallenge::new("Digest").map_err(ParseError::Grammar)?;
        for parameter in parameters {
            challenge
                .push_parameter(parameter)
                .map_err(ParseError::Grammar)?;
        }
        Ok(Self {
            parameters: challenge.into_parameters(),
        })
    }

    /// Parses an `Authentication-Info` field value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] for empty, malformed, duplicate, or oversized
    /// parameter input.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns parameters in wire order.
    #[must_use]
    pub fn parameters(&self) -> &[AuthParameter] {
        &self.parameters
    }

    /// Returns a parameter by case-insensitive name.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&AuthParameter> {
        self.parameters
            .iter()
            .find(|parameter| parameter.name().eq_ignore_ascii_case(name))
    }

    /// Returns the next server nonce, when supplied.
    #[must_use]
    pub fn next_nonce(&self) -> Option<&str> {
        self.parameter("nextnonce").map(AuthParameter::value)
    }

    /// Returns the response-authentication digest, when supplied.
    #[must_use]
    pub fn response_auth(&self) -> Option<&str> {
        self.parameter("rspauth").map(AuthParameter::value)
    }

    /// Consumes the field into ordered parameters.
    #[must_use]
    pub fn into_parameters(self) -> Vec<AuthParameter> {
        self.parameters
    }
}

impl fmt::Debug for AuthenticationInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationInfo")
            .field("parameter_count", &self.parameters.len())
            .field("next_nonce_present", &self.next_nonce().is_some())
            .field("response_auth_present", &self.response_auth().is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AuthenticationInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, parameter) in self.parameters.iter().enumerate() {
            if index != 0 {
                formatter.write_str(", ")?;
            }
            write!(formatter, "{parameter}")?;
        }
        Ok(())
    }
}

impl FromStr for AuthenticationInfo {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// Parses an `Authentication-Info` field value.
///
/// # Errors
///
/// Returns [`ParseError`] for empty, malformed, duplicate, or oversized input.
pub fn parse(input: &[u8]) -> Result<AuthenticationInfo, ParseError> {
    if input.is_empty() {
        return Err(ParseError::Empty);
    }
    let maximum = MAX_AUTH_CHALLENGE_BYTES.saturating_sub(INTERNAL_SCHEME.len());
    if input.len() > maximum {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum,
        });
    }

    let total = INTERNAL_SCHEME
        .len()
        .checked_add(input.len())
        .ok_or(ParseError::AllocationFailed)?;
    let mut wrapped = Vec::new();
    wrapped
        .try_reserve_exact(total)
        .map_err(|_| ParseError::AllocationFailed)?;
    wrapped.extend_from_slice(INTERNAL_SCHEME);
    wrapped.extend_from_slice(input);

    let challenge = AuthChallenge::from_bytes(&wrapped).map_err(ParseError::Grammar)?;
    if challenge.parameters().is_empty() {
        return Err(ParseError::Empty);
    }
    Ok(AuthenticationInfo {
        parameters: challenge.into_parameters(),
    })
}

/// Failure to parse or construct `Authentication-Info`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// No authentication parameters were present.
    Empty,
    /// Field exceeded its operational byte bound.
    TooLong {
        /// Observed byte length.
        length: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// Shared authentication parameter grammar failed.
    Grammar(ChallengeParseError),
    /// Bounded temporary allocation failed.
    AllocationFailed,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SIP Authentication-Info field value")
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Grammar(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ChallengeParseError> for ParseError {
    fn from(error: ChallengeParseError) -> Self {
        Self::Grammar(error)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use crate::sip::auth::challenge::ChallengeParseError;

    use super::{AuthenticationInfo, ParseError};

    #[test]
    fn parses_digest_success_metadata() {
        let value = AuthenticationInfo::from_bytes(
            br#"nextnonce="new-nonce", qop=auth, rspauth="abcdef", cnonce="client", nc=00000001"#,
        )
        .unwrap_or_else(|_| panic!("valid Authentication-Info"));
        assert_eq!(value.next_nonce(), Some("new-nonce"));
        assert_eq!(value.response_auth(), Some("abcdef"));
        assert_eq!(value.parameters().len(), 5);
    }

    #[test]
    fn canonical_serialization_round_trips() {
        let value = AuthenticationInfo::from_bytes(br#"nextnonce="new-nonce",rspauth="abcdef""#)
            .unwrap_or_else(|_| panic!("valid Authentication-Info"));
        assert!(AuthenticationInfo::from_bytes(value.to_string().as_bytes()).is_ok());
    }

    #[test]
    fn rejects_empty_and_duplicates() {
        assert_eq!(AuthenticationInfo::from_bytes(b""), Err(ParseError::Empty));
        let error = AuthenticationInfo::from_bytes(br"qop=auth, QOP=auth-int")
            .err()
            .unwrap_or_else(|| panic!("must reject"));
        assert_eq!(
            error,
            ParseError::Grammar(ChallengeParseError::DuplicateParameter)
        );
        assert!(error.source().is_some());
    }

    #[test]
    fn diagnostics_are_redacted() {
        let value = AuthenticationInfo::from_bytes(
            br#"nextnonce="secret-next", rspauth="secret-response""#,
        )
        .unwrap_or_else(|_| panic!("valid Authentication-Info"));
        let debug = format!("{value:?}");
        assert!(!debug.contains("secret-next"));
        assert!(!debug.contains("secret-response"));
    }
}
