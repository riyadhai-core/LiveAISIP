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

//! SIP `Authorization` header.
//!
//! The header carries end-server credentials, normally following a `401`
//! challenge. Its scheme and ordered credential parameters use the shared
//! bounded authentication grammar. Calculated Digest output can be converted
//! directly without exposing password material.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use crate::sip::auth::challenge::{AuthChallenge, ChallengeParseError};
use crate::sip::auth::digest::DigestAuthorization;

/// A validated SIP `Authorization` field value.
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct Authorization(AuthChallenge);

impl Authorization {
    /// Creates the header from validated scheme parameters.
    #[must_use]
    pub const fn new(credentials: AuthChallenge) -> Self {
        Self(credentials)
    }

    /// Parses an `Authorization` field value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when credential syntax or an operational bound
    /// is invalid.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        AuthChallenge::from_bytes(input)
            .map(Self)
            .map_err(ParseError::Grammar)
    }

    /// Converts an already calculated Digest response into this header.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] only if an internal serialization invariant is
    /// violated. No password material is retained by the result.
    pub fn from_digest(digest: &DigestAuthorization) -> Result<Self, ParseError> {
        Self::from_bytes(digest.to_string().as_bytes()).map_err(|error| match error {
            ParseError::Grammar(source) => ParseError::CalculatedDigestInvariant(source),
            ParseError::CalculatedDigestInvariant(source) => {
                ParseError::CalculatedDigestInvariant(source)
            }
        })
    }

    /// Returns the credential scheme and ordered parameters.
    #[must_use]
    pub const fn credentials(&self) -> &AuthChallenge {
        &self.0
    }

    /// Consumes the header into its credential representation.
    #[must_use]
    pub fn into_credentials(self) -> AuthChallenge {
        self.0
    }
}

impl fmt::Debug for Authorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Authorization")
            .field("scheme", &self.0.scheme())
            .field("parameter_count", &self.0.parameters().len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Authorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Authorization {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

impl From<AuthChallenge> for Authorization {
    fn from(credentials: AuthChallenge) -> Self {
        Self::new(credentials)
    }
}

impl From<Authorization> for AuthChallenge {
    fn from(value: Authorization) -> Self {
        value.into_credentials()
    }
}

/// Failure to parse or construct an `Authorization` field value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// Received credential grammar was invalid.
    Grammar(ChallengeParseError),
    /// A locally calculated Digest value failed the shared grammar invariant.
    CalculatedDigestInvariant(ChallengeParseError),
}

impl ParseError {
    /// Returns the shared authentication grammar error.
    #[must_use]
    pub const fn grammar_error(&self) -> &ChallengeParseError {
        match self {
            Self::Grammar(error) | Self::CalculatedDigestInvariant(error) => error,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SIP Authorization field value")
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.grammar_error())
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

    use crate::sip::auth::challenge::{AuthChallenge, AuthParameter, ChallengeParseError};
    use crate::sip::auth::digest::{DigestAuthorization, DigestCredentials, DigestRequest};
    use crate::sip::types::method::Method;

    use super::{Authorization, ParseError};

    #[test]
    fn parses_digest_credentials() {
        let value = Authorization::from_bytes(
            br#"Digest username="runtime", realm="router", nonce="n", uri="sip:router.example", response="0123456789abcdef", algorithm=MD5"#,
        )
        .unwrap_or_else(|_| panic!("valid credentials"));
        assert_eq!(value.credentials().scheme(), "Digest");
        assert_eq!(
            value
                .credentials()
                .parameter("username")
                .map(AuthParameter::value),
            Some("runtime")
        );
        assert!(Authorization::from_bytes(value.to_string().as_bytes()).is_ok());
    }

    #[test]
    fn wraps_calculated_digest_without_password() {
        let challenge = AuthChallenge::from_bytes(
            br#"Digest realm="router", nonce="n", algorithm=SHA-256, qop="auth""#,
        )
        .unwrap_or_else(|_| panic!("challenge"));
        let credentials = DigestCredentials::new("runtime", "secret-password")
            .unwrap_or_else(|_| panic!("credentials"));
        let digest = DigestAuthorization::calculate(
            &challenge,
            &credentials,
            DigestRequest {
                method: &Method::Invite,
                uri: "sip:router.example",
                entity_body: b"",
                nonce_count: 1,
                client_nonce: "secure-cnonce",
            },
        )
        .unwrap_or_else(|_| panic!("digest"));
        let value = Authorization::from_digest(&digest).unwrap_or_else(|_| panic!("authorization"));
        let wire = value.to_string();
        assert!(wire.starts_with("Digest "));
        assert!(!wire.contains("secret-password"));
        assert!(wire.contains("algorithm=SHA-256"));
    }

    #[test]
    fn preserves_source_error_and_redacts_diagnostics() {
        let error = Authorization::from_bytes(b"Digest username")
            .err()
            .unwrap_or_else(|| panic!("must reject"));
        assert_eq!(error.grammar_error(), &ChallengeParseError::MissingEquals);
        assert!(error.source().is_some());

        let value = Authorization::from_bytes(
            br#"Digest username="private-user", realm="private-realm", nonce="secret""#,
        )
        .unwrap_or_else(|_| panic!("credentials"));
        let debug = format!("{value:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-realm"));
        assert!(!debug.contains("secret"));
        let _: Option<ParseError> = None;
    }
}
