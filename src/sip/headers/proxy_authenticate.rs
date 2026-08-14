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

//! SIP `Proxy-Authenticate` header.
//!
//! This header carries the proxy authentication challenge returned with a
//! `407 Proxy Authentication Required` response. It shares the bounded
//! challenge grammar with `WWW-Authenticate` but remains a separate type to
//! prevent proxy and origin-server credentials from being mixed accidentally.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use crate::sip::auth::challenge::{AuthChallenge, ChallengeParseError};

/// A validated SIP `Proxy-Authenticate` field value.
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct ProxyAuthenticate(AuthChallenge);

impl ProxyAuthenticate {
    /// Creates the header from a validated challenge.
    #[must_use]
    pub const fn new(challenge: AuthChallenge) -> Self {
        Self(challenge)
    }

    /// Parses a `Proxy-Authenticate` field value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when challenge syntax or an operational bound
    /// is invalid.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        AuthChallenge::from_bytes(input)
            .map(Self)
            .map_err(ParseError)
    }

    /// Returns the parsed authentication challenge.
    #[must_use]
    pub const fn challenge(&self) -> &AuthChallenge {
        &self.0
    }

    /// Consumes the header into its challenge.
    #[must_use]
    pub fn into_challenge(self) -> AuthChallenge {
        self.0
    }
}

impl fmt::Debug for ProxyAuthenticate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyAuthenticate")
            .field("scheme", &self.0.scheme())
            .field("parameter_count", &self.0.parameters().len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ProxyAuthenticate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ProxyAuthenticate {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

impl From<AuthChallenge> for ProxyAuthenticate {
    fn from(challenge: AuthChallenge) -> Self {
        Self::new(challenge)
    }
}

impl From<ProxyAuthenticate> for AuthChallenge {
    fn from(value: ProxyAuthenticate) -> Self {
        value.into_challenge()
    }
}

/// Failure to parse a SIP `Proxy-Authenticate` field value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError(ChallengeParseError);

impl ParseError {
    /// Returns the underlying challenge grammar error.
    #[must_use]
    pub const fn challenge_error(&self) -> &ChallengeParseError {
        &self.0
    }

    /// Consumes this wrapper into the underlying error.
    #[must_use]
    pub fn into_challenge_error(self) -> ChallengeParseError {
        self.0
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SIP Proxy-Authenticate field value")
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.0)
    }
}

impl From<ChallengeParseError> for ParseError {
    fn from(error: ChallengeParseError) -> Self {
        Self(error)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use crate::sip::auth::challenge::{AuthParameter, ChallengeParseError};

    use super::ProxyAuthenticate;

    #[test]
    fn parses_digest_proxy_challenge() {
        let value = ProxyAuthenticate::from_bytes(
            br#"Digest realm="router.example", nonce="nonce", algorithm=SHA-256, qop="auth""#,
        )
        .unwrap_or_else(|_| panic!("valid challenge"));
        assert_eq!(value.challenge().scheme(), "Digest");
        assert_eq!(
            value
                .challenge()
                .parameter("algorithm")
                .map(AuthParameter::value),
            Some("SHA-256")
        );
        assert!(ProxyAuthenticate::from_bytes(value.to_string().as_bytes()).is_ok());
    }

    #[test]
    fn preserves_typed_source_error() {
        let error = ProxyAuthenticate::from_bytes(b"Digest nonce")
            .err()
            .unwrap_or_else(|| panic!("must reject"));
        assert_eq!(error.challenge_error(), &ChallengeParseError::MissingEquals);
        assert!(error.source().is_some());
    }

    #[test]
    fn diagnostics_are_redacted() {
        let value = ProxyAuthenticate::from_bytes(
            br#"Digest realm="private.example", nonce="secret-nonce""#,
        )
        .unwrap_or_else(|_| panic!("valid challenge"));
        let debug = format!("{value:?}");
        assert!(!debug.contains("private.example"));
        assert!(!debug.contains("secret-nonce"));
    }
}
