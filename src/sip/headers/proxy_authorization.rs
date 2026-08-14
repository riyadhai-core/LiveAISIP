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

//! SIP `Proxy-Authorization` header.
//!
//! This header carries credentials for a SIP proxy after a `407` challenge.
//! It intentionally wraps the identical credential grammar used by
//! `Authorization` while preserving a distinct public type, preventing proxy
//! credentials from being sent to an origin server accidentally.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use crate::sip::auth::challenge::AuthChallenge;
use crate::sip::auth::digest::DigestAuthorization;

use super::authorization::{Authorization, ParseError as AuthorizationParseError};

/// A validated SIP `Proxy-Authorization` field value.
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct ProxyAuthorization(Authorization);

impl ProxyAuthorization {
    /// Creates proxy credentials from validated scheme parameters.
    #[must_use]
    pub const fn new(credentials: AuthChallenge) -> Self {
        Self(Authorization::new(credentials))
    }

    /// Parses a `Proxy-Authorization` field value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when credential syntax or an operational bound
    /// is invalid.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        Authorization::from_bytes(input)
            .map(Self)
            .map_err(ParseError)
    }

    /// Converts a calculated Digest response into proxy credentials.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] only if a calculated serialization invariant is
    /// violated.
    pub fn from_digest(digest: &DigestAuthorization) -> Result<Self, ParseError> {
        Authorization::from_digest(digest)
            .map(Self)
            .map_err(ParseError)
    }

    /// Returns the credential scheme and ordered parameters.
    #[must_use]
    pub const fn credentials(&self) -> &AuthChallenge {
        self.0.credentials()
    }

    /// Consumes the header into its credential representation.
    #[must_use]
    pub fn into_credentials(self) -> AuthChallenge {
        self.0.into_credentials()
    }
}

impl fmt::Debug for ProxyAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyAuthorization")
            .field("scheme", &self.credentials().scheme())
            .field("parameter_count", &self.credentials().parameters().len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ProxyAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ProxyAuthorization {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

impl From<AuthChallenge> for ProxyAuthorization {
    fn from(credentials: AuthChallenge) -> Self {
        Self::new(credentials)
    }
}

impl From<ProxyAuthorization> for AuthChallenge {
    fn from(value: ProxyAuthorization) -> Self {
        value.into_credentials()
    }
}

/// Failure to parse or construct `Proxy-Authorization` credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError(AuthorizationParseError);

impl ParseError {
    /// Returns the underlying credential parse error.
    #[must_use]
    pub const fn authorization_error(&self) -> &AuthorizationParseError {
        &self.0
    }

    /// Consumes this wrapper into the underlying error.
    #[must_use]
    pub fn into_authorization_error(self) -> AuthorizationParseError {
        self.0
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SIP Proxy-Authorization field value")
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.0)
    }
}

impl From<AuthorizationParseError> for ParseError {
    fn from(error: AuthorizationParseError) -> Self {
        Self(error)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use crate::sip::auth::challenge::{AuthChallenge, AuthParameter};
    use crate::sip::auth::digest::{DigestAuthorization, DigestCredentials, DigestRequest};
    use crate::sip::types::method::Method;

    use super::ProxyAuthorization;

    #[test]
    fn parses_proxy_digest_credentials() {
        let value = ProxyAuthorization::from_bytes(
            br#"Digest username="runtime", realm="router", nonce="n", uri="sip:router.example", response="0123456789abcdef", algorithm=MD5"#,
        )
        .unwrap_or_else(|_| panic!("valid credentials"));
        assert_eq!(
            value
                .credentials()
                .parameter("username")
                .map(AuthParameter::value),
            Some("runtime")
        );
        assert!(ProxyAuthorization::from_bytes(value.to_string().as_bytes()).is_ok());
    }

    #[test]
    fn wraps_calculated_digest() {
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
        let value = ProxyAuthorization::from_digest(&digest)
            .unwrap_or_else(|_| panic!("proxy authorization"));
        let wire = value.to_string();
        assert!(wire.starts_with("Digest "));
        assert!(!wire.contains("secret-password"));
        assert!(wire.contains("algorithm=SHA-256"));
    }

    #[test]
    fn errors_preserve_sources_and_debug_is_redacted() {
        let error = ProxyAuthorization::from_bytes(b"Digest username")
            .err()
            .unwrap_or_else(|| panic!("must reject"));
        assert!(error.source().is_some());

        let value = ProxyAuthorization::from_bytes(
            br#"Digest username="private-user", realm="private-realm", nonce="secret""#,
        )
        .unwrap_or_else(|_| panic!("credentials"));
        let debug = format!("{value:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-realm"));
        assert!(!debug.contains("secret"));
    }
}
