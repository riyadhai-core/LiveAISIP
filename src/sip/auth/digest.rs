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

//! SIP Digest client authentication.
//!
//! SHA-256 is supported and preferred, with MD5 retained only for deployed SIP
//! interoperability. Session variants and both `auth` and `auth-int` quality
//! of protection are implemented. The caller supplies a cryptographically
//! random client nonce and monotonically increasing nonce count; this module
//! performs no hidden randomness or global state mutation.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;

use md5::Md5;
use sha2::{Digest as _, Sha256};

use crate::sip::types::method::Method;

use super::challenge::{AuthChallenge, AuthParameter};

/// Maximum accepted username size.
pub const MAX_DIGEST_USERNAME_BYTES: usize = 1024;
/// Maximum accepted password size.
pub const MAX_DIGEST_PASSWORD_BYTES: usize = 4096;
/// Maximum accepted request-target or client-nonce size.
pub const MAX_DIGEST_COMPONENT_BYTES: usize = 8192;

/// Digest hashing algorithm selected from a challenge.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DigestAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-256 with session-bound A1.
    Sha256Sess,
    /// Legacy MD5 interoperability.
    Md5,
    /// Legacy MD5 with session-bound A1.
    Md5Sess,
}

impl DigestAlgorithm {
    /// Returns the canonical wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha256Sess => "SHA-256-sess",
            Self::Md5 => "MD5",
            Self::Md5Sess => "MD5-sess",
        }
    }

    const fn is_session(self) -> bool {
        matches!(self, Self::Sha256Sess | Self::Md5Sess)
    }
}

/// Negotiated Digest quality of protection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QualityOfProtection {
    /// Authenticate request metadata.
    Auth,
    /// Authenticate request metadata and entity body.
    AuthInt,
}

impl QualityOfProtection {
    /// Returns the canonical wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::AuthInt => "auth-int",
        }
    }
}

/// Client credentials used to calculate a Digest response.
#[derive(Clone, Eq, PartialEq)]
pub struct DigestCredentials {
    username: Box<str>,
    password: Box<str>,
}

impl DigestCredentials {
    /// Creates bounded credentials.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-containing components.
    pub fn new(
        username: impl Into<Box<str>>,
        password: impl Into<Box<str>>,
    ) -> Result<Self, DigestError> {
        let username = username.into();
        let password = password.into();
        validate_secret(
            &username,
            MAX_DIGEST_USERNAME_BYTES,
            CredentialRole::Username,
        )?;
        validate_secret(
            &password,
            MAX_DIGEST_PASSWORD_BYTES,
            CredentialRole::Password,
        )?;
        Ok(Self { username, password })
    }

    /// Returns the username.
    #[must_use]
    pub const fn username(&self) -> &str {
        &self.username
    }
}

impl fmt::Debug for DigestCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigestCredentials")
            .field("username_bytes", &self.username.len())
            .field("password_bytes", &self.password.len())
            .finish_non_exhaustive()
    }
}

/// Inputs specific to the request being authenticated.
#[derive(Clone, Copy)]
pub struct DigestRequest<'a> {
    /// Exact request method.
    pub method: &'a Method,
    /// Exact serialized Request-URI.
    pub uri: &'a str,
    /// Entity body used by `auth-int`.
    pub entity_body: &'a [u8],
    /// Nonce count for this server nonce; must be non-zero.
    pub nonce_count: u32,
    /// Cryptographically random caller-generated client nonce.
    pub client_nonce: &'a str,
}

impl fmt::Debug for DigestRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigestRequest")
            .field("method", &self.method)
            .field("uri_bytes", &self.uri.len())
            .field("entity_body_bytes", &self.entity_body.len())
            .field("nonce_count", &self.nonce_count)
            .field("client_nonce_bytes", &self.client_nonce.len())
            .finish_non_exhaustive()
    }
}

/// A computed Digest authorization field value.
#[derive(Clone, Eq, PartialEq)]
pub struct DigestAuthorization {
    username: Box<str>,
    realm: Box<str>,
    nonce: Box<str>,
    uri: Box<str>,
    response: Box<str>,
    algorithm: DigestAlgorithm,
    opaque: Option<Box<str>>,
    qop: Option<QualityOfProtection>,
    nonce_count: Option<u32>,
    client_nonce: Option<Box<str>>,
}

impl DigestAuthorization {
    /// Computes a Digest authorization from a parsed challenge.
    ///
    /// `auth` is preferred when the challenge offers multiple qop values.
    /// Challenges without qop use the RFC 2069-compatible response form.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schemes, algorithms, qop sets, missing mandatory
    /// parameters, invalid request inputs, and unsupported `userhash=true`.
    pub fn calculate(
        challenge: &AuthChallenge,
        credentials: &DigestCredentials,
        request: DigestRequest<'_>,
    ) -> Result<Self, DigestError> {
        if !challenge.scheme().eq_ignore_ascii_case("Digest") {
            return Err(DigestError::UnsupportedScheme);
        }
        let realm = required(challenge, "realm", DigestError::MissingRealm)?;
        let nonce = required(challenge, "nonce", DigestError::MissingNonce)?;
        if challenge
            .parameter("userhash")
            .is_some_and(|value| value.value().eq_ignore_ascii_case("true"))
        {
            return Err(DigestError::UnsupportedUserHash);
        }
        validate_component(request.uri, ComponentRole::Uri)?;
        validate_component(request.client_nonce, ComponentRole::ClientNonce)?;

        let algorithm =
            parse_algorithm(challenge.parameter("algorithm").map(AuthParameter::value))?;
        let qop = parse_qop(challenge.parameter("qop").map(AuthParameter::value))?;
        if qop.is_some() && request.nonce_count == 0 {
            return Err(DigestError::ZeroNonceCount);
        }
        if algorithm.is_session() && request.client_nonce.is_empty() {
            return Err(DigestError::MissingClientNonce);
        }

        let mut ha1 = hash_join(
            algorithm,
            &[
                credentials.username.as_bytes(),
                realm.as_bytes(),
                credentials.password.as_bytes(),
            ],
        );
        if algorithm.is_session() {
            ha1 = hash_join(
                algorithm,
                &[
                    ha1.as_bytes(),
                    nonce.as_bytes(),
                    request.client_nonce.as_bytes(),
                ],
            );
        }

        let ha2 = match qop {
            Some(QualityOfProtection::AuthInt) => {
                let entity_hash = hash(algorithm, request.entity_body);
                hash_join(
                    algorithm,
                    &[
                        request.method.as_bytes(),
                        request.uri.as_bytes(),
                        entity_hash.as_bytes(),
                    ],
                )
            }
            _ => hash_join(
                algorithm,
                &[request.method.as_bytes(), request.uri.as_bytes()],
            ),
        };

        let nonce_count_text = format!("{:08x}", request.nonce_count);
        let response = if let Some(qop) = qop {
            hash_join(
                algorithm,
                &[
                    ha1.as_bytes(),
                    nonce.as_bytes(),
                    nonce_count_text.as_bytes(),
                    request.client_nonce.as_bytes(),
                    qop.as_str().as_bytes(),
                    ha2.as_bytes(),
                ],
            )
        } else {
            hash_join(
                algorithm,
                &[ha1.as_bytes(), nonce.as_bytes(), ha2.as_bytes()],
            )
        };

        Ok(Self {
            username: credentials.username.clone(),
            realm: realm.into(),
            nonce: nonce.into(),
            uri: request.uri.into(),
            response: response.into(),
            algorithm,
            opaque: challenge
                .parameter("opaque")
                .map(|value| value.value().into()),
            qop,
            nonce_count: qop.map(|_| request.nonce_count),
            client_nonce: qop
                .or_else(|| algorithm.is_session().then_some(QualityOfProtection::Auth))
                .map(|_| request.client_nonce.into()),
        })
    }

    /// Returns the selected algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// Returns selected qop, if offered by the challenge.
    #[must_use]
    pub const fn qop(&self) -> Option<QualityOfProtection> {
        self.qop
    }

    /// Returns the lowercase hexadecimal response digest.
    #[must_use]
    pub const fn response(&self) -> &str {
        &self.response
    }
}

impl fmt::Debug for DigestAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigestAuthorization")
            .field("algorithm", &self.algorithm)
            .field("qop", &self.qop)
            .field("username_bytes", &self.username.len())
            .field("realm_bytes", &self.realm.len())
            .field("nonce_bytes", &self.nonce.len())
            .field("uri_bytes", &self.uri.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for DigestAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Digest username=")?;
        write_quoted(formatter, &self.username)?;
        formatter.write_str(", realm=")?;
        write_quoted(formatter, &self.realm)?;
        formatter.write_str(", nonce=")?;
        write_quoted(formatter, &self.nonce)?;
        formatter.write_str(", uri=")?;
        write_quoted(formatter, &self.uri)?;
        write!(
            formatter,
            ", response=\"{}\", algorithm={}",
            self.response,
            self.algorithm.as_str()
        )?;
        if let Some(opaque) = &self.opaque {
            formatter.write_str(", opaque=")?;
            write_quoted(formatter, opaque)?;
        }
        if let (Some(qop), Some(count), Some(client_nonce)) =
            (self.qop, self.nonce_count, self.client_nonce.as_deref())
        {
            write!(formatter, ", qop={}, nc={count:08x}, cnonce=", qop.as_str())?;
            write_quoted(formatter, client_nonce)?;
        } else if let Some(client_nonce) = self.client_nonce.as_deref() {
            formatter.write_str(", cnonce=")?;
            write_quoted(formatter, client_nonce)?;
        }
        Ok(())
    }
}

fn required<'a>(
    challenge: &'a AuthChallenge,
    name: &str,
    missing: DigestError,
) -> Result<&'a str, DigestError> {
    challenge
        .parameter(name)
        .map(AuthParameter::value)
        .ok_or(missing)
}

fn parse_algorithm(value: Option<&str>) -> Result<DigestAlgorithm, DigestError> {
    match value.unwrap_or("MD5") {
        value if value.eq_ignore_ascii_case("SHA-256") => Ok(DigestAlgorithm::Sha256),
        value if value.eq_ignore_ascii_case("SHA-256-sess") => Ok(DigestAlgorithm::Sha256Sess),
        value if value.eq_ignore_ascii_case("MD5") => Ok(DigestAlgorithm::Md5),
        value if value.eq_ignore_ascii_case("MD5-sess") => Ok(DigestAlgorithm::Md5Sess),
        _ => Err(DigestError::UnsupportedAlgorithm),
    }
}

fn parse_qop(value: Option<&str>) -> Result<Option<QualityOfProtection>, DigestError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let mut auth_int = false;
    for item in value.split(',').map(str::trim) {
        if item.eq_ignore_ascii_case("auth") {
            return Ok(Some(QualityOfProtection::Auth));
        }
        if item.eq_ignore_ascii_case("auth-int") {
            auth_int = true;
        }
    }
    if auth_int {
        Ok(Some(QualityOfProtection::AuthInt))
    } else {
        Err(DigestError::UnsupportedQop)
    }
}

fn hash_join(algorithm: DigestAlgorithm, parts: &[&[u8]]) -> String {
    let mut joined = Vec::new();
    let length = parts.iter().map(|part| part.len()).sum::<usize>() + parts.len().saturating_sub(1);
    joined.reserve(length);
    for (index, part) in parts.iter().enumerate() {
        if index != 0 {
            joined.push(b':');
        }
        joined.extend_from_slice(part);
    }
    hash(algorithm, &joined)
}

fn hash(algorithm: DigestAlgorithm, input: &[u8]) -> String {
    match algorithm {
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess => hex(&Sha256::digest(input)),
        DigestAlgorithm::Md5 | DigestAlgorithm::Md5Sess => hex(&Md5::digest(input)),
    }
}

fn hex(input: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn write_quoted(formatter: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    formatter.write_char('"')?;
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            formatter.write_char('\\')?;
        }
        formatter.write_char(character)?;
    }
    formatter.write_char('"')
}

#[derive(Clone, Copy)]
enum CredentialRole {
    Username,
    Password,
}

fn validate_secret(value: &str, maximum: usize, role: CredentialRole) -> Result<(), DigestError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(match role {
            CredentialRole::Username => DigestError::InvalidUsername,
            CredentialRole::Password => DigestError::InvalidPassword,
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ComponentRole {
    Uri,
    ClientNonce,
}

fn validate_component(value: &str, role: ComponentRole) -> Result<(), DigestError> {
    if value.is_empty()
        || value.len() > MAX_DIGEST_COMPONENT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(match role {
            ComponentRole::Uri => DigestError::InvalidUri,
            ComponentRole::ClientNonce => DigestError::MissingClientNonce,
        });
    }
    Ok(())
}

/// Digest calculation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DigestError {
    /// Authentication scheme was not Digest.
    UnsupportedScheme,
    /// Realm parameter was absent.
    MissingRealm,
    /// Nonce parameter was absent.
    MissingNonce,
    /// Algorithm token was unsupported.
    UnsupportedAlgorithm,
    /// Offered qop set contained no supported value.
    UnsupportedQop,
    /// Username was invalid or exceeded its bound.
    InvalidUsername,
    /// Password was invalid or exceeded its bound.
    InvalidPassword,
    /// Request-URI was invalid or exceeded its bound.
    InvalidUri,
    /// Client nonce was absent or invalid.
    MissingClientNonce,
    /// qop authentication used nonce count zero.
    ZeroNonceCount,
    /// Username hashing is not yet supported.
    UnsupportedUserHash,
}

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP Digest authentication calculation failed")
    }
}

impl StdError for DigestError {}

#[cfg(test)]
mod tests {
    use crate::sip::auth::challenge::AuthChallenge;
    use crate::sip::types::method::Method;

    use super::{
        DigestAlgorithm, DigestAuthorization, DigestCredentials, DigestError, DigestRequest,
        QualityOfProtection,
    };

    fn credentials() -> DigestCredentials {
        DigestCredentials::new("Mufasa", "Circle Of Life")
            .unwrap_or_else(|_| panic!("valid credentials"))
    }

    #[test]
    fn matches_rfc_2617_md5_auth_vector() {
        let challenge = AuthChallenge::from_bytes(
            br#"Digest realm="testrealm@host.com", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#,
        )
        .unwrap_or_else(|_| panic!("challenge"));
        let authorization = DigestAuthorization::calculate(
            &challenge,
            &credentials(),
            DigestRequest {
                method: &Method::Extension("GET".into()),
                uri: "/dir/index.html",
                entity_body: b"",
                nonce_count: 1,
                client_nonce: "0a4f113b",
            },
        )
        .unwrap_or_else(|_| panic!("calculate"));
        assert_eq!(authorization.response(), "6629fae49393a05397450978507c4ef1");
        assert_eq!(authorization.algorithm(), DigestAlgorithm::Md5);
        assert_eq!(authorization.qop(), Some(QualityOfProtection::Auth));
    }

    #[test]
    fn sha256_is_selected_and_auth_is_preferred() {
        let challenge = AuthChallenge::from_bytes(
            br#"Digest realm="router", nonce="n", algorithm=SHA-256, qop="auth-int, auth""#,
        )
        .unwrap_or_else(|_| panic!("challenge"));
        let authorization = DigestAuthorization::calculate(
            &challenge,
            &credentials(),
            DigestRequest {
                method: &Method::Invite,
                uri: "sip:router.example",
                entity_body: b"v=0\r\n",
                nonce_count: 7,
                client_nonce: "secure-client-nonce",
            },
        )
        .unwrap_or_else(|_| panic!("calculate"));
        assert_eq!(authorization.algorithm(), DigestAlgorithm::Sha256);
        assert_eq!(authorization.qop(), Some(QualityOfProtection::Auth));
        assert_eq!(authorization.response().len(), 64);
    }

    #[test]
    fn auth_int_changes_when_entity_body_changes() {
        let challenge = AuthChallenge::from_bytes(
            br#"Digest realm="router", nonce="n", algorithm=SHA-256, qop="auth-int""#,
        )
        .unwrap_or_else(|_| panic!("challenge"));
        let calculate = |body| {
            DigestAuthorization::calculate(
                &challenge,
                &credentials(),
                DigestRequest {
                    method: &Method::Invite,
                    uri: "sip:router.example",
                    entity_body: body,
                    nonce_count: 1,
                    client_nonce: "client-nonce",
                },
            )
            .unwrap_or_else(|_| panic!("calculate"))
        };
        assert_ne!(calculate(b"one").response(), calculate(b"two").response());
    }

    #[test]
    fn rejects_unsupported_or_incomplete_challenges() {
        let basic = AuthChallenge::from_bytes(br#"Basic realm="x""#)
            .unwrap_or_else(|_| panic!("challenge"));
        let request = DigestRequest {
            method: &Method::Invite,
            uri: "sip:x.example",
            entity_body: b"",
            nonce_count: 1,
            client_nonce: "cnonce",
        };
        assert_eq!(
            DigestAuthorization::calculate(&basic, &credentials(), request),
            Err(DigestError::UnsupportedScheme)
        );
    }

    #[test]
    fn diagnostics_never_expose_credentials_or_challenge_values() {
        let credentials = DigestCredentials::new("private-user", "secret-password")
            .unwrap_or_else(|_| panic!("credentials"));
        let challenge = AuthChallenge::from_bytes(
            br#"Digest realm="secret-realm", nonce="secret-nonce", algorithm=SHA-256, qop="auth""#,
        )
        .unwrap_or_else(|_| panic!("challenge"));
        let authorization = DigestAuthorization::calculate(
            &challenge,
            &credentials,
            DigestRequest {
                method: &Method::Invite,
                uri: "sip:private-target.example",
                entity_body: b"",
                nonce_count: 1,
                client_nonce: "secret-cnonce",
            },
        )
        .unwrap_or_else(|_| panic!("calculate"));
        let debug = format!("{credentials:?} {authorization:?}");
        for secret in [
            "private-user",
            "secret-password",
            "secret-realm",
            "secret-nonce",
            "private-target",
            "secret-cnonce",
        ] {
            assert!(!debug.contains(secret));
        }
    }
}
