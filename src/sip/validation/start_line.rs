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

//! Typed SIP start-line validation.
//!
//! This module validates the semantic components of a structurally parsed SIP
//! request line or status line.
//!
//! Structural parsing has already established safe byte boundaries and exact
//! start-line component separation. This layer therefore delegates individual
//! component semantics to the existing typed parsers for:
//!
//! - SIP methods;
//! - request URIs;
//! - SIP versions;
//! - response status codes.
//!
//! The returned values are owned typed representations. The original
//! [`RawMessage`](crate::sip::types::message::RawMessage) remains unchanged and
//! continues to preserve the exact wire representation.
//!
//! `CSeq` consistency and typed core-header validation belong to later
//! validation layers.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::parser::uri::{self, ParseError as UriParseError};
use crate::sip::types::message::{RawMessage, RawStartLineView};
use crate::sip::types::method::{Method, ParseError as MethodParseError};
use crate::sip::types::status::{ParseError as StatusParseError, StatusCode};
use crate::sip::types::uri::Uri;
use crate::sip::types::version::{ParseError as VersionParseError, Version};

/// Validates and types the start line of a structurally parsed SIP message.
///
/// This operation performs no mutation of the raw message. Request methods,
/// request URIs, versions, and status codes are interpreted using their
/// existing typed parsers.
///
/// # Errors
///
/// Returns [`ValidationError`] when any start-line component is structurally
/// representable but semantically invalid or unsupported by the corresponding
/// typed parser.
pub fn validate(message: &RawMessage) -> Result<ValidatedStartLine, ValidationError> {
    match message.start_line_view() {
        RawStartLineView::Request(line) => {
            let method =
                Method::from_bytes(line.method()).map_err(ValidationError::InvalidMethod)?;

            let uri = uri::parse(line.uri()).map_err(ValidationError::InvalidRequestUri)?;

            let version =
                Version::from_bytes(line.version()).map_err(ValidationError::InvalidVersion)?;

            Ok(ValidatedStartLine::Request(ValidatedRequestLine {
                method,
                uri,
                version,
            }))
        }
        RawStartLineView::Response(line) => {
            let version =
                Version::from_bytes(line.version()).map_err(ValidationError::InvalidVersion)?;

            let status =
                StatusCode::from_bytes(line.status()).map_err(ValidationError::InvalidStatus)?;

            Ok(ValidatedStartLine::Response(ValidatedResponseLine {
                version,
                status,
            }))
        }
    }
}

/// A semantically validated SIP start line.
pub enum ValidatedStartLine {
    /// A validated SIP request line.
    Request(ValidatedRequestLine),

    /// A validated SIP status line.
    Response(ValidatedResponseLine),
}

impl ValidatedStartLine {
    /// Returns the validated request line when this represents a request.
    #[must_use]
    pub const fn as_request(&self) -> Option<&ValidatedRequestLine> {
        match self {
            Self::Request(request) => Some(request),
            Self::Response(_) => None,
        }
    }

    /// Returns the validated response line when this represents a response.
    #[must_use]
    pub const fn as_response(&self) -> Option<&ValidatedResponseLine> {
        match self {
            Self::Request(_) => None,
            Self::Response(response) => Some(response),
        }
    }

    /// Consumes the start line and returns the validated request when present.
    #[must_use]
    pub fn into_request(self) -> Option<ValidatedRequestLine> {
        match self {
            Self::Request(request) => Some(request),
            Self::Response(_) => None,
        }
    }

    /// Consumes the start line and returns the validated response when present.
    #[must_use]
    pub fn into_response(self) -> Option<ValidatedResponseLine> {
        match self {
            Self::Request(_) => None,
            Self::Response(response) => Some(response),
        }
    }
}

/// A semantically validated SIP request line.
pub struct ValidatedRequestLine {
    method: Method,
    uri: Uri,
    version: Version,
}

impl ValidatedRequestLine {
    /// Returns the request method.
    #[must_use]
    pub const fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the request URI.
    #[must_use]
    pub const fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns the SIP version.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// Consumes the request line into its typed components.
    #[must_use]
    pub fn into_parts(self) -> (Method, Uri, Version) {
        (self.method, self.uri, self.version)
    }
}

/// A semantically validated SIP response status line.
pub struct ValidatedResponseLine {
    version: Version,
    status: StatusCode,
}

impl ValidatedResponseLine {
    /// Returns the SIP version.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// Returns the response status code.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Consumes the response line into its typed components.
    #[must_use]
    pub const fn into_parts(self) -> (Version, StatusCode) {
        (self.version, self.status)
    }
}

/// Failure to semantically validate a SIP start-line component.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidationError {
    /// The request method was invalid.
    InvalidMethod(MethodParseError),

    /// The request URI was invalid.
    InvalidRequestUri(UriParseError),

    /// The SIP version was invalid or unsupported.
    InvalidVersion(VersionParseError),

    /// The response status code was invalid.
    InvalidStatus(StatusParseError),
}

impl ValidationError {
    /// Returns a stable low-cardinality classification suitable for metrics
    /// and structured logs.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::InvalidMethod(_) => "invalid-method",
            Self::InvalidRequestUri(_) => "invalid-request-uri",
            Self::InvalidVersion(_) => "invalid-version",
            Self::InvalidStatus(_) => "invalid-status",
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMethod(error) => {
                write!(formatter, "invalid SIP request method: {error}")
            }
            Self::InvalidRequestUri(error) => {
                write!(formatter, "invalid SIP request URI: {error}")
            }
            Self::InvalidVersion(error) => {
                write!(formatter, "invalid or unsupported SIP version: {error}")
            }
            Self::InvalidStatus(error) => {
                write!(formatter, "invalid SIP response status code: {error}")
            }
        }
    }
}

impl StdError for ValidationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidMethod(error) => Some(error),
            Self::InvalidRequestUri(error) => Some(error),
            Self::InvalidVersion(error) => Some(error),
            Self::InvalidStatus(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ValidatedStartLine, ValidationError, validate};
    use crate::sip::parser::message::parse;
    use crate::sip::types::method::Method;
    use crate::sip::types::version::Version;
    use std::error::Error as _;
    use std::sync::Arc;

    fn parse_message(input: &[u8]) -> crate::sip::types::message::RawMessage {
        let Ok(message) = parse(Arc::from(input)) else {
            panic!("expected structurally valid SIP message");
        };

        message
    }

    #[test]
    fn validates_request_start_line() {
        let message =
            parse_message(b"INVITE sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n");

        let Ok(ValidatedStartLine::Request(request)) = validate(&message) else {
            panic!("expected validated request line");
        };

        assert_eq!(request.method(), &Method::Invite);
        assert_eq!(request.uri().to_string(), "sip:bob@example.com");
        assert_eq!(request.version(), Version::Sip2);
    }

    #[test]
    fn validates_response_start_line() {
        let message = parse_message(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n");

        let Ok(ValidatedStartLine::Response(response)) = validate(&message) else {
            panic!("expected validated response line");
        };

        assert_eq!(response.version(), Version::Sip2);
        assert_eq!(response.status().to_string(), "200");
    }

    #[test]
    fn preserves_extension_request_method() {
        let message =
            parse_message(b"PING sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n");

        let Ok(ValidatedStartLine::Request(request)) = validate(&message) else {
            panic!("expected extension request method");
        };

        assert!(request.method().is_extension());
        assert_eq!(request.method().as_str(), "PING");
    }

    #[test]
    fn lowercase_core_method_remains_extension_method() {
        let message =
            parse_message(b"invite sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n");

        let Ok(ValidatedStartLine::Request(request)) = validate(&message) else {
            panic!("expected structurally valid extension method");
        };

        assert!(request.method().is_extension());
        assert_eq!(request.method().as_str(), "invite");
    }

    #[test]
    fn rejects_invalid_request_uri() {
        let message = parse_message(b"OPTIONS not-a-uri SIP/2.0\r\nContent-Length: 0\r\n\r\n");

        assert!(matches!(
            validate(&message),
            Err(ValidationError::InvalidRequestUri(_))
        ));
    }

    #[test]
    fn rejects_unsupported_request_version() {
        let message =
            parse_message(b"OPTIONS sip:bob@example.com SIP/3.0\r\nContent-Length: 0\r\n\r\n");

        assert!(matches!(
            validate(&message),
            Err(ValidationError::InvalidVersion(_))
        ));
    }

    #[test]
    fn rejects_invalid_request_version_syntax() {
        let message =
            parse_message(b"OPTIONS sip:bob@example.com FUTURE/7.4\r\nContent-Length: 0\r\n\r\n");

        assert!(matches!(
            validate(&message),
            Err(ValidationError::InvalidVersion(_))
        ));
    }

    #[test]
    fn rejects_unsupported_response_version() {
        let message = parse_message(b"SIP/3.0 200 OK\r\nContent-Length: 0\r\n\r\n");

        assert!(matches!(
            validate(&message),
            Err(ValidationError::InvalidVersion(_))
        ));
    }

    #[test]
    fn rejects_status_below_sip_response_range() {
        let message = parse_message(b"SIP/2.0 099 Invalid\r\nContent-Length: 0\r\n\r\n");

        assert!(matches!(
            validate(&message),
            Err(ValidationError::InvalidStatus(_))
        ));
    }

    #[test]
    fn rejects_status_above_sip_response_range() {
        let message = parse_message(b"SIP/2.0 700 Invalid\r\nContent-Length: 0\r\n\r\n");

        assert!(matches!(
            validate(&message),
            Err(ValidationError::InvalidStatus(_))
        ));
    }

    #[test]
    fn accepts_unknown_status_inside_valid_response_range() {
        let message = parse_message(b"SIP/2.0 699 Extension\r\nContent-Length: 0\r\n\r\n");

        let Ok(ValidatedStartLine::Response(response)) = validate(&message) else {
            panic!("expected valid extension status code");
        };

        assert_eq!(response.status().to_string(), "699");
    }

    #[test]
    fn request_accessors_distinguish_message_kind() {
        let message =
            parse_message(b"OPTIONS sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n");

        let Ok(validated) = validate(&message) else {
            panic!("expected validated request");
        };

        assert!(validated.as_request().is_some());
        assert!(validated.as_response().is_none());
    }

    #[test]
    fn response_accessors_distinguish_message_kind() {
        let message = parse_message(b"SIP/2.0 486 Busy Here\r\nContent-Length: 0\r\n\r\n");

        let Ok(validated) = validate(&message) else {
            panic!("expected validated response");
        };

        assert!(validated.as_request().is_none());
        assert!(validated.as_response().is_some());
    }

    #[test]
    fn request_can_be_consumed_into_parts() {
        let message =
            parse_message(b"BYE sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n");

        let Ok(validated) = validate(&message) else {
            panic!("expected validated request");
        };

        let Some(request) = validated.into_request() else {
            panic!("expected request");
        };

        let (method, uri, version) = request.into_parts();

        assert_eq!(method, Method::Bye);
        assert_eq!(uri.to_string(), "sip:bob@example.com");
        assert_eq!(version, Version::Sip2);
    }

    #[test]
    fn response_can_be_consumed_into_parts() {
        let message = parse_message(b"SIP/2.0 486 Busy Here\r\nContent-Length: 0\r\n\r\n");

        let Ok(validated) = validate(&message) else {
            panic!("expected validated response");
        };

        let Some(response) = validated.into_response() else {
            panic!("expected response");
        };

        let (version, status) = response.into_parts();

        assert_eq!(version, Version::Sip2);
        assert_eq!(status.to_string(), "486");
    }

    #[test]
    fn error_classes_are_stable() {
        let invalid_uri = parse_message(b"OPTIONS invalid SIP/2.0\r\nContent-Length: 0\r\n\r\n");

        let Err(error) = validate(&invalid_uri) else {
            panic!("expected URI validation failure");
        };

        assert_eq!(error.class(), "invalid-request-uri");

        let invalid_version =
            parse_message(b"OPTIONS sip:bob@example.com SIP/3.0\r\nContent-Length: 0\r\n\r\n");

        let Err(error) = validate(&invalid_version) else {
            panic!("expected version validation failure");
        };

        assert_eq!(error.class(), "invalid-version");

        let invalid_status = parse_message(b"SIP/2.0 999 Invalid\r\nContent-Length: 0\r\n\r\n");

        let Err(error) = validate(&invalid_status) else {
            panic!("expected status validation failure");
        };

        assert_eq!(error.class(), "invalid-status");
    }

    #[test]
    fn nested_parse_errors_are_exposed_as_sources() {
        let message = parse_message(b"OPTIONS invalid SIP/2.0\r\nContent-Length: 0\r\n\r\n");

        let Err(error) = validate(&message) else {
            panic!("expected URI validation failure");
        };

        assert!(error.source().is_some());
    }
}
