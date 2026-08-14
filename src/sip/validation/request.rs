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

//! Validated SIP request envelope.
//!
//! This module composes structural message, start-line, and typed core-header
//! validation into the boundary consumed by request transactions. It adds the
//! request-wide invariants that do not belong to any individual field:
//!
//! - the message must be a request;
//! - the request line must use the exact `Method SP Request-URI SP SIP-Version`
//!   wire layout;
//! - `Max-Forwards` must be present;
//! - the request-line method and `CSeq` method must match exactly.
//!
//! Transaction, dialog, routing, authentication, and method-specific policy
//! remain outside this layer. In particular, Via branch-cookie rules, tag
//! requirements, route-set processing, and request-method admission are not
//! enforced here.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::types::message::{MessageKind, RawMessage, RawStartLineView};

use super::headers::{self, ValidatedCoreHeaders};
use super::start_line::{self, ValidatedRequestLine, ValidatedStartLine};

/// A structurally and semantically validated SIP request.
///
/// The original immutable wire message is retained losslessly beside owned
/// typed values. Private fields prevent downstream code from constructing an
/// envelope that bypasses request validation.
pub struct ValidatedRequest {
    message: RawMessage,
    request_line: ValidatedRequestLine,
    core_headers: ValidatedCoreHeaders,
}

impl ValidatedRequest {
    /// Returns the original immutable SIP message.
    #[must_use]
    pub const fn message(&self) -> &RawMessage {
        &self.message
    }

    /// Returns the typed request line.
    #[must_use]
    pub const fn request_line(&self) -> &ValidatedRequestLine {
        &self.request_line
    }

    /// Returns the typed transaction-critical headers.
    #[must_use]
    pub const fn core_headers(&self) -> &ValidatedCoreHeaders {
        &self.core_headers
    }

    /// Consumes the envelope and returns the original immutable message.
    #[must_use]
    pub fn into_message(self) -> RawMessage {
        self.message
    }
}

impl fmt::Debug for ValidatedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedRequest")
            .field("message_bytes", &self.message.len())
            .field("header_count", &self.message.header_count())
            .field("body_bytes", &self.message.body().len())
            .field("via_entries", &self.core_headers.via_entry_count())
            .field(
                "max_forwards_present",
                &self.core_headers.max_forwards().is_some(),
            )
            .finish_non_exhaustive()
    }
}

/// Validates a structurally parsed message as a SIP request.
///
/// Validation is bounded by the limits enforced by the structural parser and
/// typed core-header validator. The input is consumed so a successful result
/// can retain the exact raw wire message without copying it.
///
/// # Errors
///
/// Returns [`ValidationError`] when the message is a response, its request
/// line or core headers are invalid, `Max-Forwards` is absent, or its
/// request-line and `CSeq` methods disagree.
pub fn validate(message: RawMessage) -> Result<ValidatedRequest, ValidationError> {
    if message.kind() != MessageKind::Request {
        return Err(ValidationError::NotRequest);
    }

    validate_request_line_layout(&message)?;

    let start_line = start_line::validate(&message).map_err(ValidationError::StartLine)?;
    let ValidatedStartLine::Request(request_line) = start_line else {
        return Err(ValidationError::NotRequest);
    };

    let core_headers = headers::validate(&message).map_err(ValidationError::Headers)?;

    if core_headers.max_forwards().is_none() {
        return Err(ValidationError::MissingMaxForwards);
    }

    if request_line.method() != core_headers.cseq().method() {
        return Err(ValidationError::CSeqMethodMismatch);
    }

    Ok(ValidatedRequest {
        message,
        request_line,
        core_headers,
    })
}

fn validate_request_line_layout(message: &RawMessage) -> Result<(), ValidationError> {
    let RawStartLineView::Request(line) = message.start_line_view() else {
        return Err(ValidationError::NotRequest);
    };

    let expected_uri_start = line.method().len().checked_add(1);
    let expected_version_start = expected_uri_start
        .and_then(|start| start.checked_add(line.uri().len()))
        .and_then(|end| end.checked_add(1));
    let expected_line_length =
        expected_version_start.and_then(|start| start.checked_add(line.version().len()));

    let exact = expected_uri_start
        .zip(expected_version_start)
        .zip(expected_line_length)
        .is_some_and(|((uri_start, version_start), line_length)| {
            line.line().len() == line_length
                && line.line().get(line.method().len()) == Some(&b' ')
                && line.line().get(uri_start..uri_start + line.uri().len()) == Some(line.uri())
                && line.line().get(version_start - 1) == Some(&b' ')
                && line.line().get(version_start..) == Some(line.version())
        });

    if !exact {
        return Err(ValidationError::InvalidRequestLineLayout);
    }

    Ok(())
}

/// Failure to validate a complete SIP request.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidationError {
    /// The structural message is a SIP response rather than a request.
    NotRequest,

    /// The request-line components were not separated by exactly one SP.
    InvalidRequestLineLayout,

    /// A typed start-line component was invalid.
    StartLine(start_line::ValidationError),

    /// The core message headers were invalid.
    Headers(headers::ValidationError),

    /// The request omitted `Max-Forwards`.
    MissingMaxForwards,

    /// The request-line method and `CSeq` method differed.
    CSeqMethodMismatch,
}

impl ValidationError {
    /// Returns a stable low-cardinality classification suitable for metrics
    /// and structured logs.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::NotRequest => "not-request",
            Self::InvalidRequestLineLayout => "invalid-request-line-layout",
            Self::StartLine(_) => "invalid-start-line",
            Self::Headers(_) => "invalid-headers",
            Self::MissingMaxForwards => "missing-max-forwards",
            Self::CSeqMethodMismatch => "cseq-method-mismatch",
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRequest => formatter.write_str("SIP message is not a request"),
            Self::InvalidRequestLineLayout => {
                formatter.write_str("SIP request line does not use exact SP separators")
            }
            Self::StartLine(error) => write!(formatter, "invalid SIP request line: {error}"),
            Self::Headers(error) => write!(formatter, "invalid SIP request headers: {error}"),
            Self::MissingMaxForwards => {
                formatter.write_str("SIP request is missing required Max-Forwards header")
            }
            Self::CSeqMethodMismatch => {
                formatter.write_str("SIP request-line method does not match the CSeq method")
            }
        }
    }
}

impl StdError for ValidationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::StartLine(error) => Some(error),
            Self::Headers(error) => Some(error),
            Self::NotRequest
            | Self::InvalidRequestLineLayout
            | Self::MissingMaxForwards
            | Self::CSeqMethodMismatch => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;
    use std::sync::Arc;

    use crate::sip::parser::message::parse;
    use crate::sip::types::message::RawMessage;
    use crate::sip::types::method::Method;

    use super::{ValidationError, validate};

    fn parse_message(input: &[u8]) -> RawMessage {
        let Ok(message) = parse(Arc::from(input)) else {
            panic!("expected structurally representable SIP message");
        };

        message
    }

    fn request(method: &str, cseq_method: &str, max_forwards: &str) -> RawMessage {
        let bytes = format!(
            "{method} sip:service@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP runtime.example.com;branch=z9hG4bK-one\r\n\
             From: <sip:runtime@example.com>;tag=local\r\n\
             To: <sip:service@example.com>\r\n\
             Call-ID: private-call-id@example.com\r\n\
             CSeq: 1 {cseq_method}\r\n\
             {max_forwards}\
             Content-Length: 0\r\n\
             \r\n"
        );

        parse_message(bytes.as_bytes())
    }

    #[test]
    fn validates_and_retains_a_canonical_outbound_request() {
        let message = request("INVITE", "INVITE", "Max-Forwards: 70\r\n");
        let original = message.as_bytes().as_ptr();

        let Ok(validated) = validate(message) else {
            panic!("expected valid request");
        };

        assert_eq!(validated.request_line().method(), &Method::Invite);
        assert_eq!(validated.core_headers().cseq().sequence(), 1);
        assert_eq!(
            validated
                .core_headers()
                .max_forwards()
                .map(crate::sip::headers::max_forwards::MaxForwards::as_u8),
            Some(70)
        );
        assert_eq!(validated.message().as_bytes().as_ptr(), original);
    }

    #[test]
    fn accepts_matching_bounded_extension_methods() {
        let message = request("AI-CALL", "AI-CALL", "Max-Forwards: 12\r\n");

        let Ok(validated) = validate(message) else {
            panic!("expected matching extension method");
        };

        assert_eq!(validated.request_line().method().as_str(), "AI-CALL");
    }

    #[test]
    fn rejects_a_response_before_request_validation() {
        let message = parse_message(
            b"SIP/2.0 200 OK\r\n\
              Via: SIP/2.0/UDP runtime.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:runtime@example.com>;tag=local\r\n\
              To: <sip:service@example.com>;tag=remote\r\n\
              Call-ID: private-call-id@example.com\r\n\
              CSeq: 1 INVITE\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        let Err(error) = validate(message) else {
            panic!("expected response rejection");
        };

        assert!(matches!(error, ValidationError::NotRequest));
        assert_eq!(error.class(), "not-request");
    }

    #[test]
    fn rejects_missing_max_forwards() {
        let message = request("OPTIONS", "OPTIONS", "");

        let Err(error) = validate(message) else {
            panic!("expected missing Max-Forwards rejection");
        };

        assert!(matches!(error, ValidationError::MissingMaxForwards));
    }

    #[test]
    fn rejects_cseq_method_mismatch_without_disclosing_methods() {
        let message = request("INVITE", "BYE", "Max-Forwards: 70\r\n");

        let Err(error) = validate(message) else {
            panic!("expected CSeq mismatch");
        };

        assert!(matches!(error, ValidationError::CSeqMethodMismatch));
        assert_eq!(error.class(), "cseq-method-mismatch");
        assert!(!error.to_string().contains("INVITE"));
        assert!(!error.to_string().contains("BYE"));
    }

    #[test]
    fn rejects_case_distinct_extension_methods() {
        let message = request("AI-CALL", "ai-call", "Max-Forwards: 70\r\n");

        let Err(error) = validate(message) else {
            panic!("expected case-sensitive CSeq mismatch");
        };

        assert!(matches!(error, ValidationError::CSeqMethodMismatch));
    }

    #[test]
    fn propagates_start_line_failures_with_a_source() {
        let message = request("invite", "invite", "Max-Forwards: 70\r\n");
        let Ok(validated) = validate(message) else {
            panic!("lowercase token is a valid extension method");
        };

        assert_eq!(validated.request_line().method().as_str(), "invite");

        let message = parse_message(
            b"INVITE invalid-uri SIP/2.0\r\n\
              Via: SIP/2.0/UDP runtime.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:runtime@example.com>;tag=local\r\n\
              To: <sip:service@example.com>\r\n\
              Call-ID: private-call-id@example.com\r\n\
              CSeq: 1 INVITE\r\n\
              Max-Forwards: 70\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        let Err(error) = validate(message) else {
            panic!("expected URI failure");
        };

        assert!(matches!(error, ValidationError::StartLine(_)));
        assert!(StdError::source(&error).is_some());
    }

    #[test]
    fn propagates_core_header_failures_with_a_source() {
        let message = parse_message(
            b"INVITE sip:service@example.com SIP/2.0\r\n\
              From: <sip:runtime@example.com>;tag=local\r\n\
              To: <sip:service@example.com>\r\n\
              Call-ID: private-call-id@example.com\r\n\
              CSeq: 1 INVITE\r\n\
              Max-Forwards: 70\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        let Err(error) = validate(message) else {
            panic!("expected missing Via failure");
        };

        assert!(matches!(error, ValidationError::Headers(_)));
        assert!(StdError::source(&error).is_some());
    }

    #[test]
    fn debug_output_is_redacted() {
        let message = request("INVITE", "INVITE", "Max-Forwards: 70\r\n");
        let Ok(validated) = validate(message) else {
            panic!("expected valid request");
        };

        let debug = format!("{validated:?}");
        assert!(!debug.contains("private-call-id"));
        assert!(!debug.contains("runtime.example.com"));
        assert!(!debug.contains("service@example.com"));
    }

    #[test]
    fn consuming_envelope_returns_original_message() {
        let message = request("BYE", "BYE", "Max-Forwards: 69\r\n");
        let expected = message.as_bytes().to_vec();
        let Ok(validated) = validate(message) else {
            panic!("expected valid request");
        };

        assert_eq!(validated.into_message().as_bytes(), expected);
    }
}
