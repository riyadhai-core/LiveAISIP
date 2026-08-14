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

//! Validated SIP response envelope.
//!
//! This module composes structural message, start-line, and typed core-header
//! validation into the boundary consumed by client transactions. It verifies
//! that the message is a response and that its status line uses the exact
//! `SIP-Version SP Status-Code SP Reason-Phrase` wire layout.
//!
//! Response matching, Via branch processing, tag requirements, authentication
//! challenge handling, and status-specific header policy belong to later
//! transaction, dialog, and authentication layers.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::types::message::{MessageKind, RawMessage, RawStartLineView};

use super::headers::{self, ValidatedCoreHeaders};
use super::start_line::{self, ValidatedResponseLine, ValidatedStartLine};

/// A structurally and semantically validated SIP response.
///
/// The exact immutable wire message remains available beside owned typed
/// values. Private fields prevent downstream code from forging the validation
/// guarantees.
pub struct ValidatedResponse {
    message: RawMessage,
    response_line: ValidatedResponseLine,
    core_headers: ValidatedCoreHeaders,
}

impl ValidatedResponse {
    /// Returns the original immutable SIP message.
    #[must_use]
    pub const fn message(&self) -> &RawMessage {
        &self.message
    }

    /// Returns the typed response status line.
    #[must_use]
    pub const fn response_line(&self) -> &ValidatedResponseLine {
        &self.response_line
    }

    /// Returns the typed transaction-critical headers.
    #[must_use]
    pub const fn core_headers(&self) -> &ValidatedCoreHeaders {
        &self.core_headers
    }

    /// Returns the original reason-phrase bytes.
    ///
    /// The phrase is informational and must not be used to make protocol
    /// decisions. It may be empty and is not included in `Debug` output.
    #[must_use]
    pub fn reason_phrase(&self) -> &[u8] {
        let RawStartLineView::Response(line) = self.message.start_line_view() else {
            unreachable!("validated response retained a request start line");
        };

        line.reason()
    }

    /// Consumes the envelope and returns the original immutable message.
    #[must_use]
    pub fn into_message(self) -> RawMessage {
        self.message
    }
}

impl fmt::Debug for ValidatedResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedResponse")
            .field("status", &self.response_line.status().as_u16())
            .field("message_bytes", &self.message.len())
            .field("header_count", &self.message.header_count())
            .field("body_bytes", &self.message.body().len())
            .field("via_entries", &self.core_headers.via_entry_count())
            .finish_non_exhaustive()
    }
}

/// Validates a structurally parsed message as a SIP response.
///
/// The input is consumed so the successful envelope can preserve the exact
/// raw message without copying it.
///
/// # Errors
///
/// Returns [`ValidationError`] when the message is a request, its status line
/// is malformed, or its transaction-critical headers are invalid.
pub fn validate(message: RawMessage) -> Result<ValidatedResponse, ValidationError> {
    if message.kind() != MessageKind::Response {
        return Err(ValidationError::NotResponse);
    }

    validate_status_line_layout(&message)?;

    let start_line = start_line::validate(&message).map_err(ValidationError::StartLine)?;
    let ValidatedStartLine::Response(response_line) = start_line else {
        return Err(ValidationError::NotResponse);
    };

    let core_headers = headers::validate(&message).map_err(ValidationError::Headers)?;

    Ok(ValidatedResponse {
        message,
        response_line,
        core_headers,
    })
}

fn validate_status_line_layout(message: &RawMessage) -> Result<(), ValidationError> {
    let RawStartLineView::Response(line) = message.start_line_view() else {
        return Err(ValidationError::NotResponse);
    };

    let expected_status_start = line.version().len().checked_add(1);
    let expected_reason_start = expected_status_start
        .and_then(|start| start.checked_add(line.status().len()))
        .and_then(|end| end.checked_add(1));
    let expected_line_length =
        expected_reason_start.and_then(|start| start.checked_add(line.reason().len()));

    let exact = expected_status_start
        .zip(expected_reason_start)
        .zip(expected_line_length)
        .is_some_and(|((status_start, reason_start), line_length)| {
            line.line().len() == line_length
                && line.line().get(line.version().len()) == Some(&b' ')
                && line
                    .line()
                    .get(status_start..status_start + line.status().len())
                    == Some(line.status())
                && line.line().get(reason_start - 1) == Some(&b' ')
                && line.line().get(reason_start..) == Some(line.reason())
        });

    if !exact {
        return Err(ValidationError::InvalidStatusLineLayout);
    }

    Ok(())
}

/// Failure to validate a complete SIP response.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidationError {
    /// The structural message is a SIP request rather than a response.
    NotResponse,

    /// The status-line components were not separated by exactly one SP.
    InvalidStatusLineLayout,

    /// A typed status-line component was invalid.
    StartLine(start_line::ValidationError),

    /// The core message headers were invalid.
    Headers(headers::ValidationError),
}

impl ValidationError {
    /// Returns a stable low-cardinality classification suitable for metrics
    /// and structured logs.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::NotResponse => "not-response",
            Self::InvalidStatusLineLayout => "invalid-status-line-layout",
            Self::StartLine(_) => "invalid-start-line",
            Self::Headers(_) => "invalid-headers",
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotResponse => formatter.write_str("SIP message is not a response"),
            Self::InvalidStatusLineLayout => {
                formatter.write_str("SIP status line does not use exact SP separators")
            }
            Self::StartLine(error) => write!(formatter, "invalid SIP status line: {error}"),
            Self::Headers(error) => write!(formatter, "invalid SIP response headers: {error}"),
        }
    }
}

impl StdError for ValidationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::StartLine(error) => Some(error),
            Self::Headers(error) => Some(error),
            Self::NotResponse | Self::InvalidStatusLineLayout => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;
    use std::sync::Arc;

    use crate::sip::parser::message::parse;
    use crate::sip::types::message::RawMessage;
    use crate::sip::types::status::StatusCode;

    use super::{ValidationError, validate};

    fn parse_message(input: &[u8]) -> RawMessage {
        let Ok(message) = parse(Arc::from(input)) else {
            panic!("expected structurally representable SIP message");
        };

        message
    }

    fn response(status: &str, reason: &str) -> RawMessage {
        let bytes = format!(
            "SIP/2.0 {status} {reason}\r\n\
             Via: SIP/2.0/UDP runtime.example.com;branch=z9hG4bK-one\r\n\
             From: <sip:runtime@example.com>;tag=local\r\n\
             To: <sip:service@example.com>;tag=remote\r\n\
             Call-ID: private-call-id@example.com\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );

        parse_message(bytes.as_bytes())
    }

    #[test]
    fn validates_and_retains_a_canonical_response() {
        let message = response("200", "OK");
        let original = message.as_bytes().as_ptr();

        let Ok(validated) = validate(message) else {
            panic!("expected valid response");
        };

        assert_eq!(validated.response_line().status(), StatusCode::OK);
        assert_eq!(validated.reason_phrase(), b"OK");
        assert_eq!(validated.core_headers().cseq().sequence(), 1);
        assert!(validated.core_headers().max_forwards().is_none());
        assert_eq!(validated.message().as_bytes().as_ptr(), original);
    }

    #[test]
    fn accepts_an_empty_reason_phrase() {
        let message = response("100", "");

        let Ok(validated) = validate(message) else {
            panic!("expected empty reason phrase to remain valid");
        };

        assert_eq!(validated.response_line().status(), StatusCode::TRYING);
        assert!(validated.reason_phrase().is_empty());
    }

    #[test]
    fn preserves_extension_status_and_reason_phrase() {
        let message = response("699", "Private Failure Detail");

        let Ok(validated) = validate(message) else {
            panic!("expected valid extension response");
        };

        assert_eq!(validated.response_line().status().as_u16(), 699);
        assert_eq!(validated.reason_phrase(), b"Private Failure Detail");
    }

    #[test]
    fn rejects_a_request_before_response_validation() {
        let message = parse_message(
            b"OPTIONS sip:service@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP runtime.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:runtime@example.com>;tag=local\r\n\
              To: <sip:service@example.com>\r\n\
              Call-ID: private-call-id@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Max-Forwards: 70\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        let Err(error) = validate(message) else {
            panic!("expected request rejection");
        };

        assert!(matches!(error, ValidationError::NotResponse));
        assert_eq!(error.class(), "not-response");
    }

    #[test]
    fn propagates_invalid_status_with_a_source() {
        let message = response("099", "Invalid");

        let Err(error) = validate(message) else {
            panic!("expected status rejection");
        };

        assert!(matches!(error, ValidationError::StartLine(_)));
        assert!(StdError::source(&error).is_some());
    }

    #[test]
    fn propagates_core_header_failure_with_a_source() {
        let message = parse_message(
            b"SIP/2.0 200 OK\r\n\
              From: <sip:runtime@example.com>;tag=local\r\n\
              To: <sip:service@example.com>;tag=remote\r\n\
              Call-ID: private-call-id@example.com\r\n\
              CSeq: 1 INVITE\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        let Err(error) = validate(message) else {
            panic!("expected missing Via rejection");
        };

        assert!(matches!(error, ValidationError::Headers(_)));
        assert!(StdError::source(&error).is_some());
    }

    #[test]
    fn debug_output_is_redacted() {
        let message = response("486", "Sensitive Private Phrase");
        let Ok(validated) = validate(message) else {
            panic!("expected valid response");
        };

        let debug = format!("{validated:?}");
        assert!(!debug.contains("Sensitive Private Phrase"));
        assert!(!debug.contains("private-call-id"));
        assert!(!debug.contains("runtime.example.com"));
        assert!(!debug.contains("service@example.com"));
    }

    #[test]
    fn consuming_envelope_returns_original_message() {
        let message = response("503", "Service Unavailable");
        let expected = message.as_bytes().to_vec();
        let Ok(validated) = validate(message) else {
            panic!("expected valid response");
        };

        assert_eq!(validated.into_message().as_bytes(), expected);
    }
}
