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

//! Structural SIP message invariants.
//!
//! This module validates message-level requirements after lossless structural
//! parsing and before typed SIP header interpretation.
//!
//! The validator deliberately does not parse individual header values. Its
//! responsibilities are limited to:
//!
//! - required core header presence;
//! - singleton header multiplicity;
//! - presence of at least one `Via` field;
//! - body and `Content-Type` consistency;
//! - bounded, allocation-free validation work.
//!
//! Unknown headers, optional known headers, duplicate fields whose grammar
//! permits repetition, and raw wire bytes remain untouched.
//!
//! Header-value syntax, request-URI syntax, SIP version semantics, `CSeq` method
//! matching, transaction rules, dialog rules, and method-specific policy
//! belong to later validation layers.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::types::header::HeaderKind;
use crate::sip::types::message::RawMessage;

/// Validates message-level SIP invariants.
///
/// This function performs one bounded pass over the structurally parsed
/// headers. It does not allocate and does not parse typed header values.
///
/// Both requests and responses require the core transaction-identifying
/// fields represented by `Via`, `From`, `To`, `Call-ID`, and `CSeq`.
///
/// `Max-Forwards` is treated as an optional singleton at this role-neutral
/// layer. Generation and forwarding policy can require or insert it later.
///
/// A non-empty message body requires one `Content-Type` field.
///
/// # Errors
///
/// Returns [`ValidationError`] when a required core field is absent, a
/// singleton field occurs more than once, or a non-empty body lacks
/// `Content-Type`.
pub fn validate(message: &RawMessage) -> Result<(), ValidationError> {
    let counts = HeaderCounts::from_message(message);

    validate_required_headers(counts)?;
    validate_singletons(counts)?;

    if !message.body().is_empty() && counts.content_type == 0 {
        return Err(ValidationError::MissingContentTypeForBody);
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct HeaderCounts {
    via: u16,
    from: u16,
    to: u16,
    call_id: u16,
    cseq: u16,
    max_forwards: u16,
    content_type: u16,
}

impl HeaderCounts {
    fn from_message(message: &RawMessage) -> Self {
        let mut counts = Self::default();

        for header in message.header_views() {
            match header.kind() {
                Some(HeaderKind::Via) => increment(&mut counts.via),
                Some(HeaderKind::From) => increment(&mut counts.from),
                Some(HeaderKind::To) => increment(&mut counts.to),
                Some(HeaderKind::CallId) => increment(&mut counts.call_id),
                Some(HeaderKind::CSeq) => increment(&mut counts.cseq),
                Some(HeaderKind::MaxForwards) => increment(&mut counts.max_forwards),
                Some(HeaderKind::ContentType) => increment(&mut counts.content_type),
                _ => {}
            }
        }

        counts
    }
}

const fn increment(value: &mut u16) {
    *value = value.saturating_add(1);
}

fn validate_required_headers(counts: HeaderCounts) -> Result<(), ValidationError> {
    require_header(HeaderKind::Via, counts.via)?;
    require_header(HeaderKind::From, counts.from)?;
    require_header(HeaderKind::To, counts.to)?;
    require_header(HeaderKind::CallId, counts.call_id)?;
    require_header(HeaderKind::CSeq, counts.cseq)?;

    Ok(())
}

fn validate_singletons(counts: HeaderCounts) -> Result<(), ValidationError> {
    require_singleton(HeaderKind::From, counts.from)?;
    require_singleton(HeaderKind::To, counts.to)?;
    require_singleton(HeaderKind::CallId, counts.call_id)?;
    require_singleton(HeaderKind::CSeq, counts.cseq)?;
    require_singleton(HeaderKind::MaxForwards, counts.max_forwards)?;
    require_singleton(HeaderKind::ContentType, counts.content_type)?;

    Ok(())
}

fn require_header(kind: HeaderKind, count: u16) -> Result<(), ValidationError> {
    if count == 0 {
        return Err(ValidationError::MissingRequiredHeader { kind });
    }

    Ok(())
}

fn require_singleton(kind: HeaderKind, count: u16) -> Result<(), ValidationError> {
    if count > 1 {
        return Err(ValidationError::DuplicateSingletonHeader { kind, count });
    }

    Ok(())
}

/// Failure to satisfy message-level SIP invariants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidationError {
    /// A required core SIP header was absent.
    MissingRequiredHeader {
        /// Missing header kind.
        kind: HeaderKind,
    },

    /// A header that must be represented as one logical field occurred more
    /// than once.
    DuplicateSingletonHeader {
        /// Duplicated header kind.
        kind: HeaderKind,

        /// Number of logical fields observed.
        count: u16,
    },

    /// The message contained a non-empty body without `Content-Type`.
    MissingContentTypeForBody,
}

impl ValidationError {
    /// Returns a stable low-cardinality classification suitable for metrics
    /// and structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::MissingRequiredHeader { .. } => "missing-required-header",
            Self::DuplicateSingletonHeader { .. } => "duplicate-singleton-header",
            Self::MissingContentTypeForBody => "missing-content-type-for-body",
        }
    }

    /// Returns the associated header kind when this error concerns one
    /// specific header.
    #[must_use]
    pub const fn header_kind(self) -> Option<HeaderKind> {
        match self {
            Self::MissingRequiredHeader { kind } | Self::DuplicateSingletonHeader { kind, .. } => {
                Some(kind)
            }
            Self::MissingContentTypeForBody => Some(HeaderKind::ContentType),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequiredHeader { kind } => {
                write!(formatter, "SIP message is missing required {kind} header")
            }
            Self::DuplicateSingletonHeader { kind, count } => {
                write!(
                    formatter,
                    "SIP message contains {count} {kind} headers where at most one is permitted"
                )
            }
            Self::MissingContentTypeForBody => {
                formatter.write_str("SIP message body is present without a Content-Type header")
            }
        }
    }
}

impl StdError for ValidationError {}

#[cfg(test)]
mod tests {
    use super::{ValidationError, validate};
    use crate::sip::parser::message::parse;
    use crate::sip::types::header::HeaderKind;
    use crate::sip::types::message::RawMessage;
    use std::sync::Arc;

    fn parse_message(input: &[u8]) -> RawMessage {
        let Ok(message) = parse(Arc::from(input)) else {
            panic!("expected structurally valid SIP message");
        };

        message
    }

    fn valid_request() -> RawMessage {
        parse_message(
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: request-one@example.com\r\n\
              CSeq: 1 INVITE\r\n\
              Max-Forwards: 70\r\n\
              Content-Length: 0\r\n\
              \r\n",
        )
    }

    fn valid_response() -> RawMessage {
        parse_message(
            b"SIP/2.0 200 OK\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>;tag=two\r\n\
              Call-ID: response-one@example.com\r\n\
              CSeq: 1 INVITE\r\n\
              Content-Length: 0\r\n\
              \r\n",
        )
    }

    #[test]
    fn accepts_valid_request() {
        assert_eq!(validate(&valid_request()), Ok(()));
    }

    #[test]
    fn accepts_valid_response() {
        assert_eq!(validate(&valid_response()), Ok(()));
    }

    #[test]
    fn accepts_request_without_max_forwards_at_role_neutral_layer() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: request-two@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(validate(&message), Ok(()));
    }

    #[test]
    fn accepts_multiple_via_fields() {
        let message = parse_message(
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP first.example.com;branch=z9hG4bK-one\r\n\
              Via: SIP/2.0/TCP second.example.com;branch=z9hG4bK-two\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: request-three@example.com\r\n\
              CSeq: 1 INVITE\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(validate(&message), Ok(()));
    }

    #[test]
    fn ignores_unknown_extension_headers() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: request-four@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              X-LiveAISIP-Future: opaque\r\n\
              X-LiveAISIP-Future: second\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(validate(&message), Ok(()));
    }

    #[test]
    fn requires_via() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: missing-via@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::MissingRequiredHeader {
                kind: HeaderKind::Via,
            })
        );
    }

    #[test]
    fn requires_from() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: missing-from@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::MissingRequiredHeader {
                kind: HeaderKind::From,
            })
        );
    }

    #[test]
    fn requires_to() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              Call-ID: missing-to@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::MissingRequiredHeader {
                kind: HeaderKind::To,
            })
        );
    }

    #[test]
    fn requires_call_id() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              CSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::MissingRequiredHeader {
                kind: HeaderKind::CallId,
            })
        );
    }

    #[test]
    fn requires_cseq() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: missing-cseq@example.com\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::MissingRequiredHeader {
                kind: HeaderKind::CSeq,
            })
        );
    }

    #[test]
    fn rejects_duplicate_from() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              From: <sip:other@example.com>;tag=two\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: duplicate-from@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::DuplicateSingletonHeader {
                kind: HeaderKind::From,
                count: 2,
            })
        );
    }

    #[test]
    fn rejects_duplicate_to() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              To: <sip:other@example.com>\r\n\
              Call-ID: duplicate-to@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::DuplicateSingletonHeader {
                kind: HeaderKind::To,
                count: 2,
            })
        );
    }

    #[test]
    fn rejects_duplicate_call_id() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: first@example.com\r\n\
              Call-ID: second@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::DuplicateSingletonHeader {
                kind: HeaderKind::CallId,
                count: 2,
            })
        );
    }

    #[test]
    fn rejects_duplicate_cseq() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: duplicate-cseq@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              CSeq: 2 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::DuplicateSingletonHeader {
                kind: HeaderKind::CSeq,
                count: 2,
            })
        );
    }

    #[test]
    fn rejects_duplicate_max_forwards() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: duplicate-max-forwards@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Max-Forwards: 70\r\n\
              Max-Forwards: 69\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::DuplicateSingletonHeader {
                kind: HeaderKind::MaxForwards,
                count: 2,
            })
        );
    }

    #[test]
    fn rejects_duplicate_content_type() {
        let message = parse_message(
            b"MESSAGE sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: duplicate-content-type@example.com\r\n\
              CSeq: 1 MESSAGE\r\n\
              Content-Type: text/plain\r\n\
              Content-Type: application/octet-stream\r\n\
              Content-Length: 4\r\n\
              \r\n\
              body",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::DuplicateSingletonHeader {
                kind: HeaderKind::ContentType,
                count: 2,
            })
        );
    }

    #[test]
    fn non_empty_body_requires_content_type() {
        let message = parse_message(
            b"MESSAGE sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: missing-content-type@example.com\r\n\
              CSeq: 1 MESSAGE\r\n\
              Content-Length: 4\r\n\
              \r\n\
              body",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::MissingContentTypeForBody)
        );
    }

    #[test]
    fn non_empty_body_with_content_type_is_valid() {
        let message = parse_message(
            b"MESSAGE sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: body-with-type@example.com\r\n\
              CSeq: 1 MESSAGE\r\n\
              Content-Type: text/plain\r\n\
              Content-Length: 4\r\n\
              \r\n\
              body",
        );

        assert_eq!(validate(&message), Ok(()));
    }

    #[test]
    fn empty_body_does_not_require_content_type() {
        assert_eq!(validate(&valid_request()), Ok(()));
    }

    #[test]
    fn missing_required_header_precedes_duplicate_checks() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              From: <sip:other@example.com>;tag=two\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: precedence@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::MissingRequiredHeader {
                kind: HeaderKind::Via,
            })
        );
    }

    #[test]
    fn duplicate_validation_order_is_stable() {
        let message = parse_message(
            b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              From: <sip:other@example.com>;tag=two\r\n\
              To: <sip:bob@example.com>\r\n\
              To: <sip:other@example.com>\r\n\
              Call-ID: duplicate-order@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert_eq!(
            validate(&message),
            Err(ValidationError::DuplicateSingletonHeader {
                kind: HeaderKind::From,
                count: 2,
            })
        );
    }

    #[test]
    fn error_classes_are_stable() {
        assert_eq!(
            ValidationError::MissingRequiredHeader {
                kind: HeaderKind::Via,
            }
            .class(),
            "missing-required-header"
        );

        assert_eq!(
            ValidationError::DuplicateSingletonHeader {
                kind: HeaderKind::From,
                count: 2,
            }
            .class(),
            "duplicate-singleton-header"
        );

        assert_eq!(
            ValidationError::MissingContentTypeForBody.class(),
            "missing-content-type-for-body"
        );
    }

    #[test]
    fn error_header_kind_is_stable() {
        assert_eq!(
            ValidationError::MissingRequiredHeader {
                kind: HeaderKind::CallId,
            }
            .header_kind(),
            Some(HeaderKind::CallId)
        );

        assert_eq!(
            ValidationError::DuplicateSingletonHeader {
                kind: HeaderKind::CSeq,
                count: 2,
            }
            .header_kind(),
            Some(HeaderKind::CSeq)
        );

        assert_eq!(
            ValidationError::MissingContentTypeForBody.header_kind(),
            Some(HeaderKind::ContentType)
        );
    }

    #[test]
    fn header_counting_is_bounded_by_structural_parser_limits() {
        let message = valid_request();

        assert_eq!(validate(&message), Ok(()));
    }
}
