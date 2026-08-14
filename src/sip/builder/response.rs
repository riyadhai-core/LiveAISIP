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

//! Safe SIP response construction.
//!
//! The Runtime initiates calls but established dialogs can deliver inbound
//! requests. This builder creates bounded responses while protecting Via,
//! From, To, Call-ID, CSeq, `Content-Type`, and `Content-Length` ownership.
//! Transaction matching, To-tag creation, routing, and method-specific policy
//! remain responsibilities of later transaction and dialog layers.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::framing::MAX_BODY_BYTES;
use crate::sip::headers::call_id::CallId;
use crate::sip::headers::content_type::ContentType;
use crate::sip::headers::cseq::CSeq;
use crate::sip::headers::from::FromHeader;
use crate::sip::headers::to::ToHeader;
use crate::sip::headers::via::Via;
use crate::sip::serializer::message::{self, SerializeError};
use crate::sip::types::header::{Header, HeaderKind, HeaderValue, HeaderValueError};
use crate::sip::types::response::Response;
use crate::sip::types::status::StatusCode;
use crate::sip::types::version::Version;

use super::headers::{BuildError as HeaderBuildError, HeaderList};

/// A bounded SIP response under construction.
pub struct ResponseBuilder {
    status: StatusCode,
    reason_phrase: HeaderValue,
    headers: HeaderList,
    body: Vec<u8>,
}

impl ResponseBuilder {
    /// Creates a response with all transaction-critical response fields.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe reason phrase or when a typed core field
    /// cannot be assembled within configured bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        status: StatusCode,
        reason_phrase: &[u8],
        via: &Via,
        from: &FromHeader,
        to: &ToHeader,
        call_id: &CallId,
        cseq: &CSeq,
    ) -> Result<Self, BuildError> {
        let reason_phrase =
            HeaderValue::from_bytes(reason_phrase).map_err(BuildError::InvalidReasonPhrase)?;
        let mut headers = HeaderList::new();
        headers.push_typed(HeaderKind::Via, via)?;
        headers.push_typed(HeaderKind::From, from)?;
        headers.push_typed(HeaderKind::To, to)?;
        headers.push_typed(HeaderKind::CallId, call_id)?;
        headers.push_typed(HeaderKind::CSeq, cseq)?;
        Ok(Self {
            status,
            reason_phrase,
            headers,
            body: Vec::new(),
        })
    }

    /// Appends one non-core extension or optional field.
    ///
    /// # Errors
    ///
    /// Rejects builder-owned fields and bounded collection failures.
    pub fn push_header(&mut self, header: Header) -> Result<(), BuildError> {
        if let Some(kind) = header.name().kind()
            && is_reserved(kind)
        {
            return Err(BuildError::ReservedHeader { kind });
        }
        self.headers.push(header).map_err(BuildError::Headers)
    }

    /// Formats and appends one recognized optional field.
    ///
    /// # Errors
    ///
    /// Rejects builder-owned fields and bounded formatting failures.
    pub fn push_typed<T>(&mut self, kind: HeaderKind, value: &T) -> Result<(), BuildError>
    where
        T: fmt::Display + ?Sized,
    {
        if is_reserved(kind) {
            return Err(BuildError::ReservedHeader { kind });
        }
        self.headers
            .push_typed(kind, value)
            .map_err(BuildError::Headers)
    }

    /// Adds a bounded body and `Content-Type` atomically.
    ///
    /// # Errors
    ///
    /// Rejects repeated bodies, oversized bodies, and bounded allocation or
    /// header-formatting failures.
    pub fn with_body(
        mut self,
        content_type: &ContentType,
        body: &[u8],
    ) -> Result<Self, BuildError> {
        if self.headers.contains(HeaderKind::ContentType) || !self.body.is_empty() {
            return Err(BuildError::BodyAlreadySet);
        }
        if body.len() > MAX_BODY_BYTES {
            return Err(BuildError::BodyTooLarge {
                attempted: body.len(),
                maximum: MAX_BODY_BYTES,
            });
        }
        self.headers
            .push_typed(HeaderKind::ContentType, content_type)?;
        self.body
            .try_reserve_exact(body.len())
            .map_err(|_| BuildError::AllocationFailed)?;
        self.body.extend_from_slice(body);
        Ok(self)
    }

    /// Returns the status code.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the informational reason phrase.
    #[must_use]
    pub fn reason_phrase(&self) -> &[u8] {
        self.reason_phrase.as_bytes()
    }

    /// Returns ordered response fields.
    #[must_use]
    pub fn headers(&self) -> &[Header] {
        self.headers.as_slice()
    }

    /// Returns response body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Finishes construction as an immutable canonical response.
    ///
    /// Existing reason-phrase, header, and body storage is moved without
    /// copying or allocating.
    #[must_use]
    pub fn build(self) -> Response {
        Response::from_builder_parts(
            self.status,
            self.reason_phrase,
            self.headers.into_vec(),
            self.body,
        )
    }

    /// Serializes the response with authoritative `Content-Length`.
    ///
    /// # Errors
    ///
    /// Propagates bounded serialization failures.
    pub fn serialize(&self) -> Result<Vec<u8>, BuildError> {
        message::serialize_response(
            Version::Sip2,
            self.status,
            self.reason_phrase.as_bytes(),
            self.headers.as_slice(),
            &self.body,
        )
        .map_err(BuildError::Serialize)
    }
}

impl fmt::Debug for ResponseBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseBuilder")
            .field("status", &self.status.as_u16())
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

const fn is_reserved(kind: HeaderKind) -> bool {
    matches!(
        kind,
        HeaderKind::Via
            | HeaderKind::From
            | HeaderKind::To
            | HeaderKind::CallId
            | HeaderKind::CSeq
            | HeaderKind::ContentLength
            | HeaderKind::ContentType
    )
}

/// Failure to construct or serialize a SIP response.
#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    /// The reason phrase contained prohibited bytes.
    InvalidReasonPhrase(HeaderValueError),
    /// A caller attempted to replace a builder-owned field.
    ReservedHeader {
        /// Reserved field kind.
        kind: HeaderKind,
    },
    /// A body had already been installed.
    BodyAlreadySet,
    /// The body exceeded its framing bound.
    BodyTooLarge {
        /// Attempted byte length.
        attempted: usize,
        /// Maximum byte length.
        maximum: usize,
    },
    /// Header assembly failed.
    Headers(HeaderBuildError),
    /// Wire serialization failed.
    Serialize(SerializeError),
    /// Bounded body allocation failed.
    AllocationFailed,
}

impl From<HeaderBuildError> for BuildError {
    fn from(error: HeaderBuildError) -> Self {
        Self::Headers(error)
    }
}

impl BuildError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::InvalidReasonPhrase(_) => "invalid-reason-phrase",
            Self::ReservedHeader { .. } => "reserved-header",
            Self::BodyAlreadySet => "body-already-set",
            Self::BodyTooLarge { .. } => "body-too-large",
            Self::Headers(_) => "invalid-headers",
            Self::Serialize(_) => "serialization-failed",
            Self::AllocationFailed => "allocation-failed",
        }
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReasonPhrase(error) => {
                write!(formatter, "invalid SIP response reason phrase: {error}")
            }
            Self::ReservedHeader { kind } => {
                write!(formatter, "{kind} is owned by the SIP response builder")
            }
            Self::BodyAlreadySet => formatter.write_str("response body is already set"),
            Self::BodyTooLarge { attempted, maximum } => {
                write!(
                    formatter,
                    "response body {attempted} exceeds maximum {maximum}"
                )
            }
            Self::Headers(error) => write!(formatter, "response header build failed: {error}"),
            Self::Serialize(error) => write!(formatter, "response serialization failed: {error}"),
            Self::AllocationFailed => formatter.write_str("bounded response allocation failed"),
        }
    }
}

impl StdError for BuildError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidReasonPhrase(error) => Some(error),
            Self::Headers(error) => Some(error),
            Self::Serialize(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::sip::headers::call_id::CallId;
    use crate::sip::headers::content_type::ContentType;
    use crate::sip::headers::cseq::CSeq;
    use crate::sip::headers::from::FromHeader;
    use crate::sip::headers::to::ToHeader;
    use crate::sip::headers::via::Via;
    use crate::sip::parser::message::parse;
    use crate::sip::types::header::{Header, HeaderKind, HeaderName, HeaderValue};
    use crate::sip::types::method::Method;
    use crate::sip::types::status::StatusCode;
    use crate::sip::validation;

    use super::{BuildError, ResponseBuilder};

    fn builder(status: StatusCode, reason: &[u8]) -> Result<ResponseBuilder, BuildError> {
        let Ok(via) = Via::from_bytes(b"SIP/2.0/UDP runtime.example.com;branch=z9hG4bK-one") else {
            panic!("valid Via");
        };
        let Ok(from) = FromHeader::from_bytes(b"<sip:runtime@example.com>;tag=local") else {
            panic!("valid From");
        };
        let Ok(to) = ToHeader::from_bytes(b"<sip:service@example.com>;tag=remote") else {
            panic!("valid To");
        };
        let Ok(call_id) = CallId::from_bytes(b"private-call-id@example.com") else {
            panic!("valid Call-ID");
        };
        let Ok(cseq) = CSeq::new(1, Method::Invite) else {
            panic!("valid CSeq");
        };
        ResponseBuilder::new(status, reason, &via, &from, &to, &call_id, &cseq)
    }

    #[test]
    fn round_trips_through_response_validation() {
        let Ok(builder) = builder(StatusCode::OK, b"OK") else {
            panic!("valid builder");
        };
        let Ok(bytes) = builder.serialize() else {
            panic!("serialize");
        };
        let Ok(raw) = parse(Arc::from(bytes)) else {
            panic!("parse");
        };
        assert!(validation::response::validate(raw).is_ok());
    }

    #[test]
    fn empty_reason_is_valid_and_injection_is_rejected() {
        let Ok(response) = builder(StatusCode::TRYING, b"") else {
            panic!("valid builder");
        };
        assert!(response.reason_phrase().is_empty());
        assert!(matches!(
            builder(StatusCode::OK, b"OK\r\nInjected: yes"),
            Err(BuildError::InvalidReasonPhrase(_))
        ));
    }

    #[test]
    fn reserved_fields_cannot_be_added() {
        let Ok(mut builder) = builder(StatusCode::OK, b"OK") else {
            panic!("valid builder");
        };
        let Ok(value) = HeaderValue::from_bytes(b"2 INVITE") else {
            panic!("valid value");
        };
        let header = Header::new(HeaderName::known(HeaderKind::CSeq), value);
        assert!(matches!(
            builder.push_header(header),
            Err(BuildError::ReservedHeader {
                kind: HeaderKind::CSeq
            })
        ));
    }

    #[test]
    fn body_and_content_type_are_coupled() {
        let Ok(builder) = builder(StatusCode::OK, b"OK") else {
            panic!("valid builder");
        };
        let Ok(content_type) = ContentType::from_bytes(b"application/sdp") else {
            panic!("valid type");
        };
        let Ok(builder) = builder.with_body(&content_type, b"v=0\r\n") else {
            panic!("valid body");
        };
        assert_eq!(builder.body(), b"v=0\r\n");
        assert!(builder.serialize().is_ok());
    }

    #[test]
    fn optional_fields_work_and_debug_is_redacted() {
        let Ok(mut builder) = builder(StatusCode::BUSY_HERE, b"Sensitive Private Phrase") else {
            panic!("valid builder");
        };
        assert!(builder.push_typed(HeaderKind::Supported, &"timer").is_ok());
        assert_eq!(builder.headers().len(), 6);
        let debug = format!("{builder:?}");
        assert!(!debug.contains("Sensitive Private Phrase"));
        assert!(!debug.contains("private-call-id"));
        assert!(!debug.contains("runtime.example.com"));
    }
}
