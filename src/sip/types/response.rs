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

//! Immutable canonical outbound SIP response.
//!
//! [`Response`](crate::sip::types::response::Response) is the finished value produced by the bounded response
//! builder. It is distinct from the lossless untrusted wire representation and
//! from the validated inbound response envelope. Private fields and a single
//! builder-owned construction path preserve required header, singleton,
//! reason-phrase, body, and framing invariants.
//!
//! The informational reason phrase remains byte-oriented and never appears in
//! diagnostics. `Content-Length` is deliberately absent from retained headers;
//! canonical serialization derives it from the immutable body every time.

use std::fmt;

use crate::sip::serializer::message::{self, SerializeError};

use super::header::{Header, HeaderKind, HeaderValue};
use super::status::StatusCode;
use super::version::Version;

/// A completed immutable outbound SIP response.
pub struct Response {
    version: Version,
    status: StatusCode,
    reason_phrase: HeaderValue,
    headers: Vec<Header>,
    body: Vec<u8>,
}

impl Response {
    /// Creates a response from parts already admitted by `ResponseBuilder`.
    ///
    /// This remains crate-private so external callers cannot bypass builder
    /// ownership of transaction-critical headers, the reason phrase, body
    /// bounds, or `Content-Length` exclusion.
    pub(crate) fn from_builder_parts(
        status: StatusCode,
        reason_phrase: HeaderValue,
        headers: Vec<Header>,
        body: Vec<u8>,
    ) -> Self {
        debug_assert!(
            !headers
                .iter()
                .any(|header| header.name().kind() == Some(HeaderKind::ContentLength))
        );
        Self {
            version: Version::Sip2,
            status,
            reason_phrase,
            headers,
            body,
        }
    }

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

    /// Returns the informational reason-phrase bytes.
    ///
    /// Protocol decisions must use [`Self::status`] rather than this phrase.
    #[must_use]
    pub fn reason_phrase(&self) -> &[u8] {
        self.reason_phrase.as_bytes()
    }

    /// Returns ordered caller-supplied headers.
    ///
    /// `Content-Length` is absent because serialization owns it.
    #[must_use]
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// Returns the first header with this recognized kind.
    #[must_use]
    pub fn header(&self, kind: HeaderKind) -> Option<&Header> {
        self.headers
            .iter()
            .find(|header| header.name().kind() == Some(kind))
    }

    /// Counts physical header fields with this recognized kind.
    #[must_use]
    pub fn header_count(&self, kind: HeaderKind) -> usize {
        self.headers
            .iter()
            .filter(|header| header.name().kind() == Some(kind))
            .count()
    }

    /// Returns the immutable response body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Serializes the response with authoritative `Content-Length`.
    ///
    /// # Errors
    ///
    /// Preserves bounded canonical serializer failures.
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        message::serialize_response(
            self.version,
            self.status,
            self.reason_phrase.as_bytes(),
            &self.headers,
            &self.body,
        )
    }

    /// Consumes the response into its owned components.
    #[must_use]
    pub fn into_parts(self) -> (Version, StatusCode, HeaderValue, Vec<Header>, Vec<u8>) {
        (
            self.version,
            self.status,
            self.reason_phrase,
            self.headers,
            self.body,
        )
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Response")
            .field("version", &self.version)
            .field("status", &self.status.as_u16())
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::sip::builder::response::ResponseBuilder;
    use crate::sip::headers::call_id::CallId;
    use crate::sip::headers::content_type::ContentType;
    use crate::sip::headers::cseq::CSeq;
    use crate::sip::headers::from::FromHeader;
    use crate::sip::headers::to::ToHeader;
    use crate::sip::headers::via::Via;
    use crate::sip::parser::message;
    use crate::sip::types::header::HeaderKind;
    use crate::sip::types::method::Method;
    use crate::sip::types::status::StatusCode;
    use crate::sip::types::version::Version;
    use crate::sip::validation;

    fn builder(status: StatusCode, reason: &[u8]) -> ResponseBuilder {
        let via = Via::from_bytes(b"SIP/2.0/UDP runtime.example.com;branch=z9hG4bK-response")
            .unwrap_or_else(|_| panic!("Via"));
        let from = FromHeader::from_bytes(b"<sip:runtime@example.com>;tag=local")
            .unwrap_or_else(|_| panic!("From"));
        let to = ToHeader::from_bytes(b"<sip:callee@example.net>;tag=remote")
            .unwrap_or_else(|_| panic!("To"));
        let call_id =
            CallId::new("response-secret@example.com").unwrap_or_else(|_| panic!("Call-ID"));
        let cseq = CSeq::new(1, Method::Invite).unwrap_or_else(|_| panic!("CSeq"));
        ResponseBuilder::new(status, reason, &via, &from, &to, &call_id, &cseq)
            .unwrap_or_else(|_| panic!("builder"))
    }

    #[test]
    fn finished_response_is_immutable_and_exposes_bounded_parts() {
        let response = builder(StatusCode::OK, b"OK").build();
        assert_eq!(response.version(), Version::Sip2);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.reason_phrase(), b"OK");
        assert_eq!(response.headers().len(), 5);
        assert_eq!(response.header_count(HeaderKind::Via), 1);
        assert!(response.header(HeaderKind::CallId).is_some());
        assert!(response.header(HeaderKind::ContentLength).is_none());
        assert!(response.body().is_empty());
    }

    #[test]
    fn empty_reason_phrase_serializes_and_revalidates() {
        let response = builder(StatusCode::TRYING, b"").build();
        let bytes = response.serialize().unwrap_or_else(|_| panic!("serialize"));
        assert!(bytes.starts_with(b"SIP/2.0 100 \r\n"));
        let raw = message::parse(Arc::from(bytes)).unwrap_or_else(|_| panic!("parse"));
        assert!(validation::response::validate(raw).is_ok());
    }

    #[test]
    fn body_serialization_owns_content_length() {
        let content_type =
            ContentType::from_bytes(b"application/sdp").unwrap_or_else(|_| panic!("Content-Type"));
        let response = builder(StatusCode::OK, b"OK")
            .with_body(&content_type, b"v=0\r\n")
            .unwrap_or_else(|_| panic!("body"))
            .build();
        let bytes = response.serialize().unwrap_or_else(|_| panic!("serialize"));
        assert!(
            bytes
                .windows(19)
                .any(|value| value == b"Content-Length: 5\r\n")
        );
        let raw = message::parse(Arc::from(bytes)).unwrap_or_else(|_| panic!("parse"));
        assert!(validation::response::validate(raw).is_ok());
    }

    #[test]
    fn consuming_parts_preserves_header_order_and_body() {
        let content_type =
            ContentType::from_bytes(b"application/sdp").unwrap_or_else(|_| panic!("Content-Type"));
        let response = builder(StatusCode::OK, b"Private phrase")
            .with_body(&content_type, b"v=0\r\n")
            .unwrap_or_else(|_| panic!("body"))
            .build();
        let (version, status, reason, headers, body) = response.into_parts();
        assert_eq!(version, Version::Sip2);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reason.as_bytes(), b"Private phrase");
        assert_eq!(headers[0].name().kind(), Some(HeaderKind::Via));
        assert_eq!(body, b"v=0\r\n");
    }

    #[test]
    fn debug_redacts_reason_headers_and_body() {
        let response = builder(StatusCode::BUSY_HERE, b"Sensitive Private Phrase").build();
        let debug = format!("{response:?}");
        assert!(debug.contains("486"));
        assert!(!debug.contains("Sensitive"));
        assert!(!debug.contains("response-secret"));
        assert!(!debug.contains("runtime.example.com"));
    }
}
