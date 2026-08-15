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

//! Immutable canonical outbound SIP request.
//!
//! [`Request`](crate::sip::types::request::Request) is the finished value produced
//! by the bounded request builder.
//! It is deliberately distinct from
//! [`RawMessage`](crate::sip::types::message::RawMessage), which losslessly
//! represents untrusted received wire bytes, and from
//! [`ValidatedRequest`](crate::sip::validation::request::ValidatedRequest),
//! which proves that a structurally parsed wire message satisfies request-wide
//! semantic rules.
//!
//! A request owns already-validated typed start-line components, an ordered
//! bounded header collection, and an immutable body. Its fields are private
//! and its only construction path is the invariant-enforcing outbound builder.
//! `Content-Length` is never retained here: serialization computes it from the
//! body every time, preventing stale framing metadata.

use std::fmt;

use crate::sip::serializer::message::{self, SerializeError};

use super::header::{Header, HeaderKind};
use super::method::Method;
use super::uri::Uri;
use super::version::Version;

/// A completed immutable outbound SIP request.
pub struct Request {
    method: Method,
    uri: Uri,
    version: Version,
    headers: Vec<Header>,
    body: Vec<u8>,
}

impl Request {
    /// Creates a request from parts already admitted by `RequestBuilder`.
    ///
    /// This remains crate-private so callers cannot bypass builder ownership of
    /// required core headers, singleton rules, `CSeq` matching, body bounds, and
    /// Content-Length exclusion.
    pub(crate) fn from_builder_parts(
        method: Method,
        uri: Uri,
        headers: Vec<Header>,
        body: Vec<u8>,
    ) -> Self {
        debug_assert!(
            !headers
                .iter()
                .any(|header| header.name().kind() == Some(HeaderKind::ContentLength))
        );
        Self {
            method,
            uri,
            version: Version::Sip2,
            headers,
            body,
        }
    }

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

    /// Returns the immutable body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Serializes the complete request with authoritative `Content-Length`.
    ///
    /// # Errors
    ///
    /// Preserves bounded canonical serializer failures.
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        message::serialize_request(
            &self.method,
            &self.uri,
            self.version,
            &self.headers,
            &self.body,
        )
    }

    /// Consumes the request into its owned components.
    #[must_use]
    pub fn into_parts(self) -> (Method, Uri, Version, Vec<Header>, Vec<u8>) {
        (self.method, self.uri, self.version, self.headers, self.body)
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Request")
            .field("version", &self.version)
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::sip::builder::request::RequestBuilder;
    use crate::sip::headers::call_id::CallId;
    use crate::sip::headers::content_type::ContentType;
    use crate::sip::headers::cseq::CSeq;
    use crate::sip::headers::from::FromHeader;
    use crate::sip::headers::max_forwards::MaxForwards;
    use crate::sip::headers::to::ToHeader;
    use crate::sip::headers::via::Via;
    use crate::sip::parser::{message, uri};
    use crate::sip::types::header::HeaderKind;
    use crate::sip::types::method::Method;
    use crate::sip::types::version::Version;
    use crate::sip::validation;

    fn builder() -> RequestBuilder {
        let via = Via::from_bytes(b"SIP/2.0/UDP runtime.example.com;branch=z9hG4bK-request")
            .unwrap_or_else(|_| panic!("Via"));
        let from = FromHeader::from_bytes(b"<sip:runtime@example.com>;tag=local")
            .unwrap_or_else(|_| panic!("From"));
        let to = ToHeader::from_bytes(b"<sip:callee@example.net>").unwrap_or_else(|_| panic!("To"));
        let call_id =
            CallId::new("request-secret@example.com").unwrap_or_else(|_| panic!("Call-ID"));
        let cseq = CSeq::new(1, Method::Invite).unwrap_or_else(|_| panic!("CSeq"));
        let target = uri::parse(b"sip:callee@example.net").unwrap_or_else(|_| panic!("URI"));
        RequestBuilder::new(
            Method::Invite,
            target,
            &via,
            &from,
            &to,
            &call_id,
            &cseq,
            MaxForwards::new(70),
        )
        .unwrap_or_else(|_| panic!("builder"))
    }

    #[test]
    fn finished_request_is_immutable_and_exposes_bounded_parts() {
        let request = builder().build();
        assert_eq!(request.method(), &Method::Invite);
        assert_eq!(request.version(), Version::Sip2);
        assert_eq!(request.headers().len(), 6);
        assert_eq!(request.header_count(HeaderKind::Via), 1);
        assert!(request.header(HeaderKind::CallId).is_some());
        assert!(request.header(HeaderKind::ContentLength).is_none());
        assert!(request.body().is_empty());
    }

    #[test]
    fn serialization_inserts_authoritative_length_and_revalidates() {
        let content_type =
            ContentType::from_bytes(b"application/sdp").unwrap_or_else(|_| panic!("Content-Type"));
        let request = builder()
            .with_body(&content_type, b"v=0\r\n")
            .unwrap_or_else(|_| panic!("body"))
            .build();
        let bytes = request.serialize().unwrap_or_else(|_| panic!("serialize"));
        assert!(
            bytes
                .windows(19)
                .any(|value| value == b"Content-Length: 5\r\n")
        );
        let raw = message::parse(Arc::from(bytes)).unwrap_or_else(|_| panic!("parse"));
        assert!(validation::request::validate(raw).is_ok());
    }

    #[test]
    fn consuming_parts_preserves_order_and_body() {
        let content_type =
            ContentType::from_bytes(b"application/sdp").unwrap_or_else(|_| panic!("Content-Type"));
        let request = builder()
            .with_body(&content_type, b"v=0\r\n")
            .unwrap_or_else(|_| panic!("body"))
            .build();
        let (method, _uri, version, headers, body) = request.into_parts();
        assert_eq!(method, Method::Invite);
        assert_eq!(version, Version::Sip2);
        assert_eq!(headers[0].name().kind(), Some(HeaderKind::Via));
        assert_eq!(body.as_slice(), b"v=0\r\n");
    }

    #[test]
    fn debug_redacts_method_uri_headers_and_body() {
        let request = builder().build();
        let debug = format!("{request:?}");
        assert!(!debug.contains("INVITE"));
        assert!(!debug.contains("callee"));
        assert!(!debug.contains("request-secret"));
        assert!(debug.contains("header_count"));
    }
}
