// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Safe construction of outbound SIP requests.
//!
//! Every request is born with the transaction-critical fields required by the
//! Runtime UAC. Core fields, Content-Type, and Content-Length cannot be added
//! again through the extension API.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::framing::MAX_BODY_BYTES;
use crate::sip::headers::call_id::CallId;
use crate::sip::headers::content_type::ContentType;
use crate::sip::headers::cseq::CSeq;
use crate::sip::headers::from::FromHeader;
use crate::sip::headers::max_forwards::MaxForwards;
use crate::sip::headers::to::ToHeader;
use crate::sip::headers::via::Via;
use crate::sip::serializer::message::{self, SerializeError};
use crate::sip::types::header::{Header, HeaderKind};
use crate::sip::types::method::Method;
use crate::sip::types::uri::Uri;
use crate::sip::types::version::Version;

use super::headers::{BuildError as HeaderBuildError, HeaderList};

/// A bounded outbound SIP request under construction.
pub struct RequestBuilder {
    method: Method,
    uri: Uri,
    headers: HeaderList,
    body: Vec<u8>,
}

impl RequestBuilder {
    /// Creates a request with every required UAC core field.
    ///
    /// # Errors
    ///
    /// Returns an error when `CSeq` does not match the request method or a typed
    /// core value cannot be assembled within the header bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        method: Method,
        uri: Uri,
        via: &Via,
        from: &FromHeader,
        to: &ToHeader,
        call_id: &CallId,
        cseq: &CSeq,
        max_forwards: MaxForwards,
    ) -> Result<Self, BuildError> {
        if &method != cseq.method() {
            return Err(BuildError::CSeqMethodMismatch);
        }

        let mut headers = HeaderList::new();
        headers.push_typed(HeaderKind::Via, via)?;
        headers.push_typed(HeaderKind::From, from)?;
        headers.push_typed(HeaderKind::To, to)?;
        headers.push_typed(HeaderKind::CallId, call_id)?;
        headers.push_typed(HeaderKind::CSeq, cseq)?;
        headers.push_typed(HeaderKind::MaxForwards, &max_forwards)?;

        Ok(Self {
            method,
            uri,
            headers,
            body: Vec::new(),
        })
    }

    /// Appends one non-core extension or optional field.
    ///
    /// # Errors
    ///
    /// Rejects fields owned by request invariants and propagates bounded
    /// header-collection failures.
    pub fn push_header(&mut self, header: Header) -> Result<(), BuildError> {
        if let Some(kind) = header.name().kind()
            && is_reserved(kind)
        {
            return Err(BuildError::ReservedHeader { kind });
        }
        self.headers.push(header).map_err(BuildError::Headers)
    }

    /// Formats and appends a recognized optional typed field.
    ///
    /// # Errors
    ///
    /// Returns an error for a reserved request field or bounded formatting and
    /// collection failure.
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

    /// Adds a bounded body and its required Content-Type as one consuming
    /// operation.
    ///
    /// # Errors
    ///
    /// Returns an error if a body was already set, the body exceeds the
    /// framing bound, allocation fails, or Content-Type cannot be formatted.
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

    /// Returns the ordered outbound headers.
    #[must_use]
    pub fn headers(&self) -> &[Header] {
        self.headers.as_slice()
    }

    /// Returns the body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Serializes the complete request with authoritative Content-Length.
    ///
    /// # Errors
    ///
    /// Propagates bounded SIP serialization failures.
    pub fn serialize(&self) -> Result<Vec<u8>, BuildError> {
        message::serialize_request(
            &self.method,
            &self.uri,
            Version::Sip2,
            self.headers.as_slice(),
            &self.body,
        )
        .map_err(BuildError::Serialize)
    }
}

impl fmt::Debug for RequestBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBuilder")
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
            | HeaderKind::MaxForwards
            | HeaderKind::ContentLength
            | HeaderKind::ContentType
    )
}

/// Failure to construct or serialize an outbound request.
#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    /// Request-line and `CSeq` methods differed.
    CSeqMethodMismatch,
    /// A caller attempted to replace a builder-owned field.
    ReservedHeader {
        /// Reserved field kind.
        kind: HeaderKind,
    },
    /// A body or Content-Type had already been installed.
    BodyAlreadySet,
    /// The requested body exceeded the framing bound.
    BodyTooLarge {
        /// Attempted body length.
        attempted: usize,
        /// Maximum body length.
        maximum: usize,
    },
    /// Header assembly failed.
    Headers(HeaderBuildError),
    /// Complete wire serialization failed.
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
    /// Returns a stable low-cardinality class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::CSeqMethodMismatch => "cseq-method-mismatch",
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
            Self::CSeqMethodMismatch => {
                formatter.write_str("request method does not match CSeq method")
            }
            Self::ReservedHeader { kind } => {
                write!(formatter, "{kind} is owned by the SIP request builder")
            }
            Self::BodyAlreadySet => formatter.write_str("request body is already set"),
            Self::BodyTooLarge { attempted, maximum } => {
                write!(
                    formatter,
                    "request body {attempted} exceeds maximum {maximum}"
                )
            }
            Self::Headers(error) => write!(formatter, "request header build failed: {error}"),
            Self::Serialize(error) => write!(formatter, "request serialization failed: {error}"),
            Self::AllocationFailed => formatter.write_str("bounded request allocation failed"),
        }
    }
}

impl StdError for BuildError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Headers(error) => Some(error),
            Self::Serialize(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::sip::framing::MAX_BODY_BYTES;
    use crate::sip::headers::call_id::CallId;
    use crate::sip::headers::content_type::ContentType;
    use crate::sip::headers::cseq::CSeq;
    use crate::sip::headers::from::FromHeader;
    use crate::sip::headers::max_forwards::MaxForwards;
    use crate::sip::headers::to::ToHeader;
    use crate::sip::headers::via::Via;
    use crate::sip::parser::{message::parse, uri};
    use crate::sip::types::header::{Header, HeaderKind, HeaderName, HeaderValue};
    use crate::sip::types::method::Method;
    use crate::sip::validation;

    use super::{BuildError, RequestBuilder};

    fn builder(method: Method, cseq_method: Method) -> Result<RequestBuilder, BuildError> {
        let Ok(uri) = uri::parse(b"sip:service@example.com") else {
            panic!("valid URI");
        };
        let Ok(via) = Via::from_bytes(b"SIP/2.0/UDP runtime.example.com;branch=z9hG4bK-one") else {
            panic!("valid Via");
        };
        let Ok(from) = FromHeader::from_bytes(b"<sip:runtime@example.com>;tag=local") else {
            panic!("valid From");
        };
        let Ok(to) = ToHeader::from_bytes(b"<sip:service@example.com>") else {
            panic!("valid To");
        };
        let Ok(call_id) = CallId::from_bytes(b"private-call-id@example.com") else {
            panic!("valid Call-ID");
        };
        let Ok(cseq) = CSeq::new(1, cseq_method) else {
            panic!("valid CSeq");
        };
        RequestBuilder::new(
            method,
            uri,
            &via,
            &from,
            &to,
            &call_id,
            &cseq,
            MaxForwards::new(70),
        )
    }

    #[test]
    fn builds_request_that_round_trips_through_validation() {
        let Ok(builder) = builder(Method::Invite, Method::Invite) else {
            panic!("valid builder");
        };
        let Ok(bytes) = builder.serialize() else {
            panic!("serialization");
        };
        let Ok(raw) = parse(Arc::from(bytes)) else {
            panic!("parse");
        };
        assert!(validation::request::validate(raw).is_ok());
    }

    #[test]
    fn rejects_cseq_mismatch_at_construction() {
        assert!(matches!(
            builder(Method::Invite, Method::Bye),
            Err(BuildError::CSeqMethodMismatch)
        ));
    }

    #[test]
    fn reserved_core_headers_cannot_be_added() {
        let Ok(mut builder) = builder(Method::Invite, Method::Invite) else {
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
    fn body_and_content_type_are_installed_together() {
        let Ok(builder) = builder(Method::Invite, Method::Invite) else {
            panic!("valid builder");
        };
        let Ok(content_type) = ContentType::from_bytes(b"application/sdp") else {
            panic!("valid content type");
        };
        let Ok(builder) = builder.with_body(&content_type, b"v=0\r\n") else {
            panic!("valid body");
        };
        assert_eq!(builder.body(), b"v=0\r\n");
        assert!(
            builder
                .headers()
                .iter()
                .any(|h| h.name().kind() == Some(HeaderKind::ContentType))
        );
        assert!(builder.serialize().is_ok());
    }

    #[test]
    fn oversized_body_is_rejected_before_copying() {
        let Ok(builder) = builder(Method::Invite, Method::Invite) else {
            panic!("valid builder");
        };
        let Ok(content_type) = ContentType::from_bytes(b"application/sdp") else {
            panic!("valid content type");
        };
        let body = vec![0_u8; MAX_BODY_BYTES + 1];
        assert!(matches!(
            builder.with_body(&content_type, &body),
            Err(BuildError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn optional_headers_are_preserved() {
        let Ok(mut builder) = builder(Method::Options, Method::Options) else {
            panic!("valid builder");
        };
        assert!(
            builder
                .push_typed(HeaderKind::Supported, &"timer, 100rel")
                .is_ok()
        );
        assert_eq!(builder.headers().len(), 7);
    }

    #[test]
    fn debug_is_redacted() {
        let Ok(builder) = builder(Method::Invite, Method::Invite) else {
            panic!("valid builder");
        };
        let debug = format!("{builder:?}");
        assert!(!debug.contains("private-call-id"));
        assert!(!debug.contains("runtime.example.com"));
        assert!(!debug.contains("service@example.com"));
    }
}
