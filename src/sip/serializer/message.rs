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

//! Complete bounded SIP wire-message serialization.
//!
//! This layer exclusively owns Content-Length. Callers may not supply it; the
//! serializer inserts the exact body length automatically, preventing stale or
//! conflicting framing metadata.

use std::collections::TryReserveError;
use std::error::Error as StdError;
use std::fmt::{self, Write as _};

use crate::sip::framing::{MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_LINE_BYTES, MAX_MESSAGE_BYTES};
use crate::sip::types::header::{Header, HeaderKind, HeaderName, HeaderValue};
use crate::sip::types::method::Method;
use crate::sip::types::status::StatusCode;
use crate::sip::types::uri::Uri;
use crate::sip::types::version::Version;

use super::headers::{HeaderSectionWriter, SerializeError as HeaderSerializeError};

const CRLF: &[u8] = b"\r\n";

/// Serializes one complete canonical SIP request.
///
/// # Errors
///
/// Returns an error when a configured resource bound would be exceeded,
/// Content-Length was supplied by the caller, or allocation fails.
pub fn serialize_request(
    method: &Method,
    uri: &Uri,
    version: Version,
    headers: &[Header],
    body: &[u8],
) -> Result<Vec<u8>, SerializeError> {
    let mut line = String::new();
    line.try_reserve(MAX_LINE_BYTES)
        .map_err(SerializeError::AllocationFailed)?;
    write!(line, "{method} {uri} {version}").map_err(|_| SerializeError::FormattingFailed)?;
    serialize(line.as_bytes(), headers, body)
}

/// Serializes one complete canonical SIP response.
///
/// The reason phrase may be empty. Horizontal tab, printable ASCII, and
/// obs-text are accepted; CR, LF, and other control bytes are rejected.
///
/// # Errors
///
/// Returns an error for an invalid reason phrase or when a configured
/// resource bound would be exceeded.
pub fn serialize_response(
    version: Version,
    status: StatusCode,
    reason_phrase: &[u8],
    headers: &[Header],
    body: &[u8],
) -> Result<Vec<u8>, SerializeError> {
    validate_reason_phrase(reason_phrase)?;

    let prefix = format!("{version} {} ", status.as_u16());
    let line_length =
        prefix
            .len()
            .checked_add(reason_phrase.len())
            .ok_or(SerializeError::StartLineTooLong {
                attempted: usize::MAX,
                maximum: MAX_LINE_BYTES,
            })?;
    validate_start_line_length(line_length)?;

    let mut line = Vec::new();
    line.try_reserve_exact(line_length)
        .map_err(SerializeError::AllocationFailed)?;
    line.extend_from_slice(prefix.as_bytes());
    line.extend_from_slice(reason_phrase);
    serialize(&line, headers, body)
}

fn serialize(
    start_line: &[u8],
    headers: &[Header],
    body: &[u8],
) -> Result<Vec<u8>, SerializeError> {
    validate_start_line_length(start_line.len())?;

    if body.len() > MAX_BODY_BYTES {
        return Err(SerializeError::BodyTooLarge {
            attempted: body.len(),
            maximum: MAX_BODY_BYTES,
        });
    }

    if headers
        .iter()
        .any(|header| header.name().kind() == Some(HeaderKind::ContentLength))
    {
        return Err(SerializeError::CallerProvidedContentLength);
    }

    let mut section = HeaderSectionWriter::new();
    for header in headers {
        section.push(header)?;
    }

    let length_name = HeaderName::known(HeaderKind::ContentLength);
    let length_text = body.len().to_string();
    let length_value = HeaderValue::from_bytes(length_text.as_bytes())
        .map_err(|_| SerializeError::FormattingFailed)?;
    section.push_parts(&length_name, &length_value)?;
    let section = section.finish()?;

    let header_bytes = start_line
        .len()
        .checked_add(CRLF.len())
        .and_then(|length| length.checked_add(section.len()))
        .ok_or(SerializeError::HeaderSectionTooLarge {
            attempted: usize::MAX,
            maximum: MAX_HEADER_BYTES,
        })?;
    if header_bytes > MAX_HEADER_BYTES {
        return Err(SerializeError::HeaderSectionTooLarge {
            attempted: header_bytes,
            maximum: MAX_HEADER_BYTES,
        });
    }

    let message_bytes =
        header_bytes
            .checked_add(body.len())
            .ok_or(SerializeError::MessageTooLarge {
                attempted: usize::MAX,
                maximum: MAX_MESSAGE_BYTES,
            })?;
    if message_bytes > MAX_MESSAGE_BYTES {
        return Err(SerializeError::MessageTooLarge {
            attempted: message_bytes,
            maximum: MAX_MESSAGE_BYTES,
        });
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(message_bytes)
        .map_err(SerializeError::AllocationFailed)?;
    output.extend_from_slice(start_line);
    output.extend_from_slice(CRLF);
    output.extend_from_slice(&section);
    output.extend_from_slice(body);
    debug_assert_eq!(output.len(), message_bytes);
    Ok(output)
}

fn validate_start_line_length(length: usize) -> Result<(), SerializeError> {
    if length > MAX_LINE_BYTES {
        return Err(SerializeError::StartLineTooLong {
            attempted: length,
            maximum: MAX_LINE_BYTES,
        });
    }
    Ok(())
}

fn validate_reason_phrase(input: &[u8]) -> Result<(), SerializeError> {
    if let Some((index, byte)) = input
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| !matches!(*byte, b'\t' | b' '..=b'~' | 0x80..=0xff))
    {
        return Err(SerializeError::InvalidReasonPhraseByte { index, byte });
    }
    Ok(())
}

/// Failure to serialize a complete SIP message.
#[derive(Debug)]
#[non_exhaustive]
pub enum SerializeError {
    /// A canonical start line exceeded the physical-line limit.
    StartLineTooLong {
        /// Attempted byte length, excluding CRLF.
        attempted: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// A reason phrase contained a prohibited control byte.
    InvalidReasonPhraseByte {
        /// Offset within the reason phrase.
        index: usize,
        /// Prohibited byte.
        byte: u8,
    },
    /// The caller supplied serializer-owned framing metadata.
    CallerProvidedContentLength,
    /// Header serialization failed.
    Headers(HeaderSerializeError),
    /// Start line plus headers exceeded the header-section bound.
    HeaderSectionTooLarge {
        /// Attempted byte length.
        attempted: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// The body exceeded its configured bound.
    BodyTooLarge {
        /// Attempted byte length.
        attempted: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// The complete message exceeded its configured bound.
    MessageTooLarge {
        /// Attempted byte length.
        attempted: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// Canonical formatting unexpectedly failed.
    FormattingFailed,
    /// A bounded output allocation could not be reserved.
    AllocationFailed(TryReserveError),
}

impl SerializeError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::StartLineTooLong { .. } => "start-line-too-long",
            Self::InvalidReasonPhraseByte { .. } => "invalid-reason-phrase-byte",
            Self::CallerProvidedContentLength => "caller-provided-content-length",
            Self::Headers(_) => "invalid-header-section",
            Self::HeaderSectionTooLarge { .. } => "header-section-too-large",
            Self::BodyTooLarge { .. } => "body-too-large",
            Self::MessageTooLarge { .. } => "message-too-large",
            Self::FormattingFailed => "formatting-failed",
            Self::AllocationFailed(_) => "allocation-failed",
        }
    }
}

impl From<HeaderSerializeError> for SerializeError {
    fn from(error: HeaderSerializeError) -> Self {
        Self::Headers(error)
    }
}

impl fmt::Display for SerializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartLineTooLong { attempted, maximum } => write!(
                formatter,
                "serialized SIP start-line length {attempted} exceeds maximum {maximum}"
            ),
            Self::InvalidReasonPhraseByte { index, byte } => write!(
                formatter,
                "invalid SIP reason-phrase byte 0x{byte:02x} at offset {index}"
            ),
            Self::CallerProvidedContentLength => formatter.write_str(
                "Content-Length is serializer-managed and must not be supplied by the caller",
            ),
            Self::Headers(error) => write!(formatter, "failed to serialize SIP headers: {error}"),
            Self::HeaderSectionTooLarge { attempted, maximum } => write!(
                formatter,
                "serialized SIP header section length {attempted} exceeds maximum {maximum}"
            ),
            Self::BodyTooLarge { attempted, maximum } => {
                write!(
                    formatter,
                    "SIP body length {attempted} exceeds maximum {maximum}"
                )
            }
            Self::MessageTooLarge { attempted, maximum } => write!(
                formatter,
                "serialized SIP message length {attempted} exceeds maximum {maximum}"
            ),
            Self::FormattingFailed => formatter.write_str("canonical SIP formatting failed"),
            Self::AllocationFailed(_) => {
                formatter.write_str("failed to reserve bounded SIP message output")
            }
        }
    }
}

impl StdError for SerializeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Headers(error) => Some(error),
            Self::AllocationFailed(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::sip::framing::MAX_BODY_BYTES;
    use crate::sip::parser::{message::parse, uri};
    use crate::sip::types::header::{Header, HeaderKind, HeaderName, HeaderValue};
    use crate::sip::types::method::Method;
    use crate::sip::types::status::StatusCode;
    use crate::sip::types::version::Version;
    use crate::sip::validation;

    use super::{SerializeError, serialize_request, serialize_response};

    fn header(kind: HeaderKind, bytes: &[u8]) -> Header {
        let Ok(value) = HeaderValue::from_bytes(bytes) else {
            panic!("expected valid header value");
        };
        Header::new(HeaderName::known(kind), value)
    }

    fn core_headers() -> Vec<Header> {
        vec![
            header(
                HeaderKind::Via,
                b"SIP/2.0/UDP runtime.example.com;branch=z9hG4bK-one",
            ),
            header(HeaderKind::From, b"<sip:runtime@example.com>;tag=one"),
            header(HeaderKind::To, b"<sip:service@example.com>"),
            header(HeaderKind::CallId, b"private-call-id@example.com"),
            header(HeaderKind::CSeq, b"1 INVITE"),
            header(HeaderKind::MaxForwards, b"70"),
        ]
    }

    #[test]
    fn request_round_trips_through_parser_and_validation() {
        let Ok(uri) = uri::parse(b"sip:service@example.com") else {
            panic!("expected URI");
        };
        let body = b"v=0\r\n";
        let mut headers = core_headers();
        headers.push(header(HeaderKind::ContentType, b"application/sdp"));

        let Ok(bytes) = serialize_request(&Method::Invite, &uri, Version::Sip2, &headers, body)
        else {
            panic!("expected serialized request");
        };
        let Ok(raw) = parse(Arc::from(bytes)) else {
            panic!("expected parser round trip");
        };
        let Ok(validated) = validation::request::validate(raw) else {
            panic!("expected request validation round trip");
        };

        assert_eq!(validated.message().body(), body);
        assert_eq!(
            validated
                .core_headers()
                .content_length()
                .map(crate::sip::headers::content_length::ContentLength::as_usize),
            Some(body.len())
        );
    }

    #[test]
    fn response_round_trips_with_empty_reason_phrase() {
        let Ok(bytes) =
            serialize_response(Version::Sip2, StatusCode::TRYING, b"", &core_headers(), b"")
        else {
            panic!("expected serialized response");
        };
        let Ok(raw) = parse(Arc::from(bytes)) else {
            panic!("expected parser round trip");
        };
        let Ok(validated) = validation::response::validate(raw) else {
            panic!("expected response validation round trip");
        };
        assert!(validated.reason_phrase().is_empty());
    }

    #[test]
    fn inserts_exact_content_length_for_binary_body() {
        let Ok(uri) = uri::parse(b"sip:service@example.com") else {
            panic!("expected URI");
        };
        let body = [0_u8, 1, 2, 255];
        let Ok(bytes) =
            serialize_request(&Method::Invite, &uri, Version::Sip2, &core_headers(), &body)
        else {
            panic!("expected serialization");
        };
        let expected = b"Content-Length: 4";
        assert!(
            bytes
                .windows(expected.len())
                .any(|window| window == expected)
        );
        assert!(bytes.ends_with(&body));
    }

    #[test]
    fn rejects_caller_supplied_content_length() {
        let Ok(uri) = uri::parse(b"sip:service@example.com") else {
            panic!("expected URI");
        };
        let mut headers = core_headers();
        headers.push(header(HeaderKind::ContentLength, b"0"));
        let Err(error) = serialize_request(&Method::Invite, &uri, Version::Sip2, &headers, b"")
        else {
            panic!("expected managed-header rejection");
        };
        assert!(matches!(error, SerializeError::CallerProvidedContentLength));
    }

    #[test]
    fn rejects_reason_phrase_injection() {
        let Err(error) = serialize_response(
            Version::Sip2,
            StatusCode::OK,
            b"OK\r\nInjected: yes",
            &core_headers(),
            b"",
        ) else {
            panic!("expected reason rejection");
        };
        assert!(matches!(
            error,
            SerializeError::InvalidReasonPhraseByte { .. }
        ));
    }

    #[test]
    fn accepts_exact_body_limit_and_rejects_next_byte() {
        let Ok(uri) = uri::parse(b"sip:service@example.com") else {
            panic!("expected URI");
        };
        let body = vec![0_u8; MAX_BODY_BYTES];
        assert!(
            serialize_request(&Method::Invite, &uri, Version::Sip2, &core_headers(), &body).is_ok()
        );
        let oversized = vec![0_u8; MAX_BODY_BYTES + 1];
        let Err(error) = serialize_request(
            &Method::Invite,
            &uri,
            Version::Sip2,
            &core_headers(),
            &oversized,
        ) else {
            panic!("expected body limit rejection");
        };
        assert!(matches!(error, SerializeError::BodyTooLarge { .. }));
    }

    #[test]
    fn errors_do_not_disclose_message_contents() {
        let error = serialize_response(
            Version::Sip2,
            StatusCode::OK,
            b"private\nphrase",
            &core_headers(),
            b"",
        )
        .err();
        let Some(error) = error else {
            panic!("expected error");
        };
        assert!(!format!("{error:?}").contains("private"));
        assert!(!error.to_string().contains("private"));
    }
}
