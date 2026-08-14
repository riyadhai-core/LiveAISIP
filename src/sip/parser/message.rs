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

//! Lossless structural SIP message parser.
//!
//! This module parses one already-framed SIP message into the compact
//! span-backed representation defined by [`crate::sip::types::message`].
//!
//! Parsing is deliberately divided from typed semantic interpretation. This
//! layer validates structural invariants required to represent the message
//! safely and unambiguously while preserving:
//!
//! - original message bytes;
//! - header wire order;
//! - repeated headers;
//! - extension headers;
//! - original header-name spelling;
//! - compact header names;
//! - raw header-value whitespace;
//! - valid SIP header folding;
//! - arbitrary binary message bodies.
//!
//! Framing-sensitive `Content-Length` handling is validated here as defense in
//! depth. Duplicate `Content-Length` fields are rejected because competing
//! framing lengths cannot safely be deferred to a later semantic-policy
//! layer.
//!
//! Individual header semantics, request-URI semantics, SIP version support,
//! transaction requirements, and method-specific policy belong to later typed
//! parsing and validation layers.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use crate::sip::framing::{
    MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_HEADER_COUNT, MAX_LINE_BYTES, MAX_MESSAGE_BYTES,
};
use crate::sip::types::header::{HeaderKind, MAX_HEADER_NAME_BYTES};
use crate::sip::types::message::{
    BuildError, LayoutError, RawHeader, RawMessage, RawRequestLine, RawResponseLine, RawStartLine,
    Span, SpanError,
};
use crate::sip::types::method::MAX_METHOD_BYTES;

/// Parses one owned, already-framed SIP message.
///
/// The supplied buffer must contain exactly one SIP message and no bytes from
/// a subsequent stream message. For datagram input without `Content-Length`,
/// the bytes following the header terminator are treated as the complete body.
///
/// No per-header name or value buffers are allocated. The returned
/// [`RawMessage`] retains one immutable shared backing buffer and stores
/// compact spans into it.
///
/// # Errors
///
/// Returns [`ParseError`] when the input violates structural SIP grammar,
/// operational resource limits, framing-sensitive `Content-Length` rules, or
/// internal structural metadata invariants.
pub fn parse(bytes: Arc<[u8]>) -> Result<RawMessage, ParseError> {
    validate_message_size(bytes.len())?;

    let start_line_end = find_line_end(&bytes, 0)?;

    if start_line_end == 0 {
        return Err(ParseError::EmptyStartLine);
    }

    let start_line = parse_start_line(&bytes[..start_line_end])?;

    let mut offset = start_line_end
        .checked_add(2)
        .ok_or(ParseError::OffsetOverflow)?;

    let mut headers = Vec::new();
    let mut content_length = None;
    let body_start;

    loop {
        if offset > MAX_HEADER_BYTES {
            return Err(ParseError::HeaderSectionTooLarge {
                length: offset,
                maximum: MAX_HEADER_BYTES,
            });
        }

        if offset >= bytes.len() {
            return Err(ParseError::MissingHeaderTerminator);
        }

        if is_crlf_at(&bytes, offset) {
            body_start = offset.checked_add(2).ok_or(ParseError::OffsetOverflow)?;

            if body_start > MAX_HEADER_BYTES {
                return Err(ParseError::HeaderSectionTooLarge {
                    length: body_start,
                    maximum: MAX_HEADER_BYTES,
                });
            }

            break;
        }

        if is_wsp(bytes[offset]) {
            return Err(ParseError::ContinuationWithoutHeader { index: offset });
        }

        if headers.len() >= MAX_HEADER_COUNT {
            return Err(ParseError::TooManyHeaders {
                maximum: MAX_HEADER_COUNT,
            });
        }

        let parsed = parse_header(&bytes, offset)?;

        if parsed.next_offset > MAX_HEADER_BYTES {
            return Err(ParseError::HeaderSectionTooLarge {
                length: parsed.next_offset,
                maximum: MAX_HEADER_BYTES,
            });
        }

        if parsed.is_content_length {
            if content_length.is_some() {
                return Err(ParseError::DuplicateContentLength);
            }

            let raw_value = parsed
                .header
                .value_span()
                .get(&bytes)
                .ok_or(ParseError::MetadataOutOfBounds)?;

            content_length = Some(parse_content_length(raw_value)?);
        }

        offset = parsed.next_offset;
        headers.push(parsed.header);
    }

    let body_length = bytes
        .len()
        .checked_sub(body_start)
        .ok_or(ParseError::OffsetOverflow)?;

    if body_length > MAX_BODY_BYTES {
        return Err(ParseError::BodyTooLarge {
            length: body_length,
            maximum: MAX_BODY_BYTES,
        });
    }

    if let Some(content_length) = content_length
        && content_length != body_length
    {
        return Err(ParseError::ContentLengthMismatch {
            declared: content_length,
            actual: body_length,
        });
    }

    let body = make_span(body_start, bytes.len())?;

    RawMessage::new(bytes, start_line, headers, body).map_err(ParseError::MessageBuild)
}

/// Parses one SIP message from an owned byte vector.
///
/// The vector is converted into the immutable backing storage used by
/// [`RawMessage`].
///
/// # Errors
///
/// Returns the same errors as [`parse`].
pub fn parse_vec(bytes: Vec<u8>) -> Result<RawMessage, ParseError> {
    parse(Arc::from(bytes))
}

struct ParsedHeader {
    header: RawHeader,
    next_offset: usize,
    is_content_length: bool,
}

fn validate_message_size(length: usize) -> Result<(), ParseError> {
    if length == 0 {
        return Err(ParseError::EmptyMessage);
    }

    if length > MAX_MESSAGE_BYTES {
        return Err(ParseError::MessageTooLarge {
            length,
            maximum: MAX_MESSAGE_BYTES,
        });
    }

    Ok(())
}

fn parse_start_line(line: &[u8]) -> Result<RawStartLine, ParseError> {
    if starts_with_ascii_case_insensitive(line, b"SIP/") {
        parse_response_line(line)
    } else {
        parse_request_line(line)
    }
}

fn parse_request_line(line: &[u8]) -> Result<RawStartLine, ParseError> {
    let Some(first_space) = find_byte(line, b' ') else {
        return Err(ParseError::InvalidRequestLine);
    };

    let uri_start = first_space
        .checked_add(1)
        .ok_or(ParseError::OffsetOverflow)?;

    let Some(relative_second_space) = find_byte(&line[uri_start..], b' ') else {
        return Err(ParseError::InvalidRequestLine);
    };

    let second_space = uri_start
        .checked_add(relative_second_space)
        .ok_or(ParseError::OffsetOverflow)?;

    let version_start = second_space
        .checked_add(1)
        .ok_or(ParseError::OffsetOverflow)?;

    let method = &line[..first_space];
    let uri = &line[uri_start..second_space];
    let version = &line[version_start..];

    if method.is_empty()
        || uri.is_empty()
        || version.is_empty()
        || method.len() > MAX_METHOD_BYTES
        || !method.iter().copied().all(is_token_byte)
        || uri.iter().copied().any(is_request_component_separator)
        || version.iter().copied().any(is_request_component_separator)
    {
        return Err(ParseError::InvalidRequestLine);
    }

    validate_start_line_component(uri)?;
    validate_start_line_component(version)?;

    let line_span = make_span(0, line.len())?;
    let method_span = make_span(0, first_space)?;
    let uri_span = make_span(uri_start, second_space)?;
    let version_span = make_span(version_start, line.len())?;

    let request = RawRequestLine::new(line_span, method_span, uri_span, version_span)
        .map_err(ParseError::MetadataLayout)?;

    Ok(RawStartLine::Request(request))
}

fn parse_response_line(line: &[u8]) -> Result<RawStartLine, ParseError> {
    let Some(first_space) = find_byte(line, b' ') else {
        return Err(ParseError::InvalidResponseLine);
    };

    let status_start = first_space
        .checked_add(1)
        .ok_or(ParseError::OffsetOverflow)?;

    let Some(relative_second_space) = find_byte(&line[status_start..], b' ') else {
        return Err(ParseError::InvalidResponseLine);
    };

    let second_space = status_start
        .checked_add(relative_second_space)
        .ok_or(ParseError::OffsetOverflow)?;

    let reason_start = second_space
        .checked_add(1)
        .ok_or(ParseError::OffsetOverflow)?;

    let version = &line[..first_space];
    let status = &line[status_start..second_space];
    let reason = &line[reason_start..];

    if version.is_empty()
        || status.len() != 3
        || !status.iter().all(u8::is_ascii_digit)
        || version.iter().copied().any(is_request_component_separator)
    {
        return Err(ParseError::InvalidResponseLine);
    }

    validate_start_line_component(version)?;
    validate_reason_phrase(reason)?;

    let line_span = make_span(0, line.len())?;
    let version_span = make_span(0, first_space)?;
    let status_span = make_span(status_start, second_space)?;
    let reason_span = make_span(reason_start, line.len())?;

    let response = RawResponseLine::new(line_span, version_span, status_span, reason_span)
        .map_err(ParseError::MetadataLayout)?;

    Ok(RawStartLine::Response(response))
}

fn parse_header(input: &[u8], start: usize) -> Result<ParsedHeader, ParseError> {
    let first_line_end = find_line_end(input, start)?;

    let first_line = &input[start..first_line_end];

    let Some(relative_colon) = find_byte(first_line, b':') else {
        return Err(ParseError::MissingHeaderColon { index: start });
    };

    let colon = start
        .checked_add(relative_colon)
        .ok_or(ParseError::OffsetOverflow)?;

    let name_end = trim_trailing_wsp_index(input, start, colon);

    if name_end == start {
        return Err(ParseError::InvalidHeaderName { index: start });
    }

    let name_length = name_end
        .checked_sub(start)
        .ok_or(ParseError::OffsetOverflow)?;

    if name_length > MAX_HEADER_NAME_BYTES {
        return Err(ParseError::HeaderNameTooLong {
            length: name_length,
            maximum: MAX_HEADER_NAME_BYTES,
        });
    }

    let name = &input[start..name_end];

    if !name.iter().copied().all(is_token_byte) {
        return Err(ParseError::InvalidHeaderName { index: start });
    }

    if !input[name_end..colon].iter().copied().all(is_wsp) {
        return Err(ParseError::InvalidHeaderName { index: start });
    }

    let value_start = colon.checked_add(1).ok_or(ParseError::OffsetOverflow)?;

    validate_field_value_line(input, value_start, first_line_end)?;

    let mut field_end = first_line_end;
    let mut next_offset = first_line_end
        .checked_add(2)
        .ok_or(ParseError::OffsetOverflow)?;

    while next_offset < input.len() && !is_crlf_at(input, next_offset) && is_wsp(input[next_offset])
    {
        let continuation_end = find_line_end(input, next_offset)?;

        validate_field_value_line(input, next_offset, continuation_end)?;

        field_end = continuation_end;
        next_offset = continuation_end
            .checked_add(2)
            .ok_or(ParseError::OffsetOverflow)?;
    }

    let name_span = make_span(start, name_end)?;
    let value_span = make_span(value_start, field_end)?;

    let kind = HeaderKind::from_name_bytes(name);
    let is_content_length = matches!(kind, Some(HeaderKind::ContentLength));

    let header = RawHeader::new(name_span, value_span, kind).map_err(ParseError::MetadataLayout)?;

    Ok(ParsedHeader {
        header,
        next_offset,
        is_content_length,
    })
}

fn parse_content_length(input: &[u8]) -> Result<usize, ParseError> {
    let mut offset = 0_usize;

    skip_linear_whitespace(input, &mut offset)?;

    let digits_start = offset;

    while offset < input.len() && input[offset].is_ascii_digit() {
        offset += 1;
    }

    if offset == digits_start {
        return Err(ParseError::InvalidContentLength);
    }

    let mut value = 0_usize;

    for digit in &input[digits_start..offset] {
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(usize::from(*digit - b'0')))
            .ok_or(ParseError::ContentLengthOverflow)?;
    }

    skip_linear_whitespace(input, &mut offset)?;

    if offset != input.len() {
        return Err(ParseError::InvalidContentLength);
    }

    if value > MAX_BODY_BYTES {
        return Err(ParseError::BodyTooLarge {
            length: value,
            maximum: MAX_BODY_BYTES,
        });
    }

    Ok(value)
}

fn skip_linear_whitespace(input: &[u8], offset: &mut usize) -> Result<(), ParseError> {
    loop {
        while *offset < input.len() && is_wsp(input[*offset]) {
            *offset += 1;
        }

        if *offset >= input.len() {
            return Ok(());
        }

        if input[*offset] != b'\r' {
            return Ok(());
        }

        let lf = offset.checked_add(1).ok_or(ParseError::OffsetOverflow)?;

        if input.get(lf) != Some(&b'\n') {
            return Err(ParseError::InvalidContentLength);
        }

        let continuation = lf.checked_add(1).ok_or(ParseError::OffsetOverflow)?;

        if continuation >= input.len() || !is_wsp(input[continuation]) {
            return Err(ParseError::InvalidContentLength);
        }

        *offset = continuation;
    }
}

fn find_line_end(input: &[u8], start: usize) -> Result<usize, ParseError> {
    if start >= input.len() {
        return Err(ParseError::MissingLineTerminator { index: start });
    }

    let mut index = start;

    while index < input.len() {
        let line_length = index.checked_sub(start).ok_or(ParseError::OffsetOverflow)?;

        if line_length > MAX_LINE_BYTES {
            return Err(ParseError::LineTooLong {
                maximum: MAX_LINE_BYTES,
            });
        }

        match input[index] {
            b'\r' => {
                if input.get(index + 1) == Some(&b'\n') {
                    let final_length =
                        index.checked_sub(start).ok_or(ParseError::OffsetOverflow)?;

                    if final_length > MAX_LINE_BYTES {
                        return Err(ParseError::LineTooLong {
                            maximum: MAX_LINE_BYTES,
                        });
                    }

                    return Ok(index);
                }

                return Err(ParseError::InvalidLineEnding { index });
            }
            b'\n' => {
                return Err(ParseError::InvalidLineEnding { index });
            }
            _ => {
                index += 1;
            }
        }
    }

    Err(ParseError::MissingLineTerminator { index: start })
}

fn validate_start_line_component(input: &[u8]) -> Result<(), ParseError> {
    if let Some((index, _)) = input
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| is_invalid_start_line_byte(*byte))
    {
        return Err(ParseError::InvalidStartLineByte { index });
    }

    Ok(())
}

fn validate_reason_phrase(input: &[u8]) -> Result<(), ParseError> {
    if let Some((index, byte)) = input
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| is_invalid_reason_phrase_byte(*byte))
    {
        return Err(ParseError::InvalidReasonPhraseByte { index, byte });
    }

    Ok(())
}

fn validate_field_value_line(input: &[u8], start: usize, end: usize) -> Result<(), ParseError> {
    for (relative_index, byte) in input[start..end].iter().copied().enumerate() {
        if is_invalid_field_value_byte(byte) {
            let index = start
                .checked_add(relative_index)
                .ok_or(ParseError::OffsetOverflow)?;

            return Err(ParseError::InvalidHeaderValueByte { index, byte });
        }
    }

    Ok(())
}

fn trim_trailing_wsp_index(input: &[u8], start: usize, end: usize) -> usize {
    let mut index = end;

    while index > start && is_wsp(input[index - 1]) {
        index -= 1;
    }

    index
}

fn starts_with_ascii_case_insensitive(input: &[u8], prefix: &[u8]) -> bool {
    input
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

fn find_byte(input: &[u8], needle: u8) -> Option<usize> {
    input.iter().position(|byte| *byte == needle)
}

fn make_span(start: usize, end: usize) -> Result<Span, ParseError> {
    Span::new(start, end).map_err(ParseError::MetadataSpan)
}

fn is_crlf_at(input: &[u8], index: usize) -> bool {
    input.get(index) == Some(&b'\r') && input.get(index + 1) == Some(&b'\n')
}

const fn is_wsp(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

const fn is_request_component_separator(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

const fn is_invalid_start_line_byte(byte: u8) -> bool {
    byte.is_ascii_control() || byte == 0x7f
}

const fn is_invalid_reason_phrase_byte(byte: u8) -> bool {
    (byte.is_ascii_control() && byte != b'\t') || byte == 0x7f
}

const fn is_invalid_field_value_byte(byte: u8) -> bool {
    (byte.is_ascii_control() && byte != b'\t') || byte == 0x7f
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

/// Failure to structurally parse one framed SIP message.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// The supplied message buffer was empty.
    EmptyMessage,

    /// The complete framed message exceeded the configured operational bound.
    MessageTooLarge {
        /// Actual message size in bytes.
        length: usize,

        /// Maximum accepted message size in bytes.
        maximum: usize,
    },

    /// The start line contained no bytes.
    EmptyStartLine,

    /// A physical signaling line exceeded the configured line-length bound.
    LineTooLong {
        /// Maximum accepted physical line size in bytes.
        maximum: usize,
    },

    /// A signaling line was not terminated using exact CRLF.
    InvalidLineEnding {
        /// Byte offset where invalid line-ending syntax was found.
        index: usize,
    },

    /// A signaling line did not contain a terminating CRLF.
    MissingLineTerminator {
        /// Byte offset where the unterminated line began.
        index: usize,
    },

    /// The SIP request line was structurally invalid.
    InvalidRequestLine,

    /// The SIP response status line was structurally invalid.
    InvalidResponseLine,

    /// A request-line component contained an invalid control byte.
    InvalidStartLineByte {
        /// Offset within the affected start-line component.
        index: usize,
    },

    /// A response reason phrase contained an invalid byte.
    InvalidReasonPhraseByte {
        /// Offset within the reason phrase.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// The header section did not contain its mandatory terminating empty
    /// CRLF line.
    MissingHeaderTerminator,

    /// The header section exceeded the configured operational bound.
    HeaderSectionTooLarge {
        /// Observed header-section size in bytes.
        length: usize,

        /// Maximum accepted header-section size in bytes.
        maximum: usize,
    },

    /// The structural message contained too many logical header fields.
    TooManyHeaders {
        /// Maximum accepted logical header count.
        maximum: usize,
    },

    /// A folded continuation line appeared without a preceding header field.
    ContinuationWithoutHeader {
        /// Byte offset where the continuation line began.
        index: usize,
    },

    /// A header field did not contain its required colon delimiter.
    MissingHeaderColon {
        /// Byte offset where the malformed header began.
        index: usize,
    },

    /// A header field name was empty or violated SIP token syntax.
    InvalidHeaderName {
        /// Byte offset where the malformed header began.
        index: usize,
    },

    /// A header field name exceeded its configured size bound.
    HeaderNameTooLong {
        /// Actual field-name length in bytes.
        length: usize,

        /// Maximum accepted field-name length in bytes.
        maximum: usize,
    },

    /// A header field value contained a prohibited control byte.
    InvalidHeaderValueByte {
        /// Absolute byte offset in the message.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// More than one framing-critical `Content-Length` field was present.
    DuplicateContentLength,

    /// A `Content-Length` field did not contain one decimal value with only
    /// permitted surrounding linear whitespace.
    InvalidContentLength,

    /// Decimal `Content-Length` conversion overflowed `usize`.
    ContentLengthOverflow,

    /// The declared `Content-Length` did not match the exact framed body.
    ContentLengthMismatch {
        /// Declared body length in octets.
        declared: usize,

        /// Actual body length in octets.
        actual: usize,
    },

    /// The body exceeded the configured operational size bound.
    BodyTooLarge {
        /// Actual or declared body size in bytes.
        length: usize,

        /// Maximum accepted body size in bytes.
        maximum: usize,
    },

    /// Internal offset arithmetic overflowed.
    OffsetOverflow,

    /// Structural metadata unexpectedly referenced bytes outside the message.
    MetadataOutOfBounds,

    /// Compact span construction failed.
    MetadataSpan(SpanError),

    /// Structural request-line, response-line, or header metadata was
    /// internally inconsistent.
    MetadataLayout(LayoutError),

    /// Final immutable message construction rejected inconsistent metadata.
    MessageBuild(BuildError),
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics
    /// and structured logs.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::EmptyMessage => "empty-message",
            Self::MessageTooLarge { .. } => "message-too-large",
            Self::EmptyStartLine => "empty-start-line",
            Self::LineTooLong { .. } => "line-too-long",
            Self::InvalidLineEnding { .. } => "invalid-line-ending",
            Self::MissingLineTerminator { .. } => "missing-line-terminator",
            Self::InvalidRequestLine => "invalid-request-line",
            Self::InvalidResponseLine => "invalid-response-line",
            Self::InvalidStartLineByte { .. } => "invalid-start-line-byte",
            Self::InvalidReasonPhraseByte { .. } => "invalid-reason-phrase-byte",
            Self::MissingHeaderTerminator => "missing-header-terminator",
            Self::HeaderSectionTooLarge { .. } => "header-section-too-large",
            Self::TooManyHeaders { .. } => "too-many-headers",
            Self::ContinuationWithoutHeader { .. } => "continuation-without-header",
            Self::MissingHeaderColon { .. } => "missing-header-colon",
            Self::InvalidHeaderName { .. } => "invalid-header-name",
            Self::HeaderNameTooLong { .. } => "header-name-too-long",
            Self::InvalidHeaderValueByte { .. } => "invalid-header-value-byte",
            Self::DuplicateContentLength => "duplicate-content-length",
            Self::InvalidContentLength => "invalid-content-length",
            Self::ContentLengthOverflow => "content-length-overflow",
            Self::ContentLengthMismatch { .. } => "content-length-mismatch",
            Self::BodyTooLarge { .. } => "body-too-large",
            Self::OffsetOverflow => "offset-overflow",
            Self::MetadataOutOfBounds => "metadata-out-of-bounds",
            Self::MetadataSpan(_) => "metadata-span",
            Self::MetadataLayout(_) => "metadata-layout",
            Self::MessageBuild(_) => "message-build",
        }
    }
}

fn format_limit_error(
    formatter: &mut fmt::Formatter<'_>,
    subject: &str,
    length: usize,
    maximum: usize,
) -> fmt::Result {
    write!(
        formatter,
        "{subject} length {length} exceeds maximum {maximum}"
    )
}

fn format_nested_error(
    formatter: &mut fmt::Formatter<'_>,
    subject: &str,
    error: &dyn fmt::Display,
) -> fmt::Result {
    write!(formatter, "{subject}: {error}")
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMessage => formatter.write_str("SIP message is empty"),
            Self::MessageTooLarge { length, maximum } => {
                format_limit_error(formatter, "SIP message", *length, *maximum)
            }
            Self::EmptyStartLine => formatter.write_str("SIP start line is empty"),
            Self::LineTooLong { maximum } => {
                write!(
                    formatter,
                    "SIP signaling line exceeds maximum {maximum} bytes"
                )
            }
            Self::InvalidLineEnding { index } => {
                write!(formatter, "invalid SIP line ending at byte offset {index}")
            }
            Self::MissingLineTerminator { index } => write!(
                formatter,
                "SIP signaling line beginning at byte offset {index} has no terminating CRLF"
            ),
            Self::InvalidRequestLine => {
                formatter.write_str("SIP request line is structurally invalid")
            }
            Self::InvalidResponseLine => {
                formatter.write_str("SIP response status line is structurally invalid")
            }
            Self::InvalidStartLineByte { index } => write!(
                formatter,
                "SIP start-line component contains an invalid byte at offset {index}"
            ),
            Self::InvalidReasonPhraseByte { index, byte } => write!(
                formatter,
                "SIP response reason phrase contains invalid byte 0x{byte:02x} at offset {index}"
            ),
            Self::MissingHeaderTerminator => {
                formatter.write_str("SIP message is missing the mandatory empty header line")
            }
            Self::HeaderSectionTooLarge { length, maximum } => {
                format_limit_error(formatter, "SIP header section", *length, *maximum)
            }
            Self::TooManyHeaders { maximum } => {
                write!(
                    formatter,
                    "SIP message contains more than {maximum} headers"
                )
            }
            Self::ContinuationWithoutHeader { index } => write!(
                formatter,
                "SIP header continuation at byte offset {index} has no preceding header"
            ),
            Self::MissingHeaderColon { index } => write!(
                formatter,
                "SIP header beginning at byte offset {index} has no colon delimiter"
            ),
            Self::InvalidHeaderName { index } => write!(
                formatter,
                "SIP header beginning at byte offset {index} has an invalid field name"
            ),
            Self::HeaderNameTooLong { length, maximum } => {
                format_limit_error(formatter, "SIP header-name", *length, *maximum)
            }
            Self::InvalidHeaderValueByte { index, byte } => write!(
                formatter,
                "SIP header value contains invalid byte 0x{byte:02x} at offset {index}"
            ),
            Self::DuplicateContentLength => {
                formatter.write_str("SIP message contains duplicate Content-Length fields")
            }
            Self::InvalidContentLength => {
                formatter.write_str("SIP Content-Length value is invalid")
            }
            Self::ContentLengthOverflow => {
                formatter.write_str("SIP Content-Length value overflows platform size")
            }
            Self::ContentLengthMismatch { declared, actual } => write!(
                formatter,
                "SIP Content-Length declares {declared} bytes but framed body contains {actual}"
            ),
            Self::BodyTooLarge { length, maximum } => {
                format_limit_error(formatter, "SIP body", *length, *maximum)
            }
            Self::OffsetOverflow => {
                formatter.write_str("SIP structural parser offset arithmetic overflowed")
            }
            Self::MetadataOutOfBounds => {
                formatter.write_str("SIP structural metadata exceeds message buffer")
            }
            Self::MetadataSpan(error) => {
                format_nested_error(formatter, "SIP structural span construction failed", error)
            }
            Self::MetadataLayout(error) => {
                format_nested_error(formatter, "SIP structural metadata layout failed", error)
            }
            Self::MessageBuild(error) => format_nested_error(
                formatter,
                "SIP structural message construction failed",
                error,
            ),
        }
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::MetadataSpan(error) => Some(error),
            Self::MetadataLayout(error) => Some(error),
            Self::MessageBuild(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SpanError> for ParseError {
    fn from(error: SpanError) -> Self {
        Self::MetadataSpan(error)
    }
}

impl From<LayoutError> for ParseError {
    fn from(error: LayoutError) -> Self {
        Self::MetadataLayout(error)
    }
}

impl From<BuildError> for ParseError {
    fn from(error: BuildError) -> Self {
        Self::MessageBuild(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_BODY_BYTES, MAX_HEADER_COUNT, MAX_HEADER_NAME_BYTES, MAX_LINE_BYTES, ParseError, parse,
        parse_vec,
    };
    use crate::sip::types::header::HeaderKind;
    use crate::sip::types::message::{MessageKind, RawStartLineView};
    use std::sync::Arc;

    fn parse_bytes(input: &[u8]) -> Result<crate::sip::types::message::RawMessage, ParseError> {
        parse(Arc::from(input))
    }

    #[test]
    fn parses_basic_request() {
        let Ok(message) = parse_bytes(
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP host.example.com\r\n\
              Content-Length: 0\r\n\
              \r\n",
        ) else {
            panic!("expected structurally valid request");
        };

        assert_eq!(message.kind(), MessageKind::Request);
        assert_eq!(message.header_count(), 2);
        assert!(message.body().is_empty());

        let RawStartLineView::Request(line) = message.start_line_view() else {
            panic!("expected request-line view");
        };

        assert_eq!(line.method(), b"INVITE");
        assert_eq!(line.uri(), b"sip:bob@example.com");
        assert_eq!(line.version(), b"SIP/2.0");
    }

    #[test]
    fn parses_basic_response() {
        let Ok(message) = parse_bytes(
            b"SIP/2.0 486 Busy Here\r\n\
              Via: SIP/2.0/UDP host.example.com\r\n\
              Content-Length: 0\r\n\
              \r\n",
        ) else {
            panic!("expected structurally valid response");
        };

        assert_eq!(message.kind(), MessageKind::Response);

        let RawStartLineView::Response(line) = message.start_line_view() else {
            panic!("expected response-line view");
        };

        assert_eq!(line.version(), b"SIP/2.0");
        assert_eq!(line.status(), b"486");
        assert_eq!(line.reason(), b"Busy Here");
    }

    #[test]
    fn response_reason_phrase_may_be_empty() {
        let Ok(message) = parse_bytes(b"SIP/2.0 200 \r\nContent-Length: 0\r\n\r\n") else {
            panic!("expected response with empty reason phrase");
        };

        let RawStartLineView::Response(line) = message.start_line_view() else {
            panic!("expected response");
        };

        assert!(line.reason().is_empty());
    }

    #[test]
    fn preserves_binary_body() {
        let mut input =
            b"MESSAGE sip:bob@example.com SIP/2.0\r\nContent-Length: 4\r\n\r\n".to_vec();

        input.extend_from_slice(&[0x00, 0xff, 0x10, 0x80]);

        let Ok(message) = parse_vec(input) else {
            panic!("expected binary body");
        };

        assert_eq!(message.body(), &[0x00, 0xff, 0x10, 0x80]);
    }

    #[test]
    fn datagram_style_message_without_content_length_uses_remaining_body() {
        let Ok(message) =
            parse_bytes(b"MESSAGE sip:bob@example.com SIP/2.0\r\nX-Test: one\r\n\r\nbody")
        else {
            panic!("expected message without Content-Length");
        };

        assert_eq!(message.body(), b"body");
    }

    #[test]
    fn preserves_unknown_header() {
        let Ok(message) = parse_bytes(
            b"OPTIONS sip:a@example.com SIP/2.0\r\n\
              X-RiyadhAI-Future: opaque-value\r\n\
              \r\n",
        ) else {
            panic!("expected extension header");
        };

        let Some(header) = message.header(0) else {
            panic!("expected header");
        };

        assert_eq!(header.name(), b"X-RiyadhAI-Future");
        assert_eq!(header.value(), b" opaque-value");
        assert_eq!(header.kind(), None);
    }

    #[test]
    fn preserves_duplicate_extension_headers_in_wire_order() {
        let Ok(message) = parse_bytes(
            b"OPTIONS sip:a@example.com SIP/2.0\r\n\
              X-Test: first\r\n\
              X-Test: second\r\n\
              \r\n",
        ) else {
            panic!("expected duplicate extension headers");
        };

        assert_eq!(message.header_count(), 2);

        let Some(first) = message.header(0) else {
            panic!("expected first header");
        };

        let Some(second) = message.header(1) else {
            panic!("expected second header");
        };

        assert_eq!(first.value(), b" first");
        assert_eq!(second.value(), b" second");
    }

    #[test]
    fn preserves_duplicate_non_framing_known_headers() {
        let Ok(message) = parse_bytes(
            b"OPTIONS sip:a@example.com SIP/2.0\r\n\
              Via: first\r\n\
              Via: second\r\n\
              \r\n",
        ) else {
            panic!("expected duplicate Via fields");
        };

        assert_eq!(message.header_count(), 2);

        for header in message.header_views() {
            assert_eq!(header.kind(), Some(&HeaderKind::Via));
        }
    }

    #[test]
    fn recognizes_header_names_case_insensitively() {
        let Ok(message) = parse_bytes(
            b"OPTIONS sip:a@example.com SIP/2.0\r\n\
              vIa: value\r\n\
              cOnTeNt-LeNgTh: 0\r\n\
              \r\n",
        ) else {
            panic!("expected mixed-case header names");
        };

        let Some(via) = message.header(0) else {
            panic!("expected Via");
        };

        let Some(content_length) = message.header(1) else {
            panic!("expected Content-Length");
        };

        assert_eq!(via.kind(), Some(&HeaderKind::Via));
        assert_eq!(content_length.kind(), Some(&HeaderKind::ContentLength));
    }

    #[test]
    fn recognizes_compact_header_names() {
        let Ok(message) = parse_bytes(
            b"OPTIONS sip:a@example.com SIP/2.0\r\n\
              v: via\r\n\
              f: from\r\n\
              t: to\r\n\
              i: call-id\r\n\
              m: contact\r\n\
              c: content-type\r\n\
              e: encoding\r\n\
              s: subject\r\n\
              k: supported\r\n\
              l: 0\r\n\
              \r\n",
        ) else {
            panic!("expected compact header names");
        };

        let expected = [
            HeaderKind::Via,
            HeaderKind::From,
            HeaderKind::To,
            HeaderKind::CallId,
            HeaderKind::Contact,
            HeaderKind::ContentType,
            HeaderKind::ContentEncoding,
            HeaderKind::Subject,
            HeaderKind::Supported,
            HeaderKind::ContentLength,
        ];

        assert_eq!(message.header_count(), expected.len());

        for (index, expected_kind) in expected.iter().enumerate() {
            let Some(header) = message.header(index) else {
                panic!("expected compact header");
            };

            assert_eq!(header.kind(), Some(expected_kind));
        }
    }

    #[test]
    fn preserves_original_compact_name_bytes() {
        let Ok(message) = parse_bytes(b"OPTIONS sip:a@example.com SIP/2.0\r\nV: value\r\n\r\n")
        else {
            panic!("expected compact Via");
        };

        let Some(header) = message.header(0) else {
            panic!("expected Via");
        };

        assert_eq!(header.kind(), Some(&HeaderKind::Via));
        assert_eq!(header.name(), b"V");
    }

    #[test]
    fn accepts_whitespace_before_colon() {
        let Ok(message) =
            parse_bytes(b"OPTIONS sip:a@example.com SIP/2.0\r\nSubject \t : value\r\n\r\n")
        else {
            panic!("expected whitespace around colon");
        };

        let Some(header) = message.header(0) else {
            panic!("expected Subject");
        };

        assert_eq!(header.name(), b"Subject");
        assert_eq!(header.line(), b"Subject \t : value");
        assert_eq!(header.value(), b" value");
    }

    #[test]
    fn preserves_empty_header_value() {
        let Ok(message) = parse_bytes(b"OPTIONS sip:a@example.com SIP/2.0\r\nSupported:\r\n\r\n")
        else {
            panic!("expected empty field value");
        };

        let Some(header) = message.header(0) else {
            panic!("expected Supported");
        };

        assert!(header.value().is_empty());
    }

    #[test]
    fn preserves_folded_header_as_one_logical_header() {
        let Ok(message) = parse_bytes(
            b"OPTIONS sip:a@example.com SIP/2.0\r\n\
              Subject: first line\r\n\
              \tsecond line\r\n\
              \r\n",
        ) else {
            panic!("expected folded header");
        };

        assert_eq!(message.header_count(), 1);

        let Some(header) = message.header(0) else {
            panic!("expected Subject");
        };

        assert_eq!(header.kind(), Some(&HeaderKind::Subject));
        assert_eq!(header.value(), b" first line\r\n\tsecond line");
        assert_eq!(header.line(), b"Subject: first line\r\n\tsecond line");
    }

    #[test]
    fn folded_content_length_accepts_leading_linear_whitespace() {
        let Ok(message) = parse_bytes(
            b"MESSAGE sip:a@example.com SIP/2.0\r\n\
              Content-Length:\r\n\
              \t4\r\n\
              \r\n\
              body",
        ) else {
            panic!("expected folded Content-Length");
        };

        assert_eq!(message.body(), b"body");
    }

    #[test]
    fn rejects_content_length_fold_inside_decimal_digits() {
        assert!(matches!(
            parse_bytes(
                b"MESSAGE sip:a@example.com SIP/2.0\r\n\
                  Content-Length: 1\r\n\
                  \t2\r\n\
                  \r\n\
                  123456789012"
            ),
            Err(ParseError::InvalidContentLength)
        ));
    }

    #[test]
    fn rejects_duplicate_content_length() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                  Content-Length: 0\r\n\
                  l: 0\r\n\
                  \r\n"
            ),
            Err(ParseError::DuplicateContentLength)
        ));
    }

    #[test]
    fn rejects_content_length_shorter_than_body() {
        assert!(matches!(
            parse_bytes(
                b"MESSAGE sip:a@example.com SIP/2.0\r\n\
                  Content-Length: 3\r\n\
                  \r\n\
                  body"
            ),
            Err(ParseError::ContentLengthMismatch {
                declared: 3,
                actual: 4,
            })
        ));
    }

    #[test]
    fn rejects_content_length_longer_than_body() {
        assert!(matches!(
            parse_bytes(
                b"MESSAGE sip:a@example.com SIP/2.0\r\n\
                  Content-Length: 5\r\n\
                  \r\n\
                  body"
            ),
            Err(ParseError::ContentLengthMismatch {
                declared: 5,
                actual: 4,
            })
        ));
    }

    #[test]
    fn rejects_non_decimal_content_length() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                  Content-Length: four\r\n\
                  \r\n"
            ),
            Err(ParseError::InvalidContentLength)
        ));
    }

    #[test]
    fn rejects_signed_content_length() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                  Content-Length: +0\r\n\
                  \r\n"
            ),
            Err(ParseError::InvalidContentLength)
        ));
    }

    #[test]
    fn rejects_content_length_with_internal_whitespace() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                  Content-Length: 1 2\r\n\
                  \r\n"
            ),
            Err(ParseError::InvalidContentLength)
        ));
    }

    #[test]
    fn rejects_content_length_numeric_overflow() {
        let decimal = "9".repeat(128);

        let input =
            format!("OPTIONS sip:a@example.com SIP/2.0\r\nContent-Length: {decimal}\r\n\r\n");

        assert!(matches!(
            parse_bytes(input.as_bytes()),
            Err(ParseError::ContentLengthOverflow)
        ));
    }

    #[test]
    fn rejects_declared_body_above_operational_limit() {
        let input = format!(
            "OPTIONS sip:a@example.com SIP/2.0\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );

        assert!(matches!(
            parse_bytes(input.as_bytes()),
            Err(ParseError::BodyTooLarge {
                length,
                maximum: MAX_BODY_BYTES,
            }) if length == MAX_BODY_BYTES + 1
        ));
    }

    #[test]
    fn rejects_continuation_without_preceding_header() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                  \torphaned\r\n\
                  \r\n"
            ),
            Err(ParseError::ContinuationWithoutHeader { .. })
        ));
    }

    #[test]
    fn rejects_header_without_colon() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                  Invalid Header\r\n\
                  \r\n"
            ),
            Err(ParseError::MissingHeaderColon { .. })
        ));
    }

    #[test]
    fn rejects_empty_header_name() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                  : value\r\n\
                  \r\n"
            ),
            Err(ParseError::InvalidHeaderName { .. })
        ));
    }

    #[test]
    fn rejects_invalid_header_name_character() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                  Bad@Name: value\r\n\
                  \r\n"
            ),
            Err(ParseError::InvalidHeaderName { .. })
        ));
    }

    #[test]
    fn rejects_header_name_above_operational_limit() {
        let name = "A".repeat(MAX_HEADER_NAME_BYTES + 1);

        let input = format!("OPTIONS sip:a@example.com SIP/2.0\r\n{name}: value\r\n\r\n");

        assert!(matches!(
            parse_bytes(input.as_bytes()),
            Err(ParseError::HeaderNameTooLong {
                length,
                maximum: MAX_HEADER_NAME_BYTES,
            }) if length == MAX_HEADER_NAME_BYTES + 1
        ));
    }

    #[test]
    fn rejects_nul_in_header_value() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                  X-Test: one\x00two\r\n\
                  \r\n"
            ),
            Err(ParseError::InvalidHeaderValueByte { byte: 0x00, .. })
        ));
    }

    #[test]
    fn rejects_del_in_header_value() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                  X-Test: one\x7ftwo\r\n\
                  \r\n"
            ),
            Err(ParseError::InvalidHeaderValueByte { byte: 0x7f, .. })
        ));
    }

    #[test]
    fn accepts_non_utf8_extension_header_value() {
        let mut input = b"OPTIONS sip:a@example.com SIP/2.0\r\nX-Binary: ".to_vec();

        input.extend_from_slice(&[0x80, 0xff]);
        input.extend_from_slice(b"\r\n\r\n");

        let Ok(message) = parse_vec(input) else {
            panic!("expected opaque non-UTF-8 header bytes");
        };

        let Some(header) = message.header(0) else {
            panic!("expected extension header");
        };

        assert_eq!(header.value(), &[b' ', 0x80, 0xff]);
    }

    #[test]
    fn rejects_bare_lf_in_start_line() {
        assert!(matches!(
            parse_bytes(b"OPTIONS sip:a@example.com SIP/2.0\n\r\n"),
            Err(ParseError::InvalidLineEnding { .. })
        ));
    }

    #[test]
    fn rejects_bare_cr_in_start_line() {
        assert!(matches!(
            parse_bytes(b"OPTIONS sip:a@example.com SIP/2.0\rX\r\n"),
            Err(ParseError::InvalidLineEnding { .. })
        ));
    }

    #[test]
    fn rejects_missing_start_line_terminator() {
        assert!(matches!(
            parse_bytes(b"OPTIONS sip:a@example.com SIP/2.0"),
            Err(ParseError::MissingLineTerminator { index: 0 })
        ));
    }

    #[test]
    fn rejects_missing_empty_header_terminator() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                  Via: value\r\n"
            ),
            Err(ParseError::MissingHeaderTerminator)
        ));
    }

    #[test]
    fn rejects_empty_start_line() {
        assert!(matches!(
            parse_bytes(b"\r\n\r\n"),
            Err(ParseError::EmptyStartLine)
        ));
    }

    #[test]
    fn rejects_request_line_without_exact_spaces() {
        assert!(matches!(
            parse_bytes(
                b"OPTIONS  sip:a@example.com SIP/2.0\r\n\
                  \r\n"
            ),
            Err(ParseError::InvalidRequestLine)
        ));

        assert!(matches!(
            parse_bytes(
                b"OPTIONS\tsip:a@example.com SIP/2.0\r\n\
                  \r\n"
            ),
            Err(ParseError::InvalidRequestLine)
        ));
    }

    #[test]
    fn rejects_request_method_with_invalid_token_character() {
        assert!(matches!(
            parse_bytes(
                b"BAD/METHOD sip:a@example.com SIP/2.0\r\n\
                  \r\n"
            ),
            Err(ParseError::InvalidRequestLine)
        ));
    }

    #[test]
    fn rejects_request_method_above_operational_limit() {
        let method = "M".repeat(crate::sip::types::method::MAX_METHOD_BYTES + 1);

        let input = format!("{method} sip:a@example.com SIP/2.0\r\n\r\n");

        assert!(matches!(
            parse_bytes(input.as_bytes()),
            Err(ParseError::InvalidRequestLine)
        ));
    }

    #[test]
    fn request_uri_semantics_are_deferred() {
        let Ok(message) = parse_bytes(b"OPTIONS future-value SIP/2.0\r\n\r\n") else {
            panic!("expected structurally representable request");
        };

        let RawStartLineView::Request(line) = message.start_line_view() else {
            panic!("expected request");
        };

        assert_eq!(line.uri(), b"future-value");
    }

    #[test]
    fn request_version_semantics_are_deferred() {
        let Ok(message) = parse_bytes(b"OPTIONS sip:a@example.com FUTURE/7.4\r\n\r\n") else {
            panic!("expected structurally representable request");
        };

        let RawStartLineView::Request(line) = message.start_line_view() else {
            panic!("expected request");
        };

        assert_eq!(line.version(), b"FUTURE/7.4");
    }

    #[test]
    fn rejects_response_without_status_separator() {
        assert!(matches!(
            parse_bytes(b"SIP/2.0 200\r\n\r\n"),
            Err(ParseError::InvalidResponseLine)
        ));
    }

    #[test]
    fn rejects_response_with_non_three_digit_status() {
        assert!(matches!(
            parse_bytes(b"SIP/2.0 20 OK\r\n\r\n"),
            Err(ParseError::InvalidResponseLine)
        ));

        assert!(matches!(
            parse_bytes(b"SIP/2.0 2000 OK\r\n\r\n"),
            Err(ParseError::InvalidResponseLine)
        ));
    }

    #[test]
    fn rejects_response_with_non_decimal_status() {
        assert!(matches!(
            parse_bytes(b"SIP/2.0 2A0 OK\r\n\r\n"),
            Err(ParseError::InvalidResponseLine)
        ));
    }

    #[test]
    fn response_status_semantics_are_deferred() {
        let Ok(message) = parse_bytes(b"SIP/2.0 999 Extension\r\n\r\n") else {
            panic!("expected structurally valid three-digit status");
        };

        let RawStartLineView::Response(line) = message.start_line_view() else {
            panic!("expected response");
        };

        assert_eq!(line.status(), b"999");
    }

    #[test]
    fn recognizes_response_version_prefix_case_insensitively() {
        let Ok(message) = parse_bytes(b"sip/2.0 200 OK\r\n\r\n") else {
            panic!("expected response classification");
        };

        assert_eq!(message.kind(), MessageKind::Response);
    }

    #[test]
    fn accepts_horizontal_tab_in_reason_phrase() {
        let Ok(message) = parse_bytes(b"SIP/2.0 500 Failure\tDetail\r\n\r\n") else {
            panic!("expected horizontal tab in reason phrase");
        };

        let RawStartLineView::Response(line) = message.start_line_view() else {
            panic!("expected response");
        };

        assert_eq!(line.reason(), b"Failure\tDetail");
    }

    #[test]
    fn rejects_control_byte_in_reason_phrase() {
        assert!(matches!(
            parse_bytes(b"SIP/2.0 500 Failure\x01Detail\r\n\r\n"),
            Err(ParseError::InvalidReasonPhraseByte { byte: 0x01, .. })
        ));
    }

    #[test]
    fn rejects_start_line_above_operational_limit() {
        let uri = "a".repeat(MAX_LINE_BYTES);

        let input = format!("OPTIONS {uri} SIP/2.0\r\n\r\n");

        assert!(matches!(
            parse_bytes(input.as_bytes()),
            Err(ParseError::LineTooLong {
                maximum: MAX_LINE_BYTES,
            })
        ));
    }

    #[test]
    fn rejects_physical_header_line_above_operational_limit() {
        let value = "a".repeat(MAX_LINE_BYTES);

        let input = format!("OPTIONS sip:a@example.com SIP/2.0\r\nX-Test: {value}\r\n\r\n");

        assert!(matches!(
            parse_bytes(input.as_bytes()),
            Err(ParseError::LineTooLong {
                maximum: MAX_LINE_BYTES,
            })
        ));
    }

    #[test]
    fn folded_lines_are_individually_bounded() {
        let value = "a".repeat(MAX_LINE_BYTES);

        let input =
            format!("OPTIONS sip:a@example.com SIP/2.0\r\nX-Test: first\r\n {value}\r\n\r\n");

        assert!(matches!(
            parse_bytes(input.as_bytes()),
            Err(ParseError::LineTooLong {
                maximum: MAX_LINE_BYTES,
            })
        ));
    }

    #[test]
    fn enforces_logical_header_count() {
        let mut input = b"OPTIONS sip:a@example.com SIP/2.0\r\n".to_vec();

        for _ in 0..MAX_HEADER_COUNT {
            input.extend_from_slice(b"X-Test: value\r\n");
        }

        input.extend_from_slice(b"X-Extra: value\r\n\r\n");

        assert!(matches!(
            parse_vec(input),
            Err(ParseError::TooManyHeaders {
                maximum: MAX_HEADER_COUNT,
            })
        ));
    }

    #[test]
    fn folded_continuations_do_not_increase_logical_header_count() {
        let mut input = b"OPTIONS sip:a@example.com SIP/2.0\r\nX-Test: first\r\n".to_vec();

        for _ in 0..32 {
            input.extend_from_slice(b" continuation\r\n");
        }

        input.extend_from_slice(b"\r\n");

        let Ok(message) = parse_vec(input) else {
            panic!("expected one folded logical header");
        };

        assert_eq!(message.header_count(), 1);
    }

    #[test]
    fn preserves_original_message_bytes_exactly() {
        let input = b"OPTIONS sip:a@example.com SIP/2.0\r\n\
                      Subject \t:  exact value \t\r\n\
                      X-Test: two\r\n\
                      \r\n";

        let Ok(message) = parse_bytes(input) else {
            panic!("expected valid message");
        };

        assert_eq!(message.as_bytes(), input);
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::EmptyMessage.class(), "empty-message");

        assert_eq!(
            ParseError::InvalidRequestLine.class(),
            "invalid-request-line"
        );

        assert_eq!(
            ParseError::InvalidResponseLine.class(),
            "invalid-response-line"
        );

        assert_eq!(
            ParseError::MissingHeaderTerminator.class(),
            "missing-header-terminator"
        );

        assert_eq!(
            ParseError::DuplicateContentLength.class(),
            "duplicate-content-length"
        );

        assert_eq!(
            ParseError::InvalidContentLength.class(),
            "invalid-content-length"
        );

        assert_eq!(
            ParseError::ContentLengthMismatch {
                declared: 1,
                actual: 2,
            }
            .class(),
            "content-length-mismatch"
        );

        assert_eq!(
            ParseError::ContinuationWithoutHeader { index: 1 }.class(),
            "continuation-without-header"
        );
    }

    #[test]
    fn nested_metadata_errors_expose_sources() {
        use std::error::Error as _;

        let error =
            ParseError::MetadataLayout(crate::sip::types::message::LayoutError::InvalidHeader);

        assert!(error.source().is_some());
    }
}
