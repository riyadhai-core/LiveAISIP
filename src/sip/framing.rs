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

//! SIP wire-message framing.
//!
//! This module identifies complete SIP messages before full parsing. Framing is
//! allocation-free and applies strict resource bounds before protocol messages
//! enter the parser or transaction layers.
//!
//! Stream and datagram transports intentionally have different completion
//! semantics. Stream messages require an explicit body length, while datagrams
//! can use the packet boundary when no body length is declared.

use std::error::Error as StdError;
use std::fmt;
use std::ops::Range;

/// Maximum accepted length of one physical SIP line, excluding its terminating
/// CRLF.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// Maximum number of logical SIP header fields accepted in one message.
pub const MAX_HEADER_COUNT: usize = 128;

/// Maximum accepted size of the SIP start-line and header section.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Maximum accepted SIP message-body size.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Maximum accepted size of one framed SIP message.
pub const MAX_MESSAGE_BYTES: usize = MAX_HEADER_BYTES + MAX_BODY_BYTES;

/// Transport framing mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Byte-stream transport such as TCP or TLS.
    Stream,

    /// Message-oriented datagram transport such as UDP.
    Datagram,
}

/// Location and size information for one complete SIP message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Boundary {
    message_offset: usize,
    header_bytes: usize,
    body_bytes: usize,
    message_bytes: usize,
    consumed_bytes: usize,
}

impl Boundary {
    /// Returns the offset at which the SIP start-line begins.
    #[must_use]
    pub const fn message_offset(self) -> usize {
        self.message_offset
    }

    /// Returns the number of bytes occupied by the start-line, headers, and
    /// terminating empty line.
    #[must_use]
    pub const fn header_bytes(self) -> usize {
        self.header_bytes
    }

    /// Returns the number of bytes in the SIP message body.
    #[must_use]
    pub const fn body_bytes(self) -> usize {
        self.body_bytes
    }

    /// Returns the complete SIP message size, excluding ignored stream prefix
    /// bytes and discarded datagram trailing bytes.
    #[must_use]
    pub const fn message_bytes(self) -> usize {
        self.message_bytes
    }

    /// Returns the number of input bytes consumed by this framing decision.
    #[must_use]
    pub const fn consumed_bytes(self) -> usize {
        self.consumed_bytes
    }

    /// Returns the byte range containing the complete SIP message.
    #[must_use]
    pub fn message_range(self) -> Range<usize> {
        self.message_offset..self.message_offset + self.message_bytes
    }

    /// Returns the byte range containing the SIP message body.
    #[must_use]
    pub fn body_range(self) -> Range<usize> {
        let body_start = self.message_offset + self.header_bytes;
        body_start..body_start + self.body_bytes
    }

    /// Returns the number of trailing datagram bytes excluded from the declared
    /// SIP message.
    ///
    /// Stream framing returns zero because bytes after the first complete
    /// message remain available for subsequent framing.
    #[must_use]
    pub const fn discarded_trailing_bytes(self) -> usize {
        self.consumed_bytes - (self.message_offset + self.message_bytes)
    }
}

/// Result of inspecting an input buffer for a complete SIP message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// More bytes are required before a complete stream message is available.
    NeedMoreData {
        /// Exact required input size when the header section is already known.
        ///
        /// `None` means the complete header section has not yet arrived.
        required_total: Option<usize>,
    },

    /// One complete SIP message is available.
    Complete(Boundary),
}

/// SIP framing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The SIP header section exceeded its configured bound.
    HeaderTooLarge,

    /// A physical SIP line exceeded its configured bound.
    LineTooLong,

    /// The message contained more logical headers than permitted.
    TooManyHeaders,

    /// The SIP start-line was empty or structurally invalid for framing.
    InvalidStartLine,

    /// A header line was structurally malformed.
    InvalidHeaderSyntax,

    /// A SIP header name contained a byte outside the SIP token grammar.
    InvalidHeaderName,

    /// A line contained an invalid CR or LF sequence.
    InvalidLineEnding,

    /// A stream message did not contain `Content-Length`.
    MissingContentLength,

    /// More than one `Content-Length` field was present.
    DuplicateContentLength,

    /// A `Content-Length` field did not contain a valid decimal length.
    InvalidContentLength,

    /// The decimal `Content-Length` value overflowed `usize`.
    ContentLengthOverflow,

    /// The declared or implicit body exceeded the configured body limit.
    BodyTooLarge,

    /// The complete SIP message exceeded the configured message limit.
    MessageTooLarge,

    /// A datagram ended before the complete declared SIP message was present.
    TruncatedDatagram,
}

impl Error {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::HeaderTooLarge => "header-too-large",
            Self::LineTooLong => "line-too-long",
            Self::TooManyHeaders => "too-many-headers",
            Self::InvalidStartLine => "invalid-start-line",
            Self::InvalidHeaderSyntax => "invalid-header-syntax",
            Self::InvalidHeaderName => "invalid-header-name",
            Self::InvalidLineEnding => "invalid-line-ending",
            Self::MissingContentLength => "missing-content-length",
            Self::DuplicateContentLength => "duplicate-content-length",
            Self::InvalidContentLength => "invalid-content-length",
            Self::ContentLengthOverflow => "content-length-overflow",
            Self::BodyTooLarge => "body-too-large",
            Self::MessageTooLarge => "message-too-large",
            Self::TruncatedDatagram => "truncated-datagram",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::HeaderTooLarge => "SIP header section exceeds the configured limit",
            Self::LineTooLong => "SIP line exceeds the configured limit",
            Self::TooManyHeaders => "SIP message contains too many headers",
            Self::InvalidStartLine => "SIP start-line is invalid",
            Self::InvalidHeaderSyntax => "SIP header syntax is invalid",
            Self::InvalidHeaderName => "SIP header name is invalid",
            Self::InvalidLineEnding => "SIP message contains an invalid line ending",
            Self::MissingContentLength => "stream SIP message is missing Content-Length",
            Self::DuplicateContentLength => "SIP message contains duplicate Content-Length",
            Self::InvalidContentLength => "SIP Content-Length value is invalid",
            Self::ContentLengthOverflow => "SIP Content-Length value overflowed",
            Self::BodyTooLarge => "SIP message body exceeds the configured limit",
            Self::MessageTooLarge => "SIP message exceeds the configured limit",
            Self::TruncatedDatagram => "SIP datagram ended before the complete message",
        };

        formatter.write_str(message)
    }
}

impl StdError for Error {}

/// Inspects an input buffer and determines whether it contains one complete SIP
/// message.
///
/// This function performs framing only. It does not fully parse the SIP
/// start-line, headers, URI, SDP, or message body.
///
/// # Errors
///
/// Returns [`Error`] when framing syntax is malformed, resource limits are
/// exceeded, stream framing lacks a body length, or a datagram is shorter than
/// its declared message size.
pub fn inspect(input: &[u8], mode: Mode) -> Result<Status, Error> {
    let message_offset = match mode {
        Mode::Stream => skip_stream_prefix(input),
        Mode::Datagram => 0,
    };

    if message_offset >= input.len() {
        return incomplete(mode);
    }

    let Some(headers) = scan_headers(input, message_offset, mode)? else {
        return Ok(Status::NeedMoreData {
            required_total: None,
        });
    };

    let body_start = message_offset
        .checked_add(headers.header_bytes)
        .ok_or(Error::MessageTooLarge)?;

    match mode {
        Mode::Stream => inspect_stream(input, message_offset, body_start, headers),
        Mode::Datagram => inspect_datagram(input, message_offset, body_start, headers),
    }
}

#[derive(Clone, Copy, Debug)]
struct HeaderScan {
    header_bytes: usize,
    content_length: Option<usize>,
}

fn inspect_stream(
    input: &[u8],
    message_offset: usize,
    body_start: usize,
    headers: HeaderScan,
) -> Result<Status, Error> {
    let body_bytes = headers.content_length.ok_or(Error::MissingContentLength)?;

    validate_sizes(headers.header_bytes, body_bytes)?;

    let required_total = body_start
        .checked_add(body_bytes)
        .ok_or(Error::MessageTooLarge)?;

    if input.len() < required_total {
        return Ok(Status::NeedMoreData {
            required_total: Some(required_total),
        });
    }

    let message_bytes = headers
        .header_bytes
        .checked_add(body_bytes)
        .ok_or(Error::MessageTooLarge)?;

    Ok(Status::Complete(Boundary {
        message_offset,
        header_bytes: headers.header_bytes,
        body_bytes,
        message_bytes,
        consumed_bytes: required_total,
    }))
}

fn inspect_datagram(
    input: &[u8],
    message_offset: usize,
    body_start: usize,
    headers: HeaderScan,
) -> Result<Status, Error> {
    let available_body = input
        .len()
        .checked_sub(body_start)
        .ok_or(Error::TruncatedDatagram)?;

    let body_bytes = match headers.content_length {
        Some(declared) => {
            if available_body < declared {
                return Err(Error::TruncatedDatagram);
            }

            declared
        }
        None => available_body,
    };

    validate_sizes(headers.header_bytes, body_bytes)?;

    let message_bytes = headers
        .header_bytes
        .checked_add(body_bytes)
        .ok_or(Error::MessageTooLarge)?;

    Ok(Status::Complete(Boundary {
        message_offset,
        header_bytes: headers.header_bytes,
        body_bytes,
        message_bytes,
        consumed_bytes: input.len(),
    }))
}

fn validate_sizes(header_bytes: usize, body_bytes: usize) -> Result<(), Error> {
    if body_bytes > MAX_BODY_BYTES {
        return Err(Error::BodyTooLarge);
    }

    let message_bytes = header_bytes
        .checked_add(body_bytes)
        .ok_or(Error::MessageTooLarge)?;

    if message_bytes > MAX_MESSAGE_BYTES {
        return Err(Error::MessageTooLarge);
    }

    Ok(())
}

fn scan_headers(
    input: &[u8],
    message_offset: usize,
    mode: Mode,
) -> Result<Option<HeaderScan>, Error> {
    let mut position = message_offset;
    let mut first_line = true;
    let mut header_count = 0usize;
    let mut previous_header = false;
    let mut content_length = None;
    let mut active_content_length = None;

    loop {
        let Some(line_end) = find_line_end(input, position)? else {
            enforce_incomplete_limits(input, message_offset, position)?;
            return incomplete_headers(mode);
        };

        let line_bytes = line_end - position;

        if line_bytes > MAX_LINE_BYTES {
            return Err(Error::LineTooLong);
        }

        let after_line = line_end.checked_add(2).ok_or(Error::HeaderTooLarge)?;
        let total_header_bytes = after_line
            .checked_sub(message_offset)
            .ok_or(Error::HeaderTooLarge)?;

        if total_header_bytes > MAX_HEADER_BYTES {
            return Err(Error::HeaderTooLarge);
        }

        let line = &input[position..line_end];

        if first_line {
            validate_start_line(line)?;
            first_line = false;
            position = after_line;
            continue;
        }

        if line.is_empty() {
            finalize_content_length(&mut active_content_length, &mut content_length)?;

            return Ok(Some(HeaderScan {
                header_bytes: total_header_bytes,
                content_length,
            }));
        }

        if matches!(line.first(), Some(b' ' | b'\t')) {
            if !previous_header {
                return Err(Error::InvalidHeaderSyntax);
            }

            if let Some(parser) = active_content_length.as_mut() {
                parser.push(line)?;
            }

            position = after_line;
            continue;
        }

        finalize_content_length(&mut active_content_length, &mut content_length)?;

        header_count = header_count.checked_add(1).ok_or(Error::TooManyHeaders)?;

        if header_count > MAX_HEADER_COUNT {
            return Err(Error::TooManyHeaders);
        }

        let (name, value) = split_header(line)?;

        if is_content_length_name(name) {
            if content_length.is_some() {
                return Err(Error::DuplicateContentLength);
            }

            let mut parser = ContentLengthParser::new();
            parser.push(value)?;
            active_content_length = Some(parser);
        }

        previous_header = true;
        position = after_line;
    }
}

fn finalize_content_length(
    active: &mut Option<ContentLengthParser>,
    content_length: &mut Option<usize>,
) -> Result<(), Error> {
    let Some(parser) = active.take() else {
        return Ok(());
    };

    if content_length.is_some() {
        return Err(Error::DuplicateContentLength);
    }

    *content_length = Some(parser.finish()?);
    Ok(())
}

fn split_header(line: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return Err(Error::InvalidHeaderSyntax);
    };

    let name = trim_trailing_whitespace(&line[..colon]);

    if name.is_empty() {
        return Err(Error::InvalidHeaderName);
    }

    if !name.iter().copied().all(is_token_byte) {
        return Err(Error::InvalidHeaderName);
    }

    Ok((name, &line[colon + 1..]))
}

fn validate_start_line(line: &[u8]) -> Result<(), Error> {
    if line.is_empty() || matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(Error::InvalidStartLine);
    }

    Ok(())
}

fn find_line_end(input: &[u8], start: usize) -> Result<Option<usize>, Error> {
    let mut index = start;

    while index < input.len() {
        match input[index] {
            b'\r' => {
                let next = index.checked_add(1).ok_or(Error::InvalidLineEnding)?;

                if next >= input.len() {
                    return Ok(None);
                }

                if input[next] != b'\n' {
                    return Err(Error::InvalidLineEnding);
                }

                return Ok(Some(index));
            }
            b'\n' => return Err(Error::InvalidLineEnding),
            _ => {
                index += 1;
            }
        }
    }

    Ok(None)
}

fn enforce_incomplete_limits(
    input: &[u8],
    message_offset: usize,
    line_start: usize,
) -> Result<(), Error> {
    let current_line_bytes = input.len().saturating_sub(line_start);

    if current_line_bytes > MAX_LINE_BYTES {
        return Err(Error::LineTooLong);
    }

    let current_header_bytes = input.len().saturating_sub(message_offset);

    if current_header_bytes > MAX_HEADER_BYTES {
        return Err(Error::HeaderTooLarge);
    }

    Ok(())
}

fn incomplete_headers(mode: Mode) -> Result<Option<HeaderScan>, Error> {
    match mode {
        Mode::Stream => Ok(None),
        Mode::Datagram => Err(Error::TruncatedDatagram),
    }
}

fn incomplete(mode: Mode) -> Result<Status, Error> {
    match mode {
        Mode::Stream => Ok(Status::NeedMoreData {
            required_total: None,
        }),
        Mode::Datagram => Err(Error::TruncatedDatagram),
    }
}

fn skip_stream_prefix(input: &[u8]) -> usize {
    let mut offset = 0usize;

    while input.get(offset..offset + 2) == Some(b"\r\n") {
        offset += 2;
    }

    offset
}

fn trim_trailing_whitespace(mut input: &[u8]) -> &[u8] {
    while matches!(input.last(), Some(b' ' | b'\t')) {
        input = &input[..input.len() - 1];
    }

    input
}

fn is_content_length_name(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"Content-Length") || name.eq_ignore_ascii_case(b"l")
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

#[derive(Clone, Copy, Debug)]
struct ContentLengthParser {
    value: usize,
    saw_digit: bool,
    trailing_whitespace: bool,
}

impl ContentLengthParser {
    const fn new() -> Self {
        Self {
            value: 0,
            saw_digit: false,
            trailing_whitespace: false,
        }
    }

    fn push(&mut self, input: &[u8]) -> Result<(), Error> {
        for byte in input.iter().copied() {
            match byte {
                b'0'..=b'9' => {
                    if self.trailing_whitespace {
                        return Err(Error::InvalidContentLength);
                    }

                    self.saw_digit = true;

                    self.value = self
                        .value
                        .checked_mul(10)
                        .and_then(|value| value.checked_add(usize::from(byte - b'0')))
                        .ok_or(Error::ContentLengthOverflow)?;
                }
                b' ' | b'\t' => {
                    if self.saw_digit {
                        self.trailing_whitespace = true;
                    }
                }
                _ => return Err(Error::InvalidContentLength),
            }
        }

        Ok(())
    }

    fn finish(self) -> Result<usize, Error> {
        if !self.saw_digit {
            return Err(Error::InvalidContentLength);
        }

        Ok(self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, MAX_BODY_BYTES, Mode, Status, inspect};

    #[test]
    fn frames_complete_stream_message() {
        let input = b"OPTIONS sip:example.com SIP/2.0\r\nContent-Length: 4\r\n\r\ntest";

        let Ok(Status::Complete(boundary)) = inspect(input, Mode::Stream) else {
            panic!("expected complete stream message");
        };

        assert_eq!(boundary.message_offset(), 0);
        assert_eq!(boundary.body_bytes(), 4);
        assert_eq!(&input[boundary.body_range()], b"test");
        assert_eq!(boundary.consumed_bytes(), input.len());
    }

    #[test]
    fn stream_ignores_leading_crlf() {
        let input = b"\r\n\r\nOPTIONS sip:example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";

        let Ok(Status::Complete(boundary)) = inspect(input, Mode::Stream) else {
            panic!("expected complete stream message");
        };

        assert_eq!(boundary.message_offset(), 4);
        assert_eq!(
            &input[boundary.message_range()],
            b"OPTIONS sip:example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn stream_requires_content_length() {
        let input = b"OPTIONS sip:example.com SIP/2.0\r\nVia: SIP/2.0/TCP host\r\n\r\n";

        assert_eq!(
            inspect(input, Mode::Stream),
            Err(Error::MissingContentLength)
        );
    }

    #[test]
    fn incomplete_stream_body_reports_required_total() {
        let input = b"INVITE sip:user@example.com SIP/2.0\r\nContent-Length: 8\r\n\r\nabc";

        let Ok(Status::NeedMoreData {
            required_total: Some(required_total),
        }) = inspect(input, Mode::Stream)
        else {
            panic!("expected incomplete stream body");
        };

        assert_eq!(required_total, input.len() + 5);
    }

    #[test]
    fn stream_consumes_only_first_message() {
        let first = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let second = b"OPTIONS sip:b SIP/2.0\r\nContent-Length: 0\r\n\r\n";

        let mut input = Vec::from(first.as_slice());
        input.extend_from_slice(second);

        let Ok(Status::Complete(boundary)) = inspect(&input, Mode::Stream) else {
            panic!("expected first complete stream message");
        };

        assert_eq!(boundary.consumed_bytes(), first.len());
        assert_eq!(&input[boundary.message_range()], first);
    }

    #[test]
    fn datagram_without_content_length_uses_packet_boundary() {
        let input =
            b"MESSAGE sip:user@example.com SIP/2.0\r\nContent-Type: text/plain\r\n\r\nhello";

        let Ok(Status::Complete(boundary)) = inspect(input, Mode::Datagram) else {
            panic!("expected complete datagram");
        };

        assert_eq!(boundary.body_bytes(), 5);
        assert_eq!(&input[boundary.body_range()], b"hello");
        assert_eq!(boundary.discarded_trailing_bytes(), 0);
    }

    #[test]
    fn datagram_discards_bytes_after_declared_body() {
        let input = b"MESSAGE sip:user@example.com SIP/2.0\r\nContent-Length: 5\r\n\r\nhelloEXTRA";

        let Ok(Status::Complete(boundary)) = inspect(input, Mode::Datagram) else {
            panic!("expected complete datagram");
        };

        assert_eq!(&input[boundary.body_range()], b"hello");
        assert_eq!(boundary.discarded_trailing_bytes(), 5);
        assert_eq!(boundary.consumed_bytes(), input.len());
    }

    #[test]
    fn truncated_declared_datagram_is_rejected() {
        let input = b"MESSAGE sip:user@example.com SIP/2.0\r\nContent-Length: 10\r\n\r\nshort";

        assert_eq!(
            inspect(input, Mode::Datagram),
            Err(Error::TruncatedDatagram)
        );
    }

    #[test]
    fn compact_content_length_is_supported() {
        let input = b"OPTIONS sip:example.com SIP/2.0\r\nl: 0\r\n\r\n";

        let Ok(Status::Complete(boundary)) = inspect(input, Mode::Stream) else {
            panic!("expected compact Content-Length to frame");
        };

        assert_eq!(boundary.body_bytes(), 0);
    }

    #[test]
    fn content_length_name_is_case_insensitive() {
        let input = b"OPTIONS sip:example.com SIP/2.0\r\ncOnTeNt-LeNgTh: 0\r\n\r\n";

        assert!(matches!(
            inspect(input, Mode::Stream),
            Ok(Status::Complete(_))
        ));
    }

    #[test]
    fn duplicate_content_length_is_rejected() {
        let input = b"OPTIONS sip:example.com SIP/2.0\r\nContent-Length: 0\r\nl: 0\r\n\r\n";

        assert_eq!(
            inspect(input, Mode::Stream),
            Err(Error::DuplicateContentLength)
        );
    }

    #[test]
    fn malformed_content_length_is_rejected() {
        let input = b"OPTIONS sip:example.com SIP/2.0\r\nContent-Length: four\r\n\r\n";

        assert_eq!(
            inspect(input, Mode::Stream),
            Err(Error::InvalidContentLength)
        );
    }

    #[test]
    fn folded_content_length_is_supported() {
        let input = b"MESSAGE sip:user@example.com SIP/2.0\r\nContent-Length:\r\n 5\r\n\r\nhello";

        let Ok(Status::Complete(boundary)) = inspect(input, Mode::Stream) else {
            panic!("expected folded Content-Length to frame");
        };

        assert_eq!(boundary.body_bytes(), 5);
    }

    #[test]
    fn orphan_header_continuation_is_rejected() {
        let input =
            b"OPTIONS sip:example.com SIP/2.0\r\n continuation\r\nContent-Length: 0\r\n\r\n";

        assert_eq!(
            inspect(input, Mode::Stream),
            Err(Error::InvalidHeaderSyntax)
        );
    }

    #[test]
    fn lone_lf_is_rejected() {
        let input = b"OPTIONS sip:example.com SIP/2.0\nContent-Length: 0\r\n\r\n";

        assert_eq!(inspect(input, Mode::Stream), Err(Error::InvalidLineEnding));
    }

    #[test]
    fn oversized_declared_body_is_rejected() {
        let body_length = MAX_BODY_BYTES + 1;
        let input = format!(
            "MESSAGE sip:user@example.com SIP/2.0\r\nContent-Length: {body_length}\r\n\r\n"
        );

        assert_eq!(
            inspect(input.as_bytes(), Mode::Stream),
            Err(Error::BodyTooLarge)
        );
    }

    #[test]
    fn message_range_excludes_stream_keepalive_prefix() {
        let input = b"\r\nOPTIONS sip:example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";

        let Ok(Status::Complete(boundary)) = inspect(input, Mode::Stream) else {
            panic!("expected complete stream message");
        };

        assert_eq!(boundary.message_offset(), 2);
        assert_eq!(
            &input[boundary.message_range()],
            b"OPTIONS sip:example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n"
        );
    }
}
