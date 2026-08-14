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

//! Lossless structural SIP message representation.
//!
//! This module defines the immutable representation produced by the structural
//! SIP message parser.
//!
//! One reference-counted byte buffer owns the complete framed SIP message.
//! Start-line components, header names, header values, and the body are
//! represented by compact spans into that buffer. This avoids allocating and
//! copying a separate string or byte vector for every header.
//!
//! Structural representation is deliberately distinct from typed semantic
//! interpretation:
//!
//! - structural parsing answers whether bytes can be represented safely and
//!   unambiguously;
//! - typed header parsers interpret individual SIP constructs;
//! - message validation and policy decide whether those constructs are
//!   acceptable for a particular SIP operation.
//!
//! Header ordering, duplicate headers, unknown extension headers, original
//! header-name spelling, raw field values, and complete message bytes are
//! preserved.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use super::header::HeaderKind;

/// Maximum byte length accepted by the raw structural message representation.
///
/// This is intentionally the same bound enforced by the SIP framer so the
/// structural representation cannot admit a message that the framing layer
/// itself would reject.
pub const MAX_RAW_MESSAGE_BYTES: usize = crate::sip::framing::MAX_MESSAGE_BYTES;

/// Maximum number of headers retained by one structural SIP message.
///
/// This is intentionally the same bound enforced by the SIP framer.
pub const MAX_RAW_HEADER_COUNT: usize = crate::sip::framing::MAX_HEADER_COUNT;

/// A compact half-open byte span into a SIP message buffer.
///
/// Spans use `u32` offsets because the configured `LiveAISIP` SIP message
/// bounds are far below the representable range. Using compact offsets keeps
/// per-header structural metadata small on 64-bit hosts.
///
/// A span represents bytes in the range `start..end`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Span {
    start: u32,
    end: u32,
}

impl Span {
    /// Creates a byte span.
    ///
    /// # Errors
    ///
    /// Returns [`SpanError::Reversed`] when `start > end`, or
    /// [`SpanError::OffsetTooLarge`] when either offset cannot be represented
    /// by the compact `u32` storage format.
    pub fn new(start: usize, end: usize) -> Result<Self, SpanError> {
        if start > end {
            return Err(SpanError::Reversed { start, end });
        }

        let start = u32::try_from(start).map_err(|_| SpanError::OffsetTooLarge { value: start })?;

        let end = u32::try_from(end).map_err(|_| SpanError::OffsetTooLarge { value: end })?;

        Ok(Self { start, end })
    }

    /// Returns the first byte offset.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start as usize
    }

    /// Returns the exclusive final byte offset.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end as usize
    }

    /// Returns the span length in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end() - self.start()
    }

    /// Returns whether this span contains zero bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// Returns whether `other` is fully contained by this span.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    /// Returns whether this span ends before or exactly where `other` starts.
    #[must_use]
    pub const fn precedes(self, other: Self) -> bool {
        self.end <= other.start
    }

    /// Resolves the span against an arbitrary byte slice.
    ///
    /// `None` is returned when this span does not fit inside `bytes`.
    #[must_use]
    pub fn get(self, bytes: &[u8]) -> Option<&[u8]> {
        bytes.get(self.start()..self.end())
    }
}

/// Failure to construct a compact [`Span`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SpanError {
    /// The start offset was greater than the end offset.
    Reversed {
        /// Requested start offset.
        start: usize,

        /// Requested end offset.
        end: usize,
    },

    /// An offset exceeded the compact span representation.
    OffsetTooLarge {
        /// Offset that could not be represented.
        value: usize,
    },
}

impl SpanError {
    /// Returns a stable low-cardinality error classification.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Reversed { .. } => "reversed",
            Self::OffsetTooLarge { .. } => "offset-too-large",
        }
    }
}

impl fmt::Display for SpanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reversed { start, end } => {
                write!(
                    formatter,
                    "SIP byte span start {start} is greater than end {end}"
                )
            }
            Self::OffsetTooLarge { value } => {
                write!(
                    formatter,
                    "SIP byte offset {value} exceeds compact span capacity"
                )
            }
        }
    }
}

impl StdError for SpanError {}

/// Structural kind of a SIP message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    /// SIP request message.
    Request,

    /// SIP response message.
    Response,
}

/// Structural metadata for a SIP request line.
///
/// The spans identify the complete start line and its method, request URI, and
/// SIP-version components. The byte contents remain in the owning
/// [`RawMessage`] buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawRequestLine {
    line: Span,
    method: Span,
    uri: Span,
    version: Span,
}

impl RawRequestLine {
    /// Creates validated structural request-line metadata.
    ///
    /// # Errors
    ///
    /// Returns [`LayoutError::InvalidRequestLine`] when the line is empty,
    /// component spans fall outside the complete line, a required component is
    /// empty, or the components are not in wire order with separators between
    /// them.
    pub fn new(line: Span, method: Span, uri: Span, version: Span) -> Result<Self, LayoutError> {
        if line.is_empty()
            || method.is_empty()
            || uri.is_empty()
            || version.is_empty()
            || !line.contains(method)
            || !line.contains(uri)
            || !line.contains(version)
            || method.end() >= uri.start()
            || uri.end() >= version.start()
        {
            return Err(LayoutError::InvalidRequestLine);
        }

        Ok(Self {
            line,
            method,
            uri,
            version,
        })
    }

    /// Returns the complete request-line span excluding its trailing CRLF.
    #[must_use]
    pub const fn line_span(self) -> Span {
        self.line
    }

    /// Returns the method-token span.
    #[must_use]
    pub const fn method_span(self) -> Span {
        self.method
    }

    /// Returns the request-URI span.
    #[must_use]
    pub const fn uri_span(self) -> Span {
        self.uri
    }

    /// Returns the SIP-version span.
    #[must_use]
    pub const fn version_span(self) -> Span {
        self.version
    }
}

/// Structural metadata for a SIP response status line.
///
/// The spans identify the complete status line and its SIP version, status
/// code, and reason phrase. The reason phrase is allowed to be empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawResponseLine {
    line: Span,
    version: Span,
    status: Span,
    reason: Span,
}

impl RawResponseLine {
    /// Creates validated structural response-line metadata.
    ///
    /// # Errors
    ///
    /// Returns [`LayoutError::InvalidResponseLine`] when required components
    /// are empty, component spans fall outside the complete line, or the
    /// components are not in wire order with required separators.
    pub fn new(line: Span, version: Span, status: Span, reason: Span) -> Result<Self, LayoutError> {
        if line.is_empty()
            || version.is_empty()
            || status.is_empty()
            || !line.contains(version)
            || !line.contains(status)
            || !line.contains(reason)
            || version.end() >= status.start()
            || status.end() >= reason.start()
        {
            return Err(LayoutError::InvalidResponseLine);
        }

        Ok(Self {
            line,
            version,
            status,
            reason,
        })
    }

    /// Returns the complete status-line span excluding its trailing CRLF.
    #[must_use]
    pub const fn line_span(self) -> Span {
        self.line
    }

    /// Returns the SIP-version span.
    #[must_use]
    pub const fn version_span(self) -> Span {
        self.version
    }

    /// Returns the three-digit status-code span.
    #[must_use]
    pub const fn status_span(self) -> Span {
        self.status
    }

    /// Returns the reason-phrase span.
    ///
    /// The span may be empty.
    #[must_use]
    pub const fn reason_span(self) -> Span {
        self.reason
    }
}

/// Structural SIP start-line metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawStartLine {
    /// SIP request line.
    Request(RawRequestLine),

    /// SIP response status line.
    Response(RawResponseLine),
}

impl RawStartLine {
    /// Returns whether this is a request or response.
    #[must_use]
    pub const fn kind(self) -> MessageKind {
        match self {
            Self::Request(_) => MessageKind::Request,
            Self::Response(_) => MessageKind::Response,
        }
    }

    /// Returns the complete start-line span excluding trailing CRLF.
    #[must_use]
    pub const fn line_span(self) -> Span {
        match self {
            Self::Request(line) => line.line_span(),
            Self::Response(line) => line.line_span(),
        }
    }

    /// Returns request-line metadata when this is a request.
    #[must_use]
    pub const fn as_request(self) -> Option<RawRequestLine> {
        match self {
            Self::Request(line) => Some(line),
            Self::Response(_) => None,
        }
    }

    /// Returns response-line metadata when this is a response.
    #[must_use]
    pub const fn as_response(self) -> Option<RawResponseLine> {
        match self {
            Self::Response(line) => Some(line),
            Self::Request(_) => None,
        }
    }
}

/// Structural metadata for one SIP header field.
///
/// Both the original header-name bytes and the complete raw field-value bytes
/// are retained as spans. The value span starts immediately after the colon
/// and extends to the byte before CRLF, so original leading and trailing
/// horizontal whitespace is preserved.
///
/// `kind` is only a classification optimization. It does not replace the raw
/// header-name bytes and therefore does not destroy original spelling or
/// compact-header representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawHeader {
    name: Span,
    value: Span,
    kind: Option<HeaderKind>,
}

impl RawHeader {
    /// Creates structural header metadata.
    ///
    /// # Errors
    ///
    /// Returns [`LayoutError::InvalidHeader`] when the header-name span is
    /// empty or there is no room between the name and value spans for the
    /// required colon delimiter.
    pub fn new(name: Span, value: Span, kind: Option<HeaderKind>) -> Result<Self, LayoutError> {
        if name.is_empty() || name.end() >= value.start() {
            return Err(LayoutError::InvalidHeader);
        }

        Ok(Self { name, value, kind })
    }

    /// Returns the original header-name span.
    #[must_use]
    pub const fn name_span(&self) -> Span {
        self.name
    }

    /// Returns the complete raw field-value span.
    ///
    /// Leading and trailing horizontal whitespace after the colon is retained.
    #[must_use]
    pub const fn value_span(&self) -> Span {
        self.value
    }

    /// Returns the complete header-line span excluding trailing CRLF.
    ///
    /// Because the name and value refer to the original shared byte buffer,
    /// bytes between the spans include the colon and any surrounding
    /// whitespace exactly as received.
    #[must_use]
    pub const fn line_span(&self) -> Span {
        Span {
            start: self.name.start,
            end: self.value.end,
        }
    }

    /// Returns the recognized header kind when known.
    ///
    /// `None` means the header is an extension or otherwise not classified by
    /// the current `LiveAISIP` header registry. Its original name remains
    /// available through [`RawHeader::name_span`].
    #[must_use]
    pub const fn kind(&self) -> Option<&HeaderKind> {
        self.kind.as_ref()
    }

    /// Returns whether the header is currently classified as a known header.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        self.kind.is_some()
    }
}

/// Failure to construct structural metadata before it is attached to a
/// concrete message buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LayoutError {
    /// Request-line component spans were inconsistent.
    InvalidRequestLine,

    /// Response-line component spans were inconsistent.
    InvalidResponseLine,

    /// Header name/value spans were inconsistent.
    InvalidHeader,
}

impl LayoutError {
    /// Returns a stable low-cardinality error classification.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::InvalidRequestLine => "invalid-request-line",
            Self::InvalidResponseLine => "invalid-response-line",
            Self::InvalidHeader => "invalid-header",
        }
    }
}

impl fmt::Display for LayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestLine => {
                formatter.write_str("invalid structural SIP request-line layout")
            }
            Self::InvalidResponseLine => {
                formatter.write_str("invalid structural SIP response-line layout")
            }
            Self::InvalidHeader => formatter.write_str("invalid structural SIP header layout"),
        }
    }
}

impl StdError for LayoutError {}

/// Immutable lossless structural representation of one framed SIP message.
///
/// A `RawMessage` owns exactly one framed SIP message. There are no trailing
/// bytes from a subsequent stream message. Header metadata preserves wire
/// order and duplicates.
///
/// This type does not claim that typed SIP semantics are valid. That belongs
/// to the typed parser and validation layers.
#[derive(Clone)]
pub struct RawMessage {
    bytes: Arc<[u8]>,
    start_line: RawStartLine,
    headers: Vec<RawHeader>,
    body: Span,
}

impl RawMessage {
    /// Creates a structural SIP message from one owned backing buffer.
    ///
    /// This constructor validates metadata containment, header ordering,
    /// message-size limits, header-count limits, body placement, and that the
    /// body terminates exactly at the end of the backing buffer.
    ///
    /// It does not parse SIP grammar or inspect field semantics.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when structural metadata is inconsistent with
    /// the supplied backing buffer.
    pub fn new(
        bytes: Arc<[u8]>,
        start_line: RawStartLine,
        headers: Vec<RawHeader>,
        body: Span,
    ) -> Result<Self, BuildError> {
        let length = bytes.len();

        if length == 0 {
            return Err(BuildError::EmptyBuffer);
        }

        if length > MAX_RAW_MESSAGE_BYTES {
            return Err(BuildError::MessageTooLarge {
                length,
                maximum: MAX_RAW_MESSAGE_BYTES,
            });
        }

        if headers.len() > MAX_RAW_HEADER_COUNT {
            return Err(BuildError::TooManyHeaders {
                maximum: MAX_RAW_HEADER_COUNT,
            });
        }

        let start_line_span = start_line.line_span();

        if start_line_span.start() != 0 {
            return Err(BuildError::StartLineNotAtZero);
        }

        if start_line_span.end() > length {
            return Err(BuildError::StartLineOutOfBounds);
        }

        if body.end() > length {
            return Err(BuildError::BodyOutOfBounds);
        }

        if body.end() != length {
            return Err(BuildError::BodyNotTerminal);
        }

        let mut previous_end = start_line_span.end();

        for (index, header) in headers.iter().enumerate() {
            let line = header.line_span();

            if line.end() > length {
                return Err(BuildError::HeaderOutOfBounds { index });
            }

            if line.start() < previous_end {
                return Err(BuildError::HeadersOutOfOrder { index });
            }

            previous_end = line.end();
        }

        if body.start() < previous_end {
            return Err(BuildError::BodyBeforeHeaders);
        }

        Ok(Self {
            bytes,
            start_line,
            headers,
            body,
        })
    }

    /// Creates a structural message while transferring ownership of a byte
    /// vector into the shared immutable backing storage.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] under the same conditions as [`RawMessage::new`].
    pub fn from_vec(
        bytes: Vec<u8>,
        start_line: RawStartLine,
        headers: Vec<RawHeader>,
        body: Span,
    ) -> Result<Self, BuildError> {
        Self::new(Arc::from(bytes), start_line, headers, body)
    }

    /// Returns whether this is a SIP request or response.
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        self.start_line.kind()
    }

    /// Returns the complete immutable framed SIP message bytes.
    ///
    /// These are the original message bytes, not a canonical serialization.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the message byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the backing message buffer is empty.
    ///
    /// Successfully constructed values always return `false`; this method is
    /// provided alongside [`RawMessage::len`] for conventional collection-like
    /// API symmetry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns structural start-line metadata.
    #[must_use]
    pub const fn start_line(&self) -> RawStartLine {
        self.start_line
    }

    /// Returns the original complete start-line bytes, excluding CRLF.
    #[must_use]
    pub fn start_line_bytes(&self) -> &[u8] {
        self.slice(self.start_line.line_span())
    }

    /// Returns a zero-allocation view over the start-line components.
    #[must_use]
    pub fn start_line_view(&self) -> RawStartLineView<'_> {
        match self.start_line {
            RawStartLine::Request(line) => RawStartLineView::Request(RawRequestLineView {
                line: self.slice(line.line_span()),
                method: self.slice(line.method_span()),
                uri: self.slice(line.uri_span()),
                version: self.slice(line.version_span()),
            }),
            RawStartLine::Response(line) => RawStartLineView::Response(RawResponseLineView {
                line: self.slice(line.line_span()),
                version: self.slice(line.version_span()),
                status: self.slice(line.status_span()),
                reason: self.slice(line.reason_span()),
            }),
        }
    }

    /// Returns structural header metadata in original wire order.
    #[must_use]
    pub fn headers(&self) -> &[RawHeader] {
        &self.headers
    }

    /// Returns the number of header fields.
    #[must_use]
    pub fn header_count(&self) -> usize {
        self.headers.len()
    }

    /// Returns a zero-allocation header view by wire-order index.
    #[must_use]
    pub fn header(&self, index: usize) -> Option<RawHeaderView<'_>> {
        let metadata = self.headers.get(index)?;

        Some(RawHeaderView {
            metadata,
            bytes: &self.bytes,
        })
    }

    /// Iterates over zero-allocation header views in original wire order.
    pub fn header_views(&self) -> impl Iterator<Item = RawHeaderView<'_>> {
        self.headers.iter().map(|metadata| RawHeaderView {
            metadata,
            bytes: &self.bytes,
        })
    }

    /// Returns the exact body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.slice(self.body)
    }

    /// Returns the body span.
    #[must_use]
    pub const fn body_span(&self) -> Span {
        self.body
    }

    /// Consumes the structural message and returns its immutable backing bytes.
    #[must_use]
    pub fn into_bytes(self) -> Arc<[u8]> {
        self.bytes
    }

    fn slice(&self, span: Span) -> &[u8] {
        &self.bytes[span.start()..span.end()]
    }
}

impl fmt::Debug for RawMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawMessage")
            .field("kind", &self.kind())
            .field("message_bytes", &self.bytes.len())
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            // Raw SIP contents are intentionally omitted because signaling
            // headers and bodies can contain credentials, identities, tokens,
            // telephone numbers, and other sensitive data.
            .finish_non_exhaustive()
    }
}

/// Zero-allocation borrowed view of one raw SIP header.
///
/// The view exposes exact wire bytes while keeping ownership in the enclosing
/// [`RawMessage`].
#[derive(Clone, Copy)]
pub struct RawHeaderView<'a> {
    metadata: &'a RawHeader,
    bytes: &'a [u8],
}

impl<'a> RawHeaderView<'a> {
    /// Returns the original header-name bytes.
    #[must_use]
    pub fn name(self) -> &'a [u8] {
        &self.bytes[self.metadata.name.start()..self.metadata.name.end()]
    }

    /// Returns the complete raw field-value bytes after the colon.
    ///
    /// Leading and trailing horizontal whitespace is preserved.
    #[must_use]
    pub fn value(self) -> &'a [u8] {
        &self.bytes[self.metadata.value.start()..self.metadata.value.end()]
    }

    /// Returns the original header line excluding trailing CRLF.
    #[must_use]
    pub fn line(self) -> &'a [u8] {
        let span = self.metadata.line_span();

        &self.bytes[span.start()..span.end()]
    }

    /// Returns the recognized header classification when known.
    #[must_use]
    pub const fn kind(self) -> Option<&'a HeaderKind> {
        self.metadata.kind()
    }

    /// Returns the underlying structural metadata.
    #[must_use]
    pub const fn metadata(self) -> &'a RawHeader {
        self.metadata
    }
}

/// Borrowed zero-allocation view over a SIP start line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawStartLineView<'a> {
    /// SIP request-line view.
    Request(RawRequestLineView<'a>),

    /// SIP response status-line view.
    Response(RawResponseLineView<'a>),
}

/// Borrowed zero-allocation view over a SIP request line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawRequestLineView<'a> {
    line: &'a [u8],
    method: &'a [u8],
    uri: &'a [u8],
    version: &'a [u8],
}

impl<'a> RawRequestLineView<'a> {
    /// Returns the complete request-line bytes excluding CRLF.
    #[must_use]
    pub const fn line(self) -> &'a [u8] {
        self.line
    }

    /// Returns the raw method token.
    #[must_use]
    pub const fn method(self) -> &'a [u8] {
        self.method
    }

    /// Returns the raw request URI.
    #[must_use]
    pub const fn uri(self) -> &'a [u8] {
        self.uri
    }

    /// Returns the raw SIP version.
    #[must_use]
    pub const fn version(self) -> &'a [u8] {
        self.version
    }
}

/// Borrowed zero-allocation view over a SIP response status line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawResponseLineView<'a> {
    line: &'a [u8],
    version: &'a [u8],
    status: &'a [u8],
    reason: &'a [u8],
}

impl<'a> RawResponseLineView<'a> {
    /// Returns the complete status-line bytes excluding CRLF.
    #[must_use]
    pub const fn line(self) -> &'a [u8] {
        self.line
    }

    /// Returns the raw SIP version.
    #[must_use]
    pub const fn version(self) -> &'a [u8] {
        self.version
    }

    /// Returns the raw status-code bytes.
    #[must_use]
    pub const fn status(self) -> &'a [u8] {
        self.status
    }

    /// Returns the raw reason phrase.
    ///
    /// The returned slice may be empty.
    #[must_use]
    pub const fn reason(self) -> &'a [u8] {
        self.reason
    }
}

/// Failure to attach structural metadata to a concrete framed SIP message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    /// The backing message buffer was empty.
    EmptyBuffer,

    /// The backing message exceeded the framing-layer message bound.
    MessageTooLarge {
        /// Actual message size in bytes.
        length: usize,

        /// Maximum accepted message size.
        maximum: usize,
    },

    /// The start line did not begin at byte zero.
    StartLineNotAtZero,

    /// The start-line span exceeded the backing buffer.
    StartLineOutOfBounds,

    /// The message contained too many headers.
    TooManyHeaders {
        /// Maximum accepted header count.
        maximum: usize,
    },

    /// A header span exceeded the backing buffer.
    HeaderOutOfBounds {
        /// Header index in wire order.
        index: usize,
    },

    /// Header metadata was not ordered according to the wire representation.
    HeadersOutOfOrder {
        /// First header index found out of order.
        index: usize,
    },

    /// The body span exceeded the backing buffer.
    BodyOutOfBounds,

    /// The body began before the structural header section ended.
    BodyBeforeHeaders,

    /// The body did not terminate exactly at the end of the backing message.
    BodyNotTerminal,
}

impl BuildError {
    /// Returns a stable low-cardinality error classification.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::EmptyBuffer => "empty-buffer",
            Self::MessageTooLarge { .. } => "message-too-large",
            Self::StartLineNotAtZero => "start-line-not-at-zero",
            Self::StartLineOutOfBounds => "start-line-out-of-bounds",
            Self::TooManyHeaders { .. } => "too-many-headers",
            Self::HeaderOutOfBounds { .. } => "header-out-of-bounds",
            Self::HeadersOutOfOrder { .. } => "headers-out-of-order",
            Self::BodyOutOfBounds => "body-out-of-bounds",
            Self::BodyBeforeHeaders => "body-before-headers",
            Self::BodyNotTerminal => "body-not-terminal",
        }
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBuffer => formatter.write_str("structural SIP message buffer is empty"),
            Self::MessageTooLarge { length, maximum } => write!(
                formatter,
                "structural SIP message length {length} exceeds maximum {maximum}"
            ),
            Self::StartLineNotAtZero => {
                formatter.write_str("structural SIP start line does not begin at byte zero")
            }
            Self::StartLineOutOfBounds => {
                formatter.write_str("structural SIP start line exceeds message buffer")
            }
            Self::TooManyHeaders { maximum } => {
                write!(
                    formatter,
                    "structural SIP message contains more than {maximum} headers"
                )
            }
            Self::HeaderOutOfBounds { index } => {
                write!(
                    formatter,
                    "structural SIP header at index {index} exceeds message buffer"
                )
            }
            Self::HeadersOutOfOrder { index } => {
                write!(
                    formatter,
                    "structural SIP header at index {index} is out of wire order"
                )
            }
            Self::BodyOutOfBounds => {
                formatter.write_str("structural SIP body exceeds message buffer")
            }
            Self::BodyBeforeHeaders => {
                formatter.write_str("structural SIP body begins before headers end")
            }
            Self::BodyNotTerminal => {
                formatter.write_str("structural SIP body does not terminate at message end")
            }
        }
    }
}

impl StdError for BuildError {}

#[cfg(test)]
mod tests {
    use super::{
        BuildError, LayoutError, MAX_RAW_HEADER_COUNT, MessageKind, RawHeader, RawMessage,
        RawRequestLine, RawResponseLine, RawStartLine, RawStartLineView, Span, SpanError,
    };
    use crate::sip::types::header::HeaderKind;
    use std::mem::size_of;
    use std::sync::Arc;

    fn span(start: usize, end: usize) -> Span {
        let Ok(span) = Span::new(start, end) else {
            panic!("expected valid test span");
        };

        span
    }

    fn request_message() -> RawMessage {
        let bytes: Arc<[u8]> = Arc::from(
            &b"INVITE sip:a@example.com SIP/2.0\r\nVia: x\r\nX-Test: value\r\n\r\nbody"[..],
        );

        let Ok(request_line) =
            RawRequestLine::new(span(0, 32), span(0, 6), span(7, 24), span(25, 32))
        else {
            panic!("expected valid request-line metadata");
        };

        let Ok(via) = RawHeader::new(span(34, 37), span(38, 40), Some(HeaderKind::Via)) else {
            panic!("expected valid Via metadata");
        };

        let Ok(extension) = RawHeader::new(span(42, 48), span(49, 55), None) else {
            panic!("expected valid extension-header metadata");
        };

        let Ok(message) = RawMessage::new(
            bytes,
            RawStartLine::Request(request_line),
            vec![via, extension],
            span(59, 63),
        ) else {
            panic!("expected valid structural request");
        };

        message
    }

    #[test]
    fn span_is_compact() {
        assert_eq!(size_of::<Span>(), 8);
    }

    #[test]
    fn span_reports_offsets_and_length() {
        let span = span(10, 25);

        assert_eq!(span.start(), 10);
        assert_eq!(span.end(), 25);
        assert_eq!(span.len(), 15);
        assert!(!span.is_empty());
    }

    #[test]
    fn empty_span_is_supported() {
        let span = span(10, 10);

        assert!(span.is_empty());
        assert_eq!(span.len(), 0);
    }

    #[test]
    fn span_rejects_reversed_offsets() {
        assert_eq!(
            Span::new(20, 10),
            Err(SpanError::Reversed { start: 20, end: 10 })
        );
    }

    #[test]
    fn span_resolves_without_allocation() {
        let bytes = b"0123456789";
        let span = span(2, 6);

        assert_eq!(span.get(bytes), Some(&b"2345"[..]));
    }

    #[test]
    fn span_returns_none_when_out_of_bounds() {
        let bytes = b"short";
        let span = span(0, 10);

        assert_eq!(span.get(bytes), None);
    }

    #[test]
    fn span_containment_is_correct() {
        let outer = span(10, 30);

        assert!(outer.contains(span(10, 30)));
        assert!(outer.contains(span(15, 20)));
        assert!(outer.contains(span(30, 30)));
        assert!(!outer.contains(span(9, 20)));
        assert!(!outer.contains(span(20, 31)));
    }

    #[test]
    fn request_line_rejects_empty_method() {
        assert_eq!(
            RawRequestLine::new(span(0, 20), span(0, 0), span(1, 10), span(11, 18),),
            Err(LayoutError::InvalidRequestLine)
        );
    }

    #[test]
    fn request_line_rejects_overlapping_components() {
        assert_eq!(
            RawRequestLine::new(span(0, 20), span(0, 6), span(6, 12), span(13, 20),),
            Err(LayoutError::InvalidRequestLine)
        );
    }

    #[test]
    fn response_line_allows_empty_reason_phrase() {
        let Ok(line) = RawResponseLine::new(span(0, 12), span(0, 7), span(8, 11), span(12, 12))
        else {
            panic!("expected valid response line with empty reason phrase");
        };

        assert!(line.reason_span().is_empty());
    }

    #[test]
    fn response_line_rejects_overlapping_status_and_reason() {
        assert_eq!(
            RawResponseLine::new(span(0, 15), span(0, 7), span(8, 11), span(11, 15),),
            Err(LayoutError::InvalidResponseLine)
        );
    }

    #[test]
    fn header_rejects_empty_name() {
        assert_eq!(
            RawHeader::new(span(0, 0), span(1, 5), None),
            Err(LayoutError::InvalidHeader)
        );
    }

    #[test]
    fn header_requires_space_for_colon_delimiter() {
        assert_eq!(
            RawHeader::new(span(0, 4), span(4, 8), None),
            Err(LayoutError::InvalidHeader)
        );
    }

    #[test]
    fn structural_request_preserves_original_message_bytes() {
        let message = request_message();

        assert_eq!(
            message.as_bytes(),
            b"INVITE sip:a@example.com SIP/2.0\r\nVia: x\r\nX-Test: value\r\n\r\nbody"
        );

        assert_eq!(message.kind(), MessageKind::Request);
        assert!(!message.is_empty());
        assert_eq!(message.len(), 63);
    }

    #[test]
    fn structural_request_exposes_start_line_without_reparsing() {
        let message = request_message();

        assert_eq!(
            message.start_line_bytes(),
            b"INVITE sip:a@example.com SIP/2.0"
        );

        let RawStartLineView::Request(line) = message.start_line_view() else {
            panic!("expected request-line view");
        };

        assert_eq!(line.method(), b"INVITE");
        assert_eq!(line.uri(), b"sip:a@example.com");
        assert_eq!(line.version(), b"SIP/2.0");

        assert_eq!(line.line(), b"INVITE sip:a@example.com SIP/2.0");
    }

    #[test]
    fn structural_request_preserves_header_order() {
        let message = request_message();

        assert_eq!(message.header_count(), 2);

        let Some(first) = message.header(0) else {
            panic!("expected first header");
        };

        let Some(second) = message.header(1) else {
            panic!("expected second header");
        };

        assert_eq!(first.name(), b"Via");
        assert_eq!(second.name(), b"X-Test");
    }

    #[test]
    fn structural_request_preserves_exact_raw_header_value() {
        let message = request_message();

        let Some(via) = message.header(0) else {
            panic!("expected Via header");
        };

        assert_eq!(via.value(), b" x");
        assert_eq!(via.line(), b"Via: x");
    }

    #[test]
    fn known_header_classification_does_not_replace_raw_name() {
        let message = request_message();

        let Some(via) = message.header(0) else {
            panic!("expected Via header");
        };

        assert_eq!(via.kind(), Some(&HeaderKind::Via));
        assert_eq!(via.name(), b"Via");
    }

    #[test]
    fn unknown_header_requires_no_owned_name_string() {
        let message = request_message();

        let Some(extension) = message.header(1) else {
            panic!("expected extension header");
        };

        assert_eq!(extension.kind(), None);
        assert_eq!(extension.name(), b"X-Test");
        assert_eq!(extension.value(), b" value");
    }

    #[test]
    fn structural_request_exposes_body_span_without_copying() {
        let message = request_message();

        assert_eq!(message.body(), b"body");
        assert_eq!(message.body_span(), span(59, 63));
    }

    #[test]
    fn header_iterator_preserves_wire_order() {
        let message = request_message();

        let names: Vec<&[u8]> = message
            .header_views()
            .map(super::RawHeaderView::name)
            .collect();

        assert_eq!(names, [&b"Via"[..], &b"X-Test"[..]]);
    }

    #[test]
    fn duplicate_header_metadata_is_preserved() {
        let bytes: Arc<[u8]> = Arc::from(
            &b"OPTIONS sip:a@example.com SIP/2.0\r\nVia: first\r\nVia: second\r\n\r\n"[..],
        );

        let Ok(request_line) =
            RawRequestLine::new(span(0, 33), span(0, 7), span(8, 25), span(26, 33))
        else {
            panic!("expected request line");
        };

        let Ok(first) = RawHeader::new(span(35, 38), span(39, 45), Some(HeaderKind::Via)) else {
            panic!("expected first Via");
        };

        let Ok(second) = RawHeader::new(span(47, 50), span(51, 58), Some(HeaderKind::Via)) else {
            panic!("expected second Via");
        };

        let Ok(message) = RawMessage::new(
            bytes,
            RawStartLine::Request(request_line),
            vec![first, second],
            span(62, 62),
        ) else {
            panic!("expected structural message with duplicate Via headers");
        };

        assert_eq!(message.header_count(), 2);

        let values: Vec<&[u8]> = message
            .header_views()
            .map(super::RawHeaderView::value)
            .collect();

        assert_eq!(values, [&b" first"[..], &b" second"[..]]);
    }

    #[test]
    fn structural_response_exposes_status_line_components() {
        let bytes: Arc<[u8]> = Arc::from(&b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"[..]);

        let Ok(response_line) =
            RawResponseLine::new(span(0, 14), span(0, 7), span(8, 11), span(12, 14))
        else {
            panic!("expected response line");
        };

        let Ok(content_length) =
            RawHeader::new(span(16, 30), span(31, 33), Some(HeaderKind::ContentLength))
        else {
            panic!("expected Content-Length header");
        };

        let Ok(message) = RawMessage::new(
            bytes,
            RawStartLine::Response(response_line),
            vec![content_length],
            span(37, 37),
        ) else {
            panic!("expected structural response");
        };

        assert_eq!(message.kind(), MessageKind::Response);
        assert!(message.body().is_empty());

        let RawStartLineView::Response(line) = message.start_line_view() else {
            panic!("expected response-line view");
        };

        assert_eq!(line.version(), b"SIP/2.0");
        assert_eq!(line.status(), b"200");
        assert_eq!(line.reason(), b"OK");
        assert_eq!(line.line(), b"SIP/2.0 200 OK");
    }

    #[test]
    fn message_rejects_start_line_not_at_zero() {
        let bytes: Arc<[u8]> = Arc::from(&b"_INVITE x SIP/2.0\r\n\r\n"[..]);

        let Ok(line) = RawRequestLine::new(span(1, 17), span(1, 7), span(8, 9), span(10, 17))
        else {
            panic!("expected abstract request-line metadata");
        };

        assert!(matches!(
            RawMessage::new(bytes, RawStartLine::Request(line), Vec::new(), span(21, 21),),
            Err(BuildError::StartLineNotAtZero)
        ));
    }

    #[test]
    fn message_rejects_out_of_order_headers() {
        let message = request_message();

        let bytes = Arc::from(message.as_bytes());

        let headers = vec![message.headers()[1].clone(), message.headers()[0].clone()];

        assert!(matches!(
            RawMessage::new(bytes, message.start_line(), headers, message.body_span(),),
            Err(BuildError::HeadersOutOfOrder { index: 1 })
        ));
    }

    #[test]
    fn message_rejects_body_before_headers() {
        let message = request_message();

        assert!(matches!(
            RawMessage::new(
                Arc::from(message.as_bytes()),
                message.start_line(),
                message.headers().to_vec(),
                span(54, 63),
            ),
            Err(BuildError::BodyBeforeHeaders)
        ));
    }

    #[test]
    fn message_rejects_nonterminal_body() {
        let message = request_message();

        assert!(matches!(
            RawMessage::new(
                Arc::from(message.as_bytes()),
                message.start_line(),
                message.headers().to_vec(),
                span(59, 62),
            ),
            Err(BuildError::BodyNotTerminal)
        ));
    }

    #[test]
    fn message_rejects_excessive_header_count_before_order_validation() {
        let message = request_message();

        let Some(header) = message.headers().first().cloned() else {
            panic!("expected header");
        };

        let headers = vec![header; MAX_RAW_HEADER_COUNT + 1];

        assert!(matches!(
            RawMessage::new(
                Arc::from(message.as_bytes()),
                message.start_line(),
                headers,
                message.body_span(),
            ),
            Err(BuildError::TooManyHeaders {
                maximum: MAX_RAW_HEADER_COUNT,
            })
        ));
    }

    #[test]
    fn debug_output_does_not_dump_sip_payload() {
        let message = request_message();
        let debug = format!("{message:?}");

        assert!(debug.contains("RawMessage"));
        assert!(debug.contains("header_count"));
        assert!(debug.contains("body_bytes"));

        assert!(!debug.contains("INVITE"));
        assert!(!debug.contains("sip:a@example.com"));
        assert!(!debug.contains("X-Test"));
        assert!(!debug.contains("value"));
    }

    #[test]
    fn build_error_classes_are_stable() {
        assert_eq!(BuildError::EmptyBuffer.class(), "empty-buffer");

        assert_eq!(
            BuildError::StartLineNotAtZero.class(),
            "start-line-not-at-zero"
        );

        assert_eq!(
            BuildError::HeaderOutOfBounds { index: 1 }.class(),
            "header-out-of-bounds"
        );

        assert_eq!(
            BuildError::HeadersOutOfOrder { index: 1 }.class(),
            "headers-out-of-order"
        );

        assert_eq!(BuildError::BodyBeforeHeaders.class(), "body-before-headers");

        assert_eq!(BuildError::BodyNotTerminal.class(), "body-not-terminal");
    }

    #[test]
    fn layout_error_classes_are_stable() {
        assert_eq!(
            LayoutError::InvalidRequestLine.class(),
            "invalid-request-line"
        );

        assert_eq!(
            LayoutError::InvalidResponseLine.class(),
            "invalid-response-line"
        );

        assert_eq!(LayoutError::InvalidHeader.class(), "invalid-header");
    }

    #[test]
    fn span_error_classes_are_stable() {
        assert_eq!(SpanError::Reversed { start: 2, end: 1 }.class(), "reversed");

        assert_eq!(
            SpanError::OffsetTooLarge { value: usize::MAX }.class(),
            "offset-too-large"
        );
    }
}
