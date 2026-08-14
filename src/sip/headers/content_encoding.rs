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

//! SIP `Content-Encoding` header.
//!
//! This module provides strongly typed parsing and serialization for SIP
//! `Content-Encoding` field values.
//!
//! A Content-Encoding value contains one or more comma-separated content
//! codings. Coding order is preserved exactly because multiple codings are
//! semantically ordered.
//!
//! Common content codings use allocation-free representations. Unknown valid
//! coding tokens remain supported and preserve their original spelling.
//! Comparisons are case-insensitive.
//!
//! Header unfolding belongs to the generic SIP message parser. This parser
//! accepts spaces and horizontal tabs around comma separators but rejects
//! embedded CR and LF bytes.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

/// Maximum accepted SIP `Content-Encoding` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_CONTENT_ENCODING_BYTES: usize = 8 * 1024;

/// Maximum number of content codings accepted in one field value.
pub const MAX_CONTENT_CODINGS: usize = 64;

/// Maximum accepted content-coding token size in bytes.
pub const MAX_CONTENT_CODING_BYTES: usize = 256;

/// A validated SIP `Content-Encoding` field value.
///
/// The coding list is always non-empty and retains wire order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentEncoding {
    codings: Vec<ContentCoding>,
}

impl ContentEncoding {
    /// Creates a Content-Encoding value containing one coding.
    #[must_use]
    pub fn new(coding: ContentCoding) -> Self {
        Self {
            codings: vec![coding],
        }
    }

    /// Creates a Content-Encoding value from a non-empty ordered coding list.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Empty`] when `codings` is empty,
    /// [`ParseError::TooManyCodings`] when the coding-count bound is exceeded,
    /// or [`ParseError::TooLong`] when the canonical serialized value exceeds
    /// the field-value size bound.
    pub fn from_codings(codings: Vec<ContentCoding>) -> Result<Self, ParseError> {
        if codings.is_empty() {
            return Err(ParseError::Empty);
        }

        if codings.len() > MAX_CONTENT_CODINGS {
            return Err(ParseError::TooManyCodings {
                maximum: MAX_CONTENT_CODINGS,
            });
        }

        let length = serialized_length(&codings);

        if length > MAX_CONTENT_ENCODING_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_CONTENT_ENCODING_BYTES,
            });
        }

        Ok(Self { codings })
    }

    /// Parses a SIP `Content-Encoding` field value from wire bytes.
    ///
    /// Header-name and `HCOLON` parsing are outside this function.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the field value is empty, contains an
    /// invalid coding token or separator, contains embedded line breaks, or
    /// exceeds an operational bound.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns all content codings in wire order.
    #[must_use]
    pub fn codings(&self) -> &[ContentCoding] {
        &self.codings
    }

    /// Returns the first content coding.
    #[must_use]
    pub fn first(&self) -> &ContentCoding {
        &self.codings[0]
    }

    /// Returns the number of content codings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.codings.len()
    }

    /// Returns whether the coding list is empty.
    ///
    /// Successfully constructed Content-Encoding values are never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.codings.is_empty()
    }

    /// Returns whether the field contains `coding`.
    ///
    /// Comparison is ASCII case-insensitive.
    #[must_use]
    pub fn contains(&self, coding: &str) -> bool {
        self.codings
            .iter()
            .any(|candidate| candidate.as_str().eq_ignore_ascii_case(coding))
    }

    /// Appends another coding while preserving ordering.
    ///
    /// Repeated codings are permitted because the list represents an ordered
    /// sequence of transformations rather than a set.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyCodings`] when the coding-count bound has
    /// been reached or [`ParseError::TooLong`] when the resulting serialized
    /// value would exceed the field-value size bound.
    pub fn push(&mut self, coding: ContentCoding) -> Result<(), ParseError> {
        if self.codings.len() >= MAX_CONTENT_CODINGS {
            return Err(ParseError::TooManyCodings {
                maximum: MAX_CONTENT_CODINGS,
            });
        }

        let separator_length = if self.codings.is_empty() { 0 } else { 2 };
        let length = self
            .wire_len()
            .saturating_add(separator_length)
            .saturating_add(coding.as_str().len());

        if length > MAX_CONTENT_ENCODING_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_CONTENT_ENCODING_BYTES,
            });
        }

        self.codings.push(coding);
        Ok(())
    }

    /// Consumes the value into its ordered content codings.
    #[must_use]
    pub fn into_codings(self) -> Vec<ContentCoding> {
        self.codings
    }

    fn wire_len(&self) -> usize {
        serialized_length(&self.codings)
    }
}

impl fmt::Display for ContentEncoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, coding) in self.codings.iter().enumerate() {
            if index != 0 {
                formatter.write_str(", ")?;
            }

            fmt::Display::fmt(coding, formatter)?;
        }

        Ok(())
    }
}

impl FromStr for ContentEncoding {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// One validated SIP content-coding token.
///
/// Common codings use allocation-free representations. Unknown valid codings
/// retain their original spelling while comparisons remain case-insensitive.
#[derive(Clone, Debug)]
pub struct ContentCoding {
    representation: ContentCodingRepresentation,
}

impl ContentCoding {
    /// Creates a validated content coding from text.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the coding is empty, exceeds the configured
    /// token-size bound, or violates the SIP token grammar.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ParseError> {
        Self::from_bytes(value.as_ref().as_bytes())
    }

    /// Parses a content coding from wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the coding is empty, exceeds the configured
    /// token-size bound, is not valid UTF-8, or violates the SIP token grammar.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        validate_coding(input)?;

        let representation = if input.eq_ignore_ascii_case(b"gzip") {
            ContentCodingRepresentation::Gzip
        } else if input.eq_ignore_ascii_case(b"compress") {
            ContentCodingRepresentation::Compress
        } else if input.eq_ignore_ascii_case(b"deflate") {
            ContentCodingRepresentation::Deflate
        } else if input.eq_ignore_ascii_case(b"identity") {
            ContentCodingRepresentation::Identity
        } else {
            let value = std::str::from_utf8(input).map_err(|_| ParseError::InvalidUtf8)?;

            ContentCodingRepresentation::Extension(value.into())
        };

        Ok(Self { representation })
    }

    /// Creates the common `gzip` content coding.
    #[must_use]
    pub const fn gzip() -> Self {
        Self {
            representation: ContentCodingRepresentation::Gzip,
        }
    }

    /// Creates the common `compress` content coding.
    #[must_use]
    pub const fn compress() -> Self {
        Self {
            representation: ContentCodingRepresentation::Compress,
        }
    }

    /// Creates the common `deflate` content coding.
    #[must_use]
    pub const fn deflate() -> Self {
        Self {
            representation: ContentCodingRepresentation::Deflate,
        }
    }

    /// Creates the `identity` content coding.
    #[must_use]
    pub const fn identity() -> Self {
        Self {
            representation: ContentCodingRepresentation::Identity,
        }
    }

    /// Returns the textual content-coding token.
    ///
    /// Common codings use canonical lowercase spelling. Extension codings
    /// retain their validated input spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.representation {
            ContentCodingRepresentation::Gzip => "gzip",
            ContentCodingRepresentation::Compress => "compress",
            ContentCodingRepresentation::Deflate => "deflate",
            ContentCodingRepresentation::Identity => "identity",
            ContentCodingRepresentation::Extension(value) => value,
        }
    }

    /// Returns whether this is `gzip`.
    #[must_use]
    pub const fn is_gzip(&self) -> bool {
        matches!(self.representation, ContentCodingRepresentation::Gzip)
    }

    /// Returns whether this is `compress`.
    #[must_use]
    pub const fn is_compress(&self) -> bool {
        matches!(self.representation, ContentCodingRepresentation::Compress)
    }

    /// Returns whether this is `deflate`.
    #[must_use]
    pub const fn is_deflate(&self) -> bool {
        matches!(self.representation, ContentCodingRepresentation::Deflate)
    }

    /// Returns whether this is `identity`.
    #[must_use]
    pub const fn is_identity(&self) -> bool {
        matches!(self.representation, ContentCodingRepresentation::Identity)
    }

    /// Returns whether this is an extension coding.
    #[must_use]
    pub const fn is_extension(&self) -> bool {
        matches!(
            self.representation,
            ContentCodingRepresentation::Extension(_)
        )
    }
}

impl PartialEq for ContentCoding {
    fn eq(&self, other: &Self) -> bool {
        self.as_str().eq_ignore_ascii_case(other.as_str())
    }
}

impl Eq for ContentCoding {}

impl fmt::Display for ContentCoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ContentCoding {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

#[derive(Clone, Debug)]
enum ContentCodingRepresentation {
    Gzip,
    Compress,
    Deflate,
    Identity,
    Extension(Box<str>),
}

/// Parses a SIP `Content-Encoding` field value.
///
/// # Errors
///
/// Returns [`ParseError`] when the value violates Content-Encoding syntax or
/// an operational bound.
pub fn parse(input: &[u8]) -> Result<ContentEncoding, ParseError> {
    if input.len() > MAX_CONTENT_ENCODING_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_CONTENT_ENCODING_BYTES,
        });
    }

    if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ParseError::InvalidLineBreak);
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut codings = Vec::new();

    for (coding_index, segment) in input.split(|byte| *byte == b',').enumerate() {
        if codings.len() >= MAX_CONTENT_CODINGS {
            return Err(ParseError::TooManyCodings {
                maximum: MAX_CONTENT_CODINGS,
            });
        }

        let segment = trim_lws(segment);

        if segment.is_empty() {
            return Err(ParseError::EmptyCoding { coding_index });
        }

        codings.push(ContentCoding::from_bytes(segment)?);
    }

    ContentEncoding::from_codings(codings)
}

fn validate_coding(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyCoding { coding_index: 0 });
    }

    if input.len() > MAX_CONTENT_CODING_BYTES {
        return Err(ParseError::CodingTooLong {
            length: input.len(),
            maximum: MAX_CONTENT_CODING_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidCodingByte { index, byte });
        }
    }

    Ok(())
}

fn serialized_length(codings: &[ContentCoding]) -> usize {
    let coding_bytes = codings
        .iter()
        .map(|coding| coding.as_str().len())
        .sum::<usize>();

    let separators = codings.len().saturating_sub(1).saturating_mul(2);

    coding_bytes.saturating_add(separators)
}

fn trim_lws(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(|byte| is_lws(*byte)) {
        input = &input[1..];
    }

    while input.last().is_some_and(|byte| is_lws(*byte)) {
        input = &input[..input.len() - 1];
    }

    input
}

const fn is_lws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

/// Failure to parse or construct a SIP `Content-Encoding` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The Content-Encoding field value was empty.
    Empty,

    /// The field value exceeded the configured operational size limit.
    TooLong {
        /// Actual field-value length in bytes.
        length: usize,

        /// Maximum accepted field-value length in bytes.
        maximum: usize,
    },

    /// A CR or LF appeared inside the field value.
    InvalidLineBreak,

    /// A comma-delimited content-coding position was empty.
    EmptyCoding {
        /// Zero-based coding position.
        coding_index: usize,
    },

    /// A content-coding token exceeded its operational size limit.
    CodingTooLong {
        /// Actual coding length in bytes.
        length: usize,

        /// Maximum accepted coding length in bytes.
        maximum: usize,
    },

    /// A content-coding byte violated the SIP token grammar.
    InvalidCodingByte {
        /// Offset of the invalid byte within the coding token.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// The field exceeded the bounded content-coding count.
    TooManyCodings {
        /// Maximum accepted content-coding count.
        maximum: usize,
    },

    /// A supposedly textual coding was not valid UTF-8.
    InvalidUtf8,
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong { .. } => "too-long",
            Self::InvalidLineBreak => "invalid-line-break",
            Self::EmptyCoding { .. } => "empty-coding",
            Self::CodingTooLong { .. } => "coding-too-long",
            Self::InvalidCodingByte { .. } => "invalid-coding-byte",
            Self::TooManyCodings { .. } => "too-many-codings",
            Self::InvalidUtf8 => "invalid-utf8",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP Content-Encoding field value is empty"),
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP Content-Encoding field-value length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidLineBreak => {
                formatter.write_str("SIP Content-Encoding contains an invalid line break")
            }
            Self::EmptyCoding { coding_index } => {
                write!(
                    formatter,
                    "SIP Content-Encoding coding at position {coding_index} is empty"
                )
            }
            Self::CodingTooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP Content-Encoding coding length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidCodingByte { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP Content-Encoding coding byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::TooManyCodings { maximum } => {
                write!(
                    formatter,
                    "SIP Content-Encoding contains more than {maximum} codings"
                )
            }
            Self::InvalidUtf8 => {
                formatter.write_str("SIP Content-Encoding coding is not valid UTF-8")
            }
        }
    }
}

impl StdError for ParseError {}

#[cfg(test)]
mod tests {
    use super::{
        ContentCoding, ContentEncoding, MAX_CONTENT_CODING_BYTES, MAX_CONTENT_CODINGS,
        MAX_CONTENT_ENCODING_BYTES, ParseError, parse,
    };
    use std::str::FromStr;

    #[test]
    fn parses_single_gzip() {
        let Ok(content_encoding) = parse(b"gzip") else {
            panic!("expected valid Content-Encoding");
        };

        assert_eq!(content_encoding.len(), 1);
        assert!(content_encoding.first().is_gzip());
        assert_eq!(content_encoding.to_string(), "gzip");
    }

    #[test]
    fn parses_multiple_codings() {
        let Ok(content_encoding) = parse(b"gzip, deflate, identity") else {
            panic!("expected multiple content codings");
        };

        assert_eq!(content_encoding.len(), 3);
        assert!(content_encoding.codings()[0].is_gzip());
        assert!(content_encoding.codings()[1].is_deflate());
        assert!(content_encoding.codings()[2].is_identity());
    }

    #[test]
    fn common_codings_are_recognized_case_insensitively() {
        let Ok(content_encoding) = parse(b"GZIP, DEFLATE, Compress, IDENTITY") else {
            panic!("expected case-insensitive common codings");
        };

        assert!(content_encoding.codings()[0].is_gzip());
        assert!(content_encoding.codings()[1].is_deflate());
        assert!(content_encoding.codings()[2].is_compress());
        assert!(content_encoding.codings()[3].is_identity());

        assert_eq!(
            content_encoding.to_string(),
            "gzip, deflate, compress, identity"
        );
    }

    #[test]
    fn preserves_extension_coding_spelling() {
        let Ok(content_encoding) = parse(b"X-Custom.Encoding") else {
            panic!("expected extension coding");
        };

        assert!(content_encoding.first().is_extension());
        assert_eq!(content_encoding.first().as_str(), "X-Custom.Encoding");
        assert_eq!(content_encoding.to_string(), "X-Custom.Encoding");
    }

    #[test]
    fn extension_comparison_is_case_insensitive() {
        let Ok(first) = ContentCoding::new("X-Custom") else {
            panic!("expected valid extension coding");
        };

        let Ok(second) = ContentCoding::new("x-custom") else {
            panic!("expected valid extension coding");
        };

        assert_eq!(first, second);
    }

    #[test]
    fn contains_is_case_insensitive() {
        let Ok(content_encoding) = parse(b"gzip, X-Custom") else {
            panic!("expected valid Content-Encoding");
        };

        assert!(content_encoding.contains("GZIP"));
        assert!(content_encoding.contains("x-custom"));
        assert!(content_encoding.contains("X-CUSTOM"));
        assert!(!content_encoding.contains("deflate"));
    }

    #[test]
    fn preserves_coding_order() {
        let Ok(content_encoding) = parse(b"deflate, gzip, identity") else {
            panic!("expected ordered codings");
        };

        assert_eq!(content_encoding.codings()[0].as_str(), "deflate");
        assert_eq!(content_encoding.codings()[1].as_str(), "gzip");
        assert_eq!(content_encoding.codings()[2].as_str(), "identity");
    }

    #[test]
    fn repeated_codings_are_permitted() {
        let Ok(content_encoding) = parse(b"gzip, gzip") else {
            panic!("expected repeated ordered codings");
        };

        assert_eq!(content_encoding.len(), 2);
        assert!(content_encoding.codings()[0].is_gzip());
        assert!(content_encoding.codings()[1].is_gzip());
    }

    #[test]
    fn accepts_whitespace_around_commas() {
        let Ok(content_encoding) = parse(b" \t gzip \t,\t deflate \t ") else {
            panic!("expected delimiter whitespace");
        };

        assert_eq!(content_encoding.to_string(), "gzip, deflate");
    }

    #[test]
    fn accepts_full_sip_token_character_set() {
        let value = "a-z.1!%*_+`'~";

        let Ok(coding) = ContentCoding::new(value) else {
            panic!("expected valid token");
        };

        assert_eq!(coding.as_str(), value);
    }

    #[test]
    fn parses_common_compress_coding() {
        let Ok(coding) = ContentCoding::from_str("compress") else {
            panic!("expected compress coding");
        };

        assert!(coding.is_compress());
        assert_eq!(coding.to_string(), "compress");
    }

    #[test]
    fn constructors_create_common_codings() {
        assert!(ContentCoding::gzip().is_gzip());
        assert!(ContentCoding::compress().is_compress());
        assert!(ContentCoding::deflate().is_deflate());
        assert!(ContentCoding::identity().is_identity());
    }

    #[test]
    fn content_encoding_constructor_creates_single_coding() {
        let content_encoding = ContentEncoding::new(ContentCoding::gzip());

        assert_eq!(content_encoding.len(), 1);
        assert!(content_encoding.first().is_gzip());
    }

    #[test]
    fn constructs_from_multiple_codings() {
        let codings = vec![
            ContentCoding::gzip(),
            ContentCoding::deflate(),
            ContentCoding::identity(),
        ];

        let Ok(content_encoding) = ContentEncoding::from_codings(codings) else {
            panic!("expected valid coding list");
        };

        assert_eq!(content_encoding.len(), 3);
    }

    #[test]
    fn push_appends_in_order() {
        let mut content_encoding = ContentEncoding::new(ContentCoding::gzip());

        assert!(content_encoding.push(ContentCoding::deflate()).is_ok());
        assert!(content_encoding.push(ContentCoding::identity()).is_ok());

        assert_eq!(content_encoding.to_string(), "gzip, deflate, identity");
    }

    #[test]
    fn rejects_empty_field_value() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b" \t "), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_empty_constructor_list() {
        assert_eq!(
            ContentEncoding::from_codings(Vec::new()),
            Err(ParseError::Empty)
        );
    }

    #[test]
    fn rejects_leading_comma() {
        assert_eq!(
            parse(b", gzip"),
            Err(ParseError::EmptyCoding { coding_index: 0 })
        );
    }

    #[test]
    fn rejects_trailing_comma() {
        assert_eq!(
            parse(b"gzip,"),
            Err(ParseError::EmptyCoding { coding_index: 1 })
        );
    }

    #[test]
    fn rejects_empty_middle_coding() {
        assert_eq!(
            parse(b"gzip, , deflate"),
            Err(ParseError::EmptyCoding { coding_index: 1 })
        );
    }

    #[test]
    fn rejects_semicolon_separator() {
        assert_eq!(
            parse(b"gzip;deflate"),
            Err(ParseError::InvalidCodingByte {
                index: 4,
                byte: b';',
            })
        );
    }

    #[test]
    fn rejects_internal_whitespace() {
        assert_eq!(
            parse(b"gzip deflate"),
            Err(ParseError::InvalidCodingByte {
                index: 4,
                byte: b' ',
            })
        );
    }

    #[test]
    fn rejects_invalid_token_character() {
        assert_eq!(
            parse(b"def@late"),
            Err(ParseError::InvalidCodingByte {
                index: 3,
                byte: b'@',
            })
        );
    }

    #[test]
    fn rejects_non_ascii_coding() {
        assert_eq!(
            ContentCoding::from_bytes(&[b'g', b'z', 0xff]),
            Err(ParseError::InvalidCodingByte {
                index: 2,
                byte: 0xff,
            })
        );
    }

    #[test]
    fn rejects_embedded_crlf() {
        assert_eq!(
            parse(b"gzip,\r\n deflate"),
            Err(ParseError::InvalidLineBreak)
        );
    }

    #[test]
    fn rejects_field_above_size_limit() {
        let input = vec![b'a'; MAX_CONTENT_ENCODING_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_CONTENT_ENCODING_BYTES + 1,
                maximum: MAX_CONTENT_ENCODING_BYTES,
            })
        );
    }

    #[test]
    fn rejects_coding_above_size_limit() {
        let value = "a".repeat(MAX_CONTENT_CODING_BYTES + 1);

        assert_eq!(
            ContentCoding::new(value),
            Err(ParseError::CodingTooLong {
                length: MAX_CONTENT_CODING_BYTES + 1,
                maximum: MAX_CONTENT_CODING_BYTES,
            })
        );
    }

    #[test]
    fn accepts_coding_at_size_limit() {
        let value = "a".repeat(MAX_CONTENT_CODING_BYTES);

        let Ok(coding) = ContentCoding::new(&value) else {
            panic!("expected coding at operational limit");
        };

        assert_eq!(coding.as_str(), value);
    }

    #[test]
    fn rejects_too_many_codings_during_construction() {
        let codings = (0..=MAX_CONTENT_CODINGS)
            .map(|_| ContentCoding::gzip())
            .collect::<Vec<_>>();

        assert_eq!(
            ContentEncoding::from_codings(codings),
            Err(ParseError::TooManyCodings {
                maximum: MAX_CONTENT_CODINGS,
            })
        );
    }

    #[test]
    fn rejects_too_many_codings_during_parsing() {
        let input = std::iter::repeat_n("a", MAX_CONTENT_CODINGS + 1)
            .collect::<Vec<_>>()
            .join(",");

        assert_eq!(
            parse(input.as_bytes()),
            Err(ParseError::TooManyCodings {
                maximum: MAX_CONTENT_CODINGS,
            })
        );
    }

    #[test]
    fn push_enforces_coding_count() {
        let codings = (0..MAX_CONTENT_CODINGS)
            .map(|_| ContentCoding::gzip())
            .collect::<Vec<_>>();

        let Ok(mut content_encoding) = ContentEncoding::from_codings(codings) else {
            panic!("expected coding list at count limit");
        };

        assert_eq!(
            content_encoding.push(ContentCoding::deflate()),
            Err(ParseError::TooManyCodings {
                maximum: MAX_CONTENT_CODINGS,
            })
        );
    }

    #[test]
    fn parses_from_str() {
        let Ok(content_encoding) = ContentEncoding::from_str("gzip, deflate") else {
            panic!("expected valid Content-Encoding");
        };

        assert_eq!(content_encoding.len(), 2);
    }

    #[test]
    fn coding_parses_from_str() {
        let Ok(coding) = ContentCoding::from_str("GZIP") else {
            panic!("expected valid coding");
        };

        assert!(coding.is_gzip());
    }

    #[test]
    fn consumes_into_codings() {
        let Ok(content_encoding) = parse(b"gzip, deflate") else {
            panic!("expected valid Content-Encoding");
        };

        let codings = content_encoding.into_codings();

        assert_eq!(codings.len(), 2);
        assert!(codings[0].is_gzip());
        assert!(codings[1].is_deflate());
    }

    #[test]
    fn content_encoding_equality_uses_coding_semantics() {
        let Ok(first) = parse(b"GZIP, X-Custom") else {
            panic!("expected valid first value");
        };

        let Ok(second) = parse(b"gzip, x-custom") else {
            panic!("expected valid second value");
        };

        assert_eq!(first, second);
    }

    #[test]
    fn display_is_canonical_for_common_codings() {
        let Ok(content_encoding) = parse(b"GZIP, Deflate, COMPRESS, Identity") else {
            panic!("expected valid Content-Encoding");
        };

        assert_eq!(
            content_encoding.to_string(),
            "gzip, deflate, compress, identity"
        );
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");
        assert_eq!(ParseError::InvalidLineBreak.class(), "invalid-line-break");
        assert_eq!(
            ParseError::EmptyCoding { coding_index: 1 }.class(),
            "empty-coding"
        );
        assert_eq!(
            ParseError::CodingTooLong {
                length: 257,
                maximum: 256,
            }
            .class(),
            "coding-too-long"
        );
        assert_eq!(
            ParseError::InvalidCodingByte {
                index: 0,
                byte: b'@',
            }
            .class(),
            "invalid-coding-byte"
        );
        assert_eq!(
            ParseError::TooManyCodings {
                maximum: MAX_CONTENT_CODINGS,
            }
            .class(),
            "too-many-codings"
        );
    }
}
