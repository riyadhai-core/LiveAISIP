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

//! SIP `Supported` header.
//!
//! This module provides strongly typed parsing and serialization for SIP
//! `Supported` field values.
//!
//! A Supported field contains an ordered comma-separated list of SIP option
//! tags. An empty field value is valid and advertises support for no
//! extensions.
//!
//! Option tags use SIP token syntax and are compared case-insensitively.
//! Common option tags use allocation-free representations. Unknown valid
//! option tags preserve their original spelling.
//!
//! Repeated option tags are preserved rather than rejected because uniqueness
//! is not a syntactic requirement of the field-value grammar.
//!
//! Header unfolding belongs to the generic SIP message parser. This parser
//! accepts spaces and horizontal tabs around comma separators but rejects
//! embedded CR and LF bytes.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

/// Maximum accepted SIP `Supported` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_SUPPORTED_BYTES: usize = 8 * 1024;

/// Maximum number of option tags accepted in one `Supported` field value.
pub const MAX_OPTION_TAGS: usize = 64;

/// Maximum accepted SIP option-tag size in bytes.
pub const MAX_OPTION_TAG_BYTES: usize = 256;

/// A validated SIP `Supported` field value.
///
/// Option-tag ordering is preserved. The list may be empty.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Supported {
    option_tags: Vec<OptionTag>,
}

impl Supported {
    /// Creates an empty Supported value.
    ///
    /// An empty Supported value advertises support for no SIP extensions.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            option_tags: Vec::new(),
        }
    }

    /// Creates a Supported value containing one option tag.
    #[must_use]
    pub fn single(option_tag: OptionTag) -> Self {
        Self {
            option_tags: vec![option_tag],
        }
    }

    /// Creates a Supported value from an ordered option-tag vector.
    ///
    /// Empty vectors are valid.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyOptionTags`] when the configured tag-count
    /// bound is exceeded or [`ParseError::TooLong`] when the canonical
    /// serialized field value exceeds its operational size limit.
    pub fn from_option_tags(option_tags: Vec<OptionTag>) -> Result<Self, ParseError> {
        if option_tags.len() > MAX_OPTION_TAGS {
            return Err(ParseError::TooManyOptionTags {
                maximum: MAX_OPTION_TAGS,
            });
        }

        let length = serialized_length(&option_tags);

        if length > MAX_SUPPORTED_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_SUPPORTED_BYTES,
            });
        }

        Ok(Self { option_tags })
    }

    /// Parses a SIP `Supported` field value from wire bytes.
    ///
    /// Header-name and `HCOLON` parsing are outside this function.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when an option tag is malformed, an empty list
    /// element is present, an embedded line break appears, or an operational
    /// bound is exceeded.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns all option tags in wire order.
    #[must_use]
    pub fn option_tags(&self) -> &[OptionTag] {
        &self.option_tags
    }

    /// Returns mutable access to all option tags.
    #[must_use]
    pub fn option_tags_mut(&mut self) -> &mut [OptionTag] {
        &mut self.option_tags
    }

    /// Returns the first option tag.
    ///
    /// Empty Supported values return `None`.
    #[must_use]
    pub fn first(&self) -> Option<&OptionTag> {
        self.option_tags.first()
    }

    /// Returns the number of advertised option tags.
    #[must_use]
    pub fn len(&self) -> usize {
        self.option_tags.len()
    }

    /// Returns whether no option tags are advertised.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.option_tags.is_empty()
    }

    /// Returns whether the specified option tag is advertised.
    ///
    /// Comparison is ASCII case-insensitive.
    #[must_use]
    pub fn contains(&self, option_tag: &OptionTag) -> bool {
        self.option_tags
            .iter()
            .any(|candidate| candidate == option_tag)
    }

    /// Returns whether an option tag with this name is advertised.
    ///
    /// Comparison is ASCII case-insensitive.
    #[must_use]
    pub fn supports(&self, option_tag: &str) -> bool {
        self.option_tags
            .iter()
            .any(|candidate| candidate.as_str().eq_ignore_ascii_case(option_tag))
    }

    /// Appends an option tag while preserving ordering.
    ///
    /// Repeated option tags are permitted.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyOptionTags`] when the configured tag-count
    /// bound has been reached or [`ParseError::TooLong`] when the resulting
    /// serialized value would exceed the field-value size bound.
    pub fn push(&mut self, option_tag: OptionTag) -> Result<(), ParseError> {
        if self.option_tags.len() >= MAX_OPTION_TAGS {
            return Err(ParseError::TooManyOptionTags {
                maximum: MAX_OPTION_TAGS,
            });
        }

        let separator_length = if self.option_tags.is_empty() { 0 } else { 2 };

        let length = serialized_length(&self.option_tags)
            .saturating_add(separator_length)
            .saturating_add(option_tag.as_str().len());

        if length > MAX_SUPPORTED_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_SUPPORTED_BYTES,
            });
        }

        self.option_tags.push(option_tag);
        Ok(())
    }

    /// Consumes the value into its ordered option-tag vector.
    #[must_use]
    pub fn into_option_tags(self) -> Vec<OptionTag> {
        self.option_tags
    }
}

impl fmt::Display for Supported {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, option_tag) in self.option_tags.iter().enumerate() {
            if index != 0 {
                formatter.write_str(", ")?;
            }

            fmt::Display::fmt(option_tag, formatter)?;
        }

        Ok(())
    }
}

impl FromStr for Supported {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// One validated SIP option tag.
///
/// Common option tags use allocation-free representations. Unknown valid
/// option tags preserve their original spelling. Equality is
/// case-insensitive.
#[derive(Clone, Debug)]
pub struct OptionTag {
    representation: OptionTagRepresentation,
}

impl OptionTag {
    /// Creates a validated SIP option tag from text.
    ///
    /// # Errors
    ///
    /// Returns [`OptionTagError`] when the value is empty, exceeds the
    /// configured size limit, or violates SIP token syntax.
    pub fn new(value: impl AsRef<str>) -> Result<Self, OptionTagError> {
        Self::from_bytes(value.as_ref().as_bytes())
    }

    /// Parses a SIP option tag from wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`OptionTagError`] when the value is empty, exceeds the
    /// configured size limit, is not valid UTF-8, or violates SIP token
    /// syntax.
    pub fn from_bytes(input: &[u8]) -> Result<Self, OptionTagError> {
        validate_option_tag(input)?;

        let representation = if input.eq_ignore_ascii_case(b"100rel") {
            OptionTagRepresentation::Rel100
        } else if input.eq_ignore_ascii_case(b"timer") {
            OptionTagRepresentation::Timer
        } else if input.eq_ignore_ascii_case(b"path") {
            OptionTagRepresentation::Path
        } else if input.eq_ignore_ascii_case(b"outbound") {
            OptionTagRepresentation::Outbound
        } else if input.eq_ignore_ascii_case(b"gruu") {
            OptionTagRepresentation::Gruu
        } else {
            let value = std::str::from_utf8(input).map_err(|_| OptionTagError::InvalidUtf8)?;

            OptionTagRepresentation::Extension(value.into())
        };

        Ok(Self { representation })
    }

    /// Creates the `100rel` option tag.
    #[must_use]
    pub const fn rel100() -> Self {
        Self {
            representation: OptionTagRepresentation::Rel100,
        }
    }

    /// Creates the `timer` option tag.
    #[must_use]
    pub const fn timer() -> Self {
        Self {
            representation: OptionTagRepresentation::Timer,
        }
    }

    /// Creates the `path` option tag.
    #[must_use]
    pub const fn path() -> Self {
        Self {
            representation: OptionTagRepresentation::Path,
        }
    }

    /// Creates the `outbound` option tag.
    #[must_use]
    pub const fn outbound() -> Self {
        Self {
            representation: OptionTagRepresentation::Outbound,
        }
    }

    /// Creates the `gruu` option tag.
    #[must_use]
    pub const fn gruu() -> Self {
        Self {
            representation: OptionTagRepresentation::Gruu,
        }
    }

    /// Returns the textual option-tag value.
    ///
    /// Known option tags use canonical lowercase spelling. Extension tags
    /// preserve their validated input spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.representation {
            OptionTagRepresentation::Rel100 => "100rel",
            OptionTagRepresentation::Timer => "timer",
            OptionTagRepresentation::Path => "path",
            OptionTagRepresentation::Outbound => "outbound",
            OptionTagRepresentation::Gruu => "gruu",
            OptionTagRepresentation::Extension(value) => value,
        }
    }

    /// Returns whether this is the `100rel` option tag.
    #[must_use]
    pub const fn is_100rel(&self) -> bool {
        matches!(self.representation, OptionTagRepresentation::Rel100)
    }

    /// Returns whether this is the `timer` option tag.
    #[must_use]
    pub const fn is_timer(&self) -> bool {
        matches!(self.representation, OptionTagRepresentation::Timer)
    }

    /// Returns whether this is the `path` option tag.
    #[must_use]
    pub const fn is_path(&self) -> bool {
        matches!(self.representation, OptionTagRepresentation::Path)
    }

    /// Returns whether this is the `outbound` option tag.
    #[must_use]
    pub const fn is_outbound(&self) -> bool {
        matches!(self.representation, OptionTagRepresentation::Outbound)
    }

    /// Returns whether this is the `gruu` option tag.
    #[must_use]
    pub const fn is_gruu(&self) -> bool {
        matches!(self.representation, OptionTagRepresentation::Gruu)
    }

    /// Returns whether this is an extension option tag.
    #[must_use]
    pub const fn is_extension(&self) -> bool {
        matches!(self.representation, OptionTagRepresentation::Extension(_))
    }
}

impl PartialEq for OptionTag {
    fn eq(&self, other: &Self) -> bool {
        self.as_str().eq_ignore_ascii_case(other.as_str())
    }
}

impl Eq for OptionTag {}

impl fmt::Display for OptionTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for OptionTag {
    type Err = OptionTagError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

#[derive(Clone, Debug)]
enum OptionTagRepresentation {
    Rel100,
    Timer,
    Path,
    Outbound,
    Gruu,
    Extension(Box<str>),
}

/// Parses a SIP `Supported` field value.
///
/// An empty or whitespace-only field value is valid and produces an empty
/// [`Supported`] value.
///
/// # Errors
///
/// Returns [`ParseError`] when a non-empty value violates Supported syntax or
/// an operational bound.
pub fn parse(input: &[u8]) -> Result<Supported, ParseError> {
    if input.len() > MAX_SUPPORTED_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_SUPPORTED_BYTES,
        });
    }

    if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ParseError::InvalidLineBreak);
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Ok(Supported::new());
    }

    let mut option_tags = Vec::new();

    for (option_index, segment) in input.split(|byte| *byte == b',').enumerate() {
        if option_tags.len() >= MAX_OPTION_TAGS {
            return Err(ParseError::TooManyOptionTags {
                maximum: MAX_OPTION_TAGS,
            });
        }

        let segment = trim_lws(segment);

        if segment.is_empty() {
            return Err(ParseError::EmptyOptionTag { option_index });
        }

        let option_tag =
            OptionTag::from_bytes(segment).map_err(|source| ParseError::InvalidOptionTag {
                option_index,
                source,
            })?;

        option_tags.push(option_tag);
    }

    Supported::from_option_tags(option_tags)
}

fn validate_option_tag(input: &[u8]) -> Result<(), OptionTagError> {
    if input.is_empty() {
        return Err(OptionTagError::Empty);
    }

    if input.len() > MAX_OPTION_TAG_BYTES {
        return Err(OptionTagError::TooLong {
            length: input.len(),
            maximum: MAX_OPTION_TAG_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(OptionTagError::InvalidByte { index, byte });
        }
    }

    Ok(())
}

fn serialized_length(option_tags: &[OptionTag]) -> usize {
    let option_tag_bytes = option_tags
        .iter()
        .map(|option_tag| option_tag.as_str().len())
        .sum::<usize>();

    let separators = option_tags.len().saturating_sub(1).saturating_mul(2);

    option_tag_bytes.saturating_add(separators)
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

/// Failure to parse or construct one SIP option tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OptionTagError {
    /// The option tag was empty.
    Empty,

    /// The option tag exceeded the configured operational size limit.
    TooLong {
        /// Actual option-tag length in bytes.
        length: usize,

        /// Maximum accepted option-tag length in bytes.
        maximum: usize,
    },

    /// An option-tag byte violated SIP token syntax.
    InvalidByte {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A validated textual option tag was not valid UTF-8.
    InvalidUtf8,
}

impl OptionTagError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong { .. } => "too-long",
            Self::InvalidByte { .. } => "invalid-byte",
            Self::InvalidUtf8 => "invalid-utf8",
        }
    }
}

impl fmt::Display for OptionTagError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP option tag is empty"),
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP option-tag length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidByte { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP option-tag byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::InvalidUtf8 => formatter.write_str("SIP option tag is not valid UTF-8"),
        }
    }
}

impl StdError for OptionTagError {}

/// Failure to parse or construct a SIP `Supported` field value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The field value exceeded the configured operational size limit.
    TooLong {
        /// Actual field-value length in bytes.
        length: usize,

        /// Maximum accepted field-value length in bytes.
        maximum: usize,
    },

    /// A CR or LF appeared inside the field value.
    InvalidLineBreak,

    /// A comma-delimited option-tag position was empty.
    EmptyOptionTag {
        /// Zero-based option-tag position.
        option_index: usize,
    },

    /// One option tag was malformed.
    InvalidOptionTag {
        /// Zero-based option-tag position.
        option_index: usize,

        /// Underlying option-tag validation failure.
        source: OptionTagError,
    },

    /// The field exceeded the bounded option-tag count.
    TooManyOptionTags {
        /// Maximum accepted option-tag count.
        maximum: usize,
    },
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::TooLong { .. } => "too-long",
            Self::InvalidLineBreak => "invalid-line-break",
            Self::EmptyOptionTag { .. } => "empty-option-tag",
            Self::InvalidOptionTag { .. } => "invalid-option-tag",
            Self::TooManyOptionTags { .. } => "too-many-option-tags",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP Supported field-value length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidLineBreak => {
                formatter.write_str("SIP Supported contains an invalid line break")
            }
            Self::EmptyOptionTag { option_index } => {
                write!(
                    formatter,
                    "SIP Supported option tag at position {option_index} is empty"
                )
            }
            Self::InvalidOptionTag {
                option_index,
                source,
            } => {
                write!(
                    formatter,
                    "invalid SIP Supported option tag at position {option_index}: {source}"
                )
            }
            Self::TooManyOptionTags { maximum } => {
                write!(
                    formatter,
                    "SIP Supported contains more than {maximum} option tags"
                )
            }
        }
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidOptionTag { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_OPTION_TAG_BYTES, MAX_OPTION_TAGS, MAX_SUPPORTED_BYTES, OptionTag, OptionTagError,
        ParseError, Supported, parse,
    };
    use std::error::Error as _;
    use std::str::FromStr;

    #[test]
    fn empty_value_is_valid() {
        let Ok(supported) = parse(b"") else {
            panic!("expected valid empty Supported value");
        };

        assert!(supported.is_empty());
        assert_eq!(supported.len(), 0);
        assert_eq!(supported.first(), None);
        assert_eq!(supported.to_string(), "");
    }

    #[test]
    fn whitespace_only_value_is_valid() {
        let Ok(supported) = parse(b" \t ") else {
            panic!("expected valid empty Supported value");
        };

        assert!(supported.is_empty());
    }

    #[test]
    fn parses_single_option_tag() {
        let Ok(supported) = parse(b"100rel") else {
            panic!("expected valid Supported value");
        };

        assert_eq!(supported.len(), 1);
        assert!(supported.first().is_some_and(OptionTag::is_100rel));
    }

    #[test]
    fn parses_multiple_option_tags() {
        let Ok(supported) = parse(b"100rel, timer, path, outbound, gruu") else {
            panic!("expected valid Supported value");
        };

        assert_eq!(supported.len(), 5);
        assert!(supported.option_tags()[0].is_100rel());
        assert!(supported.option_tags()[1].is_timer());
        assert!(supported.option_tags()[2].is_path());
        assert!(supported.option_tags()[3].is_outbound());
        assert!(supported.option_tags()[4].is_gruu());
    }

    #[test]
    fn common_option_tags_are_case_insensitive() {
        let Ok(supported) = parse(b"100REL, TIMER, PATH, OUTBOUND, GRUU") else {
            panic!("expected case-insensitive option tags");
        };

        assert!(supported.option_tags()[0].is_100rel());
        assert!(supported.option_tags()[1].is_timer());
        assert!(supported.option_tags()[2].is_path());
        assert!(supported.option_tags()[3].is_outbound());
        assert!(supported.option_tags()[4].is_gruu());

        assert_eq!(supported.to_string(), "100rel, timer, path, outbound, gruu");
    }

    #[test]
    fn preserves_extension_option_tag_spelling() {
        let Ok(supported) = parse(b"X-Custom.Option") else {
            panic!("expected extension option tag");
        };

        let Some(option_tag) = supported.first() else {
            panic!("expected one option tag");
        };

        assert!(option_tag.is_extension());
        assert_eq!(option_tag.as_str(), "X-Custom.Option");
        assert_eq!(supported.to_string(), "X-Custom.Option");
    }

    #[test]
    fn extension_option_tag_equality_is_case_insensitive() {
        let Ok(first) = OptionTag::new("X-Custom") else {
            panic!("expected valid first option tag");
        };

        let Ok(second) = OptionTag::new("x-custom") else {
            panic!("expected valid second option tag");
        };

        assert_eq!(first, second);
    }

    #[test]
    fn supports_is_case_insensitive() {
        let Ok(supported) = parse(b"timer, X-Custom") else {
            panic!("expected valid Supported value");
        };

        assert!(supported.supports("timer"));
        assert!(supported.supports("TIMER"));
        assert!(supported.supports("x-custom"));
        assert!(supported.supports("X-CUSTOM"));
        assert!(!supported.supports("path"));
    }

    #[test]
    fn contains_uses_option_tag_semantics() {
        let Ok(supported) = parse(b"TIMER, X-Custom") else {
            panic!("expected valid Supported value");
        };

        assert!(supported.contains(&OptionTag::timer()));

        let Ok(extension) = OptionTag::new("x-custom") else {
            panic!("expected extension option tag");
        };

        assert!(supported.contains(&extension));
    }

    #[test]
    fn preserves_option_tag_order() {
        let Ok(supported) = parse(b"path, 100rel, timer") else {
            panic!("expected ordered option tags");
        };

        assert!(supported.option_tags()[0].is_path());
        assert!(supported.option_tags()[1].is_100rel());
        assert!(supported.option_tags()[2].is_timer());
    }

    #[test]
    fn repeated_option_tags_are_preserved() {
        let Ok(supported) = parse(b"timer, TIMER, path") else {
            panic!("expected repeated option tags");
        };

        assert_eq!(supported.len(), 3);
        assert!(supported.option_tags()[0].is_timer());
        assert!(supported.option_tags()[1].is_timer());
        assert!(supported.option_tags()[2].is_path());
    }

    #[test]
    fn accepts_whitespace_around_commas() {
        let Ok(supported) = parse(b" \ttimer\t,\t100rel  ,   path\t ") else {
            panic!("expected delimiter whitespace");
        };

        assert_eq!(supported.to_string(), "timer, 100rel, path");
    }

    #[test]
    fn accepts_full_sip_token_character_set() {
        let value = "a-z.1!%*_+`'~";

        let Ok(option_tag) = OptionTag::new(value) else {
            panic!("expected valid SIP token");
        };

        assert_eq!(option_tag.as_str(), value);
    }

    #[test]
    fn common_constructors_create_expected_option_tags() {
        assert!(OptionTag::rel100().is_100rel());
        assert!(OptionTag::timer().is_timer());
        assert!(OptionTag::path().is_path());
        assert!(OptionTag::outbound().is_outbound());
        assert!(OptionTag::gruu().is_gruu());
    }

    #[test]
    fn default_is_empty() {
        let supported = Supported::default();

        assert!(supported.is_empty());
        assert_eq!(supported.to_string(), "");
    }

    #[test]
    fn single_constructor_contains_option_tag() {
        let supported = Supported::single(OptionTag::timer());

        assert_eq!(supported.len(), 1);
        assert!(supported.supports("timer"));
    }

    #[test]
    fn constructs_from_empty_option_tag_vector() {
        let Ok(supported) = Supported::from_option_tags(Vec::new()) else {
            panic!("expected valid empty option-tag vector");
        };

        assert!(supported.is_empty());
    }

    #[test]
    fn constructs_from_multiple_option_tags() {
        let option_tags = vec![OptionTag::rel100(), OptionTag::timer(), OptionTag::path()];

        let Ok(supported) = Supported::from_option_tags(option_tags) else {
            panic!("expected valid option-tag vector");
        };

        assert_eq!(supported.to_string(), "100rel, timer, path");
    }

    #[test]
    fn push_appends_option_tag() {
        let mut supported = Supported::new();

        assert!(supported.push(OptionTag::timer()).is_ok());
        assert!(supported.push(OptionTag::rel100()).is_ok());
        assert!(supported.push(OptionTag::path()).is_ok());

        assert_eq!(supported.to_string(), "timer, 100rel, path");
    }

    #[test]
    fn push_allows_duplicate_option_tag() {
        let mut supported = Supported::single(OptionTag::timer());

        assert!(supported.push(OptionTag::timer()).is_ok());

        assert_eq!(supported.len(), 2);
    }

    #[test]
    fn rejects_leading_comma() {
        assert_eq!(
            parse(b", timer"),
            Err(ParseError::EmptyOptionTag { option_index: 0 })
        );
    }

    #[test]
    fn rejects_trailing_comma() {
        assert_eq!(
            parse(b"timer,"),
            Err(ParseError::EmptyOptionTag { option_index: 1 })
        );
    }

    #[test]
    fn rejects_empty_middle_option_tag() {
        assert_eq!(
            parse(b"timer, , path"),
            Err(ParseError::EmptyOptionTag { option_index: 1 })
        );
    }

    #[test]
    fn rejects_internal_whitespace() {
        assert_eq!(
            parse(b"session timer"),
            Err(ParseError::InvalidOptionTag {
                option_index: 0,
                source: OptionTagError::InvalidByte {
                    index: 7,
                    byte: b' ',
                },
            })
        );
    }

    #[test]
    fn rejects_invalid_token_character() {
        assert_eq!(
            parse(b"tim@er"),
            Err(ParseError::InvalidOptionTag {
                option_index: 0,
                source: OptionTagError::InvalidByte {
                    index: 3,
                    byte: b'@',
                },
            })
        );
    }

    #[test]
    fn rejects_semicolon_separator() {
        assert_eq!(
            parse(b"timer;path"),
            Err(ParseError::InvalidOptionTag {
                option_index: 0,
                source: OptionTagError::InvalidByte {
                    index: 5,
                    byte: b';',
                },
            })
        );
    }

    #[test]
    fn rejects_non_ascii_option_tag() {
        assert_eq!(
            OptionTag::from_bytes(&[b'a', b'b', 0xff]),
            Err(OptionTagError::InvalidByte {
                index: 2,
                byte: 0xff,
            })
        );
    }

    #[test]
    fn rejects_embedded_crlf() {
        assert_eq!(parse(b"timer,\r\n path"), Err(ParseError::InvalidLineBreak));
    }

    #[test]
    fn rejects_field_above_size_limit() {
        let input = vec![b'a'; MAX_SUPPORTED_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_SUPPORTED_BYTES + 1,
                maximum: MAX_SUPPORTED_BYTES,
            })
        );
    }

    #[test]
    fn rejects_option_tag_above_size_limit() {
        let value = "a".repeat(MAX_OPTION_TAG_BYTES + 1);

        assert_eq!(
            OptionTag::new(value),
            Err(OptionTagError::TooLong {
                length: MAX_OPTION_TAG_BYTES + 1,
                maximum: MAX_OPTION_TAG_BYTES,
            })
        );
    }

    #[test]
    fn accepts_option_tag_at_size_limit() {
        let value = "a".repeat(MAX_OPTION_TAG_BYTES);

        let Ok(option_tag) = OptionTag::new(&value) else {
            panic!("expected option tag at operational limit");
        };

        assert_eq!(option_tag.as_str(), value);
    }

    #[test]
    fn rejects_too_many_option_tags_during_construction() {
        let option_tags = (0..=MAX_OPTION_TAGS)
            .map(|_| OptionTag::timer())
            .collect::<Vec<_>>();

        assert_eq!(
            Supported::from_option_tags(option_tags),
            Err(ParseError::TooManyOptionTags {
                maximum: MAX_OPTION_TAGS,
            })
        );
    }

    #[test]
    fn rejects_too_many_option_tags_during_parsing() {
        let input = std::iter::repeat_n("a", MAX_OPTION_TAGS + 1)
            .collect::<Vec<_>>()
            .join(",");

        assert_eq!(
            parse(input.as_bytes()),
            Err(ParseError::TooManyOptionTags {
                maximum: MAX_OPTION_TAGS,
            })
        );
    }

    #[test]
    fn push_enforces_option_tag_count() {
        let option_tags = (0..MAX_OPTION_TAGS)
            .map(|_| OptionTag::timer())
            .collect::<Vec<_>>();

        let Ok(mut supported) = Supported::from_option_tags(option_tags) else {
            panic!("expected option-tag list at operational limit");
        };

        assert_eq!(
            supported.push(OptionTag::path()),
            Err(ParseError::TooManyOptionTags {
                maximum: MAX_OPTION_TAGS,
            })
        );
    }

    #[test]
    fn parses_from_str() {
        let Ok(supported) = Supported::from_str("timer, 100rel, path") else {
            panic!("expected valid Supported value");
        };

        assert_eq!(supported.len(), 3);
    }

    #[test]
    fn empty_string_parses_from_str() {
        let Ok(supported) = Supported::from_str("") else {
            panic!("expected valid empty Supported value");
        };

        assert!(supported.is_empty());
    }

    #[test]
    fn option_tag_parses_from_str() {
        let Ok(option_tag) = OptionTag::from_str("TIMER") else {
            panic!("expected valid option tag");
        };

        assert!(option_tag.is_timer());
    }

    #[test]
    fn consumes_into_option_tags() {
        let Ok(supported) = parse(b"timer, path") else {
            panic!("expected valid Supported value");
        };

        let option_tags = supported.into_option_tags();

        assert_eq!(option_tags.len(), 2);
        assert!(option_tags[0].is_timer());
        assert!(option_tags[1].is_path());
    }

    #[test]
    fn supported_equality_uses_case_insensitive_option_tag_semantics() {
        let Ok(first) = parse(b"TIMER, X-Custom") else {
            panic!("expected valid first Supported value");
        };

        let Ok(second) = parse(b"timer, x-custom") else {
            panic!("expected valid second Supported value");
        };

        assert_eq!(first, second);
    }

    #[test]
    fn display_canonicalizes_common_option_tags() {
        let Ok(supported) = parse(b"TIMER, 100REL, PATH, OUTBOUND, GRUU") else {
            panic!("expected valid Supported value");
        };

        assert_eq!(supported.to_string(), "timer, 100rel, path, outbound, gruu");
    }

    #[test]
    fn invalid_option_tag_exposes_source_error() {
        let Err(error) = parse(b"tim@er") else {
            panic!("expected invalid option tag");
        };

        assert!(error.source().is_some());
    }

    #[test]
    fn non_nested_parse_error_has_no_source() {
        let error = ParseError::EmptyOptionTag { option_index: 0 };

        assert!(error.source().is_none());
    }

    #[test]
    fn option_tag_error_classes_are_stable() {
        assert_eq!(OptionTagError::Empty.class(), "empty");

        assert_eq!(
            OptionTagError::TooLong {
                length: MAX_OPTION_TAG_BYTES + 1,
                maximum: MAX_OPTION_TAG_BYTES,
            }
            .class(),
            "too-long"
        );

        assert_eq!(
            OptionTagError::InvalidByte {
                index: 0,
                byte: b'@',
            }
            .class(),
            "invalid-byte"
        );
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(
            ParseError::TooLong {
                length: MAX_SUPPORTED_BYTES + 1,
                maximum: MAX_SUPPORTED_BYTES,
            }
            .class(),
            "too-long"
        );

        assert_eq!(ParseError::InvalidLineBreak.class(), "invalid-line-break");

        assert_eq!(
            ParseError::EmptyOptionTag { option_index: 1 }.class(),
            "empty-option-tag"
        );

        assert_eq!(
            ParseError::InvalidOptionTag {
                option_index: 0,
                source: OptionTagError::InvalidByte {
                    index: 0,
                    byte: b'@',
                },
            }
            .class(),
            "invalid-option-tag"
        );

        assert_eq!(
            ParseError::TooManyOptionTags {
                maximum: MAX_OPTION_TAGS,
            }
            .class(),
            "too-many-option-tags"
        );
    }
}
