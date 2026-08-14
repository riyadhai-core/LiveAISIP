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

//! SIP `Require` header.
//!
//! This module provides strongly typed parsing and serialization for SIP
//! `Require` field values.
//!
//! A Require field contains a non-empty ordered comma-separated list of SIP
//! option tags. Each tag identifies an extension that the recipient must
//! understand in order to process the message correctly.
//!
//! Option-tag syntax and comparison semantics are shared with the `Supported`
//! header implementation. Option tags use SIP token syntax and compare
//! case-insensitively.
//!
//! Repeated option tags are preserved rather than rejected because uniqueness
//! is not a syntactic requirement of the field-value grammar.
//!
//! This module validates standalone field-value syntax only. Message-level
//! rules governing where Require may appear and how unsupported extensions are
//! handled belong to SIP message validation and transaction processing.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use crate::sip::headers::supported::{OptionTag, OptionTagError};

/// Maximum accepted SIP `Require` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_REQUIRE_BYTES: usize = 8 * 1024;

/// Maximum number of option tags accepted in one `Require` field value.
pub const MAX_REQUIRED_OPTION_TAGS: usize = 64;

/// A validated SIP `Require` field value.
///
/// The option-tag list is always non-empty and preserves wire order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Require {
    option_tags: Vec<OptionTag>,
}

impl Require {
    /// Creates a Require value containing one option tag.
    #[must_use]
    pub fn new(option_tag: OptionTag) -> Self {
        Self {
            option_tags: vec![option_tag],
        }
    }

    /// Creates a Require value from a non-empty ordered option-tag vector.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Empty`] when `option_tags` is empty,
    /// [`ParseError::TooManyOptionTags`] when the configured count bound is
    /// exceeded, or [`ParseError::TooLong`] when the canonical serialized
    /// value exceeds the field-value size bound.
    pub fn from_option_tags(option_tags: Vec<OptionTag>) -> Result<Self, ParseError> {
        if option_tags.is_empty() {
            return Err(ParseError::Empty);
        }

        if option_tags.len() > MAX_REQUIRED_OPTION_TAGS {
            return Err(ParseError::TooManyOptionTags {
                maximum: MAX_REQUIRED_OPTION_TAGS,
            });
        }

        let length = serialized_length(&option_tags);

        if length > MAX_REQUIRE_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_REQUIRE_BYTES,
            });
        }

        Ok(Self { option_tags })
    }

    /// Parses a SIP `Require` field value from wire bytes.
    ///
    /// Header-name and `HCOLON` parsing are outside this function.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the field value is empty, an option tag is
    /// malformed, an empty list element is present, an embedded line break
    /// appears, or an operational bound is exceeded.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns all required option tags in wire order.
    #[must_use]
    pub fn option_tags(&self) -> &[OptionTag] {
        &self.option_tags
    }

    /// Returns mutable access to all required option tags.
    #[must_use]
    pub fn option_tags_mut(&mut self) -> &mut [OptionTag] {
        &mut self.option_tags
    }

    /// Returns the first required option tag.
    ///
    /// Successfully constructed Require values are always non-empty.
    #[must_use]
    pub fn first(&self) -> &OptionTag {
        &self.option_tags[0]
    }

    /// Returns the number of required option tags.
    #[must_use]
    pub fn len(&self) -> usize {
        self.option_tags.len()
    }

    /// Returns whether the required option-tag list is empty.
    ///
    /// Successfully constructed Require values are never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.option_tags.is_empty()
    }

    /// Returns whether the specified option tag is required.
    ///
    /// Comparison follows SIP token semantics and is ASCII case-insensitive.
    #[must_use]
    pub fn contains(&self, option_tag: &OptionTag) -> bool {
        self.option_tags
            .iter()
            .any(|candidate| candidate == option_tag)
    }

    /// Returns whether an option tag with this textual name is required.
    ///
    /// Comparison follows SIP token semantics and is ASCII case-insensitive.
    #[must_use]
    pub fn requires(&self, option_tag: &str) -> bool {
        self.option_tags
            .iter()
            .any(|candidate| candidate.as_str().eq_ignore_ascii_case(option_tag))
    }

    /// Appends another required option tag while preserving ordering.
    ///
    /// Repeated option tags are permitted.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyOptionTags`] when the configured count
    /// bound has been reached or [`ParseError::TooLong`] when the resulting
    /// serialized value would exceed the field-value size bound.
    pub fn push(&mut self, option_tag: OptionTag) -> Result<(), ParseError> {
        if self.option_tags.len() >= MAX_REQUIRED_OPTION_TAGS {
            return Err(ParseError::TooManyOptionTags {
                maximum: MAX_REQUIRED_OPTION_TAGS,
            });
        }

        let length = serialized_length(&self.option_tags)
            .saturating_add(2)
            .saturating_add(option_tag.as_str().len());

        if length > MAX_REQUIRE_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_REQUIRE_BYTES,
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

impl fmt::Display for Require {
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

impl FromStr for Require {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// Parses a SIP `Require` field value.
///
/// # Errors
///
/// Returns [`ParseError`] when the field value violates Require syntax or an
/// operational bound.
pub fn parse(input: &[u8]) -> Result<Require, ParseError> {
    if input.len() > MAX_REQUIRE_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_REQUIRE_BYTES,
        });
    }

    if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ParseError::InvalidLineBreak);
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut option_tags = Vec::new();

    for (option_index, segment) in input.split(|byte| *byte == b',').enumerate() {
        if option_tags.len() >= MAX_REQUIRED_OPTION_TAGS {
            return Err(ParseError::TooManyOptionTags {
                maximum: MAX_REQUIRED_OPTION_TAGS,
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

    Require::from_option_tags(option_tags)
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

/// Failure to parse or construct a SIP `Require` field value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The Require field value was empty.
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

    /// A comma-delimited option-tag position was empty.
    EmptyOptionTag {
        /// Zero-based option-tag position.
        option_index: usize,
    },

    /// One required option tag was malformed.
    InvalidOptionTag {
        /// Zero-based option-tag position.
        option_index: usize,

        /// Underlying option-tag validation failure.
        source: OptionTagError,
    },

    /// The field exceeded the bounded required option-tag count.
    TooManyOptionTags {
        /// Maximum accepted required option-tag count.
        maximum: usize,
    },
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
            Self::EmptyOptionTag { .. } => "empty-option-tag",
            Self::InvalidOptionTag { .. } => "invalid-option-tag",
            Self::TooManyOptionTags { .. } => "too-many-option-tags",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP Require field value is empty"),
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP Require field-value length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidLineBreak => {
                formatter.write_str("SIP Require contains an invalid line break")
            }
            Self::EmptyOptionTag { option_index } => {
                write!(
                    formatter,
                    "SIP Require option tag at position {option_index} is empty"
                )
            }
            Self::InvalidOptionTag {
                option_index,
                source,
            } => {
                write!(
                    formatter,
                    "invalid SIP Require option tag at position {option_index}: {source}"
                )
            }
            Self::TooManyOptionTags { maximum } => {
                write!(
                    formatter,
                    "SIP Require contains more than {maximum} option tags"
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
    use super::{MAX_REQUIRE_BYTES, MAX_REQUIRED_OPTION_TAGS, ParseError, Require, parse};
    use crate::sip::headers::supported::{OptionTag, OptionTagError};
    use std::error::Error as _;
    use std::str::FromStr;

    #[test]
    fn parses_single_option_tag() {
        let Ok(require) = parse(b"100rel") else {
            panic!("expected valid Require value");
        };

        assert_eq!(require.len(), 1);
        assert!(require.first().is_100rel());
    }

    #[test]
    fn parses_multiple_option_tags() {
        let Ok(require) = parse(b"100rel, precondition, timer, replaces") else {
            panic!("expected valid Require value");
        };

        assert_eq!(require.len(), 4);
        assert!(require.option_tags()[0].is_100rel());
        assert_eq!(require.option_tags()[1].as_str(), "precondition");
        assert!(require.option_tags()[2].is_timer());
        assert_eq!(require.option_tags()[3].as_str(), "replaces");
    }

    #[test]
    fn option_tags_compare_case_insensitively() {
        let Ok(require) = parse(b"100REL, TIMER, PreCondition") else {
            panic!("expected case-insensitive option tags");
        };

        assert!(require.requires("100rel"));
        assert!(require.requires("timer"));
        assert!(require.requires("precondition"));
        assert!(require.requires("PRECONDITION"));
    }

    #[test]
    fn known_option_tags_are_canonicalized() {
        let Ok(require) = parse(b"100REL, TIMER, PATH, OUTBOUND, GRUU") else {
            panic!("expected known option tags");
        };

        assert_eq!(require.to_string(), "100rel, timer, path, outbound, gruu");
    }

    #[test]
    fn extension_option_tag_spelling_is_preserved() {
        let Ok(require) = parse(b"X-LiveAISIP.Option") else {
            panic!("expected extension option tag");
        };

        assert_eq!(require.first().as_str(), "X-LiveAISIP.Option");
        assert!(require.first().is_extension());
    }

    #[test]
    fn requires_extension_case_insensitively() {
        let Ok(require) = parse(b"X-Custom") else {
            panic!("expected extension option tag");
        };

        assert!(require.requires("X-Custom"));
        assert!(require.requires("x-custom"));
        assert!(require.requires("X-CUSTOM"));
    }

    #[test]
    fn contains_uses_option_tag_semantics() {
        let Ok(require) = parse(b"TIMER, X-Custom") else {
            panic!("expected valid Require value");
        };

        assert!(require.contains(&OptionTag::timer()));

        let Ok(extension) = OptionTag::new("x-custom") else {
            panic!("expected extension option tag");
        };

        assert!(require.contains(&extension));
    }

    #[test]
    fn preserves_option_tag_order() {
        let Ok(require) = parse(b"precondition, 100rel, timer, replaces") else {
            panic!("expected ordered option tags");
        };

        assert_eq!(require.option_tags()[0].as_str(), "precondition");
        assert!(require.option_tags()[1].is_100rel());
        assert!(require.option_tags()[2].is_timer());
        assert_eq!(require.option_tags()[3].as_str(), "replaces");
    }

    #[test]
    fn repeated_option_tags_are_preserved() {
        let Ok(require) = parse(b"timer, TIMER, 100rel") else {
            panic!("expected repeated option tags");
        };

        assert_eq!(require.len(), 3);
        assert!(require.option_tags()[0].is_timer());
        assert!(require.option_tags()[1].is_timer());
        assert!(require.option_tags()[2].is_100rel());
    }

    #[test]
    fn accepts_whitespace_around_commas() {
        let Ok(require) = parse(b" \t100rel\t,\tprecondition  ,   timer\t ") else {
            panic!("expected delimiter whitespace");
        };

        assert_eq!(require.to_string(), "100rel, precondition, timer");
    }

    #[test]
    fn rejects_empty_field() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b" \t "), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_empty_constructor_vector() {
        assert_eq!(
            Require::from_option_tags(Vec::new()),
            Err(ParseError::Empty)
        );
    }

    #[test]
    fn rejects_leading_comma() {
        assert_eq!(
            parse(b", 100rel"),
            Err(ParseError::EmptyOptionTag { option_index: 0 })
        );
    }

    #[test]
    fn rejects_trailing_comma() {
        assert_eq!(
            parse(b"100rel,"),
            Err(ParseError::EmptyOptionTag { option_index: 1 })
        );
    }

    #[test]
    fn rejects_empty_middle_option_tag() {
        assert_eq!(
            parse(b"100rel, , timer"),
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
            parse(b"100@rel"),
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
            parse(b"100rel;timer"),
            Err(ParseError::InvalidOptionTag {
                option_index: 0,
                source: OptionTagError::InvalidByte {
                    index: 6,
                    byte: b';',
                },
            })
        );
    }

    #[test]
    fn rejects_embedded_crlf() {
        assert_eq!(
            parse(b"100rel,\r\n timer"),
            Err(ParseError::InvalidLineBreak)
        );
    }

    #[test]
    fn rejects_field_above_size_limit() {
        let input = vec![b'a'; MAX_REQUIRE_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_REQUIRE_BYTES + 1,
                maximum: MAX_REQUIRE_BYTES,
            })
        );
    }

    #[test]
    fn constructor_creates_single_option_tag() {
        let require = Require::new(OptionTag::rel100());

        assert_eq!(require.len(), 1);
        assert!(require.first().is_100rel());
        assert!(require.requires("100rel"));
    }

    #[test]
    fn constructs_from_multiple_option_tags() {
        let option_tags = vec![OptionTag::rel100(), OptionTag::timer(), OptionTag::path()];

        let Ok(require) = Require::from_option_tags(option_tags) else {
            panic!("expected valid option-tag vector");
        };

        assert_eq!(require.to_string(), "100rel, timer, path");
    }

    #[test]
    fn push_appends_option_tag() {
        let mut require = Require::new(OptionTag::rel100());

        assert!(require.push(OptionTag::timer()).is_ok());
        assert!(require.push(OptionTag::path()).is_ok());

        assert_eq!(require.to_string(), "100rel, timer, path");
    }

    #[test]
    fn push_allows_duplicate_option_tag() {
        let mut require = Require::new(OptionTag::timer());

        assert!(require.push(OptionTag::timer()).is_ok());

        assert_eq!(require.len(), 2);
    }

    #[test]
    fn rejects_too_many_option_tags_during_construction() {
        let option_tags = (0..=MAX_REQUIRED_OPTION_TAGS)
            .map(|_| OptionTag::timer())
            .collect::<Vec<_>>();

        assert_eq!(
            Require::from_option_tags(option_tags),
            Err(ParseError::TooManyOptionTags {
                maximum: MAX_REQUIRED_OPTION_TAGS,
            })
        );
    }

    #[test]
    fn rejects_too_many_option_tags_during_parsing() {
        let input = std::iter::repeat_n("a", MAX_REQUIRED_OPTION_TAGS + 1)
            .collect::<Vec<_>>()
            .join(",");

        assert_eq!(
            parse(input.as_bytes()),
            Err(ParseError::TooManyOptionTags {
                maximum: MAX_REQUIRED_OPTION_TAGS,
            })
        );
    }

    #[test]
    fn push_enforces_option_tag_count() {
        let option_tags = (0..MAX_REQUIRED_OPTION_TAGS)
            .map(|_| OptionTag::timer())
            .collect::<Vec<_>>();

        let Ok(mut require) = Require::from_option_tags(option_tags) else {
            panic!("expected option-tag list at operational limit");
        };

        assert_eq!(
            require.push(OptionTag::path()),
            Err(ParseError::TooManyOptionTags {
                maximum: MAX_REQUIRED_OPTION_TAGS,
            })
        );
    }

    #[test]
    fn parses_from_str() {
        let Ok(require) = Require::from_str("100rel, precondition, timer") else {
            panic!("expected valid Require value");
        };

        assert_eq!(require.len(), 3);
    }

    #[test]
    fn empty_string_from_str_is_rejected() {
        assert_eq!(Require::from_str(""), Err(ParseError::Empty));
    }

    #[test]
    fn consumes_into_option_tags() {
        let Ok(require) = parse(b"100rel, timer") else {
            panic!("expected valid Require value");
        };

        let option_tags = require.into_option_tags();

        assert_eq!(option_tags.len(), 2);
        assert!(option_tags[0].is_100rel());
        assert!(option_tags[1].is_timer());
    }

    #[test]
    fn require_equality_uses_option_tag_semantics() {
        let Ok(first) = parse(b"TIMER, X-Custom") else {
            panic!("expected valid first Require value");
        };

        let Ok(second) = parse(b"timer, x-custom") else {
            panic!("expected valid second Require value");
        };

        assert_eq!(first, second);
    }

    #[test]
    fn invalid_option_tag_exposes_source_error() {
        let Err(error) = parse(b"100@rel") else {
            panic!("expected invalid option tag");
        };

        assert!(error.source().is_some());
    }

    #[test]
    fn non_nested_error_has_no_source() {
        assert!(ParseError::Empty.source().is_none());
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");

        assert_eq!(
            ParseError::TooLong {
                length: MAX_REQUIRE_BYTES + 1,
                maximum: MAX_REQUIRE_BYTES,
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
                maximum: MAX_REQUIRED_OPTION_TAGS,
            }
            .class(),
            "too-many-option-tags"
        );
    }
}
