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

//! SIP `Allow` header.
//!
//! This module provides strongly typed parsing and serialization for SIP
//! `Allow` field values.
//!
//! An Allow value is an ordered comma-separated list of SIP methods. An empty
//! field value is valid and represents support for no methods.
//!
//! Core SIP methods use the shared allocation-free
//! [`Method`](crate::sip::types::method::Method) representation.
//! Valid extension methods remain supported and preserve their exact spelling.
//!
//! SIP method names are case-sensitive. This module therefore does not
//! canonicalize extension methods or reinterpret lowercase core-method names.
//!
//! Repeated methods are preserved rather than rejected because the SIP grammar
//! does not make uniqueness a syntactic requirement. Higher layers may treat
//! the value as a capability set when appropriate.
//!
//! Header unfolding belongs to the generic SIP message parser. This parser
//! accepts spaces and horizontal tabs around comma separators but rejects
//! embedded CR and LF bytes.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use crate::sip::types::method::{Method, ParseError as MethodParseError};

/// Maximum accepted SIP `Allow` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_ALLOW_BYTES: usize = 8 * 1024;

/// Maximum number of methods accepted in one `Allow` field value.
pub const MAX_ALLOW_METHODS: usize = 64;

/// A validated SIP `Allow` field value.
///
/// Method ordering is preserved. The list may be empty.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Allow {
    methods: Vec<Method>,
}

impl Allow {
    /// Creates an empty Allow value.
    ///
    /// An empty Allow value is valid SIP syntax and indicates that no methods
    /// are being advertised by this field value.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            methods: Vec::new(),
        }
    }

    /// Creates an Allow value containing one method.
    #[must_use]
    pub fn single(method: Method) -> Self {
        Self {
            methods: vec![method],
        }
    }

    /// Creates an Allow value from an ordered method vector.
    ///
    /// Empty vectors are valid.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyMethods`] when the configured method-count
    /// bound is exceeded or [`ParseError::TooLong`] when the canonical
    /// serialized value exceeds the field-value size bound.
    pub fn from_methods(methods: Vec<Method>) -> Result<Self, ParseError> {
        validate_method_count(methods.len())?;

        let length = serialized_length(&methods);

        if length > MAX_ALLOW_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_ALLOW_BYTES,
            });
        }

        Ok(Self { methods })
    }

    /// Parses a SIP `Allow` field value from wire bytes.
    ///
    /// Header-name and `HCOLON` parsing are outside this function.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when a method is malformed, an empty list element
    /// is present, an embedded line break appears, or an operational bound is
    /// exceeded.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns all advertised methods in wire order.
    #[must_use]
    pub fn methods(&self) -> &[Method] {
        &self.methods
    }

    /// Returns mutable access to all advertised methods.
    #[must_use]
    pub fn methods_mut(&mut self) -> &mut [Method] {
        &mut self.methods
    }

    /// Returns the first advertised method.
    ///
    /// Empty Allow values return `None`.
    #[must_use]
    pub fn first(&self) -> Option<&Method> {
        self.methods.first()
    }

    /// Returns the number of advertised methods.
    #[must_use]
    pub fn len(&self) -> usize {
        self.methods.len()
    }

    /// Returns whether no methods are advertised.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }

    /// Returns whether the exact method is present.
    ///
    /// SIP method comparison is case-sensitive.
    #[must_use]
    pub fn contains(&self, method: &Method) -> bool {
        self.methods.iter().any(|candidate| candidate == method)
    }

    /// Returns whether a method with exactly this textual name is present.
    ///
    /// Comparison is intentionally case-sensitive.
    #[must_use]
    pub fn contains_name(&self, method: &str) -> bool {
        self.methods
            .iter()
            .any(|candidate| candidate.as_str() == method)
    }

    /// Appends a method while preserving ordering.
    ///
    /// Repeated methods are permitted.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyMethods`] when the configured method-count
    /// bound has been reached or [`ParseError::TooLong`] when the resulting
    /// canonical field value would exceed the field-value size bound.
    pub fn push(&mut self, method: Method) -> Result<(), ParseError> {
        if self.methods.len() >= MAX_ALLOW_METHODS {
            return Err(ParseError::TooManyMethods {
                maximum: MAX_ALLOW_METHODS,
            });
        }

        let separator_length = if self.methods.is_empty() { 0 } else { 2 };
        let length = serialized_length(&self.methods)
            .saturating_add(separator_length)
            .saturating_add(method.as_str().len());

        if length > MAX_ALLOW_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_ALLOW_BYTES,
            });
        }

        self.methods.push(method);
        Ok(())
    }

    /// Consumes the value into its ordered method vector.
    #[must_use]
    pub fn into_methods(self) -> Vec<Method> {
        self.methods
    }
}

impl fmt::Display for Allow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, method) in self.methods.iter().enumerate() {
            if index != 0 {
                formatter.write_str(", ")?;
            }

            fmt::Display::fmt(method, formatter)?;
        }

        Ok(())
    }
}

impl FromStr for Allow {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// Parses a SIP `Allow` field value.
///
/// An empty or whitespace-only field value is valid and produces an empty
/// [`Allow`] value.
///
/// # Errors
///
/// Returns [`ParseError`] when a non-empty value violates Allow syntax or an
/// operational bound.
pub fn parse(input: &[u8]) -> Result<Allow, ParseError> {
    if input.len() > MAX_ALLOW_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_ALLOW_BYTES,
        });
    }

    if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ParseError::InvalidLineBreak);
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Ok(Allow::new());
    }

    let mut methods = Vec::new();

    for (method_index, segment) in input.split(|byte| *byte == b',').enumerate() {
        if methods.len() >= MAX_ALLOW_METHODS {
            return Err(ParseError::TooManyMethods {
                maximum: MAX_ALLOW_METHODS,
            });
        }

        let segment = trim_lws(segment);

        if segment.is_empty() {
            return Err(ParseError::EmptyMethod { method_index });
        }

        let method = Method::from_bytes(segment).map_err(ParseError::InvalidMethod)?;
        methods.push(method);
    }

    Allow::from_methods(methods)
}

fn validate_method_count(count: usize) -> Result<(), ParseError> {
    if count > MAX_ALLOW_METHODS {
        return Err(ParseError::TooManyMethods {
            maximum: MAX_ALLOW_METHODS,
        });
    }

    Ok(())
}

fn serialized_length(methods: &[Method]) -> usize {
    let method_bytes = methods
        .iter()
        .map(|method| method.as_str().len())
        .sum::<usize>();

    let separators = methods.len().saturating_sub(1).saturating_mul(2);

    method_bytes.saturating_add(separators)
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

/// Failure to parse or construct a SIP `Allow` value.
#[derive(Clone, Debug, Eq, PartialEq)]
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

    /// A comma-delimited method position was empty.
    EmptyMethod {
        /// Zero-based method position.
        method_index: usize,
    },

    /// A SIP method was malformed.
    InvalidMethod(MethodParseError),

    /// The field exceeded the bounded method count.
    TooManyMethods {
        /// Maximum accepted method count.
        maximum: usize,
    },
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::TooLong { .. } => "too-long",
            Self::InvalidLineBreak => "invalid-line-break",
            Self::EmptyMethod { .. } => "empty-method",
            Self::InvalidMethod(_) => "invalid-method",
            Self::TooManyMethods { .. } => "too-many-methods",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP Allow field-value length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidLineBreak => {
                formatter.write_str("SIP Allow contains an invalid line break")
            }
            Self::EmptyMethod { method_index } => {
                write!(
                    formatter,
                    "SIP Allow method at position {method_index} is empty"
                )
            }
            Self::InvalidMethod(error) => {
                write!(formatter, "invalid SIP Allow method: {error}")
            }
            Self::TooManyMethods { maximum } => {
                write!(formatter, "SIP Allow contains more than {maximum} methods")
            }
        }
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidMethod(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Allow, MAX_ALLOW_BYTES, MAX_ALLOW_METHODS, ParseError, parse};
    use crate::sip::types::method::Method;
    use std::error::Error as _;
    use std::str::FromStr;

    #[test]
    fn empty_value_is_valid() {
        let Ok(allow) = parse(b"") else {
            panic!("expected valid empty Allow value");
        };

        assert!(allow.is_empty());
        assert_eq!(allow.len(), 0);
        assert_eq!(allow.first(), None);
        assert_eq!(allow.to_string(), "");
    }

    #[test]
    fn whitespace_only_value_is_valid() {
        let Ok(allow) = parse(b" \t ") else {
            panic!("expected valid empty Allow value");
        };

        assert!(allow.is_empty());
    }

    #[test]
    fn parses_single_method() {
        let Ok(allow) = parse(b"INVITE") else {
            panic!("expected valid Allow value");
        };

        assert_eq!(allow.len(), 1);
        assert_eq!(allow.first(), Some(&Method::Invite));
        assert!(allow.contains(&Method::Invite));
    }

    #[test]
    fn parses_multiple_methods() {
        let Ok(allow) = parse(b"INVITE, ACK, CANCEL, OPTIONS, BYE") else {
            panic!("expected valid Allow value");
        };

        assert_eq!(allow.len(), 5);
        assert_eq!(allow.methods()[0], Method::Invite);
        assert_eq!(allow.methods()[1], Method::Ack);
        assert_eq!(allow.methods()[2], Method::Cancel);
        assert_eq!(allow.methods()[3], Method::Options);
        assert_eq!(allow.methods()[4], Method::Bye);
    }

    #[test]
    fn preserves_method_order() {
        let Ok(allow) = parse(b"BYE, INVITE, ACK") else {
            panic!("expected ordered methods");
        };

        assert_eq!(allow.methods()[0], Method::Bye);
        assert_eq!(allow.methods()[1], Method::Invite);
        assert_eq!(allow.methods()[2], Method::Ack);
    }

    #[test]
    fn accepts_whitespace_around_commas() {
        let Ok(allow) = parse(b" \tINVITE\t,\tACK  ,   BYE\t ") else {
            panic!("expected valid delimiter whitespace");
        };

        assert_eq!(allow.to_string(), "INVITE, ACK, BYE");
    }

    #[test]
    fn preserves_extension_method() {
        let Ok(allow) = parse(b"INVITE, X-LiveAISIP") else {
            panic!("expected extension method");
        };

        assert_eq!(allow.methods()[1].as_str(), "X-LiveAISIP");
        assert!(allow.methods()[1].is_extension());
        assert_eq!(allow.to_string(), "INVITE, X-LiveAISIP");
    }

    #[test]
    fn extension_method_case_is_preserved() {
        let Ok(allow) = parse(b"X-Mixed-Case") else {
            panic!("expected extension method");
        };

        assert_eq!(allow.first().map(Method::as_str), Some("X-Mixed-Case"));
    }

    #[test]
    fn lowercase_core_name_remains_extension_method() {
        let Ok(allow) = parse(b"invite") else {
            panic!("expected valid extension method");
        };

        let Some(method) = allow.first() else {
            panic!("expected one method");
        };

        assert!(method.is_extension());
        assert_eq!(method.as_str(), "invite");
        assert!(!allow.contains(&Method::Invite));
        assert!(allow.contains_name("invite"));
        assert!(!allow.contains_name("INVITE"));
    }

    #[test]
    fn contains_name_is_case_sensitive() {
        let Ok(allow) = parse(b"INVITE, X-Method") else {
            panic!("expected valid Allow value");
        };

        assert!(allow.contains_name("INVITE"));
        assert!(!allow.contains_name("invite"));
        assert!(allow.contains_name("X-Method"));
        assert!(!allow.contains_name("x-method"));
    }

    #[test]
    fn repeated_methods_are_preserved() {
        let Ok(allow) = parse(b"INVITE, INVITE, BYE") else {
            panic!("expected repeated methods to remain syntactically valid");
        };

        assert_eq!(allow.len(), 3);
        assert_eq!(allow.methods()[0], Method::Invite);
        assert_eq!(allow.methods()[1], Method::Invite);
        assert_eq!(allow.methods()[2], Method::Bye);
    }

    #[test]
    fn default_is_empty() {
        let allow = Allow::default();

        assert!(allow.is_empty());
        assert_eq!(allow.to_string(), "");
    }

    #[test]
    fn single_constructor_contains_method() {
        let allow = Allow::single(Method::Register);

        assert_eq!(allow.len(), 1);
        assert!(allow.contains(&Method::Register));
    }

    #[test]
    fn constructs_from_empty_method_vector() {
        let Ok(allow) = Allow::from_methods(Vec::new()) else {
            panic!("expected valid empty method vector");
        };

        assert!(allow.is_empty());
    }

    #[test]
    fn constructs_from_multiple_methods() {
        let methods = vec![Method::Invite, Method::Ack, Method::Bye];

        let Ok(allow) = Allow::from_methods(methods) else {
            panic!("expected valid method vector");
        };

        assert_eq!(allow.to_string(), "INVITE, ACK, BYE");
    }

    #[test]
    fn push_appends_method() {
        let mut allow = Allow::new();

        assert!(allow.push(Method::Invite).is_ok());
        assert!(allow.push(Method::Ack).is_ok());
        assert!(allow.push(Method::Bye).is_ok());

        assert_eq!(allow.to_string(), "INVITE, ACK, BYE");
    }

    #[test]
    fn push_allows_duplicate_method() {
        let mut allow = Allow::single(Method::Invite);

        assert!(allow.push(Method::Invite).is_ok());

        assert_eq!(allow.len(), 2);
    }

    #[test]
    fn rejects_leading_comma() {
        assert_eq!(
            parse(b", INVITE"),
            Err(ParseError::EmptyMethod { method_index: 0 })
        );
    }

    #[test]
    fn rejects_trailing_comma() {
        assert_eq!(
            parse(b"INVITE,"),
            Err(ParseError::EmptyMethod { method_index: 1 })
        );
    }

    #[test]
    fn rejects_empty_middle_method() {
        assert_eq!(
            parse(b"INVITE, , BYE"),
            Err(ParseError::EmptyMethod { method_index: 1 })
        );
    }

    #[test]
    fn rejects_semicolon_separator() {
        assert!(matches!(
            parse(b"INVITE;BYE"),
            Err(ParseError::InvalidMethod(_))
        ));
    }

    #[test]
    fn rejects_internal_method_whitespace() {
        assert!(matches!(
            parse(b"INV ITE"),
            Err(ParseError::InvalidMethod(_))
        ));
    }

    #[test]
    fn rejects_invalid_method_character() {
        assert!(matches!(
            parse(b"INV@ITE"),
            Err(ParseError::InvalidMethod(_))
        ));
    }

    #[test]
    fn rejects_embedded_crlf() {
        assert_eq!(parse(b"INVITE,\r\n ACK"), Err(ParseError::InvalidLineBreak));
    }

    #[test]
    fn rejects_field_above_size_limit() {
        let input = vec![b'A'; MAX_ALLOW_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_ALLOW_BYTES + 1,
                maximum: MAX_ALLOW_BYTES,
            })
        );
    }

    #[test]
    fn rejects_too_many_methods_during_construction() {
        let methods = (0..=MAX_ALLOW_METHODS)
            .map(|_| Method::Invite)
            .collect::<Vec<_>>();

        assert_eq!(
            Allow::from_methods(methods),
            Err(ParseError::TooManyMethods {
                maximum: MAX_ALLOW_METHODS,
            })
        );
    }

    #[test]
    fn rejects_too_many_methods_during_parsing() {
        let input = std::iter::repeat_n("INVITE", MAX_ALLOW_METHODS + 1)
            .collect::<Vec<_>>()
            .join(",");

        assert_eq!(
            parse(input.as_bytes()),
            Err(ParseError::TooManyMethods {
                maximum: MAX_ALLOW_METHODS,
            })
        );
    }

    #[test]
    fn push_enforces_method_count() {
        let methods = (0..MAX_ALLOW_METHODS)
            .map(|_| Method::Invite)
            .collect::<Vec<_>>();

        let Ok(mut allow) = Allow::from_methods(methods) else {
            panic!("expected method list at operational limit");
        };

        assert_eq!(
            allow.push(Method::Bye),
            Err(ParseError::TooManyMethods {
                maximum: MAX_ALLOW_METHODS,
            })
        );
    }

    #[test]
    fn parses_from_str() {
        let Ok(allow) = Allow::from_str("INVITE, ACK, BYE") else {
            panic!("expected valid Allow value");
        };

        assert_eq!(allow.len(), 3);
    }

    #[test]
    fn empty_string_parses_from_str() {
        let Ok(allow) = Allow::from_str("") else {
            panic!("expected valid empty Allow value");
        };

        assert!(allow.is_empty());
    }

    #[test]
    fn consumes_into_methods() {
        let Ok(allow) = parse(b"INVITE, ACK") else {
            panic!("expected valid Allow value");
        };

        let methods = allow.into_methods();

        assert_eq!(methods, vec![Method::Invite, Method::Ack]);
    }

    #[test]
    fn invalid_method_exposes_source_error() {
        let Err(error) = parse(b"INV@ITE") else {
            panic!("expected invalid method");
        };

        assert!(error.source().is_some());
    }

    #[test]
    fn non_nested_error_has_no_source() {
        let error = ParseError::EmptyMethod { method_index: 0 };

        assert!(error.source().is_none());
    }

    #[test]
    fn display_preserves_extension_case_and_canonicalizes_core_methods() {
        let Ok(allow) = parse(b"invite, ACK, X-Mixed-Case") else {
            panic!("expected valid Allow value");
        };

        assert_eq!(allow.to_string(), "invite, ACK, X-Mixed-Case");
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(
            ParseError::TooLong {
                length: MAX_ALLOW_BYTES + 1,
                maximum: MAX_ALLOW_BYTES,
            }
            .class(),
            "too-long"
        );

        assert_eq!(ParseError::InvalidLineBreak.class(), "invalid-line-break");

        assert_eq!(
            ParseError::EmptyMethod { method_index: 1 }.class(),
            "empty-method"
        );

        assert_eq!(
            ParseError::TooManyMethods {
                maximum: MAX_ALLOW_METHODS,
            }
            .class(),
            "too-many-methods"
        );
    }
}
