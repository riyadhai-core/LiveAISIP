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

//! SIP `Call-ID` header.
//!
//! This module provides the strongly typed representation of the SIP
//! `Call-ID` field value.
//!
//! A `Call-ID` is preserved exactly as received after validation. Its value is
//! case-sensitive and is never normalized, decoded, or rewritten.
//!
//! Parsing is allocation-free until a successfully validated identifier is
//! transferred into the owned [`CallId`] representation.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

/// Maximum accepted SIP `Call-ID` size in bytes.
///
/// SIP does not define this operational ceiling. `LiveAISIP` applies a bounded
/// value to prevent malformed or hostile identifiers from consuming
/// unbounded memory.
pub const MAX_CALL_ID_BYTES: usize = 1024;

/// A validated SIP `Call-ID` field value.
///
/// Equality and hashing are intentionally case-sensitive.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CallId(Box<str>);

impl CallId {
    /// Creates a validated `Call-ID` from owned or borrowed text.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the value violates the SIP `Call-ID`
    /// grammar or exceeds the configured operational size limit.
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let value = value.into();

        validate(value.as_bytes())?;

        Ok(Self(value))
    }

    /// Parses a SIP `Call-ID` from wire bytes.
    ///
    /// The accepted grammar is:
    ///
    /// ```text
    /// callid = word [ "@" word ]
    /// ```
    ///
    /// No surrounding whitespace is accepted here. Whitespace surrounding a
    /// header field value must be handled by the generic header parser.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the value is empty, too large, contains an
    /// invalid `word` byte, contains multiple `@` separators, or contains an
    /// empty component around `@`.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        validate(input)?;

        let value = std::str::from_utf8(input).map_err(|_| {
            let (index, byte) = first_non_ascii(input).unwrap_or((0, 0));

            ParseError::InvalidWordByte { index, byte }
        })?;

        Ok(Self(value.into()))
    }

    /// Returns the complete `Call-ID` value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the complete `Call-ID` as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the identifier portion before the optional `@`.
    #[must_use]
    pub fn local_id(&self) -> &str {
        match self.0.split_once('@') {
            Some((local_id, _)) => local_id,
            None => &self.0,
        }
    }

    /// Returns the optional component following `@`.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.0.split_once('@').map(|(_, host)| host)
    }

    /// Returns whether the identifier contains an `@` component.
    #[must_use]
    pub fn has_host(&self) -> bool {
        self.0.as_bytes().contains(&b'@')
    }

    /// Returns the complete identifier length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the identifier is empty.
    ///
    /// A successfully constructed `Call-ID` is never empty, so this always
    /// returns `false`. The method is provided alongside [`CallId::len`] for
    /// conventional container-style inspection.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for CallId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallId")
            .field("bytes", &self.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for CallId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CallId {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

fn validate(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    if input.len() > MAX_CALL_ID_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_CALL_ID_BYTES,
        });
    }

    let mut separator = None;

    for (index, byte) in input.iter().copied().enumerate() {
        if byte == b'@' {
            if separator.is_some() {
                return Err(ParseError::MultipleAtSigns { index });
            }

            separator = Some(index);
            continue;
        }

        if !is_word_byte(byte) {
            return Err(ParseError::InvalidWordByte { index, byte });
        }
    }

    if let Some(index) = separator {
        if index == 0 {
            return Err(ParseError::EmptyLocalId);
        }

        if index == input.len() - 1 {
            return Err(ParseError::EmptyHost);
        }
    }

    Ok(())
}

fn first_non_ascii(input: &[u8]) -> Option<(usize, u8)> {
    input
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| !byte.is_ascii())
}

const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'!'
                | b'%'
                | b'*'
                | b'_'
                | b'+'
                | b'`'
                | b'\''
                | b'~'
                | b'('
                | b')'
                | b'<'
                | b'>'
                | b':'
                | b'\\'
                | b'"'
                | b'/'
                | b'['
                | b']'
                | b'?'
                | b'{'
                | b'}'
        )
}

/// Failure to parse or construct a SIP `Call-ID` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The field value was empty.
    Empty,

    /// The identifier exceeded the configured operational size limit.
    TooLong {
        /// Actual identifier length in bytes.
        length: usize,

        /// Maximum accepted identifier length in bytes.
        maximum: usize,
    },

    /// A byte was not valid in the SIP `word` grammar.
    InvalidWordByte {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// More than one raw `@` separator appeared in the identifier.
    MultipleAtSigns {
        /// Offset of the second `@`.
        index: usize,
    },

    /// The identifier portion before `@` was empty.
    EmptyLocalId,

    /// The component following `@` was empty.
    EmptyHost,
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong { .. } => "too-long",
            Self::InvalidWordByte { .. } => "invalid-word-byte",
            Self::MultipleAtSigns { .. } => "multiple-at-signs",
            Self::EmptyLocalId => "empty-local-id",
            Self::EmptyHost => "empty-host",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP Call-ID is empty"),
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP Call-ID length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidWordByte { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP Call-ID byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::MultipleAtSigns { index } => {
                write!(
                    formatter,
                    "SIP Call-ID contains multiple @ separators; additional separator at offset {index}"
                )
            }
            Self::EmptyLocalId => {
                formatter.write_str("SIP Call-ID has an empty identifier before @")
            }
            Self::EmptyHost => formatter.write_str("SIP Call-ID has an empty component after @"),
        }
    }
}

impl StdError for ParseError {}

#[cfg(test)]
mod tests {
    use super::{CallId, MAX_CALL_ID_BYTES, ParseError};
    use std::collections::HashSet;
    use std::str::FromStr;

    #[test]
    fn parses_simple_call_id() {
        let Ok(call_id) = CallId::from_bytes(b"a84b4c76e66710") else {
            panic!("expected valid Call-ID");
        };

        assert_eq!(call_id.as_str(), "a84b4c76e66710");
        assert_eq!(call_id.local_id(), "a84b4c76e66710");
        assert_eq!(call_id.host(), None);
        assert!(!call_id.has_host());
    }

    #[test]
    fn parses_call_id_with_host_component() {
        let Ok(call_id) = CallId::from_bytes(b"a84b4c76e66710@pc33.atlanta.com") else {
            panic!("expected valid Call-ID");
        };

        assert_eq!(call_id.local_id(), "a84b4c76e66710");
        assert_eq!(call_id.host(), Some("pc33.atlanta.com"));
        assert!(call_id.has_host());
    }

    #[test]
    fn preserves_wire_value_exactly() {
        let input = "AbC-123_XYZ@example.COM";

        let Ok(call_id) = CallId::new(input) else {
            panic!("expected valid Call-ID");
        };

        assert_eq!(call_id.as_str(), input);
        assert_eq!(call_id.to_string(), input);
    }

    #[test]
    fn equality_is_case_sensitive() {
        let Ok(first) = CallId::new("ABC@example.com") else {
            panic!("expected valid Call-ID");
        };
        let Ok(second) = CallId::new("abc@example.com") else {
            panic!("expected valid Call-ID");
        };

        assert_ne!(first, second);
    }

    #[test]
    fn hashing_is_case_sensitive() {
        let Ok(first) = CallId::new("ABC@example.com") else {
            panic!("expected valid Call-ID");
        };
        let Ok(second) = CallId::new("abc@example.com") else {
            panic!("expected valid Call-ID");
        };

        let mut identifiers = HashSet::new();

        assert!(identifiers.insert(first));
        assert!(identifiers.insert(second));
        assert_eq!(identifiers.len(), 2);
    }

    #[test]
    fn accepts_complete_word_character_set() {
        let value = r#"Az09-.!%*_+`'~()<>:\"/[]?{}"#;

        let Ok(call_id) = CallId::new(value) else {
            panic!("expected SIP word characters to be valid");
        };

        assert_eq!(call_id.as_str(), value);
    }

    #[test]
    fn accepts_word_character_set_on_both_sides_of_at() {
        let value = r"left-._+!%'~@right-._+!%'~";

        let Ok(call_id) = CallId::new(value) else {
            panic!("expected valid Call-ID components");
        };

        assert_eq!(call_id.local_id(), "left-._+!%'~");
        assert_eq!(call_id.host(), Some("right-._+!%'~"));
    }

    #[test]
    fn rejects_empty_call_id() {
        assert_eq!(CallId::from_bytes(b""), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_space() {
        assert_eq!(
            CallId::from_bytes(b"abc def"),
            Err(ParseError::InvalidWordByte {
                index: 3,
                byte: b' ',
            })
        );
    }

    #[test]
    fn rejects_horizontal_tab() {
        assert_eq!(
            CallId::from_bytes(b"abc\tdef"),
            Err(ParseError::InvalidWordByte {
                index: 3,
                byte: b'\t',
            })
        );
    }

    #[test]
    fn rejects_carriage_return() {
        assert_eq!(
            CallId::from_bytes(b"abc\rdef"),
            Err(ParseError::InvalidWordByte {
                index: 3,
                byte: b'\r',
            })
        );
    }

    #[test]
    fn rejects_line_feed() {
        assert_eq!(
            CallId::from_bytes(b"abc\ndef"),
            Err(ParseError::InvalidWordByte {
                index: 3,
                byte: b'\n',
            })
        );
    }

    #[test]
    fn rejects_comma() {
        assert_eq!(
            CallId::from_bytes(b"abc,def"),
            Err(ParseError::InvalidWordByte {
                index: 3,
                byte: b',',
            })
        );
    }

    #[test]
    fn rejects_semicolon() {
        assert_eq!(
            CallId::from_bytes(b"abc;def"),
            Err(ParseError::InvalidWordByte {
                index: 3,
                byte: b';',
            })
        );
    }

    #[test]
    fn rejects_equal_sign() {
        assert_eq!(
            CallId::from_bytes(b"abc=def"),
            Err(ParseError::InvalidWordByte {
                index: 3,
                byte: b'=',
            })
        );
    }

    #[test]
    fn rejects_non_ascii_byte() {
        assert_eq!(
            CallId::from_bytes(b"abc\xff"),
            Err(ParseError::InvalidWordByte {
                index: 3,
                byte: 0xff,
            })
        );
    }

    #[test]
    fn rejects_empty_local_id() {
        assert_eq!(
            CallId::from_bytes(b"@example.com"),
            Err(ParseError::EmptyLocalId)
        );
    }

    #[test]
    fn rejects_empty_host_component() {
        assert_eq!(
            CallId::from_bytes(b"identifier@"),
            Err(ParseError::EmptyHost)
        );
    }

    #[test]
    fn rejects_multiple_at_signs() {
        assert_eq!(
            CallId::from_bytes(b"identifier@example.com@other.example.com"),
            Err(ParseError::MultipleAtSigns { index: 22 })
        );
    }

    #[test]
    fn accepts_value_at_size_limit() {
        let value = "A".repeat(MAX_CALL_ID_BYTES);

        let Ok(call_id) = CallId::new(value) else {
            panic!("expected Call-ID at operational limit");
        };

        assert_eq!(call_id.len(), MAX_CALL_ID_BYTES);
    }

    #[test]
    fn rejects_value_above_size_limit() {
        let value = "A".repeat(MAX_CALL_ID_BYTES + 1);

        assert_eq!(
            CallId::new(value),
            Err(ParseError::TooLong {
                length: MAX_CALL_ID_BYTES + 1,
                maximum: MAX_CALL_ID_BYTES,
            })
        );
    }

    #[test]
    fn parses_from_str() {
        let Ok(call_id) = CallId::from_str("abc123@example.com") else {
            panic!("expected valid Call-ID");
        };

        assert_eq!(call_id.as_str(), "abc123@example.com");
    }

    #[test]
    fn exposes_raw_bytes() {
        let Ok(call_id) = CallId::new("abc123@example.com") else {
            panic!("expected valid Call-ID");
        };

        assert_eq!(call_id.as_bytes(), b"abc123@example.com");
    }

    #[test]
    fn display_preserves_value() {
        let Ok(call_id) = CallId::new("AbC123@example.COM") else {
            panic!("expected valid Call-ID");
        };

        assert_eq!(call_id.to_string(), "AbC123@example.COM");
    }

    #[test]
    fn debug_does_not_expose_identifier() {
        let Ok(call_id) = CallId::new("sensitive-id@example.com") else {
            panic!("expected valid Call-ID");
        };

        let debug = format!("{call_id:?}");

        assert!(debug.contains("CallId"));
        assert!(debug.contains("bytes"));
        assert!(!debug.contains("sensitive-id"));
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");

        assert_eq!(
            ParseError::TooLong {
                length: 1025,
                maximum: 1024,
            }
            .class(),
            "too-long"
        );

        assert_eq!(
            ParseError::InvalidWordByte {
                index: 0,
                byte: b' ',
            }
            .class(),
            "invalid-word-byte"
        );

        assert_eq!(
            ParseError::MultipleAtSigns { index: 4 }.class(),
            "multiple-at-signs"
        );

        assert_eq!(ParseError::EmptyLocalId.class(), "empty-local-id");
        assert_eq!(ParseError::EmptyHost.class(), "empty-host");
    }
}
