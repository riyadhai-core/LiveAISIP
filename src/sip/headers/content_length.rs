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

//! SIP `Content-Length` header.
//!
//! This module provides the strongly typed representation of the SIP
//! `Content-Length` field value.
//!
//! Parsing is allocation-free and accepts only the decimal digits belonging to
//! the field value. Header-line whitespace and unfolding are responsibilities
//! of the generic SIP header parser.
//!
//! The accepted body size is bounded by the same operational limit used by the
//! SIP framing subsystem.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use crate::sip::framing::MAX_BODY_BYTES;

/// Maximum accepted SIP `Content-Length` value.
///
/// This is the same `LiveAISIP` operational bound used by SIP framing rather
/// than a protocol-defined SIP maximum.
pub const MAX_CONTENT_LENGTH_BYTES: usize = MAX_BODY_BYTES;

/// A validated SIP `Content-Length` field value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ContentLength(usize);

impl ContentLength {
    /// Creates a `Content-Length` value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooLarge`] when `length` exceeds the configured
    /// operational body-size limit.
    pub const fn new(length: usize) -> Result<Self, ParseError> {
        if length > MAX_CONTENT_LENGTH_BYTES {
            return Err(ParseError::TooLarge {
                maximum: MAX_CONTENT_LENGTH_BYTES,
            });
        }

        Ok(Self(length))
    }

    /// Parses a `Content-Length` field value from wire bytes.
    ///
    /// The input must contain one or more ASCII decimal digits and no
    /// surrounding whitespace.
    ///
    /// Parsing performs no allocation.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Empty`] for an empty value,
    /// [`ParseError::InvalidDigit`] for non-decimal input, or
    /// [`ParseError::TooLarge`] when the declared body size exceeds the
    /// configured operational limit.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(ParseError::Empty);
        }

        let mut length = 0_usize;

        for (index, byte) in input.iter().copied().enumerate() {
            if !byte.is_ascii_digit() {
                return Err(ParseError::InvalidDigit { index, byte });
            }

            let digit = usize::from(byte - b'0');

            if length > (MAX_CONTENT_LENGTH_BYTES - digit) / 10 {
                return Err(ParseError::TooLarge {
                    maximum: MAX_CONTENT_LENGTH_BYTES,
                });
            }

            length = length * 10 + digit;
        }

        Ok(Self(length))
    }

    /// Returns the declared body size in bytes.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Returns whether the message declares an empty body.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for ContentLength {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl FromStr for ContentLength {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

impl TryFrom<usize> for ContentLength {
    type Error = ParseError;

    fn try_from(length: usize) -> Result<Self, Self::Error> {
        Self::new(length)
    }
}

impl From<ContentLength> for usize {
    fn from(content_length: ContentLength) -> Self {
        content_length.as_usize()
    }
}

/// Failure to parse or construct a SIP `Content-Length` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The field value was empty.
    Empty,

    /// The field value contained a non-decimal byte.
    InvalidDigit {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// The declared body size exceeded the configured operational limit.
    TooLarge {
        /// Maximum accepted body size in bytes.
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
            Self::InvalidDigit { .. } => "invalid-digit",
            Self::TooLarge { .. } => "too-large",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP Content-Length is empty"),
            Self::InvalidDigit { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP Content-Length byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::TooLarge { maximum } => {
                write!(
                    formatter,
                    "SIP Content-Length exceeds maximum body size of {maximum} bytes"
                )
            }
        }
    }
}

impl StdError for ParseError {}

#[cfg(test)]
mod tests {
    use super::{ContentLength, MAX_CONTENT_LENGTH_BYTES, ParseError};
    use std::str::FromStr;

    #[test]
    fn parses_zero() {
        assert_eq!(
            ContentLength::from_bytes(b"0"),
            Ok(ContentLength::new(0).unwrap_or_else(|_| unreachable!()))
        );
    }

    #[test]
    fn parses_positive_value() {
        let Ok(length) = ContentLength::from_bytes(b"160") else {
            panic!("expected valid Content-Length");
        };

        assert_eq!(length.as_usize(), 160);
        assert!(!length.is_zero());
    }

    #[test]
    fn accepts_leading_zeroes() {
        let Ok(length) = ContentLength::from_bytes(b"000160") else {
            panic!("expected valid Content-Length");
        };

        assert_eq!(length.as_usize(), 160);
        assert_eq!(length.to_string(), "160");
    }

    #[test]
    fn zero_reports_empty_body() {
        let Ok(length) = ContentLength::new(0) else {
            panic!("expected zero Content-Length");
        };

        assert!(length.is_zero());
    }

    #[test]
    fn rejects_empty_value() {
        assert_eq!(ContentLength::from_bytes(b""), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_space() {
        assert_eq!(
            ContentLength::from_bytes(b"12 3"),
            Err(ParseError::InvalidDigit {
                index: 2,
                byte: b' ',
            })
        );
    }

    #[test]
    fn rejects_leading_space() {
        assert_eq!(
            ContentLength::from_bytes(b" 123"),
            Err(ParseError::InvalidDigit {
                index: 0,
                byte: b' ',
            })
        );
    }

    #[test]
    fn rejects_trailing_space() {
        assert_eq!(
            ContentLength::from_bytes(b"123 "),
            Err(ParseError::InvalidDigit {
                index: 3,
                byte: b' ',
            })
        );
    }

    #[test]
    fn rejects_plus_sign() {
        assert_eq!(
            ContentLength::from_bytes(b"+1"),
            Err(ParseError::InvalidDigit {
                index: 0,
                byte: b'+',
            })
        );
    }

    #[test]
    fn rejects_negative_sign() {
        assert_eq!(
            ContentLength::from_bytes(b"-1"),
            Err(ParseError::InvalidDigit {
                index: 0,
                byte: b'-',
            })
        );
    }

    #[test]
    fn rejects_non_decimal_input() {
        assert_eq!(
            ContentLength::from_bytes(b"12a"),
            Err(ParseError::InvalidDigit {
                index: 2,
                byte: b'a',
            })
        );
    }

    #[test]
    fn accepts_operational_maximum() {
        let input = MAX_CONTENT_LENGTH_BYTES.to_string();

        let Ok(length) = ContentLength::from_bytes(input.as_bytes()) else {
            panic!("expected operational maximum to be valid");
        };

        assert_eq!(length.as_usize(), MAX_CONTENT_LENGTH_BYTES);
    }

    #[test]
    fn rejects_value_above_operational_maximum() {
        let input = (MAX_CONTENT_LENGTH_BYTES + 1).to_string();

        assert_eq!(
            ContentLength::from_bytes(input.as_bytes()),
            Err(ParseError::TooLarge {
                maximum: MAX_CONTENT_LENGTH_BYTES,
            })
        );
    }

    #[test]
    fn rejects_very_large_decimal_without_integer_overflow() {
        let input = b"99999999999999999999999999999999999999999999999999";

        assert_eq!(
            ContentLength::from_bytes(input),
            Err(ParseError::TooLarge {
                maximum: MAX_CONTENT_LENGTH_BYTES,
            })
        );
    }

    #[test]
    fn constructor_enforces_operational_maximum() {
        assert!(ContentLength::new(MAX_CONTENT_LENGTH_BYTES).is_ok());

        assert_eq!(
            ContentLength::new(MAX_CONTENT_LENGTH_BYTES + 1),
            Err(ParseError::TooLarge {
                maximum: MAX_CONTENT_LENGTH_BYTES,
            })
        );
    }

    #[test]
    fn display_is_canonical_decimal() {
        let Ok(length) = ContentLength::new(4096) else {
            panic!("expected valid Content-Length");
        };

        assert_eq!(length.to_string(), "4096");
    }

    #[test]
    fn parses_from_str() {
        let Ok(length) = ContentLength::from_str("512") else {
            panic!("expected valid Content-Length");
        };

        assert_eq!(length.as_usize(), 512);
    }

    #[test]
    fn converts_to_and_from_usize() {
        let Ok(length) = ContentLength::try_from(1024_usize) else {
            panic!("expected valid Content-Length");
        };

        assert_eq!(usize::from(length), 1024);
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");
        assert_eq!(
            ParseError::InvalidDigit {
                index: 0,
                byte: b'x',
            }
            .class(),
            "invalid-digit"
        );
        assert_eq!(
            ParseError::TooLarge {
                maximum: MAX_CONTENT_LENGTH_BYTES,
            }
            .class(),
            "too-large"
        );
    }
}
