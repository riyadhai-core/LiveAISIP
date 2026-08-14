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

//! SIP `Max-Forwards` header.
//!
//! This module provides the strongly typed representation of the SIP
//! `Max-Forwards` field value.
//!
//! Parsing is allocation-free and accepts only an unsigned decimal value in
//! the inclusive range `0..=255`. Header-line whitespace and unfolding are
//! responsibilities of the generic SIP header parser.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

/// Conventional initial SIP `Max-Forwards` value.
pub const DEFAULT_MAX_FORWARDS: u8 = 70;

/// Largest valid SIP `Max-Forwards` value.
pub const MAX_MAX_FORWARDS: u8 = u8::MAX;

/// A validated SIP `Max-Forwards` field value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct MaxForwards(u8);

impl MaxForwards {
    /// Creates a `Max-Forwards` value from an already bounded `u8`.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Parses a `Max-Forwards` field value from wire bytes.
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
    /// [`ParseError::OutOfRange`] when the value exceeds `255`.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(ParseError::Empty);
        }

        let mut value = 0_u16;

        for (index, byte) in input.iter().copied().enumerate() {
            if !byte.is_ascii_digit() {
                return Err(ParseError::InvalidDigit { index, byte });
            }

            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(u16::from(byte - b'0')))
                .ok_or(ParseError::OutOfRange)?;

            if value > u16::from(MAX_MAX_FORWARDS) {
                return Err(ParseError::OutOfRange);
            }
        }

        let value = u8::try_from(value).map_err(|_| ParseError::OutOfRange)?;

        Ok(Self(value))
    }

    /// Returns the numeric `Max-Forwards` value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Returns whether the forwarding budget has been exhausted.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns the value after consuming one forwarding hop.
    ///
    /// Returns `None` when this value is already zero.
    #[must_use]
    pub const fn checked_decrement(self) -> Option<Self> {
        match self.0.checked_sub(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

impl Default for MaxForwards {
    fn default() -> Self {
        Self(DEFAULT_MAX_FORWARDS)
    }
}

impl fmt::Display for MaxForwards {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl FromStr for MaxForwards {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

impl From<u8> for MaxForwards {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<MaxForwards> for u8 {
    fn from(max_forwards: MaxForwards) -> Self {
        max_forwards.as_u8()
    }
}

impl TryFrom<u16> for MaxForwards {
    type Error = ParseError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let value = u8::try_from(value).map_err(|_| ParseError::OutOfRange)?;

        Ok(Self(value))
    }
}

/// Failure to parse or construct a SIP `Max-Forwards` value.
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

    /// The field value exceeded the valid `0..=255` range.
    OutOfRange,
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::InvalidDigit { .. } => "invalid-digit",
            Self::OutOfRange => "out-of-range",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP Max-Forwards is empty"),
            Self::InvalidDigit { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP Max-Forwards byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::OutOfRange => {
                formatter.write_str("SIP Max-Forwards exceeds the valid range 0..=255")
            }
        }
    }
}

impl StdError for ParseError {}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_MAX_FORWARDS, MAX_MAX_FORWARDS, MaxForwards, ParseError};
    use std::str::FromStr;

    #[test]
    fn default_is_seventy() {
        let value = MaxForwards::default();

        assert_eq!(value.as_u8(), DEFAULT_MAX_FORWARDS);
        assert_eq!(value.as_u8(), 70);
    }

    #[test]
    fn creates_from_u8() {
        let value = MaxForwards::new(42);

        assert_eq!(value.as_u8(), 42);
    }

    #[test]
    fn parses_zero() {
        let Ok(value) = MaxForwards::from_bytes(b"0") else {
            panic!("expected valid zero Max-Forwards");
        };

        assert_eq!(value.as_u8(), 0);
        assert!(value.is_zero());
    }

    #[test]
    fn parses_conventional_initial_value() {
        let Ok(value) = MaxForwards::from_bytes(b"70") else {
            panic!("expected valid Max-Forwards");
        };

        assert_eq!(value.as_u8(), 70);
        assert!(!value.is_zero());
    }

    #[test]
    fn parses_maximum_value() {
        let Ok(value) = MaxForwards::from_bytes(b"255") else {
            panic!("expected maximum Max-Forwards value");
        };

        assert_eq!(value.as_u8(), MAX_MAX_FORWARDS);
    }

    #[test]
    fn accepts_leading_zeroes() {
        let Ok(value) = MaxForwards::from_bytes(b"00070") else {
            panic!("expected valid Max-Forwards with leading zeroes");
        };

        assert_eq!(value.as_u8(), 70);
        assert_eq!(value.to_string(), "70");
    }

    #[test]
    fn rejects_empty_value() {
        assert_eq!(MaxForwards::from_bytes(b""), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_value_above_maximum() {
        assert_eq!(MaxForwards::from_bytes(b"256"), Err(ParseError::OutOfRange));
    }

    #[test]
    fn rejects_large_decimal_without_integer_overflow() {
        assert_eq!(
            MaxForwards::from_bytes(b"99999999999999999999999999999999"),
            Err(ParseError::OutOfRange)
        );
    }

    #[test]
    fn rejects_leading_space() {
        assert_eq!(
            MaxForwards::from_bytes(b" 70"),
            Err(ParseError::InvalidDigit {
                index: 0,
                byte: b' ',
            })
        );
    }

    #[test]
    fn rejects_trailing_space() {
        assert_eq!(
            MaxForwards::from_bytes(b"70 "),
            Err(ParseError::InvalidDigit {
                index: 2,
                byte: b' ',
            })
        );
    }

    #[test]
    fn rejects_plus_sign() {
        assert_eq!(
            MaxForwards::from_bytes(b"+70"),
            Err(ParseError::InvalidDigit {
                index: 0,
                byte: b'+',
            })
        );
    }

    #[test]
    fn rejects_negative_sign() {
        assert_eq!(
            MaxForwards::from_bytes(b"-1"),
            Err(ParseError::InvalidDigit {
                index: 0,
                byte: b'-',
            })
        );
    }

    #[test]
    fn rejects_non_decimal_input() {
        assert_eq!(
            MaxForwards::from_bytes(b"7a"),
            Err(ParseError::InvalidDigit {
                index: 1,
                byte: b'a',
            })
        );
    }

    #[test]
    fn checked_decrement_consumes_one_hop() {
        let value = MaxForwards::new(70);

        let Some(next) = value.checked_decrement() else {
            panic!("expected forwarding budget");
        };

        assert_eq!(next.as_u8(), 69);
    }

    #[test]
    fn checked_decrement_of_one_returns_zero() {
        let value = MaxForwards::new(1);

        let Some(next) = value.checked_decrement() else {
            panic!("expected forwarding budget");
        };

        assert_eq!(next.as_u8(), 0);
        assert!(next.is_zero());
    }

    #[test]
    fn checked_decrement_of_zero_returns_none() {
        let value = MaxForwards::new(0);

        assert_eq!(value.checked_decrement(), None);
    }

    #[test]
    fn display_is_canonical_decimal() {
        let value = MaxForwards::new(70);

        assert_eq!(value.to_string(), "70");
    }

    #[test]
    fn parses_from_str() {
        let Ok(value) = MaxForwards::from_str("32") else {
            panic!("expected valid Max-Forwards");
        };

        assert_eq!(value.as_u8(), 32);
    }

    #[test]
    fn converts_from_u8() {
        let value = MaxForwards::from(10_u8);

        assert_eq!(value.as_u8(), 10);
    }

    #[test]
    fn converts_into_u8() {
        let value = MaxForwards::new(10);

        assert_eq!(u8::from(value), 10);
    }

    #[test]
    fn try_from_u16_accepts_maximum() {
        let Ok(value) = MaxForwards::try_from(255_u16) else {
            panic!("expected valid Max-Forwards");
        };

        assert_eq!(value.as_u8(), 255);
    }

    #[test]
    fn try_from_u16_rejects_value_above_maximum() {
        assert_eq!(MaxForwards::try_from(256_u16), Err(ParseError::OutOfRange));
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
        assert_eq!(ParseError::OutOfRange.class(), "out-of-range");
    }
}
