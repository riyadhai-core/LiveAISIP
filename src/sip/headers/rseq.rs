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

//! SIP `RSeq` header.
//!
//! This module provides strongly typed parsing and serialization for the SIP
//! `RSeq` field value used by reliable provisional responses.
//!
//! An `RSeq` field contains one unsigned decimal response sequence number in
//! the inclusive range `1..=u32::MAX`.
//!
//! The first reliable provisional response in a transaction uses the narrower
//! initialization range `1..=2^31-1`. Later reliable provisional responses
//! increase the sequence number by exactly one and must never wrap.
//!
//! This module enforces the numeric wire-value constraints and provides
//! explicit helpers for initial-sequence validation and checked advancement.
//! Transaction-level sequencing and PRACK correlation belong to higher SIP
//! transaction and dialog layers.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

/// Maximum accepted SIP `RSeq` field-value size in bytes.
///
/// Valid canonical `RSeq` values require at most ten decimal digits. This
/// larger operational bound permits surrounding horizontal whitespace while
/// keeping parsing work strictly bounded.
pub const MAX_RSEQ_BYTES: usize = 64;

/// Smallest valid `RSeq` value.
pub const MIN_RSEQ: u32 = 1;

/// Largest valid `RSeq` value.
pub const MAX_RSEQ: u32 = u32::MAX;

/// Largest valid initial `RSeq` value for the first reliable provisional
/// response in a transaction.
pub const MAX_INITIAL_RSEQ: u32 = i32::MAX as u32;

/// A validated SIP `RSeq` field value.
///
/// The contained value is always in the inclusive range [`MIN_RSEQ`] through
/// [`MAX_RSEQ`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RSeq(u32);

impl RSeq {
    /// Creates a validated `RSeq` value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Zero`] because zero is not a valid `RSeq` value.
    pub const fn new(value: u32) -> Result<Self, ParseError> {
        if value == 0 {
            return Err(ParseError::Zero);
        }

        Ok(Self(value))
    }

    /// Creates a valid initial `RSeq` value.
    ///
    /// The first reliable provisional response in a transaction uses the
    /// narrower range `1..=2^31-1`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Zero`] for zero or
    /// [`ParseError::InitialValueTooLarge`] when `value` exceeds
    /// [`MAX_INITIAL_RSEQ`].
    pub const fn new_initial(value: u32) -> Result<Self, ParseError> {
        if value == 0 {
            return Err(ParseError::Zero);
        }

        if value > MAX_INITIAL_RSEQ {
            return Err(ParseError::InitialValueTooLarge {
                value,
                maximum: MAX_INITIAL_RSEQ,
            });
        }

        Ok(Self(value))
    }

    /// Parses an `RSeq` field value from wire bytes.
    ///
    /// Leading and trailing spaces and horizontal tabs are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the field value is empty, contains a line
    /// break or non-decimal byte, represents zero, overflows `u32`, or exceeds
    /// the operational field-value size bound.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns the response sequence number.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Returns whether this value is valid as the initial `RSeq` number for
    /// the first reliable provisional response in a transaction.
    #[must_use]
    pub const fn is_valid_initial(self) -> bool {
        self.0 <= MAX_INITIAL_RSEQ
    }

    /// Returns the next `RSeq` value without modifying this one.
    ///
    /// `RSeq` values must not wrap. A value of [`MAX_RSEQ`] therefore has no
    /// successor.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::SequenceExhausted`] when this value is already
    /// [`MAX_RSEQ`].
    pub const fn checked_next(self) -> Result<Self, ParseError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(ParseError::SequenceExhausted),
        }
    }

    /// Advances this `RSeq` value by exactly one.
    ///
    /// The update is transactional. When the sequence space is exhausted, the
    /// existing value remains unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::SequenceExhausted`] when this value is already
    /// [`MAX_RSEQ`].
    pub fn increment(&mut self) -> Result<(), ParseError> {
        let next = self.checked_next()?;
        *self = next;
        Ok(())
    }
}

impl fmt::Display for RSeq {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl FromStr for RSeq {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// Parses a SIP `RSeq` field value.
///
/// # Errors
///
/// Returns [`ParseError`] when the field value violates `RSeq` syntax or an
/// operational bound.
pub fn parse(input: &[u8]) -> Result<RSeq, ParseError> {
    if input.len() > MAX_RSEQ_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_RSEQ_BYTES,
        });
    }

    if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ParseError::InvalidLineBreak);
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut value = 0_u32;

    for (index, byte) in input.iter().copied().enumerate() {
        if !byte.is_ascii_digit() {
            return Err(ParseError::InvalidDigit { index, byte });
        }

        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u32::from(byte - b'0')))
            .ok_or(ParseError::Overflow)?;
    }

    RSeq::new(value)
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

/// Failure to parse, construct, or advance a SIP `RSeq` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The field value was empty.
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

    /// A non-decimal byte appeared in the `RSeq` value.
    InvalidDigit {
        /// Offset within the trimmed field value.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// The decimal value exceeded `u32`.
    Overflow,

    /// Zero was supplied even though `RSeq` values start at one.
    Zero,

    /// An initial `RSeq` value exceeded the initial-sequence range.
    InitialValueTooLarge {
        /// Supplied initial value.
        value: u32,

        /// Largest permitted initial value.
        maximum: u32,
    },

    /// The sequence is already at its maximum value and cannot advance.
    SequenceExhausted,
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
            Self::InvalidDigit { .. } => "invalid-digit",
            Self::Overflow => "overflow",
            Self::Zero => "zero",
            Self::InitialValueTooLarge { .. } => "initial-value-too-large",
            Self::SequenceExhausted => "sequence-exhausted",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP RSeq field value is empty"),
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP RSeq field-value length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidLineBreak => {
                formatter.write_str("SIP RSeq contains an invalid line break")
            }
            Self::InvalidDigit { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP RSeq byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::Overflow => {
                formatter.write_str("SIP RSeq value exceeds the supported 32-bit range")
            }
            Self::Zero => formatter.write_str("SIP RSeq value must be greater than zero"),
            Self::InitialValueTooLarge { value, maximum } => {
                write!(
                    formatter,
                    "initial SIP RSeq value {value} exceeds maximum {maximum}"
                )
            }
            Self::SequenceExhausted => {
                formatter.write_str("SIP RSeq sequence cannot advance without wrapping")
            }
        }
    }
}

impl StdError for ParseError {}

#[cfg(test)]
mod tests {
    use super::{MAX_INITIAL_RSEQ, MAX_RSEQ, MAX_RSEQ_BYTES, MIN_RSEQ, ParseError, RSeq, parse};
    use std::str::FromStr;

    #[test]
    fn parses_minimum_value() {
        let Ok(rseq) = parse(b"1") else {
            panic!("expected valid RSeq");
        };

        assert_eq!(rseq.value(), MIN_RSEQ);
        assert_eq!(rseq.to_string(), "1");
    }

    #[test]
    fn parses_typical_value() {
        let Ok(rseq) = parse(b"988789") else {
            panic!("expected valid RSeq");
        };

        assert_eq!(rseq.value(), 988_789);
    }

    #[test]
    fn parses_maximum_value() {
        let Ok(rseq) = parse(b"4294967295") else {
            panic!("expected maximum RSeq");
        };

        assert_eq!(rseq.value(), MAX_RSEQ);
        assert_eq!(rseq.value(), u32::MAX);
    }

    #[test]
    fn parses_with_surrounding_horizontal_whitespace() {
        let Ok(rseq) = parse(b" \t42\t ") else {
            panic!("expected RSeq with surrounding whitespace");
        };

        assert_eq!(rseq.value(), 42);
        assert_eq!(rseq.to_string(), "42");
    }

    #[test]
    fn canonicalizes_leading_zeroes() {
        let Ok(rseq) = parse(b"00000042") else {
            panic!("expected RSeq with leading zeroes");
        };

        assert_eq!(rseq.value(), 42);
        assert_eq!(rseq.to_string(), "42");
    }

    #[test]
    fn accepts_long_leading_zero_form_within_operational_limit() {
        let input = format!("{}1", "0".repeat(MAX_RSEQ_BYTES - 1));

        let Ok(rseq) = parse(input.as_bytes()) else {
            panic!("expected valid bounded RSeq with leading zeroes");
        };

        assert_eq!(rseq.value(), 1);
    }

    #[test]
    fn rejects_zero() {
        assert_eq!(parse(b"0"), Err(ParseError::Zero));
        assert_eq!(parse(b"0000"), Err(ParseError::Zero));
    }

    #[test]
    fn rejects_empty_field() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b" \t "), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_negative_value() {
        assert_eq!(
            parse(b"-1"),
            Err(ParseError::InvalidDigit {
                index: 0,
                byte: b'-',
            })
        );
    }

    #[test]
    fn rejects_explicit_positive_sign() {
        assert_eq!(
            parse(b"+1"),
            Err(ParseError::InvalidDigit {
                index: 0,
                byte: b'+',
            })
        );
    }

    #[test]
    fn rejects_internal_whitespace() {
        assert_eq!(
            parse(b"4 2"),
            Err(ParseError::InvalidDigit {
                index: 1,
                byte: b' ',
            })
        );
    }

    #[test]
    fn rejects_decimal_point() {
        assert_eq!(
            parse(b"4.2"),
            Err(ParseError::InvalidDigit {
                index: 1,
                byte: b'.',
            })
        );
    }

    #[test]
    fn rejects_alpha_suffix() {
        assert_eq!(
            parse(b"42abc"),
            Err(ParseError::InvalidDigit {
                index: 2,
                byte: b'a',
            })
        );
    }

    #[test]
    fn rejects_u32_overflow() {
        assert_eq!(parse(b"4294967296"), Err(ParseError::Overflow));
    }

    #[test]
    fn rejects_large_decimal_overflow() {
        assert_eq!(
            parse(b"999999999999999999999999999999"),
            Err(ParseError::Overflow)
        );
    }

    #[test]
    fn rejects_embedded_crlf() {
        assert_eq!(parse(b"42\r\n"), Err(ParseError::InvalidLineBreak));

        assert_eq!(parse(b"4\r\n2"), Err(ParseError::InvalidLineBreak));
    }

    #[test]
    fn rejects_field_above_operational_limit() {
        let input = vec![b'0'; MAX_RSEQ_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_RSEQ_BYTES + 1,
                maximum: MAX_RSEQ_BYTES,
            })
        );
    }

    #[test]
    fn constructor_accepts_minimum() {
        let Ok(rseq) = RSeq::new(MIN_RSEQ) else {
            panic!("expected minimum RSeq");
        };

        assert_eq!(rseq.value(), 1);
    }

    #[test]
    fn constructor_accepts_maximum() {
        let Ok(rseq) = RSeq::new(MAX_RSEQ) else {
            panic!("expected maximum RSeq");
        };

        assert_eq!(rseq.value(), u32::MAX);
    }

    #[test]
    fn constructor_rejects_zero() {
        assert_eq!(RSeq::new(0), Err(ParseError::Zero));
    }

    #[test]
    fn initial_constructor_accepts_minimum() {
        let Ok(rseq) = RSeq::new_initial(1) else {
            panic!("expected valid initial RSeq");
        };

        assert_eq!(rseq.value(), 1);
        assert!(rseq.is_valid_initial());
    }

    #[test]
    fn initial_constructor_accepts_maximum_initial_value() {
        let Ok(rseq) = RSeq::new_initial(MAX_INITIAL_RSEQ) else {
            panic!("expected maximum valid initial RSeq");
        };

        assert_eq!(rseq.value(), MAX_INITIAL_RSEQ);
        assert!(rseq.is_valid_initial());
    }

    #[test]
    fn initial_constructor_rejects_zero() {
        assert_eq!(RSeq::new_initial(0), Err(ParseError::Zero));
    }

    #[test]
    fn initial_constructor_rejects_value_above_initial_range() {
        let value = MAX_INITIAL_RSEQ + 1;

        assert_eq!(
            RSeq::new_initial(value),
            Err(ParseError::InitialValueTooLarge {
                value,
                maximum: MAX_INITIAL_RSEQ,
            })
        );
    }

    #[test]
    fn later_rseq_may_exceed_initial_range() {
        let value = MAX_INITIAL_RSEQ + 1;

        let Ok(rseq) = RSeq::new(value) else {
            panic!("expected valid non-initial RSeq");
        };

        assert_eq!(rseq.value(), value);
        assert!(!rseq.is_valid_initial());
    }

    #[test]
    fn checked_next_advances_by_exactly_one() {
        let Ok(rseq) = RSeq::new(42) else {
            panic!("expected valid RSeq");
        };

        let Ok(next) = rseq.checked_next() else {
            panic!("expected RSeq successor");
        };

        assert_eq!(next.value(), 43);
        assert_eq!(rseq.value(), 42);
    }

    #[test]
    fn checked_next_crosses_initial_range_boundary() {
        let Ok(rseq) = RSeq::new(MAX_INITIAL_RSEQ) else {
            panic!("expected valid RSeq");
        };

        let Ok(next) = rseq.checked_next() else {
            panic!("expected RSeq successor");
        };

        assert_eq!(next.value(), MAX_INITIAL_RSEQ + 1);
        assert!(!next.is_valid_initial());
    }

    #[test]
    fn checked_next_rejects_wraparound() {
        let Ok(rseq) = RSeq::new(MAX_RSEQ) else {
            panic!("expected maximum RSeq");
        };

        assert_eq!(rseq.checked_next(), Err(ParseError::SequenceExhausted));
    }

    #[test]
    fn increment_advances_in_place() {
        let Ok(mut rseq) = RSeq::new(100) else {
            panic!("expected valid RSeq");
        };

        assert!(rseq.increment().is_ok());

        assert_eq!(rseq.value(), 101);
    }

    #[test]
    fn increment_is_transactional_at_sequence_exhaustion() {
        let Ok(mut rseq) = RSeq::new(MAX_RSEQ) else {
            panic!("expected maximum RSeq");
        };

        assert_eq!(rseq.increment(), Err(ParseError::SequenceExhausted));

        assert_eq!(rseq.value(), MAX_RSEQ);
    }

    #[test]
    fn parses_from_str() {
        let Ok(rseq) = RSeq::from_str("42") else {
            panic!("expected valid RSeq");
        };

        assert_eq!(rseq.value(), 42);
    }

    #[test]
    fn equality_and_order_follow_sequence_number() {
        let Ok(first) = RSeq::new(10) else {
            panic!("expected first RSeq");
        };

        let Ok(second) = RSeq::new(11) else {
            panic!("expected second RSeq");
        };

        assert!(first < second);
        assert_ne!(first, second);
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");

        assert_eq!(
            ParseError::TooLong {
                length: MAX_RSEQ_BYTES + 1,
                maximum: MAX_RSEQ_BYTES,
            }
            .class(),
            "too-long"
        );

        assert_eq!(ParseError::InvalidLineBreak.class(), "invalid-line-break");

        assert_eq!(
            ParseError::InvalidDigit {
                index: 0,
                byte: b'x',
            }
            .class(),
            "invalid-digit"
        );

        assert_eq!(ParseError::Overflow.class(), "overflow");
        assert_eq!(ParseError::Zero.class(), "zero");

        assert_eq!(
            ParseError::InitialValueTooLarge {
                value: MAX_INITIAL_RSEQ + 1,
                maximum: MAX_INITIAL_RSEQ,
            }
            .class(),
            "initial-value-too-large"
        );

        assert_eq!(ParseError::SequenceExhausted.class(), "sequence-exhausted");
    }
}
