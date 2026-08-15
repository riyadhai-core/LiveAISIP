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

//! SIP `CSeq` header.
//!
//! This module provides the strongly typed representation of the SIP `CSeq`
//! field value.
//!
//! A `CSeq` consists of a decimal sequence number followed by linear
//! whitespace and a SIP method. The sequence number must be smaller than
//! `2^31`.
//!
//! Parsing performs no allocation for core methods. Extension methods retain
//! their exact case through the shared SIP
//! [`Method`](crate::sip::types::method::Method) type.
//!
//! Cross-field requirements, such as verifying that a request's `CSeq` method
//! matches its request-line method, belong to SIP message validation rather
//! than this value type.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use crate::sip::types::method::{Method, ParseError as MethodParseError};

/// Largest valid SIP `CSeq` sequence number.
///
/// SIP requires the numeric value to be less than `2^31`.
pub const MAX_CSEQ_SEQUENCE: u32 = 2_147_483_647;

/// A validated SIP `CSeq` field value.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CSeq {
    sequence: u32,
    method: Method,
}

impl CSeq {
    /// Creates a validated `CSeq`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::SequenceTooLarge`] when `sequence` exceeds the
    /// maximum permitted SIP `CSeq` value.
    pub fn new(sequence: u32, method: Method) -> Result<Self, ParseError> {
        if sequence > MAX_CSEQ_SEQUENCE {
            return Err(ParseError::SequenceTooLarge {
                maximum: MAX_CSEQ_SEQUENCE,
            });
        }

        Ok(Self { sequence, method })
    }

    /// Parses a SIP `CSeq` field value from wire bytes.
    ///
    /// The input must consist of:
    ///
    /// ```text
    /// 1*DIGIT LWS Method
    /// ```
    ///
    /// Spaces and horizontal tabs are accepted between the sequence number and
    /// method. Leading or trailing whitespace surrounding the complete field
    /// value is not accepted here; generic header parsing owns that boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the sequence number or method is malformed,
    /// the required separator is missing, or the sequence number exceeds the
    /// valid SIP range.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(ParseError::Empty);
        }

        if is_lws(input[0]) {
            return Err(ParseError::MissingSequence);
        }

        let mut index = 0;
        let mut sequence = 0_u32;

        while index < input.len() && input[index].is_ascii_digit() {
            let digit = u32::from(input[index] - b'0');

            if sequence > (MAX_CSEQ_SEQUENCE - digit) / 10 {
                return Err(ParseError::SequenceTooLarge {
                    maximum: MAX_CSEQ_SEQUENCE,
                });
            }

            sequence = sequence * 10 + digit;
            index += 1;
        }

        if index == 0 {
            return Err(ParseError::InvalidSequenceByte {
                index: 0,
                byte: input[0],
            });
        }

        if index == input.len() {
            return Err(ParseError::MissingMethod);
        }

        if !is_lws(input[index]) {
            return Err(ParseError::InvalidSequenceByte {
                index,
                byte: input[index],
            });
        }

        while index < input.len() && is_lws(input[index]) {
            index += 1;
        }

        if index == input.len() {
            return Err(ParseError::MissingMethod);
        }

        let method = Method::from_bytes(&input[index..]).map_err(ParseError::InvalidMethod)?;

        Self::new(sequence, method)
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Returns the SIP method.
    #[must_use]
    pub const fn method(&self) -> &Method {
        &self.method
    }

    /// Consumes the value into its sequence number and method.
    #[must_use]
    pub fn into_parts(self) -> (u32, Method) {
        (self.sequence, self.method)
    }
}

impl fmt::Display for CSeq {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.sequence, self.method)
    }
}

impl FromStr for CSeq {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

const fn is_lws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

/// Failure to parse or construct a SIP `CSeq` value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The field value was empty.
    Empty,

    /// No sequence number appeared before the separator.
    MissingSequence,

    /// The sequence-number portion contained a non-decimal byte.
    InvalidSequenceByte {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// The sequence number exceeded the permitted SIP range.
    SequenceTooLarge {
        /// Largest permitted sequence number.
        maximum: u32,
    },

    /// No method followed the sequence number.
    MissingMethod,

    /// The method portion was invalid.
    InvalidMethod(MethodParseError),
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::MissingSequence => "missing-sequence",
            Self::InvalidSequenceByte { .. } => "invalid-sequence-byte",
            Self::SequenceTooLarge { .. } => "sequence-too-large",
            Self::MissingMethod => "missing-method",
            Self::InvalidMethod(_) => "invalid-method",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP CSeq is empty"),
            Self::MissingSequence => formatter.write_str("SIP CSeq sequence number is missing"),
            Self::InvalidSequenceByte { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP CSeq sequence byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::SequenceTooLarge { maximum } => {
                write!(
                    formatter,
                    "SIP CSeq sequence number exceeds maximum {maximum}"
                )
            }
            Self::MissingMethod => formatter.write_str("SIP CSeq method is missing"),
            Self::InvalidMethod(error) => {
                write!(formatter, "invalid SIP CSeq method: {error}")
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
    use super::{CSeq, MAX_CSEQ_SEQUENCE, ParseError};
    use crate::sip::types::method::{Method, ParseError as MethodParseError};
    use std::str::FromStr;

    #[test]
    fn parses_invite_cseq() {
        let Ok(cseq) = CSeq::from_bytes(b"314159 INVITE") else {
            panic!("expected valid CSeq");
        };

        assert_eq!(cseq.sequence(), 314_159);
        assert_eq!(cseq.method(), &Method::Invite);
    }

    #[test]
    fn parses_register_cseq() {
        let Ok(cseq) = CSeq::from_bytes(b"1 REGISTER") else {
            panic!("expected valid CSeq");
        };

        assert_eq!(cseq.sequence(), 1);
        assert_eq!(cseq.method(), &Method::Register);
    }

    #[test]
    fn parses_zero_sequence() {
        let Ok(cseq) = CSeq::from_bytes(b"0 OPTIONS") else {
            panic!("expected valid zero CSeq");
        };

        assert_eq!(cseq.sequence(), 0);
        assert_eq!(cseq.method(), &Method::Options);
    }

    #[test]
    fn accepts_maximum_sequence() {
        let input = format!("{MAX_CSEQ_SEQUENCE} INVITE");

        let Ok(cseq) = CSeq::from_bytes(input.as_bytes()) else {
            panic!("expected maximum valid CSeq");
        };

        assert_eq!(cseq.sequence(), MAX_CSEQ_SEQUENCE);
    }

    #[test]
    fn rejects_sequence_equal_to_two_to_the_thirty_first() {
        assert_eq!(
            CSeq::from_bytes(b"2147483648 INVITE"),
            Err(ParseError::SequenceTooLarge {
                maximum: MAX_CSEQ_SEQUENCE,
            })
        );
    }

    #[test]
    fn rejects_very_large_sequence_without_integer_overflow() {
        assert_eq!(
            CSeq::from_bytes(b"999999999999999999999999999999999 INVITE"),
            Err(ParseError::SequenceTooLarge {
                maximum: MAX_CSEQ_SEQUENCE,
            })
        );
    }

    #[test]
    fn accepts_leading_zeroes() {
        let Ok(cseq) = CSeq::from_bytes(b"00042 INVITE") else {
            panic!("expected valid CSeq");
        };

        assert_eq!(cseq.sequence(), 42);
        assert_eq!(cseq.to_string(), "42 INVITE");
    }

    #[test]
    fn accepts_multiple_spaces_between_components() {
        let Ok(cseq) = CSeq::from_bytes(b"42    INVITE") else {
            panic!("expected valid CSeq whitespace");
        };

        assert_eq!(cseq.sequence(), 42);
        assert_eq!(cseq.method(), &Method::Invite);
    }

    #[test]
    fn accepts_horizontal_tab_separator() {
        let Ok(cseq) = CSeq::from_bytes(b"42\tINVITE") else {
            panic!("expected valid CSeq tab separator");
        };

        assert_eq!(cseq.sequence(), 42);
        assert_eq!(cseq.method(), &Method::Invite);
    }

    #[test]
    fn accepts_mixed_linear_whitespace_separator() {
        let Ok(cseq) = CSeq::from_bytes(b"42 \t \tINVITE") else {
            panic!("expected valid CSeq whitespace");
        };

        assert_eq!(cseq.sequence(), 42);
        assert_eq!(cseq.method(), &Method::Invite);
    }

    #[test]
    fn preserves_extension_method() {
        let Ok(cseq) = CSeq::from_bytes(b"77 X-LiveAISIP") else {
            panic!("expected valid extension method");
        };

        assert_eq!(cseq.sequence(), 77);
        assert_eq!(cseq.method().as_str(), "X-LiveAISIP");
        assert!(cseq.method().is_extension());
    }

    #[test]
    fn preserves_extension_method_case() {
        let Ok(cseq) = CSeq::from_bytes(b"77 X-Mixed-Case") else {
            panic!("expected valid extension method");
        };

        assert_eq!(cseq.method().as_str(), "X-Mixed-Case");
        assert_eq!(cseq.to_string(), "77 X-Mixed-Case");
    }

    #[test]
    fn lowercase_core_method_is_not_canonicalized() {
        let Ok(cseq) = CSeq::from_bytes(b"10 invite") else {
            panic!("expected syntactically valid extension method");
        };

        assert_eq!(cseq.method().as_str(), "invite");
        assert!(cseq.method().is_extension());
    }

    #[test]
    fn rejects_empty_value() {
        assert_eq!(CSeq::from_bytes(b""), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_missing_sequence() {
        assert_eq!(
            CSeq::from_bytes(b" INVITE"),
            Err(ParseError::MissingSequence)
        );

        assert_eq!(
            CSeq::from_bytes(b"\tINVITE"),
            Err(ParseError::MissingSequence)
        );
    }

    #[test]
    fn rejects_non_decimal_sequence() {
        assert_eq!(
            CSeq::from_bytes(b"4x INVITE"),
            Err(ParseError::InvalidSequenceByte {
                index: 1,
                byte: b'x',
            })
        );
    }

    #[test]
    fn rejects_sign_prefix() {
        assert_eq!(
            CSeq::from_bytes(b"+42 INVITE"),
            Err(ParseError::InvalidSequenceByte {
                index: 0,
                byte: b'+',
            })
        );

        assert_eq!(
            CSeq::from_bytes(b"-42 INVITE"),
            Err(ParseError::InvalidSequenceByte {
                index: 0,
                byte: b'-',
            })
        );
    }

    #[test]
    fn rejects_missing_whitespace_separator() {
        assert_eq!(
            CSeq::from_bytes(b"42INVITE"),
            Err(ParseError::InvalidSequenceByte {
                index: 2,
                byte: b'I',
            })
        );
    }

    #[test]
    fn rejects_missing_method() {
        assert_eq!(CSeq::from_bytes(b"42"), Err(ParseError::MissingMethod));
        assert_eq!(CSeq::from_bytes(b"42 "), Err(ParseError::MissingMethod));
        assert_eq!(CSeq::from_bytes(b"42 \t "), Err(ParseError::MissingMethod));
    }

    #[test]
    fn rejects_trailing_space_after_method() {
        assert_eq!(
            CSeq::from_bytes(b"42 INVITE "),
            Err(ParseError::InvalidMethod(MethodParseError::InvalidToken {
                index: 6,
                byte: b' ',
            }))
        );
    }

    #[test]
    fn rejects_invalid_method_token() {
        assert_eq!(
            CSeq::from_bytes(b"42 INVITE:bad"),
            Err(ParseError::InvalidMethod(MethodParseError::InvalidToken {
                index: 6,
                byte: b':',
            }))
        );
    }

    #[test]
    fn constructor_accepts_maximum_sequence() {
        let Ok(cseq) = CSeq::new(MAX_CSEQ_SEQUENCE, Method::Invite) else {
            panic!("expected maximum valid CSeq");
        };

        assert_eq!(cseq.sequence(), MAX_CSEQ_SEQUENCE);
    }

    #[test]
    fn constructor_rejects_sequence_above_maximum() {
        assert_eq!(
            CSeq::new(MAX_CSEQ_SEQUENCE + 1, Method::Invite),
            Err(ParseError::SequenceTooLarge {
                maximum: MAX_CSEQ_SEQUENCE,
            })
        );
    }

    #[test]
    fn display_is_canonical() {
        let Ok(cseq) = CSeq::new(42, Method::Bye) else {
            panic!("expected valid CSeq");
        };

        assert_eq!(cseq.to_string(), "42 BYE");
    }

    #[test]
    fn parses_from_str() {
        let Ok(cseq) = CSeq::from_str("100 CANCEL") else {
            panic!("expected valid CSeq");
        };

        assert_eq!(cseq.sequence(), 100);
        assert_eq!(cseq.method(), &Method::Cancel);
    }

    #[test]
    fn consumes_into_parts() {
        let Ok(cseq) = CSeq::new(81, Method::Ack) else {
            panic!("expected valid CSeq");
        };

        let (sequence, method) = cseq.into_parts();

        assert_eq!(sequence, 81);
        assert_eq!(method, Method::Ack);
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");
        assert_eq!(ParseError::MissingSequence.class(), "missing-sequence");

        assert_eq!(
            ParseError::InvalidSequenceByte {
                index: 0,
                byte: b'x',
            }
            .class(),
            "invalid-sequence-byte"
        );

        assert_eq!(
            ParseError::SequenceTooLarge {
                maximum: MAX_CSEQ_SEQUENCE,
            }
            .class(),
            "sequence-too-large"
        );

        assert_eq!(ParseError::MissingMethod.class(), "missing-method");

        assert_eq!(
            ParseError::InvalidMethod(MethodParseError::Empty).class(),
            "invalid-method"
        );
    }
}
