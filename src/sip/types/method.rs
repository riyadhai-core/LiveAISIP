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

//! SIP request methods.
//!
//! Standard SIP methods use dedicated variants and require no heap allocation.
//! Unknown but syntactically valid extension methods are retained exactly so
//! they can be validated, routed, rejected, or forwarded by later protocol
//! layers without losing their original method token.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

/// Maximum accepted size of a SIP method token in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_METHOD_BYTES: usize = 64;

/// A SIP request method.
///
/// Core SIP methods and commonly deployed standardized extension methods use
/// dedicated variants. Other valid method tokens are preserved using
/// [`Method::Extension`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Method {
    /// `INVITE`.
    Invite,

    /// `ACK`.
    Ack,

    /// `BYE`.
    Bye,

    /// `CANCEL`.
    Cancel,

    /// `REGISTER`.
    Register,

    /// `OPTIONS`.
    Options,

    /// `PRACK`.
    Prack,

    /// `UPDATE`.
    Update,

    /// `INFO`.
    Info,

    /// `MESSAGE`.
    Message,

    /// `REFER`.
    Refer,

    /// `SUBSCRIBE`.
    Subscribe,

    /// `NOTIFY`.
    Notify,

    /// `PUBLISH`.
    Publish,

    /// An otherwise valid SIP extension method.
    Extension(
        /// Exact extension-method token as received or constructed.
        Box<str>,
    ),
}

impl Method {
    /// Parses a SIP method from its wire representation.
    ///
    /// Known methods are recognized without allocation. An unknown valid
    /// extension method requires one owned string allocation.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the method is empty, exceeds the configured
    /// size bound, or contains a byte outside the SIP `token` grammar.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(ParseError::Empty);
        }

        if input.len() > MAX_METHOD_BYTES {
            return Err(ParseError::TooLong {
                length: input.len(),
                maximum: MAX_METHOD_BYTES,
            });
        }

        match input {
            b"INVITE" => Ok(Self::Invite),
            b"ACK" => Ok(Self::Ack),
            b"BYE" => Ok(Self::Bye),
            b"CANCEL" => Ok(Self::Cancel),
            b"REGISTER" => Ok(Self::Register),
            b"OPTIONS" => Ok(Self::Options),
            b"PRACK" => Ok(Self::Prack),
            b"UPDATE" => Ok(Self::Update),
            b"INFO" => Ok(Self::Info),
            b"MESSAGE" => Ok(Self::Message),
            b"REFER" => Ok(Self::Refer),
            b"SUBSCRIBE" => Ok(Self::Subscribe),
            b"NOTIFY" => Ok(Self::Notify),
            b"PUBLISH" => Ok(Self::Publish),
            _ => parse_extension(input),
        }
    }

    /// Returns the exact method representation used on the SIP wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Invite => "INVITE",
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Register => "REGISTER",
            Self::Options => "OPTIONS",
            Self::Prack => "PRACK",
            Self::Update => "UPDATE",
            Self::Info => "INFO",
            Self::Message => "MESSAGE",
            Self::Refer => "REFER",
            Self::Subscribe => "SUBSCRIBE",
            Self::Notify => "NOTIFY",
            Self::Publish => "PUBLISH",
            Self::Extension(method) => method,
        }
    }

    /// Returns the exact method representation as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Returns whether this method is one of the six methods defined directly
    /// by the core SIP specification.
    #[must_use]
    pub const fn is_core(&self) -> bool {
        matches!(
            self,
            Self::Invite | Self::Ack | Self::Bye | Self::Cancel | Self::Register | Self::Options
        )
    }

    /// Returns whether this value contains an extension method without a
    /// dedicated `LiveAISIP` variant.
    #[must_use]
    pub const fn is_extension(&self) -> bool {
        matches!(self, Self::Extension(_))
    }
}

impl fmt::Display for Method {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Method {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// Failure to parse a SIP method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The method token was empty.
    Empty,

    /// The method token exceeded the configured bound.
    TooLong {
        /// Actual method length in bytes.
        length: usize,

        /// Maximum accepted method length in bytes.
        maximum: usize,
    },

    /// A byte was not permitted by the SIP `token` grammar.
    InvalidToken {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
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
            Self::InvalidToken { .. } => "invalid-token",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP method is empty"),
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP method length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidToken { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP method byte 0x{byte:02x} at offset {index}"
                )
            }
        }
    }
}

impl StdError for ParseError {}

fn parse_extension(input: &[u8]) -> Result<Method, ParseError> {
    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidToken { index, byte });
        }
    }

    let method = match std::str::from_utf8(input) {
        Ok(method) => method,
        Err(error) => {
            let index = error.valid_up_to();
            let byte = input.get(index).copied().unwrap_or_default();

            return Err(ParseError::InvalidToken { index, byte });
        }
    };

    Ok(Method::Extension(method.into()))
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::{MAX_METHOD_BYTES, Method, ParseError};
    use std::str::FromStr;

    #[test]
    fn parses_core_methods() {
        assert_eq!(Method::from_bytes(b"INVITE"), Ok(Method::Invite));
        assert_eq!(Method::from_bytes(b"ACK"), Ok(Method::Ack));
        assert_eq!(Method::from_bytes(b"BYE"), Ok(Method::Bye));
        assert_eq!(Method::from_bytes(b"CANCEL"), Ok(Method::Cancel));
        assert_eq!(Method::from_bytes(b"REGISTER"), Ok(Method::Register));
        assert_eq!(Method::from_bytes(b"OPTIONS"), Ok(Method::Options));
    }

    #[test]
    fn parses_standard_extension_methods() {
        assert_eq!(Method::from_bytes(b"PRACK"), Ok(Method::Prack));
        assert_eq!(Method::from_bytes(b"UPDATE"), Ok(Method::Update));
        assert_eq!(Method::from_bytes(b"INFO"), Ok(Method::Info));
        assert_eq!(Method::from_bytes(b"MESSAGE"), Ok(Method::Message));
        assert_eq!(Method::from_bytes(b"REFER"), Ok(Method::Refer));
        assert_eq!(Method::from_bytes(b"SUBSCRIBE"), Ok(Method::Subscribe));
        assert_eq!(Method::from_bytes(b"NOTIFY"), Ok(Method::Notify));
        assert_eq!(Method::from_bytes(b"PUBLISH"), Ok(Method::Publish));
    }

    #[test]
    fn preserves_unknown_extension_method() {
        assert_eq!(
            Method::from_bytes(b"X-LIVEAISIP"),
            Ok(Method::Extension("X-LIVEAISIP".into()))
        );
    }

    #[test]
    fn preserves_extension_method_case() {
        assert_eq!(
            Method::from_bytes(b"custom"),
            Ok(Method::Extension("custom".into()))
        );
    }

    #[test]
    fn lowercase_core_name_is_not_canonicalized() {
        assert_eq!(
            Method::from_bytes(b"invite"),
            Ok(Method::Extension("invite".into()))
        );
    }

    #[test]
    fn rejects_empty_method() {
        assert_eq!(Method::from_bytes(b""), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_method_above_size_limit() {
        let input = vec![b'A'; MAX_METHOD_BYTES + 1];

        assert_eq!(
            Method::from_bytes(&input),
            Err(ParseError::TooLong {
                length: MAX_METHOD_BYTES + 1,
                maximum: MAX_METHOD_BYTES,
            })
        );
    }

    #[test]
    fn accepts_method_at_size_limit() {
        let input = vec![b'A'; MAX_METHOD_BYTES];

        assert!(Method::from_bytes(&input).is_ok());
    }

    #[test]
    fn rejects_space() {
        assert_eq!(
            Method::from_bytes(b"BAD METHOD"),
            Err(ParseError::InvalidToken {
                index: 3,
                byte: b' ',
            })
        );
    }

    #[test]
    fn rejects_colon() {
        assert_eq!(
            Method::from_bytes(b"BAD:METHOD"),
            Err(ParseError::InvalidToken {
                index: 3,
                byte: b':',
            })
        );
    }

    #[test]
    fn rejects_control_byte() {
        assert_eq!(
            Method::from_bytes(b"BAD\rMETHOD"),
            Err(ParseError::InvalidToken {
                index: 3,
                byte: b'\r',
            })
        );
    }

    #[test]
    fn rejects_non_ascii_byte() {
        assert_eq!(
            Method::from_bytes(b"X-\xff"),
            Err(ParseError::InvalidToken {
                index: 2,
                byte: 0xff,
            })
        );
    }

    #[test]
    fn displays_exact_wire_value() {
        assert_eq!(Method::Invite.to_string(), "INVITE");
        assert_eq!(
            Method::Extension("X-LIVEAISIP".into()).to_string(),
            "X-LIVEAISIP"
        );
    }

    #[test]
    fn parses_from_str() {
        assert_eq!(Method::from_str("BYE"), Ok(Method::Bye));
        assert_eq!(
            Method::from_str("CUSTOM"),
            Ok(Method::Extension("CUSTOM".into()))
        );
    }

    #[test]
    fn identifies_core_methods() {
        assert!(Method::Invite.is_core());
        assert!(Method::Cancel.is_core());
        assert!(Method::Options.is_core());

        assert!(!Method::Prack.is_core());
        assert!(!Method::Extension("CUSTOM".into()).is_core());
    }

    #[test]
    fn identifies_extension_methods() {
        assert!(Method::Extension("CUSTOM".into()).is_extension());
        assert!(!Method::Invite.is_extension());
        assert!(!Method::Prack.is_extension());
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");
        assert_eq!(
            ParseError::TooLong {
                length: 65,
                maximum: 64,
            }
            .class(),
            "too-long"
        );
        assert_eq!(
            ParseError::InvalidToken {
                index: 0,
                byte: b' ',
            }
            .class(),
            "invalid-token"
        );
    }
}
