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

//! SIP response status codes.
//!
//! Status codes are stored numerically rather than as a closed enum so
//! `LiveAISIP` can preserve and process valid extension response codes without
//! requiring every code to be known in advance.
//!
//! The standard response classes are represented separately by
//! [`ResponseClass`].

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

/// A valid SIP response status code.
///
/// `LiveAISIP` accepts response codes from `100` through `699`, covering the
/// six SIP response classes while preserving unknown extension codes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct StatusCode(u16);

impl StatusCode {
    /// `100 Trying`.
    pub const TRYING: Self = Self(100);

    /// `180 Ringing`.
    pub const RINGING: Self = Self(180);

    /// `181 Call Is Being Forwarded`.
    pub const CALL_IS_BEING_FORWARDED: Self = Self(181);

    /// `182 Queued`.
    pub const QUEUED: Self = Self(182);

    /// `183 Session Progress`.
    pub const SESSION_PROGRESS: Self = Self(183);

    /// `200 OK`.
    pub const OK: Self = Self(200);

    /// `300 Multiple Choices`.
    pub const MULTIPLE_CHOICES: Self = Self(300);

    /// `301 Moved Permanently`.
    pub const MOVED_PERMANENTLY: Self = Self(301);

    /// `302 Moved Temporarily`.
    pub const MOVED_TEMPORARILY: Self = Self(302);

    /// `305 Use Proxy`.
    pub const USE_PROXY: Self = Self(305);

    /// `380 Alternative Service`.
    pub const ALTERNATIVE_SERVICE: Self = Self(380);

    /// `400 Bad Request`.
    pub const BAD_REQUEST: Self = Self(400);

    /// `401 Unauthorized`.
    pub const UNAUTHORIZED: Self = Self(401);

    /// `402 Payment Required`.
    pub const PAYMENT_REQUIRED: Self = Self(402);

    /// `403 Forbidden`.
    pub const FORBIDDEN: Self = Self(403);

    /// `404 Not Found`.
    pub const NOT_FOUND: Self = Self(404);

    /// `405 Method Not Allowed`.
    pub const METHOD_NOT_ALLOWED: Self = Self(405);

    /// `406 Not Acceptable`.
    pub const NOT_ACCEPTABLE: Self = Self(406);

    /// `407 Proxy Authentication Required`.
    pub const PROXY_AUTHENTICATION_REQUIRED: Self = Self(407);

    /// `408 Request Timeout`.
    pub const REQUEST_TIMEOUT: Self = Self(408);

    /// `410 Gone`.
    pub const GONE: Self = Self(410);

    /// `413 Request Entity Too Large`.
    pub const REQUEST_ENTITY_TOO_LARGE: Self = Self(413);

    /// `414 Request-URI Too Long`.
    pub const REQUEST_URI_TOO_LONG: Self = Self(414);

    /// `415 Unsupported Media Type`.
    pub const UNSUPPORTED_MEDIA_TYPE: Self = Self(415);

    /// `416 Unsupported URI Scheme`.
    pub const UNSUPPORTED_URI_SCHEME: Self = Self(416);

    /// `420 Bad Extension`.
    pub const BAD_EXTENSION: Self = Self(420);

    /// `421 Extension Required`.
    pub const EXTENSION_REQUIRED: Self = Self(421);

    /// `423 Interval Too Brief`.
    pub const INTERVAL_TOO_BRIEF: Self = Self(423);

    /// `480 Temporarily Unavailable`.
    pub const TEMPORARILY_UNAVAILABLE: Self = Self(480);

    /// `481 Call/Transaction Does Not Exist`.
    pub const CALL_TRANSACTION_DOES_NOT_EXIST: Self = Self(481);

    /// `482 Loop Detected`.
    pub const LOOP_DETECTED: Self = Self(482);

    /// `483 Too Many Hops`.
    pub const TOO_MANY_HOPS: Self = Self(483);

    /// `484 Address Incomplete`.
    pub const ADDRESS_INCOMPLETE: Self = Self(484);

    /// `485 Ambiguous`.
    pub const AMBIGUOUS: Self = Self(485);

    /// `486 Busy Here`.
    pub const BUSY_HERE: Self = Self(486);

    /// `487 Request Terminated`.
    pub const REQUEST_TERMINATED: Self = Self(487);

    /// `488 Not Acceptable Here`.
    pub const NOT_ACCEPTABLE_HERE: Self = Self(488);

    /// `491 Request Pending`.
    pub const REQUEST_PENDING: Self = Self(491);

    /// `493 Undecipherable`.
    pub const UNDECIPHERABLE: Self = Self(493);

    /// `500 Server Internal Error`.
    pub const SERVER_INTERNAL_ERROR: Self = Self(500);

    /// `501 Not Implemented`.
    pub const NOT_IMPLEMENTED: Self = Self(501);

    /// `502 Bad Gateway`.
    pub const BAD_GATEWAY: Self = Self(502);

    /// `503 Service Unavailable`.
    pub const SERVICE_UNAVAILABLE: Self = Self(503);

    /// `504 Server Time-out`.
    pub const SERVER_TIMEOUT: Self = Self(504);

    /// `505 Version Not Supported`.
    pub const VERSION_NOT_SUPPORTED: Self = Self(505);

    /// `513 Message Too Large`.
    pub const MESSAGE_TOO_LARGE: Self = Self(513);

    /// `600 Busy Everywhere`.
    pub const BUSY_EVERYWHERE: Self = Self(600);

    /// `603 Decline`.
    pub const DECLINE: Self = Self(603);

    /// `604 Does Not Exist Anywhere`.
    pub const DOES_NOT_EXIST_ANYWHERE: Self = Self(604);

    /// `606 Not Acceptable`.
    pub const GLOBAL_NOT_ACCEPTABLE: Self = Self(606);

    /// Creates a SIP status code from its numeric representation.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::UnsupportedClass`] when the value is outside the
    /// SIP response-class range of `100` through `699`.
    pub const fn new(code: u16) -> Result<Self, ParseError> {
        if code < 100 || code > 699 {
            return Err(ParseError::UnsupportedClass { code });
        }

        Ok(Self(code))
    }

    /// Parses a three-byte SIP status code from the wire.
    ///
    /// Parsing is allocation-free.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the input is not exactly three bytes,
    /// contains a non-decimal byte, or belongs to an unsupported response
    /// class.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() != 3 {
            return Err(ParseError::InvalidLength {
                length: input.len(),
            });
        }

        for (index, byte) in input.iter().copied().enumerate() {
            if !byte.is_ascii_digit() {
                return Err(ParseError::InvalidDigit { index, byte });
            }
        }

        let code = u16::from(input[0] - b'0') * 100
            + u16::from(input[1] - b'0') * 10
            + u16::from(input[2] - b'0');

        Self::new(code)
    }

    /// Returns the numeric status code.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns the SIP response class.
    #[must_use]
    pub const fn class(self) -> ResponseClass {
        match self.0 {
            100..=199 => ResponseClass::Provisional,
            200..=299 => ResponseClass::Success,
            300..=399 => ResponseClass::Redirection,
            400..=499 => ResponseClass::ClientError,
            500..=599 => ResponseClass::ServerError,
            _ => ResponseClass::GlobalFailure,
        }
    }

    /// Returns whether this is a provisional `1xx` response.
    #[must_use]
    pub const fn is_provisional(self) -> bool {
        matches!(self.class(), ResponseClass::Provisional)
    }

    /// Returns whether this is a final response.
    #[must_use]
    pub const fn is_final(self) -> bool {
        !self.is_provisional()
    }

    /// Returns whether this is a successful `2xx` response.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self.class(), ResponseClass::Success)
    }

    /// Returns whether this is a redirection `3xx` response.
    #[must_use]
    pub const fn is_redirection(self) -> bool {
        matches!(self.class(), ResponseClass::Redirection)
    }

    /// Returns whether this is a client-error `4xx` response.
    #[must_use]
    pub const fn is_client_error(self) -> bool {
        matches!(self.class(), ResponseClass::ClientError)
    }

    /// Returns whether this is a server-error `5xx` response.
    #[must_use]
    pub const fn is_server_error(self) -> bool {
        matches!(self.class(), ResponseClass::ServerError)
    }

    /// Returns whether this is a global-failure `6xx` response.
    #[must_use]
    pub const fn is_global_failure(self) -> bool {
        matches!(self.class(), ResponseClass::GlobalFailure)
    }

    /// Returns the standard reason phrase for status codes defined by the core
    /// SIP specification.
    ///
    /// Unknown extension status codes return `None`. Received reason phrases
    /// must not be replaced or interpreted solely from this value.
    #[must_use]
    pub const fn default_reason_phrase(self) -> Option<&'static str> {
        match self.0 {
            100 => Some("Trying"),
            180 => Some("Ringing"),
            181 => Some("Call Is Being Forwarded"),
            182 => Some("Queued"),
            183 => Some("Session Progress"),

            200 => Some("OK"),

            300 => Some("Multiple Choices"),
            301 => Some("Moved Permanently"),
            302 => Some("Moved Temporarily"),
            305 => Some("Use Proxy"),
            380 => Some("Alternative Service"),

            400 => Some("Bad Request"),
            401 => Some("Unauthorized"),
            402 => Some("Payment Required"),
            403 => Some("Forbidden"),
            404 => Some("Not Found"),
            405 => Some("Method Not Allowed"),
            406 | 606 => Some("Not Acceptable"),
            407 => Some("Proxy Authentication Required"),
            408 => Some("Request Timeout"),
            410 => Some("Gone"),
            413 => Some("Request Entity Too Large"),
            414 => Some("Request-URI Too Long"),
            415 => Some("Unsupported Media Type"),
            416 => Some("Unsupported URI Scheme"),
            420 => Some("Bad Extension"),
            421 => Some("Extension Required"),
            423 => Some("Interval Too Brief"),
            480 => Some("Temporarily Unavailable"),
            481 => Some("Call/Transaction Does Not Exist"),
            482 => Some("Loop Detected"),
            483 => Some("Too Many Hops"),
            484 => Some("Address Incomplete"),
            485 => Some("Ambiguous"),
            486 => Some("Busy Here"),
            487 => Some("Request Terminated"),
            488 => Some("Not Acceptable Here"),
            491 => Some("Request Pending"),
            493 => Some("Undecipherable"),

            500 => Some("Server Internal Error"),
            501 => Some("Not Implemented"),
            502 => Some("Bad Gateway"),
            503 => Some("Service Unavailable"),
            504 => Some("Server Time-out"),
            505 => Some("Version Not Supported"),
            513 => Some("Message Too Large"),

            600 => Some("Busy Everywhere"),
            603 => Some("Decline"),
            604 => Some("Does Not Exist Anywhere"),

            _ => None,
        }
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl FromStr for StatusCode {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

impl TryFrom<u16> for StatusCode {
    type Error = ParseError;

    fn try_from(code: u16) -> Result<Self, Self::Error> {
        Self::new(code)
    }
}

impl From<StatusCode> for u16 {
    fn from(status: StatusCode) -> Self {
        status.as_u16()
    }
}

/// SIP response status-code class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ResponseClass {
    /// `1xx`: request received and processing continues.
    Provisional,

    /// `2xx`: request successfully received, understood, and accepted.
    Success,

    /// `3xx`: further action is required to complete the request.
    Redirection,

    /// `4xx`: the request cannot be fulfilled by the responding server.
    ClientError,

    /// `5xx`: the server failed to fulfill an apparently valid request.
    ServerError,

    /// `6xx`: the request cannot be fulfilled at any server.
    GlobalFailure,
}

impl ResponseClass {
    /// Returns the leading decimal digit for this response class.
    #[must_use]
    pub const fn digit(self) -> u8 {
        match self {
            Self::Provisional => 1,
            Self::Success => 2,
            Self::Redirection => 3,
            Self::ClientError => 4,
            Self::ServerError => 5,
            Self::GlobalFailure => 6,
        }
    }

    /// Returns a stable low-cardinality class name suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provisional => "provisional",
            Self::Success => "success",
            Self::Redirection => "redirection",
            Self::ClientError => "client-error",
            Self::ServerError => "server-error",
            Self::GlobalFailure => "global-failure",
        }
    }
}

impl fmt::Display for ResponseClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Failure to parse or construct a SIP response status code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The wire representation was not exactly three bytes.
    InvalidLength {
        /// Actual input length in bytes.
        length: usize,
    },

    /// The wire representation contained a non-decimal byte.
    InvalidDigit {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// The numeric code does not belong to a SIP response class supported by
    /// SIP version 2.0.
    UnsupportedClass {
        /// Numeric status code.
        code: u16,
    },
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::InvalidLength { .. } => "invalid-length",
            Self::InvalidDigit { .. } => "invalid-digit",
            Self::UnsupportedClass { .. } => "unsupported-class",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { length } => {
                write!(
                    formatter,
                    "SIP status code must contain exactly 3 bytes, received {length}"
                )
            }
            Self::InvalidDigit { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP status-code byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::UnsupportedClass { code } => {
                write!(
                    formatter,
                    "unsupported SIP response class for status code {code}"
                )
            }
        }
    }
}

impl StdError for ParseError {}

#[cfg(test)]
mod tests {
    use super::{ParseError, ResponseClass, StatusCode};
    use std::str::FromStr;

    #[test]
    fn parses_known_status_code() {
        assert_eq!(StatusCode::from_bytes(b"200"), Ok(StatusCode::OK));
    }

    #[test]
    fn preserves_unknown_extension_status_code() {
        let Ok(status) = StatusCode::from_bytes(b"299") else {
            panic!("expected valid extension response code");
        };

        assert_eq!(status.as_u16(), 299);
        assert_eq!(status.class(), ResponseClass::Success);
        assert_eq!(status.default_reason_phrase(), None);
    }

    #[test]
    fn parses_each_response_class() {
        assert_eq!(
            StatusCode::from_bytes(b"199").map(StatusCode::class),
            Ok(ResponseClass::Provisional)
        );
        assert_eq!(
            StatusCode::from_bytes(b"299").map(StatusCode::class),
            Ok(ResponseClass::Success)
        );
        assert_eq!(
            StatusCode::from_bytes(b"399").map(StatusCode::class),
            Ok(ResponseClass::Redirection)
        );
        assert_eq!(
            StatusCode::from_bytes(b"499").map(StatusCode::class),
            Ok(ResponseClass::ClientError)
        );
        assert_eq!(
            StatusCode::from_bytes(b"599").map(StatusCode::class),
            Ok(ResponseClass::ServerError)
        );
        assert_eq!(
            StatusCode::from_bytes(b"699").map(StatusCode::class),
            Ok(ResponseClass::GlobalFailure)
        );
    }

    #[test]
    fn rejects_short_status_code() {
        assert_eq!(
            StatusCode::from_bytes(b"20"),
            Err(ParseError::InvalidLength { length: 2 })
        );
    }

    #[test]
    fn rejects_long_status_code() {
        assert_eq!(
            StatusCode::from_bytes(b"2000"),
            Err(ParseError::InvalidLength { length: 4 })
        );
    }

    #[test]
    fn rejects_non_decimal_byte() {
        assert_eq!(
            StatusCode::from_bytes(b"2A0"),
            Err(ParseError::InvalidDigit {
                index: 1,
                byte: b'A',
            })
        );
    }

    #[test]
    fn rejects_zero_response_class() {
        assert_eq!(
            StatusCode::from_bytes(b"099"),
            Err(ParseError::UnsupportedClass { code: 99 })
        );
    }

    #[test]
    fn rejects_response_class_above_six() {
        assert_eq!(
            StatusCode::from_bytes(b"700"),
            Err(ParseError::UnsupportedClass { code: 700 })
        );
    }

    #[test]
    fn numeric_constructor_enforces_range() {
        assert_eq!(
            StatusCode::new(99),
            Err(ParseError::UnsupportedClass { code: 99 })
        );
        assert_eq!(StatusCode::new(100), Ok(StatusCode::TRYING));
        assert_eq!(StatusCode::new(699).map(StatusCode::as_u16), Ok(699));
        assert_eq!(
            StatusCode::new(700),
            Err(ParseError::UnsupportedClass { code: 700 })
        );
    }

    #[test]
    fn class_helpers_are_correct() {
        assert!(StatusCode::TRYING.is_provisional());
        assert!(!StatusCode::TRYING.is_final());

        assert!(StatusCode::OK.is_success());
        assert!(StatusCode::OK.is_final());

        assert!(StatusCode::MOVED_PERMANENTLY.is_redirection());
        assert!(StatusCode::BAD_REQUEST.is_client_error());
        assert!(StatusCode::SERVER_INTERNAL_ERROR.is_server_error());
        assert!(StatusCode::BUSY_EVERYWHERE.is_global_failure());
    }

    #[test]
    fn response_class_metadata_is_stable() {
        assert_eq!(ResponseClass::Provisional.digit(), 1);
        assert_eq!(ResponseClass::Success.digit(), 2);
        assert_eq!(ResponseClass::Redirection.digit(), 3);
        assert_eq!(ResponseClass::ClientError.digit(), 4);
        assert_eq!(ResponseClass::ServerError.digit(), 5);
        assert_eq!(ResponseClass::GlobalFailure.digit(), 6);

        assert_eq!(ResponseClass::Provisional.as_str(), "provisional");
        assert_eq!(ResponseClass::GlobalFailure.as_str(), "global-failure");
    }

    #[test]
    fn known_codes_have_default_reason_phrases() {
        assert_eq!(StatusCode::TRYING.default_reason_phrase(), Some("Trying"));
        assert_eq!(StatusCode::RINGING.default_reason_phrase(), Some("Ringing"));
        assert_eq!(StatusCode::OK.default_reason_phrase(), Some("OK"));
        assert_eq!(
            StatusCode::TEMPORARILY_UNAVAILABLE.default_reason_phrase(),
            Some("Temporarily Unavailable")
        );
        assert_eq!(
            StatusCode::CALL_TRANSACTION_DOES_NOT_EXIST.default_reason_phrase(),
            Some("Call/Transaction Does Not Exist")
        );
        assert_eq!(
            StatusCode::SERVICE_UNAVAILABLE.default_reason_phrase(),
            Some("Service Unavailable")
        );
        assert_eq!(
            StatusCode::VERSION_NOT_SUPPORTED.default_reason_phrase(),
            Some("Version Not Supported")
        );
        assert_eq!(
            StatusCode::BUSY_EVERYWHERE.default_reason_phrase(),
            Some("Busy Everywhere")
        );
        assert_eq!(
            StatusCode::GLOBAL_NOT_ACCEPTABLE.default_reason_phrase(),
            Some("Not Acceptable")
        );
    }

    #[test]
    fn display_writes_numeric_status_code() {
        assert_eq!(StatusCode::OK.to_string(), "200");
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE.to_string(), "503");
    }

    #[test]
    fn parses_from_str() {
        assert_eq!(StatusCode::from_str("486"), Ok(StatusCode::BUSY_HERE));
    }

    #[test]
    fn converts_to_and_from_u16() {
        let Ok(status) = StatusCode::try_from(487_u16) else {
            panic!("expected valid numeric status code");
        };

        assert_eq!(status, StatusCode::REQUEST_TERMINATED);
        assert_eq!(u16::from(status), 487);
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(
            ParseError::InvalidLength { length: 2 }.class(),
            "invalid-length"
        );
        assert_eq!(
            ParseError::InvalidDigit {
                index: 1,
                byte: b'A',
            }
            .class(),
            "invalid-digit"
        );
        assert_eq!(
            ParseError::UnsupportedClass { code: 700 }.class(),
            "unsupported-class"
        );
    }
}
