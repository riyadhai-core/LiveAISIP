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

//! Generic SIP header representation.
//!
//! This module defines validated header names and opaque header values used by
//! SIP parsing, serialization, validation, and specialized header modules.
//!
//! Standard header names use allocation-free representations. Unknown valid
//! header names retain their original spelling while comparing
//! case-insensitively as required by SIP.
//!
//! [`HeaderKind`] owns the authoritative allocation-free registry for
//! recognized long and compact SIP header names. Structural parsers use that
//! registry directly so header classification cannot diverge between parsing
//! layers.
//!
//! Header values remain byte-oriented so extension fields can be preserved
//! without forcing them through UTF-8 decoding before a header-specific parser
//! has interpreted their syntax.

use std::error::Error as StdError;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

/// Maximum accepted SIP header-name size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_HEADER_NAME_BYTES: usize = 256;

/// Maximum accepted value size for one SIP header field.
///
/// The complete SIP header section is independently bounded by the framing
/// subsystem. This limit additionally prevents individual extension headers
/// from producing unbounded allocations.
pub const MAX_HEADER_VALUE_BYTES: usize = 64 * 1024;

/// A generic SIP header field.
#[derive(Clone, Eq, PartialEq)]
pub struct Header {
    name: HeaderName,
    value: HeaderValue,
}

impl Header {
    /// Creates a header from an already validated name and value.
    #[must_use]
    pub const fn new(name: HeaderName, value: HeaderValue) -> Self {
        Self { name, value }
    }

    /// Returns the header name.
    #[must_use]
    pub const fn name(&self) -> &HeaderName {
        &self.name
    }

    /// Returns the header value.
    #[must_use]
    pub const fn value(&self) -> &HeaderValue {
        &self.value
    }

    /// Returns mutable access to the header value.
    #[must_use]
    pub const fn value_mut(&mut self) -> &mut HeaderValue {
        &mut self.value
    }

    /// Consumes the header into its name and value.
    #[must_use]
    pub fn into_parts(self) -> (HeaderName, HeaderValue) {
        (self.name, self.value)
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Header")
            .field("name", &self.name)
            .field("value_bytes", &self.value.len())
            .finish()
    }
}

/// A validated SIP header name.
///
/// Standard names use [`HeaderKind`] without allocation. Other valid token
/// names are retained as extension header names.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HeaderName(HeaderNameRepr);

impl HeaderName {
    /// Parses a SIP header name from wire bytes.
    ///
    /// Standard names and their recognized compact forms are parsed without
    /// allocation. An extension name requires one owned string allocation.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderNameError`] when the name is empty, exceeds the
    /// configured operational bound, or violates the SIP token grammar.
    pub fn from_bytes(input: &[u8]) -> Result<Self, HeaderNameError> {
        if input.is_empty() {
            return Err(HeaderNameError::Empty);
        }

        if input.len() > MAX_HEADER_NAME_BYTES {
            return Err(HeaderNameError::TooLong {
                length: input.len(),
                maximum: MAX_HEADER_NAME_BYTES,
            });
        }

        if let Some(kind) = HeaderKind::from_name_bytes(input) {
            return Ok(Self(HeaderNameRepr::Known(kind)));
        }

        for (index, byte) in input.iter().copied().enumerate() {
            if !is_token_byte(byte) {
                return Err(HeaderNameError::InvalidToken { index, byte });
            }
        }

        let name = std::str::from_utf8(input).map_err(|_| HeaderNameError::InvalidToken {
            index: 0,
            byte: input[0],
        })?;

        Ok(Self(HeaderNameRepr::Extension(ExtensionHeaderName(
            name.into(),
        ))))
    }

    /// Creates a standard SIP header name.
    #[must_use]
    pub const fn known(kind: HeaderKind) -> Self {
        Self(HeaderNameRepr::Known(kind))
    }

    /// Returns the standard header kind when this is a recognized name.
    #[must_use]
    pub const fn kind(&self) -> Option<HeaderKind> {
        match &self.0 {
            HeaderNameRepr::Known(kind) => Some(*kind),
            HeaderNameRepr::Extension(_) => None,
        }
    }

    /// Returns whether this is a recognized standard header name.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        matches!(self.0, HeaderNameRepr::Known(_))
    }

    /// Returns whether this is an extension or otherwise unrecognized header
    /// name.
    #[must_use]
    pub const fn is_extension(&self) -> bool {
        matches!(self.0, HeaderNameRepr::Extension(_))
    }

    /// Returns the header name used for canonical serialization.
    ///
    /// Recognized headers return their canonical long name. Extension names
    /// retain the spelling supplied when they were constructed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            HeaderNameRepr::Known(kind) => kind.as_str(),
            HeaderNameRepr::Extension(name) => &name.0,
        }
    }

    /// Returns the canonical header name as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Returns the compact SIP header name when one is defined.
    #[must_use]
    pub const fn compact_name(&self) -> Option<&'static str> {
        match &self.0 {
            HeaderNameRepr::Known(kind) => kind.compact_name(),
            HeaderNameRepr::Extension(_) => None,
        }
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for HeaderName {
    type Err = HeaderNameError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

impl From<HeaderKind> for HeaderName {
    fn from(kind: HeaderKind) -> Self {
        Self::known(kind)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum HeaderNameRepr {
    Known(HeaderKind),
    Extension(ExtensionHeaderName),
}

#[derive(Clone, Debug)]
struct ExtensionHeaderName(Box<str>);

impl PartialEq for ExtensionHeaderName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for ExtensionHeaderName {}

impl Hash for ExtensionHeaderName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.len().hash(state);

        for byte in self.0.bytes() {
            byte.to_ascii_lowercase().hash(state);
        }
    }
}

/// A recognized SIP header name.
///
/// This enum represents header names with core or explicitly modeled semantics
/// in `LiveAISIP`. Unknown valid names remain supported through [`HeaderName`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum HeaderKind {
    /// `Via`.
    Via,

    /// `From`.
    From,

    /// `To`.
    To,

    /// `Call-ID`.
    CallId,

    /// `CSeq`.
    CSeq,

    /// `Contact`.
    Contact,

    /// `Max-Forwards`.
    MaxForwards,

    /// `Content-Length`.
    ContentLength,

    /// `Content-Type`.
    ContentType,

    /// `Content-Encoding`.
    ContentEncoding,

    /// `Subject`.
    Subject,

    /// `Route`.
    Route,

    /// `Record-Route`.
    RecordRoute,

    /// `Supported`.
    Supported,

    /// `Require`.
    Require,

    /// `Unsupported`.
    Unsupported,

    /// `Allow`.
    Allow,

    /// `Reason`.
    Reason,

    /// `Retry-After`.
    RetryAfter,

    /// `User-Agent`.
    UserAgent,

    /// `Server`.
    Server,

    /// `P-Asserted-Identity`.
    PAssertedIdentity,

    /// `Session-Expires`.
    SessionExpires,

    /// `Min-SE`.
    MinSe,

    /// `RSeq`.
    RSeq,

    /// `Authorization`.
    Authorization,

    /// `WWW-Authenticate`.
    WwwAuthenticate,

    /// `Proxy-Authorization`.
    ProxyAuthorization,

    /// `Proxy-Authenticate`.
    ProxyAuthenticate,

    /// `Authentication-Info`.
    AuthenticationInfo,
}

impl HeaderKind {
    /// Classifies a recognized SIP header name from raw wire bytes.
    ///
    /// Matching is ASCII case-insensitive and includes every compact form
    /// modeled by [`HeaderKind`]. Unknown or syntactically invalid names return
    /// `None`; use [`HeaderName::from_bytes`] when validation and extension-name
    /// preservation are required.
    ///
    /// This is the authoritative allocation-free header-name registry used by
    /// structural parsing and generic header construction.
    #[must_use]
    pub fn from_name_bytes(input: &[u8]) -> Option<Self> {
        match input.len() {
            1 => match input[0].to_ascii_lowercase() {
                b'v' => Some(Self::Via),
                b'f' => Some(Self::From),
                b't' => Some(Self::To),
                b'i' => Some(Self::CallId),
                b'm' => Some(Self::Contact),
                b'l' => Some(Self::ContentLength),
                b'c' => Some(Self::ContentType),
                b'e' => Some(Self::ContentEncoding),
                b's' => Some(Self::Subject),
                b'k' => Some(Self::Supported),
                _ => None,
            },
            2 if input.eq_ignore_ascii_case(b"To") => Some(Self::To),
            3 if input.eq_ignore_ascii_case(b"Via") => Some(Self::Via),
            4 if input.eq_ignore_ascii_case(b"From") => Some(Self::From),
            4 if input.eq_ignore_ascii_case(b"CSeq") => Some(Self::CSeq),
            4 if input.eq_ignore_ascii_case(b"RSeq") => Some(Self::RSeq),
            5 if input.eq_ignore_ascii_case(b"Route") => Some(Self::Route),
            5 if input.eq_ignore_ascii_case(b"Allow") => Some(Self::Allow),
            6 if input.eq_ignore_ascii_case(b"Reason") => Some(Self::Reason),
            6 if input.eq_ignore_ascii_case(b"Server") => Some(Self::Server),
            6 if input.eq_ignore_ascii_case(b"Min-SE") => Some(Self::MinSe),
            7 if input.eq_ignore_ascii_case(b"Call-ID") => Some(Self::CallId),
            7 if input.eq_ignore_ascii_case(b"Contact") => Some(Self::Contact),
            7 if input.eq_ignore_ascii_case(b"Subject") => Some(Self::Subject),
            7 if input.eq_ignore_ascii_case(b"Require") => Some(Self::Require),
            9 if input.eq_ignore_ascii_case(b"Supported") => Some(Self::Supported),
            10 if input.eq_ignore_ascii_case(b"User-Agent") => Some(Self::UserAgent),
            11 if input.eq_ignore_ascii_case(b"Unsupported") => Some(Self::Unsupported),
            11 if input.eq_ignore_ascii_case(b"Retry-After") => Some(Self::RetryAfter),
            12 if input.eq_ignore_ascii_case(b"Max-Forwards") => Some(Self::MaxForwards),
            12 if input.eq_ignore_ascii_case(b"Content-Type") => Some(Self::ContentType),
            12 if input.eq_ignore_ascii_case(b"Record-Route") => Some(Self::RecordRoute),
            13 if input.eq_ignore_ascii_case(b"Authorization") => Some(Self::Authorization),
            14 if input.eq_ignore_ascii_case(b"Content-Length") => Some(Self::ContentLength),
            15 if input.eq_ignore_ascii_case(b"Session-Expires") => Some(Self::SessionExpires),
            16 if input.eq_ignore_ascii_case(b"Content-Encoding") => Some(Self::ContentEncoding),
            16 if input.eq_ignore_ascii_case(b"WWW-Authenticate") => Some(Self::WwwAuthenticate),
            18 if input.eq_ignore_ascii_case(b"Proxy-Authenticate") => {
                Some(Self::ProxyAuthenticate)
            }
            19 if input.eq_ignore_ascii_case(b"P-Asserted-Identity") => {
                Some(Self::PAssertedIdentity)
            }
            19 if input.eq_ignore_ascii_case(b"Proxy-Authorization") => {
                Some(Self::ProxyAuthorization)
            }
            19 if input.eq_ignore_ascii_case(b"Authentication-Info") => {
                Some(Self::AuthenticationInfo)
            }
            _ => None,
        }
    }

    /// Returns the canonical long header name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Via => "Via",
            Self::From => "From",
            Self::To => "To",
            Self::CallId => "Call-ID",
            Self::CSeq => "CSeq",
            Self::Contact => "Contact",
            Self::MaxForwards => "Max-Forwards",
            Self::ContentLength => "Content-Length",
            Self::ContentType => "Content-Type",
            Self::ContentEncoding => "Content-Encoding",
            Self::Subject => "Subject",
            Self::Route => "Route",
            Self::RecordRoute => "Record-Route",
            Self::Supported => "Supported",
            Self::Require => "Require",
            Self::Unsupported => "Unsupported",
            Self::Allow => "Allow",
            Self::Reason => "Reason",
            Self::RetryAfter => "Retry-After",
            Self::UserAgent => "User-Agent",
            Self::Server => "Server",
            Self::PAssertedIdentity => "P-Asserted-Identity",
            Self::SessionExpires => "Session-Expires",
            Self::MinSe => "Min-SE",
            Self::RSeq => "RSeq",
            Self::Authorization => "Authorization",
            Self::WwwAuthenticate => "WWW-Authenticate",
            Self::ProxyAuthorization => "Proxy-Authorization",
            Self::ProxyAuthenticate => "Proxy-Authenticate",
            Self::AuthenticationInfo => "Authentication-Info",
        }
    }

    /// Returns the RFC-defined compact form when available.
    #[must_use]
    pub const fn compact_name(self) -> Option<&'static str> {
        match self {
            Self::Via => Some("v"),
            Self::From => Some("f"),
            Self::To => Some("t"),
            Self::CallId => Some("i"),
            Self::Contact => Some("m"),
            Self::ContentLength => Some("l"),
            Self::ContentType => Some("c"),
            Self::ContentEncoding => Some("e"),
            Self::Subject => Some("s"),
            Self::Supported => Some("k"),
            Self::CSeq
            | Self::MaxForwards
            | Self::Route
            | Self::RecordRoute
            | Self::Require
            | Self::Unsupported
            | Self::Allow
            | Self::Reason
            | Self::RetryAfter
            | Self::UserAgent
            | Self::Server
            | Self::PAssertedIdentity
            | Self::SessionExpires
            | Self::MinSe
            | Self::RSeq
            | Self::Authorization
            | Self::WwwAuthenticate
            | Self::ProxyAuthorization
            | Self::ProxyAuthenticate
            | Self::AuthenticationInfo => None,
        }
    }
}

impl fmt::Display for HeaderKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An opaque validated SIP header value.
///
/// The value is intentionally stored as bytes. Typed header parsers decide
/// whether a particular field requires ASCII, UTF-8, tokens, quoted strings,
/// comma-separated elements, numeric values, or another grammar.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct HeaderValue(Box<[u8]>);

impl HeaderValue {
    /// Creates a header value from wire-compatible bytes.
    ///
    /// Empty values are accepted. Horizontal tab and printable ASCII are
    /// accepted directly. Bytes above ASCII are preserved for header grammars
    /// that allow non-ASCII text.
    ///
    /// Carriage return, line feed, DEL, NUL, and other ASCII control bytes are
    /// rejected. Header folding must be processed before constructing this
    /// value.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderValueError`] when the value exceeds the configured
    /// operational bound or contains a disallowed control byte.
    pub fn from_bytes(input: &[u8]) -> Result<Self, HeaderValueError> {
        if input.len() > MAX_HEADER_VALUE_BYTES {
            return Err(HeaderValueError::TooLong {
                length: input.len(),
                maximum: MAX_HEADER_VALUE_BYTES,
            });
        }

        for (index, byte) in input.iter().copied().enumerate() {
            if !is_header_value_byte(byte) {
                return Err(HeaderValueError::InvalidByte { index, byte });
            }
        }

        Ok(Self(input.into()))
    }

    /// Creates a header value from text.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`HeaderValue::from_bytes`].
    pub fn from_str_value(input: &str) -> Result<Self, HeaderValueError> {
        Self::from_bytes(input.as_bytes())
    }

    /// Returns the raw header value.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the value as UTF-8 when it contains valid UTF-8 text.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Returns the header-value length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the header value is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for HeaderValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderValue")
            .field("bytes", &self.len())
            .field("utf8", &self.as_str().is_some())
            .finish()
    }
}

/// Failure to construct a SIP header name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HeaderNameError {
    /// The header name was empty.
    Empty,

    /// The header name exceeded the configured operational size bound.
    TooLong {
        /// Actual header-name length in bytes.
        length: usize,

        /// Maximum accepted header-name length in bytes.
        maximum: usize,
    },

    /// The header name contained a byte outside the SIP token grammar.
    InvalidToken {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },
}

impl HeaderNameError {
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

impl fmt::Display for HeaderNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP header name is empty"),
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP header-name length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidToken { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP header-name byte 0x{byte:02x} at offset {index}"
                )
            }
        }
    }
}

impl StdError for HeaderNameError {}

/// Failure to construct a SIP header value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HeaderValueError {
    /// The value exceeded the configured operational size bound.
    TooLong {
        /// Actual header-value length in bytes.
        length: usize,

        /// Maximum accepted header-value length in bytes.
        maximum: usize,
    },

    /// The value contained a disallowed byte.
    InvalidByte {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },
}

impl HeaderValueError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::TooLong { .. } => "too-long",
            Self::InvalidByte { .. } => "invalid-byte",
        }
    }
}

impl fmt::Display for HeaderValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP header-value length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidByte { index, byte } => {
                write!(
                    formatter,
                    "invalid SIP header-value byte 0x{byte:02x} at offset {index}"
                )
            }
        }
    }
}

impl StdError for HeaderValueError {}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

const fn is_header_value_byte(byte: u8) -> bool {
    byte == b'\t' || matches!(byte, b' '..=b'~') || byte >= 0x80
}

#[cfg(test)]
mod tests {
    use super::{
        Header, HeaderKind, HeaderName, HeaderNameError, HeaderValue, HeaderValueError,
        MAX_HEADER_NAME_BYTES, MAX_HEADER_VALUE_BYTES,
    };
    use std::collections::HashSet;
    use std::str::FromStr;

    const KNOWN_HEADERS: [(HeaderKind, &str); 30] = [
        (HeaderKind::Via, "Via"),
        (HeaderKind::From, "From"),
        (HeaderKind::To, "To"),
        (HeaderKind::CallId, "Call-ID"),
        (HeaderKind::CSeq, "CSeq"),
        (HeaderKind::Contact, "Contact"),
        (HeaderKind::MaxForwards, "Max-Forwards"),
        (HeaderKind::ContentLength, "Content-Length"),
        (HeaderKind::ContentType, "Content-Type"),
        (HeaderKind::ContentEncoding, "Content-Encoding"),
        (HeaderKind::Subject, "Subject"),
        (HeaderKind::Route, "Route"),
        (HeaderKind::RecordRoute, "Record-Route"),
        (HeaderKind::Supported, "Supported"),
        (HeaderKind::Require, "Require"),
        (HeaderKind::Unsupported, "Unsupported"),
        (HeaderKind::Allow, "Allow"),
        (HeaderKind::Reason, "Reason"),
        (HeaderKind::RetryAfter, "Retry-After"),
        (HeaderKind::UserAgent, "User-Agent"),
        (HeaderKind::Server, "Server"),
        (HeaderKind::PAssertedIdentity, "P-Asserted-Identity"),
        (HeaderKind::SessionExpires, "Session-Expires"),
        (HeaderKind::MinSe, "Min-SE"),
        (HeaderKind::RSeq, "RSeq"),
        (HeaderKind::Authorization, "Authorization"),
        (HeaderKind::WwwAuthenticate, "WWW-Authenticate"),
        (HeaderKind::ProxyAuthorization, "Proxy-Authorization"),
        (HeaderKind::ProxyAuthenticate, "Proxy-Authenticate"),
        (HeaderKind::AuthenticationInfo, "Authentication-Info"),
    ];

    const COMPACT_HEADERS: [(u8, HeaderKind); 10] = [
        (b'v', HeaderKind::Via),
        (b'f', HeaderKind::From),
        (b't', HeaderKind::To),
        (b'i', HeaderKind::CallId),
        (b'm', HeaderKind::Contact),
        (b'l', HeaderKind::ContentLength),
        (b'c', HeaderKind::ContentType),
        (b'e', HeaderKind::ContentEncoding),
        (b's', HeaderKind::Subject),
        (b'k', HeaderKind::Supported),
    ];

    #[test]
    fn header_kind_registry_recognizes_every_canonical_name() {
        for (kind, name) in KNOWN_HEADERS {
            assert_eq!(kind.as_str(), name);

            assert_eq!(
                HeaderKind::from_name_bytes(name.as_bytes()),
                Some(kind),
                "{name}"
            );

            let lowercase = name.to_ascii_lowercase();

            assert_eq!(
                HeaderKind::from_name_bytes(lowercase.as_bytes()),
                Some(kind),
                "{name}"
            );
        }
    }

    #[test]
    fn header_kind_registry_recognizes_every_compact_name() {
        for (name, kind) in COMPACT_HEADERS {
            assert_eq!(HeaderKind::from_name_bytes(&[name]), Some(kind));

            assert_eq!(
                HeaderKind::from_name_bytes(&[name.to_ascii_uppercase()]),
                Some(kind)
            );
        }
    }

    #[test]
    fn header_kind_registry_leaves_unknown_names_unclassified() {
        assert_eq!(HeaderKind::from_name_bytes(b"X-LiveAISIP-Trace"), None);
        assert_eq!(HeaderKind::from_name_bytes(b""), None);
        assert_eq!(HeaderKind::from_name_bytes(b"Bad Header"), None);
    }

    #[test]
    fn parses_known_header_name() {
        let Ok(name) = HeaderName::from_bytes(b"Via") else {
            panic!("expected known header");
        };

        assert_eq!(name.kind(), Some(HeaderKind::Via));
        assert_eq!(name.as_str(), "Via");
        assert!(name.is_known());
        assert!(!name.is_extension());
    }

    #[test]
    fn known_header_names_are_case_insensitive() {
        let Ok(lower) = HeaderName::from_bytes(b"content-length") else {
            panic!("expected known header");
        };

        let Ok(mixed) = HeaderName::from_bytes(b"CoNtEnT-LeNgTh") else {
            panic!("expected known header");
        };

        assert_eq!(lower, mixed);
        assert_eq!(lower.kind(), Some(HeaderKind::ContentLength));
        assert_eq!(lower.as_str(), "Content-Length");
    }

    #[test]
    fn parses_rfc_compact_header_names() {
        let cases = [
            (b"v".as_slice(), HeaderKind::Via),
            (b"f".as_slice(), HeaderKind::From),
            (b"t".as_slice(), HeaderKind::To),
            (b"i".as_slice(), HeaderKind::CallId),
            (b"m".as_slice(), HeaderKind::Contact),
            (b"l".as_slice(), HeaderKind::ContentLength),
            (b"c".as_slice(), HeaderKind::ContentType),
            (b"e".as_slice(), HeaderKind::ContentEncoding),
            (b"s".as_slice(), HeaderKind::Subject),
            (b"k".as_slice(), HeaderKind::Supported),
        ];

        for (input, expected) in cases {
            let Ok(name) = HeaderName::from_bytes(input) else {
                panic!("expected compact header name");
            };

            assert_eq!(name.kind(), Some(expected));
        }
    }

    #[test]
    fn compact_header_names_are_case_insensitive() {
        let Ok(name) = HeaderName::from_bytes(b"V") else {
            panic!("expected compact Via header");
        };

        assert_eq!(name.kind(), Some(HeaderKind::Via));
        assert_eq!(name.as_str(), "Via");
    }

    #[test]
    fn exposes_compact_name_when_defined() {
        let via = HeaderName::known(HeaderKind::Via);
        let call_id = HeaderName::known(HeaderKind::CallId);
        let cseq = HeaderName::known(HeaderKind::CSeq);

        assert_eq!(via.compact_name(), Some("v"));
        assert_eq!(call_id.compact_name(), Some("i"));
        assert_eq!(cseq.compact_name(), None);
    }

    #[test]
    fn preserves_extension_header_spelling() {
        let Ok(name) = HeaderName::from_bytes(b"X-LiveAISIP-Trace") else {
            panic!("expected extension header");
        };

        assert!(name.is_extension());
        assert_eq!(name.kind(), None);
        assert_eq!(name.as_str(), "X-LiveAISIP-Trace");
    }

    #[test]
    fn extension_header_equality_is_case_insensitive() {
        let Ok(first) = HeaderName::from_bytes(b"X-LiveAISIP-Trace") else {
            panic!("expected extension header");
        };

        let Ok(second) = HeaderName::from_bytes(b"x-liveaisip-trace") else {
            panic!("expected extension header");
        };

        assert_eq!(first, second);
    }

    #[test]
    fn extension_header_hashing_matches_case_insensitive_equality() {
        let Ok(first) = HeaderName::from_bytes(b"X-LiveAISIP-Trace") else {
            panic!("expected extension header");
        };

        let Ok(second) = HeaderName::from_bytes(b"x-liveaisip-trace") else {
            panic!("expected extension header");
        };

        let mut names = HashSet::new();

        assert!(names.insert(first));
        assert!(!names.insert(second));
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn parses_header_name_from_str() {
        let Ok(name) = HeaderName::from_str("Call-ID") else {
            panic!("expected valid header name");
        };

        assert_eq!(name.kind(), Some(HeaderKind::CallId));
    }

    #[test]
    fn rejects_empty_header_name() {
        assert_eq!(HeaderName::from_bytes(b""), Err(HeaderNameError::Empty));
    }

    #[test]
    fn rejects_header_name_with_space() {
        assert_eq!(
            HeaderName::from_bytes(b"Bad Header"),
            Err(HeaderNameError::InvalidToken {
                index: 3,
                byte: b' ',
            })
        );
    }

    #[test]
    fn rejects_header_name_with_colon() {
        assert_eq!(
            HeaderName::from_bytes(b"Bad:Header"),
            Err(HeaderNameError::InvalidToken {
                index: 3,
                byte: b':',
            })
        );
    }

    #[test]
    fn rejects_non_ascii_header_name() {
        assert_eq!(
            HeaderName::from_bytes(b"X-\xff"),
            Err(HeaderNameError::InvalidToken {
                index: 2,
                byte: 0xff,
            })
        );
    }

    #[test]
    fn rejects_header_name_above_limit() {
        let input = vec![b'A'; MAX_HEADER_NAME_BYTES + 1];

        assert_eq!(
            HeaderName::from_bytes(&input),
            Err(HeaderNameError::TooLong {
                length: MAX_HEADER_NAME_BYTES + 1,
                maximum: MAX_HEADER_NAME_BYTES,
            })
        );
    }

    #[test]
    fn accepts_header_name_at_limit() {
        let input = vec![b'A'; MAX_HEADER_NAME_BYTES];

        assert!(HeaderName::from_bytes(&input).is_ok());
    }

    #[test]
    fn accepts_empty_header_value() {
        let Ok(value) = HeaderValue::from_bytes(b"") else {
            panic!("expected empty header value");
        };

        assert!(value.is_empty());
        assert_eq!(value.len(), 0);
    }

    #[test]
    fn preserves_ascii_header_value() {
        let Ok(value) = HeaderValue::from_bytes(b"application/sdp; charset=utf-8") else {
            panic!("expected valid header value");
        };

        assert_eq!(value.as_bytes(), b"application/sdp; charset=utf-8");
        assert_eq!(value.as_str(), Some("application/sdp; charset=utf-8"));
    }

    #[test]
    fn preserves_horizontal_tab() {
        let Ok(value) = HeaderValue::from_bytes(b"one\ttwo") else {
            panic!("expected horizontal tab");
        };

        assert_eq!(value.as_bytes(), b"one\ttwo");
    }

    #[test]
    fn preserves_utf8_header_value() {
        let Ok(value) = HeaderValue::from_str_value("Riyadh الرياض") else {
            panic!("expected UTF-8 header value");
        };

        assert_eq!(value.as_str(), Some("Riyadh الرياض"));
    }

    #[test]
    fn preserves_non_utf8_extension_value_bytes() {
        let input = [b'X', b'-', 0xff];

        let Ok(value) = HeaderValue::from_bytes(&input) else {
            panic!("expected opaque extension value");
        };

        assert_eq!(value.as_bytes(), input);
        assert_eq!(value.as_str(), None);
    }

    #[test]
    fn rejects_carriage_return_in_header_value() {
        assert_eq!(
            HeaderValue::from_bytes(b"value\rinjected"),
            Err(HeaderValueError::InvalidByte {
                index: 5,
                byte: b'\r',
            })
        );
    }

    #[test]
    fn rejects_line_feed_in_header_value() {
        assert_eq!(
            HeaderValue::from_bytes(b"value\ninjected"),
            Err(HeaderValueError::InvalidByte {
                index: 5,
                byte: b'\n',
            })
        );
    }

    #[test]
    fn rejects_nul_in_header_value() {
        assert_eq!(
            HeaderValue::from_bytes(b"value\0"),
            Err(HeaderValueError::InvalidByte { index: 5, byte: 0 })
        );
    }

    #[test]
    fn rejects_del_in_header_value() {
        assert_eq!(
            HeaderValue::from_bytes(b"value\x7f"),
            Err(HeaderValueError::InvalidByte {
                index: 5,
                byte: 0x7f,
            })
        );
    }

    #[test]
    fn rejects_header_value_above_limit() {
        let input = vec![b'A'; MAX_HEADER_VALUE_BYTES + 1];

        assert_eq!(
            HeaderValue::from_bytes(&input),
            Err(HeaderValueError::TooLong {
                length: MAX_HEADER_VALUE_BYTES + 1,
                maximum: MAX_HEADER_VALUE_BYTES,
            })
        );
    }

    #[test]
    fn accepts_header_value_at_limit() {
        let input = vec![b'A'; MAX_HEADER_VALUE_BYTES];

        let Ok(value) = HeaderValue::from_bytes(&input) else {
            panic!("expected value at operational limit");
        };

        assert_eq!(value.len(), MAX_HEADER_VALUE_BYTES);
    }

    #[test]
    fn constructs_generic_header() {
        let name = HeaderName::known(HeaderKind::UserAgent);

        let Ok(value) = HeaderValue::from_bytes(b"LiveAISIP") else {
            panic!("expected valid header value");
        };

        let header = Header::new(name, value);

        assert_eq!(header.name().kind(), Some(HeaderKind::UserAgent));
        assert_eq!(header.value().as_bytes(), b"LiveAISIP");
    }

    #[test]
    fn header_can_be_consumed_into_parts() {
        let name = HeaderName::known(HeaderKind::Server);

        let Ok(value) = HeaderValue::from_bytes(b"LiveAISIP") else {
            panic!("expected valid header value");
        };

        let header = Header::new(name, value);
        let (name, value) = header.into_parts();

        assert_eq!(name.kind(), Some(HeaderKind::Server));
        assert_eq!(value.as_bytes(), b"LiveAISIP");
    }

    #[test]
    fn header_name_error_classes_are_stable() {
        assert_eq!(HeaderNameError::Empty.class(), "empty");

        assert_eq!(
            HeaderNameError::TooLong {
                length: 257,
                maximum: 256,
            }
            .class(),
            "too-long"
        );

        assert_eq!(
            HeaderNameError::InvalidToken {
                index: 1,
                byte: b' ',
            }
            .class(),
            "invalid-token"
        );
    }

    #[test]
    fn header_value_error_classes_are_stable() {
        assert_eq!(
            HeaderValueError::TooLong {
                length: 65_537,
                maximum: 65_536,
            }
            .class(),
            "too-long"
        );

        assert_eq!(
            HeaderValueError::InvalidByte {
                index: 0,
                byte: b'\r',
            }
            .class(),
            "invalid-byte"
        );
    }
}
