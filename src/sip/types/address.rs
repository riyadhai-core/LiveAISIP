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

//! SIP address representation.
//!
//! SIP header fields commonly identify endpoints using either a bare URI
//! (`addr-spec`) or a bracketed `name-addr` form containing an optional display
//! name.
//!
//! This module models those forms independently from header-specific parameters
//! such as `tag`, contact parameters, routing parameters, and extension values.
//! Those parameters belong to their respective SIP header types.
//!
//! Display names are stored as logical text and serialized as quoted strings.
//! This provides deterministic output while preventing control characters from
//! being introduced into SIP header lines.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;

use crate::sip::types::uri::Uri;

/// Maximum accepted display-name size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_DISPLAY_NAME_BYTES: usize = 1024;

/// A SIP address.
///
/// The two wire-level address forms are preserved explicitly:
///
/// - [`Address::NameAddr`] represents `[display-name] <URI>`.
/// - [`Address::AddrSpec`] represents a bare URI.
#[derive(Clone, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Address {
    /// Bracketed `name-addr` representation.
    NameAddr(NameAddr),

    /// Bare `addr-spec` representation.
    AddrSpec(Uri),
}

impl Address {
    /// Creates a bracketed address without a display name.
    #[must_use]
    pub const fn name_addr(uri: Uri) -> Self {
        Self::NameAddr(NameAddr::new(uri))
    }

    /// Creates a bare URI address.
    #[must_use]
    pub const fn addr_spec(uri: Uri) -> Self {
        Self::AddrSpec(uri)
    }

    /// Returns the URI contained by this address.
    #[must_use]
    pub const fn uri(&self) -> &Uri {
        match self {
            Self::NameAddr(address) => address.uri(),
            Self::AddrSpec(uri) => uri,
        }
    }

    /// Returns mutable access to the URI contained by this address.
    #[must_use]
    pub const fn uri_mut(&mut self) -> &mut Uri {
        match self {
            Self::NameAddr(address) => address.uri_mut(),
            Self::AddrSpec(uri) => uri,
        }
    }

    /// Consumes the address and returns its URI.
    #[must_use]
    pub fn into_uri(self) -> Uri {
        match self {
            Self::NameAddr(address) => address.into_uri(),
            Self::AddrSpec(uri) => uri,
        }
    }

    /// Returns the display name when this is a `name-addr` containing one.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        match self {
            Self::NameAddr(address) => address.display_name(),
            Self::AddrSpec(_) => None,
        }
    }

    /// Returns whether this address uses the bracketed `name-addr` form.
    #[must_use]
    pub const fn is_name_addr(&self) -> bool {
        matches!(self, Self::NameAddr(_))
    }

    /// Returns whether this address uses the bare `addr-spec` form.
    #[must_use]
    pub const fn is_addr_spec(&self) -> bool {
        matches!(self, Self::AddrSpec(_))
    }

    /// Returns the `name-addr` value when present.
    #[must_use]
    pub const fn as_name_addr(&self) -> Option<&NameAddr> {
        match self {
            Self::NameAddr(address) => Some(address),
            Self::AddrSpec(_) => None,
        }
    }

    /// Returns mutable access to the `name-addr` value when present.
    #[must_use]
    pub const fn as_name_addr_mut(&mut self) -> Option<&mut NameAddr> {
        match self {
            Self::NameAddr(address) => Some(address),
            Self::AddrSpec(_) => None,
        }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameAddr(address) => formatter.debug_tuple("NameAddr").field(address).finish(),
            Self::AddrSpec(uri) => formatter.debug_tuple("AddrSpec").field(uri).finish(),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameAddr(address) => fmt::Display::fmt(address, formatter),
            Self::AddrSpec(uri) => fmt::Display::fmt(uri, formatter),
        }
    }
}

impl From<NameAddr> for Address {
    fn from(address: NameAddr) -> Self {
        Self::NameAddr(address)
    }
}

impl From<Uri> for Address {
    fn from(uri: Uri) -> Self {
        Self::AddrSpec(uri)
    }
}

/// A SIP `name-addr`.
///
/// A `name-addr` always serializes with angle brackets around its URI. The
/// display name is optional.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct NameAddr {
    display_name: Option<DisplayName>,
    uri: Uri,
}

impl NameAddr {
    /// Creates a `name-addr` without a display name.
    #[must_use]
    pub const fn new(uri: Uri) -> Self {
        Self {
            display_name: None,
            uri,
        }
    }

    /// Creates a `name-addr` containing a validated display name.
    #[must_use]
    pub const fn with_display_name(uri: Uri, display_name: DisplayName) -> Self {
        Self {
            display_name: Some(display_name),
            uri,
        }
    }

    /// Returns the optional display name.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_ref().map(DisplayName::as_str)
    }

    /// Returns the structured display-name value.
    #[must_use]
    pub const fn display_name_value(&self) -> Option<&DisplayName> {
        self.display_name.as_ref()
    }

    /// Sets the display name.
    pub fn set_display_name(&mut self, display_name: DisplayName) {
        self.display_name = Some(display_name);
    }

    /// Removes the display name.
    pub fn clear_display_name(&mut self) {
        self.display_name = None;
    }

    /// Returns the address URI.
    #[must_use]
    pub const fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns mutable access to the address URI.
    #[must_use]
    pub const fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }

    /// Consumes the value and returns its URI.
    #[must_use]
    pub fn into_uri(self) -> Uri {
        self.uri
    }
}

impl fmt::Debug for NameAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NameAddr")
            .field("display_name", &self.display_name)
            .field("uri", &self.uri)
            .finish()
    }
}

impl fmt::Display for NameAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(display_name) = &self.display_name {
            write!(formatter, "{display_name} ")?;
        }

        write!(formatter, "<{}>", self.uri)
    }
}

/// A validated SIP display name.
///
/// The logical display-name text is stored without surrounding quotation marks.
/// Serialization emits a quoted string and escapes embedded quotation marks
/// and backslashes.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DisplayName(Box<str>);

impl DisplayName {
    /// Creates a validated display name.
    ///
    /// Empty display names are allowed because an empty quoted string is
    /// syntactically representable.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::DisplayNameTooLong`] when the configured
    /// operational size limit is exceeded, or
    /// [`BuildError::InvalidDisplayName`] when the value contains control
    /// characters.
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, BuildError> {
        let value = value.into();

        if value.len() > MAX_DISPLAY_NAME_BYTES {
            return Err(BuildError::DisplayNameTooLong {
                length: value.len(),
                maximum: MAX_DISPLAY_NAME_BYTES,
            });
        }

        if value.chars().any(char::is_control) {
            return Err(BuildError::InvalidDisplayName);
        }

        Ok(Self(value))
    }

    /// Returns the logical display-name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the display-name length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the display name is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for DisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("DisplayName").field(&self.0).finish()
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_char('"')?;

        for character in self.0.chars() {
            match character {
                '"' => formatter.write_str("\\\"")?,
                '\\' => formatter.write_str("\\\\")?,
                _ => formatter.write_char(character)?,
            }
        }

        formatter.write_char('"')
    }
}

/// Failure to construct a valid SIP address component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    /// The display name exceeded the configured operational size limit.
    DisplayNameTooLong {
        /// Actual display-name length in bytes.
        length: usize,

        /// Maximum accepted display-name length in bytes.
        maximum: usize,
    },

    /// The display name contained a disallowed control character.
    InvalidDisplayName,
}

impl BuildError {
    /// Returns a stable low-cardinality classification suitable for metrics and
    /// structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::DisplayNameTooLong { .. } => "display-name-too-long",
            Self::InvalidDisplayName => "invalid-display-name",
        }
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DisplayNameTooLong { length, maximum } => {
                write!(
                    formatter,
                    "SIP display-name length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidDisplayName => {
                formatter.write_str("SIP display name contains a control character")
            }
        }
    }
}

impl StdError for BuildError {}

#[cfg(test)]
mod tests {
    use super::{Address, BuildError, DisplayName, MAX_DISPLAY_NAME_BYTES, NameAddr};
    use crate::sip::parser::uri;
    use crate::sip::types::uri::Uri;

    fn parse_uri(input: &str) -> Uri {
        let Ok(uri) = uri::parse_str(input) else {
            panic!("expected valid URI");
        };

        uri
    }

    #[test]
    fn creates_bare_addr_spec() {
        let address = Address::addr_spec(parse_uri("sip:alice@example.com"));

        assert!(address.is_addr_spec());
        assert!(!address.is_name_addr());
        assert_eq!(address.display_name(), None);
        assert_eq!(address.to_string(), "sip:alice@example.com");
    }

    #[test]
    fn creates_name_addr_without_display_name() {
        let address = Address::name_addr(parse_uri("sip:alice@example.com"));

        assert!(address.is_name_addr());
        assert!(!address.is_addr_spec());
        assert_eq!(address.display_name(), None);
        assert_eq!(address.to_string(), "<sip:alice@example.com>");
    }

    #[test]
    fn creates_name_addr_with_display_name() {
        let Ok(display_name) = DisplayName::new("Alice Smith") else {
            panic!("expected valid display name");
        };

        let address = NameAddr::with_display_name(parse_uri("sip:alice@example.com"), display_name);

        assert_eq!(address.display_name(), Some("Alice Smith"));
        assert_eq!(
            address.to_string(),
            "\"Alice Smith\" <sip:alice@example.com>"
        );
    }

    #[test]
    fn display_name_is_always_quoted() {
        let Ok(display_name) = DisplayName::new("Alice") else {
            panic!("expected valid display name");
        };

        assert_eq!(display_name.to_string(), "\"Alice\"");
    }

    #[test]
    fn escapes_quote_in_display_name() {
        let Ok(display_name) = DisplayName::new("Alice \"Voice\"") else {
            panic!("expected valid display name");
        };

        assert_eq!(display_name.to_string(), "\"Alice \\\"Voice\\\"\"");
    }

    #[test]
    fn escapes_backslash_in_display_name() {
        let Ok(display_name) = DisplayName::new(r"Alice\Voice") else {
            panic!("expected valid display name");
        };

        assert_eq!(display_name.to_string(), r#""Alice\\Voice""#);
    }

    #[test]
    fn accepts_empty_display_name() {
        let Ok(display_name) = DisplayName::new("") else {
            panic!("expected empty display name to be valid");
        };

        assert!(display_name.is_empty());
        assert_eq!(display_name.len(), 0);
        assert_eq!(display_name.to_string(), "\"\"");
    }

    #[test]
    fn accepts_unicode_display_name() {
        let Ok(display_name) = DisplayName::new("Noureddin الرياض") else {
            panic!("expected valid UTF-8 display name");
        };

        assert_eq!(display_name.as_str(), "Noureddin الرياض");
    }

    #[test]
    fn rejects_carriage_return_in_display_name() {
        assert_eq!(
            DisplayName::new("Alice\rInjected"),
            Err(BuildError::InvalidDisplayName)
        );
    }

    #[test]
    fn rejects_line_feed_in_display_name() {
        assert_eq!(
            DisplayName::new("Alice\nInjected"),
            Err(BuildError::InvalidDisplayName)
        );
    }

    #[test]
    fn rejects_tab_in_display_name() {
        assert_eq!(
            DisplayName::new("Alice\tSmith"),
            Err(BuildError::InvalidDisplayName)
        );
    }

    #[test]
    fn rejects_display_name_above_size_limit() {
        let value = "A".repeat(MAX_DISPLAY_NAME_BYTES + 1);

        assert_eq!(
            DisplayName::new(value),
            Err(BuildError::DisplayNameTooLong {
                length: MAX_DISPLAY_NAME_BYTES + 1,
                maximum: MAX_DISPLAY_NAME_BYTES,
            })
        );
    }

    #[test]
    fn accepts_display_name_at_size_limit() {
        let value = "A".repeat(MAX_DISPLAY_NAME_BYTES);

        let Ok(display_name) = DisplayName::new(value) else {
            panic!("expected display name at size limit to be valid");
        };

        assert_eq!(display_name.len(), MAX_DISPLAY_NAME_BYTES);
    }

    #[test]
    fn display_name_can_be_replaced() {
        let mut address = NameAddr::new(parse_uri("sip:alice@example.com"));

        let Ok(first) = DisplayName::new("Alice") else {
            panic!("expected valid display name");
        };
        address.set_display_name(first);

        assert_eq!(address.display_name(), Some("Alice"));

        let Ok(second) = DisplayName::new("Support") else {
            panic!("expected valid replacement display name");
        };
        address.set_display_name(second);

        assert_eq!(address.display_name(), Some("Support"));
    }

    #[test]
    fn display_name_can_be_cleared() {
        let Ok(display_name) = DisplayName::new("Alice") else {
            panic!("expected valid display name");
        };

        let mut address =
            NameAddr::with_display_name(parse_uri("sip:alice@example.com"), display_name);

        address.clear_display_name();

        assert_eq!(address.display_name(), None);
        assert_eq!(address.to_string(), "<sip:alice@example.com>");
    }

    #[test]
    fn address_exposes_underlying_uri() {
        let address = Address::addr_spec(parse_uri("sips:alice@example.com"));

        assert_eq!(address.uri().scheme(), "sips");
    }

    #[test]
    fn address_allows_uri_mutation() {
        let mut address = Address::addr_spec(parse_uri("sip:alice@example.com"));

        let Some(uri) = address.uri_mut().as_sip() else {
            panic!("expected SIP URI");
        };

        assert_eq!(uri.user(), Some("alice"));
    }

    #[test]
    fn consumes_address_into_uri() {
        let address = Address::name_addr(parse_uri("sip:alice@example.com"));
        let uri = address.into_uri();

        assert_eq!(uri.to_string(), "sip:alice@example.com");
    }

    #[test]
    fn converts_name_addr_into_address() {
        let name_addr = NameAddr::new(parse_uri("sip:alice@example.com"));
        let address = Address::from(name_addr);

        assert!(matches!(address, Address::NameAddr(_)));
    }

    #[test]
    fn converts_uri_into_addr_spec() {
        let address = Address::from(parse_uri("sip:alice@example.com"));

        assert!(matches!(address, Address::AddrSpec(_)));
    }

    #[test]
    fn returns_name_addr_reference() {
        let address = Address::name_addr(parse_uri("sip:alice@example.com"));

        let Some(name_addr) = address.as_name_addr() else {
            panic!("expected name-addr");
        };

        assert_eq!(name_addr.uri().to_string(), "sip:alice@example.com");
    }

    #[test]
    fn addr_spec_has_no_name_addr_reference() {
        let address = Address::addr_spec(parse_uri("sip:alice@example.com"));

        assert!(address.as_name_addr().is_none());
    }

    #[test]
    fn build_error_classes_are_stable() {
        assert_eq!(
            BuildError::DisplayNameTooLong {
                length: 1025,
                maximum: 1024,
            }
            .class(),
            "display-name-too-long"
        );

        assert_eq!(
            BuildError::InvalidDisplayName.class(),
            "invalid-display-name"
        );
    }
}
