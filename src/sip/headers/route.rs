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

//! SIP `Route` header.
//!
//! `Route` and `Record-Route` share the same bounded `name-addr` list grammar.
//! This module deliberately reuses that audited entry representation while
//! keeping the complete field type distinct, preventing callers from confusing
//! route-set establishment with routing an individual request.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use super::record_route::{self, RecordRoute, RecordRouteEntry};

/// Maximum accepted `Route` field-value size.
pub const MAX_ROUTE_BYTES: usize = record_route::MAX_RECORD_ROUTE_BYTES;
/// Maximum entries accepted in one `Route` field value.
pub const MAX_ROUTE_ENTRIES: usize = record_route::MAX_RECORD_ROUTE_ENTRIES;
/// Maximum parameters accepted on one route entry.
pub const MAX_ROUTE_PARAMETERS: usize = record_route::MAX_RECORD_ROUTE_PARAMETERS;

/// A route entry shared with the identical `Record-Route` grammar.
pub type RouteEntry = record_route::RecordRouteEntry;
/// A generic route-entry parameter.
pub type RouteParameter = record_route::RecordRouteParameter;

/// A validated ordered `Route` field value.
#[derive(Clone, Eq, PartialEq)]
pub struct Route {
    entries: Vec<RouteEntry>,
}

impl Route {
    /// Parses a `Route` field value from wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when syntax or an operational bound is invalid.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Creates a non-empty bounded `Route` field from entries.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] for an empty or oversized list.
    pub fn from_entries(entries: Vec<RouteEntry>) -> Result<Self, ParseError> {
        RecordRoute::from_entries(entries)
            .map(|value| Self {
                entries: value.into_entries(),
            })
            .map_err(ParseError)
    }

    /// Returns route entries in wire order.
    #[must_use]
    pub fn entries(&self) -> &[RouteEntry] {
        &self.entries
    }

    /// Consumes the field into its entries.
    #[must_use]
    pub fn into_entries(self) -> Vec<RouteEntry> {
        self.entries
    }
}

impl fmt::Debug for Route {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Route")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Route {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, entry) in self.entries.iter().enumerate() {
            if index != 0 {
                formatter.write_str(", ")?;
            }
            write!(formatter, "{entry}")?;
        }
        Ok(())
    }
}

impl FromStr for Route {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// Parses a `Route` field value.
///
/// # Errors
///
/// Returns [`ParseError`] when syntax or an operational bound is invalid.
pub fn parse(input: &[u8]) -> Result<Route, ParseError> {
    RecordRoute::from_bytes(input)
        .map(|value| Route {
            entries: value.into_entries(),
        })
        .map_err(ParseError)
}

/// Failure to parse or construct a `Route` field value.
#[derive(Debug)]
pub struct ParseError(record_route::ParseError);

impl ParseError {
    /// Returns the underlying shared route-list grammar error.
    #[must_use]
    pub const fn grammar_error(&self) -> &record_route::ParseError {
        &self.0
    }

    /// Consumes this wrapper into the shared grammar error.
    #[must_use]
    pub fn into_grammar_error(self) -> record_route::ParseError {
        self.0
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SIP Route field value")
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.0)
    }
}

impl From<record_route::ParseError> for ParseError {
    fn from(error: record_route::ParseError) -> Self {
        Self(error)
    }
}

impl From<RecordRoute> for Route {
    fn from(value: RecordRoute) -> Self {
        Self {
            entries: value.into_entries(),
        }
    }
}

impl TryFrom<Route> for RecordRoute {
    type Error = record_route::ParseError;

    fn try_from(value: Route) -> Result<Self, Self::Error> {
        Self::from_entries(value.entries)
    }
}

impl From<RecordRouteEntry> for Route {
    fn from(entry: RecordRouteEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ParseError, Route};

    #[test]
    fn parses_ordered_loose_routes() {
        let value = Route::from_bytes(b"<sip:first.example;lr>, <sips:second.example;lr>")
            .unwrap_or_else(|_| panic!("valid Route"));
        assert_eq!(value.entries().len(), 2);
        assert_eq!(value.entries()[0].uri().to_string(), "sip:first.example;lr");
        assert_eq!(
            value.entries()[1].uri().to_string(),
            "sips:second.example;lr"
        );
    }

    #[test]
    fn preserves_quoted_commas_and_parameters() {
        let value = Route::from_bytes(br#""Proxy, East" <sip:p.example;lr>;x="a,b""#)
            .unwrap_or_else(|_| panic!("valid Route"));
        assert_eq!(value.entries().len(), 1);
        assert_eq!(value.entries()[0].parameters()[0].value(), Some("a,b"));
        assert!(Route::from_bytes(value.to_string().as_bytes()).is_ok());
    }

    #[test]
    fn rejects_bare_uri_and_exposes_shared_error_as_source() {
        let error = Route::from_bytes(b"sip:proxy.example")
            .err()
            .unwrap_or_else(|| panic!("must reject"));
        assert!(matches!(
            error.grammar_error(),
            crate::sip::headers::record_route::ParseError::NameAddrRequired
        ));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn debug_is_redacted() {
        let value = Route::from_bytes(b"<sip:private-user@secret.example;lr>")
            .unwrap_or_else(|_| panic!("valid Route"));
        let debug = format!("{value:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("secret.example"));
    }

    #[test]
    fn error_display_does_not_echo_wire_input() {
        let Err(error) = Route::from_bytes(b"secret-invalid-value") else {
            panic!("must reject")
        };
        assert_eq!(error.to_string(), "invalid SIP Route field value");
        let _: ParseError = error;
    }
}
