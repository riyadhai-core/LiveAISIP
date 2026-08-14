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

//! SIP `Server` header.
//!
//! This module provides the public `Server` header type and its
//! header-specific production policy.
//!
//! The underlying product/comment grammar is shared with `User-Agent` through
//! the crate-private `product_comment` module. Parsing, token validation,
//! nested-comment handling, quoted-pair decoding, canonical escaping,
//! resource limits, serialized-length accounting, and parse errors therefore
//! have one implementation.
//!
//! The production-safe default identifies the software only as `LiveAISIP`.
//! Exact software versions, build identifiers, operating-system details,
//! deployment topology, and node-specific information are not emitted by
//! default.

use std::fmt;
use std::str::FromStr;

use super::product_comment::{self, Value};

pub use super::product_comment::{
    Comment as ServerComment, Component as ServerComponent, ParseError, Product as ServerProduct,
};

/// Maximum accepted SIP `Server` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_SERVER_BYTES: usize = product_comment::MAX_VALUE_BYTES;

/// Maximum number of components accepted in one `Server` field value.
pub const MAX_SERVER_COMPONENTS: usize = product_comment::MAX_COMPONENTS;

/// Maximum accepted product-name size in bytes.
pub const MAX_SERVER_PRODUCT_NAME_BYTES: usize = product_comment::MAX_PRODUCT_NAME_BYTES;

/// Maximum accepted product-version size in bytes.
pub const MAX_SERVER_PRODUCT_VERSION_BYTES: usize = product_comment::MAX_PRODUCT_VERSION_BYTES;

/// Maximum accepted logical comment size in bytes.
pub const MAX_SERVER_COMMENT_BYTES: usize = product_comment::MAX_COMMENT_BYTES;

/// Maximum accepted nested comment depth, including the outermost comment.
pub const MAX_SERVER_COMMENT_NESTING: usize = product_comment::MAX_COMMENT_NESTING;

/// Default production-safe SIP `Server` product identity.
///
/// The default intentionally omits version numbers, build identifiers,
/// operating-system information, node identifiers, and deployment details.
pub const DEFAULT_SERVER_PRODUCT: &str = "LiveAISIP";

/// A validated SIP `Server` field value.
///
/// `Server` is intentionally a distinct public SIP header type even though its
/// product/comment wire grammar is shared with `User-Agent`.
///
/// Successfully constructed values always contain at least one component and
/// serialize to no more than [`MAX_SERVER_BYTES`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Server {
    value: Value,
}

impl Server {
    /// Creates a `Server` value containing one validated component.
    #[must_use]
    pub fn new(component: ServerComponent) -> Self {
        Self {
            value: Value::new(component),
        }
    }

    /// Creates the production-safe default `Server` value.
    ///
    /// The default advertises only [`DEFAULT_SERVER_PRODUCT`] and deliberately
    /// omits software versions, build identifiers, operating-system details,
    /// deployment topology, and node-specific information.
    ///
    /// More detailed values remain available through explicit constructors for
    /// development, diagnostics, and interoperability testing.
    #[must_use]
    pub fn production_default() -> Self {
        Self {
            value: Value::from_known_product(DEFAULT_SERVER_PRODUCT),
        }
    }

    /// Creates a `Server` value containing one product without a version.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the product name is invalid or exceeds its
    /// operational size bound.
    pub fn product(name: impl Into<Box<str>>) -> Result<Self, ParseError> {
        Ok(Self::new(ServerComponent::product(name)?))
    }

    /// Creates a `Server` value containing one product and version.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the product name or version is invalid or
    /// exceeds its operational size bound.
    pub fn product_with_version(
        name: impl Into<Box<str>>,
        version: impl Into<Box<str>>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(ServerComponent::product_with_version(
            name, version,
        )?))
    }

    /// Creates a `Server` value from ordered validated components.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Empty`] when no components are supplied,
    /// [`ParseError::TooManyComponents`] when the component-count bound is
    /// exceeded, or [`ParseError::TooLong`] when canonical serialization
    /// exceeds the field-value size bound.
    pub fn from_components(components: Vec<ServerComponent>) -> Result<Self, ParseError> {
        Ok(Self {
            value: Value::from_components(components)?,
        })
    }

    /// Parses a SIP `Server` field value from wire bytes.
    ///
    /// Header-name and `HCOLON` parsing are outside this function.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the field value violates the shared SIP
    /// product/comment grammar or an operational bound.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns all components in wire order.
    #[must_use]
    pub fn components(&self) -> &[ServerComponent] {
        self.value.components()
    }

    /// Returns the first component.
    ///
    /// Successfully constructed `Server` values are always non-empty.
    #[must_use]
    pub fn first(&self) -> &ServerComponent {
        self.value.first()
    }

    /// Returns the number of components.
    #[must_use]
    pub fn component_count(&self) -> usize {
        self.value.component_count()
    }

    /// Returns the canonical serialized field-value length in bytes.
    #[must_use]
    pub const fn serialized_len(&self) -> usize {
        self.value.serialized_len()
    }

    /// Appends one validated component.
    ///
    /// The update is transactional. On failure, the existing `Server` value
    /// remains unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyComponents`] when the component-count
    /// bound has been reached or [`ParseError::TooLong`] when the resulting
    /// canonical field value would exceed [`MAX_SERVER_BYTES`].
    pub fn push(&mut self, component: ServerComponent) -> Result<(), ParseError> {
        self.value.push(component)
    }

    /// Consumes the value into its ordered components.
    #[must_use]
    pub fn into_components(self) -> Vec<ServerComponent> {
        self.value.into_components()
    }
}

impl Default for Server {
    /// Returns the production-safe default `Server` identity.
    ///
    /// The resulting field value is:
    ///
    /// ```text
    /// LiveAISIP
    /// ```
    fn default() -> Self {
        Self::production_default()
    }
}

impl fmt::Display for Server {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.value, formatter)
    }
}

impl FromStr for Server {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// Parses a SIP `Server` field value.
///
/// Leading and trailing spaces and horizontal tabs are accepted. Components
/// inside the field value must be separated by at least one space or
/// horizontal tab.
///
/// # Errors
///
/// Returns [`ParseError`] when the field value violates the shared SIP
/// product/comment grammar or an operational bound.
pub fn parse(input: &[u8]) -> Result<Server, ParseError> {
    Ok(Server {
        value: Value::parse(input)?,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_SERVER_PRODUCT, MAX_SERVER_BYTES, MAX_SERVER_COMMENT_BYTES,
        MAX_SERVER_COMMENT_NESTING, MAX_SERVER_COMPONENTS, MAX_SERVER_PRODUCT_NAME_BYTES,
        MAX_SERVER_PRODUCT_VERSION_BYTES, ParseError, Server, ServerComment, ServerComponent,
        ServerProduct, parse,
    };
    use std::str::FromStr;

    #[test]
    fn production_default_exposes_only_generic_product_identity() {
        let server = Server::production_default();

        assert_eq!(server.to_string(), DEFAULT_SERVER_PRODUCT);
        assert_eq!(server.component_count(), 1);
        assert_eq!(server.serialized_len(), DEFAULT_SERVER_PRODUCT.len());

        let Some(product) = server.first().as_product() else {
            panic!("expected product component");
        };

        assert_eq!(product.name(), DEFAULT_SERVER_PRODUCT);
        assert_eq!(product.version(), None);
    }

    #[test]
    fn default_is_production_safe() {
        let server = Server::default();
        let serialized = server.to_string();

        assert_eq!(serialized, DEFAULT_SERVER_PRODUCT);
        assert!(!serialized.contains("0.1.0"));
        assert!(!serialized.contains('/'));
        assert_eq!(server.component_count(), 1);
    }

    #[test]
    fn public_limits_match_shared_grammar_limits() {
        assert_eq!(MAX_SERVER_BYTES, 8 * 1024);
        assert_eq!(MAX_SERVER_COMPONENTS, 64);
        assert_eq!(MAX_SERVER_PRODUCT_NAME_BYTES, 256);
        assert_eq!(MAX_SERVER_PRODUCT_VERSION_BYTES, 256);
        assert_eq!(MAX_SERVER_COMMENT_BYTES, 2 * 1024);
        assert_eq!(MAX_SERVER_COMMENT_NESTING, 16);
    }

    #[test]
    fn creates_single_product() {
        let Ok(server) = Server::product("LiveAISIP") else {
            panic!("expected valid Server product");
        };

        assert_eq!(server.to_string(), "LiveAISIP");
        assert_eq!(server.component_count(), 1);

        let Some(product) = server.first().as_product() else {
            panic!("expected product component");
        };

        assert_eq!(product.name(), "LiveAISIP");
        assert_eq!(product.version(), None);
    }

    #[test]
    fn creates_versioned_product_explicitly() {
        let Ok(server) = Server::product_with_version("LiveAISIP", "0.1.0") else {
            panic!("expected valid versioned Server product");
        };

        assert_eq!(server.to_string(), "LiveAISIP/0.1.0");

        let Some(product) = server.first().as_product() else {
            panic!("expected product component");
        };

        assert_eq!(product.name(), "LiveAISIP");
        assert_eq!(product.version(), Some("0.1.0"));
    }

    #[test]
    fn parses_through_shared_grammar() {
        let Ok(server) = parse(b"ProductA/1.0 (comment) ProductB") else {
            panic!("expected valid Server field value");
        };

        assert_eq!(server.component_count(), 3);
        assert_eq!(server.to_string(), "ProductA/1.0 (comment) ProductB");

        assert_eq!(
            server.components()[0].as_product().map(ServerProduct::name),
            Some("ProductA")
        );

        assert_eq!(
            server.components()[1]
                .as_comment()
                .map(ServerComment::as_str),
            Some("comment")
        );

        assert_eq!(
            server.components()[2].as_product().map(ServerProduct::name),
            Some("ProductB")
        );
    }

    #[test]
    fn nested_comment_uses_shared_canonicalization() {
        let Ok(server) = parse(b"Product/1.0 (outer (nested) value)") else {
            panic!("expected nested Server comment");
        };

        assert_eq!(server.to_string(), "Product/1.0 (outer \\(nested\\) value)");

        assert_eq!(server.serialized_len(), server.to_string().len());
    }

    #[test]
    fn utf8_comment_uses_shared_parser() {
        let input = "LiveAISIP (Riyadh الرياض)";

        let Ok(server) = parse(input.as_bytes()) else {
            panic!("expected UTF-8 Server comment");
        };

        assert_eq!(
            server.components()[1]
                .as_comment()
                .map(ServerComment::as_str),
            Some("Riyadh الرياض")
        );
    }

    #[test]
    fn component_alias_exposes_shared_product_constructor() {
        let Ok(component) = ServerComponent::product_with_version("Product", "2.0") else {
            panic!("expected Server product component");
        };

        assert_eq!(component.to_string(), "Product/2.0");
    }

    #[test]
    fn component_alias_exposes_shared_comment_constructor() {
        let Ok(component) = ServerComponent::comment("RiyadhAI LLC") else {
            panic!("expected Server comment component");
        };

        assert_eq!(component.to_string(), "(RiyadhAI LLC)");
    }

    #[test]
    fn server_product_alias_exposes_shared_api() {
        let Ok(product) = ServerProduct::with_version("Product", "1.0") else {
            panic!("expected Server product");
        };

        assert_eq!(product.name(), "Product");
        assert_eq!(product.version(), Some("1.0"));
        assert!(product.has_version());
    }

    #[test]
    fn server_comment_alias_exposes_shared_api() {
        let Ok(comment) = ServerComment::new("A (B) \\ C") else {
            panic!("expected Server comment");
        };

        assert_eq!(comment.as_str(), "A (B) \\ C");
        assert_eq!(comment.to_string(), "(A \\(B\\) \\\\ C)");
    }

    #[test]
    fn new_accepts_validated_component() {
        let Ok(component) = ServerComponent::product("Product") else {
            panic!("expected product component");
        };

        let server = Server::new(component);

        assert_eq!(server.to_string(), "Product");
        assert_eq!(server.component_count(), 1);
    }

    #[test]
    fn from_components_preserves_order() {
        let Ok(first) = ServerComponent::product_with_version("A", "1") else {
            panic!("expected first product");
        };

        let Ok(comment) = ServerComponent::comment("middle") else {
            panic!("expected comment");
        };

        let Ok(last) = ServerComponent::product("B") else {
            panic!("expected last product");
        };

        let Ok(server) = Server::from_components(vec![first, comment, last]) else {
            panic!("expected Server value");
        };

        assert_eq!(server.to_string(), "A/1 (middle) B");
        assert_eq!(server.component_count(), 3);
    }

    #[test]
    fn from_components_rejects_empty_vector() {
        assert_eq!(Server::from_components(Vec::new()), Err(ParseError::Empty));
    }

    #[test]
    fn push_delegates_to_shared_bounded_value() {
        let Ok(mut server) = Server::product("A") else {
            panic!("expected initial Server value");
        };

        let Ok(component) = ServerComponent::product_with_version("B", "2") else {
            panic!("expected second product");
        };

        assert!(server.push(component).is_ok());
        assert_eq!(server.to_string(), "A B/2");
        assert_eq!(server.component_count(), 2);
    }

    #[test]
    fn push_remains_transactional_at_component_limit() {
        let mut components = Vec::new();

        for index in 0..MAX_SERVER_COMPONENTS {
            let name = format!("p{index}");

            let Ok(component) = ServerComponent::product(name) else {
                panic!("expected valid product component");
            };

            components.push(component);
        }

        let Ok(mut server) = Server::from_components(components) else {
            panic!("expected Server at component limit");
        };

        let before = server.to_string();

        let Ok(extra) = ServerComponent::product("extra") else {
            panic!("expected extra component");
        };

        assert_eq!(
            server.push(extra),
            Err(ParseError::TooManyComponents {
                maximum: MAX_SERVER_COMPONENTS,
            })
        );

        assert_eq!(server.component_count(), MAX_SERVER_COMPONENTS);
        assert_eq!(server.to_string(), before);
    }

    #[test]
    fn parser_rejects_shared_syntax_error() {
        assert_eq!(parse(b"Product/"), Err(ParseError::MissingProductVersion));
    }

    #[test]
    fn parser_rejects_shared_line_break_error() {
        assert_eq!(
            parse(b"Product/1\r\n Product/2"),
            Err(ParseError::InvalidLineBreak)
        );
    }

    #[test]
    fn parser_rejects_shared_field_size_limit() {
        let input = vec![b'a'; MAX_SERVER_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_SERVER_BYTES + 1,
                maximum: MAX_SERVER_BYTES,
            })
        );
    }

    #[test]
    fn parses_from_bytes_method() {
        let Ok(server) = Server::from_bytes(b"A/1 (test)") else {
            panic!("expected Server from bytes");
        };

        assert_eq!(server.to_string(), "A/1 (test)");
    }

    #[test]
    fn parses_from_str() {
        let Ok(server) = Server::from_str("A/1 (test) B") else {
            panic!("expected Server from string");
        };

        assert_eq!(server.to_string(), "A/1 (test) B");
    }

    #[test]
    fn serialized_length_matches_canonical_output() {
        let Ok(server) = parse(b"A/1 (outer (nested)) B/2") else {
            panic!("expected Server value");
        };

        assert_eq!(server.serialized_len(), server.to_string().len());
    }

    #[test]
    fn into_components_preserves_components() {
        let Ok(server) = parse(b"A/1 (test) B/2") else {
            panic!("expected Server value");
        };

        let components = server.into_components();

        assert_eq!(components.len(), 3);

        assert_eq!(
            components[0].as_product().map(ServerProduct::name),
            Some("A")
        );

        assert_eq!(
            components[1].as_comment().map(ServerComment::as_str),
            Some("test")
        );

        assert_eq!(
            components[2].as_product().map(ServerProduct::name),
            Some("B")
        );
    }

    #[test]
    fn parse_error_is_shared_and_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");

        assert_eq!(
            ParseError::InvalidProductName.class(),
            "invalid-product-name"
        );

        assert_eq!(
            ParseError::UnterminatedComment.class(),
            "unterminated-comment"
        );
    }
}
