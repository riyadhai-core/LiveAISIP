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

//! SIP `User-Agent` header.
//!
//! This module provides the public `User-Agent` header type and its
//! header-specific production policy.
//!
//! The underlying product/comment grammar is shared with `Server` through the
//! crate-private `product_comment` module. Parsing, token validation,
//! nested-comment handling, quoted-pair decoding, canonical escaping,
//! resource limits, serialized-length accounting, and parse errors therefore
//! have one implementation.
//!
//! The production-safe default identifies the software only as `LiveAISIP`.
//! Exact software versions, build identifiers, operating-system details,
//! deployment topology, and node-specific information are not emitted by
//! default.
//!
//! Whether a `User-Agent` field is emitted at all remains a higher-level
//! message-construction and deployment-configuration decision.

use std::fmt;
use std::str::FromStr;

use super::product_comment::{self, Value};

pub use super::product_comment::{
    Comment as UserAgentComment, Component as UserAgentComponent, ParseError,
    Product as UserAgentProduct,
};

/// Maximum accepted SIP `User-Agent` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_USER_AGENT_BYTES: usize = product_comment::MAX_VALUE_BYTES;

/// Maximum number of components accepted in one `User-Agent` field value.
pub const MAX_USER_AGENT_COMPONENTS: usize = product_comment::MAX_COMPONENTS;

/// Maximum accepted product-name size in bytes.
pub const MAX_USER_AGENT_PRODUCT_NAME_BYTES: usize = product_comment::MAX_PRODUCT_NAME_BYTES;

/// Maximum accepted product-version size in bytes.
pub const MAX_USER_AGENT_PRODUCT_VERSION_BYTES: usize = product_comment::MAX_PRODUCT_VERSION_BYTES;

/// Maximum accepted logical comment size in bytes.
pub const MAX_USER_AGENT_COMMENT_BYTES: usize = product_comment::MAX_COMMENT_BYTES;

/// Maximum accepted nested comment depth, including the outermost comment.
pub const MAX_USER_AGENT_COMMENT_NESTING: usize = product_comment::MAX_COMMENT_NESTING;

/// Default production-safe SIP `User-Agent` product identity.
///
/// The default intentionally omits version numbers, build identifiers,
/// operating-system information, node identifiers, and deployment details.
pub const DEFAULT_USER_AGENT_PRODUCT: &str = "LiveAISIP";

/// A validated SIP `User-Agent` field value.
///
/// `UserAgent` intentionally remains a distinct public SIP header type even
/// though its product/comment wire grammar is shared with `Server`.
///
/// Successfully constructed values always contain at least one component and
/// serialize to no more than [`MAX_USER_AGENT_BYTES`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserAgent {
    value: Value,
}

impl UserAgent {
    /// Creates a `User-Agent` value containing one validated component.
    #[must_use]
    pub fn new(component: UserAgentComponent) -> Self {
        Self {
            value: Value::new(component),
        }
    }

    /// Creates the production-safe default `User-Agent` value.
    ///
    /// The default advertises only [`DEFAULT_USER_AGENT_PRODUCT`] and
    /// deliberately omits software versions, build identifiers,
    /// operating-system details, deployment topology, and node-specific
    /// information.
    ///
    /// Whether the header is emitted remains a higher-level configuration
    /// decision.
    #[must_use]
    pub fn production_default() -> Self {
        Self {
            value: Value::from_known_product(DEFAULT_USER_AGENT_PRODUCT),
        }
    }

    /// Creates a `User-Agent` value containing one product without a version.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the product name is invalid or exceeds its
    /// operational size bound.
    pub fn product(name: impl Into<Box<str>>) -> Result<Self, ParseError> {
        Ok(Self::new(UserAgentComponent::product(name)?))
    }

    /// Creates a `User-Agent` value containing one product and version.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the product name or version is invalid or
    /// exceeds its operational size bound.
    pub fn product_with_version(
        name: impl Into<Box<str>>,
        version: impl Into<Box<str>>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(UserAgentComponent::product_with_version(
            name, version,
        )?))
    }

    /// Creates a `User-Agent` value from ordered validated components.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Empty`] when no components are supplied,
    /// [`ParseError::TooManyComponents`] when the component-count bound is
    /// exceeded, or [`ParseError::TooLong`] when canonical serialization
    /// exceeds the field-value size bound.
    pub fn from_components(components: Vec<UserAgentComponent>) -> Result<Self, ParseError> {
        Ok(Self {
            value: Value::from_components(components)?,
        })
    }

    /// Parses a SIP `User-Agent` field value from wire bytes.
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
    pub fn components(&self) -> &[UserAgentComponent] {
        self.value.components()
    }

    /// Returns the first component.
    ///
    /// Successfully constructed `User-Agent` values are always non-empty.
    #[must_use]
    pub fn first(&self) -> &UserAgentComponent {
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
    /// The update is transactional. On failure, the existing `User-Agent`
    /// value remains unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyComponents`] when the component-count
    /// bound has been reached or [`ParseError::TooLong`] when the resulting
    /// canonical field value would exceed [`MAX_USER_AGENT_BYTES`].
    pub fn push(&mut self, component: UserAgentComponent) -> Result<(), ParseError> {
        self.value.push(component)
    }

    /// Consumes the value into its ordered components.
    #[must_use]
    pub fn into_components(self) -> Vec<UserAgentComponent> {
        self.value.into_components()
    }
}

impl Default for UserAgent {
    /// Returns the production-safe default `User-Agent` identity.
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

impl fmt::Display for UserAgent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.value, formatter)
    }
}

impl FromStr for UserAgent {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// Parses a SIP `User-Agent` field value.
///
/// Leading and trailing spaces and horizontal tabs are accepted. Components
/// inside the field value must be separated by at least one space or
/// horizontal tab.
///
/// # Errors
///
/// Returns [`ParseError`] when the field value violates the shared SIP
/// product/comment grammar or an operational bound.
pub fn parse(input: &[u8]) -> Result<UserAgent, ParseError> {
    Ok(UserAgent {
        value: Value::parse(input)?,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_USER_AGENT_PRODUCT, MAX_USER_AGENT_BYTES, MAX_USER_AGENT_COMMENT_BYTES,
        MAX_USER_AGENT_COMMENT_NESTING, MAX_USER_AGENT_COMPONENTS,
        MAX_USER_AGENT_PRODUCT_NAME_BYTES, MAX_USER_AGENT_PRODUCT_VERSION_BYTES, ParseError,
        UserAgent, UserAgentComment, UserAgentComponent, UserAgentProduct, parse,
    };
    use std::str::FromStr;

    #[test]
    fn production_default_exposes_only_generic_product_identity() {
        let user_agent = UserAgent::production_default();

        assert_eq!(user_agent.to_string(), DEFAULT_USER_AGENT_PRODUCT);
        assert_eq!(user_agent.component_count(), 1);
        assert_eq!(
            user_agent.serialized_len(),
            DEFAULT_USER_AGENT_PRODUCT.len()
        );

        let Some(product) = user_agent.first().as_product() else {
            panic!("expected product component");
        };

        assert_eq!(product.name(), DEFAULT_USER_AGENT_PRODUCT);
        assert_eq!(product.version(), None);
    }

    #[test]
    fn default_is_production_safe() {
        let user_agent = UserAgent::default();
        let serialized = user_agent.to_string();

        assert_eq!(serialized, DEFAULT_USER_AGENT_PRODUCT);
        assert!(!serialized.contains("0.1.0"));
        assert!(!serialized.contains('/'));
        assert_eq!(user_agent.component_count(), 1);
    }

    #[test]
    fn public_limits_match_shared_grammar_limits() {
        assert_eq!(MAX_USER_AGENT_BYTES, 8 * 1024);
        assert_eq!(MAX_USER_AGENT_COMPONENTS, 64);
        assert_eq!(MAX_USER_AGENT_PRODUCT_NAME_BYTES, 256);
        assert_eq!(MAX_USER_AGENT_PRODUCT_VERSION_BYTES, 256);
        assert_eq!(MAX_USER_AGENT_COMMENT_BYTES, 2 * 1024);
        assert_eq!(MAX_USER_AGENT_COMMENT_NESTING, 16);
    }

    #[test]
    fn creates_single_product() {
        let Ok(user_agent) = UserAgent::product("LiveAISIP") else {
            panic!("expected valid User-Agent product");
        };

        assert_eq!(user_agent.to_string(), "LiveAISIP");
        assert_eq!(user_agent.component_count(), 1);

        let Some(product) = user_agent.first().as_product() else {
            panic!("expected product component");
        };

        assert_eq!(product.name(), "LiveAISIP");
        assert_eq!(product.version(), None);
    }

    #[test]
    fn creates_versioned_product_explicitly() {
        let Ok(user_agent) = UserAgent::product_with_version("LiveAISIP", "0.1.0") else {
            panic!("expected valid versioned User-Agent product");
        };

        assert_eq!(user_agent.to_string(), "LiveAISIP/0.1.0");

        let Some(product) = user_agent.first().as_product() else {
            panic!("expected product component");
        };

        assert_eq!(product.name(), "LiveAISIP");
        assert_eq!(product.version(), Some("0.1.0"));
    }

    #[test]
    fn parses_through_shared_grammar() {
        let Ok(user_agent) = parse(b"ClientA/1.0 (comment) ClientB") else {
            panic!("expected valid User-Agent field value");
        };

        assert_eq!(user_agent.component_count(), 3);
        assert_eq!(user_agent.to_string(), "ClientA/1.0 (comment) ClientB");

        assert_eq!(
            user_agent.components()[0]
                .as_product()
                .map(UserAgentProduct::name),
            Some("ClientA")
        );

        assert_eq!(
            user_agent.components()[1]
                .as_comment()
                .map(UserAgentComment::as_str),
            Some("comment")
        );

        assert_eq!(
            user_agent.components()[2]
                .as_product()
                .map(UserAgentProduct::name),
            Some("ClientB")
        );
    }

    #[test]
    fn nested_comment_uses_shared_canonicalization() {
        let Ok(user_agent) = parse(b"Client/1.0 (outer (nested) value)") else {
            panic!("expected nested User-Agent comment");
        };

        assert_eq!(
            user_agent.to_string(),
            "Client/1.0 (outer \\(nested\\) value)"
        );

        assert_eq!(user_agent.serialized_len(), user_agent.to_string().len());
    }

    #[test]
    fn utf8_comment_uses_shared_parser() {
        let input = "LiveAISIP (Riyadh الرياض)";

        let Ok(user_agent) = parse(input.as_bytes()) else {
            panic!("expected UTF-8 User-Agent comment");
        };

        assert_eq!(
            user_agent.components()[1]
                .as_comment()
                .map(UserAgentComment::as_str),
            Some("Riyadh الرياض")
        );
    }

    #[test]
    fn component_alias_exposes_shared_product_constructor() {
        let Ok(component) = UserAgentComponent::product_with_version("Client", "2.0") else {
            panic!("expected User-Agent product component");
        };

        assert_eq!(component.to_string(), "Client/2.0");
    }

    #[test]
    fn component_alias_exposes_shared_comment_constructor() {
        let Ok(component) = UserAgentComponent::comment("RiyadhAI LLC") else {
            panic!("expected User-Agent comment component");
        };

        assert_eq!(component.to_string(), "(RiyadhAI LLC)");
    }

    #[test]
    fn user_agent_product_alias_exposes_shared_api() {
        let Ok(product) = UserAgentProduct::with_version("Client", "1.0") else {
            panic!("expected User-Agent product");
        };

        assert_eq!(product.name(), "Client");
        assert_eq!(product.version(), Some("1.0"));
        assert!(product.has_version());
    }

    #[test]
    fn user_agent_comment_alias_exposes_shared_api() {
        let Ok(comment) = UserAgentComment::new("A (B) \\ C") else {
            panic!("expected User-Agent comment");
        };

        assert_eq!(comment.as_str(), "A (B) \\ C");
        assert_eq!(comment.to_string(), "(A \\(B\\) \\\\ C)");
    }

    #[test]
    fn new_accepts_validated_component() {
        let Ok(component) = UserAgentComponent::product("Client") else {
            panic!("expected product component");
        };

        let user_agent = UserAgent::new(component);

        assert_eq!(user_agent.to_string(), "Client");
        assert_eq!(user_agent.component_count(), 1);
    }

    #[test]
    fn from_components_preserves_order() {
        let Ok(first) = UserAgentComponent::product_with_version("A", "1") else {
            panic!("expected first product");
        };

        let Ok(comment) = UserAgentComponent::comment("middle") else {
            panic!("expected comment");
        };

        let Ok(last) = UserAgentComponent::product("B") else {
            panic!("expected last product");
        };

        let Ok(user_agent) = UserAgent::from_components(vec![first, comment, last]) else {
            panic!("expected User-Agent value");
        };

        assert_eq!(user_agent.to_string(), "A/1 (middle) B");
        assert_eq!(user_agent.component_count(), 3);
    }

    #[test]
    fn from_components_rejects_empty_vector() {
        assert_eq!(
            UserAgent::from_components(Vec::new()),
            Err(ParseError::Empty)
        );
    }

    #[test]
    fn push_delegates_to_shared_bounded_value() {
        let Ok(mut user_agent) = UserAgent::product("A") else {
            panic!("expected initial User-Agent value");
        };

        let Ok(component) = UserAgentComponent::product_with_version("B", "2") else {
            panic!("expected second product");
        };

        assert!(user_agent.push(component).is_ok());
        assert_eq!(user_agent.to_string(), "A B/2");
        assert_eq!(user_agent.component_count(), 2);
    }

    #[test]
    fn push_remains_transactional_at_component_limit() {
        let mut components = Vec::new();

        for index in 0..MAX_USER_AGENT_COMPONENTS {
            let name = format!("p{index}");

            let Ok(component) = UserAgentComponent::product(name) else {
                panic!("expected valid product component");
            };

            components.push(component);
        }

        let Ok(mut user_agent) = UserAgent::from_components(components) else {
            panic!("expected User-Agent at component limit");
        };

        let before = user_agent.to_string();

        let Ok(extra) = UserAgentComponent::product("extra") else {
            panic!("expected extra component");
        };

        assert_eq!(
            user_agent.push(extra),
            Err(ParseError::TooManyComponents {
                maximum: MAX_USER_AGENT_COMPONENTS,
            })
        );

        assert_eq!(user_agent.component_count(), MAX_USER_AGENT_COMPONENTS);

        assert_eq!(user_agent.to_string(), before);
    }

    #[test]
    fn parser_rejects_shared_syntax_error() {
        assert_eq!(parse(b"Client/"), Err(ParseError::MissingProductVersion));
    }

    #[test]
    fn parser_rejects_shared_line_break_error() {
        assert_eq!(
            parse(b"Client/1\r\n Client/2"),
            Err(ParseError::InvalidLineBreak)
        );
    }

    #[test]
    fn parser_rejects_shared_field_size_limit() {
        let input = vec![b'a'; MAX_USER_AGENT_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_USER_AGENT_BYTES + 1,
                maximum: MAX_USER_AGENT_BYTES,
            })
        );
    }

    #[test]
    fn parses_from_bytes_method() {
        let Ok(user_agent) = UserAgent::from_bytes(b"A/1 (test)") else {
            panic!("expected User-Agent from bytes");
        };

        assert_eq!(user_agent.to_string(), "A/1 (test)");
    }

    #[test]
    fn parses_from_str() {
        let Ok(user_agent) = UserAgent::from_str("A/1 (test) B") else {
            panic!("expected User-Agent from string");
        };

        assert_eq!(user_agent.to_string(), "A/1 (test) B");
    }

    #[test]
    fn serialized_length_matches_canonical_output() {
        let Ok(user_agent) = parse(b"A/1 (outer (nested)) B/2") else {
            panic!("expected User-Agent value");
        };

        assert_eq!(user_agent.serialized_len(), user_agent.to_string().len());
    }

    #[test]
    fn production_default_serialized_length_matches_output() {
        let user_agent = UserAgent::default();

        assert_eq!(user_agent.serialized_len(), user_agent.to_string().len());

        assert_eq!(
            user_agent.serialized_len(),
            DEFAULT_USER_AGENT_PRODUCT.len()
        );
    }

    #[test]
    fn into_components_preserves_components() {
        let Ok(user_agent) = parse(b"A/1 (test) B/2") else {
            panic!("expected User-Agent value");
        };

        let components = user_agent.into_components();

        assert_eq!(components.len(), 3);

        assert_eq!(
            components[0].as_product().map(UserAgentProduct::name),
            Some("A")
        );

        assert_eq!(
            components[1].as_comment().map(UserAgentComment::as_str),
            Some("test")
        );

        assert_eq!(
            components[2].as_product().map(UserAgentProduct::name),
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
