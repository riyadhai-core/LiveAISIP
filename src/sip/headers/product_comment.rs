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

//! Shared SIP product/comment field-value grammar.
//!
//! SIP `Server` and `User-Agent` use the same product/comment value grammar.
//! This module provides one implementation of that grammar so parsing,
//! validation, escaping, canonical serialization, size accounting, and
//! resource limits cannot silently diverge between those headers.
//!
//! Header-specific semantics and emission policy intentionally remain outside
//! this module.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;

/// Maximum accepted shared product/comment field-value size in bytes.
pub(crate) const MAX_VALUE_BYTES: usize = 8 * 1024;

/// Maximum number of product/comment components accepted in one field value.
pub(crate) const MAX_COMPONENTS: usize = 64;

/// Maximum accepted product-name size in bytes.
pub(crate) const MAX_PRODUCT_NAME_BYTES: usize = 256;

/// Maximum accepted product-version size in bytes.
pub(crate) const MAX_PRODUCT_VERSION_BYTES: usize = 256;

/// Maximum accepted logical comment size in bytes.
pub(crate) const MAX_COMMENT_BYTES: usize = 2 * 1024;

/// Maximum accepted nested comment depth, including the outermost comment.
pub(crate) const MAX_COMMENT_NESTING: usize = 16;

// A single validated product component can never exceed the complete field
// bound under the limits above.
const _: () = assert!(MAX_PRODUCT_NAME_BYTES + 1 + MAX_PRODUCT_VERSION_BYTES <= MAX_VALUE_BYTES);

// A comment containing only escapable one-byte characters represents the
// largest possible canonical serialization for a logical comment.
const _: () = assert!(2 + (MAX_COMMENT_BYTES * 2) <= MAX_VALUE_BYTES);

/// One validated component of the shared SIP product/comment grammar.
///
/// This type is re-exported under header-specific names by the `Server` and
/// `User-Agent` modules.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Component {
    /// Product token with an optional product-version token.
    Product(Product),

    /// Parenthesized comment.
    Comment(Comment),
}

impl Component {
    /// Creates a product component without a version.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the product name is empty, violates SIP
    /// token syntax, or exceeds its operational size bound.
    pub fn product(name: impl Into<Box<str>>) -> Result<Self, ParseError> {
        Ok(Self::Product(Product::new(name)?))
    }

    /// Creates a product component with a version.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the product name or version is empty,
    /// violates SIP token syntax, or exceeds an operational size bound.
    pub fn product_with_version(
        name: impl Into<Box<str>>,
        version: impl Into<Box<str>>,
    ) -> Result<Self, ParseError> {
        Ok(Self::Product(Product::with_version(name, version)?))
    }

    /// Creates a comment component from logical comment text.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the comment contains unsupported control
    /// characters or exceeds its operational size bound.
    pub fn comment(text: impl Into<Box<str>>) -> Result<Self, ParseError> {
        Ok(Self::Comment(Comment::new(text)?))
    }

    /// Returns this component as a product when applicable.
    #[must_use]
    pub const fn as_product(&self) -> Option<&Product> {
        match self {
            Self::Product(product) => Some(product),
            Self::Comment(_) => None,
        }
    }

    /// Returns this component as a comment when applicable.
    #[must_use]
    pub const fn as_comment(&self) -> Option<&Comment> {
        match self {
            Self::Product(_) => None,
            Self::Comment(comment) => Some(comment),
        }
    }

    /// Returns the canonical serialized component length in bytes.
    #[must_use]
    pub(crate) fn serialized_len(&self) -> usize {
        match self {
            Self::Product(product) => product.serialized_len(),
            Self::Comment(comment) => comment.serialized_len(),
        }
    }
}

impl fmt::Display for Component {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Product(product) => fmt::Display::fmt(product, formatter),
            Self::Comment(comment) => fmt::Display::fmt(comment, formatter),
        }
    }
}

/// A validated product in the shared SIP product/comment grammar.
///
/// Product names and optional product versions both use SIP token syntax.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Product {
    name: Box<str>,
    version: Option<Box<str>>,
}

impl Product {
    /// Creates a product without a version.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidProductName`] when `name` is empty or
    /// violates SIP token syntax, or [`ParseError::ProductNameTooLong`] when
    /// the operational size bound is exceeded.
    pub fn new(name: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let name = name.into();
        validate_product_name(name.as_bytes())?;

        Ok(Self {
            name,
            version: None,
        })
    }

    /// Creates a product with a version.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or version is empty, violates SIP
    /// token syntax, or exceeds an operational size bound.
    pub fn with_version(
        name: impl Into<Box<str>>,
        version: impl Into<Box<str>>,
    ) -> Result<Self, ParseError> {
        let name = name.into();
        let version = version.into();

        validate_product_name(name.as_bytes())?;
        validate_product_version(version.as_bytes())?;

        Ok(Self {
            name,
            version: Some(version),
        })
    }

    /// Returns the product name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional product version.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Returns whether a product version is present.
    #[must_use]
    pub const fn has_version(&self) -> bool {
        self.version.is_some()
    }

    /// Consumes the product into its name and optional version.
    #[must_use]
    pub fn into_parts(self) -> (Box<str>, Option<Box<str>>) {
        (self.name, self.version)
    }

    /// Creates a product from a source-controlled static token.
    ///
    /// This is restricted to crate-internal header policy code. Callers must
    /// provide a token that is known at development time to satisfy the same
    /// invariants enforced by [`Product::new`].
    #[must_use]
    pub(crate) fn from_known_token(name: &'static str) -> Self {
        debug_assert!(is_valid_product_name(name.as_bytes()));

        Self {
            name: Box::from(name),
            version: None,
        }
    }

    fn serialized_len(&self) -> usize {
        self.name.len() + self.version.as_ref().map_or(0, |version| 1 + version.len())
    }
}

impl fmt::Display for Product {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)?;

        if let Some(version) = &self.version {
            formatter.write_char('/')?;
            formatter.write_str(version)?;
        }

        Ok(())
    }
}

/// A validated logical comment in the shared SIP product/comment grammar.
///
/// Stored text excludes the surrounding parentheses and has quoted-pair
/// escapes decoded. Literal parentheses and backslashes are escaped during
/// canonical serialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Comment {
    text: Box<str>,
}

impl Comment {
    /// Creates a comment from logical text.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::CommentTooLong`] when the logical text exceeds
    /// the operational bound or [`ParseError::InvalidCommentByte`] when it
    /// contains an unsupported control character.
    pub fn new(text: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let text = text.into();
        validate_comment_text(&text)?;

        Ok(Self { text })
    }

    /// Returns the logical comment text without surrounding parentheses.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Consumes the comment into its logical text.
    #[must_use]
    pub fn into_inner(self) -> Box<str> {
        self.text
    }

    /// Returns the canonical serialized comment length in bytes.
    #[must_use]
    pub(crate) fn serialized_len(&self) -> usize {
        let escapes = self
            .text
            .as_bytes()
            .iter()
            .filter(|byte| matches!(**byte, b'(' | b')' | b'\\'))
            .count();

        2_usize
            .saturating_add(self.text.len())
            .saturating_add(escapes)
    }
}

impl fmt::Display for Comment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_char('(')?;

        for character in self.text.chars() {
            match character {
                '(' => formatter.write_str("\\(")?,
                ')' => formatter.write_str("\\)")?,
                '\\' => formatter.write_str("\\\\")?,
                _ => formatter.write_char(character)?,
            }
        }

        formatter.write_char(')')
    }
}

/// Internal validated value containing one or more shared components.
///
/// `Server` and `User-Agent` wrap this type rather than implementing the
/// product/comment grammar independently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Value {
    components: Vec<Component>,
    serialized_len: usize,
}

impl Value {
    /// Creates a value containing one validated component.
    #[must_use]
    pub(crate) fn new(component: Component) -> Self {
        let serialized_len = component.serialized_len();

        debug_assert!(serialized_len <= MAX_VALUE_BYTES);

        Self {
            components: vec![component],
            serialized_len,
        }
    }

    /// Creates a value containing a known source-controlled product token.
    #[must_use]
    pub(crate) fn from_known_product(name: &'static str) -> Self {
        Self::new(Component::Product(Product::from_known_token(name)))
    }

    /// Creates a value from an ordered component vector.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Empty`] when no components are supplied,
    /// [`ParseError::TooManyComponents`] when the component-count bound is
    /// exceeded, or [`ParseError::TooLong`] when canonical serialization
    /// exceeds the complete field-value bound.
    pub(crate) fn from_components(components: Vec<Component>) -> Result<Self, ParseError> {
        if components.is_empty() {
            return Err(ParseError::Empty);
        }

        if components.len() > MAX_COMPONENTS {
            return Err(ParseError::TooManyComponents {
                maximum: MAX_COMPONENTS,
            });
        }

        let mut components = components.into_iter();

        let Some(first) = components.next() else {
            return Err(ParseError::Empty);
        };

        let mut value = Self::new(first);

        for component in components {
            value.push(component)?;
        }

        Ok(value)
    }

    /// Parses one complete shared product/comment field value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when syntax is invalid or an operational bound
    /// is exceeded.
    pub(crate) fn parse(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns all components in wire order.
    #[must_use]
    pub(crate) fn components(&self) -> &[Component] {
        &self.components
    }

    /// Returns the first component.
    ///
    /// A successfully constructed value is always non-empty.
    #[must_use]
    pub(crate) fn first(&self) -> &Component {
        &self.components[0]
    }

    /// Returns the number of components.
    #[must_use]
    pub(crate) fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Returns the canonical serialized field-value length in bytes.
    #[must_use]
    pub(crate) const fn serialized_len(&self) -> usize {
        self.serialized_len
    }

    /// Appends one validated component.
    ///
    /// The mutation is transactional.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyComponents`] when the component-count
    /// bound has been reached or [`ParseError::TooLong`] when the resulting
    /// canonical value would exceed the field-value size bound.
    pub(crate) fn push(&mut self, component: Component) -> Result<(), ParseError> {
        if self.components.len() >= MAX_COMPONENTS {
            return Err(ParseError::TooManyComponents {
                maximum: MAX_COMPONENTS,
            });
        }

        let length = self
            .serialized_len
            .saturating_add(1)
            .saturating_add(component.serialized_len());

        if length > MAX_VALUE_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_VALUE_BYTES,
            });
        }

        self.components.push(component);
        self.serialized_len = length;

        Ok(())
    }

    /// Consumes the value into its ordered components.
    #[must_use]
    pub(crate) fn into_components(self) -> Vec<Component> {
        self.components
    }
}

impl fmt::Display for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, component) in self.components.iter().enumerate() {
            if index != 0 {
                formatter.write_char(' ')?;
            }

            fmt::Display::fmt(component, formatter)?;
        }

        Ok(())
    }
}

/// Parses one complete shared SIP product/comment field value.
///
/// Leading and trailing spaces and horizontal tabs are accepted. Components
/// inside the value must be separated by at least one space or horizontal
/// tab.
///
/// # Errors
///
/// Returns [`ParseError`] when syntax is invalid or an operational bound is
/// exceeded.
pub(crate) fn parse(input: &[u8]) -> Result<Value, ParseError> {
    if input.len() > MAX_VALUE_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_VALUE_BYTES,
        });
    }

    if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ParseError::InvalidLineBreak);
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut offset = 0_usize;
    let mut components = Vec::with_capacity(4);

    loop {
        if components.len() >= MAX_COMPONENTS {
            return Err(ParseError::TooManyComponents {
                maximum: MAX_COMPONENTS,
            });
        }

        let (component, consumed) = parse_component(&input[offset..], offset)?;
        components.push(component);
        offset += consumed;

        if offset == input.len() {
            break;
        }

        if !is_lws(input[offset]) {
            return Err(ParseError::MissingComponentWhitespace {
                index: offset,
                byte: input[offset],
            });
        }

        while offset < input.len() && is_lws(input[offset]) {
            offset += 1;
        }

        if offset == input.len() {
            break;
        }
    }

    Value::from_components(components)
}

fn parse_component(input: &[u8], absolute_offset: usize) -> Result<(Component, usize), ParseError> {
    let Some(first) = input.first().copied() else {
        return Err(ParseError::Empty);
    };

    if first == b'(' {
        let (comment, consumed) = parse_comment(input, absolute_offset)?;
        return Ok((Component::Comment(comment), consumed));
    }

    let (product, consumed) = parse_product(input, absolute_offset)?;
    Ok((Component::Product(product), consumed))
}

fn parse_product(input: &[u8], absolute_offset: usize) -> Result<(Product, usize), ParseError> {
    let name_length = input
        .iter()
        .take_while(|byte| is_token_byte(**byte))
        .count();

    if name_length == 0 {
        return Err(ParseError::InvalidComponentStart {
            index: absolute_offset,
            byte: input[0],
        });
    }

    if name_length > MAX_PRODUCT_NAME_BYTES {
        return Err(ParseError::ProductNameTooLong {
            length: name_length,
            maximum: MAX_PRODUCT_NAME_BYTES,
        });
    }

    let name =
        std::str::from_utf8(&input[..name_length]).map_err(|_| ParseError::InvalidProductName)?;

    let Some(next) = input.get(name_length).copied() else {
        return Ok((Product::new(name)?, name_length));
    };

    if next != b'/' {
        return Ok((Product::new(name)?, name_length));
    }

    let version_start = name_length + 1;

    if version_start >= input.len() {
        return Err(ParseError::MissingProductVersion);
    }

    let version_length = input[version_start..]
        .iter()
        .take_while(|byte| is_token_byte(**byte))
        .count();

    if version_length == 0 {
        return Err(ParseError::MissingProductVersion);
    }

    if version_length > MAX_PRODUCT_VERSION_BYTES {
        return Err(ParseError::ProductVersionTooLong {
            length: version_length,
            maximum: MAX_PRODUCT_VERSION_BYTES,
        });
    }

    let version_end = version_start + version_length;

    let version = std::str::from_utf8(&input[version_start..version_end])
        .map_err(|_| ParseError::InvalidProductVersion)?;

    Ok((Product::with_version(name, version)?, version_end))
}

fn parse_comment(input: &[u8], absolute_offset: usize) -> Result<(Comment, usize), ParseError> {
    if input.first() != Some(&b'(') {
        return Err(ParseError::InvalidComponentStart {
            index: absolute_offset,
            byte: input.first().copied().unwrap_or_default(),
        });
    }

    let mut decoded = Vec::with_capacity(input.len().min(MAX_COMMENT_BYTES));
    let mut depth = 1_usize;
    let mut index = 1_usize;

    while index < input.len() {
        let byte = input[index];

        match byte {
            b'\\' => {
                let Some(escaped) = input.get(index + 1).copied() else {
                    return Err(ParseError::UnterminatedQuotedPair);
                };

                if is_invalid_comment_control(escaped) {
                    return Err(ParseError::InvalidCommentByte {
                        index: absolute_offset + index + 1,
                        byte: escaped,
                    });
                }

                push_comment_byte(&mut decoded, escaped)?;
                index += 2;
            }
            b'(' => {
                if depth >= MAX_COMMENT_NESTING {
                    return Err(ParseError::CommentNestingTooDeep {
                        maximum: MAX_COMMENT_NESTING,
                    });
                }

                depth += 1;
                push_comment_byte(&mut decoded, b'(')?;
                index += 1;
            }
            b')' => {
                depth -= 1;

                if depth == 0 {
                    let text =
                        String::from_utf8(decoded).map_err(|_| ParseError::InvalidCommentUtf8)?;

                    return Ok((Comment::new(text)?, index + 1));
                }

                push_comment_byte(&mut decoded, b')')?;
                index += 1;
            }
            byte if is_invalid_comment_control(byte) => {
                return Err(ParseError::InvalidCommentByte {
                    index: absolute_offset + index,
                    byte,
                });
            }
            _ => {
                push_comment_byte(&mut decoded, byte)?;
                index += 1;
            }
        }
    }

    Err(ParseError::UnterminatedComment)
}

fn push_comment_byte(decoded: &mut Vec<u8>, byte: u8) -> Result<(), ParseError> {
    let length = decoded.len().saturating_add(1);

    if length > MAX_COMMENT_BYTES {
        return Err(ParseError::CommentTooLong {
            length,
            maximum: MAX_COMMENT_BYTES,
        });
    }

    decoded.push(byte);
    Ok(())
}

fn validate_product_name(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::InvalidProductName);
    }

    if input.len() > MAX_PRODUCT_NAME_BYTES {
        return Err(ParseError::ProductNameTooLong {
            length: input.len(),
            maximum: MAX_PRODUCT_NAME_BYTES,
        });
    }

    if !input.iter().copied().all(is_token_byte) {
        return Err(ParseError::InvalidProductName);
    }

    Ok(())
}

fn validate_product_version(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingProductVersion);
    }

    if input.len() > MAX_PRODUCT_VERSION_BYTES {
        return Err(ParseError::ProductVersionTooLong {
            length: input.len(),
            maximum: MAX_PRODUCT_VERSION_BYTES,
        });
    }

    if !input.iter().copied().all(is_token_byte) {
        return Err(ParseError::InvalidProductVersion);
    }

    Ok(())
}

fn validate_comment_text(text: &str) -> Result<(), ParseError> {
    if text.len() > MAX_COMMENT_BYTES {
        return Err(ParseError::CommentTooLong {
            length: text.len(),
            maximum: MAX_COMMENT_BYTES,
        });
    }

    if let Some((index, byte)) = text
        .as_bytes()
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| is_invalid_comment_control(*byte))
    {
        return Err(ParseError::InvalidCommentByte { index, byte });
    }

    Ok(())
}

fn is_valid_product_name(input: &[u8]) -> bool {
    !input.is_empty()
        && input.len() <= MAX_PRODUCT_NAME_BYTES
        && input.iter().copied().all(is_token_byte)
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

const fn is_invalid_comment_control(byte: u8) -> bool {
    byte != b'\t' && byte.is_ascii_control()
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

/// Failure to parse or construct the shared SIP product/comment grammar.
///
/// `Server` and `User-Agent` re-export this error under their respective
/// header modules so both headers use exactly the same syntax and validation
/// failure model.
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

    /// The field exceeded the bounded component count.
    TooManyComponents {
        /// Maximum accepted component count.
        maximum: usize,
    },

    /// A component began with an invalid byte.
    InvalidComponentStart {
        /// Absolute offset within the trimmed field value.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// Adjacent components were not separated by horizontal whitespace.
    MissingComponentWhitespace {
        /// Absolute offset within the trimmed field value.
        index: usize,

        /// Unexpected byte.
        byte: u8,
    },

    /// A product name was invalid.
    InvalidProductName,

    /// A product name exceeded its operational size limit.
    ProductNameTooLong {
        /// Actual product-name length in bytes.
        length: usize,

        /// Maximum accepted product-name length in bytes.
        maximum: usize,
    },

    /// A slash was present without a valid product-version token.
    MissingProductVersion,

    /// A product version was invalid.
    InvalidProductVersion,

    /// A product version exceeded its operational size limit.
    ProductVersionTooLong {
        /// Actual product-version length in bytes.
        length: usize,

        /// Maximum accepted product-version length in bytes.
        maximum: usize,
    },

    /// A comment did not contain its final closing parenthesis.
    UnterminatedComment,

    /// A comment ended immediately after an escape character.
    UnterminatedQuotedPair,

    /// A comment contained an unsupported control byte.
    InvalidCommentByte {
        /// Byte offset.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A decoded comment was not valid UTF-8.
    InvalidCommentUtf8,

    /// A logical comment exceeded its operational size limit.
    CommentTooLong {
        /// Actual logical comment length in bytes.
        length: usize,

        /// Maximum accepted logical comment length in bytes.
        maximum: usize,
    },

    /// Nested comments exceeded the configured nesting-depth bound.
    CommentNestingTooDeep {
        /// Maximum accepted nesting depth.
        maximum: usize,
    },
}

impl ParseError {
    /// Returns a stable low-cardinality classification suitable for metrics
    /// and structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong { .. } => "too-long",
            Self::InvalidLineBreak => "invalid-line-break",
            Self::TooManyComponents { .. } => "too-many-components",
            Self::InvalidComponentStart { .. } => "invalid-component-start",
            Self::MissingComponentWhitespace { .. } => "missing-component-whitespace",
            Self::InvalidProductName => "invalid-product-name",
            Self::ProductNameTooLong { .. } => "product-name-too-long",
            Self::MissingProductVersion => "missing-product-version",
            Self::InvalidProductVersion => "invalid-product-version",
            Self::ProductVersionTooLong { .. } => "product-version-too-long",
            Self::UnterminatedComment => "unterminated-comment",
            Self::UnterminatedQuotedPair => "unterminated-quoted-pair",
            Self::InvalidCommentByte { .. } => "invalid-comment-byte",
            Self::InvalidCommentUtf8 => "invalid-comment-utf8",
            Self::CommentTooLong { .. } => "comment-too-long",
            Self::CommentNestingTooDeep { .. } => "comment-nesting-too-deep",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP product/comment field value is empty"),
            Self::TooLong { length, maximum } => write!(
                formatter,
                "SIP product/comment field-value length {length} exceeds maximum {maximum}"
            ),
            Self::InvalidLineBreak => {
                formatter.write_str("SIP product/comment field contains an invalid line break")
            }
            Self::TooManyComponents { maximum } => write!(
                formatter,
                "SIP product/comment field contains more than {maximum} components"
            ),
            Self::InvalidComponentStart { index, byte } => write!(
                formatter,
                "invalid SIP product/comment component byte 0x{byte:02x} at offset {index}"
            ),
            Self::MissingComponentWhitespace { index, byte } => write!(
                formatter,
                "SIP product/comment component at offset {index} is not separated before byte \
                 0x{byte:02x}"
            ),
            Self::InvalidProductName => formatter.write_str("SIP product name is invalid"),
            Self::ProductNameTooLong { length, maximum } => write!(
                formatter,
                "SIP product-name length {length} exceeds maximum {maximum}"
            ),
            Self::MissingProductVersion => formatter.write_str("SIP product version is missing"),
            Self::InvalidProductVersion => formatter.write_str("SIP product version is invalid"),
            Self::ProductVersionTooLong { length, maximum } => write!(
                formatter,
                "SIP product-version length {length} exceeds maximum {maximum}"
            ),
            Self::UnterminatedComment => {
                formatter.write_str("SIP product/comment comment is unterminated")
            }
            Self::UnterminatedQuotedPair => {
                formatter.write_str("SIP product/comment quoted-pair is unterminated")
            }
            Self::InvalidCommentByte { index, byte } => write!(
                formatter,
                "invalid SIP comment byte 0x{byte:02x} at offset {index}"
            ),
            Self::InvalidCommentUtf8 => formatter.write_str("SIP comment is not valid UTF-8"),
            Self::CommentTooLong { length, maximum } => write!(
                formatter,
                "SIP comment length {length} exceeds maximum {maximum}"
            ),
            Self::CommentNestingTooDeep { maximum } => write!(
                formatter,
                "SIP comment nesting exceeds maximum depth {maximum}"
            ),
        }
    }
}

impl StdError for ParseError {}

#[cfg(test)]
mod tests {
    use super::{
        Comment, Component, MAX_COMMENT_BYTES, MAX_COMMENT_NESTING, MAX_COMPONENTS,
        MAX_PRODUCT_NAME_BYTES, MAX_PRODUCT_VERSION_BYTES, MAX_VALUE_BYTES, ParseError, Product,
        Value, parse,
    };

    #[test]
    fn parses_product_without_version() {
        let Ok(value) = parse(b"LiveAISIP") else {
            panic!("expected valid product");
        };

        let Some(product) = value.first().as_product() else {
            panic!("expected product component");
        };

        assert_eq!(product.name(), "LiveAISIP");
        assert_eq!(product.version(), None);
        assert!(!product.has_version());
    }

    #[test]
    fn parses_product_with_version() {
        let Ok(value) = parse(b"LiveAISIP/0.1.0") else {
            panic!("expected versioned product");
        };

        let Some(product) = value.first().as_product() else {
            panic!("expected product component");
        };

        assert_eq!(product.name(), "LiveAISIP");
        assert_eq!(product.version(), Some("0.1.0"));
        assert!(product.has_version());
    }

    #[test]
    fn parses_multiple_products_and_comments() {
        let Ok(value) = parse(b"ProductA/1.0 (comment) ProductB ProductC/3.0") else {
            panic!("expected multiple components");
        };

        assert_eq!(value.component_count(), 4);

        assert_eq!(
            value.components()[0].as_product().map(Product::name),
            Some("ProductA")
        );

        assert_eq!(
            value.components()[1].as_comment().map(Comment::as_str),
            Some("comment")
        );

        assert_eq!(
            value.components()[2].as_product().map(Product::name),
            Some("ProductB")
        );

        assert_eq!(
            value.components()[3].as_product().map(Product::name),
            Some("ProductC")
        );
    }

    #[test]
    fn accepts_full_sip_token_character_set() {
        let token = "SIP-Core.2!%*_+`'~";

        let Ok(product) = Product::new(token) else {
            panic!("expected valid SIP product token");
        };

        assert_eq!(product.name(), token);
        assert_eq!(product.to_string(), token);
    }

    #[test]
    fn accepts_full_sip_token_character_set_in_version() {
        let version = "2.0!%*_+`'~-x";

        let Ok(product) = Product::with_version("Product", version) else {
            panic!("expected valid SIP product version");
        };

        assert_eq!(product.version(), Some(version));
        assert_eq!(product.to_string(), format!("Product/{version}"));
    }

    #[test]
    fn parses_empty_comment() {
        let Ok(value) = parse(b"()") else {
            panic!("expected empty comment");
        };

        assert_eq!(value.first().as_comment().map(Comment::as_str), Some(""));

        assert_eq!(value.to_string(), "()");
    }

    #[test]
    fn parses_simple_comment() {
        let Ok(value) = parse(b"(RiyadhAI LLC)") else {
            panic!("expected comment");
        };

        assert_eq!(
            value.first().as_comment().map(Comment::as_str),
            Some("RiyadhAI LLC")
        );
    }

    #[test]
    fn parses_nested_comments() {
        let Ok(value) = parse(b"(outer (middle (inner)) end)") else {
            panic!("expected nested comment");
        };

        assert_eq!(
            value.first().as_comment().map(Comment::as_str),
            Some("outer (middle (inner)) end")
        );
    }

    #[test]
    fn nested_comments_are_canonicalized_on_serialization() {
        let Ok(value) = parse(b"(outer (nested) end)") else {
            panic!("expected nested comment");
        };

        assert_eq!(value.to_string(), "(outer \\(nested\\) end)");
    }

    #[test]
    fn parses_escaped_parentheses() {
        let Ok(value) = parse(b"(one \\(two\\) three)") else {
            panic!("expected escaped parentheses");
        };

        assert_eq!(
            value.first().as_comment().map(Comment::as_str),
            Some("one (two) three")
        );

        assert_eq!(value.to_string(), "(one \\(two\\) three)");
    }

    #[test]
    fn parses_escaped_backslash() {
        let Ok(value) = parse(b"(path \\\\ node)") else {
            panic!("expected escaped backslash");
        };

        assert_eq!(
            value.first().as_comment().map(Comment::as_str),
            Some("path \\ node")
        );

        assert_eq!(value.to_string(), "(path \\\\ node)");
    }

    #[test]
    fn parses_utf8_comment() {
        let input = "LiveAISIP (Riyadh الرياض)";

        let Ok(value) = parse(input.as_bytes()) else {
            panic!("expected UTF-8 comment");
        };

        assert_eq!(
            value.components()[1].as_comment().map(Comment::as_str),
            Some("Riyadh الرياض")
        );
    }

    #[test]
    fn accepts_surrounding_horizontal_whitespace() {
        let Ok(value) = parse(b" \t LiveAISIP \t ") else {
            panic!("expected surrounding whitespace");
        };

        assert_eq!(value.to_string(), "LiveAISIP");
    }

    #[test]
    fn canonicalizes_inter_component_whitespace() {
        let Ok(value) = parse(b"A/1   \t B/2 \t (comment)") else {
            panic!("expected component whitespace");
        };

        assert_eq!(value.to_string(), "A/1 B/2 (comment)");
    }

    #[test]
    fn rejects_empty_value() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b" \t "), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_line_break() {
        assert_eq!(parse(b"A/1\r\n B/2"), Err(ParseError::InvalidLineBreak));
    }

    #[test]
    fn rejects_invalid_component_start() {
        assert_eq!(
            parse(b"@invalid"),
            Err(ParseError::InvalidComponentStart {
                index: 0,
                byte: b'@',
            })
        );
    }

    #[test]
    fn rejects_missing_product_version() {
        assert_eq!(parse(b"Product/"), Err(ParseError::MissingProductVersion));
    }

    #[test]
    fn rejects_whitespace_after_product_slash() {
        assert_eq!(parse(b"Product/ 1"), Err(ParseError::MissingProductVersion));
    }

    #[test]
    fn rejects_invalid_character_after_product() {
        assert_eq!(
            parse(b"Product@bad"),
            Err(ParseError::MissingComponentWhitespace {
                index: 7,
                byte: b'@',
            })
        );
    }

    #[test]
    fn requires_whitespace_between_product_and_comment() {
        assert_eq!(
            parse(b"Product/1(comment)"),
            Err(ParseError::MissingComponentWhitespace {
                index: 9,
                byte: b'(',
            })
        );
    }

    #[test]
    fn requires_whitespace_between_comments() {
        assert_eq!(
            parse(b"(one)(two)"),
            Err(ParseError::MissingComponentWhitespace {
                index: 5,
                byte: b'(',
            })
        );
    }

    #[test]
    fn rejects_unterminated_comment() {
        assert_eq!(parse(b"(unfinished"), Err(ParseError::UnterminatedComment));
    }

    #[test]
    fn rejects_unterminated_quoted_pair() {
        assert_eq!(
            parse(b"(unfinished\\"),
            Err(ParseError::UnterminatedQuotedPair)
        );
    }

    #[test]
    fn rejects_control_byte_in_comment() {
        assert_eq!(
            parse(b"(bad\x01comment)"),
            Err(ParseError::InvalidCommentByte {
                index: 4,
                byte: 0x01,
            })
        );
    }

    #[test]
    fn rejects_invalid_utf8_comment() {
        assert_eq!(
            parse(&[b'(', 0xff, b')']),
            Err(ParseError::InvalidCommentUtf8)
        );
    }

    #[test]
    fn product_constructor_rejects_empty_name() {
        assert_eq!(Product::new(""), Err(ParseError::InvalidProductName));
    }

    #[test]
    fn product_constructor_rejects_invalid_name() {
        assert_eq!(
            Product::new("bad product"),
            Err(ParseError::InvalidProductName)
        );
    }

    #[test]
    fn product_constructor_rejects_empty_version() {
        assert_eq!(
            Product::with_version("Product", ""),
            Err(ParseError::MissingProductVersion)
        );
    }

    #[test]
    fn product_constructor_rejects_invalid_version() {
        assert_eq!(
            Product::with_version("Product", "bad version"),
            Err(ParseError::InvalidProductVersion)
        );
    }

    #[test]
    fn product_into_parts_preserves_values() {
        let Ok(product) = Product::with_version("Product", "1.0") else {
            panic!("expected product");
        };

        let (name, version) = product.into_parts();

        assert_eq!(&*name, "Product");
        assert_eq!(version.as_deref(), Some("1.0"));
    }

    #[test]
    fn component_constructors_build_expected_variants() {
        let Ok(product) = Component::product("Product") else {
            panic!("expected product component");
        };

        assert!(product.as_product().is_some());
        assert!(product.as_comment().is_none());

        let Ok(comment) = Component::comment("comment") else {
            panic!("expected comment component");
        };

        assert!(comment.as_product().is_none());
        assert!(comment.as_comment().is_some());
    }

    #[test]
    fn comment_constructor_escapes_reserved_characters() {
        let Ok(comment) = Comment::new("A (B) \\ C") else {
            panic!("expected comment");
        };

        assert_eq!(comment.as_str(), "A (B) \\ C");
        assert_eq!(comment.to_string(), "(A \\(B\\) \\\\ C)");
    }

    #[test]
    fn comment_into_inner_preserves_logical_text() {
        let Ok(comment) = Comment::new("logical text") else {
            panic!("expected comment");
        };

        let text = comment.into_inner();

        assert_eq!(&*text, "logical text");
    }

    #[test]
    fn rejects_product_name_above_limit() {
        let name = "a".repeat(MAX_PRODUCT_NAME_BYTES + 1);

        assert_eq!(
            Product::new(name),
            Err(ParseError::ProductNameTooLong {
                length: MAX_PRODUCT_NAME_BYTES + 1,
                maximum: MAX_PRODUCT_NAME_BYTES,
            })
        );
    }

    #[test]
    fn rejects_product_version_above_limit() {
        let version = "1".repeat(MAX_PRODUCT_VERSION_BYTES + 1);

        assert_eq!(
            Product::with_version("Product", version),
            Err(ParseError::ProductVersionTooLong {
                length: MAX_PRODUCT_VERSION_BYTES + 1,
                maximum: MAX_PRODUCT_VERSION_BYTES,
            })
        );
    }

    #[test]
    fn rejects_comment_above_limit_from_constructor() {
        let comment = "a".repeat(MAX_COMMENT_BYTES + 1);

        assert_eq!(
            Comment::new(comment),
            Err(ParseError::CommentTooLong {
                length: MAX_COMMENT_BYTES + 1,
                maximum: MAX_COMMENT_BYTES,
            })
        );
    }

    #[test]
    fn rejects_comment_above_limit_during_parsing() {
        let input = format!("({})", "a".repeat(MAX_COMMENT_BYTES + 1));

        assert_eq!(
            parse(input.as_bytes()),
            Err(ParseError::CommentTooLong {
                length: MAX_COMMENT_BYTES + 1,
                maximum: MAX_COMMENT_BYTES,
            })
        );
    }

    #[test]
    fn accepts_comment_at_maximum_nesting_depth() {
        let opening = "(".repeat(MAX_COMMENT_NESTING);
        let closing = ")".repeat(MAX_COMMENT_NESTING);
        let input = format!("{opening}x{closing}");

        let Ok(value) = parse(input.as_bytes()) else {
            panic!("expected maximum supported nesting depth");
        };

        assert_eq!(value.component_count(), 1);
    }

    #[test]
    fn rejects_comment_above_maximum_nesting_depth() {
        let opening = "(".repeat(MAX_COMMENT_NESTING + 1);
        let closing = ")".repeat(MAX_COMMENT_NESTING + 1);
        let input = format!("{opening}x{closing}");

        assert_eq!(
            parse(input.as_bytes()),
            Err(ParseError::CommentNestingTooDeep {
                maximum: MAX_COMMENT_NESTING,
            })
        );
    }

    #[test]
    fn rejects_field_above_limit_before_parsing() {
        let input = vec![b'a'; MAX_VALUE_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_VALUE_BYTES + 1,
                maximum: MAX_VALUE_BYTES,
            })
        );
    }

    #[test]
    fn value_from_components_rejects_empty_vector() {
        assert_eq!(Value::from_components(Vec::new()), Err(ParseError::Empty));
    }

    #[test]
    fn value_preserves_component_order() {
        let Ok(first) = Component::product_with_version("A", "1") else {
            panic!("expected first product");
        };

        let Ok(comment) = Component::comment("middle") else {
            panic!("expected comment");
        };

        let Ok(last) = Component::product("B") else {
            panic!("expected last product");
        };

        let Ok(value) = Value::from_components(vec![first, comment, last]) else {
            panic!("expected shared value");
        };

        assert_eq!(value.to_string(), "A/1 (middle) B");
    }

    #[test]
    fn value_push_appends_component() {
        let Ok(first) = Component::product("A") else {
            panic!("expected first component");
        };

        let mut value = Value::new(first);

        let Ok(second) = Component::product_with_version("B", "2") else {
            panic!("expected second component");
        };

        assert!(value.push(second).is_ok());

        assert_eq!(value.to_string(), "A B/2");
        assert_eq!(value.component_count(), 2);
    }

    #[test]
    fn serialized_length_matches_output() {
        let Ok(value) = parse(b"LiveAISIP/0.1.0 (RiyadhAI LLC) SIP/2.0") else {
            panic!("expected shared value");
        };

        assert_eq!(value.serialized_len(), value.to_string().len());
    }

    #[test]
    fn canonical_comment_expansion_is_included_in_cached_length() {
        let Ok(value) = parse(b"(outer (nested) value)") else {
            panic!("expected nested comment");
        };

        assert_eq!(value.to_string(), "(outer \\(nested\\) value)");

        assert_eq!(value.serialized_len(), value.to_string().len());
    }

    #[test]
    fn push_is_transactional_when_field_limit_is_exceeded() {
        let name = "a".repeat(MAX_PRODUCT_NAME_BYTES);
        let version = "1".repeat(MAX_PRODUCT_VERSION_BYTES);

        let mut components = Vec::new();

        for _ in 0..15 {
            let Ok(component) = Component::product_with_version(name.clone(), version.clone())
            else {
                panic!("expected maximum-sized product");
            };

            components.push(component);
        }

        let Ok(mut value) = Value::from_components(components) else {
            panic!("expected shared value below field limit");
        };

        assert_eq!(value.serialized_len(), 7_709);

        let Ok(extra) = Component::product_with_version(name, version) else {
            panic!("expected additional product");
        };

        assert_eq!(
            value.push(extra),
            Err(ParseError::TooLong {
                length: 8_223,
                maximum: MAX_VALUE_BYTES,
            })
        );

        assert_eq!(value.serialized_len(), 7_709);
        assert_eq!(value.component_count(), 15);
    }

    #[test]
    fn enforces_component_count() {
        let mut components = Vec::new();

        for index in 0..MAX_COMPONENTS {
            let name = format!("p{index}");

            let Ok(component) = Component::product(name) else {
                panic!("expected product component");
            };

            components.push(component);
        }

        let Ok(mut value) = Value::from_components(components) else {
            panic!("expected value at component-count limit");
        };

        let Ok(extra) = Component::product("extra") else {
            panic!("expected extra component");
        };

        assert_eq!(
            value.push(extra),
            Err(ParseError::TooManyComponents {
                maximum: MAX_COMPONENTS,
            })
        );
    }

    #[test]
    fn from_components_rejects_too_many_components() {
        let mut components = Vec::new();

        for index in 0..=MAX_COMPONENTS {
            let name = format!("p{index}");

            let Ok(component) = Component::product(name) else {
                panic!("expected product component");
            };

            components.push(component);
        }

        assert_eq!(
            Value::from_components(components),
            Err(ParseError::TooManyComponents {
                maximum: MAX_COMPONENTS,
            })
        );
    }

    #[test]
    fn into_components_preserves_all_components() {
        let Ok(value) = parse(b"A/1 (test) B/2") else {
            panic!("expected shared value");
        };

        let components = value.into_components();

        assert_eq!(components.len(), 3);
    }

    #[test]
    fn known_product_constructor_preserves_invariants() {
        let value = Value::from_known_product("LiveAISIP");

        assert_eq!(value.to_string(), "LiveAISIP");
        assert_eq!(value.serialized_len(), "LiveAISIP".len());

        let Some(product) = value.first().as_product() else {
            panic!("expected known product");
        };

        assert_eq!(product.name(), "LiveAISIP");
        assert_eq!(product.version(), None);
    }

    #[test]
    fn value_parse_method_uses_shared_parser() {
        let Ok(value) = Value::parse(b"A/1 (test)") else {
            panic!("expected shared value");
        };

        assert_eq!(value.to_string(), "A/1 (test)");
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");

        assert_eq!(
            ParseError::TooLong {
                length: MAX_VALUE_BYTES + 1,
                maximum: MAX_VALUE_BYTES,
            }
            .class(),
            "too-long"
        );

        assert_eq!(ParseError::InvalidLineBreak.class(), "invalid-line-break");

        assert_eq!(
            ParseError::TooManyComponents {
                maximum: MAX_COMPONENTS,
            }
            .class(),
            "too-many-components"
        );

        assert_eq!(
            ParseError::InvalidComponentStart {
                index: 0,
                byte: b'@',
            }
            .class(),
            "invalid-component-start"
        );

        assert_eq!(
            ParseError::MissingComponentWhitespace {
                index: 1,
                byte: b'@',
            }
            .class(),
            "missing-component-whitespace"
        );

        assert_eq!(
            ParseError::InvalidProductName.class(),
            "invalid-product-name"
        );

        assert_eq!(
            ParseError::ProductNameTooLong {
                length: MAX_PRODUCT_NAME_BYTES + 1,
                maximum: MAX_PRODUCT_NAME_BYTES,
            }
            .class(),
            "product-name-too-long"
        );

        assert_eq!(
            ParseError::MissingProductVersion.class(),
            "missing-product-version"
        );

        assert_eq!(
            ParseError::InvalidProductVersion.class(),
            "invalid-product-version"
        );

        assert_eq!(
            ParseError::ProductVersionTooLong {
                length: MAX_PRODUCT_VERSION_BYTES + 1,
                maximum: MAX_PRODUCT_VERSION_BYTES,
            }
            .class(),
            "product-version-too-long"
        );

        assert_eq!(
            ParseError::UnterminatedComment.class(),
            "unterminated-comment"
        );

        assert_eq!(
            ParseError::UnterminatedQuotedPair.class(),
            "unterminated-quoted-pair"
        );

        assert_eq!(
            ParseError::InvalidCommentByte {
                index: 0,
                byte: 0x01,
            }
            .class(),
            "invalid-comment-byte"
        );

        assert_eq!(
            ParseError::InvalidCommentUtf8.class(),
            "invalid-comment-utf8"
        );

        assert_eq!(
            ParseError::CommentTooLong {
                length: MAX_COMMENT_BYTES + 1,
                maximum: MAX_COMMENT_BYTES,
            }
            .class(),
            "comment-too-long"
        );

        assert_eq!(
            ParseError::CommentNestingTooDeep {
                maximum: MAX_COMMENT_NESTING,
            }
            .class(),
            "comment-nesting-too-deep"
        );
    }
}
