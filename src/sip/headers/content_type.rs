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

//! SIP `Content-Type` header.
//!
//! This module provides strongly typed parsing and serialization for SIP
//! `Content-Type` field values.
//!
//! Media type and subtype identifiers are case-insensitive and serialize in
//! canonical lowercase form. The common `application/sdp` representation is
//! allocation-free.
//!
//! Media parameters are preserved in wire order. Parameter names are
//! case-insensitive and canonicalized to lowercase, while parameter values
//! preserve their logical case. Duplicate parameter names are rejected to
//! avoid ambiguous interpretation.
//!
//! Header unfolding belongs to the generic SIP message parser. This parser
//! accepts spaces and horizontal tabs as linear whitespace but never accepts
//! embedded CR or LF bytes.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

/// Maximum accepted SIP `Content-Type` field-value size in bytes.
///
/// This is a `LiveAISIP` operational limit rather than a SIP protocol limit.
pub const MAX_CONTENT_TYPE_BYTES: usize = 8 * 1024;

/// Maximum accepted media type or subtype token size in bytes.
pub const MAX_MEDIA_TOKEN_BYTES: usize = 256;

/// Maximum number of media parameters accepted in one `Content-Type` value.
pub const MAX_MEDIA_PARAMETERS: usize = 64;

/// Maximum accepted media parameter-name size in bytes.
pub const MAX_MEDIA_PARAMETER_NAME_BYTES: usize = 256;

/// Maximum accepted media parameter-value size in bytes.
pub const MAX_MEDIA_PARAMETER_VALUE_BYTES: usize = 4096;

/// A validated SIP `Content-Type` field value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentType {
    media_type: MediaType,
    parameters: Vec<MediaParameter>,
}

impl ContentType {
    /// Creates a `Content-Type` value without parameters.
    #[must_use]
    pub const fn new(media_type: MediaType) -> Self {
        Self {
            media_type,
            parameters: Vec::new(),
        }
    }

    /// Creates the common `application/sdp` Content-Type.
    #[must_use]
    pub const fn application_sdp() -> Self {
        Self::new(MediaType::application_sdp())
    }

    /// Parses a SIP `Content-Type` field value from wire bytes.
    ///
    /// Header-name and `HCOLON` parsing are outside this function.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the media type, subtype, parameters,
    /// quoting, or an operational bound is invalid.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns the media type.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }

    /// Returns all media parameters in wire order.
    #[must_use]
    pub fn parameters(&self) -> &[MediaParameter] {
        &self.parameters
    }

    /// Returns the first parameter with the requested case-insensitive name.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&MediaParameter> {
        self.parameters
            .iter()
            .find(|parameter| parameter.name().eq_ignore_ascii_case(name))
    }

    /// Returns the `charset` parameter value when present.
    #[must_use]
    pub fn charset(&self) -> Option<&str> {
        self.parameter("charset").map(MediaParameter::value)
    }

    /// Returns the `boundary` parameter value when present.
    #[must_use]
    pub fn boundary(&self) -> Option<&str> {
        self.parameter("boundary").map(MediaParameter::value)
    }

    /// Adds a media parameter.
    ///
    /// Parameter names are unique case-insensitively.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::DuplicateParameter`] when the name already
    /// exists or [`ParseError::TooManyParameters`] when the bounded parameter
    /// count has been reached.
    pub fn push_parameter(&mut self, parameter: MediaParameter) -> Result<(), ParseError> {
        if self.parameters.len() >= MAX_MEDIA_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_MEDIA_PARAMETERS,
            });
        }

        if self
            .parameters
            .iter()
            .any(|existing| existing.name().eq_ignore_ascii_case(parameter.name()))
        {
            return Err(ParseError::DuplicateParameter);
        }

        self.parameters.push(parameter);
        Ok(())
    }

    /// Returns the number of media parameters.
    #[must_use]
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Returns whether this value represents `application/sdp`.
    #[must_use]
    pub const fn is_application_sdp(&self) -> bool {
        self.media_type.is_application_sdp()
    }

    /// Consumes the value into its media type and ordered parameters.
    #[must_use]
    pub fn into_parts(self) -> (MediaType, Vec<MediaParameter>) {
        (self.media_type, self.parameters)
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.media_type)?;

        for parameter in &self.parameters {
            write!(formatter, ";{parameter}")?;
        }

        Ok(())
    }
}

impl FromStr for ContentType {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// A validated media type consisting of a top-level type and subtype.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaType {
    top_level: MediaTopLevel,
    subtype: MediaSubtype,
}

impl MediaType {
    /// Creates a media type from validated components.
    #[must_use]
    pub const fn new(top_level: MediaTopLevel, subtype: MediaSubtype) -> Self {
        Self { top_level, subtype }
    }

    /// Creates the common `application/sdp` media type.
    #[must_use]
    pub const fn application_sdp() -> Self {
        Self {
            top_level: MediaTopLevel::Application,
            subtype: MediaSubtype::Sdp,
        }
    }

    /// Creates a media type from textual components.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when either component is empty, oversized, or
    /// violates the SIP token grammar.
    pub fn from_components(top_level: &str, subtype: &str) -> Result<Self, ParseError> {
        Ok(Self {
            top_level: MediaTopLevel::from_bytes(top_level.as_bytes())?,
            subtype: MediaSubtype::from_bytes(subtype.as_bytes())?,
        })
    }

    /// Returns the top-level media type.
    #[must_use]
    pub const fn top_level(&self) -> &MediaTopLevel {
        &self.top_level
    }

    /// Returns the media subtype.
    #[must_use]
    pub const fn subtype(&self) -> &MediaSubtype {
        &self.subtype
    }

    /// Returns whether this is `application/sdp`.
    #[must_use]
    pub const fn is_application_sdp(&self) -> bool {
        matches!(self.top_level, MediaTopLevel::Application)
            && matches!(self.subtype, MediaSubtype::Sdp)
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.top_level, self.subtype)
    }
}

/// Top-level media type.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MediaTopLevel {
    /// `text`.
    Text,

    /// `image`.
    Image,

    /// `audio`.
    Audio,

    /// `video`.
    Video,

    /// `application`.
    Application,

    /// `message`.
    Message,

    /// `multipart`.
    Multipart,

    /// Valid extension top-level media type.
    Extension(Box<str>),
}

impl MediaTopLevel {
    /// Parses a top-level media type token.
    ///
    /// Standard top-level names are recognized case-insensitively and use
    /// allocation-free variants. Extension names are normalized to lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the token is empty, oversized, or invalid.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        validate_media_token(input, MediaTokenKind::TopLevel)?;

        if input.eq_ignore_ascii_case(b"text") {
            Ok(Self::Text)
        } else if input.eq_ignore_ascii_case(b"image") {
            Ok(Self::Image)
        } else if input.eq_ignore_ascii_case(b"audio") {
            Ok(Self::Audio)
        } else if input.eq_ignore_ascii_case(b"video") {
            Ok(Self::Video)
        } else if input.eq_ignore_ascii_case(b"application") {
            Ok(Self::Application)
        } else if input.eq_ignore_ascii_case(b"message") {
            Ok(Self::Message)
        } else if input.eq_ignore_ascii_case(b"multipart") {
            Ok(Self::Multipart)
        } else {
            Ok(Self::Extension(lowercase_token(input)?))
        }
    }

    /// Returns the canonical lowercase textual representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Application => "application",
            Self::Message => "message",
            Self::Multipart => "multipart",
            Self::Extension(value) => value,
        }
    }
}

impl fmt::Display for MediaTopLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Media subtype.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MediaSubtype {
    /// `sdp`.
    ///
    /// This subtype has a dedicated allocation-free representation because it
    /// is the primary media description type used by SIP telephony.
    Sdp,

    /// Valid registered or extension media subtype.
    Extension(Box<str>),
}

impl MediaSubtype {
    /// Parses a media subtype token.
    ///
    /// `sdp` is recognized case-insensitively and uses an allocation-free
    /// variant. Other valid values are normalized to lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the token is empty, oversized, or invalid.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        validate_media_token(input, MediaTokenKind::Subtype)?;

        if input.eq_ignore_ascii_case(b"sdp") {
            Ok(Self::Sdp)
        } else {
            Ok(Self::Extension(lowercase_token(input)?))
        }
    }

    /// Returns the canonical lowercase subtype.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sdp => "sdp",
            Self::Extension(value) => value,
        }
    }
}

impl fmt::Display for MediaSubtype {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A validated media parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaParameter {
    name: Box<str>,
    value: MediaParameterValue,
}

impl MediaParameter {
    /// Creates a token-valued media parameter.
    ///
    /// The parameter name is normalized to lowercase. The parameter value
    /// preserves its original case.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or value violates the SIP token
    /// grammar or an operational size limit.
    pub fn token(name: impl AsRef<str>, value: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let name = normalize_parameter_name(name.as_ref().as_bytes())?;
        let value = value.into();

        validate_token_parameter_value(value.as_bytes())?;

        Ok(Self {
            name,
            value: MediaParameterValue::Token(value),
        })
    }

    /// Creates a quoted media parameter.
    ///
    /// The supplied value is logical text without surrounding quotation marks.
    /// The parameter name is normalized to lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name or value is invalid or exceeds an
    /// operational size limit.
    pub fn quoted(name: impl AsRef<str>, value: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let name = normalize_parameter_name(name.as_ref().as_bytes())?;
        let value = value.into();

        validate_quoted_parameter_value(value.as_bytes())?;

        Ok(Self {
            name,
            value: MediaParameterValue::Quoted(value),
        })
    }

    /// Returns the canonical lowercase parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the logical parameter value.
    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_str()
    }

    /// Returns the typed parameter value.
    #[must_use]
    pub const fn typed_value(&self) -> &MediaParameterValue {
        &self.value
    }

    /// Returns whether the parameter uses quoted-string serialization.
    #[must_use]
    pub const fn is_quoted(&self) -> bool {
        self.value.is_quoted()
    }

    /// Consumes the parameter into its name and typed value.
    #[must_use]
    pub fn into_parts(self) -> (Box<str>, MediaParameterValue) {
        (self.name, self.value)
    }
}

impl fmt::Display for MediaParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}={}", self.name, self.value)
    }
}

/// Media parameter value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MediaParameterValue {
    /// SIP token value.
    Token(Box<str>),

    /// Logical quoted-string value.
    Quoted(Box<str>),
}

impl MediaParameterValue {
    /// Returns the logical parameter value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Token(value) | Self::Quoted(value) => value,
        }
    }

    /// Returns whether this value uses quoted-string serialization.
    #[must_use]
    pub const fn is_quoted(&self) -> bool {
        matches!(self, Self::Quoted(_))
    }
}

impl fmt::Display for MediaParameterValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(value) => formatter.write_str(value),
            Self::Quoted(value) => write_quoted(formatter, value),
        }
    }
}

/// Parses a SIP `Content-Type` field value.
///
/// # Errors
///
/// Returns [`ParseError`] when the field value violates media-type syntax or
/// an operational bound.
pub fn parse(input: &[u8]) -> Result<ContentType, ParseError> {
    if input.len() > MAX_CONTENT_TYPE_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_CONTENT_TYPE_BYTES,
        });
    }

    if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ParseError::InvalidLineBreak);
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    let (media_type, parameters) = parse_media_type(input)?;
    let mut content_type = ContentType::new(media_type);

    parse_parameters(&mut content_type, parameters)?;

    Ok(content_type)
}

fn parse_media_type(input: &[u8]) -> Result<(MediaType, &[u8]), ParseError> {
    let (top_level, remaining) = parse_top_level(input)?;
    let remaining = trim_lws_start(remaining);

    if remaining.is_empty() {
        return Err(ParseError::MissingSlash);
    }

    if remaining[0] != b'/' {
        return Err(ParseError::InvalidMediaTypeSeparator { byte: remaining[0] });
    }

    let remaining = trim_lws_start(&remaining[1..]);
    let (subtype, remaining) = parse_subtype(remaining)?;

    Ok((MediaType::new(top_level, subtype), remaining))
}

fn parse_top_level(input: &[u8]) -> Result<(MediaTopLevel, &[u8]), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingTopLevel);
    }

    let length = token_prefix_length(input);

    if length == 0 {
        return Err(ParseError::InvalidTopLevelByte {
            index: 0,
            byte: input[0],
        });
    }

    let value = MediaTopLevel::from_bytes(&input[..length])?;

    Ok((value, &input[length..]))
}

fn parse_subtype(input: &[u8]) -> Result<(MediaSubtype, &[u8]), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingSubtype);
    }

    let length = token_prefix_length(input);

    if length == 0 {
        return Err(ParseError::InvalidSubtypeByte {
            index: 0,
            byte: input[0],
        });
    }

    let value = MediaSubtype::from_bytes(&input[..length])?;

    Ok((value, &input[length..]))
}

fn parse_parameters(content_type: &mut ContentType, mut input: &[u8]) -> Result<(), ParseError> {
    loop {
        input = trim_lws_start(input);

        if input.is_empty() {
            return Ok(());
        }

        if input[0] != b';' {
            return Err(ParseError::UnexpectedTrailingData { byte: input[0] });
        }

        input = trim_lws_start(&input[1..]);

        if input.is_empty() {
            return Err(ParseError::EmptyParameter);
        }

        if content_type.parameter_count() >= MAX_MEDIA_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_MEDIA_PARAMETERS,
            });
        }

        let (name, remaining) = parse_parameter_name(input)?;
        input = trim_lws_start(remaining);

        if input.first() != Some(&b'=') {
            return Err(ParseError::MissingParameterEquals);
        }

        input = trim_lws_start(&input[1..]);

        if input.is_empty() {
            return Err(ParseError::MissingParameterValue);
        }

        let (parameter, remaining) = parse_parameter_value(name, input)?;
        content_type.push_parameter(parameter)?;
        input = remaining;
    }
}

fn parse_parameter_name(input: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let length = token_prefix_length(input);

    if length == 0 {
        return Err(ParseError::InvalidParameterName {
            index: 0,
            byte: input[0],
        });
    }

    if length > MAX_MEDIA_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length,
            maximum: MAX_MEDIA_PARAMETER_NAME_BYTES,
        });
    }

    Ok((&input[..length], &input[length..]))
}

fn parse_parameter_value<'a>(
    name: &[u8],
    input: &'a [u8],
) -> Result<(MediaParameter, &'a [u8]), ParseError> {
    if input[0] == b'"' {
        return parse_quoted_parameter(name, input);
    }

    parse_token_parameter(name, input)
}

fn parse_token_parameter<'a>(
    name: &[u8],
    input: &'a [u8],
) -> Result<(MediaParameter, &'a [u8]), ParseError> {
    let length = token_prefix_length(input);

    if length == 0 {
        return Err(ParseError::InvalidParameterValue {
            index: 0,
            byte: input[0],
        });
    }

    let value = &input[..length];

    if value.len() > MAX_MEDIA_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: value.len(),
            maximum: MAX_MEDIA_PARAMETER_VALUE_BYTES,
        });
    }

    let remaining = trim_lws_start(&input[length..]);

    if !remaining.is_empty() && remaining[0] != b';' {
        return Err(ParseError::UnexpectedTrailingData { byte: remaining[0] });
    }

    let name = bytes_to_str(name)?;
    let value = bytes_to_str(value)?;
    let parameter = MediaParameter::token(name, value)?;

    Ok((parameter, remaining))
}

fn parse_quoted_parameter<'a>(
    name: &[u8],
    input: &'a [u8],
) -> Result<(MediaParameter, &'a [u8]), ParseError> {
    let (value, consumed) = parse_quoted_value(input)?;

    if value.len() > MAX_MEDIA_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: value.len(),
            maximum: MAX_MEDIA_PARAMETER_VALUE_BYTES,
        });
    }

    let remaining = trim_lws_start(&input[consumed..]);

    if !remaining.is_empty() && remaining[0] != b';' {
        return Err(ParseError::UnexpectedTrailingData { byte: remaining[0] });
    }

    let name = bytes_to_str(name)?;
    let parameter = MediaParameter::quoted(name, value)?;

    Ok((parameter, remaining))
}

fn parse_quoted_value(input: &[u8]) -> Result<(String, usize), ParseError> {
    if input.first() != Some(&b'"') {
        return Err(ParseError::InvalidQuotedString);
    }

    let mut decoded = Vec::with_capacity(input.len().saturating_sub(2));
    let mut index = 1;

    while index < input.len() {
        match input[index] {
            b'"' => {
                let value =
                    String::from_utf8(decoded).map_err(|_| ParseError::InvalidQuotedString)?;

                return Ok((value, index + 1));
            }
            b'\\' => {
                index = decode_quoted_pair(input, index, &mut decoded)?;
            }
            b'\t' => {
                decoded.push(b' ');
                index += 1;
            }
            b'\r' | b'\n' => return Err(ParseError::InvalidQuotedString),
            byte if byte.is_ascii_control() => return Err(ParseError::InvalidQuotedString),
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }

        if decoded.len() > MAX_MEDIA_PARAMETER_VALUE_BYTES {
            return Err(ParseError::ParameterValueTooLong {
                length: decoded.len(),
                maximum: MAX_MEDIA_PARAMETER_VALUE_BYTES,
            });
        }
    }

    Err(ParseError::InvalidQuotedString)
}

fn decode_quoted_pair(
    input: &[u8],
    index: usize,
    decoded: &mut Vec<u8>,
) -> Result<usize, ParseError> {
    let Some(escaped) = input.get(index + 1).copied() else {
        return Err(ParseError::InvalidQuotedString);
    };

    if matches!(escaped, b'\r' | b'\n') || escaped.is_ascii_control() {
        return Err(ParseError::InvalidQuotedString);
    }

    decoded.push(escaped);

    Ok(index + 2)
}

fn validate_media_token(input: &[u8], kind: MediaTokenKind) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(match kind {
            MediaTokenKind::TopLevel => ParseError::MissingTopLevel,
            MediaTokenKind::Subtype => ParseError::MissingSubtype,
        });
    }

    if input.len() > MAX_MEDIA_TOKEN_BYTES {
        return Err(ParseError::MediaTokenTooLong {
            length: input.len(),
            maximum: MAX_MEDIA_TOKEN_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(match kind {
                MediaTokenKind::TopLevel => ParseError::InvalidTopLevelByte { index, byte },
                MediaTokenKind::Subtype => ParseError::InvalidSubtypeByte { index, byte },
            });
        }
    }

    Ok(())
}

fn normalize_parameter_name(input: &[u8]) -> Result<Box<str>, ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyParameter);
    }

    if input.len() > MAX_MEDIA_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: input.len(),
            maximum: MAX_MEDIA_PARAMETER_NAME_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidParameterName { index, byte });
        }
    }

    lowercase_token(input)
}

fn validate_token_parameter_value(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::MissingParameterValue);
    }

    if input.len() > MAX_MEDIA_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_MEDIA_PARAMETER_VALUE_BYTES,
        });
    }

    for (index, byte) in input.iter().copied().enumerate() {
        if !is_token_byte(byte) {
            return Err(ParseError::InvalidParameterValue { index, byte });
        }
    }

    Ok(())
}

fn validate_quoted_parameter_value(input: &[u8]) -> Result<(), ParseError> {
    if input.len() > MAX_MEDIA_PARAMETER_VALUE_BYTES {
        return Err(ParseError::ParameterValueTooLong {
            length: input.len(),
            maximum: MAX_MEDIA_PARAMETER_VALUE_BYTES,
        });
    }

    if std::str::from_utf8(input).is_err() {
        return Err(ParseError::InvalidQuotedString);
    }

    if input.iter().copied().any(|byte| byte.is_ascii_control()) {
        return Err(ParseError::InvalidQuotedString);
    }

    Ok(())
}

fn lowercase_token(input: &[u8]) -> Result<Box<str>, ParseError> {
    let value = std::str::from_utf8(input).map_err(|_| ParseError::InvalidUtf8)?;

    Ok(value.to_ascii_lowercase().into_boxed_str())
}

fn bytes_to_str(input: &[u8]) -> Result<&str, ParseError> {
    std::str::from_utf8(input).map_err(|_| ParseError::InvalidUtf8)
}

fn token_prefix_length(input: &[u8]) -> usize {
    input
        .iter()
        .take_while(|byte| is_token_byte(**byte))
        .count()
}

fn write_quoted(formatter: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    formatter.write_char('"')?;

    for character in value.chars() {
        match character {
            '"' => formatter.write_str("\\\"")?,
            '\\' => formatter.write_str("\\\\")?,
            _ => formatter.write_char(character)?,
        }
    }

    formatter.write_char('"')
}

fn trim_lws(mut input: &[u8]) -> &[u8] {
    input = trim_lws_start(input);

    while input.last().is_some_and(|byte| is_lws(*byte)) {
        input = &input[..input.len() - 1];
    }

    input
}

fn trim_lws_start(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(|byte| is_lws(*byte)) {
        input = &input[1..];
    }

    input
}

const fn is_lws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

#[derive(Clone, Copy)]
enum MediaTokenKind {
    TopLevel,
    Subtype,
}

/// Failure to parse or construct a SIP `Content-Type` value.
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

    /// The top-level media type was missing.
    MissingTopLevel,

    /// The `/` separating media type and subtype was missing.
    MissingSlash,

    /// A byte other than `/` appeared where the separator was required.
    InvalidMediaTypeSeparator {
        /// Unexpected separator byte.
        byte: u8,
    },

    /// The media subtype was missing.
    MissingSubtype,

    /// A top-level media type byte violated the SIP token grammar.
    InvalidTopLevelByte {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A media subtype byte violated the SIP token grammar.
    InvalidSubtypeByte {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A media type or subtype token exceeded the operational size limit.
    MediaTokenTooLong {
        /// Actual token length in bytes.
        length: usize,

        /// Maximum accepted token length in bytes.
        maximum: usize,
    },

    /// A media parameter was empty.
    EmptyParameter,

    /// A media parameter name was invalid.
    InvalidParameterName {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A media parameter name exceeded the operational size limit.
    ParameterNameTooLong {
        /// Actual name length in bytes.
        length: usize,

        /// Maximum accepted name length in bytes.
        maximum: usize,
    },

    /// A media parameter was missing its `=` separator.
    MissingParameterEquals,

    /// A media parameter value was missing.
    MissingParameterValue,

    /// A media parameter token value was invalid.
    InvalidParameterValue {
        /// Offset of the invalid byte.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// A quoted-string parameter was malformed.
    InvalidQuotedString,

    /// A media parameter value exceeded the operational size limit.
    ParameterValueTooLong {
        /// Actual value length in bytes.
        length: usize,

        /// Maximum accepted value length in bytes.
        maximum: usize,
    },

    /// A parameter name appeared more than once.
    DuplicateParameter,

    /// The media type exceeded the bounded parameter count.
    TooManyParameters {
        /// Maximum accepted parameter count.
        maximum: usize,
    },

    /// Unexpected data followed a valid media-type component.
    UnexpectedTrailingData {
        /// First unexpected byte.
        byte: u8,
    },

    /// A supposedly textual media component was not valid UTF-8.
    InvalidUtf8,
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
            Self::MissingTopLevel => "missing-top-level",
            Self::MissingSlash => "missing-slash",
            Self::InvalidMediaTypeSeparator { .. } => "invalid-media-type-separator",
            Self::MissingSubtype => "missing-subtype",
            Self::InvalidTopLevelByte { .. } => "invalid-top-level-byte",
            Self::InvalidSubtypeByte { .. } => "invalid-subtype-byte",
            Self::MediaTokenTooLong { .. } => "media-token-too-long",
            Self::EmptyParameter => "empty-parameter",
            Self::InvalidParameterName { .. } => "invalid-parameter-name",
            Self::ParameterNameTooLong { .. } => "parameter-name-too-long",
            Self::MissingParameterEquals => "missing-parameter-equals",
            Self::MissingParameterValue => "missing-parameter-value",
            Self::InvalidParameterValue { .. } => "invalid-parameter-value",
            Self::InvalidQuotedString => "invalid-quoted-string",
            Self::ParameterValueTooLong { .. } => "parameter-value-too-long",
            Self::DuplicateParameter => "duplicate-parameter",
            Self::TooManyParameters { .. } => "too-many-parameters",
            Self::UnexpectedTrailingData { .. } => "unexpected-trailing-data",
            Self::InvalidUtf8 => "invalid-utf8",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP Content-Type field value is empty"),
            Self::TooLong { length, maximum } => {
                write_limit(formatter, "SIP Content-Type field-value", *length, *maximum)
            }
            Self::InvalidLineBreak => {
                formatter.write_str("SIP Content-Type contains an invalid line break")
            }
            Self::MissingTopLevel => {
                formatter.write_str("SIP Content-Type top-level media type is missing")
            }
            Self::MissingSlash => formatter.write_str("SIP Content-Type media type is missing '/'"),
            Self::InvalidMediaTypeSeparator { byte } => write!(
                formatter,
                "invalid SIP Content-Type media separator byte 0x{byte:02x}"
            ),
            Self::MissingSubtype => {
                formatter.write_str("SIP Content-Type media subtype is missing")
            }
            Self::InvalidTopLevelByte { index, byte } => {
                write_invalid_byte(formatter, "SIP Content-Type top-level type", *index, *byte)
            }
            Self::InvalidSubtypeByte { index, byte } => {
                write_invalid_byte(formatter, "SIP Content-Type subtype", *index, *byte)
            }
            Self::MediaTokenTooLong { length, maximum } => {
                write_limit(formatter, "SIP Content-Type media token", *length, *maximum)
            }
            Self::EmptyParameter => {
                formatter.write_str("SIP Content-Type media parameter is empty")
            }
            Self::InvalidParameterName { index, byte } => {
                write_invalid_byte(formatter, "SIP Content-Type parameter-name", *index, *byte)
            }
            Self::ParameterNameTooLong { length, maximum } => write_limit(
                formatter,
                "SIP Content-Type parameter-name",
                *length,
                *maximum,
            ),
            Self::MissingParameterEquals => {
                formatter.write_str("SIP Content-Type media parameter is missing '='")
            }
            Self::MissingParameterValue => {
                formatter.write_str("SIP Content-Type media parameter value is missing")
            }
            Self::InvalidParameterValue { index, byte } => {
                write_invalid_byte(formatter, "SIP Content-Type parameter value", *index, *byte)
            }
            Self::InvalidQuotedString => {
                formatter.write_str("SIP Content-Type quoted string is invalid")
            }
            Self::ParameterValueTooLong { length, maximum } => write_limit(
                formatter,
                "SIP Content-Type parameter-value",
                *length,
                *maximum,
            ),
            Self::DuplicateParameter => {
                formatter.write_str("SIP Content-Type parameter name is duplicated")
            }
            Self::TooManyParameters { maximum } => write!(
                formatter,
                "SIP Content-Type contains more than {maximum} parameters"
            ),
            Self::UnexpectedTrailingData { byte } => write!(
                formatter,
                "unexpected byte 0x{byte:02x} follows SIP Content-Type content"
            ),
            Self::InvalidUtf8 => {
                formatter.write_str("SIP Content-Type textual component is not valid UTF-8")
            }
        }
    }
}

fn write_invalid_byte(
    formatter: &mut fmt::Formatter<'_>,
    subject: &str,
    index: usize,
    byte: u8,
) -> fmt::Result {
    write!(
        formatter,
        "invalid {subject} byte 0x{byte:02x} at offset {index}"
    )
}

fn write_limit(
    formatter: &mut fmt::Formatter<'_>,
    subject: &str,
    length: usize,
    maximum: usize,
) -> fmt::Result {
    write!(
        formatter,
        "{subject} length {length} exceeds maximum {maximum}"
    )
}

impl StdError for ParseError {}

#[cfg(test)]
mod tests {
    use super::{
        ContentType, MAX_CONTENT_TYPE_BYTES, MAX_MEDIA_PARAMETER_NAME_BYTES,
        MAX_MEDIA_PARAMETER_VALUE_BYTES, MAX_MEDIA_PARAMETERS, MAX_MEDIA_TOKEN_BYTES,
        MediaParameter, MediaParameterValue, MediaSubtype, MediaTopLevel, MediaType, ParseError,
        parse,
    };
    use std::str::FromStr;

    #[test]
    fn parses_application_sdp() {
        let Ok(content_type) = parse(b"application/sdp") else {
            panic!("expected valid Content-Type");
        };

        assert!(content_type.is_application_sdp());
        assert!(content_type.parameters().is_empty());
    }

    #[test]
    fn standard_application_sdp_is_canonicalized() {
        let Ok(content_type) = parse(b"APPLICATION/SDP") else {
            panic!("expected case-insensitive application/sdp");
        };

        assert_eq!(content_type.to_string(), "application/sdp");
    }

    #[test]
    fn application_sdp_constructor_is_allocation_free_representation() {
        let content_type = ContentType::application_sdp();

        assert_eq!(
            content_type.media_type().top_level(),
            &MediaTopLevel::Application
        );
        assert_eq!(content_type.media_type().subtype(), &MediaSubtype::Sdp);
    }

    #[test]
    fn parses_common_top_level_types() {
        let cases = [
            ("text/plain", "text/plain"),
            ("image/png", "image/png"),
            ("audio/pcmu", "audio/pcmu"),
            ("video/h264", "video/h264"),
            ("message/sipfrag", "message/sipfrag"),
            ("multipart/mixed", "multipart/mixed"),
        ];

        for (input, expected) in cases {
            let Ok(content_type) = ContentType::from_str(input) else {
                panic!("expected valid media type");
            };

            assert_eq!(content_type.to_string(), expected);
        }
    }

    #[test]
    fn preserves_registered_subtype_semantics_in_lowercase() {
        let Ok(content_type) = parse(b"Application/Problem+JSON") else {
            panic!("expected valid registered subtype");
        };

        assert_eq!(content_type.to_string(), "application/problem+json");
    }

    #[test]
    fn preserves_extension_top_level_in_lowercase() {
        let Ok(content_type) = parse(b"X-LiveAISIP/Example") else {
            panic!("expected extension media type");
        };

        assert_eq!(content_type.to_string(), "x-liveaisip/example");
    }

    #[test]
    fn accepts_whitespace_around_slash() {
        let Ok(content_type) = parse(b"application \t/ \t sdp") else {
            panic!("expected valid delimiter whitespace");
        };

        assert!(content_type.is_application_sdp());
        assert_eq!(content_type.to_string(), "application/sdp");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let Ok(content_type) = parse(b" \t application/sdp \t ") else {
            panic!("expected surrounding whitespace");
        };

        assert!(content_type.is_application_sdp());
    }

    #[test]
    fn parses_token_parameter() {
        let Ok(content_type) = parse(b"text/plain;charset=utf-8") else {
            panic!("expected token parameter");
        };

        assert_eq!(content_type.charset(), Some("utf-8"));
        assert!(!content_type.parameters()[0].is_quoted());
    }

    #[test]
    fn parameter_names_are_case_insensitive_and_canonicalized() {
        let Ok(content_type) = parse(b"text/plain;CHARSET=UTF-8") else {
            panic!("expected charset parameter");
        };

        assert_eq!(
            content_type.parameter("charset").map(MediaParameter::name),
            Some("charset")
        );
        assert_eq!(
            content_type.parameter("CHARSET").map(MediaParameter::value),
            Some("UTF-8")
        );
        assert_eq!(content_type.to_string(), "text/plain;charset=UTF-8");
    }

    #[test]
    fn parameter_values_preserve_case() {
        let Ok(content_type) = parse(b"text/plain;charset=UTF-8") else {
            panic!("expected charset parameter");
        };

        assert_eq!(content_type.charset(), Some("UTF-8"));
    }

    #[test]
    fn parses_quoted_parameter() {
        let Ok(content_type) = parse(b"multipart/mixed;boundary=\"boundary value\"") else {
            panic!("expected quoted boundary parameter");
        };

        assert_eq!(content_type.boundary(), Some("boundary value"));
        assert!(content_type.parameters()[0].is_quoted());
    }

    #[test]
    fn quoted_parameter_may_be_empty() {
        let Ok(content_type) = parse(b"text/plain;x-empty=\"\"") else {
            panic!("expected empty quoted parameter");
        };

        assert_eq!(
            content_type.parameter("x-empty").map(MediaParameter::value),
            Some("")
        );
    }

    #[test]
    fn quoted_parameter_may_contain_semicolon() {
        let Ok(content_type) = parse(b"text/plain;x-value=\"one;two\";charset=utf-8") else {
            panic!("expected quoted semicolon");
        };

        assert_eq!(
            content_type.parameter("x-value").map(MediaParameter::value),
            Some("one;two")
        );
        assert_eq!(content_type.charset(), Some("utf-8"));
    }

    #[test]
    fn quoted_parameter_unescapes_quote_and_backslash() {
        let Ok(content_type) = parse(b"text/plain;x-value=\"A \\\"B\\\" \\\\ C\"") else {
            panic!("expected quoted escapes");
        };

        assert_eq!(
            content_type.parameter("x-value").map(MediaParameter::value),
            Some("A \"B\" \\ C")
        );
    }

    #[test]
    fn quoted_parameter_serialization_reescapes_value() {
        let Ok(parameter) = MediaParameter::quoted("x-value", "A \"B\" \\ C") else {
            panic!("expected valid quoted parameter");
        };

        assert_eq!(parameter.to_string(), "x-value=\"A \\\"B\\\" \\\\ C\"");
    }

    #[test]
    fn accepts_whitespace_around_parameter_delimiters() {
        let Ok(content_type) = parse(b"text/plain \t; \tcharset \t= \tutf-8") else {
            panic!("expected parameter delimiter whitespace");
        };

        assert_eq!(content_type.charset(), Some("utf-8"));
        assert_eq!(content_type.to_string(), "text/plain;charset=utf-8");
    }

    #[test]
    fn parses_multiple_parameters_in_wire_order() {
        let Ok(content_type) = parse(b"multipart/mixed;boundary=abc;charset=utf-8;x-mode=fast")
        else {
            panic!("expected multiple parameters");
        };

        assert_eq!(content_type.parameters().len(), 3);
        assert_eq!(content_type.parameters()[0].name(), "boundary");
        assert_eq!(content_type.parameters()[1].name(), "charset");
        assert_eq!(content_type.parameters()[2].name(), "x-mode");
    }

    #[test]
    fn rejects_duplicate_parameter_case_insensitively() {
        assert_eq!(
            parse(b"text/plain;charset=utf-8;CHARSET=ascii"),
            Err(ParseError::DuplicateParameter)
        );
    }

    #[test]
    fn rejects_empty_field_value() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b" \t "), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_field_above_size_limit() {
        let input = vec![b'A'; MAX_CONTENT_TYPE_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_CONTENT_TYPE_BYTES + 1,
                maximum: MAX_CONTENT_TYPE_BYTES,
            })
        );
    }

    #[test]
    fn rejects_embedded_crlf() {
        assert_eq!(
            parse(b"application/\r\n sdp"),
            Err(ParseError::InvalidLineBreak)
        );
    }

    #[test]
    fn rejects_missing_slash() {
        assert_eq!(parse(b"application"), Err(ParseError::MissingSlash));
    }

    #[test]
    fn rejects_missing_subtype() {
        assert_eq!(parse(b"application/"), Err(ParseError::MissingSubtype));
    }

    #[test]
    fn rejects_missing_top_level() {
        assert_eq!(
            parse(b"/sdp"),
            Err(ParseError::InvalidTopLevelByte {
                index: 0,
                byte: b'/',
            })
        );
    }

    #[test]
    fn rejects_invalid_top_level_byte() {
        assert_eq!(
            parse(b"app@lication/sdp"),
            Err(ParseError::InvalidMediaTypeSeparator { byte: b'@' })
        );
    }

    #[test]
    fn rejects_invalid_subtype_trailing_byte() {
        assert_eq!(
            parse(b"application/sdp@"),
            Err(ParseError::UnexpectedTrailingData { byte: b'@' })
        );
    }

    #[test]
    fn rejects_empty_parameter() {
        assert_eq!(parse(b"application/sdp;"), Err(ParseError::EmptyParameter));
    }

    #[test]
    fn rejects_parameter_missing_equals() {
        assert_eq!(
            parse(b"text/plain;charset"),
            Err(ParseError::MissingParameterEquals)
        );
    }

    #[test]
    fn rejects_parameter_missing_value() {
        assert_eq!(
            parse(b"text/plain;charset="),
            Err(ParseError::MissingParameterValue)
        );
    }

    #[test]
    fn rejects_invalid_token_parameter_value() {
        assert_eq!(
            parse(b"text/plain;charset=utf/8"),
            Err(ParseError::UnexpectedTrailingData { byte: b'/' })
        );
    }

    #[test]
    fn rejects_unterminated_quoted_parameter() {
        assert_eq!(
            parse(b"text/plain;charset=\"utf-8"),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn rejects_control_byte_in_quoted_parameter() {
        assert_eq!(
            parse(b"text/plain;x-value=\"one\x01two\""),
            Err(ParseError::InvalidQuotedString)
        );
    }

    #[test]
    fn media_type_constructor_canonicalizes_components() {
        let Ok(media_type) = MediaType::from_components("APPLICATION", "JSON") else {
            panic!("expected valid media type");
        };

        assert_eq!(media_type.to_string(), "application/json");
    }

    #[test]
    fn creates_token_parameter() {
        let Ok(parameter) = MediaParameter::token("Charset", "UTF-8") else {
            panic!("expected valid token parameter");
        };

        assert_eq!(parameter.name(), "charset");
        assert_eq!(parameter.value(), "UTF-8");
        assert_eq!(parameter.to_string(), "charset=UTF-8");
    }

    #[test]
    fn creates_quoted_parameter() {
        let Ok(parameter) = MediaParameter::quoted("Boundary", "one two") else {
            panic!("expected valid quoted parameter");
        };

        assert_eq!(parameter.name(), "boundary");
        assert_eq!(parameter.value(), "one two");
        assert!(parameter.is_quoted());
    }

    #[test]
    fn typed_parameter_value_is_exposed() {
        let Ok(parameter) = MediaParameter::token("charset", "utf-8") else {
            panic!("expected token parameter");
        };

        assert!(matches!(
            parameter.typed_value(),
            MediaParameterValue::Token(_)
        ));
    }

    #[test]
    fn rejects_invalid_parameter_name() {
        assert_eq!(
            MediaParameter::token("bad:name", "value"),
            Err(ParseError::InvalidParameterName {
                index: 3,
                byte: b':',
            })
        );
    }

    #[test]
    fn rejects_invalid_direct_token_parameter_value() {
        assert_eq!(
            MediaParameter::token("charset", "utf 8"),
            Err(ParseError::InvalidParameterValue {
                index: 3,
                byte: b' ',
            })
        );
    }

    #[test]
    fn rejects_parameter_name_above_size_limit() {
        let name = "A".repeat(MAX_MEDIA_PARAMETER_NAME_BYTES + 1);

        assert_eq!(
            MediaParameter::token(name, "value"),
            Err(ParseError::ParameterNameTooLong {
                length: MAX_MEDIA_PARAMETER_NAME_BYTES + 1,
                maximum: MAX_MEDIA_PARAMETER_NAME_BYTES,
            })
        );
    }

    #[test]
    fn rejects_parameter_value_above_size_limit() {
        let value = "A".repeat(MAX_MEDIA_PARAMETER_VALUE_BYTES + 1);

        assert_eq!(
            MediaParameter::token("x-value", value),
            Err(ParseError::ParameterValueTooLong {
                length: MAX_MEDIA_PARAMETER_VALUE_BYTES + 1,
                maximum: MAX_MEDIA_PARAMETER_VALUE_BYTES,
            })
        );
    }

    #[test]
    fn rejects_media_token_above_size_limit() {
        let top_level = "A".repeat(MAX_MEDIA_TOKEN_BYTES + 1);

        assert_eq!(
            MediaType::from_components(&top_level, "value"),
            Err(ParseError::MediaTokenTooLong {
                length: MAX_MEDIA_TOKEN_BYTES + 1,
                maximum: MAX_MEDIA_TOKEN_BYTES,
            })
        );
    }

    #[test]
    fn enforces_parameter_count() {
        let mut content_type = ContentType::application_sdp();

        for index in 0..MAX_MEDIA_PARAMETERS {
            let name = format!("x-{index}");
            let Ok(parameter) = MediaParameter::token(name, "value") else {
                panic!("expected valid parameter");
            };

            assert!(content_type.push_parameter(parameter).is_ok());
        }

        let Ok(extra) = MediaParameter::token("x-extra", "value") else {
            panic!("expected valid parameter");
        };

        assert_eq!(
            content_type.push_parameter(extra),
            Err(ParseError::TooManyParameters {
                maximum: MAX_MEDIA_PARAMETERS,
            })
        );
    }

    #[test]
    fn display_is_canonical() {
        let Ok(content_type) = parse(b"APPLICATION/SDP;CHARSET=UTF-8;x-note=\"Voice Gateway\"")
        else {
            panic!("expected valid Content-Type");
        };

        assert_eq!(
            content_type.to_string(),
            "application/sdp;charset=UTF-8;x-note=\"Voice Gateway\""
        );
    }

    #[test]
    fn parses_from_str() {
        let Ok(content_type) = ContentType::from_str("application/sdp;charset=utf-8") else {
            panic!("expected valid Content-Type");
        };

        assert!(content_type.is_application_sdp());
        assert_eq!(content_type.charset(), Some("utf-8"));
    }

    #[test]
    fn consumes_into_parts() {
        let Ok(content_type) = parse(b"text/plain;charset=utf-8") else {
            panic!("expected valid Content-Type");
        };

        let (media_type, parameters) = content_type.into_parts();

        assert_eq!(media_type.to_string(), "text/plain");
        assert_eq!(parameters.len(), 1);
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");
        assert_eq!(ParseError::InvalidLineBreak.class(), "invalid-line-break");
        assert_eq!(ParseError::MissingSlash.class(), "missing-slash");
        assert_eq!(ParseError::MissingSubtype.class(), "missing-subtype");
        assert_eq!(
            ParseError::InvalidParameterName {
                index: 0,
                byte: b':',
            }
            .class(),
            "invalid-parameter-name"
        );
        assert_eq!(
            ParseError::DuplicateParameter.class(),
            "duplicate-parameter"
        );
        assert_eq!(
            ParseError::TooManyParameters {
                maximum: MAX_MEDIA_PARAMETERS,
            }
            .class(),
            "too-many-parameters"
        );
    }
}
