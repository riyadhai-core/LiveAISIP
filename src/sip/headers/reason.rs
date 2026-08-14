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

//! SIP `Reason` header.
//!
//! This module provides bounded parsing, validation, representation, and
//! canonical serialization for SIP `Reason` field values.
//!
//! Parsing is intentionally lossless with respect to value and parameter
//! multiplicity. Repeated reason parameters are preserved in wire order
//! rather than rejected or collapsed. Interpretation of ambiguous repeated
//! parameters belongs to a higher semantic-policy layer.
//!
//! A `Reason` field can contain multiple comma-separated reason values. Each
//! reason value contains a protocol token followed by zero or more parameters.
//! Known parameters include `cause`, `text`, and the `Q.850` `location`
//! extension. Unknown generic parameters are preserved.
//!
//! Resource bounds are enforced during both parsing and programmatic
//! construction so malformed or adversarial input cannot cause unbounded
//! collection growth or field-size expansion.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;
use std::net::Ipv6Addr;
use std::str::FromStr;

/// Maximum accepted SIP `Reason` field-value size in bytes.
///
/// This is a `LiveAISIP` operational bound rather than a SIP protocol limit.
pub const MAX_REASON_BYTES: usize = 8 * 1024;

/// Maximum number of comma-separated reason values in one field value.
pub const MAX_REASON_VALUES: usize = 64;

/// Maximum number of parameters accepted in one reason value.
pub const MAX_REASON_PARAMETERS: usize = 64;

/// Maximum protocol-token size in bytes.
pub const MAX_REASON_PROTOCOL_BYTES: usize = 256;

/// Maximum parameter-name size in bytes.
pub const MAX_REASON_PARAMETER_NAME_BYTES: usize = 256;

/// Maximum decimal `cause` representation size in bytes.
///
/// The wire grammar defines a sequence of decimal digits rather than a
/// fixed-width machine integer. Keeping a bounded textual representation
/// avoids introducing an artificial protocol range restriction.
pub const MAX_REASON_CAUSE_BYTES: usize = 64;

/// Maximum logical `text` size in bytes.
pub const MAX_REASON_TEXT_BYTES: usize = 2 * 1024;

/// Maximum logical or bare extension-parameter value size in bytes.
pub const MAX_REASON_EXTENSION_VALUE_BYTES: usize = 2 * 1024;

/// A validated SIP `Reason` field value.
///
/// The value always contains at least one [`ReasonValue`]. Reason-value
/// multiplicity is preserved; protocol-specific rules governing whether
/// repeated protocol values are meaningful belong to the semantic-policy
/// layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reason {
    values: Vec<ReasonValue>,
    serialized_len: usize,
}

impl Reason {
    /// Creates a `Reason` field containing one reason value.
    #[must_use]
    pub fn new(reason_value: ReasonValue) -> Self {
        let serialized_len = reason_value.serialized_len();

        Self {
            values: vec![reason_value],
            serialized_len,
        }
    }

    /// Creates a `Reason` field from ordered reason values.
    ///
    /// Repeated protocol values are preserved. A higher policy layer decides
    /// whether multiplicity is permitted for the corresponding registered
    /// reason protocol.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Empty`] when no values are supplied,
    /// [`ParseError::TooManyValues`] when the value-count bound is exceeded,
    /// or [`ParseError::TooLong`] when canonical serialization exceeds the
    /// field-size bound.
    pub fn from_values(reason_values: Vec<ReasonValue>) -> Result<Self, ParseError> {
        if reason_values.is_empty() {
            return Err(ParseError::Empty);
        }

        if reason_values.len() > MAX_REASON_VALUES {
            return Err(ParseError::TooManyValues {
                maximum: MAX_REASON_VALUES,
            });
        }

        let mut iterator = reason_values.into_iter();

        let Some(first) = iterator.next() else {
            return Err(ParseError::Empty);
        };

        let mut reason = Self::new(first);

        for reason_value in iterator {
            reason.push(reason_value)?;
        }

        Ok(reason)
    }

    /// Parses a complete SIP `Reason` field value from wire bytes.
    ///
    /// Header-name and `HCOLON` parsing are outside this function.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when syntax is invalid or an operational bound
    /// is exceeded.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }

    /// Returns all reason values in wire order.
    #[must_use]
    pub fn values(&self) -> &[ReasonValue] {
        &self.values
    }

    /// Returns the first reason value.
    ///
    /// Successfully constructed `Reason` values are always non-empty.
    #[must_use]
    pub fn first(&self) -> &ReasonValue {
        &self.values[0]
    }

    /// Returns the number of reason values.
    #[must_use]
    pub fn value_count(&self) -> usize {
        self.values.len()
    }

    /// Returns the canonical serialized field-value length in bytes.
    #[must_use]
    pub const fn serialized_len(&self) -> usize {
        self.serialized_len
    }

    /// Appends one reason value.
    ///
    /// Repeated protocol values are preserved. The update is transactional.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyValues`] when the value-count bound has
    /// been reached or [`ParseError::TooLong`] when the resulting canonical
    /// field value would exceed [`MAX_REASON_BYTES`].
    pub fn push(&mut self, reason_value: ReasonValue) -> Result<(), ParseError> {
        if self.values.len() >= MAX_REASON_VALUES {
            return Err(ParseError::TooManyValues {
                maximum: MAX_REASON_VALUES,
            });
        }

        let length = self
            .serialized_len
            .saturating_add(2)
            .saturating_add(reason_value.serialized_len());

        if length > MAX_REASON_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_REASON_BYTES,
            });
        }

        self.values.push(reason_value);
        self.serialized_len = length;

        Ok(())
    }

    /// Returns how many reason values use the supplied protocol.
    ///
    /// Protocol comparison uses [`ReasonProtocol`] equality semantics.
    #[must_use]
    pub fn protocol_count(&self, protocol: &ReasonProtocol) -> usize {
        self.values
            .iter()
            .filter(|reason_value| reason_value.protocol() == protocol)
            .count()
    }

    /// Consumes the field into its ordered reason values.
    #[must_use]
    pub fn into_values(self) -> Vec<ReasonValue> {
        self.values
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, reason_value) in self.values.iter().enumerate() {
            if index != 0 {
                formatter.write_str(", ")?;
            }

            fmt::Display::fmt(reason_value, formatter)?;
        }

        Ok(())
    }
}

impl FromStr for Reason {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// One reason value within a SIP `Reason` field.
///
/// Parameters are retained exactly in their parsed order, including repeated
/// parameter names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReasonValue {
    protocol: ReasonProtocol,
    parameters: Vec<ReasonParameter>,
    serialized_len: usize,
}

impl ReasonValue {
    /// Creates a reason value containing only a protocol.
    ///
    /// A `cause` parameter is not required by the field grammar itself.
    #[must_use]
    pub fn new(protocol: ReasonProtocol) -> Self {
        let serialized_len = protocol.as_str().len();

        Self {
            protocol,
            parameters: Vec::new(),
            serialized_len,
        }
    }

    /// Creates a reason value from an ordered parameter vector.
    ///
    /// Duplicate parameter names are retained in the supplied order.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the parameter-count bound is exceeded or
    /// when canonical serialization would exceed the field-size bound.
    pub fn from_parameters(
        protocol: ReasonProtocol,
        parameters: Vec<ReasonParameter>,
    ) -> Result<Self, ParseError> {
        if parameters.len() > MAX_REASON_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_REASON_PARAMETERS,
            });
        }

        let mut reason_value = Self::new(protocol);

        for parameter in parameters {
            reason_value.push_parameter(parameter)?;
        }

        Ok(reason_value)
    }

    /// Returns the reason protocol.
    #[must_use]
    pub const fn protocol(&self) -> &ReasonProtocol {
        &self.protocol
    }

    /// Returns all parameters in wire order.
    #[must_use]
    pub fn parameters(&self) -> &[ReasonParameter] {
        &self.parameters
    }

    /// Returns the number of parameters.
    #[must_use]
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Returns the canonical serialized reason-value length in bytes.
    #[must_use]
    pub const fn serialized_len(&self) -> usize {
        self.serialized_len
    }

    /// Returns all parameters whose names match `name`.
    ///
    /// Parameter-name matching is ASCII case-insensitive. Repeated parameters
    /// are returned in wire order.
    pub fn parameters_named<'a, 'name>(
        &'a self,
        name: &'name str,
    ) -> impl Iterator<Item = &'a ReasonParameter> + use<'a, 'name> {
        self.parameters
            .iter()
            .filter(move |parameter| parameter.name().eq_ignore_ascii_case(name))
    }

    /// Returns the first parameter named `name`.
    ///
    /// This accessor is explicitly first-value semantics. Use
    /// [`ReasonValue::unique_parameter`] when ambiguity must be detected.
    #[must_use]
    pub fn first_parameter(&self, name: &str) -> Option<&ReasonParameter> {
        self.parameters_named(name).next()
    }

    /// Returns a parameter named `name` only when its occurrence is
    /// unambiguous.
    ///
    /// # Errors
    ///
    /// Returns [`MultiplicityError`] when more than one matching parameter is
    /// present.
    pub fn unique_parameter(
        &self,
        name: &str,
    ) -> Result<Option<&ReasonParameter>, MultiplicityError> {
        unique_item(self.parameters_named(name))
    }

    /// Returns all `cause` parameters in wire order.
    pub fn causes(&self) -> impl Iterator<Item = &ReasonCause> {
        self.parameters.iter().filter_map(ReasonParameter::as_cause)
    }

    /// Returns the first `cause` parameter.
    ///
    /// This accessor deliberately exposes first-value semantics. Use
    /// [`ReasonValue::unique_cause`] when repeated causes must be treated as
    /// ambiguous.
    #[must_use]
    pub fn first_cause(&self) -> Option<&ReasonCause> {
        self.causes().next()
    }

    /// Returns the `cause` only when zero or one `cause` parameter exists.
    ///
    /// # Errors
    ///
    /// Returns [`MultiplicityError`] when more than one `cause` is present.
    pub fn unique_cause(&self) -> Result<Option<&ReasonCause>, MultiplicityError> {
        unique_item(self.causes())
    }

    /// Returns all logical `text` parameters in wire order.
    pub fn texts(&self) -> impl Iterator<Item = &str> {
        self.parameters.iter().filter_map(ReasonParameter::as_text)
    }

    /// Returns the first logical `text` parameter.
    ///
    /// Use [`ReasonValue::unique_text`] when ambiguity must be detected.
    #[must_use]
    pub fn first_text(&self) -> Option<&str> {
        self.texts().next()
    }

    /// Returns the logical `text` only when zero or one `text` parameter
    /// exists.
    ///
    /// # Errors
    ///
    /// Returns [`MultiplicityError`] when more than one `text` is present.
    pub fn unique_text(&self) -> Result<Option<&str>, MultiplicityError> {
        unique_item(self.texts())
    }

    /// Returns all `location` parameters in wire order.
    pub fn locations(&self) -> impl Iterator<Item = IsupLocation> + '_ {
        self.parameters
            .iter()
            .filter_map(ReasonParameter::as_location)
    }

    /// Returns the first `location` parameter.
    ///
    /// A syntactically valid location on a protocol other than `Q.850` is
    /// still preserved. Use [`ReasonValue::first_q850_location`] when
    /// protocol semantics are required.
    #[must_use]
    pub fn first_location(&self) -> Option<IsupLocation> {
        self.locations().next()
    }

    /// Returns the `location` only when zero or one location exists.
    ///
    /// # Errors
    ///
    /// Returns [`MultiplicityError`] when more than one location parameter is
    /// present.
    pub fn unique_location(&self) -> Result<Option<IsupLocation>, MultiplicityError> {
        unique_item(self.locations())
    }

    /// Returns the first `location` only when this is a `Q.850` reason value.
    ///
    /// Location parameters on other protocols remain preserved but are not
    /// interpreted as effective `Q.850` locations.
    #[must_use]
    pub fn first_q850_location(&self) -> Option<IsupLocation> {
        if self.protocol.is_q850() {
            self.first_location()
        } else {
            None
        }
    }

    /// Returns the unique `Q.850` location when this reason uses `Q.850`.
    ///
    /// # Errors
    ///
    /// Returns [`MultiplicityError`] when a `Q.850` reason contains multiple
    /// location parameters.
    pub fn unique_q850_location(&self) -> Result<Option<IsupLocation>, MultiplicityError> {
        if self.protocol.is_q850() {
            self.unique_location()
        } else {
            Ok(None)
        }
    }

    /// Returns a SIP status code only when the reason uses protocol `SIP`,
    /// has exactly one `cause`, and that cause is within the SIP response-code
    /// range.
    ///
    /// # Errors
    ///
    /// Returns [`MultiplicityError`] when multiple `cause` parameters are
    /// present.
    pub fn unique_sip_status_code(&self) -> Result<Option<u16>, MultiplicityError> {
        if !self.protocol.is_sip() {
            return Ok(None);
        }

        let Some(cause) = self.unique_cause()? else {
            return Ok(None);
        };

        let Some(cause) = cause.as_u16() else {
            return Ok(None);
        };

        if (100..=699).contains(&cause) {
            Ok(Some(cause))
        } else {
            Ok(None)
        }
    }

    /// Appends one parameter.
    ///
    /// Repeated parameter names are intentionally preserved. The update is
    /// transactional.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooManyParameters`] when the parameter-count
    /// bound has been reached or [`ParseError::TooLong`] when the resulting
    /// canonical reason value exceeds [`MAX_REASON_BYTES`].
    pub fn push_parameter(&mut self, parameter: ReasonParameter) -> Result<(), ParseError> {
        if self.parameters.len() >= MAX_REASON_PARAMETERS {
            return Err(ParseError::TooManyParameters {
                maximum: MAX_REASON_PARAMETERS,
            });
        }

        let length = self
            .serialized_len
            .saturating_add(1)
            .saturating_add(parameter.serialized_len());

        if length > MAX_REASON_BYTES {
            return Err(ParseError::TooLong {
                length,
                maximum: MAX_REASON_BYTES,
            });
        }

        self.parameters.push(parameter);
        self.serialized_len = length;

        Ok(())
    }

    /// Consumes the reason value into its protocol and ordered parameters.
    #[must_use]
    pub fn into_parts(self) -> (ReasonProtocol, Vec<ReasonParameter>) {
        (self.protocol, self.parameters)
    }
}

impl fmt::Display for ReasonValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.protocol, formatter)?;

        for parameter in &self.parameters {
            formatter.write_char(';')?;
            fmt::Display::fmt(parameter, formatter)?;
        }

        Ok(())
    }
}

/// Protocol identifier carried by a SIP `Reason` value.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ReasonProtocol {
    /// SIP status-code reason protocol.
    Sip,

    /// ITU-T `Q.850` cause-value reason protocol.
    Q850,

    /// Another registered or extension protocol token.
    Extension(Box<str>),
}

impl ReasonProtocol {
    /// Parses and validates a protocol token.
    ///
    /// Known protocol names are recognized case-insensitively and serialized
    /// using canonical spellings.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidProtocol`] when the token is empty or
    /// invalid, or [`ParseError::ProtocolTooLong`] when it exceeds the
    /// operational bound.
    pub fn new(protocol: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let protocol = protocol.into();

        validate_protocol(protocol.as_bytes())?;

        if protocol.eq_ignore_ascii_case("SIP") {
            return Ok(Self::Sip);
        }

        if protocol.eq_ignore_ascii_case("Q.850") {
            return Ok(Self::Q850);
        }

        Ok(Self::Extension(protocol))
    }

    /// Returns the protocol token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sip => "SIP",
            Self::Q850 => "Q.850",
            Self::Extension(protocol) => protocol,
        }
    }

    /// Returns whether this protocol is `SIP`.
    #[must_use]
    pub const fn is_sip(&self) -> bool {
        matches!(self, Self::Sip)
    }

    /// Returns whether this protocol is `Q.850`.
    #[must_use]
    pub const fn is_q850(&self) -> bool {
        matches!(self, Self::Q850)
    }
}

impl PartialEq for ReasonProtocol {
    fn eq(&self, other: &Self) -> bool {
        self.as_str().eq_ignore_ascii_case(other.as_str())
    }
}

impl Eq for ReasonProtocol {}

impl fmt::Display for ReasonProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ReasonProtocol {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

/// Decimal `cause` value carried by a SIP `Reason` parameter.
///
/// The decimal representation is retained instead of forcing the value into a
/// fixed-width integer. Leading zeroes are therefore preserved on the wire.
#[derive(Clone, Debug)]
pub struct ReasonCause {
    digits: Box<str>,
}

impl ReasonCause {
    /// Creates a decimal `cause` from a `u32`.
    #[must_use]
    pub fn new(value: u32) -> Self {
        Self {
            digits: value.to_string().into_boxed_str(),
        }
    }

    /// Parses a decimal `cause` from wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidCause`] when the representation is empty
    /// or contains a non-decimal byte, or [`ParseError::CauseTooLong`] when
    /// it exceeds the operational bound.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(ParseError::InvalidCause);
        }

        if input.len() > MAX_REASON_CAUSE_BYTES {
            return Err(ParseError::CauseTooLong {
                length: input.len(),
                maximum: MAX_REASON_CAUSE_BYTES,
            });
        }

        if !input.iter().all(u8::is_ascii_digit) {
            return Err(ParseError::InvalidCause);
        }

        let digits = std::str::from_utf8(input).map_err(|_| ParseError::InvalidCause)?;

        Ok(Self {
            digits: Box::from(digits),
        })
    }

    /// Returns the exact decimal wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.digits
    }

    /// Returns the numeric value as `u32` when it fits.
    #[must_use]
    pub fn as_u32(&self) -> Option<u32> {
        self.digits.parse().ok()
    }

    /// Returns the numeric value as `u16` when it fits.
    #[must_use]
    pub fn as_u16(&self) -> Option<u16> {
        self.digits.parse().ok()
    }

    fn normalized_digits(&self) -> &str {
        let normalized = self.digits.trim_start_matches('0');

        if normalized.is_empty() {
            "0"
        } else {
            normalized
        }
    }
}

impl PartialEq for ReasonCause {
    fn eq(&self, other: &Self) -> bool {
        self.normalized_digits() == other.normalized_digits()
    }
}

impl Eq for ReasonCause {}

impl fmt::Display for ReasonCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.digits)
    }
}

impl FromStr for ReasonCause {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// `Q.850` ISUP release-location value carried by the `Reason` header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IsupLocation {
    /// User.
    U,

    /// Private network serving the local user.
    Lpn,

    /// Public network serving the local user.
    Ln,

    /// Transit network.
    Tn,

    /// Public network serving the remote user.
    Rln,

    /// Private network serving the remote user.
    Rpn,

    /// Spare location value 6.
    Loc6,

    /// International network.
    Intl,

    /// Spare location value 8.
    Loc8,

    /// Spare location value 9.
    Loc9,

    /// Network beyond the interworking point.
    Bi,

    /// Spare location value 11.
    Loc11,

    /// Reserved location value 12.
    Loc12,

    /// Reserved location value 13.
    Loc13,

    /// Reserved location value 14.
    Loc14,

    /// Reserved location value 15.
    Loc15,
}

impl IsupLocation {
    /// Parses a `Q.850` release-location token.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidLocation`] for an unknown value.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if eq_ascii(input, b"U") {
            return Ok(Self::U);
        }
        if eq_ascii(input, b"LPN") {
            return Ok(Self::Lpn);
        }
        if eq_ascii(input, b"LN") {
            return Ok(Self::Ln);
        }
        if eq_ascii(input, b"TN") {
            return Ok(Self::Tn);
        }
        if eq_ascii(input, b"RLN") {
            return Ok(Self::Rln);
        }
        if eq_ascii(input, b"RPN") {
            return Ok(Self::Rpn);
        }
        if eq_ascii(input, b"LOC-6") {
            return Ok(Self::Loc6);
        }
        if eq_ascii(input, b"INTL") {
            return Ok(Self::Intl);
        }
        if eq_ascii(input, b"LOC-8") {
            return Ok(Self::Loc8);
        }
        if eq_ascii(input, b"LOC-9") {
            return Ok(Self::Loc9);
        }
        if eq_ascii(input, b"BI") {
            return Ok(Self::Bi);
        }
        if eq_ascii(input, b"LOC-11") {
            return Ok(Self::Loc11);
        }
        if eq_ascii(input, b"LOC-12") {
            return Ok(Self::Loc12);
        }
        if eq_ascii(input, b"LOC-13") {
            return Ok(Self::Loc13);
        }
        if eq_ascii(input, b"LOC-14") {
            return Ok(Self::Loc14);
        }
        if eq_ascii(input, b"LOC-15") {
            return Ok(Self::Loc15);
        }

        Err(ParseError::InvalidLocation)
    }

    /// Returns the canonical wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::U => "U",
            Self::Lpn => "LPN",
            Self::Ln => "LN",
            Self::Tn => "TN",
            Self::Rln => "RLN",
            Self::Rpn => "RPN",
            Self::Loc6 => "LOC-6",
            Self::Intl => "INTL",
            Self::Loc8 => "LOC-8",
            Self::Loc9 => "LOC-9",
            Self::Bi => "BI",
            Self::Loc11 => "LOC-11",
            Self::Loc12 => "LOC-12",
            Self::Loc13 => "LOC-13",
            Self::Loc14 => "LOC-14",
            Self::Loc15 => "LOC-15",
        }
    }
}

impl fmt::Display for IsupLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for IsupLocation {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// One parameter of a SIP `Reason` value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReasonParameter {
    /// Decimal protocol cause.
    Cause(ReasonCause),

    /// Human-readable quoted text stored as logical text.
    Text(Box<str>),

    /// `Q.850` ISUP release location.
    Location(IsupLocation),

    /// Another generic SIP parameter.
    Extension(ExtensionParameter),
}

impl ReasonParameter {
    /// Creates a `cause` parameter from a `u32`.
    #[must_use]
    pub fn cause(value: u32) -> Self {
        Self::Cause(ReasonCause::new(value))
    }

    /// Creates a `cause` parameter from decimal wire text.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the decimal representation is invalid or
    /// exceeds its operational bound.
    pub fn cause_digits(input: &[u8]) -> Result<Self, ParseError> {
        Ok(Self::Cause(ReasonCause::from_bytes(input)?))
    }

    /// Creates a logical `text` parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the value contains an unsupported control
    /// byte or exceeds its operational bound.
    pub fn text(text: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let text = text.into();
        validate_quoted_logical(&text, QuotedKind::Text)?;

        Ok(Self::Text(text))
    }

    /// Creates a `location` parameter.
    #[must_use]
    pub const fn location(location: IsupLocation) -> Self {
        Self::Location(location)
    }

    /// Creates an extension parameter.
    ///
    /// Names `cause`, `text`, and `location` are reserved for the typed
    /// parameter variants.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name is invalid, reserved, or exceeds
    /// its operational bound.
    pub fn extension(
        name: impl Into<Box<str>>,
        value: Option<ParameterValue>,
    ) -> Result<Self, ParseError> {
        Ok(Self::Extension(ExtensionParameter::new(name, value)?))
    }

    /// Returns the parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Cause(_) => "cause",
            Self::Text(_) => "text",
            Self::Location(_) => "location",
            Self::Extension(parameter) => parameter.name(),
        }
    }

    /// Returns the cause when this is a `cause` parameter.
    #[must_use]
    pub const fn as_cause(&self) -> Option<&ReasonCause> {
        match self {
            Self::Cause(cause) => Some(cause),
            Self::Text(_) | Self::Location(_) | Self::Extension(_) => None,
        }
    }

    /// Returns logical text when this is a `text` parameter.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Cause(_) | Self::Location(_) | Self::Extension(_) => None,
        }
    }

    /// Returns the location when this is a `location` parameter.
    #[must_use]
    pub const fn as_location(&self) -> Option<IsupLocation> {
        match self {
            Self::Location(location) => Some(*location),
            Self::Cause(_) | Self::Text(_) | Self::Extension(_) => None,
        }
    }

    /// Returns the extension parameter when applicable.
    #[must_use]
    pub const fn as_extension(&self) -> Option<&ExtensionParameter> {
        match self {
            Self::Extension(parameter) => Some(parameter),
            Self::Cause(_) | Self::Text(_) | Self::Location(_) => None,
        }
    }

    fn serialized_len(&self) -> usize {
        match self {
            Self::Cause(cause) => "cause=".len() + cause.as_str().len(),
            Self::Text(text) => "text=".len() + quoted_serialized_len(text),
            Self::Location(location) => "location=".len() + location.as_str().len(),
            Self::Extension(parameter) => parameter.serialized_len(),
        }
    }
}

impl fmt::Display for ReasonParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cause(cause) => write!(formatter, "cause={cause}"),
            Self::Text(text) => {
                formatter.write_str("text=")?;
                write_quoted(formatter, text)
            }
            Self::Location(location) => write!(formatter, "location={location}"),
            Self::Extension(parameter) => fmt::Display::fmt(parameter, formatter),
        }
    }
}

/// Generic extension parameter carried by a SIP `Reason` value.
#[derive(Clone, Debug)]
pub struct ExtensionParameter {
    name: Box<str>,
    value: Option<ParameterValue>,
}

impl ExtensionParameter {
    /// Creates a generic extension parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the name is invalid, reserved, or exceeds
    /// its configured size bound.
    pub fn new(
        name: impl Into<Box<str>>,
        value: Option<ParameterValue>,
    ) -> Result<Self, ParseError> {
        let name = name.into();

        validate_extension_name(name.as_bytes())?;

        Ok(Self { name, value })
    }

    /// Returns the parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional parameter value.
    #[must_use]
    pub const fn value(&self) -> Option<&ParameterValue> {
        self.value.as_ref()
    }

    fn serialized_len(&self) -> usize {
        self.name.len()
            + self
                .value
                .as_ref()
                .map_or(0, |value| 1 + value.serialized_len())
    }
}

impl PartialEq for ExtensionParameter {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq_ignore_ascii_case(&other.name) && self.value == other.value
    }
}

impl Eq for ExtensionParameter {}

impl fmt::Display for ExtensionParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)?;

        if let Some(value) = &self.value {
            formatter.write_char('=')?;
            fmt::Display::fmt(value, formatter)?;
        }

        Ok(())
    }
}

/// Value of a generic SIP `Reason` extension parameter.
///
/// Unknown extension semantics are deliberately not guessed. Bare extension
/// values therefore retain exact case for both representation and equality.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParameterValue {
    /// Unquoted SIP token or bracketed IPv6 host representation.
    Bare(Box<str>),

    /// Logical quoted-string text.
    Quoted(Box<str>),
}

impl ParameterValue {
    /// Creates an unquoted generic value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the value is empty, invalid, or exceeds its
    /// operational bound.
    pub fn bare(value: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let value = value.into();

        validate_bare_extension_value(value.as_bytes())?;

        Ok(Self::Bare(value))
    }

    /// Creates a logical quoted-string extension value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the logical text contains an unsupported
    /// control byte or exceeds its operational bound.
    pub fn quoted(value: impl Into<Box<str>>) -> Result<Self, ParseError> {
        let value = value.into();

        validate_quoted_logical(&value, QuotedKind::Extension)?;

        Ok(Self::Quoted(value))
    }

    /// Returns the logical value without surrounding quotes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Bare(value) | Self::Quoted(value) => value,
        }
    }

    /// Returns whether quoted-string serialization is used.
    #[must_use]
    pub const fn is_quoted(&self) -> bool {
        matches!(self, Self::Quoted(_))
    }

    fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.first() == Some(&b'"') {
            return Ok(Self::Quoted(parse_quoted(input, QuotedKind::Extension)?));
        }

        let value = std::str::from_utf8(input).map_err(|_| ParseError::InvalidExtensionValue)?;

        Self::bare(value)
    }

    fn serialized_len(&self) -> usize {
        match self {
            Self::Bare(value) => value.len(),
            Self::Quoted(value) => quoted_serialized_len(value),
        }
    }
}

impl fmt::Display for ParameterValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bare(value) => formatter.write_str(value),
            Self::Quoted(value) => write_quoted(formatter, value),
        }
    }
}

/// Error returned when an accessor requiring one unambiguous occurrence finds
/// multiple matching parameters.
///
/// Parsing itself preserves repeated parameters and does not produce this
/// error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiplicityError {
    count: usize,
}

impl MultiplicityError {
    /// Returns the number of matching occurrences that caused ambiguity.
    #[must_use]
    pub const fn count(self) -> usize {
        self.count
    }
}

impl fmt::Display for MultiplicityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SIP Reason parameter is ambiguous because {} occurrences are present",
            self.count
        )
    }
}

impl StdError for MultiplicityError {}

/// Parses a complete SIP `Reason` field value.
///
/// Leading and trailing spaces and horizontal tabs are accepted.
///
/// # Errors
///
/// Returns [`ParseError`] when syntax is invalid or an operational bound is
/// exceeded.
pub fn parse(input: &[u8]) -> Result<Reason, ParseError> {
    if input.len() > MAX_REASON_BYTES {
        return Err(ParseError::TooLong {
            length: input.len(),
            maximum: MAX_REASON_BYTES,
        });
    }

    if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ParseError::InvalidLineBreak);
    }

    let input = trim_lws(input);

    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut values = Vec::new();
    let mut offset = 0_usize;

    loop {
        if values.len() >= MAX_REASON_VALUES {
            return Err(ParseError::TooManyValues {
                maximum: MAX_REASON_VALUES,
            });
        }

        let remaining = &input[offset..];
        let comma = find_top_level_delimiter(remaining, b',')?;
        let length = comma.unwrap_or(remaining.len());
        let segment = trim_lws(&remaining[..length]);

        if segment.is_empty() {
            return Err(ParseError::EmptyReasonValue);
        }

        values.push(parse_reason_value(segment)?);

        let Some(comma_offset) = comma else {
            break;
        };

        offset += comma_offset + 1;

        if offset >= input.len() {
            return Err(ParseError::EmptyReasonValue);
        }
    }

    Reason::from_values(values)
}

fn parse_reason_value(input: &[u8]) -> Result<ReasonValue, ParseError> {
    let protocol_length = input
        .iter()
        .take_while(|byte| is_token_byte(**byte))
        .count();

    if protocol_length == 0 {
        return Err(ParseError::InvalidProtocol);
    }

    if protocol_length > MAX_REASON_PROTOCOL_BYTES {
        return Err(ParseError::ProtocolTooLong {
            length: protocol_length,
            maximum: MAX_REASON_PROTOCOL_BYTES,
        });
    }

    let protocol_text =
        std::str::from_utf8(&input[..protocol_length]).map_err(|_| ParseError::InvalidProtocol)?;

    let mut reason_value = ReasonValue::new(ReasonProtocol::new(protocol_text)?);
    let mut offset = protocol_length;

    skip_lws(input, &mut offset);

    while offset < input.len() {
        if input[offset] != b';' {
            return Err(ParseError::UnexpectedByte {
                index: offset,
                byte: input[offset],
            });
        }

        offset += 1;
        skip_lws(input, &mut offset);

        if offset >= input.len() {
            return Err(ParseError::MissingParameterName);
        }

        let remaining = &input[offset..];
        let semicolon = find_top_level_delimiter(remaining, b';')?;
        let length = semicolon.unwrap_or(remaining.len());
        let parameter_input = trim_lws(&remaining[..length]);

        if parameter_input.is_empty() {
            return Err(ParseError::MissingParameterName);
        }

        reason_value.push_parameter(parse_parameter(parameter_input)?)?;

        let Some(semicolon_offset) = semicolon else {
            break;
        };

        // Keep the cursor on the next semicolon. The next iteration validates
        // and consumes that delimiter before parsing the following parameter.
        offset += semicolon_offset;
    }

    Ok(reason_value)
}

fn parse_parameter(input: &[u8]) -> Result<ReasonParameter, ParseError> {
    let name_length = input
        .iter()
        .take_while(|byte| is_token_byte(**byte))
        .count();

    if name_length == 0 {
        return Err(ParseError::InvalidParameterName);
    }

    if name_length > MAX_REASON_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: name_length,
            maximum: MAX_REASON_PARAMETER_NAME_BYTES,
        });
    }

    let name =
        std::str::from_utf8(&input[..name_length]).map_err(|_| ParseError::InvalidParameterName)?;

    let mut offset = name_length;
    skip_lws(input, &mut offset);

    if offset == input.len() {
        if is_reserved_parameter_name(name) {
            return Err(ParseError::MissingParameterValue);
        }

        return ReasonParameter::extension(name, None);
    }

    if input[offset] != b'=' {
        return Err(ParseError::UnexpectedByte {
            index: offset,
            byte: input[offset],
        });
    }

    offset += 1;
    skip_lws(input, &mut offset);

    if offset == input.len() {
        return Err(ParseError::MissingParameterValue);
    }

    let value = trim_lws(&input[offset..]);

    if name.eq_ignore_ascii_case("cause") {
        return ReasonParameter::cause_digits(value);
    }

    if name.eq_ignore_ascii_case("text") {
        if value.first() != Some(&b'"') {
            return Err(ParseError::TextMustBeQuoted);
        }

        return Ok(ReasonParameter::Text(parse_quoted(
            value,
            QuotedKind::Text,
        )?));
    }

    if name.eq_ignore_ascii_case("location") {
        return Ok(ReasonParameter::Location(IsupLocation::from_bytes(value)?));
    }

    ReasonParameter::extension(name, Some(ParameterValue::from_bytes(value)?))
}

fn find_top_level_delimiter(input: &[u8], delimiter: u8) -> Result<Option<usize>, ParseError> {
    let mut quoted = false;
    let mut index = 0_usize;

    while index < input.len() {
        match input[index] {
            b'"' => {
                quoted = !quoted;
                index += 1;
            }
            b'\\' if quoted => {
                if index + 1 >= input.len() {
                    return Err(ParseError::UnterminatedQuotedPair);
                }

                index += 2;
            }
            byte if !quoted && byte == delimiter => {
                return Ok(Some(index));
            }
            _ => {
                index += 1;
            }
        }
    }

    if quoted {
        return Err(ParseError::UnterminatedQuotedString);
    }

    Ok(None)
}

fn parse_quoted(input: &[u8], kind: QuotedKind) -> Result<Box<str>, ParseError> {
    if input.first() != Some(&b'"') {
        return Err(ParseError::ExpectedQuotedString);
    }

    let mut decoded = Vec::with_capacity(input.len().min(kind.maximum()));
    let mut index = 1_usize;

    while index < input.len() {
        match input[index] {
            b'"' => {
                if index + 1 != input.len() {
                    return Err(ParseError::UnexpectedByte {
                        index: index + 1,
                        byte: input[index + 1],
                    });
                }

                let text = String::from_utf8(decoded).map_err(|_| ParseError::InvalidQuotedUtf8)?;

                return Ok(text.into_boxed_str());
            }
            b'\\' => {
                let Some(escaped) = input.get(index + 1).copied() else {
                    return Err(ParseError::UnterminatedQuotedPair);
                };

                if is_invalid_quoted_control(escaped) {
                    return Err(ParseError::InvalidQuotedByte {
                        index: index + 1,
                        byte: escaped,
                    });
                }

                push_quoted_byte(&mut decoded, escaped, kind)?;
                index += 2;
            }
            byte if is_invalid_quoted_control(byte) => {
                return Err(ParseError::InvalidQuotedByte { index, byte });
            }
            byte => {
                push_quoted_byte(&mut decoded, byte, kind)?;
                index += 1;
            }
        }
    }

    Err(ParseError::UnterminatedQuotedString)
}

fn push_quoted_byte(decoded: &mut Vec<u8>, byte: u8, kind: QuotedKind) -> Result<(), ParseError> {
    let length = decoded.len().saturating_add(1);

    if length > kind.maximum() {
        return Err(kind.too_long(length));
    }

    decoded.push(byte);
    Ok(())
}

fn validate_protocol(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() || !input.iter().copied().all(is_token_byte) {
        return Err(ParseError::InvalidProtocol);
    }

    if input.len() > MAX_REASON_PROTOCOL_BYTES {
        return Err(ParseError::ProtocolTooLong {
            length: input.len(),
            maximum: MAX_REASON_PROTOCOL_BYTES,
        });
    }

    Ok(())
}

fn validate_extension_name(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() || !input.iter().copied().all(is_token_byte) {
        return Err(ParseError::InvalidParameterName);
    }

    if input.len() > MAX_REASON_PARAMETER_NAME_BYTES {
        return Err(ParseError::ParameterNameTooLong {
            length: input.len(),
            maximum: MAX_REASON_PARAMETER_NAME_BYTES,
        });
    }

    let name = std::str::from_utf8(input).map_err(|_| ParseError::InvalidParameterName)?;

    if is_reserved_parameter_name(name) {
        return Err(ParseError::ReservedParameterName);
    }

    Ok(())
}

fn validate_bare_extension_value(input: &[u8]) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::InvalidExtensionValue);
    }

    if input.len() > MAX_REASON_EXTENSION_VALUE_BYTES {
        return Err(ParseError::ExtensionValueTooLong {
            length: input.len(),
            maximum: MAX_REASON_EXTENSION_VALUE_BYTES,
        });
    }

    if input.iter().copied().all(is_token_byte) || is_ipv6_reference(input) {
        return Ok(());
    }

    Err(ParseError::InvalidExtensionValue)
}

fn validate_quoted_logical(text: &str, kind: QuotedKind) -> Result<(), ParseError> {
    if text.len() > kind.maximum() {
        return Err(kind.too_long(text.len()));
    }

    if let Some((index, byte)) = text
        .as_bytes()
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| is_invalid_quoted_control(*byte))
    {
        return Err(ParseError::InvalidQuotedByte { index, byte });
    }

    Ok(())
}

fn unique_item<T>(mut iterator: impl Iterator<Item = T>) -> Result<Option<T>, MultiplicityError> {
    let Some(first) = iterator.next() else {
        return Ok(None);
    };

    if iterator.next().is_none() {
        return Ok(Some(first));
    }

    Err(MultiplicityError {
        count: 2 + iterator.count(),
    })
}

fn quoted_serialized_len(text: &str) -> usize {
    let escapes = text
        .as_bytes()
        .iter()
        .filter(|byte| matches!(**byte, b'"' | b'\\'))
        .count();

    2_usize.saturating_add(text.len()).saturating_add(escapes)
}

fn write_quoted(formatter: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
    formatter.write_char('"')?;

    for character in text.chars() {
        match character {
            '"' => formatter.write_str("\\\"")?,
            '\\' => formatter.write_str("\\\\")?,
            _ => formatter.write_char(character)?,
        }
    }

    formatter.write_char('"')
}

fn is_reserved_parameter_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("cause")
        || name.eq_ignore_ascii_case("text")
        || name.eq_ignore_ascii_case("location")
}

fn is_ipv6_reference(input: &[u8]) -> bool {
    if input.len() < 3 || input.first() != Some(&b'[') || input.last() != Some(&b']') {
        return false;
    }

    let address = &input[1..input.len() - 1];

    let Ok(address) = std::str::from_utf8(address) else {
        return false;
    };

    Ipv6Addr::from_str(address).is_ok()
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

fn skip_lws(input: &[u8], offset: &mut usize) {
    while *offset < input.len() && is_lws(input[*offset]) {
        *offset += 1;
    }
}

fn eq_ascii(left: &[u8], right: &[u8]) -> bool {
    left.eq_ignore_ascii_case(right)
}

const fn is_lws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

const fn is_invalid_quoted_control(byte: u8) -> bool {
    byte != b'\t' && byte.is_ascii_control()
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

#[derive(Clone, Copy)]
enum QuotedKind {
    Text,
    Extension,
}

impl QuotedKind {
    const fn maximum(self) -> usize {
        match self {
            Self::Text => MAX_REASON_TEXT_BYTES,
            Self::Extension => MAX_REASON_EXTENSION_VALUE_BYTES,
        }
    }

    const fn too_long(self, length: usize) -> ParseError {
        match self {
            Self::Text => ParseError::TextTooLong {
                length,
                maximum: MAX_REASON_TEXT_BYTES,
            },
            Self::Extension => ParseError::ExtensionValueTooLong {
                length,
                maximum: MAX_REASON_EXTENSION_VALUE_BYTES,
            },
        }
    }
}

/// Failure to parse or construct a SIP `Reason` field value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The field value was empty.
    Empty,

    /// The complete field value exceeded the configured size bound.
    TooLong {
        /// Actual serialized or input length in bytes.
        length: usize,

        /// Maximum accepted length in bytes.
        maximum: usize,
    },

    /// A CR or LF appeared inside the field value.
    InvalidLineBreak,

    /// The field exceeded the bounded reason-value count.
    TooManyValues {
        /// Maximum accepted reason-value count.
        maximum: usize,
    },

    /// A comma produced an empty reason value.
    EmptyReasonValue,

    /// The reason protocol token was invalid.
    InvalidProtocol,

    /// The protocol token exceeded its operational size bound.
    ProtocolTooLong {
        /// Actual protocol length in bytes.
        length: usize,

        /// Maximum accepted protocol length in bytes.
        maximum: usize,
    },

    /// A reason value exceeded the bounded parameter count.
    TooManyParameters {
        /// Maximum accepted parameter count.
        maximum: usize,
    },

    /// A parameter name was missing.
    MissingParameterName,

    /// A parameter name was invalid.
    InvalidParameterName,

    /// A parameter name exceeded its operational size bound.
    ParameterNameTooLong {
        /// Actual parameter-name length in bytes.
        length: usize,

        /// Maximum accepted parameter-name length in bytes.
        maximum: usize,
    },

    /// An extension constructor attempted to use a typed parameter name.
    ReservedParameterName,

    /// A parameter requiring a value did not contain one.
    MissingParameterValue,

    /// A `cause` parameter was not a non-empty decimal digit sequence.
    InvalidCause,

    /// A decimal `cause` representation exceeded its operational bound.
    CauseTooLong {
        /// Actual decimal representation length in bytes.
        length: usize,

        /// Maximum accepted representation length in bytes.
        maximum: usize,
    },

    /// A `text` parameter was not encoded as a quoted string.
    TextMustBeQuoted,

    /// Logical reason text exceeded its operational size bound.
    TextTooLong {
        /// Actual logical text length in bytes.
        length: usize,

        /// Maximum accepted logical text length in bytes.
        maximum: usize,
    },

    /// A quoted string was expected.
    ExpectedQuotedString,

    /// A quoted string did not contain a terminating quote.
    UnterminatedQuotedString,

    /// A quoted-pair escape did not contain an escaped byte.
    UnterminatedQuotedPair,

    /// A quoted value contained an unsupported control byte.
    InvalidQuotedByte {
        /// Byte offset within the quoted representation or logical text.
        index: usize,

        /// Invalid byte.
        byte: u8,
    },

    /// Decoded quoted text was not valid UTF-8.
    InvalidQuotedUtf8,

    /// A `Q.850` release-location token was invalid.
    InvalidLocation,

    /// An extension parameter value exceeded its operational size bound.
    ExtensionValueTooLong {
        /// Actual value length in bytes.
        length: usize,

        /// Maximum accepted value length in bytes.
        maximum: usize,
    },

    /// An unquoted generic extension value was invalid.
    InvalidExtensionValue,

    /// An unexpected byte appeared where a separator was required.
    UnexpectedByte {
        /// Byte offset within the current reason value or parameter.
        index: usize,

        /// Unexpected byte.
        byte: u8,
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
            Self::TooManyValues { .. } => "too-many-values",
            Self::EmptyReasonValue => "empty-reason-value",
            Self::InvalidProtocol => "invalid-protocol",
            Self::ProtocolTooLong { .. } => "protocol-too-long",
            Self::TooManyParameters { .. } => "too-many-parameters",
            Self::MissingParameterName => "missing-parameter-name",
            Self::InvalidParameterName => "invalid-parameter-name",
            Self::ParameterNameTooLong { .. } => "parameter-name-too-long",
            Self::ReservedParameterName => "reserved-parameter-name",
            Self::MissingParameterValue => "missing-parameter-value",
            Self::InvalidCause => "invalid-cause",
            Self::CauseTooLong { .. } => "cause-too-long",
            Self::TextMustBeQuoted => "text-must-be-quoted",
            Self::TextTooLong { .. } => "text-too-long",
            Self::ExpectedQuotedString => "expected-quoted-string",
            Self::UnterminatedQuotedString => "unterminated-quoted-string",
            Self::UnterminatedQuotedPair => "unterminated-quoted-pair",
            Self::InvalidQuotedByte { .. } => "invalid-quoted-byte",
            Self::InvalidQuotedUtf8 => "invalid-quoted-utf8",
            Self::InvalidLocation => "invalid-location",
            Self::ExtensionValueTooLong { .. } => "extension-value-too-long",
            Self::InvalidExtensionValue => "invalid-extension-value",
            Self::UnexpectedByte { .. } => "unexpected-byte",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SIP Reason field value is empty"),
            Self::TooLong { length, maximum } => write!(
                formatter,
                "SIP Reason field-value length {length} exceeds maximum {maximum}"
            ),
            Self::InvalidLineBreak => {
                formatter.write_str("SIP Reason contains an invalid line break")
            }
            Self::TooManyValues { maximum } => {
                write!(
                    formatter,
                    "SIP Reason contains more than {maximum} reason values"
                )
            }
            Self::EmptyReasonValue => {
                formatter.write_str("SIP Reason contains an empty reason value")
            }
            Self::InvalidProtocol => formatter.write_str("SIP Reason protocol token is invalid"),
            Self::ProtocolTooLong { length, maximum } => write!(
                formatter,
                "SIP Reason protocol length {length} exceeds maximum {maximum}"
            ),
            Self::TooManyParameters { maximum } => write!(
                formatter,
                "SIP Reason value contains more than {maximum} parameters"
            ),
            Self::MissingParameterName => {
                formatter.write_str("SIP Reason parameter name is missing")
            }
            Self::InvalidParameterName => {
                formatter.write_str("SIP Reason parameter name is invalid")
            }
            Self::ParameterNameTooLong { length, maximum } => write!(
                formatter,
                "SIP Reason parameter-name length {length} exceeds maximum {maximum}"
            ),
            Self::ReservedParameterName => {
                formatter.write_str("SIP Reason extension uses a reserved parameter name")
            }
            Self::MissingParameterValue => {
                formatter.write_str("SIP Reason parameter value is missing")
            }
            Self::InvalidCause => {
                formatter.write_str("SIP Reason cause must contain decimal digits")
            }
            Self::CauseTooLong { length, maximum } => write!(
                formatter,
                "SIP Reason cause length {length} exceeds maximum {maximum}"
            ),
            Self::TextMustBeQuoted => {
                formatter.write_str("SIP Reason text parameter must be a quoted string")
            }
            Self::TextTooLong { length, maximum } => write!(
                formatter,
                "SIP Reason text length {length} exceeds maximum {maximum}"
            ),
            Self::ExpectedQuotedString => {
                formatter.write_str("SIP Reason parameter requires a quoted string")
            }
            Self::UnterminatedQuotedString => {
                formatter.write_str("SIP Reason quoted string is unterminated")
            }
            Self::UnterminatedQuotedPair => {
                formatter.write_str("SIP Reason quoted-pair escape is unterminated")
            }
            Self::InvalidQuotedByte { index, byte } => write!(
                formatter,
                "invalid SIP Reason quoted byte 0x{byte:02x} at offset {index}"
            ),
            Self::InvalidQuotedUtf8 => {
                formatter.write_str("SIP Reason quoted value is not valid UTF-8")
            }
            Self::InvalidLocation => {
                formatter.write_str("SIP Reason Q.850 location value is invalid")
            }
            Self::ExtensionValueTooLong { length, maximum } => write!(
                formatter,
                "SIP Reason extension-value length {length} exceeds maximum {maximum}"
            ),
            Self::InvalidExtensionValue => {
                formatter.write_str("SIP Reason extension parameter value is invalid")
            }
            Self::UnexpectedByte { index, byte } => write!(
                formatter,
                "unexpected SIP Reason byte 0x{byte:02x} at offset {index}"
            ),
        }
    }
}

impl StdError for ParseError {}

#[cfg(test)]
mod tests {
    use super::{
        IsupLocation, MAX_REASON_BYTES, MAX_REASON_CAUSE_BYTES, MAX_REASON_PARAMETERS,
        MAX_REASON_VALUES, MultiplicityError, ParameterValue, ParseError, Reason, ReasonCause,
        ReasonParameter, ReasonProtocol, ReasonValue, parse,
    };
    use std::str::FromStr;

    #[test]
    fn parses_sip_reason() {
        let Ok(reason) = parse(b"SIP ;cause=200 ;text=\"Call completed elsewhere\"") else {
            panic!("expected valid SIP Reason");
        };

        assert_eq!(reason.value_count(), 1);
        assert_eq!(reason.first().protocol(), &ReasonProtocol::Sip);

        assert_eq!(
            reason
                .first()
                .unique_cause()
                .ok()
                .flatten()
                .and_then(ReasonCause::as_u16),
            Some(200)
        );

        assert_eq!(
            reason.first().unique_text(),
            Ok(Some("Call completed elsewhere"))
        );

        assert_eq!(
            reason.to_string(),
            "SIP;cause=200;text=\"Call completed elsewhere\""
        );
    }

    #[test]
    fn parses_q850_reason() {
        let Ok(reason) = parse(b"Q.850 ;cause=16 ;text=\"Terminated\"") else {
            panic!("expected valid Q.850 Reason");
        };

        assert_eq!(reason.first().protocol(), &ReasonProtocol::Q850);

        assert_eq!(
            reason
                .first()
                .unique_cause()
                .ok()
                .flatten()
                .and_then(ReasonCause::as_u16),
            Some(16)
        );

        assert_eq!(reason.first().unique_text(), Ok(Some("Terminated")));
    }

    #[test]
    fn parses_multiple_reason_values() {
        let Ok(reason) = parse(b"SIP;cause=486, Q.850;cause=17;text=\"User busy\"") else {
            panic!("expected multiple Reason values");
        };

        assert_eq!(reason.value_count(), 2);

        assert_eq!(
            reason.to_string(),
            "SIP;cause=486, Q.850;cause=17;text=\"User busy\""
        );
    }

    #[test]
    fn repeated_protocol_values_are_preserved() {
        let Ok(reason) = parse(b"Example;cause=1, example;cause=2") else {
            panic!("expected repeated protocol values");
        };

        let Ok(protocol) = ReasonProtocol::new("EXAMPLE") else {
            panic!("expected protocol");
        };

        assert_eq!(reason.protocol_count(&protocol), 2);
        assert_eq!(reason.value_count(), 2);
    }

    #[test]
    fn protocol_without_parameters_is_valid() {
        let Ok(reason) = parse(b"ExampleProtocol") else {
            panic!("expected protocol-only Reason");
        };

        assert_eq!(reason.first().parameter_count(), 0);
    }

    #[test]
    fn cause_is_not_syntactically_required() {
        let Ok(reason) = parse(b"SIP;text=\"diagnostic\"") else {
            panic!("expected Reason without cause");
        };

        assert_eq!(reason.first().unique_cause(), Ok(None));
        assert_eq!(reason.first().unique_text(), Ok(Some("diagnostic")));
    }

    #[test]
    fn known_protocols_are_canonicalized() {
        let Ok(reason) = parse(b"sIp;cause=486, q.850;cause=16") else {
            panic!("expected known protocols");
        };

        assert_eq!(reason.to_string(), "SIP;cause=486, Q.850;cause=16");
    }

    #[test]
    fn extension_protocol_spelling_is_preserved() {
        let Ok(reason) = parse(b"Preemption;cause=2") else {
            panic!("expected extension protocol");
        };

        assert_eq!(reason.first().protocol().as_str(), "Preemption");
    }

    #[test]
    fn parses_q850_location() {
        let Ok(reason) = parse(b"Q.850;cause=1;location=LN") else {
            panic!("expected Q.850 location");
        };

        assert_eq!(reason.first().unique_location(), Ok(Some(IsupLocation::Ln)));

        assert_eq!(
            reason.first().unique_q850_location(),
            Ok(Some(IsupLocation::Ln))
        );
    }

    #[test]
    fn location_is_case_insensitive_and_canonicalized() {
        let Ok(reason) = parse(b"Q.850;cause=16;location=intl") else {
            panic!("expected Q.850 location");
        };

        assert_eq!(
            reason.first().unique_location(),
            Ok(Some(IsupLocation::Intl))
        );

        assert_eq!(reason.to_string(), "Q.850;cause=16;location=INTL");
    }

    #[test]
    fn location_on_non_q850_protocol_is_preserved_but_not_effective() {
        let Ok(reason) = parse(b"SIP;cause=486;location=LN") else {
            panic!("expected syntactically valid location");
        };

        assert_eq!(reason.first().unique_location(), Ok(Some(IsupLocation::Ln)));

        assert_eq!(reason.first().unique_q850_location(), Ok(None));
    }

    #[test]
    fn parses_all_q850_locations() {
        let values = [
            ("U", IsupLocation::U),
            ("LPN", IsupLocation::Lpn),
            ("LN", IsupLocation::Ln),
            ("TN", IsupLocation::Tn),
            ("RLN", IsupLocation::Rln),
            ("RPN", IsupLocation::Rpn),
            ("LOC-6", IsupLocation::Loc6),
            ("INTL", IsupLocation::Intl),
            ("LOC-8", IsupLocation::Loc8),
            ("LOC-9", IsupLocation::Loc9),
            ("BI", IsupLocation::Bi),
            ("LOC-11", IsupLocation::Loc11),
            ("LOC-12", IsupLocation::Loc12),
            ("LOC-13", IsupLocation::Loc13),
            ("LOC-14", IsupLocation::Loc14),
            ("LOC-15", IsupLocation::Loc15),
        ];

        for (wire, expected) in values {
            let Ok(location) = IsupLocation::from_str(wire) else {
                panic!("expected valid location");
            };

            assert_eq!(location, expected);
            assert_eq!(location.to_string(), wire);
        }
    }

    #[test]
    fn preserves_duplicate_cause_parameters() {
        let Ok(reason) = parse(b"SIP;cause=486;CAUSE=487") else {
            panic!("expected duplicate causes to be preserved");
        };

        let causes: Vec<_> = reason.first().causes().map(ReasonCause::as_str).collect();

        assert_eq!(causes, ["486", "487"]);
        assert_eq!(reason.first().parameter_count(), 2);

        assert_eq!(reason.to_string(), "SIP;cause=486;cause=487");
    }

    #[test]
    fn duplicate_cause_is_reported_as_ambiguous_by_unique_accessor() {
        let Ok(reason) = parse(b"SIP;cause=486;cause=487") else {
            panic!("expected duplicate causes");
        };

        assert_eq!(
            reason.first().unique_cause(),
            Err(MultiplicityError { count: 2 })
        );
    }

    #[test]
    fn preserves_duplicate_text_parameters() {
        let Ok(reason) = parse(b"SIP;text=\"one\";TEXT=\"two\"") else {
            panic!("expected duplicate text parameters");
        };

        let texts: Vec<_> = reason.first().texts().collect();

        assert_eq!(texts, ["one", "two"]);

        assert_eq!(
            reason.first().unique_text(),
            Err(MultiplicityError { count: 2 })
        );
    }

    #[test]
    fn preserves_duplicate_location_parameters() {
        let Ok(reason) = parse(b"Q.850;location=LN;LOCATION=TN") else {
            panic!("expected duplicate locations");
        };

        let locations: Vec<_> = reason.first().locations().collect();

        assert_eq!(locations, [IsupLocation::Ln, IsupLocation::Tn]);

        assert_eq!(
            reason.first().unique_location(),
            Err(MultiplicityError { count: 2 })
        );
    }

    #[test]
    fn preserves_duplicate_extension_parameters() {
        let Ok(reason) = parse(b"Example;vendor=one;VENDOR=two") else {
            panic!("expected duplicate extension parameters");
        };

        let parameters: Vec<_> = reason.first().parameters_named("vendor").collect();

        assert_eq!(parameters.len(), 2);

        assert_eq!(
            reason.first().unique_parameter("vendor"),
            Err(MultiplicityError { count: 2 })
        );

        assert_eq!(reason.to_string(), "Example;vendor=one;VENDOR=two");
    }

    #[test]
    fn duplicate_parameter_order_is_preserved() {
        let Ok(reason) = parse(b"SIP;cause=486;text=\"one\";cause=487;text=\"two\"") else {
            panic!("expected duplicate parameters");
        };

        assert_eq!(reason.first().parameters()[0].name(), "cause");
        assert_eq!(reason.first().parameters()[1].name(), "text");
        assert_eq!(reason.first().parameters()[2].name(), "cause");
        assert_eq!(reason.first().parameters()[3].name(), "text");
    }

    #[test]
    fn first_accessors_are_explicit_about_first_value_semantics() {
        let Ok(reason) = parse(b"SIP;cause=486;cause=487;text=\"one\";text=\"two\"") else {
            panic!("expected duplicate parameters");
        };

        assert_eq!(
            reason.first().first_cause().map(ReasonCause::as_str),
            Some("486")
        );

        assert_eq!(reason.first().first_text(), Some("one"));
    }

    #[test]
    fn unique_parameter_returns_single_value() {
        let Ok(reason) = parse(b"Example;vendor=value") else {
            panic!("expected extension parameter");
        };

        let Ok(Some(parameter)) = reason.first().unique_parameter("VENDOR") else {
            panic!("expected unique extension parameter");
        };

        assert_eq!(parameter.name(), "vendor");
    }

    #[test]
    fn multiplicity_error_reports_occurrence_count() {
        let Ok(reason) = parse(b"SIP;cause=1;cause=2;cause=3") else {
            panic!("expected repeated causes");
        };

        let Err(error) = reason.first().unique_cause() else {
            panic!("expected ambiguity");
        };

        assert_eq!(error.count(), 3);
    }

    #[test]
    fn parses_extension_flag_parameter() {
        let Ok(reason) = parse(b"Example;flag") else {
            panic!("expected extension flag");
        };

        let Some(parameter) = reason.first().first_parameter("FLAG") else {
            panic!("expected extension flag");
        };

        let Some(extension) = parameter.as_extension() else {
            panic!("expected extension parameter");
        };

        assert_eq!(extension.name(), "flag");
        assert_eq!(extension.value(), None);
    }

    #[test]
    fn parses_extension_bare_parameter() {
        let Ok(reason) = parse(b"Example;vendor=value") else {
            panic!("expected extension parameter");
        };

        let Some(parameter) = reason.first().first_parameter("vendor") else {
            panic!("expected extension parameter");
        };

        let Some(extension) = parameter.as_extension() else {
            panic!("expected extension parameter");
        };

        let Some(value) = extension.value() else {
            panic!("expected extension value");
        };

        assert_eq!(value.as_str(), "value");
        assert!(!value.is_quoted());
    }

    #[test]
    fn parses_extension_ipv6_host() {
        let Ok(reason) = parse(b"Example;source=[2001:db8::1]") else {
            panic!("expected IPv6 extension value");
        };

        assert_eq!(reason.to_string(), "Example;source=[2001:db8::1]");
    }

    #[test]
    fn quoted_extension_may_contain_delimiters() {
        let Ok(reason) = parse(b"Example;note=\"one;two,three\";flag") else {
            panic!("expected quoted extension");
        };

        assert_eq!(reason.value_count(), 1);
        assert_eq!(reason.first().parameter_count(), 2);

        let Some(parameter) = reason.first().first_parameter("note") else {
            panic!("expected note parameter");
        };

        let Some(extension) = parameter.as_extension() else {
            panic!("expected extension parameter");
        };

        let Some(value) = extension.value() else {
            panic!("expected value");
        };

        assert_eq!(value.as_str(), "one;two,three");
        assert!(value.is_quoted());
    }

    #[test]
    fn quoted_text_may_contain_delimiters() {
        let Ok(reason) = parse(b"SIP;cause=200;text=\"one;two,three\"") else {
            panic!("expected quoted text");
        };

        assert_eq!(reason.first().unique_text(), Ok(Some("one;two,three")));
    }

    #[test]
    fn quoted_text_decodes_and_reencodes_escapes() {
        let Ok(reason) = parse(b"SIP;text=\"say \\\"hello\\\" \\\\ done\"") else {
            panic!("expected escaped text");
        };

        assert_eq!(
            reason.first().unique_text(),
            Ok(Some("say \"hello\" \\ done"))
        );

        assert_eq!(
            reason.to_string(),
            "SIP;text=\"say \\\"hello\\\" \\\\ done\""
        );
    }

    #[test]
    fn quoted_text_supports_utf8() {
        let input = "SIP;text=\"Riyadh الرياض\"";

        let Ok(reason) = parse(input.as_bytes()) else {
            panic!("expected UTF-8 text");
        };

        assert_eq!(reason.first().unique_text(), Ok(Some("Riyadh الرياض")));
    }

    #[test]
    fn cause_leading_zeroes_are_preserved() {
        let Ok(reason) = parse(b"Q.850;cause=0016") else {
            panic!("expected cause");
        };

        let Ok(Some(cause)) = reason.first().unique_cause() else {
            panic!("expected unique cause");
        };

        assert_eq!(cause.as_str(), "0016");
        assert_eq!(cause.as_u16(), Some(16));
        assert_eq!(reason.to_string(), "Q.850;cause=0016");
    }

    #[test]
    fn numerically_equivalent_causes_compare_equal() {
        let Ok(first) = ReasonCause::from_str("0016") else {
            panic!("expected first cause");
        };

        let Ok(second) = ReasonCause::from_str("16") else {
            panic!("expected second cause");
        };

        assert_eq!(first, second);
    }

    #[test]
    fn large_bounded_decimal_cause_is_preserved() {
        let digits = "9".repeat(MAX_REASON_CAUSE_BYTES);

        let Ok(cause) = ReasonCause::from_str(&digits) else {
            panic!("expected bounded cause");
        };

        assert_eq!(cause.as_str(), digits);
        assert_eq!(cause.as_u32(), None);
    }

    #[test]
    fn rejects_cause_above_operational_limit() {
        let digits = "9".repeat(MAX_REASON_CAUSE_BYTES + 1);

        assert_eq!(
            ReasonCause::from_str(&digits),
            Err(ParseError::CauseTooLong {
                length: MAX_REASON_CAUSE_BYTES + 1,
                maximum: MAX_REASON_CAUSE_BYTES,
            })
        );
    }

    #[test]
    fn unique_sip_status_code_accepts_standard_code() {
        let Ok(reason) = parse(b"SIP;cause=486") else {
            panic!("expected SIP cause");
        };

        assert_eq!(reason.first().unique_sip_status_code(), Ok(Some(486)));
    }

    #[test]
    fn unique_sip_status_code_rejects_non_status_value() {
        let Ok(reason) = parse(b"SIP;cause=42") else {
            panic!("expected SIP cause");
        };

        assert_eq!(reason.first().unique_sip_status_code(), Ok(None));
    }

    #[test]
    fn unique_sip_status_code_detects_ambiguous_causes() {
        let Ok(reason) = parse(b"SIP;cause=486;cause=487") else {
            panic!("expected repeated causes");
        };

        assert_eq!(
            reason.first().unique_sip_status_code(),
            Err(MultiplicityError { count: 2 })
        );
    }

    #[test]
    fn q850_cause_is_not_interpreted_as_sip_status() {
        let Ok(reason) = parse(b"Q.850;cause=486") else {
            panic!("expected Q.850 cause");
        };

        assert_eq!(reason.first().unique_sip_status_code(), Ok(None));
    }

    #[test]
    fn programmatic_construction_preserves_duplicate_parameters() {
        let mut value = ReasonValue::new(ReasonProtocol::Sip);

        assert!(value.push_parameter(ReasonParameter::cause(486)).is_ok());
        assert!(value.push_parameter(ReasonParameter::cause(487)).is_ok());

        assert_eq!(value.to_string(), "SIP;cause=486;cause=487");

        assert_eq!(value.unique_cause(), Err(MultiplicityError { count: 2 }));
    }

    #[test]
    fn extension_bare_value_preserves_case_semantics() {
        let Ok(first) = ParameterValue::bare("VALUE") else {
            panic!("expected first extension value");
        };

        let Ok(second) = ParameterValue::bare("value") else {
            panic!("expected second extension value");
        };

        assert_ne!(first, second);
    }

    #[test]
    fn rejects_reserved_extension_parameter_names() {
        assert_eq!(
            ReasonParameter::extension("CAUSE", None),
            Err(ParseError::ReservedParameterName)
        );

        assert_eq!(
            ReasonParameter::extension("Text", None),
            Err(ParseError::ReservedParameterName)
        );

        assert_eq!(
            ReasonParameter::extension("LOCATION", None),
            Err(ParseError::ReservedParameterName)
        );
    }

    #[test]
    fn rejects_empty_field() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b" \t "), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_empty_reason_values() {
        assert_eq!(parse(b", SIP;cause=486"), Err(ParseError::EmptyReasonValue));

        assert_eq!(parse(b"SIP;cause=486,"), Err(ParseError::EmptyReasonValue));

        assert_eq!(
            parse(b"SIP;cause=486, ,Q.850;cause=16"),
            Err(ParseError::EmptyReasonValue)
        );
    }

    #[test]
    fn rejects_invalid_protocol() {
        assert_eq!(parse(b"@invalid;cause=1"), Err(ParseError::InvalidProtocol));
    }

    #[test]
    fn rejects_missing_parameter_name() {
        assert_eq!(parse(b"SIP;"), Err(ParseError::MissingParameterName));

        assert_eq!(
            parse(b"SIP;;cause=486"),
            Err(ParseError::MissingParameterName)
        );
    }

    #[test]
    fn rejects_missing_cause_value() {
        assert_eq!(parse(b"SIP;cause"), Err(ParseError::MissingParameterValue));

        assert_eq!(parse(b"SIP;cause="), Err(ParseError::MissingParameterValue));
    }

    #[test]
    fn rejects_non_decimal_cause() {
        assert_eq!(parse(b"SIP;cause=48x"), Err(ParseError::InvalidCause));
    }

    #[test]
    fn rejects_unquoted_text() {
        assert_eq!(parse(b"SIP;text=Busy"), Err(ParseError::TextMustBeQuoted));
    }

    #[test]
    fn rejects_unterminated_quoted_text() {
        assert_eq!(
            parse(b"SIP;text=\"Busy"),
            Err(ParseError::UnterminatedQuotedString)
        );
    }

    #[test]
    fn rejects_unterminated_quoted_pair() {
        assert_eq!(
            parse(b"SIP;text=\"Busy\\"),
            Err(ParseError::UnterminatedQuotedPair)
        );
    }

    #[test]
    fn rejects_invalid_q850_location() {
        assert_eq!(
            parse(b"Q.850;cause=16;location=UNKNOWN"),
            Err(ParseError::InvalidLocation)
        );
    }

    #[test]
    fn rejects_invalid_unquoted_extension_value() {
        assert_eq!(
            parse(b"Example;value=hello/world"),
            Err(ParseError::InvalidExtensionValue)
        );
    }

    #[test]
    fn rejects_embedded_line_break() {
        assert_eq!(
            parse(b"SIP;cause=486\r\n"),
            Err(ParseError::InvalidLineBreak)
        );
    }

    #[test]
    fn rejects_field_above_operational_limit() {
        let input = vec![b'a'; MAX_REASON_BYTES + 1];

        assert_eq!(
            parse(&input),
            Err(ParseError::TooLong {
                length: MAX_REASON_BYTES + 1,
                maximum: MAX_REASON_BYTES,
            })
        );
    }

    #[test]
    fn enforces_reason_value_count_transactionally() {
        let mut values = Vec::new();

        for index in 0..MAX_REASON_VALUES {
            let protocol = format!("P{index}");

            let Ok(protocol) = ReasonProtocol::new(protocol) else {
                panic!("expected protocol");
            };

            values.push(ReasonValue::new(protocol));
        }

        let Ok(mut reason) = Reason::from_values(values) else {
            panic!("expected Reason at value-count limit");
        };

        let Ok(extra_protocol) = ReasonProtocol::new("Extra") else {
            panic!("expected protocol");
        };

        let before = reason.to_string();

        assert_eq!(
            reason.push(ReasonValue::new(extra_protocol)),
            Err(ParseError::TooManyValues {
                maximum: MAX_REASON_VALUES,
            })
        );

        assert_eq!(reason.to_string(), before);
    }

    #[test]
    fn enforces_parameter_count_transactionally() {
        let Ok(protocol) = ReasonProtocol::new("Example") else {
            panic!("expected protocol");
        };

        let mut value = ReasonValue::new(protocol);

        for index in 0..MAX_REASON_PARAMETERS {
            let name = format!("p{index}");

            let Ok(parameter) = ReasonParameter::extension(name, None) else {
                panic!("expected extension parameter");
            };

            assert!(value.push_parameter(parameter).is_ok());
        }

        let before = value.to_string();

        let Ok(extra) = ReasonParameter::extension("extra", None) else {
            panic!("expected extension parameter");
        };

        assert_eq!(
            value.push_parameter(extra),
            Err(ParseError::TooManyParameters {
                maximum: MAX_REASON_PARAMETERS,
            })
        );

        assert_eq!(value.to_string(), before);
    }

    #[test]
    fn serialized_lengths_match_output() {
        let Ok(reason) = parse(b"SIP;cause=486;text=\"Busy Here\", Q.850;cause=17;location=LN")
        else {
            panic!("expected valid Reason");
        };

        assert_eq!(reason.serialized_len(), reason.to_string().len());

        for value in reason.values() {
            assert_eq!(value.serialized_len(), value.to_string().len());
        }
    }

    #[test]
    fn parses_from_str() {
        let Ok(reason) = Reason::from_str("SIP;cause=486") else {
            panic!("expected Reason from string");
        };

        assert_eq!(reason.first().unique_sip_status_code(), Ok(Some(486)));
    }

    #[test]
    fn parse_error_classes_are_stable() {
        assert_eq!(ParseError::Empty.class(), "empty");

        assert_eq!(ParseError::InvalidLineBreak.class(), "invalid-line-break");

        assert_eq!(ParseError::EmptyReasonValue.class(), "empty-reason-value");

        assert_eq!(ParseError::InvalidProtocol.class(), "invalid-protocol");

        assert_eq!(ParseError::InvalidCause.class(), "invalid-cause");

        assert_eq!(ParseError::TextMustBeQuoted.class(), "text-must-be-quoted");

        assert_eq!(ParseError::InvalidLocation.class(), "invalid-location");

        assert_eq!(
            ParseError::InvalidExtensionValue.class(),
            "invalid-extension-value"
        );
    }
}
