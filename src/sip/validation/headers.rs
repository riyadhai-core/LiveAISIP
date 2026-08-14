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

//! Typed validation of transaction-critical SIP headers.
//!
//! The structural parser deliberately retains exact field-value bytes,
//! including boundary whitespace and legal line folding. This module provides
//! the single normalization boundary between that lossless representation and
//! the owned typed header parsers.
//!
//! Validation is intentionally limited to headers required by framing,
//! transactions, and dialog identification. Optional non-core headers remain
//! lossless and can be interpreted lazily by the feature that uses them.
//! Method-specific and contextual requirements, including request-line/CSeq
//! matching, branch-cookie policy, tags, and mandatory request
//! `Max-Forwards`, belong to request, response, transaction, or dialog
//! validation.

use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt;

use crate::sip::framing::{MAX_HEADER_BYTES, MAX_LINE_BYTES};
use crate::sip::headers::call_id::{CallId, MAX_CALL_ID_BYTES, ParseError as CallIdParseError};
use crate::sip::headers::content_length::{ContentLength, ParseError as ContentLengthParseError};
use crate::sip::headers::content_type::{
    ContentType, MAX_CONTENT_TYPE_BYTES, ParseError as ContentTypeParseError,
};
use crate::sip::headers::cseq::{CSeq, ParseError as CSeqParseError};
use crate::sip::headers::from::{FromHeader, MAX_FROM_BYTES, ParseError as FromParseError};
use crate::sip::headers::max_forwards::{MaxForwards, ParseError as MaxForwardsParseError};
use crate::sip::headers::to::{MAX_TO_BYTES, ParseError as ToParseError, ToHeader};
use crate::sip::headers::via::{
    self, BudgetedParseError as ViaBudgetedParseError, MAX_VIA_BYTES, ParseError as ViaParseError,
    Via, ViaEntry,
};
use crate::sip::types::header::{
    HeaderKind, HeaderNameError, MAX_HEADER_NAME_BYTES, MAX_HEADER_VALUE_BYTES,
};
use crate::sip::types::message::{RawHeaderView, RawMessage};

use super::message;

/// Maximum number of folded continuations accepted in one logical header.
///
/// This operational limit is independent of the physical-line and complete
/// header-section bounds applied by the framing layer.
pub const MAX_FOLDS_PER_CORE_HEADER: usize = 64;

/// Maximum total number of folded continuations accepted across eagerly typed
/// core headers in one message.
pub const MAX_CORE_HEADER_FOLDS: usize = 256;

/// Maximum normalized bytes processed across all eagerly typed core headers
/// in one message.
///
/// This is deliberately stricter than the complete 64-KiB header-section
/// limit. It leaves bounded space for lazily interpreted extension fields and
/// prevents a message from spending the entire framing budget on values that
/// must allocate owned typed representations immediately.
pub const MAX_TYPED_CORE_HEADER_BYTES: usize = 32 * 1024;

/// Maximum total number of logical Via hops accepted across every `Via` field
/// in one message.
pub const MAX_TOTAL_VIA_ENTRIES: usize = via::MAX_VIA_ENTRIES;

/// Maximum total number of Via parameters accepted across all Via hops in one
/// message.
pub const MAX_TOTAL_VIA_PARAMETERS: usize = 512;

/// Maximum normalized `CSeq` field-value size accepted at the message
/// validation boundary.
///
/// The standalone `CSeq` grammar permits arbitrary linear whitespace. This
/// bound prevents large whitespace-only inputs from consuming disproportionate
/// processing time.
pub const MAX_CSEQ_VALUE_BYTES: usize = 256;

/// Maximum normalized `Max-Forwards` field-value size accepted at the message
/// validation boundary.
///
/// Values remain subject to the typed numeric range check. The allowance above
/// three bytes retains interoperability with bounded leading-zero forms.
pub const MAX_MAX_FORWARDS_VALUE_BYTES: usize = 16;

/// Maximum normalized `Content-Length` field-value size accepted at the
/// message validation boundary.
///
/// Values remain subject to the configured body-size limit. This allowance
/// retains bounded leading-zero forms without permitting arbitrarily large
/// decimal inputs.
pub const MAX_CONTENT_LENGTH_VALUE_BYTES: usize = 32;

/// Transaction-critical headers validated into owned typed representations.
///
/// All physical `Via` fields and their comma-separated entries are combined
/// into one logical [`Via`] while preserving hop order. Physical field
/// boundaries and every unknown or optional header remain available from the
/// original [`RawMessage`], which a later `ValidatedMessage` envelope will own
/// alongside this value.
///
/// Fields are private so the required-header and aggregate-bound invariants
/// cannot be forged by downstream transaction or dialog code.
pub struct ValidatedCoreHeaders {
    via: Via,
    via_field_count: usize,
    via_parameter_count: usize,
    from: FromHeader,
    to: ToHeader,
    call_id: CallId,
    cseq: CSeq,
    max_forwards: Option<MaxForwards>,
    content_length: Option<ContentLength>,
    content_type: Option<ContentType>,
}

impl ValidatedCoreHeaders {
    /// Returns the combined logical Via list in original hop order.
    #[must_use]
    pub const fn via(&self) -> &Via {
        &self.via
    }

    /// Returns the topmost Via hop.
    #[must_use]
    pub fn topmost_via(&self) -> &ViaEntry {
        self.via.first()
    }

    /// Returns the number of physical Via fields represented by the logical
    /// Via list.
    #[must_use]
    pub const fn via_field_count(&self) -> usize {
        self.via_field_count
    }

    /// Returns the total number of logical Via hops.
    #[must_use]
    pub fn via_entry_count(&self) -> usize {
        self.via.len()
    }

    /// Returns the total number of parameters across every Via hop.
    #[must_use]
    pub const fn via_parameter_count(&self) -> usize {
        self.via_parameter_count
    }

    /// Returns the typed `From` header.
    #[must_use]
    pub const fn from_header(&self) -> &FromHeader {
        &self.from
    }

    /// Returns the typed `To` header.
    #[must_use]
    pub const fn to_header(&self) -> &ToHeader {
        &self.to
    }

    /// Returns the typed `Call-ID` header.
    #[must_use]
    pub const fn call_id(&self) -> &CallId {
        &self.call_id
    }

    /// Returns the typed `CSeq` header.
    #[must_use]
    pub const fn cseq(&self) -> &CSeq {
        &self.cseq
    }

    /// Returns the optional typed `Max-Forwards` header.
    #[must_use]
    pub const fn max_forwards(&self) -> Option<MaxForwards> {
        self.max_forwards
    }

    /// Returns the optional typed `Content-Length` header.
    #[must_use]
    pub const fn content_length(&self) -> Option<ContentLength> {
        self.content_length
    }

    /// Returns the optional typed `Content-Type` header.
    #[must_use]
    pub const fn content_type(&self) -> Option<&ContentType> {
        self.content_type.as_ref()
    }
}

impl fmt::Debug for ValidatedCoreHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedCoreHeaders")
            .field("via_fields", &self.via_field_count)
            .field("via_entries", &self.via.len())
            .field("via_parameters", &self.via_parameter_count)
            .field("from_tag_present", &self.from.tag().is_some())
            .field("to_tag_present", &self.to.tag().is_some())
            .field("call_id_bytes", &self.call_id.len())
            .field("max_forwards_present", &self.max_forwards.is_some())
            .field("content_length_present", &self.content_length.is_some())
            .field("content_type_present", &self.content_type.is_some())
            .finish_non_exhaustive()
    }
}

/// Validates and types the transaction-critical headers of a structurally
/// parsed SIP message.
///
/// Validation first checks the cached header-name classifications against the
/// original wire names. This prevents manually constructed [`RawMessage`]
/// metadata from spoofing a core header kind. Message-level presence and
/// multiplicity checks then run before any value parsing, giving structural
/// failures deterministic precedence over field syntax failures.
///
/// Known optional headers outside the core set are not parsed eagerly. Their
/// raw bytes, order, and duplicates remain unchanged in `message`.
///
/// # Errors
///
/// Returns [`ValidationError`] for inconsistent structural metadata, missing
/// or duplicate core fields, illegal folding or controls, typed field-value
/// failures, aggregate resource-limit violations, or a `Content-Length` that
/// disagrees with the retained body.
pub fn validate(message: &RawMessage) -> Result<ValidatedCoreHeaders, ValidationError> {
    validate_structural_boundary(message)?;
    validate_message_requirements(message)?;
    validate_content_length_multiplicity(message)?;
    validate_raw_value_boundaries(message)?;

    let mut builder = CoreHeadersBuilder::new(message.body().len());

    for (index, header) in message.header_views().enumerate() {
        let Some(kind) = HeaderKind::from_name_bytes(header.name()) else {
            continue;
        };

        builder.consume(kind, index, header.value())?;
    }

    builder.finish()
}

fn validate_structural_boundary(message: &RawMessage) -> Result<(), ValidationError> {
    let header_bytes = message.body_span().start();

    if header_bytes > MAX_HEADER_BYTES {
        return Err(ValidationError::HeaderSectionTooLarge {
            length: header_bytes,
            maximum: MAX_HEADER_BYTES,
        });
    }

    validate_wire_layout(message)?;

    for (index, header) in message.header_views().enumerate() {
        validate_header_name(index, header.name())?;
        validate_header_delimiter(index, header)?;
        validate_physical_line_lengths(index, header.line())?;

        let classified = HeaderKind::from_name_bytes(header.name());
        let cached = header.kind().copied();

        if classified != cached {
            return Err(ValidationError::HeaderKindMismatch {
                index,
                classified,
                cached,
            });
        }
    }

    Ok(())
}

fn validate_wire_layout(message: &RawMessage) -> Result<(), ValidationError> {
    let bytes = message.as_bytes();
    let mut preceding_end = message.start_line().line_span().end();

    for (index, header) in message.headers().iter().enumerate() {
        let line = header.line_span();

        if bytes.get(preceding_end..line.start()) != Some(b"\r\n") {
            return Err(ValidationError::InvalidHeaderLayout { index: Some(index) });
        }

        preceding_end = line.end();
    }

    if bytes.get(preceding_end..message.body_span().start()) != Some(b"\r\n\r\n") {
        return Err(ValidationError::InvalidHeaderLayout {
            index: message.header_count().checked_sub(1),
        });
    }

    Ok(())
}

fn validate_header_name(index: usize, name: &[u8]) -> Result<(), ValidationError> {
    let source = if name.is_empty() {
        Some(HeaderNameError::Empty)
    } else if name.len() > MAX_HEADER_NAME_BYTES {
        Some(HeaderNameError::TooLong {
            length: name.len(),
            maximum: MAX_HEADER_NAME_BYTES,
        })
    } else {
        name.iter().copied().enumerate().find_map(|(offset, byte)| {
            (!is_token_byte(byte)).then_some(HeaderNameError::InvalidToken {
                index: offset,
                byte,
            })
        })
    };

    match source {
        Some(source) => Err(ValidationError::InvalidHeaderName { index, source }),
        None => Ok(()),
    }
}

fn validate_header_delimiter(
    index: usize,
    header: RawHeaderView<'_>,
) -> Result<(), ValidationError> {
    let line = header.line();
    let Some(value_start) = line.len().checked_sub(header.value().len()) else {
        return Err(ValidationError::InvalidHeaderDelimiter { index });
    };
    let Some(delimiter) = line.get(header.name().len()..value_start) else {
        return Err(ValidationError::InvalidHeaderDelimiter { index });
    };
    let Some((&colon, whitespace)) = delimiter.split_last() else {
        return Err(ValidationError::InvalidHeaderDelimiter { index });
    };

    if colon != b':' || !whitespace.iter().copied().all(is_wsp) {
        return Err(ValidationError::InvalidHeaderDelimiter { index });
    }

    Ok(())
}

fn validate_physical_line_lengths(index: usize, line: &[u8]) -> Result<(), ValidationError> {
    let mut physical_start = 0_usize;
    let mut cursor = 0_usize;

    while cursor < line.len() {
        if line.get(cursor..cursor.saturating_add(2)) == Some(b"\r\n") {
            validate_physical_line_length(index, cursor.saturating_sub(physical_start))?;
            cursor = cursor.saturating_add(2);
            physical_start = cursor;
        } else {
            cursor = cursor.saturating_add(1);
        }
    }

    validate_physical_line_length(index, line.len().saturating_sub(physical_start))
}

fn validate_physical_line_length(index: usize, length: usize) -> Result<(), ValidationError> {
    if length > MAX_LINE_BYTES {
        return Err(ValidationError::HeaderLineTooLong {
            index,
            length,
            maximum: MAX_LINE_BYTES,
        });
    }

    Ok(())
}

fn validate_message_requirements(message: &RawMessage) -> Result<(), ValidationError> {
    let Err(source) = message::validate(message) else {
        return Ok(());
    };

    if let message::ValidationError::DuplicateSingletonHeader { kind, .. } = source
        && let Some(location) = duplicate_location(message, kind)
    {
        return Err(ValidationError::DuplicateSingletonHeader { location });
    }

    Err(ValidationError::Message(source))
}

fn validate_content_length_multiplicity(message: &RawMessage) -> Result<(), ValidationError> {
    if let Some(location) = duplicate_location(message, HeaderKind::ContentLength) {
        return Err(ValidationError::DuplicateSingletonHeader { location });
    }

    Ok(())
}

fn duplicate_location(message: &RawMessage, kind: HeaderKind) -> Option<HeaderLocation> {
    let mut occurrence = 0_usize;

    for (index, header) in message.header_views().enumerate() {
        if HeaderKind::from_name_bytes(header.name()) != Some(kind) {
            continue;
        }

        occurrence = occurrence.saturating_add(1);

        if occurrence == 2 {
            return Some(HeaderLocation::new(kind, index, occurrence));
        }
    }

    None
}

fn validate_raw_value_boundaries(message: &RawMessage) -> Result<(), ValidationError> {
    let mut occurrences = HeaderOccurrences::default();

    for (index, header) in message.header_views().enumerate() {
        let kind = HeaderKind::from_name_bytes(header.name());
        let occurrence = kind.map_or(1, |kind| occurrences.next(kind));

        if let Err(source) = analyze_logical_value(header.value()) {
            if let Some(kind) = kind.filter(|kind| is_typed_core_kind(*kind)) {
                return Err(ValidationError::InvalidLogicalValue {
                    location: HeaderLocation::new(kind, index, occurrence),
                    source,
                });
            }

            return Err(ValidationError::InvalidRawHeaderValue {
                index,
                kind,
                source,
            });
        }
    }

    Ok(())
}

const fn is_typed_core_kind(kind: HeaderKind) -> bool {
    matches!(
        kind,
        HeaderKind::Via
            | HeaderKind::From
            | HeaderKind::To
            | HeaderKind::CallId
            | HeaderKind::CSeq
            | HeaderKind::MaxForwards
            | HeaderKind::ContentLength
            | HeaderKind::ContentType
    )
}

#[derive(Default)]
struct HeaderOccurrences {
    via: usize,
    from: usize,
    to: usize,
    call_id: usize,
    cseq: usize,
    max_forwards: usize,
    content_length: usize,
    content_type: usize,
}

impl HeaderOccurrences {
    fn next(&mut self, kind: HeaderKind) -> usize {
        let value = match kind {
            HeaderKind::Via => &mut self.via,
            HeaderKind::From => &mut self.from,
            HeaderKind::To => &mut self.to,
            HeaderKind::CallId => &mut self.call_id,
            HeaderKind::CSeq => &mut self.cseq,
            HeaderKind::MaxForwards => &mut self.max_forwards,
            HeaderKind::ContentLength => &mut self.content_length,
            HeaderKind::ContentType => &mut self.content_type,
            _ => return 1,
        };

        *value = value.saturating_add(1);
        *value
    }
}

#[derive(Default)]
struct CoreHeadersBuilder {
    via: Option<Via>,
    via_field_count: usize,
    via_parameter_count: usize,
    from: Option<FromHeader>,
    to: Option<ToHeader>,
    call_id: Option<CallId>,
    cseq: Option<CSeq>,
    max_forwards: Option<MaxForwards>,
    content_length: Option<ContentLength>,
    content_type: Option<ContentType>,
    body_length: usize,
    budget: CoreHeaderBudget,
}

impl CoreHeadersBuilder {
    const fn new(body_length: usize) -> Self {
        Self {
            via: None,
            via_field_count: 0,
            via_parameter_count: 0,
            from: None,
            to: None,
            call_id: None,
            cseq: None,
            max_forwards: None,
            content_length: None,
            content_type: None,
            body_length,
            budget: CoreHeaderBudget::new(),
        }
    }

    fn consume(
        &mut self,
        kind: HeaderKind,
        index: usize,
        raw_value: &[u8],
    ) -> Result<(), ValidationError> {
        let location = self.next_location(kind, index);

        match kind {
            HeaderKind::Via => self.parse_via(location, raw_value),
            HeaderKind::From => {
                if self.from.is_some() {
                    return Err(ValidationError::DuplicateSingletonHeader { location });
                }

                let value = self.prepare_value(location, raw_value)?;
                let parsed = FromHeader::from_bytes(trim_horizontal_whitespace(value.as_ref()))
                    .map_err(|source| ValidationError::InvalidFrom { location, source })?;

                self.from = Some(parsed);
                Ok(())
            }
            HeaderKind::To => {
                if self.to.is_some() {
                    return Err(ValidationError::DuplicateSingletonHeader { location });
                }

                let value = self.prepare_value(location, raw_value)?;
                let parsed = ToHeader::from_bytes(trim_horizontal_whitespace(value.as_ref()))
                    .map_err(|source| ValidationError::InvalidTo { location, source })?;

                self.to = Some(parsed);
                Ok(())
            }
            HeaderKind::CallId => {
                if self.call_id.is_some() {
                    return Err(ValidationError::DuplicateSingletonHeader { location });
                }

                let value = self.prepare_value(location, raw_value)?;
                let parsed = CallId::from_bytes(trim_horizontal_whitespace(value.as_ref()))
                    .map_err(|source| ValidationError::InvalidCallId { location, source })?;

                self.call_id = Some(parsed);
                Ok(())
            }
            HeaderKind::CSeq => {
                if self.cseq.is_some() {
                    return Err(ValidationError::DuplicateSingletonHeader { location });
                }

                let value = self.prepare_value(location, raw_value)?;
                let parsed = CSeq::from_bytes(trim_horizontal_whitespace(value.as_ref()))
                    .map_err(|source| ValidationError::InvalidCSeq { location, source })?;

                self.cseq = Some(parsed);
                Ok(())
            }
            HeaderKind::MaxForwards => {
                if self.max_forwards.is_some() {
                    return Err(ValidationError::DuplicateSingletonHeader { location });
                }

                let value = self.prepare_value(location, raw_value)?;
                let parsed = MaxForwards::from_bytes(trim_horizontal_whitespace(value.as_ref()))
                    .map_err(|source| ValidationError::InvalidMaxForwards { location, source })?;

                self.max_forwards = Some(parsed);
                Ok(())
            }
            HeaderKind::ContentLength => self.parse_content_length(location, raw_value),
            HeaderKind::ContentType => {
                if self.content_type.is_some() {
                    return Err(ValidationError::DuplicateSingletonHeader { location });
                }

                let value = self.prepare_value(location, raw_value)?;
                let parsed = ContentType::from_bytes(trim_horizontal_whitespace(value.as_ref()))
                    .map_err(|source| ValidationError::InvalidContentType { location, source })?;

                self.content_type = Some(parsed);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn parse_via(
        &mut self,
        location: HeaderLocation,
        raw_value: &[u8],
    ) -> Result<(), ValidationError> {
        let existing_entries = self.via.as_ref().map_or(0, Via::len);
        let existing_parameters = self.via_parameter_count;
        let remaining_entries = MAX_TOTAL_VIA_ENTRIES.saturating_sub(existing_entries);
        let remaining_parameters = MAX_TOTAL_VIA_PARAMETERS.saturating_sub(existing_parameters);
        let value = self.prepare_value(location, raw_value)?;
        let parsed = via::parse_with_budget(
            trim_horizontal_whitespace(value.as_ref()),
            remaining_entries,
            remaining_parameters,
        )
        .map_err(|error| {
            map_budgeted_via_error(error, location, existing_entries, existing_parameters)
        })?;

        let Some(total_entries) = existing_entries.checked_add(parsed.len()) else {
            return Err(ValidationError::TooManyViaEntries {
                location,
                count: usize::MAX,
                maximum: MAX_TOTAL_VIA_ENTRIES,
            });
        };

        if total_entries > MAX_TOTAL_VIA_ENTRIES {
            return Err(ValidationError::TooManyViaEntries {
                location,
                count: total_entries,
                maximum: MAX_TOTAL_VIA_ENTRIES,
            });
        }

        let mut parsed_parameters = 0_usize;

        for entry in parsed.entries() {
            let Some(count) = parsed_parameters.checked_add(entry.parameter_count()) else {
                return Err(ValidationError::TooManyViaParameters {
                    location,
                    count: usize::MAX,
                    maximum: MAX_TOTAL_VIA_PARAMETERS,
                });
            };

            parsed_parameters = count;
        }

        let Some(total_parameters) = self.via_parameter_count.checked_add(parsed_parameters) else {
            return Err(ValidationError::TooManyViaParameters {
                location,
                count: usize::MAX,
                maximum: MAX_TOTAL_VIA_PARAMETERS,
            });
        };

        if total_parameters > MAX_TOTAL_VIA_PARAMETERS {
            return Err(ValidationError::TooManyViaParameters {
                location,
                count: total_parameters,
                maximum: MAX_TOTAL_VIA_PARAMETERS,
            });
        }

        match &mut self.via {
            Some(combined) => {
                for entry in parsed.into_entries() {
                    combined
                        .push_entry(entry)
                        .map_err(|_| ValidationError::TooManyViaEntries {
                            location,
                            count: total_entries,
                            maximum: MAX_TOTAL_VIA_ENTRIES,
                        })?;
                }
            }
            None => self.via = Some(parsed),
        }

        self.via_field_count = self.via_field_count.saturating_add(1);
        self.via_parameter_count = total_parameters;

        Ok(())
    }

    fn parse_content_length(
        &mut self,
        location: HeaderLocation,
        raw_value: &[u8],
    ) -> Result<(), ValidationError> {
        if self.content_length.is_some() {
            return Err(ValidationError::DuplicateSingletonHeader { location });
        }

        let value = self.prepare_value(location, raw_value)?;
        let parsed = ContentLength::from_bytes(trim_horizontal_whitespace(value.as_ref()))
            .map_err(|source| ValidationError::InvalidContentLength { location, source })?;

        if parsed.as_usize() != self.body_length {
            return Err(ValidationError::ContentLengthMismatch {
                location,
                declared: parsed.as_usize(),
                actual: self.body_length,
            });
        }

        self.content_length = Some(parsed);
        Ok(())
    }

    fn prepare_value<'a>(
        &mut self,
        location: HeaderLocation,
        raw_value: &'a [u8],
    ) -> Result<Cow<'a, [u8]>, ValidationError> {
        let analysis = analyze_logical_value(raw_value)
            .map_err(|source| ValidationError::InvalidLogicalValue { location, source })?;

        let maximum = value_limit(location.kind());

        if analysis.trimmed_length() > maximum {
            return Err(ValidationError::HeaderValueTooLong {
                location,
                length: analysis.trimmed_length(),
                maximum,
            });
        }

        self.budget.account(location, analysis)?;

        let value = materialize_logical_value(analysis)
            .map_err(|source| ValidationError::InvalidLogicalValue { location, source })?;

        debug_assert_eq!(
            trim_horizontal_whitespace(value.as_ref()).len(),
            analysis.trimmed_length()
        );

        Ok(value)
    }

    fn next_location(&self, kind: HeaderKind, index: usize) -> HeaderLocation {
        let occurrence = match kind {
            HeaderKind::Via => self.via_field_count.saturating_add(1),
            HeaderKind::From => occurrence_for(self.from.is_some()),
            HeaderKind::To => occurrence_for(self.to.is_some()),
            HeaderKind::CallId => occurrence_for(self.call_id.is_some()),
            HeaderKind::CSeq => occurrence_for(self.cseq.is_some()),
            HeaderKind::MaxForwards => occurrence_for(self.max_forwards.is_some()),
            HeaderKind::ContentLength => occurrence_for(self.content_length.is_some()),
            HeaderKind::ContentType => occurrence_for(self.content_type.is_some()),
            _ => 1,
        };

        HeaderLocation::new(kind, index, occurrence)
    }

    fn finish(self) -> Result<ValidatedCoreHeaders, ValidationError> {
        let Self {
            via,
            via_field_count,
            via_parameter_count,
            from,
            to,
            call_id,
            cseq,
            max_forwards,
            content_length,
            content_type,
            ..
        } = self;

        let via = via.ok_or_else(|| missing_required(HeaderKind::Via))?;
        let from = from.ok_or_else(|| missing_required(HeaderKind::From))?;
        let to = to.ok_or_else(|| missing_required(HeaderKind::To))?;
        let call_id = call_id.ok_or_else(|| missing_required(HeaderKind::CallId))?;
        let cseq = cseq.ok_or_else(|| missing_required(HeaderKind::CSeq))?;

        Ok(ValidatedCoreHeaders {
            via,
            via_field_count,
            via_parameter_count,
            from,
            to,
            call_id,
            cseq,
            max_forwards,
            content_length,
            content_type,
        })
    }
}

fn map_budgeted_via_error(
    error: ViaBudgetedParseError,
    location: HeaderLocation,
    existing_entries: usize,
    existing_parameters: usize,
) -> ValidationError {
    match error {
        ViaBudgetedParseError::Parse(source) => ValidationError::InvalidVia { location, source },
        ViaBudgetedParseError::EntryBudgetExceeded { attempted, .. } => {
            ValidationError::TooManyViaEntries {
                location,
                count: existing_entries.saturating_add(attempted),
                maximum: MAX_TOTAL_VIA_ENTRIES,
            }
        }
        ViaBudgetedParseError::TotalParameterBudgetExceeded { attempted, .. } => {
            ValidationError::TooManyViaParameters {
                location,
                count: existing_parameters.saturating_add(attempted),
                maximum: MAX_TOTAL_VIA_PARAMETERS,
            }
        }
    }
}

const fn occurrence_for(already_present: bool) -> usize {
    if already_present { 2 } else { 1 }
}

const fn missing_required(kind: HeaderKind) -> ValidationError {
    ValidationError::Message(message::ValidationError::MissingRequiredHeader { kind })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CoreHeaderBudget {
    bytes: usize,
    folds: usize,
}

impl CoreHeaderBudget {
    const fn new() -> Self {
        Self { bytes: 0, folds: 0 }
    }

    fn account(
        &mut self,
        location: HeaderLocation,
        analysis: LogicalValueAnalysis<'_>,
    ) -> Result<(), ValidationError> {
        let Some(bytes) = self.bytes.checked_add(analysis.output_length()) else {
            return Err(ValidationError::CoreHeaderBytesExceeded {
                location,
                count: usize::MAX,
                maximum: MAX_TYPED_CORE_HEADER_BYTES,
            });
        };

        if bytes > MAX_TYPED_CORE_HEADER_BYTES {
            return Err(ValidationError::CoreHeaderBytesExceeded {
                location,
                count: bytes,
                maximum: MAX_TYPED_CORE_HEADER_BYTES,
            });
        }

        let Some(folds) = self.folds.checked_add(analysis.folds()) else {
            return Err(ValidationError::CoreHeaderFoldsExceeded {
                location,
                count: usize::MAX,
                maximum: MAX_CORE_HEADER_FOLDS,
            });
        };

        if folds > MAX_CORE_HEADER_FOLDS {
            return Err(ValidationError::CoreHeaderFoldsExceeded {
                location,
                count: folds,
                maximum: MAX_CORE_HEADER_FOLDS,
            });
        }

        self.bytes = bytes;
        self.folds = folds;
        Ok(())
    }
}

/// Allocation plan for one bounded logical SIP field value.
///
/// This is crate-visible so later lazy typed-header validators can reuse the
/// same folding and control-byte boundary instead of growing subtly different
/// normalizers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LogicalValueAnalysis<'a> {
    input: &'a [u8],
    output_length: usize,
    trimmed_length: usize,
    folds: usize,
}

impl LogicalValueAnalysis<'_> {
    /// Returns the exact byte length after unfolding and before outer
    /// horizontal whitespace is trimmed.
    pub(crate) const fn output_length(self) -> usize {
        self.output_length
    }

    /// Returns the exact byte length seen by an owned typed parser after
    /// unfolding and outer horizontal-whitespace trimming.
    pub(crate) const fn trimmed_length(self) -> usize {
        self.trimmed_length
    }

    /// Returns the number of folded continuations in the raw value.
    pub(crate) const fn folds(self) -> usize {
        self.folds
    }
}

/// Validates a raw field value and computes its exact bounded unfold plan.
pub(crate) fn analyze_logical_value(
    input: &[u8],
) -> Result<LogicalValueAnalysis<'_>, LogicalValueError> {
    if input.len() > MAX_HEADER_VALUE_BYTES {
        return Err(LogicalValueError::TooLong {
            length: input.len(),
            maximum: MAX_HEADER_VALUE_BYTES,
        });
    }

    let mut index = 0_usize;
    let mut output_length = 0_usize;
    let mut leading_whitespace = 0_usize;
    let mut trailing_whitespace = 0_usize;
    let mut saw_non_whitespace = false;
    let mut folds = 0_usize;

    while index < input.len() {
        match input[index] {
            b'\r' => {
                if input.get(index.saturating_add(1)) != Some(&b'\n') {
                    return Err(LogicalValueError::BareCarriageReturn { index });
                }

                let continuation = index
                    .checked_add(2)
                    .ok_or(LogicalValueError::LengthOverflow)?;

                if !input.get(continuation).is_some_and(|byte| is_wsp(*byte)) {
                    return Err(LogicalValueError::MissingContinuationWhitespace { index });
                }

                folds = folds
                    .checked_add(1)
                    .ok_or(LogicalValueError::LengthOverflow)?;

                if folds > MAX_FOLDS_PER_CORE_HEADER {
                    return Err(LogicalValueError::TooManyFolds {
                        count: folds,
                        maximum: MAX_FOLDS_PER_CORE_HEADER,
                    });
                }

                output_length = output_length
                    .checked_sub(trailing_whitespace)
                    .ok_or(LogicalValueError::LengthOverflow)?;

                if !saw_non_whitespace {
                    leading_whitespace = 0;
                }

                output_length = output_length
                    .checked_add(1)
                    .ok_or(LogicalValueError::LengthOverflow)?;
                trailing_whitespace = 1;

                if !saw_non_whitespace {
                    leading_whitespace = 1;
                }

                index = continuation;

                while input.get(index).is_some_and(|byte| is_wsp(*byte)) {
                    index += 1;
                }
            }
            b'\n' => return Err(LogicalValueError::BareLineFeed { index }),
            byte if !is_field_value_byte(byte) => {
                return Err(LogicalValueError::InvalidControl { index, byte });
            }
            byte => {
                output_length = output_length
                    .checked_add(1)
                    .ok_or(LogicalValueError::LengthOverflow)?;

                if is_wsp(byte) {
                    trailing_whitespace = trailing_whitespace
                        .checked_add(1)
                        .ok_or(LogicalValueError::LengthOverflow)?;

                    if !saw_non_whitespace {
                        leading_whitespace = leading_whitespace
                            .checked_add(1)
                            .ok_or(LogicalValueError::LengthOverflow)?;
                    }
                } else {
                    saw_non_whitespace = true;
                    trailing_whitespace = 0;
                }

                index += 1;
            }
        }
    }

    let trimmed_length = if saw_non_whitespace {
        output_length
            .checked_sub(leading_whitespace)
            .and_then(|length| length.checked_sub(trailing_whitespace))
            .ok_or(LogicalValueError::LengthOverflow)?
    } else {
        0
    };

    Ok(LogicalValueAnalysis {
        input,
        output_length,
        trimmed_length,
        folds,
    })
}

/// Materializes a previously analyzed field value, borrowing when no fold is
/// present and allocating exactly once otherwise.
pub(crate) fn materialize_logical_value(
    analysis: LogicalValueAnalysis<'_>,
) -> Result<Cow<'_, [u8]>, LogicalValueError> {
    let input = analysis.input;

    if analysis.folds() == 0 {
        return Ok(Cow::Borrowed(input));
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(analysis.output_length())
        .map_err(|_| LogicalValueError::AllocationFailed {
            requested: analysis.output_length(),
        })?;

    let mut index = 0_usize;

    while index < input.len() {
        match input[index] {
            b'\r' => {
                if input.get(index.saturating_add(1)) != Some(&b'\n') {
                    return Err(LogicalValueError::BareCarriageReturn { index });
                }

                let continuation = index
                    .checked_add(2)
                    .ok_or(LogicalValueError::LengthOverflow)?;

                if !input.get(continuation).is_some_and(|byte| is_wsp(*byte)) {
                    return Err(LogicalValueError::MissingContinuationWhitespace { index });
                }

                while output.last().is_some_and(|byte| is_wsp(*byte)) {
                    output.pop();
                }

                output.push(b' ');
                index = continuation;

                while input.get(index).is_some_and(|byte| is_wsp(*byte)) {
                    index += 1;
                }
            }
            b'\n' => return Err(LogicalValueError::BareLineFeed { index }),
            byte if !is_field_value_byte(byte) => {
                return Err(LogicalValueError::InvalidControl { index, byte });
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }

    if output.len() != analysis.output_length() {
        return Err(LogicalValueError::LengthOverflow);
    }

    Ok(Cow::Owned(output))
}

/// Removes only boundary SP/HTAB after a field value has been unfolded.
pub(crate) fn trim_horizontal_whitespace(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(|byte| is_wsp(*byte)) {
        input = &input[1..];
    }

    while input.last().is_some_and(|byte| is_wsp(*byte)) {
        input = &input[..input.len() - 1];
    }

    input
}

const fn value_limit(kind: HeaderKind) -> usize {
    match kind {
        HeaderKind::Via => MAX_VIA_BYTES,
        HeaderKind::From => MAX_FROM_BYTES,
        HeaderKind::To => MAX_TO_BYTES,
        HeaderKind::CallId => MAX_CALL_ID_BYTES,
        HeaderKind::CSeq => MAX_CSEQ_VALUE_BYTES,
        HeaderKind::MaxForwards => MAX_MAX_FORWARDS_VALUE_BYTES,
        HeaderKind::ContentLength => MAX_CONTENT_LENGTH_VALUE_BYTES,
        HeaderKind::ContentType => MAX_CONTENT_TYPE_BYTES,
        _ => MAX_HEADER_VALUE_BYTES,
    }
}

const fn is_wsp(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

const fn is_field_value_byte(byte: u8) -> bool {
    byte == b'\t' || matches!(byte, b' '..=b'~') || byte >= 0x80
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

/// Location of a core header in the original SIP message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderLocation {
    kind: HeaderKind,
    index: usize,
    occurrence: usize,
}

impl HeaderLocation {
    const fn new(kind: HeaderKind, index: usize, occurrence: usize) -> Self {
        Self {
            kind,
            index,
            occurrence,
        }
    }

    /// Returns the recognized header kind.
    #[must_use]
    pub const fn kind(self) -> HeaderKind {
        self.kind
    }

    /// Returns the zero-based header index in original wire order.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }

    /// Returns the one-based occurrence number among fields of this kind.
    #[must_use]
    pub const fn occurrence(self) -> usize {
        self.occurrence
    }
}

/// Failure to produce one safe logical field value from exact wire bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LogicalValueError {
    /// The raw value exceeded the generic header-value bound before scanning.
    TooLong {
        /// Actual raw value length.
        length: usize,

        /// Maximum accepted raw value length.
        maximum: usize,
    },

    /// A carriage return was not immediately followed by line feed.
    BareCarriageReturn {
        /// Zero-based offset in the raw field value.
        index: usize,
    },

    /// A line feed appeared without a preceding carriage return.
    BareLineFeed {
        /// Zero-based offset in the raw field value.
        index: usize,
    },

    /// A CRLF sequence was not followed by required continuation whitespace.
    MissingContinuationWhitespace {
        /// Zero-based offset of the carriage return.
        index: usize,
    },

    /// A prohibited control byte appeared in the raw field value.
    InvalidControl {
        /// Zero-based offset in the raw field value.
        index: usize,

        /// Prohibited byte.
        byte: u8,
    },

    /// One field contained too many folded continuations.
    TooManyFolds {
        /// Fold count observed before rejection.
        count: usize,

        /// Maximum accepted fold count.
        maximum: usize,
    },

    /// Length arithmetic could not be represented safely.
    LengthOverflow,

    /// A bounded unfolded buffer could not be reserved.
    AllocationFailed {
        /// Exact output capacity requested.
        requested: usize,
    },
}

impl LogicalValueError {
    /// Returns a stable low-cardinality classification suitable for metrics
    /// and structured logs.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::TooLong { .. } => "too-long",
            Self::BareCarriageReturn { .. } => "bare-carriage-return",
            Self::BareLineFeed { .. } => "bare-line-feed",
            Self::MissingContinuationWhitespace { .. } => "missing-continuation-whitespace",
            Self::InvalidControl { .. } => "invalid-control",
            Self::TooManyFolds { .. } => "too-many-folds",
            Self::LengthOverflow => "length-overflow",
            Self::AllocationFailed { .. } => "allocation-failed",
        }
    }
}

impl fmt::Display for LogicalValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { length, maximum } => write!(
                formatter,
                "raw SIP header-value length {length} exceeds maximum {maximum}"
            ),
            Self::BareCarriageReturn { index } => write!(
                formatter,
                "SIP header value contains a bare carriage return at offset {index}"
            ),
            Self::BareLineFeed { index } => write!(
                formatter,
                "SIP header value contains a bare line feed at offset {index}"
            ),
            Self::MissingContinuationWhitespace { index } => write!(
                formatter,
                "SIP header fold at offset {index} lacks continuation whitespace"
            ),
            Self::InvalidControl { index, byte } => write!(
                formatter,
                "SIP header value contains prohibited byte 0x{byte:02x} at offset {index}"
            ),
            Self::TooManyFolds { count, maximum } => write!(
                formatter,
                "SIP header value contains {count} folds, exceeding maximum {maximum}"
            ),
            Self::LengthOverflow => {
                formatter.write_str("SIP logical header-value length overflowed")
            }
            Self::AllocationFailed { requested } => write!(
                formatter,
                "unable to reserve {requested} bytes for bounded SIP header unfolding"
            ),
        }
    }
}

impl StdError for LogicalValueError {}

/// Failure to validate transaction-critical SIP headers.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidationError {
    /// Message-level presence, multiplicity, or body consistency failed.
    Message(message::ValidationError),

    /// The region preceding the body exceeded the framing header-section
    /// bound.
    HeaderSectionTooLarge {
        /// Observed byte length preceding the body.
        length: usize,

        /// Maximum accepted header-section length.
        maximum: usize,
    },

    /// Raw metadata did not describe the mandatory CRLF boundaries between
    /// the start line, logical headers, header terminator, and body.
    InvalidHeaderLayout {
        /// Header at, or immediately before, the inconsistent boundary.
        index: Option<usize>,
    },

    /// A raw header-name span did not contain one bounded SIP token.
    InvalidHeaderName {
        /// Zero-based header index in wire order.
        index: usize,

        /// Header-name grammar failure.
        source: HeaderNameError,
    },

    /// Bytes between the raw name and value spans were not `*WSP ":"`.
    InvalidHeaderDelimiter {
        /// Zero-based header index in wire order.
        index: usize,
    },

    /// A physical header line exceeded the framing line bound.
    HeaderLineTooLong {
        /// Zero-based logical header index in wire order.
        index: usize,

        /// Observed physical-line length.
        length: usize,

        /// Maximum accepted physical-line length.
        maximum: usize,
    },

    /// Cached recognized-name metadata disagreed with the original name.
    HeaderKindMismatch {
        /// Zero-based header index in wire order.
        index: usize,

        /// Classification derived from the original name bytes.
        classified: Option<HeaderKind>,

        /// Classification cached in structural metadata.
        cached: Option<HeaderKind>,
    },

    /// Exact field bytes could not be normalized safely.
    InvalidLogicalValue {
        /// Header location.
        location: HeaderLocation,

        /// Normalization failure.
        source: LogicalValueError,
    },

    /// A lazily interpreted non-core field contained structurally invalid
    /// control bytes or folding.
    InvalidRawHeaderValue {
        /// Zero-based header index in wire order.
        index: usize,

        /// Recognized header kind, when any.
        kind: Option<HeaderKind>,

        /// Raw logical-value failure.
        source: LogicalValueError,
    },

    /// A normalized core value exceeded its field-specific operational bound.
    HeaderValueTooLong {
        /// Header location.
        location: HeaderLocation,

        /// Observed logical value length.
        length: usize,

        /// Maximum accepted logical value length.
        maximum: usize,
    },

    /// Eagerly typed core values exceeded their aggregate byte budget.
    CoreHeaderBytesExceeded {
        /// Header whose addition exceeded the budget.
        location: HeaderLocation,

        /// Attempted aggregate normalized byte count.
        count: usize,

        /// Maximum aggregate normalized byte count.
        maximum: usize,
    },

    /// Eagerly typed core values exceeded their aggregate folding budget.
    CoreHeaderFoldsExceeded {
        /// Header whose addition exceeded the budget.
        location: HeaderLocation,

        /// Attempted aggregate fold count.
        count: usize,

        /// Maximum aggregate fold count.
        maximum: usize,
    },

    /// Via fields contained too many logical hops in aggregate.
    TooManyViaEntries {
        /// Via field whose addition exceeded the bound.
        location: HeaderLocation,

        /// Attempted aggregate Via-hop count.
        count: usize,

        /// Maximum aggregate Via-hop count.
        maximum: usize,
    },

    /// Via fields contained too many parameters in aggregate.
    TooManyViaParameters {
        /// Via field whose addition exceeded the bound.
        location: HeaderLocation,

        /// Attempted aggregate Via-parameter count.
        count: usize,

        /// Maximum aggregate Via-parameter count.
        maximum: usize,
    },

    /// A singleton field appeared more than once at this defensive boundary.
    DuplicateSingletonHeader {
        /// Duplicate field location.
        location: HeaderLocation,
    },

    /// A Via field was syntactically invalid.
    InvalidVia {
        /// Header location.
        location: HeaderLocation,

        /// Typed Via parse failure.
        source: ViaParseError,
    },

    /// A From field was syntactically invalid.
    InvalidFrom {
        /// Header location.
        location: HeaderLocation,

        /// Typed From parse failure.
        source: FromParseError,
    },

    /// A To field was syntactically invalid.
    InvalidTo {
        /// Header location.
        location: HeaderLocation,

        /// Typed To parse failure.
        source: ToParseError,
    },

    /// A Call-ID field was syntactically invalid.
    InvalidCallId {
        /// Header location.
        location: HeaderLocation,

        /// Typed Call-ID parse failure.
        source: CallIdParseError,
    },

    /// A `CSeq` field was syntactically invalid.
    InvalidCSeq {
        /// Header location.
        location: HeaderLocation,

        /// Typed `CSeq` parse failure.
        source: CSeqParseError,
    },

    /// A Max-Forwards field was syntactically invalid.
    InvalidMaxForwards {
        /// Header location.
        location: HeaderLocation,

        /// Typed Max-Forwards parse failure.
        source: MaxForwardsParseError,
    },

    /// A Content-Length field was syntactically invalid.
    InvalidContentLength {
        /// Header location.
        location: HeaderLocation,

        /// Typed Content-Length parse failure.
        source: ContentLengthParseError,
    },

    /// A Content-Type field was syntactically invalid.
    InvalidContentType {
        /// Header location.
        location: HeaderLocation,

        /// Typed Content-Type parse failure.
        source: ContentTypeParseError,
    },

    /// The declared Content-Length disagreed with the exact retained body.
    ContentLengthMismatch {
        /// Content-Length header location.
        location: HeaderLocation,

        /// Declared body length.
        declared: usize,

        /// Exact retained body length.
        actual: usize,
    },
}

impl ValidationError {
    /// Returns a stable low-cardinality classification suitable for metrics
    /// and structured logs.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Message(source) => source.class(),
            Self::HeaderSectionTooLarge { .. } => "header-section-too-large",
            Self::InvalidHeaderLayout { .. } => "invalid-header-layout",
            Self::InvalidHeaderName { .. } => "invalid-header-name",
            Self::InvalidHeaderDelimiter { .. } => "invalid-header-delimiter",
            Self::HeaderLineTooLong { .. } => "header-line-too-long",
            Self::HeaderKindMismatch { .. } => "header-kind-mismatch",
            Self::InvalidLogicalValue { .. } => "invalid-logical-header-value",
            Self::InvalidRawHeaderValue { .. } => "invalid-raw-header-value",
            Self::HeaderValueTooLong { .. } => "header-value-too-long",
            Self::CoreHeaderBytesExceeded { .. } => "core-header-bytes-exceeded",
            Self::CoreHeaderFoldsExceeded { .. } => "core-header-folds-exceeded",
            Self::TooManyViaEntries { .. } => "too-many-via-entries",
            Self::TooManyViaParameters { .. } => "too-many-via-parameters",
            Self::DuplicateSingletonHeader { .. } => "duplicate-singleton-header",
            Self::InvalidVia { .. } => "invalid-via",
            Self::InvalidFrom { .. } => "invalid-from",
            Self::InvalidTo { .. } => "invalid-to",
            Self::InvalidCallId { .. } => "invalid-call-id",
            Self::InvalidCSeq { .. } => "invalid-cseq",
            Self::InvalidMaxForwards { .. } => "invalid-max-forwards",
            Self::InvalidContentLength { .. } => "invalid-content-length",
            Self::InvalidContentType { .. } => "invalid-content-type",
            Self::ContentLengthMismatch { .. } => "content-length-mismatch",
        }
    }

    /// Returns the detailed source classification without exposing raw field
    /// contents.
    #[must_use]
    pub const fn detail_class(&self) -> &'static str {
        match self {
            Self::Message(source) => source.class(),
            Self::InvalidHeaderName { source, .. } => source.class(),
            Self::InvalidLogicalValue { source, .. }
            | Self::InvalidRawHeaderValue { source, .. } => source.class(),
            Self::InvalidVia { source, .. } => source.class(),
            Self::InvalidFrom { source, .. } => source.class(),
            Self::InvalidTo { source, .. } => source.class(),
            Self::InvalidCallId { source, .. } => source.class(),
            Self::InvalidCSeq { source, .. } => source.class(),
            Self::InvalidMaxForwards { source, .. } => source.class(),
            Self::InvalidContentLength { source, .. } => source.class(),
            Self::InvalidContentType { source, .. } => source.class(),
            _ => self.class(),
        }
    }

    /// Returns the associated recognized header kind when one is available.
    #[must_use]
    pub const fn header_kind(&self) -> Option<HeaderKind> {
        match self {
            Self::Message(source) => source.header_kind(),
            Self::HeaderKindMismatch {
                classified, cached, ..
            } => match classified {
                Some(kind) => Some(*kind),
                None => *cached,
            },
            Self::InvalidRawHeaderValue { kind, .. } => *kind,
            Self::InvalidLogicalValue { location, .. }
            | Self::HeaderValueTooLong { location, .. }
            | Self::CoreHeaderBytesExceeded { location, .. }
            | Self::CoreHeaderFoldsExceeded { location, .. }
            | Self::TooManyViaEntries { location, .. }
            | Self::TooManyViaParameters { location, .. }
            | Self::DuplicateSingletonHeader { location }
            | Self::InvalidVia { location, .. }
            | Self::InvalidFrom { location, .. }
            | Self::InvalidTo { location, .. }
            | Self::InvalidCallId { location, .. }
            | Self::InvalidCSeq { location, .. }
            | Self::InvalidMaxForwards { location, .. }
            | Self::InvalidContentLength { location, .. }
            | Self::InvalidContentType { location, .. }
            | Self::ContentLengthMismatch { location, .. } => Some(location.kind()),
            Self::HeaderSectionTooLarge { .. }
            | Self::InvalidHeaderLayout { .. }
            | Self::InvalidHeaderName { .. }
            | Self::InvalidHeaderDelimiter { .. }
            | Self::HeaderLineTooLong { .. } => None,
        }
    }

    /// Returns the zero-based wire-order header index when available.
    #[must_use]
    pub const fn header_index(&self) -> Option<usize> {
        match self {
            Self::InvalidHeaderLayout { index } => *index,
            Self::InvalidHeaderName { index, .. }
            | Self::InvalidHeaderDelimiter { index }
            | Self::HeaderLineTooLong { index, .. }
            | Self::HeaderKindMismatch { index, .. }
            | Self::InvalidRawHeaderValue { index, .. } => Some(*index),
            Self::InvalidLogicalValue { location, .. }
            | Self::HeaderValueTooLong { location, .. }
            | Self::CoreHeaderBytesExceeded { location, .. }
            | Self::CoreHeaderFoldsExceeded { location, .. }
            | Self::TooManyViaEntries { location, .. }
            | Self::TooManyViaParameters { location, .. }
            | Self::DuplicateSingletonHeader { location }
            | Self::InvalidVia { location, .. }
            | Self::InvalidFrom { location, .. }
            | Self::InvalidTo { location, .. }
            | Self::InvalidCallId { location, .. }
            | Self::InvalidCSeq { location, .. }
            | Self::InvalidMaxForwards { location, .. }
            | Self::InvalidContentLength { location, .. }
            | Self::InvalidContentType { location, .. }
            | Self::ContentLengthMismatch { location, .. } => Some(location.index()),
            Self::Message(_) | Self::HeaderSectionTooLarge { .. } => None,
        }
    }

    /// Returns the one-based occurrence number for the associated header kind
    /// when available.
    #[must_use]
    pub const fn header_occurrence(&self) -> Option<usize> {
        match self {
            Self::InvalidLogicalValue { location, .. }
            | Self::HeaderValueTooLong { location, .. }
            | Self::CoreHeaderBytesExceeded { location, .. }
            | Self::CoreHeaderFoldsExceeded { location, .. }
            | Self::TooManyViaEntries { location, .. }
            | Self::TooManyViaParameters { location, .. }
            | Self::DuplicateSingletonHeader { location }
            | Self::InvalidVia { location, .. }
            | Self::InvalidFrom { location, .. }
            | Self::InvalidTo { location, .. }
            | Self::InvalidCallId { location, .. }
            | Self::InvalidCSeq { location, .. }
            | Self::InvalidMaxForwards { location, .. }
            | Self::InvalidContentLength { location, .. }
            | Self::InvalidContentType { location, .. }
            | Self::ContentLengthMismatch { location, .. } => Some(location.occurrence()),
            Self::Message(_)
            | Self::HeaderSectionTooLarge { .. }
            | Self::InvalidHeaderLayout { .. }
            | Self::InvalidHeaderName { .. }
            | Self::InvalidHeaderDelimiter { .. }
            | Self::HeaderLineTooLong { .. }
            | Self::HeaderKindMismatch { .. }
            | Self::InvalidRawHeaderValue { .. } => None,
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some((location, source)) = invalid_header_source(self) {
            write_invalid_header(formatter, location, source)
        } else {
            write_non_parse_validation_error(formatter, self)
        }
    }
}

fn invalid_header_source(error: &ValidationError) -> Option<(HeaderLocation, &dyn fmt::Display)> {
    match error {
        ValidationError::InvalidLogicalValue { location, source } => Some((*location, source)),
        ValidationError::InvalidVia { location, source } => Some((*location, source)),
        ValidationError::InvalidFrom { location, source } => Some((*location, source)),
        ValidationError::InvalidTo { location, source } => Some((*location, source)),
        ValidationError::InvalidCallId { location, source } => Some((*location, source)),
        ValidationError::InvalidCSeq { location, source } => Some((*location, source)),
        ValidationError::InvalidMaxForwards { location, source } => Some((*location, source)),
        ValidationError::InvalidContentLength { location, source } => Some((*location, source)),
        ValidationError::InvalidContentType { location, source } => Some((*location, source)),
        _ => None,
    }
}

fn write_non_parse_validation_error(
    formatter: &mut fmt::Formatter<'_>,
    error: &ValidationError,
) -> fmt::Result {
    match error {
        ValidationError::Message(source) => write!(formatter, "{source}"),
        ValidationError::HeaderSectionTooLarge { .. }
        | ValidationError::InvalidHeaderLayout { .. }
        | ValidationError::InvalidHeaderName { .. }
        | ValidationError::InvalidHeaderDelimiter { .. }
        | ValidationError::HeaderLineTooLong { .. }
        | ValidationError::HeaderKindMismatch { .. }
        | ValidationError::InvalidRawHeaderValue { .. } => {
            write_structural_validation_error(formatter, error)
        }
        ValidationError::HeaderValueTooLong {
            location,
            length,
            maximum,
        } => write!(
            formatter,
            "SIP {} header at wire index {}, occurrence {} has logical value length {length}, exceeding maximum {maximum}",
            location.kind(),
            location.index(),
            location.occurrence(),
        ),
        ValidationError::CoreHeaderBytesExceeded {
            location,
            count,
            maximum,
        } => write_bounded_count(
            formatter,
            "core-header byte budget",
            "bytes",
            *location,
            *count,
            *maximum,
        ),
        ValidationError::CoreHeaderFoldsExceeded {
            location,
            count,
            maximum,
        } => write_bounded_count(
            formatter,
            "core-header fold budget",
            "folds",
            *location,
            *count,
            *maximum,
        ),
        ValidationError::TooManyViaEntries {
            location,
            count,
            maximum,
        } => write_bounded_count(
            formatter,
            "Via aggregate",
            "hops",
            *location,
            *count,
            *maximum,
        ),
        ValidationError::TooManyViaParameters {
            location,
            count,
            maximum,
        } => write_bounded_count(
            formatter,
            "Via aggregate",
            "parameters",
            *location,
            *count,
            *maximum,
        ),
        ValidationError::DuplicateSingletonHeader { location } => write!(
            formatter,
            "SIP message contains duplicate {} header at wire index {}, occurrence {}",
            location.kind(),
            location.index(),
            location.occurrence(),
        ),
        ValidationError::ContentLengthMismatch {
            location,
            declared,
            actual,
        } => write!(
            formatter,
            "SIP Content-Length at wire index {} declares {declared} bytes but the retained body contains {actual}",
            location.index(),
        ),
        ValidationError::InvalidLogicalValue { .. }
        | ValidationError::InvalidVia { .. }
        | ValidationError::InvalidFrom { .. }
        | ValidationError::InvalidTo { .. }
        | ValidationError::InvalidCallId { .. }
        | ValidationError::InvalidCSeq { .. }
        | ValidationError::InvalidMaxForwards { .. }
        | ValidationError::InvalidContentLength { .. }
        | ValidationError::InvalidContentType { .. } => {
            formatter.write_str("invalid SIP core header value")
        }
    }
}

fn write_structural_validation_error(
    formatter: &mut fmt::Formatter<'_>,
    error: &ValidationError,
) -> fmt::Result {
    match error {
        ValidationError::HeaderSectionTooLarge { length, maximum } => write!(
            formatter,
            "SIP header section length {length} exceeds maximum {maximum}"
        ),
        ValidationError::InvalidHeaderLayout { index } => match index {
            Some(index) => write!(
                formatter,
                "invalid SIP CRLF header layout at wire index {index}"
            ),
            None => formatter.write_str("invalid SIP start-line or header terminator layout"),
        },
        ValidationError::InvalidHeaderName { index, source } => write!(
            formatter,
            "invalid SIP header name at wire index {index}: {source}"
        ),
        ValidationError::InvalidHeaderDelimiter { index } => write!(
            formatter,
            "invalid SIP header delimiter at wire index {index}"
        ),
        ValidationError::HeaderLineTooLong {
            index,
            length,
            maximum,
        } => write!(
            formatter,
            "SIP physical header line at wire index {index} has length {length}, exceeding maximum {maximum}"
        ),
        ValidationError::HeaderKindMismatch {
            index,
            classified,
            cached,
        } => write_kind_mismatch(formatter, *index, *classified, *cached),
        ValidationError::InvalidRawHeaderValue {
            index,
            kind,
            source,
        } => write!(
            formatter,
            "invalid raw SIP {} header value at wire index {index}: {source}",
            kind_label(*kind),
        ),
        _ => formatter.write_str("invalid SIP structural header metadata"),
    }
}

fn write_kind_mismatch(
    formatter: &mut fmt::Formatter<'_>,
    index: usize,
    classified: Option<HeaderKind>,
    cached: Option<HeaderKind>,
) -> fmt::Result {
    write!(
        formatter,
        "SIP header classification cache mismatch at wire index {index}: name classifies as {}, metadata stores {}",
        kind_label(classified),
        kind_label(cached),
    )
}

fn write_invalid_header(
    formatter: &mut fmt::Formatter<'_>,
    location: HeaderLocation,
    source: &dyn fmt::Display,
) -> fmt::Result {
    write!(
        formatter,
        "invalid SIP {} header at wire index {}, occurrence {}: {source}",
        location.kind(),
        location.index(),
        location.occurrence(),
    )
}

fn write_bounded_count(
    formatter: &mut fmt::Formatter<'_>,
    subject: &str,
    unit: &str,
    location: HeaderLocation,
    count: usize,
    maximum: usize,
) -> fmt::Result {
    write!(
        formatter,
        "SIP {subject} reaches {count} {unit} at {} wire index {}, exceeding maximum {maximum}",
        location.kind(),
        location.index(),
    )
}

const fn kind_label(kind: Option<HeaderKind>) -> &'static str {
    match kind {
        Some(kind) => kind.as_str(),
        None => "unrecognized",
    }
}

impl StdError for ValidationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Message(source) => Some(source),
            Self::InvalidHeaderName { source, .. } => Some(source),
            Self::InvalidLogicalValue { source, .. }
            | Self::InvalidRawHeaderValue { source, .. } => Some(source),
            Self::InvalidVia { source, .. } => Some(source),
            Self::InvalidFrom { source, .. } => Some(source),
            Self::InvalidTo { source, .. } => Some(source),
            Self::InvalidCallId { source, .. } => Some(source),
            Self::InvalidCSeq { source, .. } => Some(source),
            Self::InvalidMaxForwards { source, .. } => Some(source),
            Self::InvalidContentLength { source, .. } => Some(source),
            Self::InvalidContentType { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LogicalValueError, MAX_CONTENT_LENGTH_VALUE_BYTES, MAX_CORE_HEADER_FOLDS,
        MAX_FOLDS_PER_CORE_HEADER, MAX_TOTAL_VIA_ENTRIES, MAX_TOTAL_VIA_PARAMETERS,
        MAX_TYPED_CORE_HEADER_BYTES, analyze_logical_value, materialize_logical_value,
        trim_horizontal_whitespace, validate,
    };
    use crate::sip::headers::content_length::ContentLength;
    use crate::sip::headers::content_type::ContentType;
    use crate::sip::headers::max_forwards::MaxForwards;
    use crate::sip::parser::message::parse;
    use crate::sip::types::header::HeaderKind;
    use crate::sip::types::message::{RawHeader, RawMessage, Span};
    use crate::sip::types::method::Method;
    use std::borrow::Cow;
    use std::error::Error as _;
    use std::sync::Arc;

    fn parse_message(input: &[u8]) -> RawMessage {
        let Ok(message) = parse(Arc::from(input)) else {
            panic!("expected structurally valid SIP message");
        };

        message
    }

    fn valid_request() -> RawMessage {
        parse_message(
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: \"Alice\" <sip:alice@example.com>;tag=from-one\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: request-one@example.com\r\n\
              CSeq: 1 INVITE\r\n\
              Max-Forwards: 70\r\n\
              Content-Type: application/sdp;charset=utf-8\r\n\
              Content-Length: 3\r\n\
              \r\n\
              v=0",
        )
    }

    fn build_raw_message(
        headers: &[(&[u8], &[u8], Option<HeaderKind>)],
        body: &[u8],
    ) -> RawMessage {
        build_raw_message_with_wire(headers, body, b':', b"\r\n")
    }

    fn build_raw_message_with_wire(
        headers: &[(&[u8], &[u8], Option<HeaderKind>)],
        body: &[u8],
        delimiter: u8,
        header_terminator: &[u8],
    ) -> RawMessage {
        const PREFIX: &[u8] = b"OPTIONS sip:a@example.com SIP/2.0\r\n";

        let template = parse_message(b"OPTIONS sip:a@example.com SIP/2.0\r\n\r\n");
        let start_line = template.start_line();
        let mut bytes = PREFIX.to_vec();
        let mut metadata = Vec::new();

        for (name, value, kind) in headers {
            let name_start = bytes.len();
            bytes.extend_from_slice(name);
            let name_end = bytes.len();
            bytes.push(delimiter);
            let value_start = bytes.len();
            bytes.extend_from_slice(value);
            let value_end = bytes.len();
            bytes.extend_from_slice(b"\r\n");

            let Ok(name_span) = Span::new(name_start, name_end) else {
                panic!("expected valid header-name span");
            };
            let Ok(value_span) = Span::new(value_start, value_end) else {
                panic!("expected valid header-value span");
            };
            let Ok(header) = RawHeader::new(name_span, value_span, *kind) else {
                panic!("expected valid raw-header metadata");
            };

            metadata.push(header);
        }

        bytes.extend_from_slice(header_terminator);
        let body_start = bytes.len();
        bytes.extend_from_slice(body);

        let Ok(body_span) = Span::new(body_start, bytes.len()) else {
            panic!("expected valid body span");
        };

        let Ok(message) = RawMessage::new(Arc::from(bytes), start_line, metadata, body_span) else {
            panic!("expected valid raw-message metadata");
        };

        message
    }

    fn required_headers<'a>() -> Vec<(&'a [u8], &'a [u8], Option<HeaderKind>)> {
        vec![
            (
                b"Via",
                b" SIP/2.0/UDP client.example.com;branch=z9hG4bK-one",
                Some(HeaderKind::Via),
            ),
            (
                b"From",
                b" <sip:alice@example.com>;tag=one",
                Some(HeaderKind::From),
            ),
            (b"To", b" <sip:bob@example.com>", Some(HeaderKind::To)),
            (
                b"Call-ID",
                b" raw-one@example.com",
                Some(HeaderKind::CallId),
            ),
            (b"CSeq", b" 1 OPTIONS", Some(HeaderKind::CSeq)),
        ]
    }

    #[test]
    fn validates_and_exposes_typed_core_headers() {
        let message = valid_request();
        let Ok(headers) = validate(&message) else {
            panic!("expected valid typed core headers");
        };

        assert_eq!(headers.via_field_count(), 1);
        assert_eq!(headers.via_entry_count(), 1);
        assert_eq!(headers.via_parameter_count(), 1);
        assert_eq!(headers.topmost_via().branch(), Some("z9hG4bK-one"));
        assert_eq!(headers.from_header().tag(), Some("from-one"));
        assert_eq!(headers.to_header().tag(), None);
        assert_eq!(headers.call_id().as_str(), "request-one@example.com");
        assert_eq!(headers.cseq().sequence(), 1);
        assert_eq!(headers.cseq().method(), &Method::Invite);
        assert_eq!(headers.max_forwards(), Some(MaxForwards::new(70)));
        assert_eq!(
            headers.content_length().map(ContentLength::as_usize),
            Some(3)
        );
        assert!(
            headers
                .content_type()
                .is_some_and(ContentType::is_application_sdp)
        );
        assert_eq!(message.body(), b"v=0");
    }

    #[test]
    fn accepts_absent_optional_core_headers_for_role_neutral_validation() {
        let message = parse_message(
            b"SIP/2.0 200 OK\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:bob@example.com>;tag=two\r\n\
              Call-ID: response-one@example.com\r\n\
              CSeq: 1 INVITE\r\n\
              \r\n",
        );

        let Ok(headers) = validate(&message) else {
            panic!("expected valid response core headers");
        };

        assert_eq!(headers.max_forwards(), None);
        assert_eq!(headers.content_length(), None);
        assert_eq!(headers.content_type(), None);
    }

    #[test]
    fn recognizes_compact_core_names_at_the_typed_boundary() {
        let message = parse_message(
            b"OPTIONS sip:service@example.com SIP/2.0\r\n\
              v: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              f: <sip:alice@example.com>;tag=one\r\n\
              t: <sip:service@example.com>\r\n\
              i: compact@example.com\r\n\
              CSeq: 4 OPTIONS\r\n\
              c: application/sdp\r\n\
              l: 0\r\n\
              \r\n",
        );

        let Ok(headers) = validate(&message) else {
            panic!("expected compact core fields to validate");
        };

        assert_eq!(headers.call_id().as_str(), "compact@example.com");
        assert_eq!(
            headers.content_length().map(ContentLength::as_usize),
            Some(0)
        );
        assert!(
            headers
                .content_type()
                .is_some_and(ContentType::is_application_sdp)
        );
    }

    #[test]
    fn reports_second_long_or_compact_singleton_with_exact_location() {
        let message = parse_message(
            b"OPTIONS sip:service@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              f: <sip:other@example.com>;tag=two\r\n\
              To: <sip:service@example.com>\r\n\
              Call-ID: duplicate@example.com\r\n\
              CSeq: 4 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        let Err(error) = validate(&message) else {
            panic!("expected duplicate compact singleton rejection");
        };

        assert_eq!(error.class(), "duplicate-singleton-header");
        assert_eq!(error.header_kind(), Some(HeaderKind::From));
        assert_eq!(error.header_index(), Some(2));
        assert_eq!(error.header_occurrence(), Some(2));
    }

    #[test]
    fn preserves_message_level_missing_before_duplicate_precedence() {
        let message = build_raw_message(
            &[
                (
                    b"From",
                    b" <sip:alice@example.com>;tag=one",
                    Some(HeaderKind::From),
                ),
                (
                    b"f",
                    b" <sip:other@example.com>;tag=two",
                    Some(HeaderKind::From),
                ),
                (b"To", b" <sip:service@example.com>", Some(HeaderKind::To)),
                (
                    b"Call-ID",
                    b" precedence@example.com",
                    Some(HeaderKind::CallId),
                ),
                (b"CSeq", b" 1 OPTIONS", Some(HeaderKind::CSeq)),
            ],
            b"",
        );

        let Err(error) = validate(&message) else {
            panic!("expected missing Via to precede duplicate From");
        };

        assert_eq!(error.class(), "missing-required-header");
        assert_eq!(error.header_kind(), Some(HeaderKind::Via));
        assert_eq!(error.header_index(), None);
        assert_eq!(error.header_occurrence(), None);
    }

    #[test]
    fn combines_repeated_and_comma_separated_vias_in_wire_order() {
        let message = parse_message(
            b"OPTIONS sip:service@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP first.example.com;branch=z9hG4bK-one;note=\"a,b\", SIP/2.0/TCP second.example.com;branch=z9hG4bK-two\r\n\
              v: SIP/2.0/TLS third.example.com;branch=z9hG4bK-three\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:service@example.com>\r\n\
              Call-ID: via-order@example.com\r\n\
              CSeq: 8 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        let Ok(headers) = validate(&message) else {
            panic!("expected valid combined Via list");
        };

        let mut entries = headers.via().entries().iter();
        let Some(first) = entries.next() else {
            panic!("expected first Via entry");
        };
        let Some(second) = entries.next() else {
            panic!("expected second Via entry");
        };
        let Some(third) = entries.next() else {
            panic!("expected third Via entry");
        };

        assert_eq!(first.sent_by_host().as_domain(), Some("first.example.com"));
        assert_eq!(
            second.sent_by_host().as_domain(),
            Some("second.example.com")
        );
        assert_eq!(third.sent_by_host().as_domain(), Some("third.example.com"));
        assert!(entries.next().is_none());
        assert_eq!(headers.via_field_count(), 2);
        assert_eq!(headers.via_entry_count(), 3);
    }

    #[test]
    fn unfolds_and_trims_all_typed_core_values_once() {
        let message = parse_message(
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP\r\n\
              \x20client.example.com;branch=z9hG4bK-fold\r\n\
              From: \"Alice\r\n\
              \x20Smith\" <sip:alice@example.com>;tag=one\r\n\
              To:\r\n\
              \x20<sip:bob@example.com>\r\n\
              Call-ID:\r\n\
              \x20folded@example.com\r\n\
              CSeq: 1\r\n\
              \x20INVITE\r\n\
              Max-Forwards:\r\n\
              \x2070\r\n\
              Content-Type: application/sdp;\r\n\
              \x20charset=utf-8\r\n\
              Content-Length:\r\n\
              \x200\r\n\
              \r\n",
        );

        let Ok(headers) = validate(&message) else {
            panic!("expected folded core headers to validate");
        };

        assert_eq!(
            headers.topmost_via().sent_by_host().as_domain(),
            Some("client.example.com")
        );
        assert_eq!(headers.from_header().tag(), Some("one"));
        assert_eq!(headers.call_id().as_str(), "folded@example.com");
        assert_eq!(headers.cseq().method(), &Method::Invite);
        assert_eq!(headers.max_forwards(), Some(MaxForwards::new(70)));
        assert_eq!(
            headers.content_length().map(ContentLength::as_usize),
            Some(0)
        );
        assert_eq!(
            headers.content_type().and_then(|value| value.charset()),
            Some("utf-8")
        );
    }

    #[test]
    fn no_fold_path_borrows_and_fold_path_allocates() {
        let no_fold = b"  one\t two  ";
        let Ok(no_fold_analysis) = analyze_logical_value(no_fold) else {
            panic!("expected valid unfolded analysis");
        };
        let Ok(no_fold_value) = materialize_logical_value(no_fold_analysis) else {
            panic!("expected borrowed logical value");
        };

        assert!(matches!(no_fold_value, Cow::Borrowed(_)));
        assert_eq!(
            trim_horizontal_whitespace(no_fold_value.as_ref()),
            b"one\t two"
        );

        let folded = b"one\r\n\t  two";
        let Ok(folded_analysis) = analyze_logical_value(folded) else {
            panic!("expected valid folded analysis");
        };
        let Ok(folded_value) = materialize_logical_value(folded_analysis) else {
            panic!("expected owned logical value");
        };

        assert!(matches!(folded_value, Cow::Owned(_)));
        assert_eq!(folded_value.as_ref(), b"one two");

        let folded_lws = b"one \t\r\n  two";
        let Ok(folded_lws_analysis) = analyze_logical_value(folded_lws) else {
            panic!("expected complete folded LWS analysis");
        };
        let Ok(folded_lws_value) = materialize_logical_value(folded_lws_analysis) else {
            panic!("expected complete folded LWS normalization");
        };

        assert_eq!(folded_lws_value.as_ref(), b"one two");
        assert_eq!(folded_lws_analysis.trimmed_length(), 7);
    }

    #[test]
    fn enforces_exact_per_field_fold_boundary() {
        let mut accepted = Vec::from(b"one".as_slice());

        for _ in 0..MAX_FOLDS_PER_CORE_HEADER {
            accepted.extend_from_slice(b"\r\n value");
        }

        let Ok(analysis) = analyze_logical_value(&accepted) else {
            panic!("expected maximum per-field fold count to validate");
        };
        assert_eq!(analysis.folds(), MAX_FOLDS_PER_CORE_HEADER);

        accepted.extend_from_slice(b"\r\n value");
        let Err(error) = analyze_logical_value(&accepted) else {
            panic!("expected excessive per-field fold count rejection");
        };

        assert_eq!(
            error,
            LogicalValueError::TooManyFolds {
                count: MAX_FOLDS_PER_CORE_HEADER + 1,
                maximum: MAX_FOLDS_PER_CORE_HEADER,
            }
        );
    }

    #[test]
    fn reports_typed_failure_with_kind_wire_index_and_occurrence() {
        let message = parse_message(
            b"OPTIONS sip:service@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:service@example.com>\r\n\
              Call-ID: invalid-cseq@example.com\r\n\
              CSeq: 1 BAD METHOD\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        let Err(error) = validate(&message) else {
            panic!("expected invalid CSeq");
        };

        assert_eq!(error.class(), "invalid-cseq");
        assert_eq!(error.detail_class(), "invalid-method");
        assert_eq!(error.header_kind(), Some(HeaderKind::CSeq));
        assert_eq!(error.header_index(), Some(4));
        assert_eq!(error.header_occurrence(), Some(1));
        assert!(error.source().is_some());
    }

    fn assert_typed_failure(
        headers: &[(&[u8], &[u8], Option<HeaderKind>)],
        expected_kind: HeaderKind,
        expected_class: &str,
        expected_index: usize,
    ) {
        let message = build_raw_message(headers, b"");
        let Err(error) = validate(&message) else {
            panic!("expected invalid typed core header");
        };

        assert_eq!(error.class(), expected_class);
        assert_eq!(error.header_kind(), Some(expected_kind));
        assert_eq!(error.header_index(), Some(expected_index));
        assert_eq!(error.header_occurrence(), Some(1));
        assert!(error.source().is_some());
    }

    #[test]
    fn maps_every_typed_core_dispatch_failure_without_raw_contents() {
        let mut invalid_via = required_headers();
        invalid_via[0] = (b"Via", b" invalid", Some(HeaderKind::Via));
        assert_typed_failure(&invalid_via, HeaderKind::Via, "invalid-via", 0);

        let mut invalid_from = required_headers();
        invalid_from[1] = (b"From", b" <", Some(HeaderKind::From));
        assert_typed_failure(&invalid_from, HeaderKind::From, "invalid-from", 1);

        let mut invalid_to = required_headers();
        invalid_to[2] = (b"To", b" <", Some(HeaderKind::To));
        assert_typed_failure(&invalid_to, HeaderKind::To, "invalid-to", 2);

        let mut invalid_call_id = required_headers();
        invalid_call_id[3] = (b"Call-ID", b" private id", Some(HeaderKind::CallId));
        assert_typed_failure(&invalid_call_id, HeaderKind::CallId, "invalid-call-id", 3);

        let mut invalid_max_forwards = required_headers();
        invalid_max_forwards.push((b"Max-Forwards", b" 999", Some(HeaderKind::MaxForwards)));
        assert_typed_failure(
            &invalid_max_forwards,
            HeaderKind::MaxForwards,
            "invalid-max-forwards",
            5,
        );

        let mut invalid_content_length = required_headers();
        invalid_content_length.push((b"Content-Length", b" x", Some(HeaderKind::ContentLength)));
        assert_typed_failure(
            &invalid_content_length,
            HeaderKind::ContentLength,
            "invalid-content-length",
            5,
        );

        let mut invalid_content_type = required_headers();
        invalid_content_type.push((b"Content-Type", b" invalid", Some(HeaderKind::ContentType)));
        assert_typed_failure(
            &invalid_content_type,
            HeaderKind::ContentType,
            "invalid-content-type",
            5,
        );
    }

    #[test]
    fn leaves_non_core_known_and_unknown_headers_lazy() {
        let message = parse_message(
            b"OPTIONS sip:service@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
              From: <sip:alice@example.com>;tag=one\r\n\
              To: <sip:service@example.com>\r\n\
              Call-ID: lazy@example.com\r\n\
              CSeq: 1 OPTIONS\r\n\
              Supported: ,,,\r\n\
              X-Future: opaque\xffbytes\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        assert!(validate(&message).is_ok());
        assert_eq!(message.header_count(), 8);
    }

    #[test]
    fn rejects_forged_cached_header_classification_before_presence_checks() {
        let message = build_raw_message(&[(b"X-Evil", b" anything", Some(HeaderKind::Via))], b"");

        let Err(error) = validate(&message) else {
            panic!("expected classification mismatch");
        };

        assert_eq!(error.class(), "header-kind-mismatch");
        assert_eq!(error.header_kind(), Some(HeaderKind::Via));
        assert_eq!(error.header_index(), Some(0));
    }

    #[test]
    fn rejects_forged_raw_names_delimiters_and_header_terminators() {
        let invalid_name = build_raw_message(&[(b"Bad Name", b" value", None)], b"");
        let Err(name_error) = validate(&invalid_name) else {
            panic!("expected invalid raw header name rejection");
        };

        assert_eq!(name_error.class(), "invalid-header-name");
        assert_eq!(name_error.detail_class(), "invalid-token");
        assert_eq!(name_error.header_index(), Some(0));
        assert!(name_error.source().is_some());

        let invalid_delimiter =
            build_raw_message_with_wire(&[(b"X-Test", b" value", None)], b"", b'=', b"\r\n");
        let Err(delimiter_error) = validate(&invalid_delimiter) else {
            panic!("expected invalid raw header delimiter rejection");
        };

        assert_eq!(delimiter_error.class(), "invalid-header-delimiter");
        assert_eq!(delimiter_error.header_index(), Some(0));

        let invalid_terminator =
            build_raw_message_with_wire(&[(b"X-Test", b" value", None)], b"", b':', b"\n");
        let Err(layout_error) = validate(&invalid_terminator) else {
            panic!("expected invalid raw header terminator rejection");
        };

        assert_eq!(layout_error.class(), "invalid-header-layout");
        assert_eq!(layout_error.header_index(), Some(0));
    }

    #[test]
    fn structurally_checks_lazy_extension_values_without_parsing_them() {
        let mut headers = required_headers();
        headers.push((b"X-Future", b" opaque\x7fvalue", None));
        let message = build_raw_message(&headers, b"");

        let Err(error) = validate(&message) else {
            panic!("expected invalid extension control-byte rejection");
        };

        assert_eq!(error.class(), "invalid-raw-header-value");
        assert_eq!(error.detail_class(), "invalid-control");
        assert_eq!(error.header_kind(), None);
        assert_eq!(error.header_index(), Some(5));
        assert!(error.source().is_some());
    }

    #[test]
    fn defensively_rejects_illegal_line_breaks_in_manual_raw_values() {
        let mut headers = required_headers();
        headers[0] = (
            b"Via",
            b" SIP/2.0/UDP client.example.com\rX",
            Some(HeaderKind::Via),
        );
        let message = build_raw_message(&headers, b"");

        let Err(error) = validate(&message) else {
            panic!("expected invalid raw line break");
        };

        assert_eq!(error.class(), "invalid-logical-header-value");
        assert_eq!(error.detail_class(), "bare-carriage-return");
        assert_eq!(error.header_kind(), Some(HeaderKind::Via));
        assert_eq!(error.header_index(), Some(0));
    }

    #[test]
    fn defensively_revalidates_content_length_uniqueness_and_body_match() {
        let mut duplicate_headers = required_headers();
        duplicate_headers.push((
            b"Content-Length",
            b" not-a-number",
            Some(HeaderKind::ContentLength),
        ));
        duplicate_headers.push((b"l", b" 0", Some(HeaderKind::ContentLength)));
        let duplicate = build_raw_message(&duplicate_headers, b"");

        let Err(duplicate_error) = validate(&duplicate) else {
            panic!("expected duplicate Content-Length rejection");
        };

        assert_eq!(duplicate_error.class(), "duplicate-singleton-header");
        assert_eq!(
            duplicate_error.header_kind(),
            Some(HeaderKind::ContentLength)
        );
        assert_eq!(duplicate_error.header_index(), Some(6));
        assert_eq!(duplicate_error.header_occurrence(), Some(2));

        let mut mismatch_headers = required_headers();
        mismatch_headers.push((
            b"Content-Type",
            b" application/octet-stream",
            Some(HeaderKind::ContentType),
        ));
        mismatch_headers.push((b"Content-Length", b" 0", Some(HeaderKind::ContentLength)));
        let mismatch = build_raw_message(&mismatch_headers, b"x");

        let Err(mismatch_error) = validate(&mismatch) else {
            panic!("expected Content-Length mismatch rejection");
        };

        assert_eq!(mismatch_error.class(), "content-length-mismatch");
        assert_eq!(
            mismatch_error.header_kind(),
            Some(HeaderKind::ContentLength)
        );
        assert_eq!(mismatch_error.header_index(), Some(6));
    }

    fn via_value(start: usize, count: usize, parameter_count: usize) -> String {
        let mut value = String::new();

        for offset in 0..count {
            if offset != 0 {
                value.push_str(", ");
            }

            let sequence = start.saturating_add(offset);
            value.push_str("SIP/2.0/UDP h");
            value.push_str(&sequence.to_string());
            value.push_str(".example.com");

            for parameter in 0..parameter_count {
                value.push_str(";p");
                value.push_str(&parameter.to_string());
                value.push_str("=x");
            }
        }

        value
    }

    fn message_with_vias(vias: &[String]) -> RawMessage {
        let mut input = String::from("OPTIONS sip:service@example.com SIP/2.0\r\n");

        for via in vias {
            input.push_str("Via: ");
            input.push_str(via);
            input.push_str("\r\n");
        }

        input.push_str(
            "From: <sip:alice@example.com>;tag=one\r\n\
             To: <sip:service@example.com>\r\n\
             Call-ID: aggregate@example.com\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\
             \r\n",
        );

        parse_message(input.as_bytes())
    }

    fn message_with_via_fold_counts(fold_counts: &[usize]) -> RawMessage {
        let mut input = String::from("OPTIONS sip:service@example.com SIP/2.0\r\n");

        for (index, fold_count) in fold_counts.iter().copied().enumerate() {
            input.push_str("Via: SIP/2.0/UDP");

            for _ in 0..fold_count {
                input.push_str("\r\n ");
            }

            input.push_str("hop");
            input.push_str(&index.to_string());
            input.push_str(".example.com\r\n");
        }

        input.push_str(
            "From: <sip:alice@example.com>;tag=one\r\n\
             To: <sip:service@example.com>\r\n\
             Call-ID: folds@example.com\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\
             \r\n",
        );

        parse_message(input.as_bytes())
    }

    #[test]
    fn enforces_aggregate_core_fold_boundary() {
        let accepted = message_with_via_fold_counts(&[64, 64, 64, 64]);
        assert!(validate(&accepted).is_ok());

        let rejected = message_with_via_fold_counts(&[64, 64, 64, 64, 1]);
        let Err(error) = validate(&rejected) else {
            panic!("expected excessive aggregate fold rejection");
        };

        assert_eq!(error.class(), "core-header-folds-exceeded");
        assert_eq!(error.header_kind(), Some(HeaderKind::Via));
        assert_eq!(error.header_index(), Some(4));
        assert_eq!(error.header_occurrence(), Some(5));
        assert_eq!(MAX_CORE_HEADER_FOLDS, 256);
    }

    #[test]
    fn enforces_a_meaningful_typed_core_byte_budget() {
        let padding = " ".repeat(6_550);
        let input = format!(
            "OPTIONS sip:service@example.com SIP/2.0\r\n\
             Via:{padding}SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
             From:{padding}<sip:alice@example.com>;tag=one\r\n\
             To:{padding}<sip:service@example.com>\r\n\
             Call-ID:{padding}budget@example.com\r\n\
             CSeq:{padding}1 OPTIONS\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );
        let message = parse_message(input.as_bytes());

        let Err(error) = validate(&message) else {
            panic!("expected typed core byte-budget rejection");
        };

        assert_eq!(error.class(), "core-header-bytes-exceeded");
        assert_eq!(error.header_kind(), Some(HeaderKind::CSeq));
        assert_eq!(error.header_index(), Some(4));
        let super::ValidationError::CoreHeaderBytesExceeded { maximum, .. } = error else {
            panic!("expected typed core byte-budget error");
        };
        assert_eq!(maximum, MAX_TYPED_CORE_HEADER_BYTES);
    }

    #[test]
    fn enforces_aggregate_via_entry_limit_across_fields() {
        let accepted = message_with_vias(&[via_value(0, 32, 0), via_value(32, 32, 0)]);
        let Ok(headers) = validate(&accepted) else {
            panic!("expected maximum aggregate Via count to validate");
        };

        assert_eq!(headers.via_entry_count(), MAX_TOTAL_VIA_ENTRIES);

        let rejected = message_with_vias(&[via_value(0, 32, 0), via_value(32, 33, 0)]);
        let Err(error) = validate(&rejected) else {
            panic!("expected excessive aggregate Via count rejection");
        };

        assert_eq!(error.class(), "too-many-via-entries");
        assert_eq!(error.header_index(), Some(1));
        assert_eq!(error.header_occurrence(), Some(2));
    }

    #[test]
    fn enforces_aggregate_via_parameter_limit() {
        let accepted = message_with_vias(&[via_value(0, 64, 8)]);
        let Ok(headers) = validate(&accepted) else {
            panic!("expected maximum aggregate Via parameters to validate");
        };

        assert_eq!(headers.via_parameter_count(), MAX_TOTAL_VIA_PARAMETERS);

        let rejected = message_with_vias(&[via_value(0, 64, 9)]);
        let Err(error) = validate(&rejected) else {
            panic!("expected excessive aggregate Via parameters rejection");
        };

        assert_eq!(error.class(), "too-many-via-parameters");
        assert_eq!(error.header_kind(), Some(HeaderKind::Via));
    }

    #[test]
    fn bounds_leading_zero_content_length_before_numeric_parsing() {
        let zeros = "0".repeat(MAX_CONTENT_LENGTH_VALUE_BYTES + 1);
        let input = format!(
            "OPTIONS sip:service@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-one\r\n\
             From: <sip:alice@example.com>;tag=one\r\n\
             To: <sip:service@example.com>\r\n\
             Call-ID: zeros@example.com\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: {zeros}\r\n\
             \r\n"
        );
        let message = parse_message(input.as_bytes());

        let Err(error) = validate(&message) else {
            panic!("expected excessive logical Content-Length rejection");
        };

        assert_eq!(error.class(), "header-value-too-long");
        assert_eq!(error.header_kind(), Some(HeaderKind::ContentLength));
    }

    #[test]
    fn logical_value_errors_have_stable_classes() {
        assert_eq!(
            analyze_logical_value(b"one\n two"),
            Err(LogicalValueError::BareLineFeed { index: 3 })
        );
        assert_eq!(
            analyze_logical_value(b"one\r\ntwo"),
            Err(LogicalValueError::MissingContinuationWhitespace { index: 3 })
        );
        assert_eq!(
            analyze_logical_value(b"one\0two"),
            Err(LogicalValueError::InvalidControl { index: 3, byte: 0 })
        );
        assert_eq!(
            LogicalValueError::BareLineFeed { index: 0 }.class(),
            "bare-line-feed"
        );
    }

    #[test]
    fn validated_debug_output_redacts_signaling_identifiers() {
        let message = valid_request();
        let Ok(headers) = validate(&message) else {
            panic!("expected valid typed core headers");
        };

        let debug = format!("{headers:?}");

        assert!(!debug.contains("alice"));
        assert!(!debug.contains("bob"));
        assert!(!debug.contains("client.example.com"));
        assert!(!debug.contains("request-one@example.com"));
        assert!(!debug.contains("z9hG4bK-one"));
        assert!(debug.contains("call_id_bytes"));
    }
}
