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

//! Canonical SIP header-section serialization.
//!
//! Only validated [`HeaderName`] and [`HeaderValue`] values enter this layer,
//! which makes CRLF injection unrepresentable. Each field is emitted as
//! `Name: value\r\n`; recognized compact names are deliberately expanded to
//! their canonical long form.
//!
//! The writer owns a bounded buffer, enforces physical-line and aggregate
//! header-section limits before mutation, and never leaves a partially written
//! field behind when an operation fails.

use std::collections::TryReserveError;
use std::error::Error as StdError;
use std::fmt;

use crate::sip::framing::{MAX_HEADER_BYTES, MAX_HEADER_COUNT, MAX_LINE_BYTES};
use crate::sip::types::header::{Header, HeaderName, HeaderValue};

const HEADER_SEPARATOR: &[u8] = b": ";
const CRLF: &[u8] = b"\r\n";

/// Incremental bounded writer for a canonical SIP header section.
///
/// The buffer does not include a SIP start line. Calling [`Self::finish`]
/// appends the final empty-line CRLF and returns the complete header section.
pub struct HeaderSectionWriter {
    bytes: Vec<u8>,
    header_count: usize,
}

impl HeaderSectionWriter {
    /// Creates an empty header-section writer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            header_count: 0,
        }
    }

    /// Creates an empty writer with bounded preallocated capacity.
    ///
    /// # Errors
    ///
    /// Returns [`SerializeError::SectionTooLarge`] when the requested capacity
    /// exceeds the complete section limit, or
    /// [`SerializeError::AllocationFailed`] if reservation fails.
    pub fn with_capacity(capacity: usize) -> Result<Self, SerializeError> {
        if capacity > MAX_HEADER_BYTES {
            return Err(SerializeError::SectionTooLarge {
                attempted: capacity,
                maximum: MAX_HEADER_BYTES,
            });
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(SerializeError::AllocationFailed)?;

        Ok(Self {
            bytes,
            header_count: 0,
        })
    }

    /// Appends one validated header using its canonical name.
    ///
    /// # Errors
    ///
    /// Returns [`SerializeError`] before modifying the writer when the header
    /// count, physical line, aggregate section size, or allocation bound would
    /// be exceeded.
    pub fn push(&mut self, header: &Header) -> Result<(), SerializeError> {
        self.push_parts(header.name(), header.value())
    }

    /// Appends one validated name/value pair using canonical formatting.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::push`].
    pub fn push_parts(
        &mut self,
        name: &HeaderName,
        value: &HeaderValue,
    ) -> Result<(), SerializeError> {
        let attempted_count =
            self.header_count
                .checked_add(1)
                .ok_or(SerializeError::TooManyHeaders {
                    attempted: usize::MAX,
                    maximum: MAX_HEADER_COUNT,
                })?;

        if attempted_count > MAX_HEADER_COUNT {
            return Err(SerializeError::TooManyHeaders {
                attempted: attempted_count,
                maximum: MAX_HEADER_COUNT,
            });
        }

        let line_bytes = name
            .as_bytes()
            .len()
            .checked_add(HEADER_SEPARATOR.len())
            .and_then(|length| length.checked_add(value.len()))
            .ok_or(SerializeError::LineTooLong {
                attempted: usize::MAX,
                maximum: MAX_LINE_BYTES,
            })?;

        if line_bytes > MAX_LINE_BYTES {
            return Err(SerializeError::LineTooLong {
                attempted: line_bytes,
                maximum: MAX_LINE_BYTES,
            });
        }

        let field_bytes =
            line_bytes
                .checked_add(CRLF.len())
                .ok_or(SerializeError::SectionTooLarge {
                    attempted: usize::MAX,
                    maximum: MAX_HEADER_BYTES,
                })?;
        let attempted_section = self
            .bytes
            .len()
            .checked_add(field_bytes)
            .and_then(|length| length.checked_add(CRLF.len()))
            .ok_or(SerializeError::SectionTooLarge {
                attempted: usize::MAX,
                maximum: MAX_HEADER_BYTES,
            })?;

        if attempted_section > MAX_HEADER_BYTES {
            return Err(SerializeError::SectionTooLarge {
                attempted: attempted_section,
                maximum: MAX_HEADER_BYTES,
            });
        }

        self.bytes
            .try_reserve_exact(field_bytes)
            .map_err(SerializeError::AllocationFailed)?;

        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.extend_from_slice(HEADER_SEPARATOR);
        self.bytes.extend_from_slice(value.as_bytes());
        self.bytes.extend_from_slice(CRLF);
        self.header_count = attempted_count;

        Ok(())
    }

    /// Returns the number of serialized header fields.
    #[must_use]
    pub const fn header_count(&self) -> usize {
        self.header_count
    }

    /// Returns the current serialized byte length before the final empty line.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether no header fields have been written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.header_count == 0
    }

    /// Finishes the section by appending its terminating empty line.
    ///
    /// # Errors
    ///
    /// Returns [`SerializeError::AllocationFailed`] if the final two-byte
    /// reservation fails. All size bounds were reserved during `push` calls.
    pub fn finish(mut self) -> Result<Vec<u8>, SerializeError> {
        debug_assert!(self.bytes.len().saturating_add(CRLF.len()) <= MAX_HEADER_BYTES);
        self.bytes
            .try_reserve_exact(CRLF.len())
            .map_err(SerializeError::AllocationFailed)?;
        self.bytes.extend_from_slice(CRLF);

        Ok(self.bytes)
    }
}

impl Default for HeaderSectionWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HeaderSectionWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderSectionWriter")
            .field("header_count", &self.header_count)
            .field("serialized_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Failure to serialize a bounded SIP header section.
#[derive(Debug)]
#[non_exhaustive]
pub enum SerializeError {
    /// More header fields were requested than the framing layer accepts.
    TooManyHeaders {
        /// Header count that would have resulted.
        attempted: usize,

        /// Maximum permitted header count.
        maximum: usize,
    },

    /// One canonical physical header line exceeded its bound.
    LineTooLong {
        /// Attempted line size, excluding CRLF.
        attempted: usize,

        /// Maximum permitted line size.
        maximum: usize,
    },

    /// The canonical header section exceeded its aggregate bound.
    SectionTooLarge {
        /// Attempted section size, including its final empty line.
        attempted: usize,

        /// Maximum permitted section size.
        maximum: usize,
    },

    /// The bounded output allocation could not be reserved.
    AllocationFailed(TryReserveError),
}

impl SerializeError {
    /// Returns a stable low-cardinality classification suitable for metrics.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::TooManyHeaders { .. } => "too-many-headers",
            Self::LineTooLong { .. } => "line-too-long",
            Self::SectionTooLarge { .. } => "section-too-large",
            Self::AllocationFailed(_) => "allocation-failed",
        }
    }
}

impl fmt::Display for SerializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyHeaders { attempted, maximum } => write!(
                formatter,
                "SIP header count {attempted} exceeds maximum {maximum}"
            ),
            Self::LineTooLong { attempted, maximum } => write!(
                formatter,
                "serialized SIP header line length {attempted} exceeds maximum {maximum}"
            ),
            Self::SectionTooLarge { attempted, maximum } => write!(
                formatter,
                "serialized SIP header section length {attempted} exceeds maximum {maximum}"
            ),
            Self::AllocationFailed(_) => {
                formatter.write_str("failed to reserve bounded SIP header output")
            }
        }
    }
}

impl StdError for SerializeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::AllocationFailed(error) => Some(error),
            Self::TooManyHeaders { .. }
            | Self::LineTooLong { .. }
            | Self::SectionTooLarge { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sip::framing::{MAX_HEADER_BYTES, MAX_HEADER_COUNT, MAX_LINE_BYTES};
    use crate::sip::types::header::{Header, HeaderKind, HeaderName, HeaderValue};

    use super::{HeaderSectionWriter, SerializeError};

    fn value(bytes: &[u8]) -> HeaderValue {
        let Ok(value) = HeaderValue::from_bytes(bytes) else {
            panic!("expected valid header value");
        };

        value
    }

    fn extension_name(bytes: &[u8]) -> HeaderName {
        let Ok(name) = HeaderName::from_bytes(bytes) else {
            panic!("expected valid extension name");
        };

        name
    }

    #[test]
    fn serializes_canonical_known_and_extension_headers() {
        let mut writer = HeaderSectionWriter::new();
        let via = Header::new(HeaderKind::Via.into(), value(b"SIP/2.0/UDP host"));
        let extension = Header::new(extension_name(b"X-Trace"), value(b"opaque"));

        assert!(writer.push(&via).is_ok());
        assert!(writer.push(&extension).is_ok());
        let Ok(bytes) = writer.finish() else {
            panic!("expected serialization success");
        };

        assert_eq!(bytes, b"Via: SIP/2.0/UDP host\r\nX-Trace: opaque\r\n\r\n");
    }

    #[test]
    fn empty_section_is_exactly_one_crlf() {
        let Ok(bytes) = HeaderSectionWriter::new().finish() else {
            panic!("expected empty section");
        };

        assert_eq!(bytes, b"\r\n");
    }

    #[test]
    fn validated_values_make_crlf_injection_unrepresentable() {
        assert!(HeaderValue::from_bytes(b"safe\r\nInjected: yes").is_err());
        assert!(HeaderValue::from_bytes(b"safe\nInjected: yes").is_err());
    }

    #[test]
    fn exact_maximum_physical_line_is_accepted() {
        let name = extension_name(b"X");
        let header_value = value(&vec![b'a'; MAX_LINE_BYTES - 3]);
        let mut writer = HeaderSectionWriter::new();

        assert!(writer.push_parts(&name, &header_value).is_ok());
        assert_eq!(writer.header_count(), 1);
    }

    #[test]
    fn overlong_line_is_rejected_without_mutation() {
        let name = extension_name(b"X");
        let header_value = value(&vec![b'a'; MAX_LINE_BYTES - 2]);
        let mut writer = HeaderSectionWriter::new();

        let Err(error) = writer.push_parts(&name, &header_value) else {
            panic!("expected line limit failure");
        };

        assert!(matches!(error, SerializeError::LineTooLong { .. }));
        assert_eq!(error.class(), "line-too-long");
        assert_eq!(writer.header_count(), 0);
        assert_eq!(writer.len(), 0);
    }

    #[test]
    fn exact_header_count_is_accepted_and_next_is_transactionally_rejected() {
        let name = extension_name(b"X");
        let header_value = value(b"");
        let mut writer = HeaderSectionWriter::new();

        for _ in 0..MAX_HEADER_COUNT {
            assert!(writer.push_parts(&name, &header_value).is_ok());
        }

        let length_before = writer.len();
        let Err(error) = writer.push_parts(&name, &header_value) else {
            panic!("expected header count failure");
        };

        assert!(matches!(error, SerializeError::TooManyHeaders { .. }));
        assert_eq!(writer.header_count(), MAX_HEADER_COUNT);
        assert_eq!(writer.len(), length_before);
    }

    #[test]
    fn aggregate_section_limit_is_enforced_without_partial_field() {
        let name = extension_name(b"X");
        let header_value = value(&vec![b'a'; MAX_LINE_BYTES - 3]);
        let mut writer = HeaderSectionWriter::new();

        while writer.len() + MAX_LINE_BYTES + 2 + 2 <= MAX_HEADER_BYTES {
            assert!(writer.push_parts(&name, &header_value).is_ok());
        }

        let count_before = writer.header_count();
        let length_before = writer.len();
        let Err(error) = writer.push_parts(&name, &header_value) else {
            panic!("expected section limit failure");
        };

        assert!(matches!(error, SerializeError::SectionTooLarge { .. }));
        assert_eq!(writer.header_count(), count_before);
        assert_eq!(writer.len(), length_before);
    }

    #[test]
    fn oversized_preallocation_is_rejected() {
        let Err(error) = HeaderSectionWriter::with_capacity(MAX_HEADER_BYTES + 1) else {
            panic!("expected capacity failure");
        };

        assert!(matches!(error, SerializeError::SectionTooLarge { .. }));
    }

    #[test]
    fn debug_output_does_not_contain_header_values() {
        let mut writer = HeaderSectionWriter::new();
        let header = Header::new(extension_name(b"X-Secret"), value(b"private-token"));
        assert!(writer.push(&header).is_ok());

        let debug = format!("{writer:?}");
        assert!(!debug.contains("private-token"));
        assert!(!debug.contains("X-Secret"));
    }
}
