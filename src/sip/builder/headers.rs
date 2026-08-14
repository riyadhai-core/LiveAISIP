// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Bounded outbound SIP header assembly.
//!
//! One header slot is reserved for serializer-generated Content-Length.
//! Typed values pass through a hard-limited formatter before validation, so a
//! faulty Display implementation cannot cause unbounded builder allocation.

use std::error::Error as StdError;
use std::fmt::{self, Write as _};

use crate::sip::framing::MAX_HEADER_COUNT;
use crate::sip::types::header::{
    Header, HeaderKind, HeaderName, HeaderValue, HeaderValueError, MAX_HEADER_VALUE_BYTES,
};

/// Maximum caller-supplied fields, reserving one slot for Content-Length.
pub const MAX_OUTBOUND_HEADERS: usize = MAX_HEADER_COUNT - 1;

/// Ordered bounded collection of outbound SIP headers.
pub struct HeaderList {
    headers: Vec<Header>,
}

impl HeaderList {
    /// Creates an empty collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            headers: Vec::new(),
        }
    }

    /// Appends one validated field transactionally.
    ///
    /// # Errors
    ///
    /// Rejects serializer-owned Content-Length, count overflow, or allocation
    /// failure without modifying the collection.
    pub fn push(&mut self, header: Header) -> Result<(), BuildError> {
        if header.name().kind() == Some(HeaderKind::ContentLength) {
            return Err(BuildError::ManagedContentLength);
        }
        if self.headers.len() >= MAX_OUTBOUND_HEADERS {
            return Err(BuildError::TooManyHeaders {
                attempted: self.headers.len().saturating_add(1),
                maximum: MAX_OUTBOUND_HEADERS,
            });
        }
        self.headers
            .try_reserve_exact(1)
            .map_err(|_| BuildError::AllocationFailed)?;
        self.headers.push(header);
        Ok(())
    }

    /// Formats, validates, and appends a recognized typed field value.
    ///
    /// # Errors
    ///
    /// Returns an error for managed fields, bounded-format failures, invalid
    /// value bytes, count overflow, or allocation failure.
    pub fn push_typed<T>(&mut self, kind: HeaderKind, value: &T) -> Result<(), BuildError>
    where
        T: fmt::Display + ?Sized,
    {
        if kind == HeaderKind::ContentLength {
            return Err(BuildError::ManagedContentLength);
        }
        let formatted = format_bounded(value)?;
        let value = HeaderValue::from_bytes(&formatted).map_err(BuildError::InvalidValue)?;
        self.push(Header::new(HeaderName::known(kind), value))
    }

    /// Returns the ordered fields.
    #[must_use]
    pub fn as_slice(&self) -> &[Header] {
        &self.headers
    }

    /// Returns the field count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Returns whether no fields are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Returns whether a recognized kind is present.
    #[must_use]
    pub fn contains(&self, kind: HeaderKind) -> bool {
        self.count(kind) != 0
    }

    /// Counts fields of one recognized kind.
    #[must_use]
    pub fn count(&self, kind: HeaderKind) -> usize {
        self.headers
            .iter()
            .filter(|header| header.name().kind() == Some(kind))
            .count()
    }

    /// Consumes the collection.
    #[must_use]
    pub fn into_vec(self) -> Vec<Header> {
        self.headers
    }
}

impl Default for HeaderList {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HeaderList {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderList")
            .field("header_count", &self.headers.len())
            .finish_non_exhaustive()
    }
}

fn format_bounded<T>(value: &T) -> Result<Vec<u8>, BuildError>
where
    T: fmt::Display + ?Sized,
{
    let mut writer = BoundedWriter::new();
    if write!(&mut writer, "{value}").is_err() {
        return Err(match writer.failure {
            Some(FormatFailure::TooLong(attempted)) => BuildError::ValueTooLong {
                attempted,
                maximum: MAX_HEADER_VALUE_BYTES,
            },
            Some(FormatFailure::Allocation) => BuildError::AllocationFailed,
            None => BuildError::FormattingFailed,
        });
    }
    Ok(writer.bytes)
}

struct BoundedWriter {
    bytes: Vec<u8>,
    failure: Option<FormatFailure>,
}

impl BoundedWriter {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            failure: None,
        }
    }
}

impl fmt::Write for BoundedWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let Some(attempted) = self.bytes.len().checked_add(value.len()) else {
            self.failure = Some(FormatFailure::TooLong(usize::MAX));
            return Err(fmt::Error);
        };
        if attempted > MAX_HEADER_VALUE_BYTES {
            self.failure = Some(FormatFailure::TooLong(attempted));
            return Err(fmt::Error);
        }
        if self.bytes.try_reserve_exact(value.len()).is_err() {
            self.failure = Some(FormatFailure::Allocation);
            return Err(fmt::Error);
        }
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum FormatFailure {
    TooLong(usize),
    Allocation,
}

/// Failure to assemble outbound SIP headers.
#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    /// Content-Length was supplied outside serialization.
    ManagedContentLength,
    /// The reserved header-count bound was exceeded.
    TooManyHeaders {
        /// Attempted count.
        attempted: usize,
        /// Maximum count.
        maximum: usize,
    },
    /// Typed formatting exceeded the field-value bound.
    ValueTooLong {
        /// Attempted byte length.
        attempted: usize,
        /// Maximum byte length.
        maximum: usize,
    },
    /// Formatted bytes violated generic header-value syntax.
    InvalidValue(HeaderValueError),
    /// Display returned an unrelated failure.
    FormattingFailed,
    /// A bounded allocation failed.
    AllocationFailed,
}

impl BuildError {
    /// Returns a stable low-cardinality class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::ManagedContentLength => "managed-content-length",
            Self::TooManyHeaders { .. } => "too-many-headers",
            Self::ValueTooLong { .. } => "value-too-long",
            Self::InvalidValue(_) => "invalid-value",
            Self::FormattingFailed => "formatting-failed",
            Self::AllocationFailed => "allocation-failed",
        }
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManagedContentLength => {
                formatter.write_str("Content-Length is managed by SIP serialization")
            }
            Self::TooManyHeaders { attempted, maximum } => write!(
                formatter,
                "outbound SIP header count {attempted} exceeds maximum {maximum}"
            ),
            Self::ValueTooLong { attempted, maximum } => write!(
                formatter,
                "formatted SIP header value length {attempted} exceeds maximum {maximum}"
            ),
            Self::InvalidValue(error) => write!(formatter, "invalid header value: {error}"),
            Self::FormattingFailed => formatter.write_str("SIP header formatting failed"),
            Self::AllocationFailed => formatter.write_str("bounded header allocation failed"),
        }
    }
}

impl StdError for BuildError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidValue(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use crate::sip::headers::cseq::CSeq;
    use crate::sip::types::header::{Header, HeaderKind, HeaderName, HeaderValue};
    use crate::sip::types::method::Method;

    use super::{BuildError, HeaderList, MAX_OUTBOUND_HEADERS};

    fn extension() -> Header {
        let Ok(name) = HeaderName::from_bytes(b"X-Test") else {
            panic!("valid name");
        };
        let Ok(value) = HeaderValue::from_bytes(b"opaque") else {
            panic!("valid value");
        };
        Header::new(name, value)
    }

    #[test]
    fn typed_values_are_canonical() {
        let Ok(cseq) = CSeq::new(42, Method::Invite) else {
            panic!("valid CSeq");
        };
        let mut list = HeaderList::new();
        assert!(list.push_typed(HeaderKind::CSeq, &cseq).is_ok());
        assert_eq!(list.as_slice()[0].value().as_bytes(), b"42 INVITE");
        assert!(list.contains(HeaderKind::CSeq));
    }

    #[test]
    fn content_length_is_rejected_transactionally() {
        let mut list = HeaderList::new();
        assert!(matches!(
            list.push_typed(HeaderKind::ContentLength, &0),
            Err(BuildError::ManagedContentLength)
        ));
        assert!(list.is_empty());
    }

    #[test]
    fn framing_slot_is_reserved() {
        let mut list = HeaderList::new();
        for _ in 0..MAX_OUTBOUND_HEADERS {
            assert!(list.push(extension()).is_ok());
        }
        assert!(matches!(
            list.push(extension()),
            Err(BuildError::TooManyHeaders { .. })
        ));
        assert_eq!(list.len(), MAX_OUTBOUND_HEADERS);
    }

    struct Oversized;
    impl fmt::Display for Oversized {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            let chunk = "a".repeat(1024);
            for _ in 0..70 {
                formatter.write_str(&chunk)?;
            }
            Ok(())
        }
    }

    #[test]
    fn display_is_stopped_at_the_bound() {
        let mut list = HeaderList::new();
        assert!(matches!(
            list.push_typed(HeaderKind::UserAgent, &Oversized),
            Err(BuildError::ValueTooLong { .. })
        ));
        assert!(list.is_empty());
    }

    struct Injection;
    impl fmt::Display for Injection {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("safe\r\nInjected: yes")
        }
    }

    #[test]
    fn display_injection_is_rejected() {
        let mut list = HeaderList::new();
        assert!(matches!(
            list.push_typed(HeaderKind::UserAgent, &Injection),
            Err(BuildError::InvalidValue(_))
        ));
        assert!(list.is_empty());
    }

    #[test]
    fn order_counts_and_consumption_are_preserved() {
        let mut list = HeaderList::new();
        assert!(list.push(extension()).is_ok());
        assert!(list.push_typed(HeaderKind::Supported, &"timer").is_ok());
        assert!(list.push_typed(HeaderKind::Supported, &"100rel").is_ok());
        assert_eq!(list.count(HeaderKind::Supported), 2);
        assert!(list.as_slice()[0].name().is_extension());
        assert_eq!(list.into_vec().len(), 3);
    }

    #[test]
    fn debug_is_redacted() {
        let mut list = HeaderList::new();
        assert!(list.push(extension()).is_ok());
        let debug = format!("{list:?}");
        assert!(!debug.contains("opaque"));
        assert!(!debug.contains("X-Test"));
    }
}
