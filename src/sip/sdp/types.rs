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

//! Foundational SDP wire types.
//!
//! Each SDP line is represented as one lowercase type character and a bounded
//! UTF-8 value. Known RFC fields receive dedicated variants; unknown lowercase
//! extension fields remain lossless. Line endings are owned by the document
//! parser and serializer, keeping embedded CR/LF impossible in typed values.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

/// Maximum accepted logical SDP line size, excluding CRLF.
pub const MAX_SDP_LINE_BYTES: usize = 8 * 1024;

/// An SDP field designator.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SdpField {
    /// Protocol version (`v`).
    Version,
    /// Origin (`o`).
    Origin,
    /// Session name (`s`).
    SessionName,
    /// Session or media information (`i`).
    Information,
    /// Session URI (`u`).
    Uri,
    /// Email address (`e`).
    Email,
    /// Phone number (`p`).
    Phone,
    /// Connection data (`c`).
    Connection,
    /// Bandwidth information (`b`).
    Bandwidth,
    /// Timing (`t`).
    Timing,
    /// Repeat times (`r`).
    Repeat,
    /// Time-zone adjustment (`z`).
    TimeZone,
    /// Encryption key (`k`).
    EncryptionKey,
    /// Attribute (`a`).
    Attribute,
    /// Media description (`m`).
    Media,
    /// Unknown lowercase extension field.
    Extension(char),
}

impl SdpField {
    /// Classifies one SDP type character.
    ///
    /// # Errors
    ///
    /// Rejects anything other than one lowercase ASCII letter.
    pub fn from_char(value: char) -> Result<Self, SdpLineError> {
        if !value.is_ascii_lowercase() {
            return Err(SdpLineError::InvalidField);
        }
        Ok(match value {
            'v' => Self::Version,
            'o' => Self::Origin,
            's' => Self::SessionName,
            'i' => Self::Information,
            'u' => Self::Uri,
            'e' => Self::Email,
            'p' => Self::Phone,
            'c' => Self::Connection,
            'b' => Self::Bandwidth,
            't' => Self::Timing,
            'r' => Self::Repeat,
            'z' => Self::TimeZone,
            'k' => Self::EncryptionKey,
            'a' => Self::Attribute,
            'm' => Self::Media,
            extension => Self::Extension(extension),
        })
    }

    /// Returns the exact lowercase wire character.
    #[must_use]
    pub const fn as_char(self) -> char {
        match self {
            Self::Version => 'v',
            Self::Origin => 'o',
            Self::SessionName => 's',
            Self::Information => 'i',
            Self::Uri => 'u',
            Self::Email => 'e',
            Self::Phone => 'p',
            Self::Connection => 'c',
            Self::Bandwidth => 'b',
            Self::Timing => 't',
            Self::Repeat => 'r',
            Self::TimeZone => 'z',
            Self::EncryptionKey => 'k',
            Self::Attribute => 'a',
            Self::Media => 'm',
            Self::Extension(value) => value,
        }
    }

    /// Returns whether this is an unknown extension field.
    #[must_use]
    pub const fn is_extension(self) -> bool {
        matches!(self, Self::Extension(_))
    }
}

impl fmt::Display for SdpField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_char().to_string())
    }
}

/// One validated SDP line without its CRLF terminator.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SdpLine {
    field: SdpField,
    value: Box<str>,
}

impl SdpLine {
    /// Creates a validated line from a field and logical value.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-containing values.
    pub fn new(field: SdpField, value: impl Into<Box<str>>) -> Result<Self, SdpLineError> {
        let value = value.into();
        validate_value(value.as_bytes())?;
        let length = value.len().checked_add(2).ok_or(SdpLineError::TooLong {
            length: usize::MAX,
            maximum: MAX_SDP_LINE_BYTES,
        })?;
        if length > MAX_SDP_LINE_BYTES {
            return Err(SdpLineError::TooLong {
                length,
                maximum: MAX_SDP_LINE_BYTES,
            });
        }
        Ok(Self { field, value })
    }

    /// Parses one SDP line without a trailing line ending.
    ///
    /// # Errors
    ///
    /// Returns [`SdpLineError`] for malformed `type=value` syntax or an
    /// invalid value.
    pub fn from_bytes(input: &[u8]) -> Result<Self, SdpLineError> {
        if input.len() > MAX_SDP_LINE_BYTES {
            return Err(SdpLineError::TooLong {
                length: input.len(),
                maximum: MAX_SDP_LINE_BYTES,
            });
        }
        if input.len() < 3 {
            return Err(SdpLineError::MissingValue);
        }
        if input[1] != b'=' {
            return Err(SdpLineError::MissingEquals);
        }
        let field = SdpField::from_char(char::from(input[0]))?;
        let value = std::str::from_utf8(&input[2..]).map_err(|_| SdpLineError::InvalidUtf8)?;
        Self::new(field, value)
    }

    /// Returns the field designator.
    #[must_use]
    pub const fn field(&self) -> SdpField {
        self.field
    }

    /// Returns the logical value after `=`.
    #[must_use]
    pub const fn value(&self) -> &str {
        &self.value
    }

    /// Returns serialized length without CRLF.
    #[must_use]
    pub fn len(&self) -> usize {
        2 + self.value.len()
    }

    /// Returns whether the serialized line is empty.
    ///
    /// A validated line is never empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for SdpLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdpLine")
            .field("field", &self.field)
            .field("value_bytes", &self.value.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SdpLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}={}", self.field.as_char(), self.value)
    }
}

impl FromStr for SdpLine {
    type Err = SdpLineError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

fn validate_value(value: &[u8]) -> Result<(), SdpLineError> {
    if value.is_empty() {
        return Err(SdpLineError::MissingValue);
    }
    if let Some((index, _)) = value
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| *byte != b'\t' && (*byte < 0x20 || *byte == 0x7f))
    {
        return Err(SdpLineError::InvalidControl { index: index + 2 });
    }
    Ok(())
}

/// Failure to parse or construct an SDP line.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SdpLineError {
    /// Field designator was not one lowercase ASCII letter.
    InvalidField,
    /// Equals delimiter was absent or misplaced.
    MissingEquals,
    /// Line value was absent.
    MissingValue,
    /// Line exceeded its operational bound.
    TooLong {
        /// Observed byte length.
        length: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// Value was not valid UTF-8.
    InvalidUtf8,
    /// Value contained a prohibited control byte.
    InvalidControl {
        /// Byte offset in the complete SDP line.
        index: usize,
    },
}

impl fmt::Display for SdpLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SDP line")
    }
}

impl StdError for SdpLineError {}

/// Builder for one bounded SDP media section.
pub struct SdpMediaBuilder {
    media: super::media::MediaLine,
    lines: Vec<SdpLine>,
}

impl SdpMediaBuilder {
    /// Starts a media section with its validated `m=` value.
    #[must_use]
    pub const fn new(media: super::media::MediaLine) -> Self {
        Self {
            media,
            lines: Vec::new(),
        }
    }

    /// Adds a media-level line in serialization order.
    ///
    /// # Errors
    ///
    /// Rejects `m=` and known session-only fields, count exhaustion, and
    /// allocation failure.
    pub fn push_line(&mut self, line: SdpLine) -> Result<(), SdpBuildError> {
        if !is_media_field(line.field()) {
            return Err(SdpBuildError::InvalidMediaField(line.field()));
        }
        if self.lines.len() >= super::parser::MAX_SDP_MEDIA_LINES {
            return Err(SdpBuildError::TooManyMediaLines {
                maximum: super::parser::MAX_SDP_MEDIA_LINES,
            });
        }
        self.lines
            .try_reserve(1)
            .map_err(|_| SdpBuildError::AllocationFailed)?;
        self.lines.push(line);
        Ok(())
    }

    /// Adds an attribute (`a=`) line.
    ///
    /// # Errors
    ///
    /// Returns [`SdpBuildError`] when the value or media-section bounds are
    /// invalid.
    pub fn push_attribute(&mut self, value: impl Into<Box<str>>) -> Result<(), SdpBuildError> {
        let line = SdpLine::new(SdpField::Attribute, value).map_err(SdpBuildError::Line)?;
        self.push_line(line)
    }

    fn into_section(self) -> super::parser::MediaSection {
        super::parser::MediaSection::from_parts(self.media, self.lines)
    }
}

impl fmt::Debug for SdpMediaBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdpMediaBuilder")
            .field("media_type", self.media.media())
            .field("line_count", &self.lines.len())
            .finish_non_exhaustive()
    }
}

/// Builder for a bounded SDP session document.
pub struct SdpBuilder {
    session_lines: Vec<SdpLine>,
    media_sections: Vec<super::parser::MediaSection>,
    total_lines: usize,
}

impl SdpBuilder {
    /// Creates the mandatory `v=`, `o=`, `s=`, and `t=` session prefix.
    ///
    /// The caller supplies logical values without field prefixes.
    ///
    /// # Errors
    ///
    /// Rejects invalid or oversized line values and allocation failure.
    pub fn new(
        origin: impl Into<Box<str>>,
        session_name: impl Into<Box<str>>,
        timing: impl Into<Box<str>>,
    ) -> Result<Self, SdpBuildError> {
        let lines = [
            SdpLine::new(SdpField::Version, "0").map_err(SdpBuildError::Line)?,
            SdpLine::new(SdpField::Origin, origin).map_err(SdpBuildError::Line)?,
            SdpLine::new(SdpField::SessionName, session_name).map_err(SdpBuildError::Line)?,
            SdpLine::new(SdpField::Timing, timing).map_err(SdpBuildError::Line)?,
        ];
        let mut session_lines = Vec::new();
        session_lines
            .try_reserve_exact(lines.len())
            .map_err(|_| SdpBuildError::AllocationFailed)?;
        session_lines.extend(lines);
        Ok(Self {
            session_lines,
            media_sections: Vec::new(),
            total_lines: 4,
        })
    }

    /// Adds a permitted session-level line after the mandatory prefix.
    ///
    /// # Errors
    ///
    /// Rejects mandatory singleton fields, `m=`, count exhaustion, and
    /// allocation failure.
    pub fn push_session_line(&mut self, line: SdpLine) -> Result<(), SdpBuildError> {
        if !is_additional_session_field(line.field()) {
            return Err(SdpBuildError::InvalidSessionField(line.field()));
        }
        let next_total = self.checked_total(1)?;
        self.session_lines
            .try_reserve(1)
            .map_err(|_| SdpBuildError::AllocationFailed)?;
        self.session_lines.push(line);
        self.total_lines = next_total;
        Ok(())
    }

    /// Adds a session-level attribute.
    ///
    /// # Errors
    ///
    /// Returns [`SdpBuildError`] when the value or document bounds are invalid.
    pub fn push_attribute(&mut self, value: impl Into<Box<str>>) -> Result<(), SdpBuildError> {
        let line = SdpLine::new(SdpField::Attribute, value).map_err(SdpBuildError::Line)?;
        self.push_session_line(line)
    }

    /// Adds one completed media section.
    ///
    /// # Errors
    ///
    /// Rejects media-section or total-line count exhaustion and allocation
    /// failure.
    pub fn push_media(&mut self, media: SdpMediaBuilder) -> Result<(), SdpBuildError> {
        if self.media_sections.len() >= super::parser::MAX_SDP_MEDIA_SECTIONS {
            return Err(SdpBuildError::TooManyMediaSections {
                maximum: super::parser::MAX_SDP_MEDIA_SECTIONS,
            });
        }
        let added = media
            .lines
            .len()
            .checked_add(1)
            .ok_or(SdpBuildError::TooManyLines {
                maximum: super::parser::MAX_SDP_LINES,
            })?;
        let next_total =
            self.total_lines
                .checked_add(added)
                .ok_or(SdpBuildError::TooManyLines {
                    maximum: super::parser::MAX_SDP_LINES,
                })?;
        if next_total > super::parser::MAX_SDP_LINES {
            return Err(SdpBuildError::TooManyLines {
                maximum: super::parser::MAX_SDP_LINES,
            });
        }
        self.media_sections
            .try_reserve(1)
            .map_err(|_| SdpBuildError::AllocationFailed)?;
        self.media_sections.push(media.into_section());
        self.total_lines = next_total;
        Ok(())
    }

    /// Finalizes a structurally valid, serializable SDP document.
    ///
    /// # Errors
    ///
    /// Rejects a document whose exact serialized size exceeds the SDP body
    /// bound.
    pub fn build(self) -> Result<super::parser::SdpDocument, SdpBuildError> {
        let document =
            super::parser::SdpDocument::from_parts(self.session_lines, self.media_sections);
        super::serializer::serialized_len(&document).map_err(SdpBuildError::Serialize)?;
        Ok(document)
    }

    fn checked_total(&self, added: usize) -> Result<usize, SdpBuildError> {
        let total = self
            .total_lines
            .checked_add(added)
            .ok_or(SdpBuildError::TooManyLines {
                maximum: super::parser::MAX_SDP_LINES,
            })?;
        if total > super::parser::MAX_SDP_LINES {
            return Err(SdpBuildError::TooManyLines {
                maximum: super::parser::MAX_SDP_LINES,
            });
        }
        Ok(total)
    }
}

impl fmt::Debug for SdpBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdpBuilder")
            .field("session_lines", &self.session_lines.len())
            .field("media_sections", &self.media_sections.len())
            .field("total_lines", &self.total_lines)
            .finish_non_exhaustive()
    }
}

const fn is_media_field(field: SdpField) -> bool {
    matches!(
        field,
        SdpField::Information
            | SdpField::Connection
            | SdpField::Bandwidth
            | SdpField::EncryptionKey
            | SdpField::Attribute
            | SdpField::Extension(_)
    )
}

const fn is_additional_session_field(field: SdpField) -> bool {
    !matches!(
        field,
        SdpField::Version | SdpField::Origin | SdpField::SessionName | SdpField::Media
    )
}

/// Failure to construct an SDP document.
#[derive(Debug)]
#[non_exhaustive]
pub enum SdpBuildError {
    /// A logical line value was invalid.
    Line(SdpLineError),
    /// Field cannot be added at session level through the builder.
    InvalidSessionField(SdpField),
    /// Field is not valid at media level.
    InvalidMediaField(SdpField),
    /// Document exceeded its total line bound.
    TooManyLines {
        /// Maximum accepted total lines.
        maximum: usize,
    },
    /// Media-section count exceeded its bound.
    TooManyMediaSections {
        /// Maximum accepted media-section count.
        maximum: usize,
    },
    /// One media section exceeded its line bound.
    TooManyMediaLines {
        /// Maximum accepted media-level lines.
        maximum: usize,
    },
    /// Final checked serialization sizing failed.
    Serialize(super::serializer::SdpSerializeError),
    /// Bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for SdpBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("failed to build SDP document")
    }
}

impl StdError for SdpBuildError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Line(error) => Some(error),
            Self::Serialize(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_SDP_LINE_BYTES, SdpBuildError, SdpBuilder, SdpField, SdpLine, SdpLineError,
        SdpMediaBuilder,
    };
    use crate::sip::sdp::media::MediaLine;
    use crate::sip::sdp::{parse, serialize};

    #[test]
    fn parses_known_and_extension_fields() {
        let version = SdpLine::from_bytes(b"v=0").unwrap_or_else(|_| panic!("version"));
        assert_eq!(version.field(), SdpField::Version);
        assert_eq!(version.value(), "0");
        let extension =
            SdpLine::from_bytes(b"x=private-extension").unwrap_or_else(|_| panic!("extension"));
        assert_eq!(extension.field(), SdpField::Extension('x'));
        assert_eq!(extension.to_string(), "x=private-extension");
    }

    #[test]
    fn rejects_malformed_layout_and_controls() {
        assert_eq!(SdpLine::from_bytes(b"V=0"), Err(SdpLineError::InvalidField));
        assert_eq!(
            SdpLine::from_bytes(b"v:0"),
            Err(SdpLineError::MissingEquals)
        );
        assert_eq!(
            SdpLine::from_bytes(b"s=a\r\nb"),
            Err(SdpLineError::InvalidControl { index: 3 })
        );
    }

    #[test]
    fn line_size_is_bounded_including_prefix() {
        let accepted = "a".repeat(MAX_SDP_LINE_BYTES - 2);
        assert!(SdpLine::new(SdpField::Attribute, accepted).is_ok());
        let rejected = "a".repeat(MAX_SDP_LINE_BYTES - 1);
        assert!(matches!(
            SdpLine::new(SdpField::Attribute, rejected),
            Err(SdpLineError::TooLong { .. })
        ));
    }

    #[test]
    fn debug_redacts_sdp_values() {
        let line =
            SdpLine::from_bytes(b"c=IN IP4 192.0.2.10").unwrap_or_else(|_| panic!("connection"));
        let debug = format!("{line:?}");
        assert!(!debug.contains("192.0.2.10"));
        assert!(debug.contains("value_bytes"));
    }

    #[test]
    fn builder_creates_parseable_audio_offer() {
        let mut builder = SdpBuilder::new("- 1 1 IN IP4 127.0.0.1", "LiveAISIP", "0 0")
            .unwrap_or_else(|_| panic!("builder"));
        builder
            .push_attribute("sendrecv")
            .unwrap_or_else(|_| panic!("session attribute"));
        let media = MediaLine::from_bytes(b"audio 40000 RTP/SAVP 0 8 111")
            .unwrap_or_else(|_| panic!("media"));
        let mut media = SdpMediaBuilder::new(media);
        media
            .push_line(
                SdpLine::new(SdpField::Connection, "IN IP4 192.0.2.10")
                    .unwrap_or_else(|_| panic!("connection")),
            )
            .unwrap_or_else(|_| panic!("media line"));
        media
            .push_attribute("rtpmap:111 opus/48000/2")
            .unwrap_or_else(|_| panic!("rtpmap"));
        builder
            .push_media(media)
            .unwrap_or_else(|_| panic!("media section"));
        let document = builder.build().unwrap_or_else(|_| panic!("document"));
        let wire = serialize(&document).unwrap_or_else(|_| panic!("serialize"));
        let reparsed = parse(&wire).unwrap_or_else(|_| panic!("reparse"));
        assert_eq!(reparsed.media_sections().len(), 1);
        assert_eq!(reparsed.media_sections()[0].media().port(), 40_000);
    }

    #[test]
    fn builders_reject_fields_at_wrong_scope() {
        let media =
            MediaLine::from_bytes(b"audio 40000 RTP/AVP 0").unwrap_or_else(|_| panic!("media"));
        let mut media = SdpMediaBuilder::new(media);
        let timing = SdpLine::new(SdpField::Timing, "0 0").unwrap_or_else(|_| panic!("timing"));
        assert!(matches!(
            media.push_line(timing),
            Err(SdpBuildError::InvalidMediaField(SdpField::Timing))
        ));

        let mut builder =
            SdpBuilder::new("- 1 1 IN IP4 host", "x", "0 0").unwrap_or_else(|_| panic!("builder"));
        let duplicate = SdpLine::new(SdpField::Version, "0").unwrap_or_else(|_| panic!("version"));
        assert!(matches!(
            builder.push_session_line(duplicate),
            Err(SdpBuildError::InvalidSessionField(SdpField::Version))
        ));
    }

    #[test]
    fn builder_debug_redacts_values() {
        let builder = SdpBuilder::new(
            "private-user 1 1 IN IP4 secret.example",
            "private-session",
            "0 0",
        )
        .unwrap_or_else(|_| panic!("builder"));
        let debug = format!("{builder:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("secret.example"));
        assert!(!debug.contains("private-session"));
    }
}
