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

//! Bounded SDP document parser.
//!
//! Parsing requires canonical CRLF framing and validates the mandatory
//! `v=`, `o=`, `s=`, and `t=` session structure before any `m=` section.
//! Known session-only fields are rejected inside media sections, while unknown
//! extension fields remain lossless for forward compatibility.

use std::error::Error as StdError;
use std::fmt;

use super::media::{MediaError, MediaLine};
use super::types::{SdpField, SdpLine, SdpLineError};

/// Maximum accepted SDP document size.
pub const MAX_SDP_BYTES: usize = 256 * 1024;
/// Maximum logical lines in one SDP document.
pub const MAX_SDP_LINES: usize = 2048;
/// Maximum media sections in one SDP document.
pub const MAX_SDP_MEDIA_SECTIONS: usize = 64;
/// Maximum non-`m=` lines retained in one media section.
pub const MAX_SDP_MEDIA_LINES: usize = 512;

/// A structurally validated SDP document.
pub struct SdpDocument {
    session_lines: Vec<SdpLine>,
    media_sections: Vec<MediaSection>,
}

impl SdpDocument {
    pub(crate) const fn from_parts(
        session_lines: Vec<SdpLine>,
        media_sections: Vec<MediaSection>,
    ) -> Self {
        Self {
            session_lines,
            media_sections,
        }
    }

    /// Returns session-level lines in wire order.
    #[must_use]
    pub fn session_lines(&self) -> &[SdpLine] {
        &self.session_lines
    }

    /// Returns media sections in wire order.
    #[must_use]
    pub fn media_sections(&self) -> &[MediaSection] {
        &self.media_sections
    }

    /// Returns the first session line with a requested field.
    #[must_use]
    pub fn session_line(&self, field: SdpField) -> Option<&SdpLine> {
        self.session_lines.iter().find(|line| line.field() == field)
    }

    /// Returns total logical line count.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.session_lines.len()
            + self
                .media_sections
                .iter()
                .map(|section| 1 + section.lines.len())
                .sum::<usize>()
    }
}

impl fmt::Debug for SdpDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdpDocument")
            .field("session_lines", &self.session_lines.len())
            .field("media_sections", &self.media_sections.len())
            .field("total_lines", &self.line_count())
            .finish_non_exhaustive()
    }
}

/// One SDP media section beginning with `m=`.
pub struct MediaSection {
    media: MediaLine,
    lines: Vec<SdpLine>,
}

impl MediaSection {
    pub(crate) const fn from_parts(media: MediaLine, lines: Vec<SdpLine>) -> Self {
        Self { media, lines }
    }

    /// Returns the parsed media description.
    #[must_use]
    pub const fn media(&self) -> &MediaLine {
        &self.media
    }

    /// Returns following media-level lines in wire order.
    #[must_use]
    pub fn lines(&self) -> &[SdpLine] {
        &self.lines
    }

    /// Returns the first media line with a requested field.
    #[must_use]
    pub fn line(&self, field: SdpField) -> Option<&SdpLine> {
        self.lines.iter().find(|line| line.field() == field)
    }
}

impl fmt::Debug for MediaSection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MediaSection")
            .field("media_type", self.media.media())
            .field("port", &self.media.port())
            .field("protocol", self.media.protocol())
            .field("line_count", &self.lines.len())
            .finish_non_exhaustive()
    }
}

/// Parses a complete SDP body.
///
/// # Errors
///
/// Returns [`SdpParseError`] for framing, line syntax, required ordering,
/// media syntax, or operational-bound violations.
pub fn parse(input: &[u8]) -> Result<SdpDocument, SdpParseError> {
    if input.is_empty() {
        return Err(SdpParseError::Empty);
    }
    if input.len() > MAX_SDP_BYTES {
        return Err(SdpParseError::TooLarge {
            length: input.len(),
            maximum: MAX_SDP_BYTES,
        });
    }

    let mut session_lines = Vec::new();
    let mut media_sections: Vec<MediaSection> = Vec::new();
    let mut offset = 0;
    let mut line_number = 0_usize;
    let mut saw_timing = false;

    while offset < input.len() {
        if line_number >= MAX_SDP_LINES {
            return Err(SdpParseError::TooManyLines {
                maximum: MAX_SDP_LINES,
            });
        }
        let relative_end = find_crlf(&input[offset..])
            .ok_or(SdpParseError::InvalidFraming { line: line_number })?;
        let end = offset + relative_end;
        if end == offset {
            return Err(SdpParseError::EmptyLine { line: line_number });
        }
        let line = SdpLine::from_bytes(&input[offset..end]).map_err(|source| {
            SdpParseError::InvalidLine {
                line: line_number,
                source,
            }
        })?;

        match line.field() {
            SdpField::Media => {
                if !saw_timing {
                    return Err(SdpParseError::MissingTiming);
                }
                if media_sections.len() >= MAX_SDP_MEDIA_SECTIONS {
                    return Err(SdpParseError::TooManyMediaSections {
                        maximum: MAX_SDP_MEDIA_SECTIONS,
                    });
                }
                let media = MediaLine::from_bytes(line.value().as_bytes()).map_err(|source| {
                    SdpParseError::InvalidMedia {
                        line: line_number,
                        source,
                    }
                })?;
                media_sections.push(MediaSection {
                    media,
                    lines: Vec::new(),
                });
            }
            field if media_sections.is_empty() => {
                validate_session_prefix(field, session_lines.len(), line_number)?;
                if field == SdpField::Timing {
                    saw_timing = true;
                }
                session_lines
                    .try_reserve(1)
                    .map_err(|_| SdpParseError::AllocationFailed)?;
                session_lines.push(line);
            }
            field => {
                if is_session_only(field) {
                    return Err(SdpParseError::SessionFieldInsideMedia {
                        line: line_number,
                        field,
                    });
                }
                let section = media_sections
                    .last_mut()
                    .ok_or(SdpParseError::AllocationFailed)?;
                if section.lines.len() >= MAX_SDP_MEDIA_LINES {
                    return Err(SdpParseError::TooManyMediaLines {
                        line: line_number,
                        maximum: MAX_SDP_MEDIA_LINES,
                    });
                }
                section
                    .lines
                    .try_reserve(1)
                    .map_err(|_| SdpParseError::AllocationFailed)?;
                section.lines.push(line);
            }
        }

        line_number += 1;
        offset = end + 2;
    }

    validate_required_session(&session_lines, saw_timing)?;
    Ok(SdpDocument {
        session_lines,
        media_sections,
    })
}

fn find_crlf(input: &[u8]) -> Option<usize> {
    let mut index = 0;
    while index + 1 < input.len() {
        match input[index] {
            b'\r' if input[index + 1] == b'\n' => return Some(index),
            b'\r' | b'\n' => return None,
            _ => index += 1,
        }
    }
    None
}

fn validate_session_prefix(
    field: SdpField,
    count: usize,
    line: usize,
) -> Result<(), SdpParseError> {
    let required = match count {
        0 => Some(SdpField::Version),
        1 => Some(SdpField::Origin),
        2 => Some(SdpField::SessionName),
        _ => None,
    };
    if let Some(expected) = required {
        if field != expected {
            return Err(SdpParseError::UnexpectedSessionField {
                line,
                expected,
                actual: field,
            });
        }
    } else if matches!(
        field,
        SdpField::Version | SdpField::Origin | SdpField::SessionName
    ) {
        return Err(SdpParseError::DuplicateRequiredField { line, field });
    }
    Ok(())
}

fn validate_required_session(lines: &[SdpLine], saw_timing: bool) -> Result<(), SdpParseError> {
    if lines.len() < 3 {
        return Err(SdpParseError::MissingRequiredSessionField);
    }
    if !saw_timing {
        return Err(SdpParseError::MissingTiming);
    }
    Ok(())
}

const fn is_session_only(field: SdpField) -> bool {
    matches!(
        field,
        SdpField::Version
            | SdpField::Origin
            | SdpField::SessionName
            | SdpField::Uri
            | SdpField::Email
            | SdpField::Phone
            | SdpField::Timing
            | SdpField::Repeat
            | SdpField::TimeZone
    )
}

/// Failure to parse an SDP document.
#[derive(Debug)]
#[non_exhaustive]
pub enum SdpParseError {
    /// Body was empty.
    Empty,
    /// Body exceeded its byte bound.
    TooLarge {
        /// Observed byte length.
        length: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// Document exceeded its logical line bound.
    TooManyLines {
        /// Maximum accepted line count.
        maximum: usize,
    },
    /// Line ending was missing or malformed.
    InvalidFraming {
        /// Zero-based logical line number.
        line: usize,
    },
    /// An empty line was present.
    EmptyLine {
        /// Zero-based logical line number.
        line: usize,
    },
    /// A logical line was malformed.
    InvalidLine {
        /// Zero-based logical line number.
        line: usize,
        /// Detailed line error.
        source: SdpLineError,
    },
    /// Mandatory session prefix order was violated.
    UnexpectedSessionField {
        /// Zero-based logical line number.
        line: usize,
        /// Required field at this position.
        expected: SdpField,
        /// Received field.
        actual: SdpField,
    },
    /// A mandatory singleton field appeared again.
    DuplicateRequiredField {
        /// Zero-based logical line number.
        line: usize,
        /// Duplicated field.
        field: SdpField,
    },
    /// Session ended before mandatory prefix fields were complete.
    MissingRequiredSessionField,
    /// No timing line preceded media sections or end of document.
    MissingTiming,
    /// Media description was malformed.
    InvalidMedia {
        /// Zero-based logical line number.
        line: usize,
        /// Detailed media error.
        source: MediaError,
    },
    /// Media-section count exceeded its bound.
    TooManyMediaSections {
        /// Maximum accepted media-section count.
        maximum: usize,
    },
    /// A known session-only field appeared within media.
    SessionFieldInsideMedia {
        /// Zero-based logical line number.
        line: usize,
        /// Misplaced field.
        field: SdpField,
    },
    /// One media section exceeded its line bound.
    TooManyMediaLines {
        /// Zero-based logical line number.
        line: usize,
        /// Maximum accepted media-level line count.
        maximum: usize,
    },
    /// Bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for SdpParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SDP document")
    }
}

impl StdError for SdpParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidLine { source, .. } => Some(source),
            Self::InvalidMedia { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::{SdpParseError, parse};
    use crate::sip::sdp::types::{SdpField, SdpLine};

    const VALID: &[u8] = b"v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=LiveAISIP\r\n\
t=0 0\r\n\
a=sendrecv\r\n\
m=audio 40000 RTP/AVP 0 8 111\r\n\
c=IN IP4 192.0.2.10\r\n\
a=rtpmap:111 opus/48000/2\r\n";

    #[test]
    fn parses_session_and_media_sections() {
        let document = parse(VALID).unwrap_or_else(|_| panic!("valid SDP"));
        assert_eq!(document.session_lines().len(), 5);
        assert_eq!(document.media_sections().len(), 1);
        assert_eq!(document.media_sections()[0].lines().len(), 2);
        assert_eq!(document.media_sections()[0].media().port(), 40_000);
        assert_eq!(
            document
                .session_line(SdpField::SessionName)
                .map(SdpLine::value),
            Some("LiveAISIP")
        );
        assert_eq!(document.line_count(), 8);
    }

    #[test]
    fn requires_canonical_crlf_and_terminal_line_ending() {
        assert!(matches!(
            parse(b"v=0\no=- 1 1 IN IP4 host\ns=x\nt=0 0\n"),
            Err(SdpParseError::InvalidFraming { .. })
        ));
        assert!(matches!(
            parse(b"v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0"),
            Err(SdpParseError::InvalidFraming { .. })
        ));
    }

    #[test]
    fn enforces_mandatory_prefix_and_timing() {
        assert!(matches!(
            parse(b"o=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0\r\n"),
            Err(SdpParseError::UnexpectedSessionField { .. })
        ));
        assert!(matches!(
            parse(b"v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nm=audio 9 RTP/AVP 0\r\n"),
            Err(SdpParseError::MissingTiming)
        ));
    }

    #[test]
    fn rejects_session_only_fields_inside_media() {
        let input = b"v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0\r\n\
m=audio 9 RTP/AVP 0\r\nt=1 2\r\n";
        assert!(matches!(
            parse(input),
            Err(SdpParseError::SessionFieldInsideMedia {
                field: SdpField::Timing,
                ..
            })
        ));
    }

    #[test]
    fn errors_preserve_sources_and_debug_is_redacted() {
        let input = b"v=0\r\no=- 1 1 IN IP4 secret.example\r\ns=x\r\nt=0 0\r\n\
m=audio bad RTP/AVP 0\r\n";
        let error = parse(input).err().unwrap_or_else(|| panic!("must reject"));
        assert!(error.source().is_some());

        let document = parse(VALID).unwrap_or_else(|_| panic!("valid SDP"));
        let debug = format!("{document:?} {:?}", document.media_sections()[0]);
        assert!(!debug.contains("192.0.2.10"));
        assert!(!debug.contains("127.0.0.1"));
    }
}
