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

//! Deterministic bounded SDP serialization.
//!
//! Every line is emitted with canonical CRLF framing. The exact output size is
//! checked before one fallible allocation, preventing incremental growth and
//! ensuring serializers cannot exceed the same document bound as the parser.

use std::error::Error as StdError;
use std::fmt;

use super::parser::{MAX_SDP_BYTES, SdpDocument};

const CRLF: &[u8] = b"\r\n";

/// Calculates the exact serialized SDP size.
///
/// # Errors
///
/// Returns [`SdpSerializeError`] on arithmetic overflow or when the document
/// exceeds [`MAX_SDP_BYTES`].
pub fn serialized_len(document: &SdpDocument) -> Result<usize, SdpSerializeError> {
    let mut total = 0_usize;
    for line in document.session_lines() {
        total = add_line(total, line.len())?;
    }
    for section in document.media_sections() {
        total = add_line(total, section.media().to_string().len() + 2)?;
        for line in section.lines() {
            total = add_line(total, line.len())?;
        }
    }
    if total > MAX_SDP_BYTES {
        return Err(SdpSerializeError::TooLarge {
            length: total,
            maximum: MAX_SDP_BYTES,
        });
    }
    Ok(total)
}

/// Serializes a validated SDP document with canonical CRLF line endings.
///
/// # Errors
///
/// Returns [`SdpSerializeError`] on checked-size failure or bounded allocation
/// failure.
pub fn serialize(document: &SdpDocument) -> Result<Vec<u8>, SdpSerializeError> {
    let length = serialized_len(document)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| SdpSerializeError::AllocationFailed)?;

    for line in document.session_lines() {
        push_line(&mut output, line.field().as_char(), line.value());
    }
    for section in document.media_sections() {
        let media = section.media().to_string();
        push_line(&mut output, 'm', &media);
        for line in section.lines() {
            push_line(&mut output, line.field().as_char(), line.value());
        }
    }

    debug_assert_eq!(output.len(), length);
    Ok(output)
}

fn add_line(total: usize, line_length: usize) -> Result<usize, SdpSerializeError> {
    total
        .checked_add(line_length)
        .and_then(|value| value.checked_add(CRLF.len()))
        .ok_or(SdpSerializeError::LengthOverflow)
}

fn push_line(output: &mut Vec<u8>, field: char, value: &str) {
    debug_assert!(field.is_ascii());
    output.push(field as u8);
    output.push(b'=');
    output.extend_from_slice(value.as_bytes());
    output.extend_from_slice(CRLF);
}

/// Failure to serialize an SDP document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SdpSerializeError {
    /// Checked size calculation overflowed.
    LengthOverflow,
    /// Serialized document exceeded its operational bound.
    TooLarge {
        /// Calculated byte length.
        length: usize,
        /// Maximum permitted byte length.
        maximum: usize,
    },
    /// Exact bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for SdpSerializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("failed to serialize SDP document")
    }
}

impl StdError for SdpSerializeError {}

#[cfg(test)]
mod tests {
    use super::{serialize, serialized_len};
    use crate::sip::sdp::parser::parse;

    const INPUT: &[u8] = b"v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=LiveAISIP\r\n\
t=0 0\r\n\
m=audio 40000 RTP/AVP 0 8 111\r\n\
a=rtpmap:111 opus/48000/2\r\n";

    #[test]
    fn serialization_is_exact_and_crlf_framed() {
        let document = parse(INPUT).unwrap_or_else(|_| panic!("valid SDP"));
        let output = serialize(&document).unwrap_or_else(|_| panic!("serialize"));
        assert_eq!(output, INPUT);
        assert_eq!(serialized_len(&document), Ok(output.len()));
        assert!(output.ends_with(b"\r\n"));
        assert!(!output.windows(2).any(|window| window == b"\n\n"));
    }

    #[test]
    fn parse_serialize_parse_is_stable() {
        let document = parse(INPUT).unwrap_or_else(|_| panic!("valid SDP"));
        let first = serialize(&document).unwrap_or_else(|_| panic!("serialize"));
        let reparsed = parse(&first).unwrap_or_else(|_| panic!("reparse"));
        let second = serialize(&reparsed).unwrap_or_else(|_| panic!("serialize again"));
        assert_eq!(first, second);
        assert_eq!(reparsed.line_count(), document.line_count());
    }

    #[test]
    fn media_port_ranges_are_serialized_canonically() {
        let input = b"v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0\r\n\
m=audio 5000/2 RTP/SAVP 0\r\n";
        let document = parse(input).unwrap_or_else(|_| panic!("valid SDP"));
        let output = serialize(&document).unwrap_or_else(|_| panic!("serialize"));
        assert_eq!(output, input);
    }

    #[test]
    fn serialization_does_not_include_debug_content() {
        let document = parse(INPUT).unwrap_or_else(|_| panic!("valid SDP"));
        let output = serialize(&document).unwrap_or_else(|_| panic!("serialize"));
        let text = std::str::from_utf8(&output).unwrap_or_else(|_| panic!("utf8"));
        assert!(!text.contains("SdpDocument"));
        assert!(!text.contains("MediaSection"));
    }
}
