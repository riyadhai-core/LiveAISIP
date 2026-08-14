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

//! Bounded SDP RTP codec and payload representations.
//!
//! Codec encoding names are compared case-insensitively as required by SDP,
//! while their received spelling is preserved for serialization. Payload type,
//! clock rate, and channel count are validated before entering negotiation.
//! Static G.711 and G.722 payload mappings are available without `rtpmap`.

use std::error::Error as StdError;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::num::{NonZeroU16, NonZeroU32};
use std::str::FromStr;

/// Highest valid seven-bit RTP payload type.
pub const MAX_PAYLOAD_TYPE: u8 = 127;
/// Maximum accepted codec encoding-name size.
pub const MAX_CODEC_NAME_BYTES: usize = 64;
/// Maximum accepted RTP clock rate.
pub const MAX_CODEC_CLOCK_RATE: u32 = 768_000;
/// Maximum accepted channel count.
pub const MAX_CODEC_CHANNELS: u16 = 64;

/// A validated seven-bit RTP payload type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct PayloadType(u8);

impl PayloadType {
    /// Creates a payload type.
    ///
    /// # Errors
    ///
    /// Rejects values above 127.
    pub const fn new(value: u8) -> Result<Self, CodecError> {
        if value <= MAX_PAYLOAD_TYPE {
            Ok(Self(value))
        } else {
            Err(CodecError::PayloadTypeOutOfRange { value })
        }
    }

    /// Returns the numeric payload type.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Returns whether this is in the dynamically assigned range.
    #[must_use]
    pub const fn is_dynamic(self) -> bool {
        self.0 >= 96
    }
}

impl fmt::Display for PayloadType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A validated SDP codec encoding name.
#[derive(Clone)]
#[repr(transparent)]
pub struct CodecName(Box<str>);

impl CodecName {
    /// Creates a codec name from an SDP token.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or non-token names.
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, CodecError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_CODEC_NAME_BYTES || !value.bytes().all(is_token) {
            return Err(CodecError::InvalidCodecName);
        }
        Ok(Self(value))
    }

    /// Returns the preserved encoding name.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether this is the named codec, case-insensitively.
    #[must_use]
    pub fn is(&self, name: &str) -> bool {
        self.0.eq_ignore_ascii_case(name)
    }
}

impl PartialEq for CodecName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for CodecName {}

impl Hash for CodecName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.0.bytes() {
            state.write_u8(byte.to_ascii_lowercase());
        }
    }
}

impl fmt::Debug for CodecName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("CodecName").field(&self.0).finish()
    }
}

impl fmt::Display for CodecName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One SDP `rtpmap` codec mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Codec {
    payload_type: PayloadType,
    name: CodecName,
    clock_rate: NonZeroU32,
    channels: NonZeroU16,
}

impl Codec {
    /// Creates a validated codec mapping.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive clock rates and channel counts.
    pub fn new(
        payload_type: PayloadType,
        name: CodecName,
        clock_rate: u32,
        channels: u16,
    ) -> Result<Self, CodecError> {
        let clock_rate = NonZeroU32::new(clock_rate).ok_or(CodecError::InvalidClockRate {
            value: clock_rate,
            maximum: MAX_CODEC_CLOCK_RATE,
        })?;
        if clock_rate.get() > MAX_CODEC_CLOCK_RATE {
            return Err(CodecError::InvalidClockRate {
                value: clock_rate.get(),
                maximum: MAX_CODEC_CLOCK_RATE,
            });
        }
        let channels = NonZeroU16::new(channels).ok_or(CodecError::InvalidChannels {
            value: channels,
            maximum: MAX_CODEC_CHANNELS,
        })?;
        if channels.get() > MAX_CODEC_CHANNELS {
            return Err(CodecError::InvalidChannels {
                value: channels.get(),
                maximum: MAX_CODEC_CHANNELS,
            });
        }
        Ok(Self {
            payload_type,
            name,
            clock_rate,
            channels,
        })
    }

    /// Parses an `rtpmap` value: `payload encoding/clock[/channels]`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for malformed syntax or invalid bounds.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CodecError> {
        if input.is_empty() || input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(CodecError::InvalidSyntax);
        }
        let Some(space) = input.iter().position(|byte| *byte == b' ') else {
            return Err(CodecError::InvalidSyntax);
        };
        if input[space..]
            .iter()
            .take_while(|byte| **byte == b' ')
            .count()
            != 1
        {
            return Err(CodecError::InvalidSyntax);
        }
        let payload = parse_decimal_u8(&input[..space])?;
        let encoding = &input[space + 1..];
        if encoding.contains(&b' ') || encoding.contains(&b'\t') {
            return Err(CodecError::InvalidSyntax);
        }
        let mut parts = encoding.split(|byte| *byte == b'/');
        let name = parts.next().ok_or(CodecError::InvalidSyntax)?;
        let rate = parts.next().ok_or(CodecError::InvalidSyntax)?;
        let channels = parts.next();
        if parts.next().is_some() {
            return Err(CodecError::InvalidSyntax);
        }
        let name = std::str::from_utf8(name).map_err(|_| CodecError::InvalidCodecName)?;
        let rate = parse_decimal_u32(rate)?;
        let channels = channels.map_or(Ok(1), parse_decimal_u16)?;
        Self::new(
            PayloadType::new(payload)?,
            CodecName::new(name)?,
            rate,
            channels,
        )
    }

    /// Returns a well-known static RTP/AVP mapping when defined.
    #[must_use]
    pub fn from_static_payload(payload_type: PayloadType) -> Option<Self> {
        let (name, rate, channels) = match payload_type.get() {
            0 => ("PCMU", 8_000, 1),
            3 => ("GSM", 8_000, 1),
            8 => ("PCMA", 8_000, 1),
            9 => ("G722", 8_000, 1),
            13 => ("CN", 8_000, 1),
            18 => ("G729", 8_000, 1),
            _ => return None,
        };
        let Ok(name) = CodecName::new(name) else {
            return None;
        };
        Self::new(payload_type, name, rate, channels).ok()
    }

    /// Returns payload type.
    #[must_use]
    pub const fn payload_type(&self) -> PayloadType {
        self.payload_type
    }

    /// Returns encoding name.
    #[must_use]
    pub const fn name(&self) -> &CodecName {
        &self.name
    }

    /// Returns RTP clock rate.
    #[must_use]
    pub const fn clock_rate(&self) -> u32 {
        self.clock_rate.get()
    }

    /// Returns channel count.
    #[must_use]
    pub const fn channels(&self) -> u16 {
        self.channels.get()
    }

    /// Returns whether two mappings describe the same codec independently of
    /// their payload numbers and encoding-name case.
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.name == other.name
            && self.clock_rate == other.clock_rate
            && self.channels == other.channels
    }
}

impl fmt::Display for Codec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {}/{}",
            self.payload_type, self.name, self.clock_rate
        )?;
        if self.channels.get() != 1 {
            write!(formatter, "/{}", self.channels)?;
        }
        Ok(())
    }
}

impl FromStr for Codec {
    type Err = CodecError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

fn parse_decimal_u8(input: &[u8]) -> Result<u8, CodecError> {
    parse_decimal_u32(input)
        .and_then(|value| u8::try_from(value).map_err(|_| CodecError::InvalidNumber))
}

fn parse_decimal_u16(input: &[u8]) -> Result<u16, CodecError> {
    parse_decimal_u32(input)
        .and_then(|value| u16::try_from(value).map_err(|_| CodecError::InvalidNumber))
}

fn parse_decimal_u32(input: &[u8]) -> Result<u32, CodecError> {
    if input.is_empty() || !input.iter().all(u8::is_ascii_digit) {
        return Err(CodecError::InvalidNumber);
    }
    let mut value = 0_u32;
    for byte in input {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(*byte - b'0')))
            .ok_or(CodecError::InvalidNumber)?;
    }
    Ok(value)
}

const fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

/// Failure to parse or construct an SDP codec mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CodecError {
    /// Payload type exceeded seven bits.
    PayloadTypeOutOfRange {
        /// Supplied value.
        value: u8,
    },
    /// Codec encoding name was invalid.
    InvalidCodecName,
    /// Clock rate was zero or excessive.
    InvalidClockRate {
        /// Supplied rate.
        value: u32,
        /// Maximum accepted rate.
        maximum: u32,
    },
    /// Channel count was zero or excessive.
    InvalidChannels {
        /// Supplied channel count.
        value: u16,
        /// Maximum accepted count.
        maximum: u16,
    },
    /// `rtpmap` layout was malformed.
    InvalidSyntax,
    /// Decimal component was malformed or overflowed.
    InvalidNumber,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SDP RTP codec mapping")
    }
}

impl StdError for CodecError {}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{Codec, CodecError, CodecName, PayloadType};

    #[test]
    fn parses_audio_rtpmap_values() {
        let opus = Codec::from_bytes(b"111 opus/48000/2").unwrap_or_else(|_| panic!("opus"));
        assert_eq!(opus.payload_type().get(), 111);
        assert!(opus.name().is("OPUS"));
        assert_eq!(opus.clock_rate(), 48_000);
        assert_eq!(opus.channels(), 2);
        assert_eq!(opus.to_string(), "111 opus/48000/2");
    }

    #[test]
    fn codec_names_compare_and_hash_case_insensitively() {
        let lower = CodecName::new("opus").unwrap_or_else(|_| panic!("name"));
        let upper = CodecName::new("OPUS").unwrap_or_else(|_| panic!("name"));
        assert_eq!(lower, upper);
        let mut names = HashSet::new();
        names.insert(lower);
        names.insert(upper);
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn static_telephony_payloads_are_available() {
        let payload = PayloadType::new(0).unwrap_or_else(|_| panic!("payload"));
        let codec = Codec::from_static_payload(payload).unwrap_or_else(|| panic!("PCMU"));
        assert!(codec.name().is("PCMU"));
        assert_eq!(codec.clock_rate(), 8_000);
        assert_eq!(codec.channels(), 1);
    }

    #[test]
    fn compatibility_ignores_payload_and_name_case() {
        let offered = Codec::from_bytes(b"111 opus/48000/2").unwrap_or_else(|_| panic!("codec"));
        let local = Codec::from_bytes(b"96 OPUS/48000/2").unwrap_or_else(|_| panic!("codec"));
        assert!(offered.is_compatible_with(&local));
    }

    #[test]
    fn rejects_invalid_bounds_and_layout() {
        assert!(matches!(
            Codec::from_bytes(b"128 opus/48000/2"),
            Err(CodecError::PayloadTypeOutOfRange { .. })
        ));
        assert!(matches!(
            Codec::from_bytes(b"111 opus/0/2"),
            Err(CodecError::InvalidClockRate { .. })
        ));
        assert_eq!(
            Codec::from_bytes(b"111  opus/48000/2"),
            Err(CodecError::InvalidSyntax)
        );
    }
}
