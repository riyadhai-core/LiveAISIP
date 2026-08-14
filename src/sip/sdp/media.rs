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

//! SDP media-description (`m=`) types.
//!
//! Media, transport, port, and format tokens are retained independently so RTP
//! audio, secure RTP, and future extension transports remain representable.
//! RTP payload extraction is explicit and fallible because non-RTP media
//! formats are valid SDP and must not be misinterpreted as payload numbers.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use super::codec::PayloadType;

/// Maximum number of formats on one media line.
pub const MAX_MEDIA_FORMATS: usize = 64;
/// Maximum media, transport, or format token size.
pub const MAX_MEDIA_TOKEN_BYTES: usize = 128;

/// SDP media type.
#[derive(Clone, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum MediaType {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
    /// Text media.
    Text,
    /// Application media.
    Application,
    /// Message media.
    Message,
    /// Valid extension media token.
    Extension(Box<str>),
}

impl MediaType {
    /// Parses a media token.
    ///
    /// # Errors
    ///
    /// Rejects invalid or oversized SDP tokens.
    pub fn from_bytes(input: &[u8]) -> Result<Self, MediaError> {
        validate_token(input)?;
        let value = std::str::from_utf8(input).map_err(|_| MediaError::InvalidToken)?;
        Ok(match value {
            "audio" => Self::Audio,
            "video" => Self::Video,
            "text" => Self::Text,
            "application" => Self::Application,
            "message" => Self::Message,
            extension => Self::Extension(extension.into()),
        })
    }

    /// Returns the exact wire token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Text => "text",
            Self::Application => "application",
            Self::Message => "message",
            Self::Extension(value) => value,
        }
    }
}

impl fmt::Debug for MediaType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("MediaType")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// SDP media transport protocol.
#[derive(Clone, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum TransportProtocol {
    /// RTP audio/video profile over UDP.
    RtpAvp,
    /// Secure RTP audio/video profile.
    RtpSavp,
    /// RTP feedback profile.
    RtpAvpf,
    /// Secure RTP feedback profile.
    RtpSavpf,
    /// DTLS-SRTP feedback profile.
    UdpTlsRtpSavpf,
    /// Valid extension transport token.
    Extension(Box<str>),
}

impl TransportProtocol {
    /// Parses a protocol token case-sensitively.
    ///
    /// # Errors
    ///
    /// Rejects invalid or oversized protocol tokens.
    pub fn from_bytes(input: &[u8]) -> Result<Self, MediaError> {
        validate_protocol(input)?;
        let value = std::str::from_utf8(input).map_err(|_| MediaError::InvalidProtocol)?;
        Ok(match value {
            "RTP/AVP" => Self::RtpAvp,
            "RTP/SAVP" => Self::RtpSavp,
            "RTP/AVPF" => Self::RtpAvpf,
            "RTP/SAVPF" => Self::RtpSavpf,
            "UDP/TLS/RTP/SAVPF" => Self::UdpTlsRtpSavpf,
            extension => Self::Extension(extension.into()),
        })
    }

    /// Returns the exact wire token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::RtpAvp => "RTP/AVP",
            Self::RtpSavp => "RTP/SAVP",
            Self::RtpAvpf => "RTP/AVPF",
            Self::RtpSavpf => "RTP/SAVPF",
            Self::UdpTlsRtpSavpf => "UDP/TLS/RTP/SAVPF",
            Self::Extension(value) => value,
        }
    }

    /// Returns whether this protocol carries RTP payloads.
    #[must_use]
    pub const fn is_rtp(&self) -> bool {
        matches!(
            self,
            Self::RtpAvp | Self::RtpSavp | Self::RtpAvpf | Self::RtpSavpf | Self::UdpTlsRtpSavpf
        )
    }

    /// Returns whether media protection is inherent in the profile.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        matches!(self, Self::RtpSavp | Self::RtpSavpf | Self::UdpTlsRtpSavpf)
    }
}

impl fmt::Debug for TransportProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TransportProtocol")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One media format token.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct MediaFormat(Box<str>);

impl MediaFormat {
    /// Creates a validated format token.
    ///
    /// # Errors
    ///
    /// Rejects invalid or oversized tokens.
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, MediaError> {
        let value = value.into();
        validate_token(value.as_bytes())?;
        Ok(Self(value))
    }

    /// Returns the preserved token.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses this format as an RTP payload type.
    ///
    /// # Errors
    ///
    /// Rejects non-decimal and out-of-range formats.
    pub fn payload_type(&self) -> Result<PayloadType, MediaError> {
        let value = parse_u8(self.0.as_bytes())?;
        PayloadType::new(value).map_err(|_| MediaError::InvalidPayloadType)
    }
}

impl fmt::Display for MediaFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One validated SDP `m=` value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaLine {
    media: MediaType,
    port: u16,
    port_count: u16,
    protocol: TransportProtocol,
    formats: Vec<MediaFormat>,
}

impl MediaLine {
    /// Creates a bounded media line.
    ///
    /// Port zero is valid and rejects a media stream. `port_count` must be
    /// non-zero and the complete range must fit within `u16`.
    ///
    /// # Errors
    ///
    /// Rejects invalid port ranges and empty or oversized format lists.
    pub fn new(
        media: MediaType,
        port: u16,
        port_count: u16,
        protocol: TransportProtocol,
        formats: Vec<MediaFormat>,
    ) -> Result<Self, MediaError> {
        if port_count == 0
            || u32::from(port)
                .checked_add(u32::from(port_count) - 1)
                .is_none_or(|last| last > u32::from(u16::MAX))
        {
            return Err(MediaError::InvalidPortRange);
        }
        if formats.is_empty() {
            return Err(MediaError::MissingFormats);
        }
        if formats.len() > MAX_MEDIA_FORMATS {
            return Err(MediaError::TooManyFormats {
                maximum: MAX_MEDIA_FORMATS,
            });
        }
        Ok(Self {
            media,
            port,
            port_count,
            protocol,
            formats,
        })
    }

    /// Parses an SDP `m=` value without the `m=` prefix.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError`] for malformed syntax or exceeded bounds.
    pub fn from_bytes(input: &[u8]) -> Result<Self, MediaError> {
        if input.is_empty()
            || input.contains(&b'\t')
            || input.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
        {
            return Err(MediaError::InvalidSyntax);
        }
        let parts: Vec<&[u8]> = input.split(|byte| *byte == b' ').collect();
        if parts.len() < 4 || parts.iter().any(|part| part.is_empty()) {
            return Err(MediaError::InvalidSyntax);
        }
        let media = MediaType::from_bytes(parts[0])?;
        let (port, port_count) = parse_port(parts[1])?;
        let protocol = TransportProtocol::from_bytes(parts[2])?;
        if parts.len() - 3 > MAX_MEDIA_FORMATS {
            return Err(MediaError::TooManyFormats {
                maximum: MAX_MEDIA_FORMATS,
            });
        }
        let mut formats = Vec::new();
        formats
            .try_reserve_exact(parts.len() - 3)
            .map_err(|_| MediaError::AllocationFailed)?;
        for format in &parts[3..] {
            let value = std::str::from_utf8(format).map_err(|_| MediaError::InvalidToken)?;
            formats.push(MediaFormat::new(value)?);
        }
        Self::new(media, port, port_count, protocol, formats)
    }

    /// Returns media type.
    #[must_use]
    pub const fn media(&self) -> &MediaType {
        &self.media
    }

    /// Returns first transport port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns number of consecutive ports.
    #[must_use]
    pub const fn port_count(&self) -> u16 {
        self.port_count
    }

    /// Returns transport protocol.
    #[must_use]
    pub const fn protocol(&self) -> &TransportProtocol {
        &self.protocol
    }

    /// Returns ordered format tokens.
    #[must_use]
    pub fn formats(&self) -> &[MediaFormat] {
        &self.formats
    }

    /// Returns whether the stream was rejected with port zero.
    #[must_use]
    pub const fn is_rejected(&self) -> bool {
        self.port == 0
    }

    /// Iterates RTP payload interpretations without allocating.
    pub fn payload_types(&self) -> impl Iterator<Item = Result<PayloadType, MediaError>> + '_ {
        self.formats.iter().map(MediaFormat::payload_type)
    }
}

impl fmt::Display for MediaLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.media, self.port)?;
        if self.port_count != 1 {
            write!(formatter, "/{}", self.port_count)?;
        }
        write!(formatter, " {}", self.protocol)?;
        for format in &self.formats {
            write!(formatter, " {format}")?;
        }
        Ok(())
    }
}

impl FromStr for MediaLine {
    type Err = MediaError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

fn parse_port(input: &[u8]) -> Result<(u16, u16), MediaError> {
    let mut parts = input.split(|byte| *byte == b'/');
    let port = parse_u16(parts.next().ok_or(MediaError::InvalidPort)?)?;
    let count = parts.next().map_or(Ok(1), parse_u16)?;
    if parts.next().is_some() {
        return Err(MediaError::InvalidPort);
    }
    Ok((port, count))
}

fn parse_u8(input: &[u8]) -> Result<u8, MediaError> {
    let value = parse_u32(input)?;
    u8::try_from(value).map_err(|_| MediaError::InvalidPayloadType)
}

fn parse_u16(input: &[u8]) -> Result<u16, MediaError> {
    let value = parse_u32(input)?;
    u16::try_from(value).map_err(|_| MediaError::InvalidPort)
}

fn parse_u32(input: &[u8]) -> Result<u32, MediaError> {
    if input.is_empty() || !input.iter().all(u8::is_ascii_digit) {
        return Err(MediaError::InvalidNumber);
    }
    let mut value = 0_u32;
    for byte in input {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(*byte - b'0')))
            .ok_or(MediaError::InvalidNumber)?;
    }
    Ok(value)
}

fn validate_token(input: &[u8]) -> Result<(), MediaError> {
    if input.is_empty()
        || input.len() > MAX_MEDIA_TOKEN_BYTES
        || !input.iter().copied().all(is_token)
    {
        return Err(MediaError::InvalidToken);
    }
    Ok(())
}

fn validate_protocol(input: &[u8]) -> Result<(), MediaError> {
    if input.is_empty()
        || input.len() > MAX_MEDIA_TOKEN_BYTES
        || !input
            .iter()
            .copied()
            .all(|byte| is_token(byte) || byte == b'/')
    {
        return Err(MediaError::InvalidProtocol);
    }
    Ok(())
}

const fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

/// Failure to parse or construct an SDP media line.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MediaError {
    /// Media token was invalid.
    InvalidToken,
    /// Protocol token was invalid.
    InvalidProtocol,
    /// Overall media-line layout was invalid.
    InvalidSyntax,
    /// Decimal value was malformed or overflowed.
    InvalidNumber,
    /// Port syntax was invalid.
    InvalidPort,
    /// Port count or resulting range was invalid.
    InvalidPortRange,
    /// No format token was supplied.
    MissingFormats,
    /// Format list exceeded its bound.
    TooManyFormats {
        /// Maximum accepted format count.
        maximum: usize,
    },
    /// Format was not a valid RTP payload number.
    InvalidPayloadType,
    /// Bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for MediaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SDP media description")
    }
}

impl StdError for MediaError {}

#[cfg(test)]
mod tests {
    use super::{MediaError, MediaLine, MediaType, TransportProtocol};

    #[test]
    fn parses_audio_rtp_media() {
        let media = MediaLine::from_bytes(b"audio 49170 RTP/AVP 0 8 111")
            .unwrap_or_else(|_| panic!("media"));
        assert_eq!(media.media(), &MediaType::Audio);
        assert_eq!(media.port(), 49_170);
        assert_eq!(media.protocol(), &TransportProtocol::RtpAvp);
        assert_eq!(
            media
                .payload_types()
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|_| panic!("payloads"))
                .iter()
                .map(|payload| payload.get())
                .collect::<Vec<_>>(),
            vec![0, 8, 111]
        );
        assert_eq!(media.to_string(), "audio 49170 RTP/AVP 0 8 111");
    }

    #[test]
    fn classifies_secure_profiles() {
        let media =
            MediaLine::from_bytes(b"audio 40000 RTP/SAVP 0").unwrap_or_else(|_| panic!("media"));
        assert!(media.protocol().is_rtp());
        assert!(media.protocol().is_secure());
    }

    #[test]
    fn supports_rejected_media_and_port_ranges() {
        let rejected =
            MediaLine::from_bytes(b"audio 0 RTP/AVP 0").unwrap_or_else(|_| panic!("media"));
        assert!(rejected.is_rejected());
        let ranged =
            MediaLine::from_bytes(b"audio 5000/2 RTP/AVP 0").unwrap_or_else(|_| panic!("media"));
        assert_eq!(ranged.port_count(), 2);
        assert_eq!(ranged.to_string(), "audio 5000/2 RTP/AVP 0");
    }

    #[test]
    fn preserves_non_rtp_extension_media() {
        let media = MediaLine::from_bytes(b"application 9 UDP/DTLS/SCTP webrtc-datachannel")
            .unwrap_or_else(|_| panic!("media"));
        assert_eq!(media.media(), &MediaType::Application);
        assert!(!media.protocol().is_rtp());
        assert_eq!(media.formats()[0].as_str(), "webrtc-datachannel");
        assert!(matches!(
            media.payload_types().next(),
            Some(Err(MediaError::InvalidNumber))
        ));
    }

    #[test]
    fn rejects_bad_spacing_payloads_and_ranges() {
        assert_eq!(
            MediaLine::from_bytes(b"audio  5000 RTP/AVP 0"),
            Err(MediaError::InvalidSyntax)
        );
        let media = MediaLine::from_bytes(b"audio 5000 RTP/AVP 128")
            .unwrap_or_else(|_| panic!("media syntax"));
        assert!(matches!(
            media.payload_types().next(),
            Some(Err(MediaError::InvalidPayloadType))
        ));
        assert_eq!(
            MediaLine::from_bytes(b"audio 65535/2 RTP/AVP 0"),
            Err(MediaError::InvalidPortRange)
        );
    }
}
