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

//! Strict RFC 4733 telephone-event payload representation.
//!
//! Each event payload is exactly four bytes. Unknown event codes remain
//! representable for negotiated extensions, while standard DTMF digits expose
//! a strongly typed conversion that avoids string parsing in media loops.

use std::error::Error as StdError;
use std::fmt;

/// Exact RFC 4733 telephone-event payload size.
pub const TELEPHONE_EVENT_BYTES: usize = 4;
/// Maximum six-bit attenuation volume.
pub const MAX_TELEPHONE_EVENT_VOLUME: u8 = 63;

/// A standard telephone keypad digit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DtmfDigit {
    /// Digit 0.
    Zero,
    /// Digit 1.
    One,
    /// Digit 2.
    Two,
    /// Digit 3.
    Three,
    /// Digit 4.
    Four,
    /// Digit 5.
    Five,
    /// Digit 6.
    Six,
    /// Digit 7.
    Seven,
    /// Digit 8.
    Eight,
    /// Digit 9.
    Nine,
    /// Asterisk key.
    Star,
    /// Number-sign key.
    Pound,
    /// Key A.
    A,
    /// Key B.
    B,
    /// Key C.
    C,
    /// Key D.
    D,
}

impl DtmfDigit {
    /// Parses one ASCII keypad character case-insensitively for A–D.
    ///
    /// # Errors
    ///
    /// Rejects characters outside `0`–`9`, `*`, `#`, and A–D.
    pub const fn from_ascii(value: u8) -> Result<Self, TelephoneEventError> {
        match value {
            b'0' => Ok(Self::Zero),
            b'1' => Ok(Self::One),
            b'2' => Ok(Self::Two),
            b'3' => Ok(Self::Three),
            b'4' => Ok(Self::Four),
            b'5' => Ok(Self::Five),
            b'6' => Ok(Self::Six),
            b'7' => Ok(Self::Seven),
            b'8' => Ok(Self::Eight),
            b'9' => Ok(Self::Nine),
            b'*' => Ok(Self::Star),
            b'#' => Ok(Self::Pound),
            b'A' | b'a' => Ok(Self::A),
            b'B' | b'b' => Ok(Self::B),
            b'C' | b'c' => Ok(Self::C),
            b'D' | b'd' => Ok(Self::D),
            _ => Err(TelephoneEventError::InvalidDigit { value }),
        }
    }

    /// Returns canonical ASCII keypad representation.
    #[must_use]
    pub const fn as_ascii(self) -> u8 {
        match self {
            Self::Zero => b'0',
            Self::One => b'1',
            Self::Two => b'2',
            Self::Three => b'3',
            Self::Four => b'4',
            Self::Five => b'5',
            Self::Six => b'6',
            Self::Seven => b'7',
            Self::Eight => b'8',
            Self::Nine => b'9',
            Self::Star => b'*',
            Self::Pound => b'#',
            Self::A => b'A',
            Self::B => b'B',
            Self::C => b'C',
            Self::D => b'D',
        }
    }

    /// Returns RFC 4733 event code 0–15.
    #[must_use]
    pub const fn event_code(self) -> u8 {
        match self {
            Self::Zero => 0,
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 4,
            Self::Five => 5,
            Self::Six => 6,
            Self::Seven => 7,
            Self::Eight => 8,
            Self::Nine => 9,
            Self::Star => 10,
            Self::Pound => 11,
            Self::A => 12,
            Self::B => 13,
            Self::C => 14,
            Self::D => 15,
        }
    }

    /// Classifies a standard event code.
    #[must_use]
    pub const fn from_event_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Zero),
            1 => Some(Self::One),
            2 => Some(Self::Two),
            3 => Some(Self::Three),
            4 => Some(Self::Four),
            5 => Some(Self::Five),
            6 => Some(Self::Six),
            7 => Some(Self::Seven),
            8 => Some(Self::Eight),
            9 => Some(Self::Nine),
            10 => Some(Self::Star),
            11 => Some(Self::Pound),
            12 => Some(Self::A),
            13 => Some(Self::B),
            14 => Some(Self::C),
            15 => Some(Self::D),
            _ => None,
        }
    }
}

/// A telephone-event code, including negotiated extensions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TelephoneEventCode {
    /// Standard keypad digit event 0–15.
    Digit(DtmfDigit),
    /// Hook-flash event 16.
    Flash,
    /// Other negotiated RFC 4733 event.
    Other(u8),
}

impl TelephoneEventCode {
    /// Classifies any eight-bit event code.
    #[must_use]
    pub const fn from_raw(value: u8) -> Self {
        if let Some(digit) = DtmfDigit::from_event_code(value) {
            Self::Digit(digit)
        } else if value == 16 {
            Self::Flash
        } else {
            Self::Other(value)
        }
    }

    /// Returns the event's wire code.
    #[must_use]
    pub const fn as_raw(self) -> u8 {
        match self {
            Self::Digit(digit) => digit.event_code(),
            Self::Flash => 16,
            Self::Other(value) => value,
        }
    }
}

/// One complete RFC 4733 telephone-event payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelephoneEvent {
    code: TelephoneEventCode,
    end: bool,
    volume: u8,
    duration: u16,
}

impl TelephoneEvent {
    /// Parses exactly one four-byte event payload.
    ///
    /// # Errors
    ///
    /// Rejects truncation, trailing bytes, and the reserved bit being set.
    pub fn parse(input: &[u8]) -> Result<Self, TelephoneEventError> {
        if input.len() < TELEPHONE_EVENT_BYTES {
            return Err(TelephoneEventError::Truncated {
                required: TELEPHONE_EVENT_BYTES,
                available: input.len(),
            });
        }
        if input.len() > TELEPHONE_EVENT_BYTES {
            return Err(TelephoneEventError::TrailingBytes {
                actual: input.len(),
                expected: TELEPHONE_EVENT_BYTES,
            });
        }
        if input[1] & 0x40 != 0 {
            return Err(TelephoneEventError::ReservedBitSet);
        }
        Ok(Self {
            code: TelephoneEventCode::from_raw(input[0]),
            end: input[1] & 0x80 != 0,
            volume: input[1] & 0x3f,
            duration: u16::from_be_bytes([input[2], input[3]]),
        })
    }

    /// Constructs one event payload.
    ///
    /// # Errors
    ///
    /// Rejects attenuation volume above the six-bit wire maximum.
    pub const fn new(
        code: TelephoneEventCode,
        end: bool,
        volume: u8,
        duration: u16,
    ) -> Result<Self, TelephoneEventError> {
        if volume > MAX_TELEPHONE_EVENT_VOLUME {
            return Err(TelephoneEventError::VolumeOutOfRange {
                volume,
                maximum: MAX_TELEPHONE_EVENT_VOLUME,
            });
        }
        Ok(Self {
            code,
            end,
            volume,
            duration,
        })
    }

    /// Returns event code.
    #[must_use]
    pub const fn code(self) -> TelephoneEventCode {
        self.code
    }

    /// Returns standard keypad digit when this is event 0–15.
    #[must_use]
    pub const fn digit(self) -> Option<DtmfDigit> {
        match self.code {
            TelephoneEventCode::Digit(digit) => Some(digit),
            TelephoneEventCode::Flash | TelephoneEventCode::Other(_) => None,
        }
    }

    /// Returns whether this packet marks the event's end.
    #[must_use]
    pub const fn is_end(self) -> bool {
        self.end
    }

    /// Returns attenuation in negative dBm0.
    #[must_use]
    pub const fn volume(self) -> u8 {
        self.volume
    }

    /// Returns cumulative event duration in RTP timestamp units.
    #[must_use]
    pub const fn duration(self) -> u16 {
        self.duration
    }

    /// Serializes the exact four-byte event payload.
    #[must_use]
    pub const fn encode(self) -> [u8; TELEPHONE_EVENT_BYTES] {
        let duration = self.duration.to_be_bytes();
        [
            self.code.as_raw(),
            (self.end as u8) << 7 | self.volume,
            duration[0],
            duration[1],
        ]
    }
}

/// Failure while parsing or constructing a telephone event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TelephoneEventError {
    /// Payload ends before four-byte event boundary.
    Truncated {
        /// Required byte count.
        required: usize,
        /// Available byte count.
        available: usize,
    },
    /// Payload contains bytes after one event.
    TrailingBytes {
        /// Supplied byte count.
        actual: usize,
        /// Exact expected byte count.
        expected: usize,
    },
    /// Reserved payload bit was nonzero.
    ReservedBitSet,
    /// Volume exceeds six-bit capacity.
    VolumeOutOfRange {
        /// Supplied volume.
        volume: u8,
        /// Maximum representable volume.
        maximum: u8,
    },
    /// ASCII byte is not a supported keypad character.
    InvalidDigit {
        /// Supplied ASCII byte.
        value: u8,
    },
}

impl fmt::Display for TelephoneEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                required,
                available,
            } => write!(
                formatter,
                "telephone event requires {required} bytes, has {available}"
            ),
            Self::TrailingBytes { actual, expected } => write!(
                formatter,
                "telephone event has {actual} bytes, expected {expected}"
            ),
            Self::ReservedBitSet => formatter.write_str("telephone-event reserved bit is set"),
            Self::VolumeOutOfRange { volume, maximum } => {
                write!(
                    formatter,
                    "telephone-event volume {volume} exceeds {maximum}"
                )
            }
            Self::InvalidDigit { value } => {
                write!(formatter, "invalid DTMF ASCII byte {value}")
            }
        }
    }
}

impl StdError for TelephoneEventError {}

#[cfg(test)]
mod tests {
    use super::{DtmfDigit, TelephoneEvent, TelephoneEventCode, TelephoneEventError};

    #[test]
    fn parses_and_serializes_standard_digit() {
        let bytes = [5, 0x8a, 0x01, 0x40];
        let event = TelephoneEvent::parse(&bytes).unwrap_or_else(|_| panic!("event"));
        assert_eq!(event.code(), TelephoneEventCode::Digit(DtmfDigit::Five));
        assert_eq!(event.digit(), Some(DtmfDigit::Five));
        assert!(event.is_end());
        assert_eq!(event.volume(), 10);
        assert_eq!(event.duration(), 320);
        assert_eq!(event.encode(), bytes);
    }

    #[test]
    fn preserves_extension_and_flash_codes() {
        let flash = TelephoneEvent::new(TelephoneEventCode::Flash, false, 0, 80)
            .unwrap_or_else(|_| panic!("flash"));
        assert_eq!(flash.encode()[0], 16);
        assert_eq!(flash.digit(), None);
        let extension =
            TelephoneEvent::parse(&[200, 0, 0, 1]).unwrap_or_else(|_| panic!("extension"));
        assert_eq!(extension.code(), TelephoneEventCode::Other(200));
    }

    #[test]
    fn converts_all_keypad_ascii_values() {
        for value in b"0123456789*#ABCDabcd" {
            let digit = DtmfDigit::from_ascii(*value).unwrap_or_else(|_| panic!("digit"));
            assert!(DtmfDigit::from_event_code(digit.event_code()).is_some());
        }
        assert_eq!(DtmfDigit::A.as_ascii(), b'A');
        assert_eq!(
            DtmfDigit::from_ascii(b'X'),
            Err(TelephoneEventError::InvalidDigit { value: b'X' })
        );
    }

    #[test]
    fn rejects_invalid_payload_framing() {
        assert_eq!(
            TelephoneEvent::parse(&[1, 2, 3]),
            Err(TelephoneEventError::Truncated {
                required: 4,
                available: 3,
            })
        );
        assert_eq!(
            TelephoneEvent::parse(&[1, 2, 3, 4, 5]),
            Err(TelephoneEventError::TrailingBytes {
                actual: 5,
                expected: 4,
            })
        );
        assert_eq!(
            TelephoneEvent::parse(&[1, 0x40, 0, 1]),
            Err(TelephoneEventError::ReservedBitSet)
        );
    }

    #[test]
    fn constructor_enforces_volume_bound_transactionally() {
        assert_eq!(
            TelephoneEvent::new(TelephoneEventCode::Digit(DtmfDigit::One), false, 64, 80),
            Err(TelephoneEventError::VolumeOutOfRange {
                volume: 64,
                maximum: 63,
            })
        );
    }
}
