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

//! Drift-free RTP media-clock arithmetic.
//!
//! Time conversion uses checked integer arithmetic and retains sub-tick
//! fractional remainder between advances. This is important for packetization
//! intervals that do not divide evenly into one second and avoids cumulative
//! floating-point drift over long calls.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

const NANOS_PER_SECOND: u128 = 1_000_000_000;
/// Operational maximum RTP clock rate.
pub const MAX_RTP_CLOCK_RATE: u32 = 1_000_000_000;

/// A validated RTP timestamp clock rate in ticks per second.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RtpClockRate(u32);

impl RtpClockRate {
    /// G.711 PCMU/PCMA RTP clock rate.
    pub const TELEPHONY_8_KHZ: Self = Self(8_000);
    /// `LiveAISIP` AI PCM processing rate.
    pub const AI_AUDIO_24_KHZ: Self = Self(24_000);
    /// Opus RTP clock rate.
    pub const OPUS_48_KHZ: Self = Self(48_000);
    /// Common 90 kHz video RTP clock rate.
    pub const VIDEO_90_KHZ: Self = Self(90_000);

    /// Creates a nonzero bounded RTP clock rate.
    ///
    /// # Errors
    ///
    /// Rejects zero and rates above [`MAX_RTP_CLOCK_RATE`].
    pub const fn new(ticks_per_second: u32) -> Result<Self, RtpClockError> {
        if ticks_per_second == 0 {
            return Err(RtpClockError::ZeroRate);
        }
        if ticks_per_second > MAX_RTP_CLOCK_RATE {
            return Err(RtpClockError::RateTooHigh {
                actual: ticks_per_second,
                maximum: MAX_RTP_CLOCK_RATE,
            });
        }
        Ok(Self(ticks_per_second))
    }

    /// Returns ticks per second.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Converts a whole sample count to a duration, truncating only fractions
    /// smaller than one nanosecond.
    ///
    /// # Errors
    ///
    /// Returns checked conversion failure for an unrepresentable duration.
    pub fn duration_for_ticks(self, ticks: u64) -> Result<Duration, RtpClockError> {
        let total_nanos = u128::from(ticks)
            .checked_mul(NANOS_PER_SECOND)
            .ok_or(RtpClockError::ArithmeticOverflow)?
            / u128::from(self.0);
        duration_from_nanos(total_nanos)
    }

    /// Converts a duration to whole ticks without retaining fractional state.
    ///
    /// This is suitable for one-shot measurements. Repeated media progression
    /// should use [`RtpClock::advance`] so fractional ticks are preserved.
    ///
    /// # Errors
    ///
    /// Returns overflow if the whole tick count cannot fit in `u64`.
    pub fn ticks_for_duration(self, duration: Duration) -> Result<u64, RtpClockError> {
        let numerator = duration
            .as_nanos()
            .checked_mul(u128::from(self.0))
            .ok_or(RtpClockError::ArithmeticOverflow)?;
        u64::try_from(numerator / NANOS_PER_SECOND).map_err(|_| RtpClockError::TickCountOverflow)
    }
}

/// Stateful RTP timestamp generator with retained fractional tick remainder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpClock {
    rate: RtpClockRate,
    timestamp: u32,
    fractional_numerator: u32,
}

impl RtpClock {
    /// Creates a clock at a caller-selected randomized initial timestamp.
    #[must_use]
    pub const fn new(rate: RtpClockRate, initial_timestamp: u32) -> Self {
        Self {
            rate,
            timestamp: initial_timestamp,
            fractional_numerator: 0,
        }
    }

    /// Returns the configured media clock rate.
    #[must_use]
    pub const fn rate(self) -> RtpClockRate {
        self.rate
    }

    /// Returns the current RTP timestamp.
    #[must_use]
    pub const fn timestamp(self) -> u32 {
        self.timestamp
    }

    /// Returns retained fractional numerator in billionths of a tick.
    #[must_use]
    pub const fn fractional_numerator(self) -> u32 {
        self.fractional_numerator
    }

    /// Advances by elapsed wall-clock duration and returns emitted whole ticks.
    ///
    /// Timestamp addition wraps exactly as the RTP 32-bit wire field requires.
    /// The state remains unchanged if conversion fails.
    ///
    /// # Errors
    ///
    /// Returns checked arithmetic or tick-count overflow.
    pub fn advance(&mut self, elapsed: Duration) -> Result<u64, RtpClockError> {
        let numerator = elapsed
            .as_nanos()
            .checked_mul(u128::from(self.rate.0))
            .and_then(|value| value.checked_add(u128::from(self.fractional_numerator)))
            .ok_or(RtpClockError::ArithmeticOverflow)?;
        let whole_ticks = numerator / NANOS_PER_SECOND;
        let remainder = numerator % NANOS_PER_SECOND;
        let whole_ticks_u64 =
            u64::try_from(whole_ticks).map_err(|_| RtpClockError::TickCountOverflow)?;
        let whole_tick_bytes = whole_ticks_u64.to_le_bytes();
        let wrapping_ticks = u32::from_le_bytes([
            whole_tick_bytes[0],
            whole_tick_bytes[1],
            whole_tick_bytes[2],
            whole_tick_bytes[3],
        ]);
        let next_timestamp = self.timestamp.wrapping_add(wrapping_ticks);
        let next_remainder =
            u32::try_from(remainder).map_err(|_| RtpClockError::ArithmeticOverflow)?;
        self.timestamp = next_timestamp;
        self.fractional_numerator = next_remainder;
        Ok(whole_ticks_u64)
    }

    /// Advances by an exact number of media samples/ticks.
    pub const fn advance_ticks(&mut self, ticks: u32) {
        self.timestamp = self.timestamp.wrapping_add(ticks);
    }

    /// Reanchors the RTP timestamp and clears fractional elapsed-time state.
    pub const fn reset(&mut self, timestamp: u32) {
        self.timestamp = timestamp;
        self.fractional_numerator = 0;
    }
}

/// Returns forward modular distance between two RTP timestamps.
#[must_use]
pub const fn wrapping_timestamp_distance(newer: u32, older: u32) -> u32 {
    newer.wrapping_sub(older)
}

/// Interprets the shortest signed distance between RTP timestamps.
///
/// This is valid only when compared timestamps differ by less than half the
/// 32-bit timestamp space, which is the normal receiver-window invariant.
#[must_use]
pub const fn signed_timestamp_distance(newer: u32, older: u32) -> i32 {
    i32::from_ne_bytes(newer.wrapping_sub(older).to_ne_bytes())
}

fn duration_from_nanos(total_nanos: u128) -> Result<Duration, RtpClockError> {
    let seconds = total_nanos / NANOS_PER_SECOND;
    let nanos = total_nanos % NANOS_PER_SECOND;
    let seconds = u64::try_from(seconds).map_err(|_| RtpClockError::DurationOverflow)?;
    let nanos = u32::try_from(nanos).map_err(|_| RtpClockError::DurationOverflow)?;
    Ok(Duration::new(seconds, nanos))
}

/// Failure while configuring or converting RTP media-clock time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RtpClockError {
    /// Clock rate was zero.
    ZeroRate,
    /// Clock rate exceeded the operational bound.
    RateTooHigh {
        /// Supplied ticks per second.
        actual: u32,
        /// Maximum accepted ticks per second.
        maximum: u32,
    },
    /// Checked intermediate arithmetic overflowed.
    ArithmeticOverflow,
    /// Whole tick count could not fit in `u64`.
    TickCountOverflow,
    /// Converted duration could not fit `std::time::Duration`.
    DurationOverflow,
}

impl fmt::Display for RtpClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRate => formatter.write_str("RTP clock rate is zero"),
            Self::RateTooHigh { actual, maximum } => {
                write!(formatter, "RTP clock rate {actual} exceeds {maximum}")
            }
            Self::ArithmeticOverflow => formatter.write_str("RTP clock arithmetic overflow"),
            Self::TickCountOverflow => formatter.write_str("RTP tick count overflow"),
            Self::DurationOverflow => formatter.write_str("RTP duration overflow"),
        }
    }
}

impl StdError for RtpClockError {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        MAX_RTP_CLOCK_RATE, RtpClock, RtpClockError, RtpClockRate, signed_timestamp_distance,
        wrapping_timestamp_distance,
    };

    #[test]
    fn pcmu_ten_milliseconds_is_exactly_eighty_ticks() {
        let mut clock = RtpClock::new(RtpClockRate::TELEPHONY_8_KHZ, 100);
        assert_eq!(
            clock
                .advance(Duration::from_millis(10))
                .unwrap_or_else(|_| panic!("advance")),
            80
        );
        assert_eq!(clock.timestamp(), 180);
        assert_eq!(clock.fractional_numerator(), 0);
    }

    #[test]
    fn ai_ten_milliseconds_is_exactly_240_samples() {
        let rate = RtpClockRate::AI_AUDIO_24_KHZ;
        assert_eq!(
            rate.ticks_for_duration(Duration::from_millis(10))
                .unwrap_or_else(|_| panic!("ticks")),
            240
        );
        assert_eq!(
            rate.duration_for_ticks(240)
                .unwrap_or_else(|_| panic!("duration")),
            Duration::from_millis(10)
        );
    }

    #[test]
    fn fractional_remainder_prevents_long_term_drift() {
        let rate = RtpClockRate::new(44_100).unwrap_or_else(|_| panic!("rate"));
        let mut clock = RtpClock::new(rate, 0);
        let mut emitted = 0_u64;
        for _ in 0..1_000 {
            emitted += clock
                .advance(Duration::from_millis(1))
                .unwrap_or_else(|_| panic!("advance"));
        }
        assert_eq!(emitted, 44_100);
        assert_eq!(clock.timestamp(), 44_100);
        assert_eq!(clock.fractional_numerator(), 0);
    }

    #[test]
    fn timestamp_progression_wraps_on_wire_boundary() {
        let mut clock = RtpClock::new(RtpClockRate::TELEPHONY_8_KHZ, u32::MAX - 39);
        clock.advance_ticks(80);
        assert_eq!(clock.timestamp(), 40);
        assert_eq!(wrapping_timestamp_distance(40, u32::MAX - 39), 80);
        assert_eq!(signed_timestamp_distance(40, u32::MAX - 39), 80);
    }

    #[test]
    fn reset_clears_fractional_state() {
        let mut clock = RtpClock::new(
            RtpClockRate::new(44_100).unwrap_or_else(|_| panic!("rate")),
            0,
        );
        clock
            .advance(Duration::from_millis(1))
            .unwrap_or_else(|_| panic!("advance"));
        assert_ne!(clock.fractional_numerator(), 0);
        clock.reset(7);
        assert_eq!(clock.timestamp(), 7);
        assert_eq!(clock.fractional_numerator(), 0);
    }

    #[test]
    fn validates_clock_rate_bounds() {
        assert_eq!(RtpClockRate::new(0), Err(RtpClockError::ZeroRate));
        assert_eq!(
            RtpClockRate::new(MAX_RTP_CLOCK_RATE + 1),
            Err(RtpClockError::RateTooHigh {
                actual: MAX_RTP_CLOCK_RATE + 1,
                maximum: MAX_RTP_CLOCK_RATE,
            })
        );
    }
}
