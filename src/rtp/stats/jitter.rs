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

//! RFC 3550 interarrival-jitter estimation.
//!
//! The estimator uses the RFC integer form with four fractional bits and never
//! performs floating-point arithmetic. Arrival and RTP timestamps are compared
//! modulo 32 bits, so normal RTP timestamp rollover remains transparent.

use std::time::Duration;

use crate::rtp::clock::{RtpClockError, RtpClockRate};

/// Default maximum single transit change, in seconds of media-clock time.
pub const DEFAULT_MAX_TRANSIT_STEP_SECONDS: u32 = 10;

/// Result of one jitter observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitterUpdate {
    /// First packet established the transit baseline.
    Primed,
    /// Jitter estimate was updated.
    Updated,
    /// Implausible transit discontinuity was ignored and reanchored.
    DiscontinuityIgnored {
        /// Absolute transit change in RTP timestamp units.
        delta_ticks: u32,
        /// Configured maximum accepted change.
        maximum_ticks: u32,
    },
}

/// Stateful fixed-point interarrival-jitter estimator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JitterEstimator {
    clock_rate: RtpClockRate,
    previous_transit: Option<i32>,
    jitter_q4: u64,
    maximum_step_ticks: u32,
    observations: u64,
    discontinuities: u64,
}

impl JitterEstimator {
    /// Creates an estimator with a ten-second discontinuity ceiling.
    #[must_use]
    pub fn new(clock_rate: RtpClockRate) -> Self {
        let maximum =
            u64::from(clock_rate.get()).saturating_mul(u64::from(DEFAULT_MAX_TRANSIT_STEP_SECONDS));
        let maximum_step_ticks = u32::try_from(maximum).unwrap_or(u32::MAX);
        Self::with_maximum_step(clock_rate, maximum_step_ticks)
    }

    /// Creates an estimator with a caller-selected transit-step ceiling.
    ///
    /// A ceiling of zero is useful for deterministic streams but will treat
    /// every nonzero transit change as a discontinuity.
    #[must_use]
    pub const fn with_maximum_step(clock_rate: RtpClockRate, maximum_step_ticks: u32) -> Self {
        Self {
            clock_rate,
            previous_transit: None,
            jitter_q4: 0,
            maximum_step_ticks,
            observations: 0,
            discontinuities: 0,
        }
    }

    /// Observes arrival time already expressed in RTP timestamp units.
    ///
    /// Both timestamps use their low 32 bits and therefore wrap naturally.
    pub fn observe(&mut self, arrival_timestamp: u32, rtp_timestamp: u32) -> JitterUpdate {
        let transit_bits = arrival_timestamp.wrapping_sub(rtp_timestamp);
        let transit = i32::from_ne_bytes(transit_bits.to_ne_bytes());
        self.observations = self.observations.saturating_add(1);
        let Some(previous) = self.previous_transit.replace(transit) else {
            return JitterUpdate::Primed;
        };
        let delta = transit.wrapping_sub(previous).unsigned_abs();
        if delta > self.maximum_step_ticks {
            self.discontinuities = self.discontinuities.saturating_add(1);
            return JitterUpdate::DiscontinuityIgnored {
                delta_ticks: delta,
                maximum_ticks: self.maximum_step_ticks,
            };
        }
        let decay = self.jitter_q4.saturating_add(8) >> 4;
        self.jitter_q4 = self
            .jitter_q4
            .saturating_add(u64::from(delta))
            .saturating_sub(decay);
        JitterUpdate::Updated
    }

    /// Converts a monotonic arrival duration to the configured RTP clock and
    /// observes the packet.
    ///
    /// # Errors
    ///
    /// Returns clock conversion failure without changing estimator state.
    pub fn observe_duration(
        &mut self,
        arrival: Duration,
        rtp_timestamp: u32,
    ) -> Result<JitterUpdate, RtpClockError> {
        let ticks = self.clock_rate.ticks_for_duration(arrival)?;
        let bytes = ticks.to_le_bytes();
        let arrival_timestamp = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Ok(self.observe(arrival_timestamp, rtp_timestamp))
    }

    /// Returns the media clock rate.
    #[must_use]
    pub const fn clock_rate(self) -> RtpClockRate {
        self.clock_rate
    }

    /// Returns rounded-down jitter for the RTCP interarrival-jitter field.
    #[must_use]
    pub fn jitter(self) -> u32 {
        u32::try_from((self.jitter_q4 >> 4).min(u64::from(u32::MAX))).unwrap_or(u32::MAX)
    }

    /// Returns the fixed-point estimate with four fractional bits.
    #[must_use]
    pub const fn jitter_q4(self) -> u64 {
        self.jitter_q4
    }

    /// Returns total observations including the priming packet.
    #[must_use]
    pub const fn observations(self) -> u64 {
        self.observations
    }

    /// Returns ignored discontinuity count.
    #[must_use]
    pub const fn discontinuities(self) -> u64 {
        self.discontinuities
    }

    /// Clears transit and jitter state while retaining configuration.
    pub const fn reset(&mut self) {
        self.previous_transit = None;
        self.jitter_q4 = 0;
        self.observations = 0;
        self.discontinuities = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{JitterEstimator, JitterUpdate};
    use crate::rtp::clock::RtpClockRate;

    #[test]
    fn constant_pcmu_spacing_has_zero_jitter() {
        let mut estimator = JitterEstimator::new(RtpClockRate::TELEPHONY_8_KHZ);
        assert_eq!(estimator.observe(1_000, 100), JitterUpdate::Primed);
        for index in 1..100_u32 {
            assert_eq!(
                estimator.observe(1_000 + index * 80, 100 + index * 80),
                JitterUpdate::Updated
            );
        }
        assert_eq!(estimator.jitter(), 0);
        assert_eq!(estimator.observations(), 100);
    }

    #[test]
    fn applies_rfc_fixed_point_filter() {
        let mut estimator = JitterEstimator::new(RtpClockRate::TELEPHONY_8_KHZ);
        estimator.observe(1_000, 100);
        estimator.observe(1_160, 180);
        assert_eq!(estimator.jitter_q4(), 80);
        assert_eq!(estimator.jitter(), 5);
        estimator.observe(1_240, 260);
        assert_eq!(estimator.jitter_q4(), 75);
        assert_eq!(estimator.jitter(), 4);
    }

    #[test]
    fn timestamp_wrap_does_not_create_false_jitter() {
        let mut estimator = JitterEstimator::new(RtpClockRate::TELEPHONY_8_KHZ);
        estimator.observe(u32::MAX - 39, u32::MAX - 139);
        estimator.observe(40, u32::MAX - 59);
        assert_eq!(estimator.jitter(), 0);
    }

    #[test]
    fn duration_conversion_matches_pcmu_clock() {
        let mut estimator = JitterEstimator::new(RtpClockRate::TELEPHONY_8_KHZ);
        assert_eq!(
            estimator
                .observe_duration(Duration::from_millis(10), 80)
                .unwrap_or_else(|_| panic!("observe")),
            JitterUpdate::Primed
        );
        assert_eq!(
            estimator
                .observe_duration(Duration::from_millis(20), 160)
                .unwrap_or_else(|_| panic!("observe")),
            JitterUpdate::Updated
        );
        assert_eq!(estimator.jitter(), 0);
    }

    #[test]
    fn discontinuity_is_ignored_and_reanchored() {
        let mut estimator = JitterEstimator::with_maximum_step(RtpClockRate::TELEPHONY_8_KHZ, 100);
        estimator.observe(1_000, 100);
        assert_eq!(
            estimator.observe(2_000, 100),
            JitterUpdate::DiscontinuityIgnored {
                delta_ticks: 1_000,
                maximum_ticks: 100,
            }
        );
        assert_eq!(estimator.jitter(), 0);
        assert_eq!(estimator.discontinuities(), 1);
        assert_eq!(estimator.observe(2_080, 180), JitterUpdate::Updated);
        assert_eq!(estimator.jitter(), 0);
    }

    #[test]
    fn reset_clears_measurements_not_configuration() {
        let mut estimator = JitterEstimator::new(RtpClockRate::AI_AUDIO_24_KHZ);
        estimator.observe(1_000, 0);
        estimator.observe(1_240, 0);
        estimator.reset();
        assert_eq!(estimator.clock_rate(), RtpClockRate::AI_AUDIO_24_KHZ);
        assert_eq!(estimator.observations(), 0);
        assert_eq!(estimator.jitter(), 0);
        assert_eq!(estimator.observe(5, 5), JitterUpdate::Primed);
    }
}
