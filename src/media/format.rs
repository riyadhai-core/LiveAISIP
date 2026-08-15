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

//! Validated audio formats and negotiated network packetization.

use std::error::Error as StdError;
use std::fmt;

/// Negotiated RTP packet duration and clock-domain sample count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkPacketization {
    clock_rate_hz: u32,
    packet_time_ms: u16,
    samples_per_packet: u32,
}

impl NetworkPacketization {
    /// Converts negotiated `ptime` into exact codec clock samples.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive values, arithmetic overflow, or fractional samples.
    pub fn new(clock_rate_hz: u32, packet_time_ms: u16) -> Result<Self, AudioError> {
        if clock_rate_hz == 0 || packet_time_ms == 0 || packet_time_ms > 1_000 {
            return Err(AudioError::InvalidPacketization);
        }
        let product = u64::from(clock_rate_hz)
            .checked_mul(u64::from(packet_time_ms))
            .ok_or(AudioError::InvalidPacketization)?;
        if product % 1_000 != 0 {
            return Err(AudioError::FractionalPacketSamples);
        }
        let samples_per_packet =
            u32::try_from(product / 1_000).map_err(|_| AudioError::InvalidPacketization)?;
        Ok(Self {
            clock_rate_hz,
            packet_time_ms,
            samples_per_packet,
        })
    }

    /// Returns codec clock rate.
    #[must_use]
    pub const fn clock_rate_hz(self) -> u32 {
        self.clock_rate_hz
    }

    /// Returns negotiated network packet time.
    #[must_use]
    pub const fn packet_time_ms(self) -> u16 {
        self.packet_time_ms
    }

    /// Returns codec samples carried by one network packet.
    #[must_use]
    pub const fn samples_per_packet(self) -> u32 {
        self.samples_per_packet
    }
}

/// Audio frame or format contract failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioError {
    /// AI PCM frame had wrong sample count.
    InvalidAiFrameSamples {
        /// Supplied sample count.
        actual: usize,
    },
    /// Network-side PCMU PCM frame had the wrong sample count.
    InvalidPcmuFrameSamples {
        /// Supplied sample count.
        actual: usize,
    },
    /// Clock rate or packet time was outside bounds.
    InvalidPacketization,
    /// Packet time produced fractional codec samples.
    FractionalPacketSamples,
}

impl fmt::Display for AudioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("audio frame or packetization invalid")
    }
}

impl StdError for AudioError {}

#[cfg(test)]
mod tests {
    use super::NetworkPacketization;
    use crate::media::frame::AI_SAMPLES_PER_FRAME;

    #[test]
    fn network_ptime_is_independent_from_ai_frame() {
        let packetization =
            NetworkPacketization::new(8_000, 20).unwrap_or_else(|_| panic!("packetization"));
        assert_eq!(packetization.samples_per_packet(), 160);
        assert_eq!(AI_SAMPLES_PER_FRAME, 240);
    }
}
