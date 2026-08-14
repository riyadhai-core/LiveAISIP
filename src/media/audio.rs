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

//! Fixed AI PCM contract independent of RTP packetization.

use std::error::Error as StdError;
use std::fmt;

/// AI audio sample rate.
pub const AI_SAMPLE_RATE_HZ: u32 = 24_000;
/// AI frame duration.
pub const AI_FRAME_DURATION_MS: u16 = 10;
/// Mono samples per AI frame.
pub const AI_SAMPLES_PER_FRAME: usize = 240;
/// PCM16 bytes per AI frame.
pub const AI_BYTES_PER_FRAME: usize = AI_SAMPLES_PER_FRAME * 2;

/// Exactly one PCM16/24 kHz/mono/10 ms AI frame.
#[derive(Clone, Eq, PartialEq)]
pub struct AiAudioFrame {
    samples: [i16; AI_SAMPLES_PER_FRAME],
}

impl AiAudioFrame {
    /// Copies exact-size PCM samples into an owned realtime frame.
    ///
    /// # Errors
    ///
    /// Rejects any size other than 240 mono samples.
    pub fn from_samples(samples: &[i16]) -> Result<Self, AudioError> {
        let samples = <[i16; AI_SAMPLES_PER_FRAME]>::try_from(samples).map_err(|_| {
            AudioError::InvalidAiFrameSamples {
                actual: samples.len(),
            }
        })?;
        Ok(Self { samples })
    }

    /// Creates digital silence.
    #[must_use]
    pub const fn silence() -> Self {
        Self {
            samples: [0; AI_SAMPLES_PER_FRAME],
        }
    }

    /// Returns exact PCM samples.
    #[must_use]
    pub const fn samples(&self) -> &[i16; AI_SAMPLES_PER_FRAME] {
        &self.samples
    }
}

impl fmt::Debug for AiAudioFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AiAudioFrame")
            .field("sample_rate_hz", &AI_SAMPLE_RATE_HZ)
            .field("samples", &AI_SAMPLES_PER_FRAME)
            .finish_non_exhaustive()
    }
}

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

/// Audio contract failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioError {
    /// AI PCM frame had wrong sample count.
    InvalidAiFrameSamples {
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
    use super::{AI_SAMPLES_PER_FRAME, AiAudioFrame, NetworkPacketization};
    #[test]
    fn ai_contract_is_always_24khz_ten_ms_mono() {
        assert!(AiAudioFrame::from_samples(&[0; AI_SAMPLES_PER_FRAME]).is_ok());
        assert!(AiAudioFrame::from_samples(&[0; 160]).is_err());
    }
    #[test]
    fn network_ptime_is_independent_from_ai_frame() {
        let packetization =
            NetworkPacketization::new(8_000, 20).unwrap_or_else(|_| panic!("packetization"));
        assert_eq!(packetization.samples_per_packet(), 160);
        assert_eq!(AI_SAMPLES_PER_FRAME, 240);
    }
}
