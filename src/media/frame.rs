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

//! Fixed-size PCM frames at the native AI boundary.

use std::fmt;

use super::format::AudioError;
use super::pcmu::{PCMU_SAMPLE_RATE_HZ, PCMU_SAMPLES_PER_10_MS};

/// AI audio sample rate.
pub const AI_SAMPLE_RATE_HZ: u32 = 24_000;
/// AI frame duration.
pub const AI_FRAME_DURATION_MS: u16 = 10;
/// Mono samples per AI frame.
pub const AI_SAMPLES_PER_FRAME: usize = 240;
/// PCM16 bytes per AI frame.
pub const AI_BYTES_PER_FRAME: usize = AI_SAMPLES_PER_FRAME * 2;

/// PCM16 bytes in one network-side PCMU source frame.
pub const PCMU_PCM_BYTES_PER_FRAME: usize = PCMU_SAMPLES_PER_10_MS * 2;

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

/// Exactly one PCM16/8 kHz/mono/10 ms frame feeding PCMU packetization.
///
/// Sonora's resampler will eventually produce this internal frame from the
/// public 24 kHz AI boundary. Keeping the two frame types distinct prevents a
/// 24 kHz buffer from being packetized accidentally as an 8 kHz RTP payload.
#[derive(Clone, Eq, PartialEq)]
pub struct PcmuPcmFrame {
    samples: [i16; PCMU_SAMPLES_PER_10_MS],
}

impl PcmuPcmFrame {
    /// Copies one exact network-side PCM frame.
    ///
    /// # Errors
    ///
    /// Rejects any size other than 80 mono samples.
    pub fn from_samples(samples: &[i16]) -> Result<Self, AudioError> {
        let samples = <[i16; PCMU_SAMPLES_PER_10_MS]>::try_from(samples).map_err(|_| {
            AudioError::InvalidPcmuFrameSamples {
                actual: samples.len(),
            }
        })?;
        Ok(Self { samples })
    }

    /// Creates ten milliseconds of digital silence.
    #[must_use]
    pub const fn silence() -> Self {
        Self {
            samples: [0; PCMU_SAMPLES_PER_10_MS],
        }
    }

    /// Returns the exact network-clock PCM samples.
    #[must_use]
    pub const fn samples(&self) -> &[i16; PCMU_SAMPLES_PER_10_MS] {
        &self.samples
    }
}

impl fmt::Debug for PcmuPcmFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PcmuPcmFrame")
            .field("sample_rate_hz", &PCMU_SAMPLE_RATE_HZ)
            .field("samples", &PCMU_SAMPLES_PER_10_MS)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{AI_SAMPLES_PER_FRAME, AiAudioFrame, PcmuPcmFrame};
    use crate::media::pcmu::PCMU_SAMPLES_PER_10_MS;
    #[test]
    fn ai_contract_is_always_24khz_ten_ms_mono() {
        assert!(AiAudioFrame::from_samples(&[0; AI_SAMPLES_PER_FRAME]).is_ok());
        assert!(AiAudioFrame::from_samples(&[0; 160]).is_err());
    }

    #[test]
    fn pcmu_source_contract_is_always_8khz_ten_ms_mono() {
        assert!(PcmuPcmFrame::from_samples(&[0; PCMU_SAMPLES_PER_10_MS]).is_ok());
        assert!(PcmuPcmFrame::from_samples(&[0; AI_SAMPLES_PER_FRAME]).is_err());
    }
}
