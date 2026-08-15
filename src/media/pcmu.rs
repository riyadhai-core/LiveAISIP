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

//! Allocation-free G.711 mu-law encoding and decoding.
//!
//! PCMU carries one encoded octet per 8 kHz mono sample. The codec is
//! intentionally stateless: packet timing, RTP sequence/timestamp ownership,
//! playout concealment, and resampling belong to their respective call-owned
//! layers. Bulk operations require caller-provided storage and reject work
//! above the live packetization ceiling before touching output.

use std::error::Error as StdError;
use std::fmt;

/// Static RTP payload type assigned to PCMU.
pub const PCMU_PAYLOAD_TYPE: u8 = 0;
/// PCMU RTP clock and PCM sample rate.
pub const PCMU_SAMPLE_RATE_HZ: u32 = 8_000;
/// PCMU supports one audio channel in the initial runtime profile.
pub const PCMU_CHANNELS: u8 = 1;
/// Samples and encoded octets in one 10 ms PCMU frame.
pub const PCMU_SAMPLES_PER_10_MS: usize = 80;
/// Default network packetization used by the runtime.
pub const DEFAULT_PCMU_PACKET_TIME_MS: u16 = 20;
/// Operational PCMU packetization ceiling.
pub const MAX_PCMU_PACKET_TIME_MS: u16 = 200;
/// Maximum samples or encoded octets admitted in one PCMU packet.
pub const MAX_PCMU_PACKET_SAMPLES: usize =
    PCMU_SAMPLES_PER_10_MS * (MAX_PCMU_PACKET_TIME_MS as usize / 10);

const MU_LAW_BIAS: i32 = 0x84;
const MU_LAW_CLIP: i32 = 32_635;
const SEGMENT_END: [i32; 8] = [
    0x00ff, 0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff,
];

/// Stateless G.711 mu-law codec.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct PcmuCodec;

impl PcmuCodec {
    /// Creates the initial mono PCMU codec.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Encodes PCM16 samples into caller-owned PCMU storage.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessive input and insufficient output storage. No
    /// output byte is changed when validation fails.
    pub fn encode<'a>(
        self,
        samples: &[i16],
        output: &'a mut [u8],
    ) -> Result<&'a mut [u8], PcmuError> {
        validate_lengths(samples.len(), output.len())?;
        let encoded = &mut output[..samples.len()];
        for (destination, sample) in encoded.iter_mut().zip(samples.iter().copied()) {
            *destination = encode_sample(sample);
        }
        Ok(encoded)
    }

    /// Decodes PCMU octets into caller-owned PCM16 storage.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessive input and insufficient output storage. No
    /// output sample is changed when validation fails.
    pub fn decode<'a>(
        self,
        encoded: &[u8],
        output: &'a mut [i16],
    ) -> Result<&'a mut [i16], PcmuError> {
        validate_lengths(encoded.len(), output.len())?;
        let decoded = &mut output[..encoded.len()];
        for (destination, octet) in decoded.iter_mut().zip(encoded.iter().copied()) {
            *destination = decode_sample(octet);
        }
        Ok(decoded)
    }
}

impl fmt::Debug for PcmuCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PcmuCodec")
            .field("payload_type", &PCMU_PAYLOAD_TYPE)
            .field("sample_rate_hz", &PCMU_SAMPLE_RATE_HZ)
            .field("channels", &PCMU_CHANNELS)
            .finish()
    }
}

/// Encodes one linear PCM16 sample as one G.711 mu-law octet.
#[must_use]
pub fn encode_sample(sample: i16) -> u8 {
    let linear = i32::from(sample);
    let (magnitude, mask) = if linear < 0 {
        (-linear, 0x7f_u8)
    } else {
        (linear, 0xff_u8)
    };
    let biased = magnitude.min(MU_LAW_CLIP) + MU_LAW_BIAS;
    let segment = SEGMENT_END
        .iter()
        .position(|limit| biased <= *limit)
        .unwrap_or(7);
    let mantissa = (biased >> (segment + 3)) & 0x0f;
    let segment_bits = u8::try_from(segment).unwrap_or(7);
    let mantissa_bits = u8::try_from(mantissa).unwrap_or(0x0f);
    let compressed = (segment_bits << 4) | mantissa_bits;
    compressed ^ mask
}

/// Decodes one G.711 mu-law octet into linear PCM16.
#[must_use]
pub fn decode_sample(encoded: u8) -> i16 {
    let inverted = !encoded;
    let exponent = i32::from((inverted >> 4) & 0x07);
    let mantissa = i32::from(inverted & 0x0f);
    let magnitude = ((mantissa << 3) + MU_LAW_BIAS) << exponent;
    let linear = if inverted & 0x80 != 0 {
        MU_LAW_BIAS - magnitude
    } else {
        magnitude - MU_LAW_BIAS
    };
    match i16::try_from(linear) {
        Ok(sample) => sample,
        Err(_) if linear < 0 => i16::MIN,
        Err(_) => i16::MAX,
    }
}

fn validate_lengths(input: usize, available: usize) -> Result<(), PcmuError> {
    if input == 0 {
        return Err(PcmuError::EmptyInput);
    }
    if input > MAX_PCMU_PACKET_SAMPLES {
        return Err(PcmuError::PacketTooLarge {
            actual: input,
            maximum: MAX_PCMU_PACKET_SAMPLES,
        });
    }
    if available < input {
        return Err(PcmuError::OutputTooSmall {
            required: input,
            available,
        });
    }
    Ok(())
}

/// PCMU codec input or storage failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PcmuError {
    /// A media packet cannot represent zero audio samples.
    EmptyInput,
    /// Packet duration exceeded the live PCMU ceiling.
    PacketTooLarge {
        /// Supplied samples or octets.
        actual: usize,
        /// Operational maximum.
        maximum: usize,
    },
    /// Caller-owned output storage could not hold the result.
    OutputTooSmall {
        /// Required samples or octets.
        required: usize,
        /// Supplied output elements.
        available: usize,
    },
}

impl PcmuError {
    /// Returns stable low-cardinality diagnostics.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::EmptyInput => "empty-input",
            Self::PacketTooLarge { .. } => "packet-too-large",
            Self::OutputTooSmall { .. } => "output-too-small",
        }
    }
}

impl fmt::Display for PcmuError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PCMU codec operation failed: {}", self.class())
    }
}

impl StdError for PcmuError {}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PCMU_PACKET_SAMPLES, PCMU_SAMPLES_PER_10_MS, PcmuCodec, PcmuError, decode_sample,
        encode_sample,
    };

    #[test]
    fn matches_canonical_g711_mu_law_vectors() {
        let vectors = [
            (i16::MIN, 0x00, -32_124),
            (-1_000, 0x4e, -988),
            (0, 0xff, 0),
            (1_000, 0xce, 988),
            (i16::MAX, 0x80, 32_124),
        ];
        for (linear, encoded, decoded) in vectors {
            assert_eq!(encode_sample(linear), encoded);
            assert_eq!(decode_sample(encoded), decoded);
        }
        assert_eq!(decode_sample(0x7f), 0);
    }

    #[test]
    fn every_pcm16_sample_round_trips_to_a_stable_or_canonical_zero_code() {
        for bits in u16::MIN..=u16::MAX {
            let sample = i16::from_ne_bytes(bits.to_ne_bytes());
            let encoded = encode_sample(sample);
            let reencoded = encode_sample(decode_sample(encoded));
            assert!(reencoded == encoded || (encoded == 0x7f && reencoded == 0xff));
        }
    }

    #[test]
    fn bulk_codec_uses_exact_caller_storage_without_touching_tail() {
        let codec = PcmuCodec::new();
        let input = [0_i16; PCMU_SAMPLES_PER_10_MS];
        let mut encoded = [0x55_u8; PCMU_SAMPLES_PER_10_MS + 1];
        let written = codec
            .encode(&input, &mut encoded)
            .unwrap_or_else(|_| panic!("encode"));
        assert_eq!(written, &[0xff; PCMU_SAMPLES_PER_10_MS]);
        assert_eq!(encoded[PCMU_SAMPLES_PER_10_MS], 0x55);

        let mut decoded = [123_i16; PCMU_SAMPLES_PER_10_MS + 1];
        let written = codec
            .decode(&encoded[..PCMU_SAMPLES_PER_10_MS], &mut decoded)
            .unwrap_or_else(|_| panic!("decode"));
        assert_eq!(written, &[0; PCMU_SAMPLES_PER_10_MS]);
        assert_eq!(decoded[PCMU_SAMPLES_PER_10_MS], 123);
    }

    #[test]
    fn length_failures_are_transactional_and_bounded() {
        let codec = PcmuCodec::new();
        let mut encoded = [0x55_u8; 1];
        assert_eq!(codec.encode(&[], &mut encoded), Err(PcmuError::EmptyInput));
        assert_eq!(encoded, [0x55]);

        let oversized = vec![0_i16; MAX_PCMU_PACKET_SAMPLES + 1];
        assert!(matches!(
            codec.encode(&oversized, &mut encoded),
            Err(PcmuError::PacketTooLarge { .. })
        ));
        assert_eq!(encoded, [0x55]);

        assert_eq!(
            codec.encode(&[0, 1], &mut encoded),
            Err(PcmuError::OutputTooSmall {
                required: 2,
                available: 1,
            })
        );
        assert_eq!(encoded, [0x55]);
    }

    #[test]
    fn diagnostics_never_include_audio_samples() {
        let debug = format!("{:?}", PcmuCodec::new());
        assert!(debug.contains("8000"));
        assert!(!debug.contains("32124"));
        let error = PcmuError::OutputTooSmall {
            required: 160,
            available: 80,
        };
        assert_eq!(error.class(), "output-too-small");
        assert!(!error.to_string().contains("160"));
    }
}
