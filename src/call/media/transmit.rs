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

//! Bounded call-owned PCMU transmit packetization.
//!
//! Producers enqueue exact 10 ms PCM16/8 kHz frames with the active media
//! generation. The call thread consumes exactly one frame on each native
//! media tick and emits one allocation-free 20 ms PCMU payload every two
//! ticks. Queue underflow is replaced with digital silence so RTP timestamp
//! progression remains continuous. Queue overflow rejects the newest frame.

use std::collections::VecDeque;
use std::error::Error as StdError;
use std::fmt;

use crate::media::frame::PcmuPcmFrame;
use crate::media::pcmu::{
    DEFAULT_PCMU_PACKET_TIME_MS, PCMU_SAMPLES_PER_10_MS, PcmuCodec, PcmuError,
};

/// Default buffered producer lead: 320 ms of 10 ms frames.
pub const DEFAULT_PCMU_TRANSMIT_QUEUE_FRAMES: usize = 32;
/// PCM frames combined into the initial 20 ms RTP packetization profile.
pub const PCM_FRAMES_PER_PCMU_PACKET: usize =
    DEFAULT_PCMU_PACKET_TIME_MS as usize / 10;
/// Encoded bytes in one initial PCMU RTP payload.
pub const PCM_SAMPLES_PER_PCMU_PACKET: usize =
    PCMU_SAMPLES_PER_10_MS * PCM_FRAMES_PER_PCMU_PACKET;

/// One complete allocation-free PCMU codec payload.
#[derive(Clone, Eq, PartialEq)]
pub struct PcmuPacket {
    payload: [u8; PCM_SAMPLES_PER_PCMU_PACKET],
    silence_frames: u8,
}

impl PcmuPacket {
    /// Returns the exact 20 ms PCMU payload.
    #[must_use]
    pub const fn payload(&self) -> &[u8; PCM_SAMPLES_PER_PCMU_PACKET] {
        &self.payload
    }

    /// Returns 10 ms slots synthesized because the producer queue was empty.
    #[must_use]
    pub const fn silence_frames(&self) -> u8 {
        self.silence_frames
    }
}

impl fmt::Debug for PcmuPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PcmuPacket")
            .field("payload_octets", &self.payload.len())
            .field("silence_frames", &self.silence_frames)
            .finish()
    }
}

/// Result of one exact ten-millisecond media-clock tick.
#[derive(Clone, Eq, PartialEq)]
pub enum PcmuTransmitTick {
    /// One half of the next 20 ms payload is committed.
    Accumulating {
        /// Whether this slot used synthesized silence.
        silence: bool,
    },
    /// A complete payload is ready for the RTP wire sender.
    Packet(PcmuPacket),
}

impl fmt::Debug for PcmuTransmitTick {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accumulating { silence } => formatter
                .debug_struct("Accumulating")
                .field("silence", silence)
                .finish(),
            Self::Packet(packet) => packet.fmt(formatter),
        }
    }
}

/// One generation-fenced bounded transmit queue and packet accumulator.
pub struct PcmuTransmit {
    generation: u64,
    capacity: usize,
    queue: VecDeque<PcmuPcmFrame>,
    accumulator: [i16; PCM_SAMPLES_PER_PCMU_PACKET],
    committed_frames: usize,
    committed_silence_frames: u8,
    codec: PcmuCodec,
}

impl PcmuTransmit {
    /// Preallocates one generation's complete transmit queue.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity or allocation failure before publication.
    pub fn new(generation: u64, capacity: usize) -> Result<Self, PcmuTransmitError> {
        if capacity == 0 {
            return Err(PcmuTransmitError::ZeroCapacity);
        }
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(capacity)
            .map_err(|_| PcmuTransmitError::AllocationFailed)?;
        Ok(Self {
            generation,
            capacity,
            queue,
            accumulator: [0; PCM_SAMPLES_PER_PCMU_PACKET],
            committed_frames: 0,
            committed_silence_frames: 0,
            codec: PcmuCodec::new(),
        })
    }

    /// Returns the only media generation accepted by this queue.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns queued 10 ms frames awaiting clock consumption.
    #[must_use]
    pub fn queued_frames(&self) -> usize {
        self.queue.len()
    }

    /// Enqueues one exact 10 ms producer frame without growing storage.
    ///
    /// # Errors
    ///
    /// Rejects stale generations and a full queue. The newest frame remains
    /// owned by the caller on failure.
    pub fn enqueue(
        &mut self,
        generation: u64,
        frame: PcmuPcmFrame,
    ) -> Result<(), PcmuTransmitError> {
        if generation != self.generation {
            return Err(PcmuTransmitError::StaleGeneration {
                supplied: generation,
                active: self.generation,
            });
        }
        if self.queue.len() >= self.capacity {
            return Err(PcmuTransmitError::QueueFull {
                capacity: self.capacity,
            });
        }
        self.queue.push_back(frame);
        Ok(())
    }

    /// Consumes exactly one 10 ms slot and optionally completes a PCMU packet.
    ///
    /// Empty slots become encoded digital silence. Encoding uses stack-owned
    /// fixed storage and performs no allocation.
    ///
    /// # Errors
    ///
    /// Preserves impossible internal PCMU codec-contract failures.
    pub fn tick(&mut self) -> Result<PcmuTransmitTick, PcmuTransmitError> {
        let (frame, silence) = match self.queue.pop_front() {
            Some(frame) => (frame, false),
            None => (PcmuPcmFrame::silence(), true),
        };
        let start = self.committed_frames * PCMU_SAMPLES_PER_10_MS;
        let end = start + PCMU_SAMPLES_PER_10_MS;
        self.accumulator[start..end].copy_from_slice(frame.samples());
        self.committed_frames += 1;
        self.committed_silence_frames = self
            .committed_silence_frames
            .saturating_add(u8::from(silence));
        if self.committed_frames < PCM_FRAMES_PER_PCMU_PACKET {
            return Ok(PcmuTransmitTick::Accumulating { silence });
        }

        let mut payload = [0_u8; PCM_SAMPLES_PER_PCMU_PACKET];
        self.codec
            .encode(&self.accumulator, &mut payload)
            .map_err(PcmuTransmitError::Codec)?;
        let silence_frames = self.committed_silence_frames;
        self.committed_frames = 0;
        self.committed_silence_frames = 0;
        Ok(PcmuTransmitTick::Packet(PcmuPacket {
            payload,
            silence_frames,
        }))
    }
}

impl fmt::Debug for PcmuTransmit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PcmuTransmit")
            .field("generation", &self.generation)
            .field("capacity", &self.capacity)
            .field("queued_frames", &self.queue.len())
            .field("committed_frames", &self.committed_frames)
            .finish_non_exhaustive()
    }
}

/// Bounded PCMU transmit pipeline failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PcmuTransmitError {
    /// A bounded queue must retain at least one frame.
    ZeroCapacity,
    /// Preallocation failed before the queue became visible.
    AllocationFailed,
    /// Producer work belonged to a retired media generation.
    StaleGeneration {
        /// Generation supplied by the producer.
        supplied: u64,
        /// Currently active generation.
        active: u64,
    },
    /// The fixed queue rejected its newest frame.
    QueueFull {
        /// Configured frame capacity.
        capacity: usize,
    },
    /// Fixed PCMU codec contract failed.
    Codec(PcmuError),
}

impl PcmuTransmitError {
    /// Returns a stable low-cardinality diagnostic class.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::ZeroCapacity => "zero-capacity",
            Self::AllocationFailed => "allocation-failed",
            Self::StaleGeneration { .. } => "stale-generation",
            Self::QueueFull { .. } => "queue-full",
            Self::Codec(_) => "codec",
        }
    }
}

impl fmt::Display for PcmuTransmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PCMU transmit operation failed: {}", self.class())
    }
}

impl StdError for PcmuTransmitError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::ZeroCapacity
            | Self::AllocationFailed
            | Self::StaleGeneration { .. }
            | Self::QueueFull { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PCM_SAMPLES_PER_PCMU_PACKET, PcmuTransmit, PcmuTransmitError, PcmuTransmitTick,
    };
    use crate::media::frame::PcmuPcmFrame;
    use crate::media::pcmu::{PCMU_SAMPLES_PER_10_MS, encode_sample};

    fn frame(sample: i16) -> PcmuPcmFrame {
        PcmuPcmFrame::from_samples(&[sample; PCMU_SAMPLES_PER_10_MS])
            .unwrap_or_else(|_| panic!("frame"))
    }

    #[test]
    fn two_clock_ticks_form_one_ordered_twenty_millisecond_payload() {
        let mut transmit = PcmuTransmit::new(7, 2).unwrap_or_else(|_| panic!("transmit"));
        transmit
            .enqueue(7, frame(1_000))
            .unwrap_or_else(|_| panic!("enqueue"));
        transmit
            .enqueue(7, frame(-1_000))
            .unwrap_or_else(|_| panic!("enqueue"));
        assert_eq!(
            transmit.tick(),
            Ok(PcmuTransmitTick::Accumulating { silence: false })
        );
        let Ok(PcmuTransmitTick::Packet(packet)) = transmit.tick() else {
            panic!("packet");
        };
        assert_eq!(packet.payload().len(), PCM_SAMPLES_PER_PCMU_PACKET);
        assert_eq!(packet.silence_frames(), 0);
        assert_eq!(
            &packet.payload()[..PCMU_SAMPLES_PER_10_MS],
            &[encode_sample(1_000); PCMU_SAMPLES_PER_10_MS]
        );
        assert_eq!(
            &packet.payload()[PCMU_SAMPLES_PER_10_MS..],
            &[encode_sample(-1_000); PCMU_SAMPLES_PER_10_MS]
        );
    }

    #[test]
    fn empty_ticks_preserve_continuous_packet_cadence_with_silence() {
        let mut transmit = PcmuTransmit::new(1, 1).unwrap_or_else(|_| panic!("transmit"));
        assert_eq!(
            transmit.tick(),
            Ok(PcmuTransmitTick::Accumulating { silence: true })
        );
        let Ok(PcmuTransmitTick::Packet(packet)) = transmit.tick() else {
            panic!("packet");
        };
        assert_eq!(packet.silence_frames(), 2);
        assert_eq!(packet.payload(), &[0xff; PCM_SAMPLES_PER_PCMU_PACKET]);
    }

    #[test]
    fn queue_is_generation_fenced_and_rejects_newest_on_overflow() {
        let mut transmit = PcmuTransmit::new(3, 1).unwrap_or_else(|_| panic!("transmit"));
        assert!(matches!(
            transmit.enqueue(2, frame(1)),
            Err(PcmuTransmitError::StaleGeneration {
                supplied: 2,
                active: 3
            })
        ));
        transmit
            .enqueue(3, frame(1))
            .unwrap_or_else(|_| panic!("enqueue"));
        assert_eq!(
            transmit.enqueue(3, frame(2)),
            Err(PcmuTransmitError::QueueFull { capacity: 1 })
        );
        assert_eq!(transmit.queued_frames(), 1);
    }
}
