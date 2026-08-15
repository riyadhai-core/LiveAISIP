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

//! Preallocated encoded-packet storage at the playout ingress boundary.

use std::fmt;

use crate::rtp::packet::rtp::{MAX_RTP_PACKET_BYTES, RtpPacket};

use super::RtpSessionError;

/// Default packets waiting for immediate playout-engine insertion.
pub const DEFAULT_INGRESS_QUEUE_PACKETS: usize = 128;
/// Conservative encoded payload storage for codecs without a negotiated bound.
pub const DEFAULT_PLAYOUT_PAYLOAD_BYTES: usize = 2_048;
/// Exact payload bytes for one 20 ms PCMU packet.
pub const PCMU_20MS_PAYLOAD_BYTES: usize = 160;
/// Hard per-session byte ceiling for preallocated encoded packet slots.
pub const MAX_PLAYOUT_PACKET_POOL_BYTES: usize = 4 * 1_024 * 1_024;

struct PlayoutPacketSlot {
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    payload_type: u8,
    marker: bool,
    payload_length: usize,
    occupied: bool,
}

pub(super) struct PlayoutPacketPool {
    slots: Vec<PlayoutPacketSlot>,
    payloads: Box<[u8]>,
    free: Vec<usize>,
    maximum_payload_bytes: usize,
}

impl PlayoutPacketPool {
    pub(super) fn new(
        queue_capacity: usize,
        maximum_payload_bytes: usize,
    ) -> Result<Self, RtpSessionError> {
        if maximum_payload_bytes == 0 || maximum_payload_bytes > MAX_RTP_PACKET_BYTES {
            return Err(RtpSessionError::InvalidPayloadLimit {
                value: maximum_payload_bytes,
                maximum: MAX_RTP_PACKET_BYTES,
            });
        }
        let slot_count = queue_capacity
            .checked_add(1)
            .ok_or(RtpSessionError::AllocationFailed)?;
        let pool_bytes = slot_count
            .checked_mul(maximum_payload_bytes)
            .ok_or(RtpSessionError::AllocationFailed)?;
        if pool_bytes > MAX_PLAYOUT_PACKET_POOL_BYTES {
            return Err(RtpSessionError::PacketPoolTooLarge {
                requested: pool_bytes,
                maximum: MAX_PLAYOUT_PACKET_POOL_BYTES,
            });
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(slot_count)
            .map_err(|_| RtpSessionError::AllocationFailed)?;
        for _ in 0..slot_count {
            slots.push(PlayoutPacketSlot {
                sequence_number: 0,
                timestamp: 0,
                ssrc: 0,
                payload_type: 0,
                marker: false,
                payload_length: 0,
                occupied: false,
            });
        }
        let mut payloads = Vec::new();
        payloads
            .try_reserve_exact(pool_bytes)
            .map_err(|_| RtpSessionError::AllocationFailed)?;
        payloads.resize(pool_bytes, 0);
        let mut free = Vec::new();
        free.try_reserve_exact(slot_count)
            .map_err(|_| RtpSessionError::AllocationFailed)?;
        free.extend((0..slot_count).rev());
        Ok(Self {
            slots,
            payloads: payloads.into_boxed_slice(),
            free,
            maximum_payload_bytes,
        })
    }

    pub(super) fn store(&mut self, packet: &RtpPacket<'_>) -> Result<usize, RtpSessionError> {
        if packet.payload().len() > self.maximum_payload_bytes {
            return Err(RtpSessionError::PayloadTooLarge {
                actual: packet.payload().len(),
                maximum: self.maximum_payload_bytes,
            });
        }
        let index = self
            .free
            .pop()
            .ok_or(RtpSessionError::PacketPoolExhausted)?;
        let slot = &mut self.slots[index];
        if slot.occupied {
            return Err(RtpSessionError::PacketPoolExhausted);
        }
        let header = packet.header();
        slot.sequence_number = header.sequence_number();
        slot.timestamp = header.timestamp();
        slot.ssrc = header.ssrc();
        slot.payload_type = header.payload_type();
        slot.marker = header.marker();
        let payload_start = index * self.maximum_payload_bytes;
        let payload_end = payload_start + packet.payload().len();
        self.payloads[payload_start..payload_end].copy_from_slice(packet.payload());
        slot.payload_length = packet.payload().len();
        slot.occupied = true;
        Ok(index)
    }

    pub(super) fn release(&mut self, index: usize) {
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };
        if !slot.occupied {
            return;
        }
        slot.payload_length = 0;
        slot.occupied = false;
        self.free.push(index);
    }

    pub(super) fn packet(&mut self, index: usize) -> Option<PlayoutPacket<'_>> {
        self.slots
            .get(index)
            .is_some_and(|slot| slot.occupied)
            .then_some(PlayoutPacket { pool: self, index })
    }

    pub(super) const fn maximum_payload_bytes(&self) -> usize {
        self.maximum_payload_bytes
    }

    pub(super) const fn preallocated_payload_bytes(&self) -> usize {
        self.payloads.len()
    }
}

/// Borrowed checkout of one preallocated packet admitted for playout.
///
/// Dropping this value immediately returns its storage to the owning session.
/// Keeping it alive deliberately keeps the session mutably borrowed, so the
/// receive loop cannot overwrite the payload before playout insertion.
pub struct PlayoutPacket<'a> {
    pool: &'a mut PlayoutPacketPool,
    index: usize,
}

impl PlayoutPacket<'_> {
    fn slot(&self) -> &PlayoutPacketSlot {
        &self.pool.slots[self.index]
    }

    /// Returns RTP sequence number.
    #[must_use]
    pub fn sequence_number(&self) -> u16 {
        self.slot().sequence_number
    }

    /// Returns RTP timestamp.
    #[must_use]
    pub fn timestamp(&self) -> u32 {
        self.slot().timestamp
    }

    /// Returns synchronization source.
    #[must_use]
    pub fn ssrc(&self) -> u32 {
        self.slot().ssrc
    }

    /// Returns negotiated wire payload type.
    #[must_use]
    pub fn payload_type(&self) -> u8 {
        self.slot().payload_type
    }

    /// Returns RTP marker bit.
    #[must_use]
    pub fn marker(&self) -> bool {
        self.slot().marker
    }

    /// Returns encoded codec payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let slot = self.slot();
        let payload_start = self.index * self.pool.maximum_payload_bytes;
        &self.pool.payloads[payload_start..payload_start + slot.payload_length]
    }
}

impl Drop for PlayoutPacket<'_> {
    fn drop(&mut self) {
        self.pool.release(self.index);
    }
}

impl fmt::Debug for PlayoutPacket<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let slot = self.slot();
        formatter
            .debug_struct("PlayoutPacket")
            .field("payload_type", &slot.payload_type)
            .field("marker", &slot.marker)
            .field("payload_bytes", &slot.payload_length)
            .finish_non_exhaustive()
    }
}
