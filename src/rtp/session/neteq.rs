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

//! Preallocated encoded-packet storage at the `NetEQ` ingress boundary.

use std::fmt;

use crate::rtp::packet::rtp::{MAX_RTP_PACKET_BYTES, RtpPacket};

use super::RtpSessionError;

/// Default packets waiting for immediate `NetEq` insertion.
pub const DEFAULT_INGRESS_QUEUE_PACKETS: usize = 128;
/// Default encoded payload storage reserved for every `NetEq` ingress slot.
pub const DEFAULT_NETEQ_PAYLOAD_BYTES: usize = 2_048;
/// Hard per-session byte ceiling for preallocated encoded packet slots.
pub const MAX_NETEQ_PACKET_POOL_BYTES: usize = 4 * 1_024 * 1_024;

struct NetEqPacketSlot {
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    payload_type: u8,
    marker: bool,
    payload_length: usize,
    occupied: bool,
}

pub(super) struct NetEqPacketPool {
    slots: Vec<NetEqPacketSlot>,
    payloads: Box<[u8]>,
    free: Vec<usize>,
    maximum_payload_bytes: usize,
}

impl NetEqPacketPool {
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
        if pool_bytes > MAX_NETEQ_PACKET_POOL_BYTES {
            return Err(RtpSessionError::PacketPoolTooLarge {
                requested: pool_bytes,
                maximum: MAX_NETEQ_PACKET_POOL_BYTES,
            });
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(slot_count)
            .map_err(|_| RtpSessionError::AllocationFailed)?;
        for _ in 0..slot_count {
            slots.push(NetEqPacketSlot {
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

    pub(super) fn packet(&mut self, index: usize) -> Option<NetEqPacket<'_>> {
        self.slots
            .get(index)
            .is_some_and(|slot| slot.occupied)
            .then_some(NetEqPacket { pool: self, index })
    }
}

/// Borrowed checkout of one preallocated packet slot admitted for `NetEq`.
///
/// Dropping this value immediately returns its storage to the owning session.
/// Keeping it alive deliberately keeps the session mutably borrowed, so the
/// receive loop cannot overwrite the payload before `NetEq::InsertPacket`.
pub struct NetEqPacket<'a> {
    pool: &'a mut NetEqPacketPool,
    index: usize,
}

impl NetEqPacket<'_> {
    fn slot(&self) -> &NetEqPacketSlot {
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

impl Drop for NetEqPacket<'_> {
    fn drop(&mut self) {
        self.pool.release(self.index);
    }
}

impl fmt::Debug for NetEqPacket<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let slot = self.slot();
        formatter
            .debug_struct("NetEqPacket")
            .field("payload_type", &slot.payload_type)
            .field("marker", &slot.marker)
            .field("payload_bytes", &slot.payload_length)
            .finish_non_exhaustive()
    }
}
