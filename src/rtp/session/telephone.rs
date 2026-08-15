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

//! Negotiated RFC 4733 telephone-event stream configuration.

use super::RtpSessionError;

/// Negotiated RFC 4733 stream descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelephoneEventConfig {
    payload_type: u8,
    clock_rate: u32,
    allowed_events: [u64; 4],
}

impl TelephoneEventConfig {
    /// Creates the common keypad event set 0 through 15.
    ///
    /// # Errors
    ///
    /// Rejects invalid payload types or a zero RTP clock rate.
    pub const fn standard(payload_type: u8, clock_rate: u32) -> Result<Self, RtpSessionError> {
        if payload_type > 127 || clock_rate == 0 {
            return Err(RtpSessionError::InvalidTelephoneEventConfig);
        }
        Ok(Self {
            payload_type,
            clock_rate,
            allowed_events: [0xffff, 0, 0, 0],
        })
    }

    /// Creates an event descriptor from a negotiated 256-bit allow set.
    ///
    /// # Errors
    ///
    /// Rejects invalid payload types, a zero clock rate, or an empty event set.
    pub const fn new(
        payload_type: u8,
        clock_rate: u32,
        allowed_events: [u64; 4],
    ) -> Result<Self, RtpSessionError> {
        if payload_type > 127
            || clock_rate == 0
            || (allowed_events[0] | allowed_events[1] | allowed_events[2] | allowed_events[3]) == 0
        {
            return Err(RtpSessionError::InvalidTelephoneEventConfig);
        }
        Ok(Self {
            payload_type,
            clock_rate,
            allowed_events,
        })
    }

    /// Returns negotiated dynamic payload type.
    #[must_use]
    pub const fn payload_type(self) -> u8 {
        self.payload_type
    }

    /// Returns negotiated event timestamp clock.
    #[must_use]
    pub const fn clock_rate(self) -> u32 {
        self.clock_rate
    }

    /// Returns whether one event code was negotiated.
    #[must_use]
    pub const fn allows(self, event: u8) -> bool {
        let word = event as usize / 64;
        let bit = event as usize % 64;
        self.allowed_events[word] & (1_u64 << bit) != 0
    }
}
