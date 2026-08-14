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

//! Media protection policy and explicit authentication evidence.

use std::error::Error as StdError;
use std::fmt;

/// Signaling-selected media protection invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaSecurityPolicy {
    /// Clear RTP is allowed because signaling explicitly negotiated it.
    PlainAllowed,
    /// Every admitted packet must carry successful SRTP/SRTCP authentication.
    SecureRequired,
}

/// Evidence supplied by the decrypt/authenticate boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketProtection {
    /// Packet is clear RTP/RTCP.
    Plain,
    /// Packet passed SRTP or SRTCP authentication and replay checks.
    AuthenticatedSecure,
}

impl MediaSecurityPolicy {
    /// Admits protection evidence without ever falling back from secure to clear.
    ///
    /// # Errors
    ///
    /// Rejects plain input whenever secure media was negotiated.
    pub const fn admit(self, protection: PacketProtection) -> Result<(), MediaSecurityError> {
        match (self, protection) {
            (Self::SecureRequired, PacketProtection::Plain) => {
                Err(MediaSecurityError::SecurePacketRequired)
            }
            _ => Ok(()),
        }
    }
}

/// Stable media-security policy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaSecurityError {
    /// Clear media attempted to enter a secure negotiated session.
    SecurePacketRequired,
}

impl fmt::Display for MediaSecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("media security policy rejected packet")
    }
}

impl StdError for MediaSecurityError {}

#[cfg(test)]
mod tests {
    use super::{MediaSecurityError, MediaSecurityPolicy, PacketProtection};

    #[test]
    fn secure_policy_never_downgrades_to_plain_rtp() {
        assert_eq!(
            MediaSecurityPolicy::SecureRequired.admit(PacketProtection::Plain),
            Err(MediaSecurityError::SecurePacketRequired)
        );
        assert!(
            MediaSecurityPolicy::SecureRequired
                .admit(PacketProtection::AuthenticatedSecure)
                .is_ok()
        );
    }
}
