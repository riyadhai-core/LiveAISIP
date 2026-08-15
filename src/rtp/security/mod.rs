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

/// Irreversible security requirement for one negotiated media generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaSecurityLatch {
    policy: MediaSecurityPolicy,
}

impl MediaSecurityLatch {
    /// Creates a clear-media-capable latch.
    #[must_use]
    pub const fn plain_allowed() -> Self {
        Self {
            policy: MediaSecurityPolicy::PlainAllowed,
        }
    }

    /// Permanently requires authenticated SRTP/SRTCP for this generation.
    pub const fn require_secure(&mut self) {
        self.policy = MediaSecurityPolicy::SecureRequired;
    }

    /// Returns the current one-way policy.
    #[must_use]
    pub const fn policy(self) -> MediaSecurityPolicy {
        self.policy
    }

    /// Applies packet protection evidence.
    ///
    /// # Errors
    ///
    /// Rejects unauthenticated or clear packets after secure media is required.
    pub const fn admit(self, protection: PacketProtection) -> Result<(), MediaSecurityError> {
        self.policy.admit(protection)
    }
}

/// Monotonic SRTP context generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SrtpGeneration(u64);

impl SrtpGeneration {
    /// Returns the opaque generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Generation-fenced SRTP context replacement state.
pub struct SrtpRekeyState<T> {
    generation: SrtpGeneration,
    context: T,
}

impl<T> SrtpRekeyState<T> {
    /// Installs initial directional SRTP context.
    #[must_use]
    pub const fn new(context: T) -> Self {
        Self {
            generation: SrtpGeneration(1),
            context,
        }
    }

    /// Returns current context generation.
    #[must_use]
    pub const fn generation(&self) -> SrtpGeneration {
        self.generation
    }

    /// Borrows the current private wrapper context.
    #[must_use]
    pub const fn context(&self) -> &T {
        &self.context
    }

    /// Atomically installs a new context and returns single-use rollback authority.
    ///
    /// # Errors
    ///
    /// Rejects installation when the monotonic generation is exhausted.
    pub fn install(&mut self, context: T) -> Result<SrtpRollback<T>, SrtpRekeyError> {
        let next = self
            .generation
            .0
            .checked_add(1)
            .ok_or(SrtpRekeyError::GenerationExhausted)?;
        let previous = std::mem::replace(&mut self.context, context);
        self.generation = SrtpGeneration(next);
        Ok(SrtpRollback {
            installed: self.generation,
            previous: Some(previous),
        })
    }

    /// Rolls back only if no newer rekey superseded the token.
    ///
    /// # Errors
    ///
    /// Rejects stale or consumed rollback authority and generation exhaustion.
    pub fn rollback(&mut self, mut token: SrtpRollback<T>) -> Result<(), SrtpRekeyError> {
        if token.installed != self.generation {
            return Err(SrtpRekeyError::StaleRollback);
        }
        let previous = token
            .previous
            .take()
            .ok_or(SrtpRekeyError::ConsumedRollback)?;
        self.context = previous;
        let next = self
            .generation
            .0
            .checked_add(1)
            .ok_or(SrtpRekeyError::GenerationExhausted)?;
        self.generation = SrtpGeneration(next);
        Ok(())
    }
}

impl<T> fmt::Debug for SrtpRekeyState<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SrtpRekeyState")
            .field("generation", &self.generation)
            .field("context", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Single-use authority to undo exactly one SRTP installation.
pub struct SrtpRollback<T> {
    installed: SrtpGeneration,
    previous: Option<T>,
}

impl<T> fmt::Debug for SrtpRollback<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SrtpRollback")
            .field("installed", &self.installed)
            .field("contains_context", &self.previous.is_some())
            .finish_non_exhaustive()
    }
}

/// SRTP rekey authority failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SrtpRekeyError {
    /// Context generation exhausted.
    GenerationExhausted,
    /// A newer context invalidated rollback authority.
    StaleRollback,
    /// Rollback token no longer contained prior state.
    ConsumedRollback,
}

impl fmt::Display for SrtpRekeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SRTP rekey generation rejected")
    }
}

impl StdError for SrtpRekeyError {}

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
    use super::{
        MediaSecurityError, MediaSecurityLatch, MediaSecurityPolicy, PacketProtection,
        SrtpRekeyError, SrtpRekeyState,
    };

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

    #[test]
    fn latch_is_one_way_within_media_generation() {
        let mut latch = MediaSecurityLatch::plain_allowed();
        assert!(latch.admit(PacketProtection::Plain).is_ok());
        latch.require_secure();
        assert_eq!(
            latch.admit(PacketProtection::Plain),
            Err(MediaSecurityError::SecurePacketRequired)
        );
    }

    #[test]
    fn stale_rekey_rollback_cannot_replace_newer_context() {
        let mut state = SrtpRekeyState::new("generation-1");
        let stale_rollback = state
            .install("generation-2")
            .unwrap_or_else(|_| panic!("install 2"));
        let current = state
            .install("generation-3")
            .unwrap_or_else(|_| panic!("install 3"));
        assert_eq!(
            state.rollback(stale_rollback),
            Err(SrtpRekeyError::StaleRollback)
        );
        assert_eq!(state.context(), &"generation-3");
        assert!(state.rollback(current).is_ok());
        assert_eq!(state.context(), &"generation-2");
    }
}
