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

//! Explicit remote RTP SSRC lifecycle and switch probation.

use std::error::Error as StdError;
use std::fmt;

/// Default sequential packets required to accept an unknown source.
pub const DEFAULT_SSRC_PROBATION_PACKETS: u8 = 2;

/// Remote-source switching policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourcePolicy {
    probation_packets: u8,
    allow_probationary_switch: bool,
}

impl SourcePolicy {
    /// Creates a bounded SSRC policy.
    ///
    /// # Errors
    ///
    /// Rejects zero probation.
    pub const fn new(
        probation_packets: u8,
        allow_probationary_switch: bool,
    ) -> Result<Self, SourceError> {
        if probation_packets == 0 {
            return Err(SourceError::ZeroProbation);
        }
        Ok(Self {
            probation_packets,
            allow_probationary_switch,
        })
    }

    /// Returns sequential packets needed to bind or switch.
    #[must_use]
    pub const fn probation_packets(self) -> u8 {
        self.probation_packets
    }

    /// Returns whether an un-signaled SSRC may replace an active one.
    #[must_use]
    pub const fn allows_probationary_switch(self) -> bool {
        self.allow_probationary_switch
    }
}

impl Default for SourcePolicy {
    fn default() -> Self {
        Self {
            probation_packets: DEFAULT_SSRC_PROBATION_PACKETS,
            allow_probationary_switch: false,
        }
    }
}

/// Result of observing one packet identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceObservation {
    /// Packet belongs to active source.
    Current,
    /// Candidate source is still proving sequential continuity.
    Probation {
        /// Sequential candidate packets seen.
        observed: u8,
        /// Packets required by policy.
        required: u8,
    },
    /// First remote source completed probation.
    Bound,
    /// Active source changed; receiver, RTCP, SRTP and playout state must reset.
    Switched,
    /// Source change was not authorized by policy.
    Rejected,
}

impl SourceObservation {
    /// Returns whether the packet may enter active stream processing.
    #[must_use]
    pub const fn admitted(self) -> bool {
        matches!(self, Self::Current | Self::Bound | Self::Switched)
    }

    /// Returns whether all source-specific media state must be reset.
    #[must_use]
    pub const fn requires_reset(self) -> bool {
        matches!(self, Self::Switched)
    }
}

/// Privacy-safe source lifecycle counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourceStats {
    /// Packets matching active SSRC.
    pub active_packets: u64,
    /// Packets processed during candidate probation.
    pub probation_packets: u64,
    /// Initial SSRC bindings.
    pub source_bindings: u64,
    /// Accepted active-source replacements.
    pub source_switches: u64,
    /// Rejected un-signaled source replacements.
    pub rejected_switches: u64,
}

/// Fixed-size SSRC ownership state for one inbound stream.
pub struct RemoteSourceTracker {
    policy: SourcePolicy,
    active: Option<u32>,
    candidate: Option<Candidate>,
    stats: SourceStats,
}

#[derive(Clone, Copy)]
struct Candidate {
    ssrc: u32,
    last_sequence: u16,
    sequential: u8,
}

impl RemoteSourceTracker {
    /// Creates source state, optionally bound by signaling.
    #[must_use]
    pub const fn new(expected_ssrc: Option<u32>, policy: SourcePolicy) -> Self {
        Self {
            policy,
            active: expected_ssrc,
            candidate: None,
            stats: SourceStats {
                active_packets: 0,
                probation_packets: 0,
                source_bindings: 0,
                source_switches: 0,
                rejected_switches: 0,
            },
        }
    }

    /// Observes one parsed, authenticated packet identity.
    pub fn observe(&mut self, ssrc: u32, sequence: u16) -> SourceObservation {
        if self.active == Some(ssrc) {
            self.candidate = None;
            self.stats.active_packets = self.stats.active_packets.saturating_add(1);
            return SourceObservation::Current;
        }
        if self.active.is_some() && !self.policy.allow_probationary_switch {
            self.stats.rejected_switches = self.stats.rejected_switches.saturating_add(1);
            return SourceObservation::Rejected;
        }

        self.stats.probation_packets = self.stats.probation_packets.saturating_add(1);
        let sequential = match self.candidate {
            Some(candidate)
                if candidate.ssrc == ssrc
                    && candidate.last_sequence.wrapping_add(1) == sequence =>
            {
                candidate
                    .sequential
                    .saturating_add(1)
                    .min(self.policy.probation_packets)
            }
            _ => 1,
        };
        if sequential < self.policy.probation_packets {
            self.candidate = Some(Candidate {
                ssrc,
                last_sequence: sequence,
                sequential,
            });
            return SourceObservation::Probation {
                observed: sequential,
                required: self.policy.probation_packets,
            };
        }

        let switched = self.active.replace(ssrc).is_some();
        self.candidate = None;
        if switched {
            self.stats.source_switches = self.stats.source_switches.saturating_add(1);
            SourceObservation::Switched
        } else {
            self.stats.source_bindings = self.stats.source_bindings.saturating_add(1);
            SourceObservation::Bound
        }
    }

    /// Explicitly authorizes a signaling-controlled source replacement.
    ///
    /// Returns whether active source identity changed. A true result requires
    /// resetting sequence, jitter, RTCP, SRTP replay and playout state.
    pub fn authorize(&mut self, ssrc: u32) -> bool {
        self.candidate = None;
        if self.active == Some(ssrc) {
            return false;
        }
        let switched = self.active.replace(ssrc).is_some();
        if switched {
            self.stats.source_switches = self.stats.source_switches.saturating_add(1);
        } else {
            self.stats.source_bindings = self.stats.source_bindings.saturating_add(1);
        }
        true
    }

    /// Clears identity when media is stopped or wholly renegotiated.
    pub fn clear(&mut self) {
        self.active = None;
        self.candidate = None;
    }

    /// Returns active SSRC for protocol integration; diagnostics remain redacted.
    #[must_use]
    pub const fn active_ssrc(&self) -> Option<u32> {
        self.active
    }

    /// Returns lifetime counters.
    #[must_use]
    pub const fn stats(&self) -> SourceStats {
        self.stats
    }
}

impl fmt::Debug for RemoteSourceTracker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteSourceTracker")
            .field("policy", &self.policy)
            .field("has_active_source", &self.active.is_some())
            .field("has_candidate", &self.candidate.is_some())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// Source policy configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceError {
    /// Sequential probation cannot be zero packets.
    ZeroProbation,
}

impl fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RTP source policy configuration failed")
    }
}

impl StdError for SourceError {}

#[cfg(test)]
mod tests {
    use super::{RemoteSourceTracker, SourceObservation, SourcePolicy};

    #[test]
    fn unknown_source_requires_sequential_probation() {
        let mut tracker = RemoteSourceTracker::new(None, SourcePolicy::default());
        assert!(matches!(
            tracker.observe(7, 10),
            SourceObservation::Probation { observed: 1, .. }
        ));
        assert_eq!(
            tracker.observe(7, 12),
            SourceObservation::Probation {
                observed: 1,
                required: 2
            }
        );
        assert_eq!(tracker.observe(7, 13), SourceObservation::Bound);
        assert_eq!(tracker.observe(7, 14), SourceObservation::Current);
    }

    #[test]
    fn default_rejects_unexpected_ssrc_switch() {
        let mut tracker = RemoteSourceTracker::new(Some(7), SourcePolicy::default());
        assert_eq!(tracker.observe(8, 1), SourceObservation::Rejected);
        assert_eq!(tracker.active_ssrc(), Some(7));
        assert_eq!(tracker.stats().rejected_switches, 1);
    }

    #[test]
    fn permissive_switch_is_explicit_and_requires_reset() {
        let Ok(policy) = SourcePolicy::new(2, true) else {
            panic!("policy")
        };
        let mut tracker = RemoteSourceTracker::new(Some(7), policy);
        assert!(!tracker.observe(8, 1).admitted());
        let switched = tracker.observe(8, 2);
        assert_eq!(switched, SourceObservation::Switched);
        assert!(switched.requires_reset());
        assert_eq!(tracker.active_ssrc(), Some(8));
    }

    #[test]
    fn signaling_authorization_bypasses_probation_but_reports_change() {
        let mut tracker = RemoteSourceTracker::new(Some(7), SourcePolicy::default());
        assert!(tracker.authorize(9));
        assert!(!tracker.authorize(9));
        assert_eq!(tracker.active_ssrc(), Some(9));
        assert_eq!(tracker.stats().source_switches, 1);
    }
}
