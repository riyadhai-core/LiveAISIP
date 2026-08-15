// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Bounded reactor readiness and fairness policy.

use super::error::ReactorError;

/// Maximum operating-system readiness records accepted in one wait.
pub const MAX_READY_EVENTS: usize = 1_024;
/// Maximum messages consumed from one readable source in one turn.
pub const MAX_READS_PER_SOURCE: usize = 64;
/// Maximum result records allocated by one reactor poll.
pub const MAX_BATCH_EVENTS: usize = 131_072;

/// Bounded readiness and per-source fairness policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReactorConfig {
    pub(super) ready_events: usize,
    pub(super) reads_per_source: usize,
}

impl ReactorConfig {
    /// Creates explicit readiness and read-drain budgets.
    ///
    /// # Errors
    ///
    /// Rejects zero values, hard-limit violations, and a combination whose
    /// maximum result batch would exceed [`MAX_BATCH_EVENTS`].
    pub const fn new(ready_events: usize, reads_per_source: usize) -> Result<Self, ReactorError> {
        if ready_events == 0 || ready_events > MAX_READY_EVENTS {
            return Err(ReactorError::InvalidReadyEventLimit {
                value: ready_events,
                maximum: MAX_READY_EVENTS,
            });
        }
        if reads_per_source == 0 || reads_per_source > MAX_READS_PER_SOURCE {
            return Err(ReactorError::InvalidReadBudget {
                value: reads_per_source,
                maximum: MAX_READS_PER_SOURCE,
            });
        }
        let Some(batch_events) = ready_events.checked_mul(reads_per_source + 2) else {
            return Err(ReactorError::BatchLimitExceeded {
                attempted: usize::MAX,
                maximum: MAX_BATCH_EVENTS,
            });
        };
        if batch_events > MAX_BATCH_EVENTS {
            return Err(ReactorError::BatchLimitExceeded {
                attempted: batch_events,
                maximum: MAX_BATCH_EVENTS,
            });
        }
        Ok(Self {
            ready_events,
            reads_per_source,
        })
    }

    /// Returns the maximum readiness records collected per wait.
    #[must_use]
    pub const fn ready_events(self) -> usize {
        self.ready_events
    }

    /// Returns the maximum inbound messages consumed per readable source.
    #[must_use]
    pub const fn reads_per_source(self) -> usize {
        self.reads_per_source
    }

    pub(super) const fn batch_events(self) -> usize {
        self.ready_events * (self.reads_per_source + 2)
    }
}

impl Default for ReactorConfig {
    fn default() -> Self {
        Self {
            ready_events: 256,
            reads_per_source: 16,
        }
    }
}
