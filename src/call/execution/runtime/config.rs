// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Immutable capacities and teardown policy for one call runtime.

use std::time::Duration;

use crate::call::model::redirect::RedirectPolicy;

/// Default per-call SIP transaction capacity.
pub const DEFAULT_CALL_TRANSACTION_CAPACITY: usize = 128;
/// Default per-call SIP dialog/fork capacity.
pub const DEFAULT_CALL_DIALOG_CAPACITY: usize = 32;
/// Default active deadline capacity per call.
pub const DEFAULT_CALL_DEADLINE_CAPACITY: usize = 256;
/// Default graceful protocol cleanup interval.
pub const DEFAULT_CALL_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Immutable capacities and teardown policy for one call runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallRuntimeConfig {
    pub(super) transaction_capacity: usize,
    pub(super) dialog_capacity: usize,
    pub(super) deadline_capacity: usize,
    pub(super) shutdown_grace: Duration,
    pub(super) require_secure_media: bool,
    pub(super) redirect_policy: RedirectPolicy,
}

impl CallRuntimeConfig {
    /// Creates explicit per-call ownership capacities.
    #[must_use]
    pub const fn new(
        transaction_capacity: usize,
        dialog_capacity: usize,
        deadline_capacity: usize,
        shutdown_grace: Duration,
        require_secure_media: bool,
    ) -> Self {
        Self {
            transaction_capacity,
            dialog_capacity,
            deadline_capacity,
            shutdown_grace,
            require_secure_media,
            redirect_policy: RedirectPolicy::Reject,
        }
    }

    /// Selects the bounded per-call 3xx policy before runtime construction.
    #[must_use]
    pub const fn with_redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = policy;
        self
    }

    /// Returns the graceful cleanup interval.
    #[must_use]
    pub const fn shutdown_grace(self) -> Duration {
        self.shutdown_grace
    }
}

impl Default for CallRuntimeConfig {
    fn default() -> Self {
        Self::new(
            DEFAULT_CALL_TRANSACTION_CAPACITY,
            DEFAULT_CALL_DIALOG_CAPACITY,
            DEFAULT_CALL_DEADLINE_CAPACITY,
            DEFAULT_CALL_SHUTDOWN_GRACE,
            false,
        )
    }
}
