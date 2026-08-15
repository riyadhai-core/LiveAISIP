// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Bounded transport-service policy.

use super::error::ServiceError;
use crate::sip::transport::manager::ManagerConfig;
use crate::sip::transport::udp::UdpConfig;

/// Hard upper bound for messages committed during one actor poll.
pub const MAX_WRITE_COMMITS_PER_POLL: usize = 64;

/// Bounded transport-service policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceConfig {
    pub(super) manager: ManagerConfig,
    pub(super) udp: UdpConfig,
    pub(super) write_commits_per_poll: usize,
}

impl ServiceConfig {
    /// Creates explicit actor and datagram limits.
    ///
    /// # Errors
    ///
    /// Rejects invalid manager policy or a zero/excessive write budget.
    pub const fn new(
        manager: ManagerConfig,
        udp: UdpConfig,
        write_commits_per_poll: usize,
    ) -> Result<Self, ServiceError> {
        match manager.validate() {
            Ok(()) => {}
            Err(error) => return Err(ServiceError::Manager(error)),
        }
        if write_commits_per_poll == 0 || write_commits_per_poll > MAX_WRITE_COMMITS_PER_POLL {
            return Err(ServiceError::InvalidWriteCommitBudget {
                value: write_commits_per_poll,
                maximum: MAX_WRITE_COMMITS_PER_POLL,
            });
        }
        Ok(Self {
            manager,
            udp,
            write_commits_per_poll,
        })
    }

    /// Returns reliable registry policy.
    #[must_use]
    pub const fn manager(self) -> ManagerConfig {
        self.manager
    }

    /// Returns UDP payload admission policy.
    #[must_use]
    pub const fn udp(self) -> UdpConfig {
        self.udp
    }

    /// Returns per-poll reliable commit budget.
    #[must_use]
    pub const fn write_commits_per_poll(self) -> usize {
        self.write_commits_per_poll
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            manager: ManagerConfig::new(),
            udp: UdpConfig::default(),
            write_commits_per_poll: 16,
        }
    }
}
