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

//! Process-wide configuration.
//!
//! This module contains configuration shared across the `LiveAISIP` process.
//! Configuration owned by a specific subsystem remains with that subsystem so
//! unrelated settings do not accumulate in one global structure.

use std::time::Duration;

use crate::error::{Error, Result};

/// Process-wide configuration for a `LiveAISIP` server instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// Maximum time allowed for coordinated graceful shutdown.
    pub shutdown_timeout: Duration,
}

impl Config {
    /// Creates a configuration using the default `LiveAISIP` values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            shutdown_timeout: Duration::from_secs(45),
        }
    }

    /// Validates process-wide configuration invariants.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfiguration`] when a required configuration
    /// invariant is violated.
    pub fn validate(&self) -> Result<()> {
        if self.shutdown_timeout.is_zero() {
            return Err(Error::InvalidConfiguration {
                field: "shutdown_timeout",
                reason: "must be greater than zero",
            });
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::error::Error;
    use std::time::Duration;

    #[test]
    fn default_configuration_is_valid() {
        let config = Config::default();

        assert_eq!(config.shutdown_timeout, Duration::from_secs(45));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn zero_shutdown_timeout_is_rejected() {
        let config = Config {
            shutdown_timeout: Duration::ZERO,
        };

        let Err(error) = config.validate() else {
            panic!("zero shutdown timeout must be rejected");
        };

        assert!(matches!(
            error,
            Error::InvalidConfiguration {
                field: "shutdown_timeout",
                reason: "must be greater than zero",
            }
        ));
    }
}
