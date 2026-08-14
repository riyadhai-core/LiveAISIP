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

//! Crate-wide error primitives.
//!
//! Protocol-specific errors remain inside the subsystem that owns them. This
//! module contains only errors that can cross subsystem boundaries or apply to
//! the `LiveAISIP` process as a whole.

use std::error::Error as StdError;
use std::fmt;
use std::io;

/// Convenience result type for crate-wide `LiveAISIP` operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Crate-wide `LiveAISIP` errors.
///
/// Subsystems such as SIP, RTP, and media processing should define their own
/// detailed error types rather than continuously expanding this enum.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An operating-system or network I/O operation failed.
    Io(io::Error),

    /// A required configuration value is invalid.
    InvalidConfiguration {
        /// Name of the invalid configuration field.
        field: &'static str,

        /// Reason the configuration value is invalid.
        reason: &'static str,
    },

    /// A bounded resource has reached its configured capacity.
    ResourceExhausted {
        /// Name of the exhausted resource.
        resource: &'static str,
    },

    /// The requested operation cannot start because shutdown is in progress.
    ShuttingDown,
}

impl Error {
    /// Returns a stable low-cardinality error classification.
    ///
    /// This value is suitable for structured logs and metrics labels.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::InvalidConfiguration { .. } => "invalid-configuration",
            Self::ResourceExhausted { .. } => "resource-exhausted",
            Self::ShuttingDown => "shutting-down",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::InvalidConfiguration { field, reason } => {
                write!(formatter, "invalid configuration for `{field}`: {reason}")
            }
            Self::ResourceExhausted { resource } => {
                write!(formatter, "resource capacity exhausted: {resource}")
            }
            Self::ShuttingDown => {
                formatter.write_str("operation rejected because shutdown is in progress")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidConfiguration { .. }
            | Self::ResourceExhausted { .. }
            | Self::ShuttingDown => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use std::error::Error as StdError;
    use std::io;

    #[test]
    fn io_error_preserves_source() {
        let source = io::Error::new(io::ErrorKind::ConnectionReset, "connection reset");
        let error = Error::from(source);

        assert_eq!(error.class(), "io");
        assert!(error.source().is_some());
    }

    #[test]
    fn invalid_configuration_has_stable_class() {
        let error = Error::InvalidConfiguration {
            field: "example",
            reason: "must be valid",
        };

        assert_eq!(error.class(), "invalid-configuration");
        assert_eq!(
            error.to_string(),
            "invalid configuration for `example`: must be valid"
        );
    }

    #[test]
    fn resource_exhaustion_has_stable_class() {
        let error = Error::ResourceExhausted {
            resource: "sessions",
        };

        assert_eq!(error.class(), "resource-exhausted");
        assert_eq!(error.to_string(), "resource capacity exhausted: sessions");
    }

    #[test]
    fn shutting_down_has_stable_class() {
        let error = Error::ShuttingDown;

        assert_eq!(error.class(), "shutting-down");
        assert_eq!(
            error.to_string(),
            "operation rejected because shutdown is in progress"
        );
    }
}
