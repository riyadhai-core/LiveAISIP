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

//! Runtime graceful-shutdown coordination boundary.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

/// Runtime shutdown lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownPhase {
    /// Normal admission and processing.
    Running,
    /// New admission stopped while active calls drain.
    Draining,
    /// Grace elapsed and remaining calls were asked to terminate.
    Forcing,
    /// Every active call and worker drained.
    Complete,
}

/// Explicit side effect for the runtime owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownAction {
    /// No state-changing work is due.
    None,
    /// Fence admission and begin graceful draining.
    StopAdmission,
    /// Terminate remaining calls after grace elapsed.
    ForceTerminate {
        /// Active calls present when grace expired.
        active_calls: usize,
    },
    /// All call-owned resources have drained.
    Complete,
}

/// Monotonic, idempotent graceful-shutdown coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownCoordinator {
    phase: ShutdownPhase,
    started_at: Option<Duration>,
    deadline: Option<Duration>,
    last_poll: Option<Duration>,
}

impl ShutdownCoordinator {
    /// Creates running state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: ShutdownPhase::Running,
            started_at: None,
            deadline: None,
            last_poll: None,
        }
    }

    /// Starts shutdown once and returns the admission-fence action.
    ///
    /// # Errors
    ///
    /// Rejects zero grace, deadline overflow, or repeated start.
    pub fn begin(
        &mut self,
        now: Duration,
        grace: Duration,
    ) -> Result<ShutdownAction, ShutdownError> {
        if self.phase != ShutdownPhase::Running {
            return Err(ShutdownError::AlreadyStarted);
        }
        if grace.is_zero() {
            return Err(ShutdownError::ZeroGrace);
        }
        let deadline = now.checked_add(grace).ok_or(ShutdownError::TimeOverflow)?;
        self.phase = ShutdownPhase::Draining;
        self.started_at = Some(now);
        self.deadline = Some(deadline);
        self.last_poll = Some(now);
        Ok(ShutdownAction::StopAdmission)
    }

    /// Polls draining progress and emits each transition once.
    ///
    /// # Errors
    ///
    /// Rejects polling before start and monotonic time regression.
    pub fn poll(
        &mut self,
        now: Duration,
        active_calls: usize,
    ) -> Result<ShutdownAction, ShutdownError> {
        if self.phase == ShutdownPhase::Running {
            return Err(ShutdownError::NotStarted);
        }
        if self.last_poll.is_some_and(|previous| now < previous) {
            return Err(ShutdownError::ClockMovedBackward);
        }
        self.last_poll = Some(now);
        if self.phase == ShutdownPhase::Complete {
            return Ok(ShutdownAction::None);
        }
        if active_calls == 0 {
            self.phase = ShutdownPhase::Complete;
            return Ok(ShutdownAction::Complete);
        }
        if self.phase == ShutdownPhase::Draining
            && now >= self.deadline.ok_or(ShutdownError::InternalInvariant)?
        {
            self.phase = ShutdownPhase::Forcing;
            return Ok(ShutdownAction::ForceTerminate { active_calls });
        }
        Ok(ShutdownAction::None)
    }

    /// Returns current shutdown lifecycle.
    #[must_use]
    pub const fn phase(self) -> ShutdownPhase {
        self.phase
    }

    /// Returns shutdown start time after admission was fenced.
    #[must_use]
    pub const fn started_at(self) -> Option<Duration> {
        self.started_at
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Shutdown coordination failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownError {
    /// Shutdown had already started.
    AlreadyStarted,
    /// Grace interval was zero.
    ZeroGrace,
    /// Polling occurred before shutdown began.
    NotStarted,
    /// Deadline calculation overflowed.
    TimeOverflow,
    /// Monotonic time regressed.
    ClockMovedBackward,
    /// Internal shutdown state was inconsistent.
    InternalInvariant,
}

impl fmt::Display for ShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime shutdown coordination failed")
    }
}

impl StdError for ShutdownError {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ShutdownAction, ShutdownCoordinator, ShutdownPhase};

    #[test]
    fn shutdown_fences_drains_forces_and_completes_once() {
        let mut shutdown = ShutdownCoordinator::new();
        assert_eq!(
            shutdown.begin(Duration::ZERO, Duration::from_secs(5)),
            Ok(ShutdownAction::StopAdmission)
        );
        assert_eq!(
            shutdown.poll(Duration::from_secs(4), 2),
            Ok(ShutdownAction::None)
        );
        assert_eq!(
            shutdown.poll(Duration::from_secs(5), 2),
            Ok(ShutdownAction::ForceTerminate { active_calls: 2 })
        );
        assert_eq!(shutdown.phase(), ShutdownPhase::Forcing);
        assert_eq!(
            shutdown.poll(Duration::from_secs(6), 0),
            Ok(ShutdownAction::Complete)
        );
        assert_eq!(
            shutdown.poll(Duration::from_secs(7), 0),
            Ok(ShutdownAction::None)
        );
    }
}
