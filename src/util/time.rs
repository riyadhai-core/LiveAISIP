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

//! Overflow-safe monotonic scheduling primitives.
//!
//! Runtime code represents time as a [`Duration`] since a private
//! [`MonotonicClock`] epoch. This keeps wall-clock adjustments out of protocol,
//! media, and teardown decisions while allowing deterministic tests to supply
//! explicit timestamps.

use std::error::Error as StdError;
use std::fmt;
use std::time::{Duration, Instant};

/// Private monotonic epoch for one actor or worker lifetime.
pub(crate) struct MonotonicClock {
    epoch: Instant,
}

impl MonotonicClock {
    /// Captures a new monotonic epoch.
    #[must_use]
    pub(crate) fn start() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }

    /// Returns elapsed monotonic time since this clock was started.
    #[must_use]
    pub(crate) fn now(&self) -> Duration {
        self.epoch.elapsed()
    }

    /// Returns the non-negative wait remaining until an absolute deadline.
    #[must_use]
    pub(crate) fn remaining_until(&self, deadline: Duration) -> Duration {
        deadline.saturating_sub(self.now())
    }
}

impl fmt::Debug for MonotonicClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonotonicClock")
            .finish_non_exhaustive()
    }
}

/// Result of advancing one fixed-rate absolute schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PeriodicAdvance {
    due: u64,
    executed: u64,
    next_deadline: Duration,
}

impl PeriodicAdvance {
    /// Returns intervals permitted to execute during this scheduling cycle.
    #[must_use]
    pub(crate) const fn executed(self) -> u64 {
        self.executed
    }

    /// Returns overdue intervals omitted to preserve bounded actor latency.
    #[must_use]
    pub(crate) const fn skipped(self) -> u64 {
        self.due - self.executed
    }

    /// Returns the next deadline on the original absolute cadence.
    #[must_use]
    pub(crate) const fn next_deadline(self) -> Duration {
        self.next_deadline
    }
}

/// Adds a delay to an absolute monotonic timestamp without wrapping.
///
/// # Errors
///
/// Returns [`TimeError::Overflow`] when the deadline is not representable.
pub(crate) fn checked_deadline(now: Duration, delay: Duration) -> Result<Duration, TimeError> {
    now.checked_add(delay).ok_or(TimeError::Overflow)
}

/// Returns the earliest present deadline without allocating.
#[must_use]
pub(crate) fn minimum_deadline<const N: usize>(
    deadlines: [Option<Duration>; N],
) -> Option<Duration> {
    deadlines.into_iter().flatten().min()
}

/// Advances a fixed-rate schedule while bounding work performed this cycle.
///
/// Progress is based on the previous absolute deadline, not on `now`, so a late
/// wakeup cannot permanently shift media cadence. All overdue intervals count
/// as due, but no more than `execution_limit` are marked for execution.
///
/// # Errors
///
/// Rejects zero interval/limit and arithmetic outside [`Duration`]'s range.
pub(crate) fn advance_periodic(
    next_deadline: Duration,
    now: Duration,
    interval: Duration,
    execution_limit: u64,
) -> Result<Option<PeriodicAdvance>, TimeError> {
    if interval.is_zero() {
        return Err(TimeError::ZeroInterval);
    }
    if execution_limit == 0 {
        return Err(TimeError::ZeroExecutionLimit);
    }
    if now < next_deadline {
        return Ok(None);
    }
    let late_intervals = now
        .saturating_sub(next_deadline)
        .as_nanos()
        .checked_div(interval.as_nanos())
        .ok_or(TimeError::ZeroInterval)?;
    let due = late_intervals
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(TimeError::Overflow)?;
    let advance = checked_duration_mul(interval, due)?;
    let next_deadline = checked_deadline(next_deadline, advance)?;
    Ok(Some(PeriodicAdvance {
        due,
        executed: due.min(execution_limit),
        next_deadline,
    }))
}

/// Monotonic scheduling configuration or arithmetic failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimeError {
    /// A periodic schedule used a zero interval.
    ZeroInterval,
    /// A periodic schedule allowed no bounded work per cycle.
    ZeroExecutionLimit,
    /// A timestamp or duration calculation exceeded its representation.
    Overflow,
}

impl fmt::Display for TimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroInterval => "periodic interval must be non-zero",
            Self::ZeroExecutionLimit => "periodic execution limit must be non-zero",
            Self::Overflow => "monotonic time calculation overflowed",
        })
    }
}

impl StdError for TimeError {}

fn checked_duration_mul(value: Duration, multiplier: u64) -> Result<Duration, TimeError> {
    let nanos = value
        .as_nanos()
        .checked_mul(u128::from(multiplier))
        .ok_or(TimeError::Overflow)?;
    let seconds = nanos / 1_000_000_000;
    let subsecond = u32::try_from(nanos % 1_000_000_000).map_err(|_| TimeError::Overflow)?;
    Ok(Duration::new(
        u64::try_from(seconds).map_err(|_| TimeError::Overflow)?,
        subsecond,
    ))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{MonotonicClock, TimeError, advance_periodic, checked_deadline, minimum_deadline};

    #[test]
    fn monotonic_clock_exposes_elapsed_time_and_saturating_waits() {
        let clock = MonotonicClock::start();
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first);
        assert_eq!(clock.remaining_until(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn deadline_addition_rejects_overflow() {
        assert_eq!(
            checked_deadline(Duration::MAX, Duration::from_nanos(1)),
            Err(TimeError::Overflow)
        );
        assert_eq!(
            checked_deadline(Duration::from_secs(2), Duration::from_secs(3)),
            Ok(Duration::from_secs(5))
        );
    }

    #[test]
    fn minimum_ignores_absent_deadlines() {
        assert_eq!(
            minimum_deadline([
                Some(Duration::from_secs(9)),
                None,
                Some(Duration::from_secs(3)),
            ]),
            Some(Duration::from_secs(3))
        );
        assert_eq!(minimum_deadline([None, None]), None);
    }

    #[test]
    fn periodic_schedule_preserves_absolute_grid() {
        let advance = advance_periodic(
            Duration::from_millis(10),
            Duration::from_millis(105),
            Duration::from_millis(10),
            8,
        )
        .unwrap_or_else(|_| panic!("advance"))
        .unwrap_or_else(|| panic!("due"));
        assert_eq!(advance.executed(), 8);
        assert_eq!(advance.skipped(), 2);
        assert_eq!(advance.executed() + advance.skipped(), 10);
        assert_eq!(advance.next_deadline(), Duration::from_millis(110));
    }

    #[test]
    fn future_periodic_deadline_has_no_work() {
        assert_eq!(
            advance_periodic(
                Duration::from_secs(2),
                Duration::from_secs(1),
                Duration::from_millis(10),
                1,
            ),
            Ok(None)
        );
    }

    #[test]
    fn invalid_or_unrepresentable_periodic_config_is_rejected() {
        assert_eq!(
            advance_periodic(Duration::ZERO, Duration::ZERO, Duration::ZERO, 1),
            Err(TimeError::ZeroInterval)
        );
        assert_eq!(
            advance_periodic(Duration::ZERO, Duration::ZERO, Duration::from_nanos(1), 0,),
            Err(TimeError::ZeroExecutionLimit)
        );
        assert_eq!(
            advance_periodic(Duration::MAX, Duration::MAX, Duration::from_nanos(1), 1,),
            Err(TimeError::Overflow)
        );
    }
}
