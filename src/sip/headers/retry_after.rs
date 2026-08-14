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

//! SIP `Retry-After` delta-seconds.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

/// Maximum accepted Retry-After field bytes.
pub const MAX_RETRY_AFTER_BYTES: usize = 32;

/// Typed nonnegative Retry-After delay.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RetryAfter(u32);

impl RetryAfter {
    /// Creates delay in seconds.
    #[must_use]
    pub const fn new(seconds: u32) -> Self {
        Self(seconds)
    }
    /// Parses bounded decimal field value.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, nondecimal and overflowing values.
    pub fn from_bytes(input: &[u8]) -> Result<Self, RetryAfterError> {
        if input.is_empty() {
            return Err(RetryAfterError::Empty);
        }
        if input.len() > MAX_RETRY_AFTER_BYTES {
            return Err(RetryAfterError::TooLong);
        }
        if !input.iter().all(u8::is_ascii_digit) {
            return Err(RetryAfterError::InvalidDecimal);
        }
        let mut value = 0_u32;
        for byte in input {
            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(u32::from(*byte - b'0')))
                .ok_or(RetryAfterError::Overflow)?;
        }
        Ok(Self(value))
    }
    /// Returns delay seconds.
    #[must_use]
    pub const fn seconds(self) -> u32 {
        self.0
    }
}

impl fmt::Display for RetryAfter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}
impl FromStr for RetryAfter {
    type Err = RetryAfterError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(value.as_bytes())
    }
}

/// Retry-After parse failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryAfterError {
    /// Field was empty.
    Empty,
    /// Field exceeded byte bound.
    TooLong,
    /// Field contained nondecimal data.
    InvalidDecimal,
    /// Decimal value exceeded `u32`.
    Overflow,
}
impl fmt::Display for RetryAfterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Retry-After header")
    }
}
impl StdError for RetryAfterError {}

#[cfg(test)]
mod tests {
    use super::{RetryAfter, RetryAfterError};
    #[test]
    fn parses_and_bounds_delta_seconds() {
        assert_eq!(
            RetryAfter::from_bytes(b"30").map(RetryAfter::seconds),
            Ok(30)
        );
        assert_eq!(
            RetryAfter::from_bytes(b"-1"),
            Err(RetryAfterError::InvalidDecimal)
        );
        assert_eq!(
            RetryAfter::from_bytes(b"4294967296"),
            Err(RetryAfterError::Overflow)
        );
    }
}
