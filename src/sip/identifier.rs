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

//! Cryptographically strong SIP wire identifiers.
//!
//! Transaction branches, dialog tags, Call-IDs, and Digest client nonces are
//! observable protocol values. They must be unpredictable even though most of
//! them are not bearer secrets. This module obtains 128 bits directly from the
//! operating-system CSPRNG and encodes them as lowercase hexadecimal.
//!
//! Process-local counters belong in internal identity code, not on the wire.

use std::error::Error as StdError;
use std::fmt;

use ring::rand::{SecureRandom, SystemRandom};

/// Entropy bytes carried by one generated SIP wire token.
pub const WIRE_TOKEN_BYTES: usize = 16;
/// Hexadecimal characters carried by one generated SIP wire token.
pub const WIRE_TOKEN_HEX_LENGTH: usize = WIRE_TOKEN_BYTES * 2;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Generates a fresh 128-bit lowercase-hexadecimal SIP wire token.
///
/// # Errors
///
/// Reports operating-system entropy or bounded string-allocation failure.
pub fn generate_wire_token() -> Result<String, WireTokenError> {
    let mut entropy = [0_u8; WIRE_TOKEN_BYTES];
    SystemRandom::new()
        .fill(&mut entropy)
        .map_err(|_| WireTokenError::EntropyUnavailable)?;
    let mut encoded = String::new();
    encoded
        .try_reserve_exact(WIRE_TOKEN_HEX_LENGTH)
        .map_err(|_| WireTokenError::AllocationFailed)?;
    for byte in entropy {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

/// Failure to generate a cryptographic SIP wire token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WireTokenError {
    /// The operating-system cryptographic random source failed.
    EntropyUnavailable,
    /// Fixed-size hexadecimal output allocation failed.
    AllocationFailed,
}

impl WireTokenError {
    /// Returns a stable privacy-safe diagnostic class.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::EntropyUnavailable => "entropy-unavailable",
            Self::AllocationFailed => "allocation-failed",
        }
    }
}

impl fmt::Display for WireTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SIP wire-token generation failed: {}",
            self.class()
        )
    }
}

impl StdError for WireTokenError {}

#[cfg(test)]
mod tests {
    use super::{WIRE_TOKEN_HEX_LENGTH, generate_wire_token};

    #[test]
    fn generated_token_has_fixed_lowercase_hex_encoding() {
        let token = generate_wire_token().unwrap_or_else(|_| panic!("wire token"));
        assert_eq!(token.len(), WIRE_TOKEN_HEX_LENGTH);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}
