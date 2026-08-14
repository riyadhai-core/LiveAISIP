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

//! SDP media direction attributes.
//!
//! Direction is always expressed from the owner of the SDP description. The
//! reverse operation converts a remote offer's perspective into the local
//! answer perspective. Absent direction attributes default to `sendrecv` at
//! the semantic session layer.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

/// SDP media direction.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Direction {
    /// Send and receive media.
    #[default]
    SendRecv,
    /// Send media without receiving it.
    SendOnly,
    /// Receive media without sending it.
    RecvOnly,
    /// Neither send nor receive media.
    Inactive,
}

impl Direction {
    /// Parses an exact SDP direction attribute value.
    ///
    /// SDP attribute names are case-sensitive; uppercase variants are not
    /// silently normalized.
    ///
    /// # Errors
    ///
    /// Returns [`DirectionParseError`] for an unknown value.
    pub fn from_bytes(input: &[u8]) -> Result<Self, DirectionParseError> {
        match input {
            b"sendrecv" => Ok(Self::SendRecv),
            b"sendonly" => Ok(Self::SendOnly),
            b"recvonly" => Ok(Self::RecvOnly),
            b"inactive" => Ok(Self::Inactive),
            _ => Err(DirectionParseError),
        }
    }

    /// Returns the exact SDP attribute token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendRecv => "sendrecv",
            Self::SendOnly => "sendonly",
            Self::RecvOnly => "recvonly",
            Self::Inactive => "inactive",
        }
    }

    /// Returns whether the SDP owner sends media.
    #[must_use]
    pub const fn sends(self) -> bool {
        matches!(self, Self::SendRecv | Self::SendOnly)
    }

    /// Returns whether the SDP owner receives media.
    #[must_use]
    pub const fn receives(self) -> bool {
        matches!(self, Self::SendRecv | Self::RecvOnly)
    }

    /// Reverses direction into the peer's perspective.
    #[must_use]
    pub const fn reversed(self) -> Self {
        match self {
            Self::SendRecv => Self::SendRecv,
            Self::SendOnly => Self::RecvOnly,
            Self::RecvOnly => Self::SendOnly,
            Self::Inactive => Self::Inactive,
        }
    }

    /// Computes the answer direction allowed by a remote offer and local
    /// send/receive capabilities.
    ///
    /// The result never exceeds the media directions permitted by the offer.
    #[must_use]
    pub const fn answer(self, local_can_send: bool, local_can_receive: bool) -> Self {
        let offered_to_local = self.reversed();
        let send = offered_to_local.sends() && local_can_send;
        let receive = offered_to_local.receives() && local_can_receive;
        match (send, receive) {
            (true, true) => Self::SendRecv,
            (true, false) => Self::SendOnly,
            (false, true) => Self::RecvOnly,
            (false, false) => Self::Inactive,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Direction {
    type Err = DirectionParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(input.as_bytes())
    }
}

/// Failure to parse an SDP direction attribute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectionParseError;

impl fmt::Display for DirectionParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SDP media direction")
    }
}

impl StdError for DirectionParseError {}

#[cfg(test)]
mod tests {
    use super::{Direction, DirectionParseError};

    #[test]
    fn parses_and_serializes_exact_tokens() {
        for direction in [
            Direction::SendRecv,
            Direction::SendOnly,
            Direction::RecvOnly,
            Direction::Inactive,
        ] {
            assert_eq!(
                Direction::from_bytes(direction.as_str().as_bytes()),
                Ok(direction)
            );
            assert_eq!(direction.to_string(), direction.as_str());
        }
        assert_eq!(Direction::from_bytes(b"SENDRECV"), Err(DirectionParseError));
    }

    #[test]
    fn reports_send_and_receive_capabilities() {
        assert!(Direction::SendRecv.sends());
        assert!(Direction::SendRecv.receives());
        assert!(Direction::SendOnly.sends());
        assert!(!Direction::SendOnly.receives());
        assert!(!Direction::RecvOnly.sends());
        assert!(Direction::RecvOnly.receives());
        assert!(!Direction::Inactive.sends());
        assert!(!Direction::Inactive.receives());
    }

    #[test]
    fn reversal_preserves_peer_perspective() {
        assert_eq!(Direction::SendOnly.reversed(), Direction::RecvOnly);
        assert_eq!(Direction::RecvOnly.reversed(), Direction::SendOnly);
        assert_eq!(Direction::SendRecv.reversed(), Direction::SendRecv);
        assert_eq!(Direction::Inactive.reversed(), Direction::Inactive);
    }

    #[test]
    fn answer_is_intersection_of_offer_and_local_capability() {
        assert_eq!(Direction::SendOnly.answer(true, true), Direction::RecvOnly);
        assert_eq!(Direction::RecvOnly.answer(true, true), Direction::SendOnly);
        assert_eq!(Direction::SendRecv.answer(false, true), Direction::RecvOnly);
        assert_eq!(Direction::Inactive.answer(true, true), Direction::Inactive);
    }

    #[test]
    fn default_is_sendrecv() {
        assert_eq!(Direction::default(), Direction::SendRecv);
    }
}
