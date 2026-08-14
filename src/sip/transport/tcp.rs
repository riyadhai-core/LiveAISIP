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

//! Incremental bounded SIP-over-TCP stream decoding.
//!
//! Partial reads and pipelined messages are accumulated under a hard byte
//! budget. Complete messages are extracted with immutable shared ownership.
//! A read cursor avoids shifting remaining bytes after every frame; compaction
//! occurs only after meaningful consumption.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use crate::sip::framing::{self, MAX_MESSAGE_BYTES, Mode, Status};

/// Default buffered unread bytes per TCP connection.
pub const DEFAULT_TCP_BUFFER_BYTES: usize = 2 * MAX_MESSAGE_BYTES;

/// Hard maximum buffered unread bytes per TCP connection.
pub const MAX_TCP_BUFFER_BYTES: usize = 4 * MAX_MESSAGE_BYTES;

/// Incremental bounded TCP receive buffer.
pub struct ReceiveBuffer {
    bytes: Vec<u8>,
    offset: usize,
    maximum: usize,
}

impl ReceiveBuffer {
    /// Creates a receive buffer with a validated unread-byte limit.
    ///
    /// # Errors
    ///
    /// The limit must hold one maximum SIP message and must not exceed the
    /// connection hard ceiling.
    pub fn new(maximum: usize) -> Result<Self, TcpError> {
        if !(MAX_MESSAGE_BYTES..=MAX_TCP_BUFFER_BYTES).contains(&maximum) {
            return Err(TcpError::InvalidBufferLimit {
                value: maximum,
                minimum: MAX_MESSAGE_BYTES,
                maximum: MAX_TCP_BUFFER_BYTES,
            });
        }
        Ok(Self {
            bytes: Vec::new(),
            offset: 0,
            maximum,
        })
    }

    /// Appends bytes from one socket read transactionally.
    ///
    /// # Errors
    ///
    /// Rejects an append exceeding the unread-byte limit or failing bounded
    /// allocation without changing logical buffer contents.
    pub fn append(&mut self, input: &[u8]) -> Result<(), TcpError> {
        let attempted = self
            .len()
            .checked_add(input.len())
            .ok_or(TcpError::BufferLimit {
                attempted: usize::MAX,
                maximum: self.maximum,
            })?;
        if attempted > self.maximum {
            return Err(TcpError::BufferLimit {
                attempted,
                maximum: self.maximum,
            });
        }

        self.compact_if_worthwhile();
        self.bytes
            .try_reserve_exact(input.len())
            .map_err(|_| TcpError::AllocationFailed)?;
        self.bytes.extend_from_slice(input);
        Ok(())
    }

    /// Extracts the next complete SIP message, if available.
    ///
    /// Stream keepalive prefixes consumed by the framer are discarded but are
    /// never included in the returned message.
    ///
    /// # Errors
    ///
    /// Propagates strict SIP stream-framing failures or allocation failure.
    pub fn next_message(&mut self) -> Result<Option<Arc<[u8]>>, TcpError> {
        let unread = &self.bytes[self.offset..];
        let boundary = match framing::inspect(unread, Mode::Stream).map_err(TcpError::Framing)? {
            Status::NeedMoreData { .. } => return Ok(None),
            Status::Complete(boundary) => boundary,
        };

        let Some(message) = unread.get(boundary.message_range()) else {
            return Err(TcpError::InternalBoundary);
        };
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(message.len())
            .map_err(|_| TcpError::AllocationFailed)?;
        owned.extend_from_slice(message);

        self.offset = self
            .offset
            .checked_add(boundary.consumed_bytes())
            .ok_or(TcpError::InternalBoundary)?;
        if self.offset == self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
        } else {
            self.compact_if_worthwhile();
        }
        Ok(Some(Arc::from(owned)))
    }

    /// Returns unread buffered bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    /// Returns whether no unread bytes remain.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the configured unread-byte limit.
    #[must_use]
    pub const fn maximum(&self) -> usize {
        self.maximum
    }

    /// Clears all buffered stream state.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.offset = 0;
    }

    fn compact_if_worthwhile(&mut self) {
        if self.offset != 0 && (self.offset >= self.bytes.len() / 2 || self.offset >= 64 * 1024) {
            self.bytes.copy_within(self.offset.., 0);
            self.bytes.truncate(self.bytes.len() - self.offset);
            self.offset = 0;
        }
    }
}

impl Default for ReceiveBuffer {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            offset: 0,
            maximum: DEFAULT_TCP_BUFFER_BYTES,
        }
    }
}

impl fmt::Debug for ReceiveBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiveBuffer")
            .field("unread_bytes", &self.len())
            .field("maximum", &self.maximum)
            .finish_non_exhaustive()
    }
}

/// Failure in TCP receive buffering or stream framing.
#[derive(Debug)]
#[non_exhaustive]
pub enum TcpError {
    /// Configured buffer limit was outside hard bounds.
    InvalidBufferLimit {
        /// Configured value.
        value: usize,
        /// Minimum permitted value.
        minimum: usize,
        /// Maximum permitted value.
        maximum: usize,
    },
    /// An append exceeded the unread-byte budget.
    BufferLimit {
        /// Attempted unread bytes.
        attempted: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// SIP stream framing rejected the bytes.
    Framing(framing::Error),
    /// A bounded allocation failed.
    AllocationFailed,
    /// Framing returned an inconsistent boundary.
    InternalBoundary,
}

impl TcpError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::InvalidBufferLimit { .. } => "invalid-buffer-limit",
            Self::BufferLimit { .. } => "buffer-limit",
            Self::Framing(_) => "framing",
            Self::AllocationFailed => "allocation-failed",
            Self::InternalBoundary => "internal-boundary",
        }
    }
}

impl fmt::Display for TcpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Framing(error) => write!(formatter, "SIP TCP framing failed: {error}"),
            _ => write!(formatter, "SIP TCP receive error: {}", self.class()),
        }
    }
}

impl StdError for TcpError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Framing(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReceiveBuffer, TcpError};
    use crate::sip::framing::MAX_MESSAGE_BYTES;

    const MESSAGE: &[u8] = b"OPTIONS sip:x@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP host;branch=z9hG4bK-one\r\n\
From: <sip:a@example.com>;tag=a\r\n\
To: <sip:x@example.com>\r\n\
Call-ID: one@example.com\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";

    #[test]
    fn assembles_partial_reads() {
        let mut buffer = ReceiveBuffer::default();
        for chunk in MESSAGE.chunks(7) {
            assert!(buffer.append(chunk).is_ok());
        }
        let Ok(Some(message)) = buffer.next_message() else {
            panic!("complete message")
        };
        assert_eq!(&*message, MESSAGE);
        assert!(buffer.is_empty());
    }

    #[test]
    fn extracts_pipelined_messages_and_skips_keepalive_prefix() {
        let mut input = b"\r\n\r\n".to_vec();
        input.extend_from_slice(MESSAGE);
        input.extend_from_slice(MESSAGE);
        let mut buffer = ReceiveBuffer::default();
        assert!(buffer.append(&input).is_ok());
        assert!(matches!(buffer.next_message(), Ok(Some(_))));
        assert!(matches!(buffer.next_message(), Ok(Some(_))));
        assert!(buffer.is_empty());
    }

    #[test]
    fn need_more_data_preserves_bytes_and_bad_framing_is_reported() {
        let mut buffer = ReceiveBuffer::default();
        assert!(buffer.append(&MESSAGE[..20]).is_ok());
        assert!(matches!(buffer.next_message(), Ok(None)));
        assert_eq!(buffer.len(), 20);

        buffer.clear();
        assert!(buffer.append(b"BROKEN\n").is_ok());
        assert!(matches!(buffer.next_message(), Err(TcpError::Framing(_))));
    }

    #[test]
    fn buffer_limit_is_transactional_and_debug_is_redacted() {
        let Ok(mut buffer) = ReceiveBuffer::new(MAX_MESSAGE_BYTES) else {
            panic!("valid buffer")
        };
        assert!(buffer.append(b"private").is_ok());
        let oversized = vec![0_u8; MAX_MESSAGE_BYTES];
        assert!(matches!(
            buffer.append(&oversized),
            Err(TcpError::BufferLimit { .. })
        ));
        assert_eq!(buffer.len(), 7);
        assert!(!format!("{buffer:?}").contains("private"));
    }
}
