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

//! TLS message-write and graceful-shutdown progress state.

use std::sync::Arc;

/// Result of one bounded TLS message-write attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsWriteProgress {
    /// All encrypted records for the message reached the kernel socket buffer.
    Complete,
    /// Plaintext or encrypted records remain retained by the driver.
    Pending {
        /// Message bytes not yet accepted by Rustls.
        remaining_plaintext_bytes: usize,
        /// Rustls still has encrypted records not accepted by the socket.
        encrypted_flush_pending: bool,
    },
}

/// Result of graceful TLS write shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsShutdownProgress {
    /// `close_notify` was committed and the TCP write half was closed.
    Complete,
    /// Encrypted shutdown records remain blocked on socket writability.
    Pending,
}

pub(super) struct PendingWrite {
    pub(super) message: Arc<[u8]>,
    pub(super) offset: usize,
}
