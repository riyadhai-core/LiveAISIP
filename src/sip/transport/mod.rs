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

//! Bounded SIP signaling transport.

/// Validated resolved transport destinations.
pub mod destination;

/// Reliable transport connection lifecycle and bounded outbound queues.
pub mod connection;

/// Bounded SIP-over-UDP datagram preparation.
pub mod udp;

/// Runtime-neutral SIP-over-UDP socket driver.
pub mod udp_driver;

/// Validated messages shared by datagram and stream socket drivers.
pub use udp_driver::{InboundMessage, ReceivedMessage};

/// Incremental bounded SIP-over-TCP stream decoding.
pub mod tcp;

/// Runtime-neutral SIP-over-TCP socket driver.
pub mod tcp_driver;

/// TLS security policy and handshake lifecycle.
pub mod tls;

/// Verified outbound SIP-over-TLS socket driver.
pub mod tls_driver;

/// Commit-aware bounded signaling transport orchestration.
pub mod service;

/// Native one-thread readiness reactor for bounded transport orchestration.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub mod reactor;

/// Bounded actor-owned reliable connection registry.
pub mod manager;

/// Encoded-size and security-aware destination selection.
pub mod selection;

/// Hostile-network stream limits and liveness.
pub mod stream;

/// Bounded RFC 3263 destination planning over validated DNS answers.
pub mod resolver;

/// Transport-truth metadata and exact reliable-flow routing.
pub mod flow;

/// Wire-commit-aware bounded destination failover.
pub mod failover;

/// Bounded monotonic outbound-dial failure suppression.
pub mod backoff;
