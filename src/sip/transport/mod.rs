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

/// Incremental bounded SIP-over-TCP stream decoding.
pub mod tcp;

/// TLS security policy and handshake lifecycle.
pub mod tls;

/// Bounded actor-owned reliable connection registry.
pub mod manager;

/// Encoded-size and security-aware destination selection.
pub mod selection;

/// Hostile-network stream limits and liveness.
pub mod stream;

/// Bounded RFC 3263 destination planning over validated DNS answers.
pub mod resolver;
