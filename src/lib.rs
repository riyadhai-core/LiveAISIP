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

//! Crate root.
//!
//! This module defines the top-level `LiveAISIP` crate structure and exposes
//! the major signaling, media, runtime, networking, and observability
//! subsystems.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

/// Call lifecycle and call-control primitives.
pub mod call;

/// Process-wide `LiveAISIP` configuration.
pub mod config;

/// Crate-wide error primitives.
pub mod error;

/// Audio and media processing.
pub mod media;

/// Shared networking primitives.
pub mod net;

/// Metrics and diagnostics.
pub mod observability;

/// RTP, RTCP, transport, and DTMF support.
pub mod rtp;

/// Runtime coordination and lifecycle management.
pub mod runtime;

/// SIP protocol implementation.
pub mod sip;

/// Internal utility primitives.
pub(crate) mod util;
