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

//! SIP protocol subsystem.
//!
//! This module owns SIP message processing, protocol types, signaling
//! transports, transactions, dialogs, authentication, SDP handling, validation,
//! serialization, and outbound message construction.

/// SIP authentication.
pub mod auth;

/// Outbound SIP message construction.
pub mod builder;

/// SIP dialog state and lifecycle management.
pub mod dialog;

/// SIP wire-message framing.
pub mod framing;

/// Typed and extension SIP headers.
pub mod headers;
/// Cryptographically strong identifiers serialized onto the SIP wire.
pub mod identifier;

/// SIP wire-format parsing.
pub mod parser;

/// Session Description Protocol support.
pub mod sdp;

/// SIP wire-format serialization.
pub mod serializer;

/// SIP transaction state and timers.
pub mod transaction;

/// SIP signaling transports.
pub mod transport;

/// Core SIP protocol types.
pub mod types;

/// SIP structural and semantic validation.
pub mod validation;
