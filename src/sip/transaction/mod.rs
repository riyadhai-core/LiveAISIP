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

//! SIP transaction state, matching, timers, and bounded management.

/// RFC 3261 transaction matching keys.
pub mod key;

/// Validated RFC 3261 transaction timer profiles.
pub mod timer;

/// Role-aware RFC transaction state machines.
pub mod state;

/// Deterministic client transaction engine.
pub mod client;

/// Deterministic server transaction engine.
pub mod server;

/// Bounded transaction registry and event routing.
pub mod manager;

/// Compact completion authority after heavy transaction removal.
pub mod completion;
