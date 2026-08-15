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

//! Process-wide LiveAISIP runtime services.

/// Bounded call/media admission and retry suppression.
pub mod admission;
/// Coordinated graceful shutdown.
pub mod shutdown;

/// Temporary compatibility path for call-owned deadline scheduling.
pub mod deadline {
    pub use crate::call::execution::deadline::*;
}

/// Temporary compatibility path for call-owned media generation control.
pub mod media {
    pub use crate::call::media::controller::*;
}

/// Temporary compatibility path for call health evaluation.
pub mod signaling {
    pub use crate::call::model::health::*;
}
