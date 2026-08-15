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
/// Atomic preparation of outbound call runtimes.
pub mod dial;
/// Bounded process-level call engine.
pub mod engine;
/// Typed bounded outbound media offers.
pub mod media_offer;
/// Bounded application-facing runtime service.
pub mod service;
/// Coordinated graceful shutdown.
pub mod shutdown;

pub use dial::{OutboundDialConfig, OutboundDialError, PreparedOutboundCall};
pub use engine::{
    DialedCall, RuntimeEngine, RuntimeEngineConfig, RuntimeEngineError, RuntimeShutdownProgress,
};
pub use media_offer::{MediaCodec, MediaOfferConfig, MediaOfferError};
pub use service::{
    NotificationQueueSnapshot, RuntimeCallSnapshot, RuntimeNotification, RuntimeNotificationKind,
    RuntimePumpReport, RuntimeService, RuntimeServiceConfig, RuntimeServiceError,
    ServiceShutdownProgress, TerminalOutcome,
};
