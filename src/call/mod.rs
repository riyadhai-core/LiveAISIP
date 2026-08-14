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

//! Actor-owned outbound call orchestration.

/// Single-owner call actor context.
pub mod context;
pub mod events;
pub mod leg;
pub mod lifecycle;
/// Bounded generation-fenced call registry.
pub mod manager;
/// Explicit 3xx redirect handling policy.
pub mod redirect;
pub mod state;
/// Call-level deadline identities.
pub mod timers;
/// Blind and attended transfer request/state machinery.
pub mod transfer;

pub use events::{
    CallAction, CallCommand, CallEvent, CallReference, TransferTarget, TransferTargetError,
};
pub use leg::{DialogBranchId, ForkSet};
pub use lifecycle::{CallLifecycle, LifecycleError};
pub use redirect::{RedirectDecision, RedirectError, RedirectHandler, RedirectPolicy};
pub use state::{CallEndReason, CallState};
pub use transfer::{
    TransferError, TransferNotification, TransferRequestHeaders, TransferState, TransferTracker,
};
