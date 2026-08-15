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

//! Call-owned model, execution, signaling, and media coordination.

pub mod execution;
pub mod media;
pub mod model;
pub mod signaling;

pub use execution::handle::{
    CallActionReceiveError, CallHandle, CallQueueSnapshot, CallStatusSnapshot, CallSubmitError,
    CallSubmitErrorKind, CallThreadPhase, CallToken,
};
pub use execution::runtime::{
    AudioDirection, CallMessage, CallRuntime, CallRuntimeConfig, CallRuntimeDiagnostics,
    CallRuntimeError,
};
pub use execution::thread::{
    CallExit, CallExitKind, CallThread, CallThreadConfig, CallThreadError,
};
pub use model::branch::{DialogBranchId, ForkSet};
pub use model::events::{
    CallAction, CallCommand, CallEvent, CallReference, TransferTarget, TransferTargetError,
};
pub use model::lifecycle::{CallLifecycle, LifecycleError};
pub use model::redirect::{RedirectDecision, RedirectError, RedirectHandler, RedirectPolicy};
pub use model::state::{CallEndReason, CallState};
pub use model::transfer::{
    TransferError, TransferNotification, TransferRequestHeaders, TransferState, TransferTracker,
};
pub use signaling::{SignalingError, UdpSignaling};

// Temporary source-compatibility paths while downstream users migrate to the
// ownership-oriented module tree.
/// Compatibility re-export of [`model::context`].
pub mod context {
    pub use super::model::context::*;
}
/// Compatibility re-export of [`model::events`].
pub mod events {
    pub use super::model::events::*;
}
/// Compatibility re-export of [`execution::handle`].
pub mod handle {
    pub use super::execution::handle::*;
}
/// Compatibility re-export of [`model::branch`].
pub mod leg {
    pub use super::model::branch::*;
}
/// Compatibility re-export of [`model::lifecycle`].
pub mod lifecycle {
    pub use super::model::lifecycle::*;
}
/// Compatibility re-export of [`execution::manager`].
pub mod manager {
    pub use super::execution::manager::*;
}
/// Compatibility re-export of [`model::redirect`].
pub mod redirect {
    pub use super::model::redirect::*;
}
/// Compatibility re-export of [`execution::runtime`].
pub mod runtime {
    pub use super::execution::runtime::*;
}
/// Compatibility re-export of [`model::state`].
pub mod state {
    pub use super::model::state::*;
}
/// Compatibility re-export of [`execution::thread`].
pub mod thread {
    pub use super::execution::thread::*;
}
/// Compatibility re-export of [`execution::timer`].
pub mod timers {
    pub use super::execution::timer::*;
}
/// Compatibility re-export of [`model::transfer`].
pub mod transfer {
    pub use super::model::transfer::*;
}
