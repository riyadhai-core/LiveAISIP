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
pub use signaling::{OutboundInviteConfig, OutboundInviteError, SignalingError, UdpSignaling};
