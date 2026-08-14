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

//! SIP dialog identity, state, routing, and lifecycle management.

#[path = "dialog.rs"]
pub mod core;
pub mod id;
pub mod manager;
pub mod route;
pub mod state;

pub use core::{Dialog, DialogError, DialogSequenceRole};
pub use id::{DialogId, DialogIdError, TagRole};
pub use manager::{DialogManager, DialogManagerError, DialogToken};
pub use route::{DialogRouteError, RouteSet, RoutingPlan};
pub use state::{DialogState, DialogStateError};
