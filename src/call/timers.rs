// Copyright 2026 RiyadhAI LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Call-owned deadline identities kept separate from transaction timers.

/// Call-level timer class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CallTimer {
    /// Maximum answer wait.
    NoAnswer,
    /// SIP session refresh deadline.
    SessionRefresh,
    /// Valid inbound media inactivity deadline.
    MediaInactivity,
    /// Signaling connection/flow liveness deadline.
    TransportLiveness,
    /// Transfer completion deadline.
    Transfer,
}
