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

//! Bounded RTP reception statistics for RTCP reporting and observability.

pub mod jitter;
pub mod loss;
pub mod rtt;
pub mod sequence;

pub use jitter::{JitterEstimator, JitterUpdate};
pub use loss::LossSnapshot;
pub use rtt::{CompactNtp, RttError, RttEstimator, RttUpdate};
pub use sequence::{SequenceDisposition, SequenceSnapshot, SequenceTracker};
