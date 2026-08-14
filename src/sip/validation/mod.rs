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

//! SIP semantic validation.
//!
//! Validation operates after lossless structural parsing and before
//! transaction, dialog, and method-specific processing.
//!
//! The validation layer is intentionally separated from wire parsing so
//! structurally safe extension data can remain preserved even when individual
//! SIP constructs require later typed or policy-specific interpretation.

pub mod headers;
pub mod message;
pub mod request;
pub mod response;
pub mod start_line;
