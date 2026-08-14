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

//! Core SIP protocol types.
//!
//! This module contains the strongly typed protocol primitives used by SIP
//! parsing, validation, transactions, dialogs, serialization, and message
//! construction.

/// SIP address representation.
pub mod address;

/// SIP header representation.
pub mod header;

/// Complete SIP message representation.
pub mod message;

/// SIP request methods.
pub mod method;

/// SIP request representation.
pub mod request;

/// SIP response representation.
pub mod response;

/// SIP response status codes.
pub mod status;

/// SIP URI representation.
pub mod uri;

/// SIP protocol version.
pub mod version;
