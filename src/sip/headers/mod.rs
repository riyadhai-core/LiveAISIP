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

//! Typed SIP header implementations.
//!
//! Header modules own field-specific representation, validation, parsing, and
//! canonical serialization. Shared private grammar used by multiple headers is
//! kept internal to this module tree.

/// SIP `Allow` header.
pub mod allow;

/// SIP `Authentication-Info` header.
pub mod authentication_info;

/// SIP `Authorization` header.
pub mod authorization;

/// SIP `Call-ID` header.
pub mod call_id;

/// SIP `Contact` header.
pub mod contact;

/// SIP `Content-Encoding` header.
pub mod content_encoding;

/// SIP `Content-Length` header.
pub mod content_length;

/// SIP `Content-Type` header.
pub mod content_type;

/// SIP `CSeq` header.
pub mod cseq;

/// SIP `From` header.
pub mod from;

/// SIP `Max-Forwards` header.
pub mod max_forwards;

/// SIP `Min-SE` header.
pub mod min_se;

// Shared crate-private product/comment grammar used by `Server` and
// `User-Agent`. It is intentionally not part of the public module API.
mod product_comment;

/// SIP `Proxy-Authenticate` header.
pub mod proxy_authenticate;

/// SIP `Proxy-Authorization` header.
pub mod proxy_authorization;

/// SIP `Reason` header.
pub mod reason;

/// SIP `Record-Route` header.
pub mod record_route;

/// SIP `Require` header.
pub mod require;

/// SIP `Retry-After` header.
pub mod retry_after;

/// SIP `Route` header.
pub mod route;

/// SIP `RSeq` header.
pub mod rseq;

/// SIP `Server` header.
pub mod server;

/// SIP `Session-Expires` header.
pub mod session_expires;

/// SIP `Supported` header.
pub mod supported;

/// SIP `To` header.
pub mod to;

/// SIP `Unsupported` header.
pub mod unsupported;

/// SIP `User-Agent` header.
pub mod user_agent;

/// SIP `Via` header.
pub mod via;

/// SIP `WWW-Authenticate` header.
pub mod www_authenticate;
