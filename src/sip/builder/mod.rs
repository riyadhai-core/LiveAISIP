// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Safe bounded construction of outbound SIP messages.

/// Bounded outbound header assembly.
pub mod headers;

/// Outbound SIP request construction.
pub mod request;

/// SIP response construction for received in-dialog requests.
pub mod response;
