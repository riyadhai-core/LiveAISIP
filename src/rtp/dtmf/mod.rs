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

//! RFC 4733 telephone-event sending, receiving, and payload representation.

pub mod event;
pub mod receiver;
pub mod sender;

pub use event::{DtmfDigit, TelephoneEvent, TelephoneEventCode, TelephoneEventError};
pub use receiver::{DtmfReceiveError, DtmfReceiveUpdate, DtmfReceiver, DtmfReceiverConfig};
pub use sender::{DtmfSender, DtmfSenderConfig, DtmfSenderError, DtmfTransmitPacket};
