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

//! RTCP packet parsing, reporting, source description, and compound framing.

pub mod bye;
pub mod compound;
pub mod header;
pub mod receiver_report;
pub mod report_block;
pub mod sdes;
pub mod sender_report;

pub use bye::{Goodbye, GoodbyeError};
pub use compound::{CompoundPolicy, CompoundRtcp, CompoundRtcpError, OpaqueRtcpPacket, RtcpPacket};
pub use header::{MAX_RTCP_PACKET_BYTES, RtcpHeader, RtcpHeaderError, RtcpPacketType};
pub use receiver_report::{ReceiverReport, ReceiverReportError};
pub use report_block::{ReceptionReport, ReceptionReportError};
pub use sdes::{
    MAX_SDES_ITEMS, SdesChunk, SdesItem, SdesItemType, SourceDescription, SourceDescriptionError,
};
pub use sender_report::{RtcpSenderInfo, SenderReport, SenderReportError};
