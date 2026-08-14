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

//! Bounded RTP/RTCP socket allocation and datagram transport.

pub mod allocator;
pub mod socket;
pub mod symmetric;
pub mod udp;

pub use allocator::{PortAllocationError, PortAllocator, PortLease, PortPair, PortPool};
pub use socket::{
    Component, ConfigureOperation, DEFAULT_MAX_MEDIA_DATAGRAM_BYTES, DatagramBuffer,
    InboundDatagram, MAX_MEDIA_DATAGRAM_BYTES, MediaPacketScratch, MediaSocketPair, SocketConfig,
    SocketError,
};
pub use symmetric::{
    DEFAULT_INITIAL_LATCH_PACKETS, DEFAULT_PORT_REBIND_PACKETS, SourceRejection, SymmetricConfig,
    SymmetricEndpoints, SymmetricError, SymmetricObservation,
};
pub use udp::{DatagramClassification, DatagramClassifier, DatagramClassifierStats};
