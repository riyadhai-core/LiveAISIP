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

//! Bounded SDP representation, parsing, serialization, and media negotiation.

pub mod codec;
pub mod direction;
pub mod media;
pub mod negotiation;
pub mod parser;
pub mod serializer;
pub mod types;

pub use codec::{Codec, CodecError, CodecName, PayloadType};
pub use direction::{Direction, DirectionParseError};
pub use media::{MediaError, MediaFormat, MediaLine, MediaType, TransportProtocol};
pub use negotiation::{NegotiatedMedia, NegotiationError, RtpMediaOffer};
pub use parser::{MediaSection, SdpDocument, SdpParseError, parse};
pub use serializer::{SdpSerializeError, serialize, serialized_len};
pub use types::{SdpBuildError, SdpBuilder, SdpField, SdpLine, SdpLineError, SdpMediaBuilder};
