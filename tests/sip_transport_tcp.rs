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

use std::time::Duration;

use liveaisip::sip::transport::stream::{StreamLimits, StreamPolicyError, StreamTracker};

#[test]
fn hostile_stream_cannot_exceed_buffer_pipeline_or_deadlines() {
    let limits = StreamLimits {
        maximum_buffer_bytes: 32,
        maximum_pipelined_messages: 1,
        idle_timeout: Duration::from_secs(10),
        handshake_timeout: Duration::from_secs(2),
    };
    let mut stream =
        StreamTracker::new(limits, Duration::ZERO).unwrap_or_else(|_| panic!("stream"));
    assert_eq!(
        stream.complete_handshake(Duration::from_secs(2)),
        Err(StreamPolicyError::HandshakeTimedOut)
    );

    let mut stream =
        StreamTracker::new(limits, Duration::ZERO).unwrap_or_else(|_| panic!("stream"));
    stream
        .complete_handshake(Duration::from_secs(1))
        .unwrap_or_else(|_| panic!("handshake"));
    stream
        .admit_read(32, Duration::from_secs(2))
        .unwrap_or_else(|_| panic!("read"));
    assert_eq!(
        stream.admit_read(1, Duration::from_secs(2)),
        Err(StreamPolicyError::BufferLimitExceeded)
    );
    stream
        .frame_completed(16)
        .unwrap_or_else(|_| panic!("frame"));
    assert_eq!(
        stream.frame_completed(16),
        Err(StreamPolicyError::PipelineLimitExceeded)
    );
    assert_eq!(stream.idle_expired(Duration::from_secs(12)), Ok(true));
}
