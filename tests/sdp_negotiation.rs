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

use liveaisip::media::audio::{AI_SAMPLE_RATE_HZ, AI_SAMPLES_PER_FRAME};
use liveaisip::sip::sdp::parser::parse;
use liveaisip::sip::sdp::{Direction, RtpMediaOffer};

#[test]
fn network_ptime_does_not_change_ai_frame_contract() {
    let document = parse(
        b"v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0\r\n\
m=audio 4000 RTP/AVP 0\r\na=ptime:30\r\na=maxptime:60\r\n",
    )
    .unwrap_or_else(|_| panic!("sdp"));
    let offer = RtpMediaOffer::from_section(&document.media_sections()[0], Direction::SendRecv)
        .unwrap_or_else(|_| panic!("offer"));
    assert_eq!(offer.packetization().packet_time_ms(), 30);
    assert_eq!(offer.packetization().maximum_packet_time_ms(), Some(60));
    assert_eq!(AI_SAMPLE_RATE_HZ, 24_000);
    assert_eq!(AI_SAMPLES_PER_FRAME, 240);
}

#[test]
fn packet_time_cannot_exceed_remote_maximum() {
    let document = parse(
        b"v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0\r\n\
m=audio 4000 RTP/AVP 0\r\na=ptime:30\r\na=maxptime:20\r\n",
    )
    .unwrap_or_else(|_| panic!("sdp"));
    assert!(
        RtpMediaOffer::from_section(&document.media_sections()[0], Direction::SendRecv).is_err()
    );
}
