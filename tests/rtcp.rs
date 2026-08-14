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

use liveaisip::rtp::rtcp_scheduler::{RtcpScheduleConfig, RtcpScheduler, ScheduledReport};
use liveaisip::rtp::stats::{CompactNtp, RttEstimator, RttUpdate};

#[test]
fn rtcp_sr_rr_rtt() {
    let mut scheduler = RtcpScheduler::new(
        RtcpScheduleConfig::default(),
        7,
        b"runtime@example.invalid",
        Duration::ZERO,
    )
    .unwrap_or_else(|_| panic!("scheduler"));
    assert!(matches!(
        scheduler.poll(Duration::from_secs(5), 0, 0, None),
        Ok(Some(ScheduledReport::Receiver { .. }))
    ));
    scheduler.note_rtp_sent(160);
    assert!(matches!(
        scheduler.poll(Duration::from_secs(10), 0x1234, 160, None),
        Ok(Some(ScheduledReport::Sender { .. }))
    ));

    let sent = CompactNtp::from_duration(Duration::from_secs(10));
    let arrival = CompactNtp::from_duration(Duration::from_millis(10_250));
    let receiver_delay = CompactNtp::from_duration(Duration::from_millis(100)).as_raw();
    let mut rtt = RttEstimator::new();
    assert!(matches!(
        rtt.observe(arrival, sent.as_raw(), receiver_delay),
        RttUpdate::Sampled { .. }
    ));
    assert_eq!(rtt.samples(), 1);
}
