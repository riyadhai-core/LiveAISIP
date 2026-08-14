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

use liveaisip::rtp::dtmf::{
    DtmfDigit, DtmfReceiveUpdate, DtmfReceiver, DtmfReceiverConfig, TelephoneEvent,
    TelephoneEventCode,
};

#[test]
fn dtmf_end_retransmission() {
    let code = TelephoneEventCode::Digit(DtmfDigit::Five);
    let start = TelephoneEvent::new(code, false, 10, 80).unwrap_or_else(|_| panic!("start"));
    let end = TelephoneEvent::new(code, true, 10, 160).unwrap_or_else(|_| panic!("end"));
    let mut receiver = DtmfReceiver::new(DtmfReceiverConfig::strict());
    assert!(matches!(
        receiver.observe(1000, true, start),
        Ok(DtmfReceiveUpdate::Started { .. })
    ));
    assert!(matches!(
        receiver.observe(1000, false, end),
        Ok(DtmfReceiveUpdate::Ended { .. })
    ));
    assert_eq!(
        receiver.observe(1000, false, end),
        Ok(DtmfReceiveUpdate::Duplicate)
    );
    assert_eq!(receiver.completed_events(), 1);
}
