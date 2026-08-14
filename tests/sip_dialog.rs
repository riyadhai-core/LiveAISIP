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

use liveaisip::sip::dialog::{
    PrackDisposition, PrackTracker, Refresher, SessionTimer, SessionTimerAction,
};
use liveaisip::sip::sdp::{OfferAnswer, OfferAnswerError};
use liveaisip::sip::types::method::Method;

#[test]
fn prack_reliable_183() {
    let mut tracker = PrackTracker::new();
    assert!(matches!(
        tracker.observe(41, 9, Method::Invite),
        Ok(PrackDisposition::SendPrack {
            rseq: 41,
            cseq: 9,
            method: Method::Invite,
        })
    ));
    assert!(matches!(
        tracker.observe(41, 9, Method::Invite),
        Ok(PrackDisposition::ReplayPrack { .. })
    ));
}

#[test]
fn reinvite_glare_491() {
    let mut offers = OfferAnswer::new();
    let local = offers
        .begin_local_offer()
        .unwrap_or_else(|_| panic!("local offer"));
    assert_eq!(offers.begin_remote_offer(), Err(OfferAnswerError::Glare));
    offers
        .apply_remote_answer(local)
        .unwrap_or_else(|_| panic!("answer"));
    assert!(offers.begin_remote_offer().is_ok());
}

#[test]
fn session_timer_422_retry() {
    let timer = SessionTimer::new(90, 90, Refresher::Local, Duration::ZERO)
        .unwrap_or_else(|_| panic!("timer"));
    assert_eq!(timer.retry_after_422(180), Ok(180));
    assert_eq!(
        timer.action(Duration::from_secs(45)),
        SessionTimerAction::Refresh
    );
    assert_eq!(
        timer.action(Duration::from_secs(90)),
        SessionTimerAction::Expired
    );
}
