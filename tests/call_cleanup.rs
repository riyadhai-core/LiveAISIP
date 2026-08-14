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

use liveaisip::call::{RedirectDecision, RedirectError, RedirectHandler, RedirectPolicy};
use liveaisip::runtime::admission::{AdmissionController, RetrySuppressor};
use liveaisip::sip::headers::retry_after::RetryAfter;
use liveaisip::sip::parser::uri::parse_str;

#[test]
fn overload_503_retry_after_suppresses_retry() {
    let admission =
        AdmissionController::new(1, RetryAfter::new(4)).unwrap_or_else(|_| panic!("admission"));
    let lease = admission.try_admit().unwrap_or_else(|_| panic!("lease"));
    let rejection = admission
        .try_admit()
        .err()
        .unwrap_or_else(|| panic!("rejection"));
    assert_eq!(rejection.status(), 503);

    let mut suppressor = RetrySuppressor::new(4).unwrap_or_else(|_| panic!("suppressor"));
    suppressor
        .note_503(7, Duration::ZERO, rejection.retry_after())
        .unwrap_or_else(|_| panic!("cooldown"));
    assert!(!suppressor.may_attempt(7, Duration::from_secs(3)));
    assert!(suppressor.may_attempt(7, Duration::from_secs(4)));
    drop(lease);
}

#[test]
fn redirect_is_bounded_loop_safe_and_security_preserving() {
    let first = parse_str("sips:first@example.com").unwrap_or_else(|_| panic!("first"));
    let second = parse_str("sips:second@example.com").unwrap_or_else(|_| panic!("second"));
    let insecure = parse_str("sip:plain@example.com").unwrap_or_else(|_| panic!("insecure"));
    let mut redirect = RedirectHandler::new(RedirectPolicy::Follow { maximum_hops: 2 }, true)
        .unwrap_or_else(|_| panic!("redirect"));
    assert!(matches!(
        redirect.handle(&[first.clone(), second.clone()]),
        Ok(RedirectDecision::Follow(target)) if target == first
    ));
    assert!(matches!(
        redirect.handle(&[first, second]),
        Ok(RedirectDecision::Follow(_))
    ));
    assert_eq!(
        redirect.handle(&[insecure]),
        Err(RedirectError::SecurityDowngrade)
    );
}
