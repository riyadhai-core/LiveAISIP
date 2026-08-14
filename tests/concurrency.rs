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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use liveaisip::runtime::admission::AdmissionController;
use liveaisip::sip::headers::retry_after::RetryAfter;

#[test]
fn concurrent_admission_never_exceeds_capacity() {
    const WORKERS: usize = 32;
    const CAPACITY: usize = 8;
    let admission = Arc::new(
        AdmissionController::new(CAPACITY, RetryAfter::new(3))
            .unwrap_or_else(|_| panic!("admission")),
    );
    let start = Arc::new(Barrier::new(WORKERS + 1));
    let admitted = Arc::new(AtomicUsize::new(0));
    let hold = Arc::new(Barrier::new(WORKERS + 1));
    let mut threads = Vec::new();

    for _ in 0..WORKERS {
        let admission = Arc::clone(&admission);
        let start = Arc::clone(&start);
        let admitted = Arc::clone(&admitted);
        let hold = Arc::clone(&hold);
        threads.push(std::thread::spawn(move || {
            start.wait();
            let lease = admission.try_admit().ok();
            if lease.is_some() {
                admitted.fetch_add(1, Ordering::AcqRel);
            }
            hold.wait();
            drop(lease);
        }));
    }

    start.wait();
    hold.wait();
    assert_eq!(admitted.load(Ordering::Acquire), CAPACITY);
    for thread in threads {
        thread.join().unwrap_or_else(|_| panic!("worker"));
    }
    assert_eq!(admission.active(), 0);
}
