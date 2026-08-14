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

use liveaisip::rtp::source::{RemoteSourceTracker, SourceObservation, SourcePolicy};

#[test]
fn rtp_ssrc_restart() {
    let policy = SourcePolicy::new(2, true).unwrap_or_else(|_| panic!("policy"));
    let mut sources = RemoteSourceTracker::new(Some(100), policy);
    assert_eq!(sources.observe(100, 9), SourceObservation::Current);
    assert!(matches!(
        sources.observe(200, 50),
        SourceObservation::Probation { .. }
    ));
    let switched = sources.observe(200, 51);
    assert_eq!(switched, SourceObservation::Switched);
    assert!(switched.requires_reset());
    assert_eq!(sources.active_ssrc(), Some(200));
}
