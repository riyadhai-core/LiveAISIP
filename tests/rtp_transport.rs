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

use liveaisip::rtp::security::{MediaSecurityError, MediaSecurityPolicy, PacketProtection};
use liveaisip::rtp::transport::socket::Component;
use liveaisip::rtp::transport::udp::{DatagramClassification, DatagramClassifier};

#[test]
fn classifier_runs_before_media_parser() {
    let mut classifier = DatagramClassifier::default();
    let mut stun = [0_u8; 20];
    stun[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    assert_eq!(
        classifier.classify(Component::Rtp, &stun),
        DatagramClassification::Stun
    );
    assert_eq!(classifier.stats().stun, 1);
}

#[test]
fn negotiated_srtp_never_falls_back_to_rtp() {
    assert_eq!(
        MediaSecurityPolicy::SecureRequired.admit(PacketProtection::Plain),
        Err(MediaSecurityError::SecurePacketRequired)
    );
    assert!(
        MediaSecurityPolicy::SecureRequired
            .admit(PacketProtection::AuthenticatedSecure)
            .is_ok()
    );
}
