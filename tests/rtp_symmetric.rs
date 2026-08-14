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

use std::net::SocketAddr;

use liveaisip::rtp::transport::socket::Component;
use liveaisip::rtp::transport::symmetric::{
    SymmetricConfig, SymmetricEndpoints, SymmetricObservation,
};

#[test]
fn symmetric_rtp_rebind() {
    let advertised = SocketAddr::from(([192, 0, 2, 1], 4000));
    let control = SocketAddr::from(([192, 0, 2, 1], 4001));
    let learned = SocketAddr::from(([198, 51, 100, 7], 62000));
    let rebound = SocketAddr::from(([198, 51, 100, 7], 62002));
    let config = SymmetricConfig::new(2, 3, true).unwrap_or_else(|_| panic!("config"));
    let mut endpoints = SymmetricEndpoints::new(advertised, control, config)
        .unwrap_or_else(|_| panic!("endpoints"));

    assert!(matches!(
        endpoints.observe_validated_source(Component::Rtp, learned),
        Ok(SymmetricObservation::Candidate { .. })
    ));
    assert_eq!(
        endpoints.observe_validated_source(Component::Rtp, learned),
        Ok(SymmetricObservation::Latched)
    );
    for expected in [1_u8, 2] {
        assert_eq!(
            endpoints.observe_validated_source(Component::Rtp, rebound),
            Ok(SymmetricObservation::Candidate {
                observed: expected,
                required: 3,
            })
        );
    }
    assert_eq!(
        endpoints.observe_validated_source(Component::Rtp, rebound),
        Ok(SymmetricObservation::Rebound)
    );
    assert_eq!(endpoints.destination(Component::Rtp), rebound);
}

#[test]
fn cross_address_rebind_requires_signaling() {
    let advertised = SocketAddr::from(([192, 0, 2, 1], 4000));
    let control = SocketAddr::from(([192, 0, 2, 1], 4001));
    let learned = SocketAddr::from(([198, 51, 100, 7], 62000));
    let attacker = SocketAddr::from(([203, 0, 113, 9], 62002));
    let mut endpoints = SymmetricEndpoints::new(advertised, control, SymmetricConfig::default())
        .unwrap_or_else(|_| panic!("endpoints"));
    endpoints
        .observe_validated_source(Component::Rtp, learned)
        .unwrap_or_else(|_| panic!("probation"));
    endpoints
        .observe_validated_source(Component::Rtp, learned)
        .unwrap_or_else(|_| panic!("latch"));
    assert!(matches!(
        endpoints.observe_validated_source(Component::Rtp, attacker),
        Ok(SymmetricObservation::Rejected(_))
    ));
}
