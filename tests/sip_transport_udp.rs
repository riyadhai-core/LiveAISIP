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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use liveaisip::sip::transport::destination::{Destination, Protocol, TlsIdentity};
use liveaisip::sip::transport::resolver::{
    AddressRecord, ResolutionPlan, ResolutionRequest, ResolverRecords, ServiceRecord,
};
use liveaisip::sip::transport::selection::{MessageTransportSelector, SelectionError};

#[test]
fn large_invite_uses_tcp_fallback() {
    let remote = SocketAddr::from(([192, 0, 2, 1], 5060));
    let candidates = [
        Destination::udp(remote).unwrap_or_else(|_| panic!("udp")),
        Destination::tcp(remote).unwrap_or_else(|_| panic!("tcp")),
    ];
    let selection = MessageTransportSelector::select(1_301, &candidates, None, false)
        .unwrap_or_else(|_| panic!("selection"));
    assert_eq!(selection.destination().protocol(), Protocol::Tcp);
    assert_eq!(
        MessageTransportSelector::select(1_301, &candidates[..1], None, false),
        Err(SelectionError::NoReliableFallback)
    );
}

#[test]
fn resolver_failover_preserves_sips_identity() {
    let request = ResolutionRequest::new("voice.example", true, None, None, 4)
        .unwrap_or_else(|_| panic!("request"));
    let records = ResolverRecords {
        services: vec![
            ServiceRecord::new(Protocol::Tls, 10, 1, 5061, "edge-a.example")
                .unwrap_or_else(|_| panic!("service")),
            ServiceRecord::new(Protocol::Tls, 20, 1, 5061, "edge-b.example")
                .unwrap_or_else(|_| panic!("service")),
        ],
        addresses: vec![
            AddressRecord::new("edge-a.example", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
                .unwrap_or_else(|_| panic!("address")),
            AddressRecord::new("edge-b.example", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)))
                .unwrap_or_else(|_| panic!("address")),
        ],
    };
    let mut plan =
        ResolutionPlan::build(&request, &records).unwrap_or_else(|_| panic!("resolution"));
    for _ in 0..2 {
        let candidate = plan.next_candidate().unwrap_or_else(|| panic!("candidate"));
        assert_eq!(candidate.protocol(), Protocol::Tls);
        assert_eq!(
            candidate.tls_identity().and_then(TlsIdentity::as_dns),
            Some("voice.example")
        );
    }
}
