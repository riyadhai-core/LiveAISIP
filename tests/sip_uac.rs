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

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use liveaisip::call::execution::manager::CallManager;
use liveaisip::call::model::context::CallContext;
use liveaisip::call::{
    CallAction, CallCommand, CallEvent, CallExitKind, CallRuntime, CallRuntimeConfig, UdpSignaling,
};
use liveaisip::runtime::admission::AdmissionLeaseGroup;
use liveaisip::sip::parser::message;
use liveaisip::sip::transport::udp::UdpConfig;
use liveaisip::sip::transport::udp_driver::UdpDriverConfig;
use liveaisip::sip::validation;

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn header_value<'a>(message: &'a str, name: &str) -> &'a str {
    message
        .split("\r\n")
        .find_map(|line| line.strip_prefix(name))
        .map_or_else(|| panic!("missing header"), str::trim)
}

fn receive_message(socket: &UdpSocket, buffer: &mut [u8]) -> (String, SocketAddr) {
    let (length, source) = socket
        .recv_from(buffer)
        .unwrap_or_else(|_| panic!("receive SIP message"));
    let text =
        std::str::from_utf8(&buffer[..length]).unwrap_or_else(|_| panic!("SIP message UTF-8"));
    (text.to_owned(), source)
}

fn response_for(request: &str, status: u16, reason: &str, to_tag: Option<&str>) -> String {
    let to = match to_tag {
        Some(tag) if !header_value(request, "To:").contains(";tag=") => {
            format!("{};tag={tag}", header_value(request, "To:"))
        }
        _ => header_value(request, "To:").to_owned(),
    };
    format!(
        "SIP/2.0 {status} {reason}\r\nVia: {}\r\nFrom: {}\r\nTo: {to}\r\n\
         Call-ID: {}\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n",
        header_value(request, "Via:"),
        header_value(request, "From:"),
        header_value(request, "Call-ID:"),
        header_value(request, "CSeq:")
    )
}

#[test]
fn dedicated_call_thread_completes_real_udp_invite_ack_and_bye() {
    let peer = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("peer bind"));
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap_or_else(|_| panic!("peer timeout"));
    let remote = peer.local_addr().unwrap_or_else(|_| panic!("peer address"));
    let mut signaling = UdpSignaling::bind(
        localhost(0),
        remote,
        UdpDriverConfig::default(),
        UdpConfig::default(),
    )
    .unwrap_or_else(|_| panic!("signaling"));
    let local = signaling.local_addr();
    let request = format!(
        "INVITE sip:service@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP {local};branch=z9hG4bK-thread-e2e\r\n\
         From: <sip:runtime@127.0.0.1>;tag=local-tag\r\n\
         To: <sip:service@127.0.0.1>\r\n\
         Call-ID: thread-e2e@127.0.0.1\r\n\
         CSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
    );
    let raw =
        message::parse(Arc::from(request.into_bytes())).unwrap_or_else(|_| panic!("parse INVITE"));
    signaling
        .install_initial_invite(
            validation::request::validate(raw).unwrap_or_else(|_| panic!("validate INVITE")),
        )
        .unwrap_or_else(|_| panic!("install INVITE"));
    let context = CallContext::new(Duration::ZERO, 32).unwrap_or_else(|_| panic!("call context"));
    let runtime = CallRuntime::new(
        context,
        AdmissionLeaseGroup::new(),
        CallRuntimeConfig::default(),
    )
    .and_then(|runtime| runtime.with_udp_signaling(signaling))
    .unwrap_or_else(|_| panic!("call runtime"));
    let mut manager = CallManager::new(1).unwrap_or_else(|_| panic!("call manager"));
    let token = manager
        .spawn(42, runtime)
        .unwrap_or_else(|_| panic!("spawn call"));
    manager
        .submit(token, CallEvent::Command(CallCommand::Start))
        .unwrap_or_else(|_| panic!("start call"));

    let mut buffer = [0_u8; 4_096];
    let (invite, call_endpoint) = receive_message(&peer, &mut buffer);
    assert!(invite.starts_with("INVITE "));
    peer.send_to(
        response_for(&invite, 180, "Ringing", Some("remote-tag")).as_bytes(),
        call_endpoint,
    )
    .unwrap_or_else(|_| panic!("send 180"));
    let accepted = response_for(&invite, 200, "OK", Some("remote-tag")).replace(
        "Content-Length: 0",
        "Contact: <sip:service@contact.example:5090>\r\n\
         Record-Route: <sip:far-proxy.example;lr>, <sip:near-proxy.example;lr>\r\n\
         Content-Length: 0",
    );
    peer.send_to(accepted.as_bytes(), call_endpoint)
        .unwrap_or_else(|_| panic!("send 200"));

    let (ack, _) = receive_message(&peer, &mut buffer);
    assert!(ack.starts_with("ACK sip:service@contact.example:5090 SIP/2.0"));
    assert_eq!(header_value(&ack, "CSeq:"), "1 ACK");
    assert_eq!(
        header_value(&ack, "Route:"),
        "<sip:near-proxy.example;lr>, <sip:far-proxy.example;lr>"
    );
    let mut established = false;
    for _ in 0..20 {
        if let Some(actions) = manager
            .receive_actions(token, Duration::from_millis(100))
            .unwrap_or_else(|_| panic!("receive call actions"))
            && actions
                .iter()
                .any(|action| matches!(action, CallAction::SelectBranch { .. }))
        {
            established = true;
            break;
        }
    }
    assert!(established);
    manager
        .submit(token, CallEvent::Command(CallCommand::Hangup))
        .unwrap_or_else(|_| panic!("hang up"));
    let (bye, _) = receive_message(&peer, &mut buffer);
    assert!(bye.starts_with("BYE sip:service@contact.example:5090 SIP/2.0"));
    assert_eq!(header_value(&bye, "CSeq:"), "2 BYE");
    assert_eq!(
        header_value(&bye, "Route:"),
        "<sip:near-proxy.example;lr>, <sip:far-proxy.example;lr>"
    );
    peer.send_to(
        response_for(&bye, 200, "OK", None).as_bytes(),
        call_endpoint,
    )
    .unwrap_or_else(|_| panic!("send BYE 200"));

    for _ in 0..20 {
        if manager
            .handle(token)
            .unwrap_or_else(|_| panic!("call handle"))
            .status()
            .phase
            .is_terminal()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let exit = manager
        .remove(token)
        .unwrap_or_else(|_| panic!("join call"));
    assert_eq!(exit.kind(), CallExitKind::Completed);
    assert!(exit.runtime().processed_messages >= 2);
}
