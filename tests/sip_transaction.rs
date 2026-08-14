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

use std::sync::Arc;

use liveaisip::call::{CallAction, CallCommand, CallEvent, CallLifecycle, DialogBranchId};
use liveaisip::sip::auth::{AuthChallenge, AuthContext, AuthScope, DigestCredentials};
use liveaisip::sip::parser::message::parse;
use liveaisip::sip::transaction::client::{Action, ClientTransaction};
use liveaisip::sip::transaction::timer::TimerConfig;
use liveaisip::sip::types::method::Method;
use liveaisip::sip::validation::{request, response};

fn invite() -> request::ValidatedRequest {
    let bytes = b"INVITE sip:x@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP host;branch=z9hG4bK-one\r\n\
From: <sip:a@example.com>;tag=a\r\nTo: <sip:x@example.com>\r\n\
Call-ID: one@example.com\r\nCSeq: 1 INVITE\r\n\
Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n";
    let raw = parse(Arc::from(&bytes[..])).unwrap_or_else(|_| panic!("parse request"));
    request::validate(raw).unwrap_or_else(|_| panic!("validate request"))
}

fn invite_response(status: u16, reason: &str) -> response::ValidatedResponse {
    let bytes = format!(
        "SIP/2.0 {status} {reason}\r\n\
Via: SIP/2.0/UDP host;branch=z9hG4bK-one\r\n\
From: <sip:a@example.com>;tag=a\r\nTo: <sip:x@example.com>;tag=b\r\n\
Call-ID: one@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
    );
    let raw = parse(Arc::from(bytes.into_bytes())).unwrap_or_else(|_| panic!("parse response"));
    response::validate(raw).unwrap_or_else(|_| panic!("validate response"))
}

fn challenge(nonce: &str) -> AuthChallenge {
    let value =
        format!("Digest realm=\"example\", nonce=\"{nonce}\", algorithm=SHA-256, qop=\"auth\"");
    AuthChallenge::from_bytes(value.as_bytes()).unwrap_or_else(|_| panic!("challenge"))
}

fn transaction() -> ClientTransaction {
    let mut transaction = ClientTransaction::new(invite(), false, TimerConfig::default())
        .unwrap_or_else(|_| panic!("transaction"));
    transaction.start().unwrap_or_else(|_| panic!("start"));
    transaction
}

#[test]
fn invite_401_ack_retry() {
    let mut transaction = transaction();
    let actions = transaction
        .on_response(&invite_response(401, "Unauthorized"))
        .unwrap_or_else(|_| panic!("response"));
    assert!(matches!(actions.first(), Some(Action::SendAck(_))));

    let mut auth = AuthContext::new();
    auth.install(AuthScope::Server, &[challenge("server-nonce")])
        .unwrap_or_else(|_| panic!("install"));
    let credentials =
        DigestCredentials::new("user", "password").unwrap_or_else(|_| panic!("credentials"));
    auth.authorize(
        AuthScope::Server,
        &credentials,
        &Method::Invite,
        "sip:x@example.com",
        b"",
        "client-nonce",
    )
    .unwrap_or_else(|_| panic!("authorization"));
    assert_eq!(auth.nonce_count(AuthScope::Server), 1);
    assert_eq!(auth.nonce_count(AuthScope::Proxy), 0);
}

#[test]
fn invite_407_ack_retry() {
    let mut transaction = transaction();
    let actions = transaction
        .on_response(&invite_response(407, "Proxy Authentication Required"))
        .unwrap_or_else(|_| panic!("response"));
    assert!(matches!(actions.first(), Some(Action::SendAck(_))));

    let mut auth = AuthContext::new();
    auth.install(AuthScope::Proxy, &[challenge("proxy-nonce")])
        .unwrap_or_else(|_| panic!("install"));
    let credentials =
        DigestCredentials::new("user", "password").unwrap_or_else(|_| panic!("credentials"));
    auth.authorize(
        AuthScope::Proxy,
        &credentials,
        &Method::Invite,
        "sip:x@example.com",
        b"",
        "client-nonce",
    )
    .unwrap_or_else(|_| panic!("authorization"));
    assert_eq!(auth.nonce_count(AuthScope::Proxy), 1);
    assert_eq!(auth.nonce_count(AuthScope::Server), 0);
}

#[test]
fn invite_486_ack_retransmission() {
    let mut transaction = transaction();
    let response = invite_response(486, "Busy Here");
    let first = transaction
        .on_response(&response)
        .unwrap_or_else(|_| panic!("first response"));
    let repeated = transaction
        .on_response(&response)
        .unwrap_or_else(|_| panic!("repeated response"));
    let Some(Action::SendAck(first_ack)) = first.first() else {
        panic!("first ACK")
    };
    let [Action::SendAck(repeated_ack)] = repeated.as_slice() else {
        panic!("only retransmit ACK")
    };
    assert!(Arc::ptr_eq(first_ack, repeated_ack));
}

#[test]
fn invite_200_retransmission_ack() {
    let mut transaction = transaction();
    let response = invite_response(200, "OK");
    let mut call = CallLifecycle::new().unwrap_or_else(|_| panic!("call"));
    call.handle(CallEvent::Command(CallCommand::Start))
        .unwrap_or_else(|_| panic!("start call"));
    let branch = DialogBranchId::new("remote-tag").unwrap_or_else(|_| panic!("branch"));
    for _ in 0..2 {
        let actions = transaction
            .on_response(&response)
            .unwrap_or_else(|_| panic!("response"));
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::DeliverResponse))
        );
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, Action::SendAck(_)))
        );
        let dialog_actions = call
            .handle(CallEvent::InviteAccepted {
                branch: branch.clone(),
            })
            .unwrap_or_else(|_| panic!("dialog response"));
        assert!(dialog_actions.contains(&CallAction::SendAck {
            branch: branch.clone(),
        }));
    }
}
