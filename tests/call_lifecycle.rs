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

use liveaisip::call::{
    CallAction, CallCommand, CallEndReason, CallEvent, CallLifecycle, DialogBranchId,
    TransferTarget,
};

fn branch(value: &str) -> DialogBranchId {
    DialogBranchId::new(value).unwrap_or_else(|_| panic!("branch"))
}

fn started() -> CallLifecycle {
    let mut call = CallLifecycle::new().unwrap_or_else(|_| panic!("call"));
    assert!(call.handle(CallEvent::Command(CallCommand::Start)).is_ok());
    call
}

#[test]
fn invite_cancel_487() {
    let mut call = started();
    assert_eq!(
        call.handle(CallEvent::Command(CallCommand::Hangup)),
        Ok(vec![CallAction::SendCancel])
    );
    assert_eq!(
        call.handle(CallEvent::InviteRejected {
            branch: branch("cancelled"),
            status: 487,
        }),
        Ok(vec![CallAction::Ended(CallEndReason::Canceled)])
    );
}

#[test]
fn cancel_200_race() {
    let mut call = started();
    call.handle(CallEvent::Command(CallCommand::Hangup))
        .unwrap_or_else(|_| panic!("hangup"));
    let winner = branch("winner");
    assert_eq!(
        call.handle(CallEvent::InviteAccepted {
            branch: winner.clone(),
        }),
        Ok(vec![
            CallAction::SendAck {
                branch: winner.clone(),
            },
            CallAction::SendBye { branch: winner },
        ])
    );
}

#[test]
fn fork_two_early_dialogs() {
    let mut call = started();
    call.handle(CallEvent::Provisional {
        branch: branch("east"),
        has_sdp: true,
    })
    .unwrap_or_else(|_| panic!("east"));
    call.handle(CallEvent::Provisional {
        branch: branch("west"),
        has_sdp: false,
    })
    .unwrap_or_else(|_| panic!("west"));
    assert_eq!(call.forks().len(), 2);
}

#[test]
fn fork_multiple_200() {
    let mut call = started();
    let first = branch("first");
    let second = branch("second");
    let first_actions = call
        .handle(CallEvent::InviteAccepted {
            branch: first.clone(),
        })
        .unwrap_or_else(|_| panic!("first"));
    assert!(first_actions.contains(&CallAction::SendAck { branch: first }));
    assert_eq!(
        call.handle(CallEvent::InviteAccepted {
            branch: second.clone(),
        }),
        Ok(vec![
            CallAction::SendAck {
                branch: second.clone(),
            },
            CallAction::SendBye { branch: second },
        ])
    );
}

#[test]
fn blind_transfer_requires_validated_sip_target() {
    assert!(TransferTarget::parse("https://example.com").is_err());
    let target =
        TransferTarget::parse("sip:human@example.com").unwrap_or_else(|_| panic!("target"));
    let mut call = started();
    call.handle(CallEvent::InviteAccepted {
        branch: branch("selected"),
    })
    .unwrap_or_else(|_| panic!("accepted"));
    assert_eq!(
        call.handle(CallEvent::Command(CallCommand::BlindTransfer {
            target: target.clone(),
        })),
        Ok(vec![CallAction::SendRefer { target }])
    );
}
