// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Transaction-timer records owned by one signaling engine.

use crate::call::execution::deadline::DeadlineId;
use crate::sip::transaction::client::Timer as ClientTimer;
use crate::sip::transaction::manager::Token;
use crate::sip::transaction::server::Timer as ServerTimer;
use crate::sip::transport::destination::Destination;

pub(super) struct TimerEntry {
    pub(super) id: DeadlineId,
    pub(super) token: Token,
    pub(super) timer: TransactionTimer,
}

pub(super) enum TransactionTimer {
    Client(ClientTimer),
    Server {
        timer: ServerTimer,
        destination: Destination,
    },
}

pub(super) const fn client_timer_kind(timer: ClientTimer) -> u16 {
    match timer {
        ClientTimer::Retransmit => 1,
        ClientTimer::RequestTimeout => 2,
        ClientTimer::Linger => 3,
    }
}

pub(super) const fn server_timer_kind(timer: ServerTimer) -> u16 {
    match timer {
        ServerTimer::Trying => 101,
        ServerTimer::Retransmit => 102,
        ServerTimer::FinalResponseLifetime => 103,
        ServerTimer::Termination => 104,
    }
}
