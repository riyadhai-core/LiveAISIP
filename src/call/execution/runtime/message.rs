// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Bounded messages entering one call-owning thread.

use crate::call::model::events::CallEvent;
use crate::rtp::transport::Component;

/// Direction of one native/Python audio readiness notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioDirection {
    /// Audio produced by native receive processing for Python.
    Receive,
    /// Audio produced by Python for native packetization.
    Transmit,
}

/// Bounded mailbox message entering a call thread.
#[derive(Debug)]
#[non_exhaustive]
pub enum CallMessage {
    /// Serialized SIP, control, timeout, or call-lifecycle event.
    Event(CallEvent),
    /// RTP or RTCP socket readiness notification.
    NetworkReady(Component),
    /// Call-owned SIP signaling socket is readable.
    SignalingReady,
    /// Generation-fenced native audio queue notification.
    AudioReady {
        /// Media generation attached by the producer.
        generation: u64,
        /// Receive or transmit queue direction.
        direction: AudioDirection,
    },
    /// Idempotent runtime shutdown request.
    Shutdown,
    #[cfg(test)]
    /// Test-only unexpected panic injection for containment verification.
    PanicForContainmentTest,
}
