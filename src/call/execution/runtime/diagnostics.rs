// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Privacy-safe counters owned and published by one call thread.

/// Privacy-safe counters owned and published by the call thread.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CallRuntimeDiagnostics {
    /// Last final SIP response status observed for the initial INVITE.
    pub last_sip_status: Option<u16>,
    /// A transaction-matched response reported a valued `received`/`rport`
    /// reflexive signaling endpoint.
    pub signaling_reflexive_endpoint_observed: bool,
    /// The configured Via/Contact endpoint differed from the latest reflexive
    /// endpoint reported by the remote SIP peer.
    pub signaling_advertised_endpoint_mismatch: bool,
    /// Messages processed on the owner thread.
    pub processed_messages: u64,
    /// Due protocol deadlines processed.
    pub processed_deadlines: u64,
    /// Ten-millisecond media ticks executed.
    pub media_ticks: u64,
    /// Media ticks skipped after a late wakeup.
    pub skipped_media_ticks: u64,
    /// Stale generation-fenced audio notifications rejected.
    pub stale_media_work: u64,
    /// RTP and RTCP datagrams removed from call-owned sockets.
    pub media_datagrams_received: u64,
    /// Oversized, malformed, unauthenticated, or stream-invalid media datagrams.
    pub media_datagrams_rejected: u64,
    /// Audio RTP packets admitted to the bounded playout ingress queue.
    pub rtp_audio_packets_queued: u64,
    /// Negotiated RFC 4733 packets handled outside the audio decoder path.
    pub dtmf_packets_received: u64,
    /// Valid compound RTCP datagrams admitted to session state.
    pub rtcp_packets_accepted: u64,
}
