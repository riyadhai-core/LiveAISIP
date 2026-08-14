# LiveAISIP Runtime core status

This repository is the outbound-primary LiveAISIP Runtime SIP/RTP core. It is
still alpha software: the deterministic protocol and resource-policy layers
below are implemented, while native libwebrtc, SRTP cryptography, socket-loop
integration, Router control transport, and Python bindings remain separate
integration stages.

## Architecture invariant

```text
network input
  -> bounded parse and validation
  -> typed protocol event
  -> one call-owning actor
  -> deterministic state machines and bounded queues/timers
  -> explicit transport/media actions
  -> network output
```

Socket tasks, timer tasks, RTP tasks, and foreign-language callers must not
mutate transaction, dialog, call, or media state directly.

## Implemented core checklist

| Behavior | Status | Primary implementation |
| --- | --- | --- |
| Single signaling authority | Implemented | `src/call/context.rs` |
| Bounded early/confirmed forks | Implemented | `src/call/leg.rs` |
| CANCEL/487 and CANCEL/200 races | Implemented | `src/call/lifecycle.rs` |
| ACK every forked 2xx and BYE unwanted dialogs | Implemented | `src/call/lifecycle.rs` |
| Atomic target refresh plus media replacement | Implemented | `src/runtime/media.rs` |
| Serialized offer/answer and 491 glare result | Implemented | `src/sip/sdp/offer_answer.rs` |
| Network `ptime` independent of AI frames | Implemented | `src/sip/sdp/negotiation.rs`, `src/media/audio.rs` |
| Secure symmetric RTP probation/rebinding | Implemented | `src/rtp/transport/symmetric.rs` |
| RTP/RTCP/STUN/DTLS/TURN classification | Implemented | `src/rtp/transport/udp.rs` |
| Explicit SSRC lifecycle/reset signal | Implemented | `src/rtp/source.rs`, `src/rtp/session.rs` |
| Bounded realtime queues with diagnostics | Implemented | `src/rtp/queue.rs` |
| Session-owned RTCP SR/RR, SDES, BYE, LSR/DLSR | Implemented | `src/rtp/session.rs`, `src/rtp/rtcp_scheduler.rs` |
| Independent transport/dialog/media health | Implemented | `src/runtime/signaling.rs` |
| Transaction-owned automatic 100 Trying | Implemented | `src/sip/transaction/server.rs` |
| UDP size policy and TCP/TLS fallback | Implemented | `src/sip/transport/selection.rs` |
| Bounded NAPTR/SRV/address failover planning | Implemented | `src/sip/transport/resolver.rs` |
| Hostile TCP/TLS stream bounds/deadlines | Implemented | `src/sip/transport/stream.rs` |
| 503, Retry-After, admission, retry suppression | Implemented | `src/runtime/admission.rs` |
| Stateful isolated 401/407 Digest contexts | Implemented | `src/sip/auth/context.rs` |
| PRACK/RSeq correlation | Implemented | `src/sip/dialog/reliable.rs` |
| RFC 4028 refresh, expiry, and 422 retry | Implemented | `src/sip/dialog/session_timer.rs` |
| Stable SDK call-end reasons | Implemented | `src/call/state.rs` |
| Explicit bounded redirect policy | Implemented | `src/call/redirect.rs` |
| Blind/attended REFER-Replaces and NOTIFY state | Implemented | `src/call/transfer.rs` |
| No implicit SRTP-to-RTP downgrade | Implemented | `src/rtp/security.rs`, `src/runtime/media.rs` |
| Privacy-safe bounded call timeline | Implemented | `src/observability/diagnostics.rs` |
| Graceful admission fence/drain/force shutdown | Implemented | `src/runtime/shutdown.rs` |

## Executable behavior corpus

The integration suite contains named scenarios for:

- `invite_401_ack_retry`
- `invite_407_ack_retry`
- `invite_486_ack_retransmission`
- `invite_200_retransmission_ack`
- `invite_cancel_487`
- `cancel_200_race`
- `fork_two_early_dialogs`
- `fork_multiple_200`
- `prack_reliable_183`
- `reinvite_glare_491`
- `session_timer_422_retry`
- `symmetric_rtp_rebind`
- `rtp_ssrc_restart`
- `rtcp_sr_rr_rtt`
- `dtmf_end_retransmission`

Additional integration tests cover concurrent admission, overload cooldown,
redirect loops/downgrades, stream limits, transport fallback, packet
classification, and media security.

## Integration stages not represented as complete

- Actual asynchronous DNS queries and TTL cache feeding the bounded resolver
  policy.
- Rust socket workers connecting deterministic transport actions to UDP,
  TCP, TLS, SRTP, and SRTCP implementations.
- Native libwebrtc NetEq, resampler, and APM implementation behind the reserved
  media boundaries.
- The exact 24 kHz mono PCM pointer/handle bridge and Protobuf control bridge.
- OpenAI Realtime and the LiveKit-style Python SDK surface.
- Carrier and FreeSWITCH interoperability, impairment, soak, fuzz, and load
  qualification required before production release.
