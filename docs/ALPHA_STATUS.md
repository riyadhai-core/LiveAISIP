# LiveAISIP Runtime core status

This repository is the outbound-primary LiveAISIP Runtime SIP/RTP core. It is
still alpha software: the deterministic protocol and resource-policy layers
below are implemented, while the Rust playout engine, Sonora processing, SRTP
cryptography, Router control transport, and Python bindings remain separate
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

## Capability compliance matrix

`yes` means evidence exists in this repository. `partial` means a lower layer
exists but the named stage is incomplete. `no` is deliberate and must not be
described as production-ready elsewhere.

| Capability | Types/parser | State machine | Wire executor | Automated scenario | Real interop | Load/soak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Outbound UDP INVITE/ACK/local BYE | yes | yes | yes | yes | yes (FreeSWITCH 1.11.2, direct UDP) | no |
| 401/407 Digest retry | yes | yes | yes | yes | no | no |
| CANCEL and final-response races | yes | yes | yes | partial | no | no |
| Dialog Contact/Record-Route routing | yes | yes | yes | yes | no | no |
| Per-call command/SIP/RTP/RTCP reactor | yes | yes | yes | yes | no | no |
| In-dialog inbound requests | yes | partial | partial | partial | no | no |
| PRACK/100rel | yes | yes | no | simulated | no | no |
| Session timers | yes | yes | no | simulated | no | no |
| REFER/NOTIFY transfer | yes | yes | no | simulated | no | no |
| DNS NAPTR/SRV/address selection | yes | yes | no | policy only | no | no |
| SIP TCP/TLS | yes | partial | no | framing only | no | no |
| RTP receive | yes | yes | partial | yes | no | no |
| RTP transmit | yes | partial | no | partial | no | no |
| Live RTCP | yes | yes | no | deterministic | no | no |
| DTMF receive/transmit | yes | yes | no | deterministic | no | no |
| SRTP/SRTCP | policy only | partial | no | downgrade policy | no | no |
| Rust playout engine | partial | partial | no | no | no | no |
| Sonora APM | no | no | no | no | no | no |
| 24 kHz native/Python audio bridge | contract only | partial | no | no | no | no |
| Router control transport | no | no | no | no | no | no |
| Python/OpenAI adapter | no | no | no | no | no | no |

The deterministic implementations not yet connected to a live executor remain
valuable, but they satisfy only their corresponding columns. This matrix is
the release vocabulary: a capability is enterprise verified only when every
applicable column is `yes` and the evidence is reproducible.

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
- Reliable TCP/TLS socket workers and media SRTP/SRTCP integration. The SIP
  UDP socket boundary is implemented.
- Rust playout behavior validated against the local WebRTC NetEq reference and
  pinned Sonora resampling/APM integration.
- The exact 24 kHz mono PCM pointer/handle bridge and Protobuf control bridge.
- OpenAI Realtime and the LiveKit-style Python SDK surface.
- Remote-BYE interoperability, carrier interoperability, impairment, soak,
  fuzz, and load qualification required before production release.

## Recorded direct interoperability

The outbound signaling path has completed a direct UDP call against
FreeSWITCH 1.11.2 (`release-31326320293-3f13ad1b1d`) on its external SIP
profile. The observed call reached `ACTIVE`, negotiated PCMU, remained up for
the configured duration, and was cleared by a LiveAISIP-originated BYE.

This evidence covers direct initial INVITE, provisional/final response
handling, ACK, dialog duration, and local BYE only. It does not establish
remote-BYE handling, proxied routing, authenticated interoperability, live RTP,
carrier interoperability, load, or soak readiness.
