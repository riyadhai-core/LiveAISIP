# Media architecture

The first production media profile is PCMU/8000/mono with telephone-event.
Payload type does not determine clock rate; SDP negotiation does.

```text
UDP -> SRTP/SRTCP authenticate and replay-check -> RTP/RTCP parse
    -> source validation -> Rust playout -> PCM16/8 kHz/10 ms
    -> Sonora resampling/processing -> PCM16/24 kHz/mono/10 ms
    -> bounded native audio handle -> Python AI
```

Transmit reverses the path and protects serialized RTP/RTCP before UDP. Initial
SSRC, sequence, and timestamp values are cryptographically random.

## Rust playout

The Rust playout engine owns packet reordering, duplicate and late rejection,
adaptive delay, PLC, merge, acceleration/preemptive expansion, source reset,
and statistics. Development follows WebRTC NetEq behavior using the local
WebRTC source as a reference and differential trace oracle. It is called NetEq
equivalent only after broad differential and impairment qualification.

Parity levels are tracked explicitly:

1. PCMU reorder, bounded delay, and simple PLC.
2. Adaptive delay, late handling, and merge.
3. Acceleration, preemptive expansion, and robust statistics.
4. Differential qualification against WebRTC NetEq traces.

The local WebRTC reference audit identified the responsibility boundaries that
the Rust design must make explicit: `packet_buffer`, `packet_arrival_history`,
`delay_manager`, `delay_constraints`, `buffer_level_filter`, `decision_logic`,
`normal`, `expand`, `merge`, `accelerate`, `preemptive_expand`, `sync_buffer`,
and `statistics_calculator`. The C++ implementation is a behavioral and test
oracle, not a runtime dependency. Differential tooling may receive the checkout
location through configuration; production code never embeds a developer path.

## Sonora processing

Sonora is the selected pure-Rust APM direction and replaces the obsolete CXX
APM bridge. It owns resampling, AEC3, noise suppression, AGC2, and high-pass
processing. Telephony mode disables AEC3 by default. Acoustic device mode uses
the exact render reference plus measured capture/render delay.

Sonora will be pinned deliberately and qualified on x86_64 and ARM64. Upgrades
require waveform, acoustic, performance, unsafe/SIMD, license, and regression
review; they are not routine dependency updates.

## Resource ownership

Each committed media generation owns its sockets, RTP send/receive state, RTCP,
SRTP contexts, playout, Sonora mode, scratch buffers, and bounded RX/TX queues.
Replacement is transactional and stale generations cannot mutate current media.
Audio frames never travel over unbounded channels or protobuf.
