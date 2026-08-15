# LiveAISIP architecture

LiveAISIP is a modular Rust telephony runtime. The core ownership invariant is:

```text
one call = one dedicated OS thread = one exclusive CallRuntime
```

The call thread owns every mutable SIP transaction, dialog, deadline, RTP/RTCP
session, media generation, queue policy, and shutdown transition for that call.
Device callbacks and future Python code may exchange bounded messages or fixed
audio frames; they never mutate call state directly.

## Module ownership

```text
util / net
      ↓
sip      rtp      media
  \       |       /
          call
            ↓
         runtime
            ↓
           ffi
            ↓
         Python
```

- `sip`: protocol parsing, validation, transactions, dialogs, and transport.
- `rtp`: RTP, RTCP, DTMF, source tracking, transport, and security primitives.
- `media`: decoded audio frames, formats, codecs, playout, processing, devices,
  and fixed-capacity frame queues.
- `call`: call-domain model plus call-owned execution, signaling, and media.
- `runtime`: process-wide admission, worker health, control, and shutdown only.
- `ffi`: the future stable native boundary. Protocol modules must not import it.

The pre-reorganization compatibility paths were removed during the `0.1.0`
alpha cycle. New code must use the ownership-oriented module paths directly;
the project will not carry two apparent public architectures into `1.0`.

## Process containment

A dedicated thread contains ordinary call failures, not process crashes. A
production deployment uses multiple bounded worker processes behind the Router
or supervisor. Workers advertise readiness, accept a configured number of
calls, drain during deployment, and restart after failure. Calls are not
migrated between workers; a worker crash terminates only that worker's calls.

## Capacity and readiness

Admission is constrained by the minimum safe capacity across call limits,
threads, file descriptors, RTP port pairs, memory, CPU, and scheduler latency.
Startup diagnostics must validate host limits and the actual kernel-selected
socket-buffer sizes before readiness becomes true. Capacity claims require
measured profiles for signaling, PCMU, playout, Sonora modes, and the Python/AI
bridge.

## Execution priorities

Correctness-critical internal effects execute inside the call owner. External
notifications are bounded observations and cannot prevent ACK, CANCEL, BYE,
media, refresh, rekey, or cleanup work. Existing calls and media deadlines take
priority over new admission, notifications, and diagnostics.

Idle call threads block on command wakeup, SIP/RTP/RTCP readiness, shutdown, and
the nearest monotonic deadline. Active media retains an absolute 10 ms clock;
signaling-only calls have no periodic polling wakeup.

## Configuration and versioning

Each call receives an immutable, versioned configuration snapshot. Hot reload
never partially mutates a live call. Future control, ABI, and SDK protocols use
explicit versions and capability negotiation so Router, workers, and Python
clients can roll independently.
