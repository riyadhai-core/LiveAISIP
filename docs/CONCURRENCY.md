# Concurrency contract

One dedicated OS thread exclusively owns each `CallRuntime`. Shared handles may
submit bounded commands and inspect atomic snapshots; they cannot obtain mutable
call state. Generation-fenced handles prevent stale access after identifier
reuse.

## Queues

- Commands are bounded and reserve shutdown capacity.
- Internal protocol effects do not depend on observer delivery.
- Notifications are bounded, droppable/coalescible observations.
- PCM uses preallocated SPSC rings and frame pools, never ordinary MPSC queues.
- Every queue reports depth, high-water mark, overflow, underflow, and rejection.

## Clocks

Monotonic time drives transactions, media deadlines, latency, and timeouts. Wall
time is limited to operator/CDR timestamps and RTCP NTP fields. Suspend/resume,
wall-clock steps, device drift, and remote RTP drift require explicit handling.

## Fault containment

Panics are contained at the call-thread boundary and resources release exactly
once. Process crashes remain process-wide failures, so deployment uses multiple
workers with bounded calls per worker, health, drain, and restart supervision.

Critical lifecycle races are tested as state-machine invariants: CANCEL versus
200, BYE versus timeout, re-INVITE versus hangup, PRACK versus final response,
shutdown versus retry, and media replacement versus stale RTP.
