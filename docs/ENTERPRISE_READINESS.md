# Enterprise readiness baseline

This document freezes the non-protocol requirements that accompany the detailed
capability matrix in `ALPHA_STATUS.md` and the gates in `TESTING.md`.

Production requires process sharding, measured multi-resource admission, host
limit validation, event-driven per-call execution, overload priorities, durable
idempotent call-detail events, immutable configuration snapshots, tenant-scoped
quotas, stable ABI/API versioning, controlled privacy/retention, security
operations, bounded diagnostic capture, formal lifecycle checking, and a
documented release/support policy.

Operational readiness includes FD/thread/port/memory/CPU accounting; kernel and
socket-buffer verification; readiness versus liveness; worker drain/restart;
version-skew negotiation; key/certificate rotation; vulnerability response;
redacted metrics; and runbooks for one-way audio, RTP loss, SRTP failures,
resource exhaustion, DNS/carrier outages, Python backlog, and drain timeout.

Capacity and SLOs come from measurements, never marketing constants. Suggested
qualification includes 100,000 sequential lifecycles without leakage, a 72-hour
steady-state soak, overload bursts, impairment corpora, acoustic scenarios, and
rehearsed deployment rollback. Thresholds are deployment-profile data and must
be published with the supported release.

Privacy controls cover phone numbers, SIP identities, IP addresses, audio,
transcripts, recordings, credentials, provider data, crash dumps, retention,
operator access, and deletion/export. Raw audio, authorization values, and key
material are never captured by default.
