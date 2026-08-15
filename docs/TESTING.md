# Verification and production gates

Every capability is tracked across type/parser, state machine, wire executor,
unit test, integration test, interoperability, impairment, load evidence,
operator metric, and documentation. A type or simulated state transition alone
is not enterprise support.

Required verification layers are deterministic virtual-time traces, property
tests, modeled concurrency, fuzzing, FreeSWITCH/proxy interoperability, media
impairment, acoustic testing, load/soak, and chaos. Empty fuzz targets are not
kept in the repository; the future harness must compile and run in CI when
introduced.

## Production-supported release gate

- No unresolved P0/P1 correctness findings.
- Direct and proxied SIP interoperability passes.
- Bidirectional PCMU RTP/RTCP passes under impairment.
- SRTP/SRTCP vectors and real interoperability pass.
- Rust playout passes a broad differential and impairment corpus.
- Sonora AEC/NS/AGC passes acoustic qualification.
- C ABI and Python lifecycle/compatibility tests pass.
- OpenAI full-duplex audio never blocks call threads.
- Declared concurrency passes load and soak tests.
- No monotonic leak of threads, FDs, ports, handles, buffers, or permits.
- Worker crash blast radius, drain, rolling deployment, and rollback are tested.
- CI, fuzzing, dependency review, signed artifacts, provenance, and SBOM exist.
- Metrics, alerts, dashboards, runbooks, capacity limits, and SLOs are published.
- Independent security review has no unresolved critical finding.
- Documentation matches executable behavior and contains no placeholder claims.

Maturity is reported as Experimental, Alpha, Beta, Release Candidate, or
Production Supported. It is never represented by one misleading boolean.
