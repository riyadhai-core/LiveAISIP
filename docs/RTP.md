# RTP and RTCP scope

RTP owns packet parsing/serialization, receive and transmit state, clock-domain
progression, source/SSRC validation, symmetric endpoint policy, DTMF, bounded
queues, and security evidence. RTCP owns compound packets, randomized absolute
report scheduling, SR/RR state, RTT, SDES, and BYE.

Negotiated codec descriptors carry name, clock rate, channels, payload type,
ptime/maxptime, encoded bound, decoder, and encoder. Dynamic payload types never
imply a clock rate without SDP.

Receive ordering is security-first:

```text
UDP -> authenticate/replay-check/unprotect -> parse -> source learning -> media
```

Transmit ordering is:

```text
media -> RTP/RTCP serialize -> protect -> UDP
```

Unauthenticated packets cannot update symmetric RTP state. Media generations
fence rekey, remote target, payload type, SSRC restarts, and SDP replacements.
