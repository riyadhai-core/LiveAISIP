# SIP scope and completion policy

The SIP hierarchy separates parsing, typed headers, validation, serialization,
transactions, dialogs, transport, authentication, and SDP. Protocol state
machines remain deterministic and independent from sockets, threads, Python,
and media processing.

Live correctness requires more than parser coverage. A supported operation has
an executable wire path, transaction/dialog integration, automated scenario,
real interoperability evidence, bounded diagnostics, and operator metrics.

The signaling qualification matrix includes direct and proxied FreeSWITCH,
401/407, provisional and final retransmissions, CANCEL races, non-2xx and 2xx
ACK, local/remote BYE, Record-Route and strict routing, Contact target refresh,
forking, PRACK, re-INVITE, UPDATE, hold/resume, session refresh, REFER/NOTIFY,
TCP/TLS, and DNS failover.

Unknown dialogs, invalid remote CSeq values, malformed traffic, and unsupported
methods receive defined bounded dispositions; they are never silently dropped.
