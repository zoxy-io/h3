# What each vendored specification is here for

`zig build requirements` reports coverage per RFC, and a single aggregate
number across all seven would be dishonest: this package implements four of
these documents and *borrows rules from* three of them. A requirement in a
document nobody is implementing is not an uncovered requirement.

| RFC | posture | why |
|---|---|---|
| 9000 | **implemented** | QUIC transport. The package is this document. |
| 9001 | **implemented** | QUIC-TLS. Packet protection is here; the TLS engine is the consumer's, so section 4's handshake rules are largely exceptions naming that seam. |
| 9002 | **implemented** | Loss detection and congestion control, minus ECN and pacing. |
| 9114 | **implemented** | HTTP/3, minus the control stream, SETTINGS exchange and server push. |
| 9204 | **implemented** | QPACK, static-table only by advertisement. |
| 9110 | *referenced* | HTTP semantics. The package implements the handful of rules RFC 9114 delegates here — `content-length`'s syntax, `status-code`'s three digits, the `Host` and `:authority` relationship — and nothing else. It parses no HTTP message of its own. |
| 9112 | *referenced* | HTTP/1.1. Vendored for one reason: this package writes to a proxy's threat model, and the rules that decide whether a downgraded message is ambiguous live here. It is not an HTTP/1.1 implementation and will never cite most of this document. |

**A referenced document is cited where a rule is borrowed and nowhere else.**
Marking its remaining requirements as exceptions would add hundreds of lines
saying "this is not an HTTP/1.1 implementation", which is true, uninformative,
and would bury the exceptions that carry real scope decisions — migration,
0-RTT, the QPACK dynamic table, ECN, pacing. The posture is declared once,
here, and the tool reports the two groups apart.
