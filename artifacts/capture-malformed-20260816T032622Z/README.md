# Malformed capture pin — 2026-08-16 (Package B)

Committed reference for TNSM Table VII (truncated MITM delivery to both stand-ins). Measurement only — not a vulnerability disclosure.

| Field | Value |
| --- | --- |
| Stamp | `capture-malformed-20260816T032622Z` |
| Mode | `MITM_MODE=malformed-truncated` (keep=20) · `agree.lab.stackdiff.` A |
| Bridge pcap SHA-256 | `463c23b507a37242aba9c2f3d7386d61e038f49ac64175aa5001636b869c7a71` |
| Post-smoke | `smoke-after.out` · `pass=True` |
| Replay helper | [`../../scripts/capture-malformed-timeline.sh`](../../scripts/capture-malformed-timeline.sh) |

## Established observations

- Unbound → dig SERVFAIL (UDP/TCP): resolver-generated DNS failure.
- Truncated MITM UDP reached **both** Unbound and dnsmasq (`dnsnet-bridge.pcap`).
- dnsmasq → dig: UDP timeout / TCP EOF — **no DNS reply**; **no resolver-generated RCODE**.
- dig TCP to dnsmasq opens TCP to UDP-only MITM → RST; no successful TCP fallback.

Absolute lab paths in text sidecars were redacted to `.` for publication; pcaps and dig transcripts are otherwise the 16 Aug lab pin. See `SHA256SUMS` in this directory.

```bash
sha256sum artifacts/capture-malformed-20260816T032622Z/dnsnet-bridge.pcap
# expect: 463c23b507a37242aba9c2f3d7386d61e038f49ac64175aa5001636b869c7a71
```
