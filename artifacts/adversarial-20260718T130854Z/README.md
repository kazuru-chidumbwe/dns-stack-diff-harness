# Frozen adversarial pin (DNS-02a)

Committed reference for Blog DNS-02a / tag `blog-dns02a-2026-07`.

| Field | Value |
| --- | --- |
| Path | `artifacts/adversarial-20260718T130854Z/manifest.json` |
| SHA-256 (public pin) | `faa8afbaa1b02f64fdd4a598b7a799c3f45d53af8d4e542c63ec6d8372a7d88a` |
| Lab run (pre-redaction) | Same oracle table; lab file SHA-256 `392ef8ddac255e43052848b339ed473718b30490af3ec39b7b5fffc5b84ea6ba` |
| Role | Measurement only — no Class A/B assignment |

`uname_a` uses the public alias `stackdiff-lab` (hostname redacted for publication). Profile results, divergence counts, and kernel release string are otherwise the 2026-07-18 lab pin.

| Profile | Divergences | Axes | Notes |
| --- | ---: | --- | --- |
| P-GLUE-BAILIWICK | 1 | aa | Both NOERROR + `203.0.113.20`; AA-only noise |
| P-MALFORMED-RCODE | 4 | rcode, aa, ra, hang_or_crash | Unbound SERVFAIL vs dnsmasq dig exit 9 |

Future `make adversarial` runs still write under `artifacts/` and remain gitignored. Only this frozen directory is tracked.

Verify:

```bash
sha256sum artifacts/adversarial-20260718T130854Z/manifest.json
# expect: faa8afbaa1b02f64fdd4a598b7a799c3f45d53af8d4e542c63ec6d8372a7d88a
```
