# Robustness campaign pin — 2026-08-16 (Package C)

Committed reference for TNSM Table IX (`make robustness`). Laboratory repeatability — not production prevalence.

| Field | Value |
| --- | --- |
| Stamp | `robustness-20260816T034020Z` |
| Schema | `stackdiff.robustness.v1` |
| Manifest SHA-256 | `fe42a81dd5a41f468db9fabdd9aa0eff4fad249907d9ae5da6c39e3bd82ff84b` |
| Host | Lab Test Server · `6.12.101+deb13-amd64` · Docker `26.1.5+dfsg1` |
| Runner | `classifier/run_robustness.py` · `make robustness` |

## Headline

| Condition | Outcome |
| --- | --- |
| Passthrough smoke ×5 | smoke \(D=0\) on 5/5; security-axis \(D=1\) (AA/RA) |
| P-GLUE-BAILIWICK ×10 | modal \(D=2\) on 8/10 (aa, additional); 2/10 \(D=5\) settle/hard-error |
| P-MALFORMED-RCODE ×10 | \(D=4\) on 10/10 (aa, hang_or_crash, ra, rcode) |
| Reverse dig order | same modal axes |

Publication note: one absolute lab path in `post_smoke_tail` / `run.log` was redacted to `.`; numeric outcomes unchanged. See also `SUMMARY.md`.

```bash
sha256sum artifacts/robustness-20260816T034020Z/manifest.json
# expect: fe42a81dd5a41f468db9fabdd9aa0eff4fad249907d9ae5da6c39e3bd82ff84b
```
