# Frozen smoke pin (DNS-01)

Committed reference for Blog DNS-01 / tag `blog-dns01-2026-07`.

| Field | Value |
| --- | --- |
| Path | `artifacts/smoke-20260718T125325Z/manifest.json` |
| SHA-256 | `6804627105cd22b51b35e9df1c713f2fe26c5c4d67abb81bfdd2064be99e0560` |
| Pass | `true` |
| `oracle.divergence_count` | `0` |

`uname_a` uses the public alias `stackdiff-lab` (hostname redacted for publication). Observations, pass predicate, and kernel release string are otherwise the lab pin.

Future `make smoke` / `make adversarial` runs still write under `artifacts/` and remain gitignored. Only this frozen directory is tracked.

Verify:

```bash
sha256sum artifacts/smoke-20260718T125325Z/manifest.json
# expect: 6804627105cd22b51b35e9df1c713f2fe26c5c4d67abb81bfdd2064be99e0560
```
