# Frozen post-adversarial smoke pin (Lab Test Server 2026-08-15)

Committed reference after `adversarial-20260815T073800Z` restore. Measurement hygiene only — not a findings table.

| Field | Value |
| --- | --- |
| Path | `artifacts/smoke-20260815T073919Z/manifest.json` |
| SHA-256 | `ec5196e0b95dfa1ad7899437c582956f77c0e803d9914c55658677212940990e` |
| Pass | `true` |
| Smoke-axis divergences | `0` (informational AA noise may appear; fail gate is RCODE/answers/hang) |
| Lab | Lab Test Server · kernel `6.12.101+deb13-amd64` · Docker `26.1.5+dfsg1` |
| Results tag | `results-dns02-20260815` (cite with adversarial pin below) |

Companion adversarial pin: [`../adversarial-20260815T073800Z/`](../adversarial-20260815T073800Z/) · SHA-256 `cd84b2202aadf57d624446007628d66bcd1df91341115dc833acf7708648d8d7`.

Verify:

```bash
sha256sum artifacts/smoke-20260815T073919Z/manifest.json
# expect: ec5196e0b95dfa1ad7899437c582956f77c0e803d9914c55658677212940990e
```
