# Release tags

Annotated tags mark reproducible anchors. **`main` may advance** after a tag — always `git checkout <tag>` when reproducing a cited result.

| Tag | Purpose |
| --- | --- |
| [`v0.1.2`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.2) | SemVer + GitHub Release (Zenodo) · Package B+C + Aug 2026 TNSM pins |
| [`v0.1.1`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.1) | SemVer · Aug 2026 TNSM pins (pre–Package B/C) |
| [`v0.1.0`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/v0.1.0) | First SemVer tag (package / smoke cite) |
| [`blog-dns01-2026-07`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/blog-dns01-2026-07) | DNS-01 methodology + smoke gate |
| [`blog-dns02a-2026-07`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/blog-dns02a-2026-07) | DNS-02a July adversarial measurement pin |
| [`results-dns02-20260815`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/results-dns02-20260815) | TNSM Table II pins — Aug 2026 ADDITIONAL/glue-cache + truncate (`stackdiff.adversarial.v1`) |

## Quick checkout

```bash
# SemVer / Zenodo release tree (preferred package cite)
git checkout v0.1.2

# SemVer / Aug pins only
git checkout v0.1.1

# SemVer / smoke baseline
git checkout v0.1.0
sha256sum artifacts/smoke-20260718T125325Z/manifest.json

# DNS-01 essay pin
git checkout blog-dns01-2026-07

# DNS-02a July measurement
git checkout blog-dns02a-2026-07
sha256sum artifacts/adversarial-20260718T130854Z/manifest.json

# TNSM Dec 2026 measurement pin (Aug lab)
git checkout results-dns02-20260815
sha256sum artifacts/adversarial-20260815T073800Z/manifest.json
# expect: cd84b2202aadf57d624446007628d66bcd1df91341115dc833acf7708648d8d7
sha256sum artifacts/smoke-20260815T073919Z/manifest.json
# expect: ec5196e0b95dfa1ad7899437c582956f77c0e803d9914c55658677212940990e

# Package B / C (also on v0.1.2)
sha256sum artifacts/capture-malformed-20260816T032622Z/dnsnet-bridge.pcap
# expect: 463c23b507a37242aba9c2f3d7386d61e038f49ac64175aa5001636b869c7a71
sha256sum artifacts/robustness-20260816T034020Z/manifest.json
# expect: fe42a81dd5a41f468db9fabdd9aa0eff4fad249907d9ae5da6c39e3bd82ff84b
```

## Tag policy

- **SemVer** → `v0.1.2` (current) · `v0.1.1` · `v0.1.0`. See [`CHANGELOG.md`](../CHANGELOG.md).
- **GitHub Release on a SemVer tag** is what Zenodo auto-mints when the repo is linked at https://zenodo.org/account/settings/github/
- DNS-01 essay → `blog-dns01-2026-07`.
- DNS-02a July measurement essay → `blog-dns02a-2026-07`.
- **TNSM archival measurement** → `results-dns02-20260815` (results pin; distinct from SemVer code tag).
- Never cite floating `main` for published results.
- New SemVer tags when the release boundary changes — not on every doc commit.
