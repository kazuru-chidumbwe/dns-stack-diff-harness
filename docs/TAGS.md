# Release tags

Annotated tags mark reproducible anchors. **`main` may advance** after a tag — always `git checkout <tag>` when reproducing a cited result.

| Tag | Purpose |
| --- | --- |
| [`v0.1.12`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.12) | Serial-hop cache-staleness experiment, timing fixed (`layer2-kind-serial-cache-20260912T181106Z`): ~1s-interval polling measures propagation lag directly (15.65s) instead of a single post-hoc sample; cross-checked against a 15.54s TTL-based prediction |
| [`v0.1.11`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.11) | Real serial-hop cache-staleness experiment (`layer2-kind-serial-cache-20260912T130932Z`): NodeLocal(cache)->CoreDNS->auth chain; real zone-record change served stale by NodeLocal, reconverges after cache TTL. Superseded by v0.1.12: its ~30s figure was an upper bound (sleep duration), not a measurement |
| [`v0.1.10`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.10) | Version-window PROMOTE re-run on Host B with image-tag/ID capture in the manifests (`adversarial-20260912T113912Z`/`...113934Z`, decision `change-window-version-20260912T113953Z`) |
| [`v0.1.9`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.9) | Kind L2 parallel-topology re-run (`layer2-kind-parallel-20260912T112004Z`): NodeLocal and CoreDNS each forward to the MITM independently; malformed-truncate shows a genuine divergence |
| [`v0.1.8`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.8) | Oracle both-null guard + failure-class fix, ΔD value-pair hardening, manifest image-tag capture, artifact-audit fixes (SHA256SUMS, dropped fingerprint) |
| [`v0.1.7`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.7) | Host B version-window PROMOTE instance (Unbound 1.24.0→1.25.1, MITM mode fixed) — manifests predate image-tag capture |
| [`v0.1.6`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.6) | Kind L1/L2 evidence packs shipped into `artifacts/`; `.gitignore` allowlist fix |
| [`v0.1.5`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.5) | SemVer + GitHub Release (Zenodo) · Host B PC+matrix · null-aware oracle |
| [`v0.1.4`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.4) | SemVer · Kind L1 + positive-control path (pre–Host B) |
| [`v0.1.3`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.3) | SemVer · CoreDNS-forwarder stand-in with Package B/C pins |
| [`v0.1.2`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.2) | SemVer + GitHub Release (Zenodo) · Package B+C + Aug 2026 archival pins |
| [`v0.1.1`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.1) | SemVer · Aug 2026 archival pins (pre–Package B/C) |
| [`v0.1.0`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/v0.1.0) | First SemVer tag (package / smoke cite) |
| [`blog-dns01-2026-07`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/blog-dns01-2026-07) | DNS-01 methodology + smoke gate |
| [`blog-dns02a-2026-07`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/blog-dns02a-2026-07) | DNS-02a July adversarial measurement pin |
| [`results-dns02-20260815`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/results-dns02-20260815) | Archival measurement pins — Aug 2026 ADDITIONAL/glue-cache + truncate (`stackdiff.adversarial.v1`) |

## Quick checkout

```bash
# Latest (serial-hop cache-staleness experiment, measured timing)
git checkout v0.1.12

# Previous serial-hop pack (upper-bound timing, superseded)
git checkout v0.1.11

# Version-window image-tag capture re-run
git checkout v0.1.10

# Kind L2 parallel-topology re-run
git checkout v0.1.9

# Oracle hardening + artifact-audit fixes
git checkout v0.1.8

# Host B version-window PROMOTE, Kind L1/L2 evidence
git checkout v0.1.7

# SemVer / Zenodo release tree (preferred package cite)
git checkout v0.1.5

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

# Archival measurement pin (Aug lab)
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

- **SemVer** → `v0.1.12` (current) · `v0.1.11` · `v0.1.10` · `v0.1.9` · `v0.1.8` · `v0.1.7` · `v0.1.6` · `v0.1.5` · `v0.1.4` · `v0.1.3` · `v0.1.2` · `v0.1.1` · `v0.1.0`. See [`CHANGELOG.md`](../CHANGELOG.md).
- **GitHub Release on a SemVer tag** is what Zenodo auto-mints when the repo is linked at https://zenodo.org/account/settings/github/
- DNS-01 essay → `blog-dns01-2026-07`.
- DNS-02a July measurement essay → `blog-dns02a-2026-07`.
- **Archival measurement pin** → `results-dns02-20260815` (results pin; distinct from SemVer code tag).
- Never cite floating `main` for published results.
- New SemVer tags when the release boundary changes — not on every doc commit.
