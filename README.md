# DNS Stack Diff Harness

Path-consistency differential harness for Linux / Kubernetes-style DNS resolution stacks.

StackDiff asks whether DNS components that can appear as hops on one resolution path agree under identical adversarial upstream conditions. It is not ResolFuzz / ResolverFuzz (those ask whether peer recursive resolvers agree in isolation).

Synthetic / lab only. Controlled auth; no live Internet authorities for default profiles.

## Release and blog pins (use a tag — not `main`)

| Role | Tag | Notes |
| --- | --- | --- |
| **SemVer (latest)** | [`v0.1.11`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.11) | Real serial-hop cache-staleness experiment: NodeLocal->CoreDNS->auth with caching enabled — the paper's first genuine consecutive-hop finding; Zenodo mint pending |
| **SemVer (version-window)** | [`v0.1.10`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.10) | Version-window PROMOTE re-run on Host B with image-tag/ID capture in the manifests (was asserted only in decision.json before); Zenodo mint pending |
| **SemVer (Kind L2 parallel)** | [`v0.1.9`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.9) | Kind L2 parallel-topology re-run: NodeLocal and CoreDNS each forward to the MITM independently; malformed-truncate now shows a genuine divergence; Zenodo mint pending |
| **SemVer (oracle hardening)** | [`v0.1.8`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.8) | Oracle both-null guard, failure-class fix, ΔD value-pair hardening, image-tag manifest capture, artifact-audit fixes; Zenodo mint pending |
| **SemVer (version-window)** | [`v0.1.7`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.7) | Host B version-window PROMOTE instance (Unbound 1.24.0→1.25.1, MITM mode fixed); Zenodo mint pending |
| **SemVer (Kind L1/L2)** | [`v0.1.6`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.6) | Kind L1/L2 evidence packs shipped into `artifacts/`; `.gitignore` allowlist fix; Zenodo mint pending |
| **SemVer / Zenodo Release** | [`v0.1.5`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.5) | Host B PC+matrix · null-aware · Zenodo `10.5281/zenodo.22313122` |
| **SemVer (C1–C3 / PC)** | [`v0.1.4`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.4) | Kind L1 + PC path (pre–Host B) |
| **SemVer (CoreDNS-fwd)** | [`v0.1.3`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.3) | CoreDNS-forwarder Package B/C pins |
| **SemVer (Package B+C)** | [`v0.1.2`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.2) | Aug DNS-02 + Package B/C; Zenodo `10.5281/zenodo.21961205` |
| **SemVer (Aug DNS-02 only)** | [`v0.1.1`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.1) | Aug 2026 archival measurement pins (pre–Package B/C) |
| **SemVer (smoke baseline)** | [`v0.1.0`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/v0.1.0) | DNS-01-era smoke tree |
| **DNS-01** (Part 1) | [`blog-dns01-2026-07`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/blog-dns01-2026-07) | Methodology + smoke gate |
| **DNS-02a** (Part 2) | [`blog-dns02a-2026-07`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/blog-dns02a-2026-07) | Smoke + frozen adversarial pin |

Each public essay freezes a **separate** Git tag. Do not swap essay pins.

- **DNS-01 essay / smoke baseline:** cite **`v0.1.0`** or **`blog-dns01-2026-07`**
- **Host B + null-aware cite:** cite **`v0.1.5`** · pack [`artifacts/hostb-20260904T204650Z/`](artifacts/hostb-20260904T204650Z/) · Zenodo version DOI [10.5281/zenodo.22313122](https://doi.org/10.5281/zenodo.22313122) (concept [10.5281/zenodo.21959550](https://doi.org/10.5281/zenodo.21959550))
- **Kind L1 evidence pack:** cite **`v0.1.6`** · `artifacts/layer1-kind-20260904T231736Z/` · Zenodo mint pending
- **Kind L2, parallel topology (load-bearing):** cite **`v0.1.9`** · `artifacts/layer2-kind-parallel-20260912T112004Z/` — NodeLocal and CoreDNS each forward to the MITM independently; passthrough/additional-glue agree, malformed-truncate genuinely diverges (NodeLocal times out, CoreDNS returns FORMERR) · Zenodo mint pending
- **Kind L2, serial topology (superseded, kept for history):** `v0.1.6` · `artifacts/layer2-kind-20260912T004414Z/` — pass-through fidelity only, not independent-hop agreement; see `docs/ARCHITECTURE.md`
- **Host B version-window PROMOTE instance (load-bearing):** cite **`v0.1.10`** · `artifacts/adversarial-20260912T113912Z/` (pre) · `artifacts/adversarial-20260912T113934Z/` (post) · `artifacts/change-window-version-20260912T113953Z/` (decision) · manifests carry `container_images` (tag + resolved image ID from `docker inspect`) · Zenodo mint pending
- **Host B version-window PROMOTE instance (superseded, kept for history):** `v0.1.7` · `artifacts/adversarial-20260912T070427Z/` (pre) · `artifacts/adversarial-20260912T070453Z/` (post) · manifests predate image-tag capture
- **Oracle hardening + artifact-audit fixes:** cite **`v0.1.8`** · `all_null`/`classify_failure`/`delta_divergence` in `classifier/oracle.py` · Zenodo mint pending
- **Serial-hop cache-staleness experiment (load-bearing):** cite **`v0.1.11`** · `artifacts/layer2-kind-serial-cache-20260912T130932Z/` — real consecutive-hop chain (NodeLocal cache -> CoreDNS -> auth); a real zone-record change is served stale by NodeLocal for ~30s before reconverging · Zenodo mint pending
- **Package / Zenodo cite (Aug 2026 + Package B/C):** cite **`v0.1.2`** · Zenodo [10.5281/zenodo.21961205](https://doi.org/10.5281/zenodo.21961205) (same concept DOI)
- **DNS-02a essay (July pin):** measurement pin → cite **`blog-dns02a-2026-07`**
- **Archival measurement pin (Aug 2026):** cite **`results-dns02-20260815`** — adversarial SHA `cd84b220…` · post-restore smoke SHA `ec5196e0…`
- **Package B malformed timeline:** `artifacts/capture-malformed-20260816T032622Z/` (bridge pcap SHA `463c23b5…`)
- **Package C robustness:** `artifacts/robustness-20260816T034020Z/` (manifest SHA `fe42a81d…`) · `make robustness`
- **Null-aware oracle (default):** `compare_observations(..., null_aware=True)` gates RCODE/AA/RA/ADDITIONAL/cache-accept when a role yields no DNS message; `hang_or_crash` still scores. Ungated triage: `null_aware=False` (can inflate $D(p)$).
- **Manuscript posture:** measurement-only instrument paper; Class A/B labels are not published findings this pass. See [`docs/TRIAGE-DNS02-2026-08-15.md`](docs/TRIAGE-DNS02-2026-08-15.md).

See [`docs/TAGS.md`](docs/TAGS.md) and [`CITATION.cff`](CITATION.cff). Repo root / `main` may move; published claims always link a **tag tree**.

## Threat model

See [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). Every profile must declare adversary position, capability, win condition, and `dnssec_posture`.

## Scope / isolation

See [`docs/SCOPE-ISOLATION.md`](docs/SCOPE-ISOLATION.md).

| Layer | v0 | Note |
| --- | --- | --- |
| Application-layer | In scope | Plain Docker OK |
| Klein-class shared `prandom` | Deferred | Needs VM-class isolation |
| SAD DNS-class | Deferred | Randomization (≈5.10+) ≠ netns bucket (v6.12+); pin `uname -r` |

## Lab environment

Record on every pin (also emitted by `make smoke` → `lab_environment` in the manifest):

| Field | Example pin (2026-07-18) |
| --- | --- |
| Git tag | `blog-dns01-2026-07` |
| Host OS / distro | Ubuntu 24.04.4 LTS (`stackdiff-lab`) |
| `uname -r` | `6.8.0-134-generic` |
| Distro kernel package | `linux-image-6.8.0-134-generic` `6.8.0-134.134` |
| Docker / Compose | `29.1.3` / `2.40.3` |
| Hardware / VM | QEMU/KVM |
| Manifest SHA-256 | `6804627105cd22b51b35e9df1c713f2fe26c5c4d67abb81bfdd2064be99e0560` |
| Frozen manifest | [`artifacts/smoke-20260718T125325Z/manifest.json`](artifacts/smoke-20260718T125325Z/manifest.json) |

### DNS-02 archival measurement pin (2026-08-15)

| Field | Value |
| --- | --- |
| Results tag | [`results-dns02-20260815`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/results-dns02-20260815) |
| Adversarial manifest | [`artifacts/adversarial-20260815T073800Z/manifest.json`](artifacts/adversarial-20260815T073800Z/manifest.json) |
| Adversarial SHA-256 | `cd84b2202aadf57d624446007628d66bcd1df91341115dc833acf7708648d8d7` |
| Post-restore smoke | [`artifacts/smoke-20260815T073919Z/manifest.json`](artifacts/smoke-20260815T073919Z/manifest.json) |
| Smoke SHA-256 | `ec5196e0b95dfa1ad7899437c582956f77c0e803d9914c55658677212940990e` |
| Schema | `stackdiff.adversarial.v1` |
| Package B capture | [`artifacts/capture-malformed-20260816T032622Z/`](artifacts/capture-malformed-20260816T032622Z/) · bridge pcap SHA `463c23b5…` |
| Package C robustness | [`artifacts/robustness-20260816T034020Z/`](artifacts/robustness-20260816T034020Z/) · manifest SHA `fe42a81d…` |
| Docs | [`docs/TRIAGE-DNS02-2026-08-15.md`](docs/TRIAGE-DNS02-2026-08-15.md) |

Measurement only. Class A/B labels are not published findings for the archival manuscript.

### DNS-02a adversarial pin (July blog)

| Field | Example pin (2026-07-18) |
| --- | --- |
| Git tag | `blog-dns02a-2026-07` |
| Frozen manifest | [`artifacts/adversarial-20260718T130854Z/manifest.json`](artifacts/adversarial-20260718T130854Z/manifest.json) |
| Manifest SHA-256 | `faa8afbaa1b02f64fdd4a598b7a799c3f45d53af8d4e542c63ec6d8372a7d88a` |
| Docs | [`docs/ADVERSARIAL.md`](docs/ADVERSARIAL.md) |

Reproducibility: prefer a pinned kernel for comparable runs. Plain Docker has the shared-kernel limits documented in `SCOPE-ISOLATION.md`. Frozen manifests are committed on the tags so cited SHA-256 values are independently checkable. Later `make smoke` / `make adversarial` runs stay gitignored and will produce a different hash.

## Status

| Item | State |
| --- | --- |
| Compose topology (Unbound + CoreDNS-forwarder + auth) | v0 |
| Threat / isolation / schema docs | v0 |
| Oracle validation smoke (`P-SMOKE-AGREE`) | green (lab pin above) |
| Application-layer adversarial runner | available (`make adversarial`) |
| DNS-02a frozen adversarial pin (July) | committed (measurement only) |
| DNS-02 archival pin (Aug 2026) | committed on `results-dns02-20260815` (measurement only) |
| Package B / C (malformed + robustness) | committed on `v0.1.2` |
| Klein / SAD DNS profiles | deferred |

No invented finding counts. Adversarial manifests are measurement only until Class A/B triage and disclosure.

## Quick start

Requirements: Docker Compose, Python 3.12+.

```bash
git clone https://github.com/kazuru-chidumbwe/dns-stack-diff-harness
cd dns-stack-diff-harness
git checkout blog-dns02a-2026-07   # adversarial measurement pin (not SemVer v0.1.0)
sha256sum artifacts/smoke-20260718T125325Z/manifest.json
# expect: 6804627105cd22b51b35e9df1c713f2fe26c5c4d67abb81bfdd2064be99e0560
sha256sum artifacts/adversarial-20260718T130854Z/manifest.json
# expect: faa8afbaa1b02f64fdd4a598b7a799c3f45d53af8d4e542c63ec6d8372a7d88a
docker compose -f deploy/compose.yaml up -d --build
make smoke
# new run SHA will differ; require pass=true and divergence_count=0
```

For the early DNS-01 smoke baseline only: `git checkout v0.1.0` (same tree as `blog-dns01-2026-07`).

Smoke harness failure: identical `NOERROR` plus RRset containing `203.0.113.10` required; any smoke-axis mismatch is Class C, not a finding.

Optional: `make adversarial` runs application-layer MITM profiles. It does not replace smoke. See [`docs/ADVERSARIAL.md`](docs/ADVERSARIAL.md).

Optional: `make robustness` repeats adversarial profiles with a passthrough control and role-order probe (`artifacts/robustness-*/`).

## Profiles (v0)

| ID | Layer | Status | Intent |
| --- | --- | --- | --- |
| `P-SMOKE-AGREE` | application | active | Oracle validation (forward-only) |
| `P-GLUE-BAILIWICK` | application | active | Out-of-bailiwick ADDITIONAL glue |
| `P-MALFORMED-RCODE` | application | active | Truncated/malformed upstream reply |
| `P-OS-KLEIN-PRNG-DEFERRED` | os | deferred | Shared prandom / cross-container |
| `P-OS-SAD-DNS-ICMP-DEFERRED` | os | deferred | ICMP side channel; pin kernel story |

## Divergence classes

| Class | Meaning |
| --- | --- |
| A | Documented / expected; report, do not hype |
| B | Emergent, security-relevant; disclosure first |
| C | Harness / measurement artefact; fix, never publish as finding |

## Docs

- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)
- [`docs/SCOPE-ISOLATION.md`](docs/SCOPE-ISOLATION.md)
- [`docs/SCHEMA.md`](docs/SCHEMA.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/ADVERSARIAL.md`](docs/ADVERSARIAL.md)
- [`ROADMAP.md`](ROADMAP.md)

## License

Apache-2.0 — see `LICENSE`. Citation metadata: [`CITATION.cff`](CITATION.cff).
