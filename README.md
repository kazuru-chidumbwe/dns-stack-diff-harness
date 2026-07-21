# DNS Stack Diff Harness

Path-consistency differential harness for Linux / Kubernetes-style DNS resolution stacks.

StackDiff asks whether DNS components that can appear as hops on one resolution path agree under identical adversarial upstream conditions. It is not ResolFuzz / ResolverFuzz (those ask whether peer recursive resolvers agree in isolation).

Synthetic / lab only. Controlled auth; no live Internet authorities for default profiles.

## Blog pins (use the matching tag — not `main`)

Each public essay freezes a **separate** Git tag. Do not swap them.

| Blog | Role | Tag (checkout / cite) | Tree |
| --- | --- | --- | --- |
| **DNS-01** (Part 1) | Methodology + smoke gate | [`blog-dns01-2026-07`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/blog-dns01-2026-07) | smoke pin only |
| **DNS-02a** (Part 2) | First adversarial **measurement** | [`blog-dns02a-2026-07`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/blog-dns02a-2026-07) | smoke + frozen adversarial pin |

- **DNS-01 essay:** [Path Consistency in Kubernetes DNS Stacks…](https://dev.to/kazuru_73322ef9a7d6ed2b18/path-consistency-in-kubernetes-dns-stacks-do-resolvers-agree-under-adversarial-conditions-4b6g) → cite **`blog-dns01-2026-07`**
- **DNS-02a essay:** measurement pin → cite **`blog-dns02a-2026-07`** (includes adversarial manifest SHA `faa8afba…`)

Repo root / `main` may move; blog posts always link the **tag trees** above.

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

### DNS-02a adversarial pin (measurement)

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
| Compose topology (Unbound + dnsmasq + auth) | v0 |
| Threat / isolation / schema docs | v0 |
| Oracle validation smoke (`P-SMOKE-AGREE`) | green (lab pin above) |
| Application-layer adversarial runner | available (`make adversarial`) |
| DNS-02a frozen adversarial pin | committed (measurement only) |
| Klein / SAD DNS profiles | deferred |

No invented finding counts. Adversarial manifests are measurement only until Class A/B triage and disclosure.

## Quick start

Requirements: Docker Compose, Python 3.12+.

```bash
git clone https://github.com/kazuru-chidumbwe/dns-stack-diff-harness
cd dns-stack-diff-harness
git checkout blog-dns02a-2026-07
sha256sum artifacts/smoke-20260718T125325Z/manifest.json
# expect: 6804627105cd22b51b35e9df1c713f2fe26c5c4d67abb81bfdd2064be99e0560
sha256sum artifacts/adversarial-20260718T130854Z/manifest.json
# expect: faa8afbaa1b02f64fdd4a598b7a799c3f45d53af8d4e542c63ec6d8372a7d88a
docker compose -f deploy/compose.yaml up -d --build
make smoke
# new run SHA will differ; require pass=true and divergence_count=0
```

Smoke harness failure: identical `NOERROR` plus RRset containing `203.0.113.10` required; any smoke-axis mismatch is Class C, not a finding.

Optional: `make adversarial` runs application-layer MITM profiles. It does not replace smoke. See [`docs/ADVERSARIAL.md`](docs/ADVERSARIAL.md).

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

Apache-2.0 (see `LICENSE`).
