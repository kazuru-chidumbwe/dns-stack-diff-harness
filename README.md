# DNS Stack Diff Harness

Path-consistency differential harness for Linux / Kubernetes-style DNS resolution stacks.

StackDiff asks whether DNS components that can appear as hops on one resolution path agree under identical adversarial upstream conditions. It is not ResolFuzz / ResolverFuzz (those ask whether peer recursive resolvers agree in isolation).

Synthetic / lab only. Controlled auth; no live Internet authorities for default profiles.

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
| Git tag | `blog-dns01-YYYY-MM` |
| Host OS / distro | Ubuntu 24.04.4 LTS (`stackdiff-lab`) |
| `uname -r` | `6.8.0-134-generic` |
| Distro kernel package | `linux-image-6.8.0-134-generic` `6.8.0-134.134` |
| Docker / Compose | `29.1.3` / `2.40.3` |
| Hardware / VM | QEMU/KVM |
| Manifest SHA-256 | `36da41f5dd5115e8b800e4011638466127e282d1b49d4e3810189946c036123d` |

Reproducibility: prefer a pinned kernel for comparable runs. Plain Docker has the shared-kernel limits documented in `SCOPE-ISOLATION.md`.

## Status

| Item | State |
| --- | --- |
| Compose topology (Unbound + dnsmasq + auth) | v0 |
| Threat / isolation / schema docs | v0 |
| Oracle validation smoke (`P-SMOKE-AGREE`) | green (lab pin above) |
| Application-layer adversarial runner | available (`make adversarial`) |
| Klein / SAD DNS profiles | deferred |

No invented finding counts. Adversarial manifests are measurement only until Class A/B triage and disclosure.

## Quick start

Requirements: Docker Compose, Python 3.12+.

```bash
git clone <PUBLIC_REPO_URL>
cd dns-stack-diff-harness
git checkout blog-dns01-YYYY-MM   # pin when published; not main
docker compose -f deploy/compose.yaml up -d --build
make smoke
# record uname -r, docker version, manifest SHA-256
```

Smoke harness failure: identical `NOERROR` plus RRset containing `203.0.113.10` required; any smoke-axis mismatch is Class C, not a finding.

Optional: `make adversarial` runs application-layer MITM profiles. It does not replace smoke.

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
- [`ROADMAP.md`](ROADMAP.md)

## License

Apache-2.0 (see `LICENSE`).
