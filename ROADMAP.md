# Roadmap — StackDiff

## v0 (current) — pair mode + oracle validation smoke

- Threat model + scope/isolation docs (written)
- Profile schema with adversary + `dnssec_posture`
- Two resolvers: Unbound + dnsmasq (path-role stand-ins)
- `P-SMOKE-AGREE` green and pinned (Unbound **forward-only** = oracle validation step)
- Application-layer only under plain Docker; record `uname -r` on every pin

## DNS-02 — first adversarial table

- [x] MITM injector (`deploy/mitm/dns_mitm.py`) + `compose.adversarial.yaml` overlay
- [x] Activate `P-GLUE-BAILIWICK` + `P-MALFORMED-RCODE` (`make adversarial`)
- [x] Frozen measurement pin `artifacts/adversarial-20260718T130854Z/` + tag `blog-dns02a-2026-07`
- [ ] First Class A/B table from pinned manifests + root-cause notes (triage, not auto-label)
- [ ] Unbound **full recursive** mode enabled (smoke stays forward-only)
- [ ] Disclosure process before any “exploitable” language
- Draw structural inspiration from ResolverFuzz-style differential cases (no CVE overlap claims)

## Path mode (after oracle trusted)

Chain hops: stub → node-local / systemd-resolved → CoreDNS → upstream.

| Metric | Meaning |
| --- | --- |
| Per-hop disagreement | Adjacent hops differ on a security axis under the same profile |
| End-to-end resolution success | Client-visible answer succeeds even if an intermediate hop would have rejected |
| Weakest-hop posture | Which hop’s accept/reject decision determines the path outcome |
| Class mix | A/B/C rates across the chain (not just pairwise) |

Same profiles and oracle; unit of comparison becomes consecutive hops (and optionally full-path vs pairwise).

## OS-layer (split)

| Class | Status | Gate |
| --- | --- | --- |
| Klein / shared `prandom` | Deferred | Firecracker / Kata / full VM |
| SAD DNS | Deferred | Pin kernel: randomization backport (≈5.10+) **and** msgs-per-sec netns shape (v6.12+ mainline); full commit URLs only |

See `docs/SCOPE-ISOLATION.md`.

## Later enhancements

- Statistical analysis (repeated runs, confidence intervals on divergence rates)
- Bring systemd-resolved and CoreDNS into path mode earlier once pair oracle is trusted
- Quantitative cache-poisoning success probability under pinned profiles (disclosure-gated)

