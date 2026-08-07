# Pre-publish checklist (smoke dogfood)

Do **not** publish Blog DNS-01 until every item is checked on the pin tag.

**External validation:** plan/isolation/path framing reviewed 18 Jul 2026; gate remains green `make smoke`. Klein cite: arXiv:**2012.07432** (not 2012.07464).

## Isolation / claims

- [ ] SCOPE-ISOLATION: randomization (`b38e7819…`, ≈5.10+) as **primary** mitigation; netns move as separate isolation story
- [ ] Distro footnote (Ubuntu 24.04 / enterprise often &lt; 6.12) present
- [x] Lab Environment + Latest Run tables filled from pin (lab SHA above; public tag TBD)
- [x] Manifest includes `lab_environment.uname_r` and `harness_failure_criterion`
- [x] Title is technical (path consistency), not clickbait-only
- [x] ResolverFuzz credited for real cache-poisoning-class findings; no overlap claims
- [x] `make schema` + green `make smoke` on pin (lab; public tag freeze still open)
- [x] Full commit URLs only (no truncated hashes)
- [x] Smoke Unbound = forward-only oracle validation step
- [x] No “N new CVEs” language

## DNSSEC posture

- [ ] Every profile has `dnssec_posture` with `mode` + per-resolver settings
- [ ] Smoke is `matched` non-validating for `lab.stackdiff.`
- [ ] Unbound: `domain-insecure: "lab.stackdiff."`
- [ ] dnsmasq: DNSSEC validation not enabled; `cache-size=0`
- [ ] No Class A/B table published without stating matched vs deliberately mismatched

## Deterministic smoke

- [ ] Auth zone static (`agree` → `203.0.113.10`)
- [ ] Both resolvers share upstream `172.30.0.10`
- [ ] Smoke pass axes = RCODE + answers (+ hang/crash) — not AA/RA alone

## Links / pin discipline

- [ ] Blog doc links use `<PUBLIC_REPO_URL>/blob/blog-dns01-YYYY-MM/docs/...` (not bare relative paths, not `main`)
- [ ] `git clone` / `git checkout` / ROADMAP links use the same placeholders until freeze
- [ ] Real tag + URL replace all placeholders at publish

## Dogfood

- [x] `make schema` passes (lab 2026-07-18)
- [x] `make smoke` exits 0 — `artifacts/smoke-20260718T125325Z/`
- [x] Manifest `"pass": true` and `oracle.divergence_count: 0`
- [x] Blog Lab Environment / Latest Run filled from that manifest (rev H); public tag URL still TBD at freeze
