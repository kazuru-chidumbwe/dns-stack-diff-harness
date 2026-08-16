# Adversarial runner (DNS-02)

Application-layer MITM profiles via `make adversarial`. This does **not** replace `make smoke`.

## What it measures

Two active profiles under identical upstream conditions (Unbound + dnsmasq path-role stand-ins):

| Profile | Injector mode | Intent |
| --- | --- | --- |
| `P-GLUE-BAILIWICK` | `additional-glue` | Out-of-bailiwick ADDITIONAL glue + **cache-accept probe** (`ns.evil.test.`) |
| `P-MALFORMED-RCODE` | `malformed-truncated` | Truncated / malformed upstream reply |

For glue, the oracle uses `GLUE_AXES` (`additional`, `glue_cache_accept` in addition to the security axes). Client ANSWER often strips ADDITIONAL; the follow-up probe is the primary bailiwick signal.

Results are **measurement only**. Manifests record divergences + `class_hint`. Do not publish Class A/B or “exploitable” language without separate triage and disclosure. See [`TRIAGE-DNS02-2026-08-15.md`](TRIAGE-DNS02-2026-08-15.md).

## Run

```bash
git checkout v0.1.2
docker compose -f deploy/compose.yaml up -d --build
make smoke          # instrument still green
make adversarial    # writes artifacts/adversarial-<UTC>/manifest.json
make robustness     # Package C: repeats + passthrough + role-order
```

After adversarial / robustness, topology restores toward smoke. Optional: re-check `make smoke`.

Malformed packet timeline helper (Package B): `scripts/capture-malformed-timeline.sh` → `artifacts/capture-malformed-<UTC>/`.

## Frozen public pins (Aug 2026 + Package B/C)

| Role | Path | Verify |
| --- | --- | --- |
| Adversarial (Table IV) | `artifacts/adversarial-20260815T073800Z/` | SHA `cd84b220…` |
| Post-restore smoke | `artifacts/smoke-20260815T073919Z/` | SHA `ec5196e0…` |
| Malformed capture (Table VII) | `artifacts/capture-malformed-20260816T032622Z/` | bridge pcap `463c23b5…` |
| Robustness (Table IX) | `artifacts/robustness-20260816T034020Z/` | manifest `fe42a81d…` |

## Frozen public pin (DNS-02a July)

| Field | Value |
| --- | --- |
| Tag | `blog-dns02a-2026-07` |
| Manifest | [`artifacts/adversarial-20260718T130854Z/manifest.json`](../artifacts/adversarial-20260718T130854Z/manifest.json) |
| SHA-256 | `faa8afbaa1b02f64fdd4a598b7a799c3f45d53af8d4e542c63ec6d8372a7d88a` |

A fresh `make adversarial` produces a **different** SHA. The frozen file is the citeable pin; new runs are for local triage.

## Scope reminder

| Layer | Plain Docker? |
| --- | --- |
| Application-layer (RCODE, RRset, flags, hang/crash) | In scope |
| Klein / SAD DNS OS-layer | Deferred — see [`SCOPE-ISOLATION.md`](SCOPE-ISOLATION.md) |
