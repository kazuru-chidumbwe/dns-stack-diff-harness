# Adversarial runner (DNS-02)

Application-layer MITM profiles via `make adversarial`. This does **not** replace `make smoke`.

## What it measures

Two active profiles under identical upstream conditions (Unbound + dnsmasq path-role stand-ins):

| Profile | Injector mode | Intent |
| --- | --- | --- |
| `P-GLUE-BAILIWICK` | `additional-glue` | Out-of-bailiwick ADDITIONAL glue |
| `P-MALFORMED-RCODE` | `malformed-truncated` | Truncated / malformed upstream reply |

Results are **measurement only**. Manifests record divergences + `class_hint`. Do not publish Class A/B or “exploitable” language without separate triage and disclosure.

## Run

```bash
git checkout blog-dns02a-2026-07   # or main after that tag lands
docker compose -f deploy/compose.yaml up -d --build
make smoke          # instrument still green
make adversarial    # writes artifacts/adversarial-<UTC>/manifest.json
```

After the run, topology restores to smoke (direct-to-auth). Optional: re-check `make smoke`.

## Frozen public pin (DNS-02a)

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
