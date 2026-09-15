# Changelog



All notable changes to this project are documented in this file.



The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),

and this project adheres to [Semantic Versioning](https://semver.org/v2.0.0.html).



Citation / essay pins (`blog-*`) remain valid reproducibility anchors.

Prefer **SemVer** (`vX.Y.Z`) for package citations; see [`docs/TAGS.md`](docs/TAGS.md).

Zenodo minting stopped after `v0.1.5`; `.zenodo.json` removed in `v0.1.12`. `v0.1.6` onward cite the GitHub tag directly, not a DOI.



## [0.1.13] — 2026-09-15

### Added

- `scripts/layer2_compose_serial_cache.sh`: second serial-hop pairing, Unbound (cache) -> CoreDNS-forwarder (no cache) -> auth. Same remaining-TTL prediction as the Kind experiment.
- Kind and compose TTL sweeps on Testbed B (20 / 60 / 120 / 300 s). Packs `artifacts/layer2-kind-serial-cache-20260915T185233Z` (and 185304Z / 185538Z / 185749Z) and `artifacts/layer2-compose-serial-cache-20260915T192609Z` (and 192636Z / 192742Z / 192949Z).

### Fixed

- `scripts/layer2_kind_serial_cache.sh`: NodeLocal no longer forwards to `10.96.0.10` (an address it binds). A dedicated `coredns-direct` Service is the upstream. `ZONE_TTL` rewrites the zone `$TTL`. Poll window is `2 * min(cache, zone) + 30`. The v0.1.12 15.65s pack remains as a self-forward measurement.


## [0.1.12] — 2026-09-12

### Removed

- `.zenodo.json`: stops the GitHub→Zenodo auto-mint metadata. No new DOI has been minted since `v0.1.5`; going forward the manuscript and this repo cite the GitHub tag directly (matches the paper's own citation [24], which already dropped Zenodo). Existing DOIs for `v0.1.2`/`v0.1.5` remain valid and are kept for historical citation.

### Fixed

- `scripts/layer2_kind_serial_cache.sh`: replaced the single post-hoc sample (sleep `CACHE_TTL+8`, then one dig) with ~1s-interval polling of NodeLocal from the moment of promotion, recording first-observation time. External review (Reviewer X) correctly identified that the v0.1.11 pack's `propagation_lag_observed_s` (~30.3s) was an upper bound, not a measurement, since the cache entry was populated before the change and its true remaining TTL at promotion time was ~15.1s, not the full 20s. Re-run (`artifacts/layer2-kind-serial-cache-20260912T181106Z/`) measures 15.65s directly, cross-checked against an independent TTL-based prediction of 15.54s (agree within 0.11s). Also fixed the script's SHA256SUMS finalization so `run.log` is hashed after `cleanup()`'s own logging completes, instead of relying on a manual post-run fix.

## [0.1.11] — 2026-09-12

### Added

- Real serial-hop cache-staleness experiment (`artifacts/layer2-kind-serial-cache-20260912T130932Z/`, `scripts/layer2_kind_serial_cache.sh`): a genuine consecutive-hop chain (NodeLocal -> CoreDNS -> auth) with NodeLocal's cache enabled, not a parallel comparison and not a bare relay. A real authoritative zone-record change (`www` A: `.20` -> `.21`) is served stale by NodeLocal for ~30s (its 20s cache TTL plus query/rollout timing) while CoreDNS reflects it immediately; both reconverge once the cache entry expires. This is the paper's first result that seriality itself, not implementation difference, produces. Superseded by v0.1.12's timing fix; kept for history.

## [0.1.10] — 2026-09-12

### Added

- Re-ran the version-window PROMOTE instance on Host B with `v0.1.9` code (`artifacts/adversarial-20260912T113912Z/` pre, `artifacts/adversarial-20260912T113934Z/` post, decision `artifacts/change-window-version-20260912T113953Z/`). Manifests now carry `container_images` with the configured tag and the resolved image ID read from the live container, closing the gap the `v0.1.7` manifests had (image change previously only asserted by the wrapper script). Same result as before: D(p) pre=2 post=2, axes unchanged (AA, RA), decision PROMOTE — no regression, just independently verifiable provenance.

## [0.1.9] — 2026-09-12

### Added

- Kind L2 parallel-topology re-run (`artifacts/layer2-kind-parallel-20260912T112004Z/`, `scripts/layer2_kind_adversarial_parallel.sh`): NodeLocal and CoreDNS each forward `lab.stackdiff` directly to the MITM independently instead of NodeLocal relaying through CoreDNS. Restores the Section III-D pair-mode invariant. Result: passthrough and additional-glue fully agree; malformed-truncate genuinely diverges (NodeLocal client timeout, CoreDNS `FORMERR`) — $D_{\mathrm{null}}=1$ on FailureMode, replicating the August Unbound-vs-dnsmasq malformed finding on an independent resolver pair in a different environment.
- Prior serial-topology pack (`layer2-kind-20260912T004414Z/`) kept for history, marked superseded in its own `SUMMARY.md`.

## [0.1.8] — 2026-09-12

### Fixed

- Both-null soundness hole: `compare_observations()` now reports `all_null`; `layer3_change_window.py` and `layer3_version_window.sh` emit `INCONCLUSIVE` (not `PROMOTE`) when either pin's stand-ins returned no DNS message at all.
- `hang_or_crash` compared only presence/absence of `error`, scoring a timeout on one side and a hard `dig` exit on the other as agreement. Added `classify_failure()` to compare normalized failure classes instead.
- `ΔD` baseline subtraction (paper-side, Section III-B) matched by axis name only, which could mask a baseline axis whose divergent value-pair reverses polarity under the adversary. Added `delta_divergence()` matching on the full (axis, value-pair) tuple.
- `run_adversarial.py` now records each resolver's configured image tag and resolved image ID (read from the live container via `docker inspect`, not asserted by the caller) into `manifest["container_images"]`.
- `docs/TAGS.md`, the top-level `README.md`, and four `artifacts/*/README.md` files still named a prior target venue and were missing tags `v0.1.3`–`v0.1.7` entirely.
- `artifacts/layer1-kind-20260904T231736Z/SHA256SUMS.txt` used absolute host paths, failing `sha256sum -c` from a fresh checkout; rewritten relative.
- `artifacts/layer2-kind-20260912T004414Z/SHA256SUMS.txt` listed `run.log`, which was never committed and whose printed hash didn't match any locally available copy; removed the line rather than ship an unverified file.
- Dropped the unreproducible "combined adversarial digs fingerprint" for the Kind L2 pack; citations now point at the two per-file SHAs, which verify.

### Documented

- `artifacts/layer2-kind-20260912T004414Z/SUMMARY.md` now states plainly that NodeLocal forwards to CoreDNS, which forwards to the MITM (serial, not parallel) — the pack is a pass-through fidelity result, not independent-hop agreement.
- `docs/ARCHITECTURE.md` gained a concrete one-line-Corefile parallel-topology fix plan for the next Kind L2 re-run on Lab Test Server.

## [0.1.7] — 2026-09-12

### Added

- Host B version-window PROMOTE instance (`scripts/layer3_version_window.sh`): MITM mode held fixed at `authority-ns-glue`, Unbound image swapped 1.24.0→1.25.1. Brackets the change-window workflow's other branch alongside the existing HOLD vignette.

## [0.1.6] — 2026-09-12

### Added

- Kind L1 (`artifacts/layer1-kind-20260904T231736Z/`) and Kind L2 (`artifacts/layer2-kind-20260912T004414Z/`) evidence packs shipped into `artifacts/`, with `.gitignore` allowlist fix so they are actually committed (previously captured but never tracked).

## [0.1.5] — 2026-09-05

### Added

- Null-aware divergence scoring in `classifier/oracle.py` (`null_aware=True` default; ungated triage via `null_aware=False`).
- Host B campaign pack `artifacts/hostb-20260904T204650Z/` (`PC_ARMED=1`, Unbound 1.20/1.24/1.25 no cache-accept flip, robustness, change-window HOLD, Kind L1 out-of-claims).
- CoreDNS-forwarder pair path, CVE-2025-11411 positive-control scripts, and related profiles/docs from the Host B upgrade track.

### Changed

- README / Zenodo metadata retargeted to `v0.1.5` (prior Zenodo version DOI remains `10.5281/zenodo.21961205` until next mint).

## [0.1.2] — 2026-08-16



### Added



- Package B malformed capture pin `artifacts/capture-malformed-20260816T032622Z/` (malformed-capture timeline table).

- Package C robustness pin `artifacts/robustness-20260816T034020Z/` + `make robustness` / `classifier/run_robustness.py` (robustness table).

- Replay helper `scripts/capture-malformed-timeline.sh`.



### Changed



- README / TAGS / Zenodo metadata retargeted to `v0.1.2` (concept DOI unchanged).



## [0.1.1] — 2026-08-16



### Added



- August 2026 DNS-02 lab pins (`results-dns02-20260815`): ADDITIONAL + glue cache-accept axes; Table II adversarial SHA `cd84b220…`; post-restore smoke SHA `ec5196e0…`.

- `.zenodo.json` for GitHub→Zenodo release metadata.

- `CITATION.cff` (ORCID attribution).



### Changed



- README / venue docs made venue-neutral; measurement-only stance.



## [0.1.0] — 2026-07-27



### Added



- First SemVer tag for package / smoke citation (DNS-01 smoke instrument).

- Essay pin `blog-dns01-2026-07` remains the DNS-01 methodology cite.

- Essay pin `blog-dns02a-2026-07` remains the DNS-02a July adversarial measurement cite.

- `CHANGELOG.md` and SemVer tag policy in `docs/TAGS.md`.



[0.1.2]: https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.2

[0.1.1]: https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.1

[0.1.0]: https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.0

