# Host B campaign pin — 20260904T204650Z

Lab: Host B `test-server` · kernel 6.8.0-139-generic · Docker 29.1.3 · `PC_ARMED=1` · `PHASE=DONE EXIT=0`.

| Artifact | Role |
| --- | --- |
| `positive-control-20260904T202443Z/` | CVE-2025-11411-shaped PC · `pass=true` |
| `gate-cve11411/` | Unbound 1.20.0 / 1.24.0 / 1.25.1 · no cache-accept flip |
| `robustness-20260904T202608Z/` | Package C-style repeats on CoreDNS-forwarder pair |
| `change-window-20260904T203720Z/` | HOLD · D 2→3 Class A ADDITIONAL |
| `layer1-kind-20260904T203956Z/` | Kind present · probe timeout · **out of claims** |

Oracle: null-aware `compare_observations(..., null_aware=True)` is default (TNSM Table IV). Ungated triage: `null_aware=False`.
