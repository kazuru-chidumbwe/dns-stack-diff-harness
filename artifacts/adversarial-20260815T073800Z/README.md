# Adversarial pin — Lab Test Server 2026-08-15

Committed reference for TNSM Table II measurement pins (ADDITIONAL glue + malformed). Measurement only — Class A/B not published.

| Field | Value |
| --- | --- |
| Host | Lab Test Server · `6.12.101+deb13-amd64` · Docker `26.1.5+dfsg1` |
| Manifest SHA-256 | `cd84b2202aadf57d624446007628d66bcd1df91341115dc833acf7708648d8d7` |
| Schema | `stackdiff.adversarial.v1` |
| Smoke after | [`../smoke-20260815T073919Z/`](../smoke-20260815T073919Z/) · `pass=true` |
| Results tag | `results-dns02-20260815` |

Glue: ADDITIONAL echo diverge (dnsmasq yes / Unbound no); both `glue_cache_accept=false`.  
Malformed: Unbound SERVFAIL vs dnsmasq dig hard-error (4 axes).

See `docs/TRIAGE-DNS02-2026-08-15.md`. Prior public blog pin remains `adversarial-20260718T130854Z` / tag `blog-dns02a-2026-07`.

Verify:

```bash
sha256sum artifacts/adversarial-20260815T073800Z/manifest.json
# expect: cd84b2202aadf57d624446007628d66bcd1df91341115dc833acf7708648d8d7
```
