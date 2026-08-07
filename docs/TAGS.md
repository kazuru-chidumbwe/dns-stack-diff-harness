# Release tags

Annotated tags mark reproducible anchors. **`main` may advance** after a tag — always `git checkout <tag>` when reproducing a cited result.

| Tag | Commit | Purpose |
| --- | --- | --- |
| [`v0.1.0`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/releases/tag/v0.1.0) | `60d47e1` | First SemVer release (SoftwareX / package cite) |
| [`blog-dns01-2026-07`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/blog-dns01-2026-07) | `43789fd` | DNS-01 methodology + smoke gate |
| [`blog-dns02a-2026-07`](https://github.com/kazuru-chidumbwe/dns-stack-diff-harness/tree/blog-dns02a-2026-07) | `8fa31c6` | DNS-02a adversarial measurement pin |

## Quick checkout

```bash
# SoftwareX / SemVer
git checkout v0.1.0
sha256sum artifacts/smoke-20260718T125325Z/manifest.json

# DNS-01 essay pin
git checkout blog-dns01-2026-07

# DNS-02a adversarial measurement
git checkout blog-dns02a-2026-07
sha256sum artifacts/adversarial-20260718T130854Z/manifest.json
```

## Tag policy

- **SemVer / SoftwareX C1** → `v0.1.0` (see [`CHANGELOG.md`](../CHANGELOG.md)).
- DNS-01 essay → `blog-dns01-2026-07`.
- DNS-02a measurement essay → `blog-dns02a-2026-07`.
- Never cite floating `main` for published results.
- New SemVer tags when the release boundary changes — not on every doc commit.
