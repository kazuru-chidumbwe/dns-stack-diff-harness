# Threat Model

StackDiff profiles are invalid unless they state **who** the adversary is, **what** they can do, **what winning means**, and **DNSSEC posture**.

## Path vs peer

| Model | Question |
| --- | --- |
| Peer-consistency (ResolFuzz, ResolverFuzz) | Do isolated recursive resolvers disagree on the same query–response? |
| Path-consistency (StackDiff) | Do hops on one resolution path disagree under the same adversarial upstream conditions? |

v0 uses **pair mode**: Unbound and dnsmasq as **role stand-ins** for path hops (local forwarder/cache ≈ NodeLocal / systemd-resolved; full recursive/validating ≈ CoreDNS recursive or upstream). Path mode (chained hops) comes after the pair-mode oracle is trusted.

## Required fields (every profile)

| Field | Allowed values / content |
| --- | --- |
| `adversary.position` | `on-path` · `off-path` · `malicious-but-trusted-upstream` · `none` (smoke / benign) |
| `adversary.capability` | What they can manipulate |
| `adversary.win_condition` | What “adversary succeeded” means for **this** profile |
| `dnssec_posture.mode` | `matched` · `deliberately_mismatched` |
| `dnssec_posture.unbound` / `dnsmasq` | Per-resolver validation setting for this profile |

## DNSSEC posture (manufactured-finding hazard)

| Resolver | Default behavior |
| --- | --- |
| Unbound | Strict DNSSEC validation **on** by default |
| dnsmasq | Validation **off** unless trust anchors / `--dnssec` configured |

If a profile does not pin posture, DNSSEC-related divergences are **Class A config accidents**, not interesting path findings. Smoke uses **matched non-validating** for `lab.stackdiff.`. Deliberate mismatch is allowed only when the win condition is explicitly about fail-open vs fail-closed DNSSEC policy.

## Adversary positions

| Position | Meaning |
| --- | --- |
| `on-path` | Observe and/or modify DNS messages between resolver and upstream |
| `off-path` | Cannot see the query; may spoof / use side channels (often OS-layer — see Scope / Isolation) |
| `malicious-but-trusted-upstream` | Resolver trusts an upstream that returns adversarial answers |
| `none` | No adversary; instrument check (smoke) |

## Win conditions (examples)

- Hop A caches / returns an answer hop B would reject  
- DNSSEC fail-open on one hop vs SERVFAIL on another (**requires** deliberate posture mismatch or path-role difference stated in profile)  
- Out-of-bailiwick glue used vs ignored  
- Malformed response partial answer vs drop vs SERVFAIL  
- Hang / crash on one hop only  

## OS-layer classes (not interchangeable)

| Class | Example | v0 |
| --- | --- | --- |
| Klein / shared `prandom` | Cross-layer port prediction across containers | Deferred — see `SCOPE-ISOLATION.md` |
| SAD DNS / ICMP ratelimit | Port inference via ICMP rate-limit side channel | Deferred **pending per-kernel netns verification** |

## Disclosure

Class B “exploitable” claims require root-cause notes and a disclosure process before public naming of live vulnerable versions.
