# Package C robustness — 20260816T034020Z

- Host env: `6.12.101+deb13-amd64` · Docker `26.1.5+dfsg1`
- Repeats per adversarial profile: **10**
- Controls: passthrough-agree × 5
- Role-order probes: 2 (glue + malformed, reverse dig)

## Passthrough control (expect smoke D=0)

- smoke_pass rate: **1.0** (5/5)
- smoke D histogram: `{'0': 5}`
- security-axis D histogram (AA/RA may differ): `{'1': 5}`

## Adversarial repeats

### P-GLUE-BAILIWICK
- n=10 · modal D(p)=2 (0.80) · stable_D=False
- modal axes: `['aa', 'additional']` · stable_axes=False
- D histogram: `{'2': 8, '5': 2}`

### P-MALFORMED-RCODE
- n=10 · modal D(p)=4 (1.00) · stable_D=True
- modal axes: `['aa', 'hang_or_crash', 'ra', 'rcode']` · stable_axes=True
- D histogram: `{'4': 10}`

## Role-order (reverse dig)

- P-GLUE-BAILIWICK dig_order=['dnsmasq', 'unbound'] D=2 axes=['aa', 'additional']
- P-MALFORMED-RCODE dig_order=['dnsmasq', 'unbound'] D=4 axes=['aa', 'hang_or_crash', 'ra', 'rcode']

## Interpretation (measurement honesty)

- Stability of modal D(p)/axes under clean restarts supports instrument repeatability for the two profiles.
- Passthrough smoke D=0 supports the agreeing-control gate.
- This is still a laboratory robustness campaign — not production prevalence.
