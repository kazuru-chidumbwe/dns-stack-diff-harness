# Package C robustness — 20260904T202608Z

- Host env: `6.8.0-139-generic` · Docker `29.1.3`
- Repeats per adversarial profile: **10**
- Controls: passthrough-agree × 5
- Role-order probes: 3 (glue + malformed, reverse dig)

## Passthrough control (expect smoke D=0)

- smoke_pass rate: **1.0** (5/5)
- smoke D histogram: `{'0': 5}`
- security-axis D histogram (AA/RA may differ): `{'2': 5}`

## Adversarial repeats

### P-GLUE-AUTHORITY-NS
- n=10 · modal D(p)=2 (1.00) · stable_D=True
- modal axes: `['aa', 'ra']` · stable_axes=True
- D histogram: `{'2': 10}`

### P-GLUE-BAILIWICK
- n=10 · modal D(p)=3 (1.00) · stable_D=True
- modal axes: `['aa', 'additional', 'ra']` · stable_axes=True
- D histogram: `{'3': 10}`

### P-MALFORMED-RCODE
- n=10 · modal D(p)=2 (1.00) · stable_D=True
- modal axes: `['ra', 'rcode']` · stable_axes=True
- D histogram: `{'2': 10}`

## Role-order (reverse dig)

- P-GLUE-AUTHORITY-NS dig_order=['coredns_fwd', 'unbound'] D=2 axes=['aa', 'ra']
- P-GLUE-BAILIWICK dig_order=['coredns_fwd', 'unbound'] D=3 axes=['aa', 'additional', 'ra']
- P-MALFORMED-RCODE dig_order=['coredns_fwd', 'unbound'] D=2 axes=['ra', 'rcode']

## Interpretation (measurement honesty)

- Stability of modal D(p)/axes under clean restarts supports instrument repeatability for the two profiles.
- Passthrough smoke D=0 supports the agreeing-control gate.
- This is still a laboratory robustness campaign — not production prevalence.
