If `compliance_screening.enabled` is true in the context payload, add a `compliance_map` object to each relevant finding.

Rules for `compliance_map`:
- keys must be the framework names from `compliance_screening.frameworks`
- values must be one of:
  - `Gap`
  - `Partial`
  - `Aligned`
  - `N/A`
- only map frameworks that are materially relevant to the evidence
- if the evidence does not support a grounded mapping, use `N/A`
- never invent compliance assurance from static findings alone
