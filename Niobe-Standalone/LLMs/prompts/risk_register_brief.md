Read the context payload and produce only a JSON object with a single top-level key named `validated_findings`.

The `validated_findings` value must be an array of objects. Do not wrap the JSON in markdown fences. Do not add commentary.

You are preparing the structured Gate 3 `Triage` output for the HLD-aligned Risk Register workbook. The logical pipeline is: `Normalizzazione`, `Clustering`, `Triage`, `Reporting`. The arithmetic scoring is deterministic in code, not in your response.
Every finding must be evidence-anchored. If the evidence is weak, leave it out rather than inflating certainty.

For each finding object, provide these fields:
- `finding_id`
- `title`
- `finding_type`
- `affected_asset`
- `taxonomy`
- `description`
- `evidence_summary`
- `validation_status`
- `evidence_confidence`
- `likelihood`
- `technical_impact`
- `business_impact`
- `control_weakness`
- `compliance_exposure`
- `remediation_effort`
- `transaction_impact`
- `classification`
- `suggested_action`
- `executive_description`
- `key_evidence`
- `compliance_map` only when the context payload enables compliance screening

Rules:
- include only validated findings or exceptionally justified observations that are still decision-relevant
- use `deep_review_findings` when present as a post-correlation code-review input, but preserve contestability discipline
- if a deep-review item is grounded by snippets and tool anchors, it may be included even when the original scanner signal was partial
- if a deep-review item remains only inferential after reading the code snippets, exclude it from the register rather than inflating certainty
- do not include false positives, speculative candidates, or unvalidated hypotheses
- `finding_id` must follow `TLF-<AREA>-<NNN>`, for example `TLF-APP-001`
- keep `finding_type` to one of:
  - `Vulnerability`
  - `Control Gap`
  - `Configuration Issue`
  - `Architecture Weakness`
  - `Logic Defect`
  - `Non-compliance`
- keep `evidence_confidence` to `High`, `Medium`, or `Low`
- keep the eight numeric dimensions in the 1-5 range, using the HLD scales from the context payload
- do not compute `inherent_risk`, `residual_risk`, `transaction_materiality`, `final_score`, or `grade`; code will calculate them deterministically
- keep `classification` to one of:
  - `Red Flag`
  - `Negotiation Relevant`
  - `Integration Item`
  - `Observation`
- use `Red Flag` only if the evidence clearly meets the HLD red-flag criteria
- preserve candidate vs validated finding discipline: the register should be evidence-driven and contestable
- use concise, workbook-ready strings; avoid paragraphs longer than necessary
- map taxonomy to the best grounded references available from evidence, for example CWE/CVE/CAPEC/ATT&CK, OWASP ASVS 5.0, OWASP WSTG, CVSS v4.0
- map taxonomy to both CWE and CVE identifiers when evidence supports it, not only CWE; include CVSS v4.0 base score reference when available
- affected assets must identify the component and the path whenever the evidence supports it
- taxonomy must be grounded and specific; never answer with placeholders such as `to be confirmed`
- if the evidence is only inferential and not tool-backed, mark the item conservatively and keep the wording explicit about uncertainty
- if the evidence is too weak to justify numeric scoring, exclude the item instead of inventing certainty
