Read the context payload and produce only a JSON object with a single top-level key named `deep_review_findings`.

The `deep_review_findings` value must be an array of objects. Do not wrap the JSON in markdown fences. Do not add commentary.

You are performing the Gate 3 `Triage` pass after `Normalizzazione` and `Clustering`. This is not a narrative summary. It is a focused adjudication step that must inspect the provided code snippets, clustered evidence and custom business logic paths.

Primary objectives:
- validate or reject materially relevant code-level weaknesses after correlating tool findings and heuristic signals
- focus first on IDOR / missing object-level authorization, SQL injection, NoSQL injection (NoSQLi), SSRF, unsafe deserialization, command injection, path traversal, XXE (XML External Entity), XSS stored, XSS reflected, DOM-based attacks, information disclosure (verbose errors, stack traces, debug endpoints), malware signatures or suspicious binary patterns, unparsed file uploads (magic-byte validation bypass), memory safety issues (buffer overflows, use-after-free, double-free in C/C++/Rust unsafe blocks), race conditions, TOCTOU (Time-of-Check-Time-of-Use), concurrency issues (deadlocks, data races, missing synchronization), and classic low-level unsafe primitives
- assess overall code security posture, maintainability and technical debt when the evidence supports systemic weaknesses beyond individual findings
- first identify the components that appear to implement the application's custom business logic, then prioritize those components for the deep review without ignoring other high-risk surfaces
- distinguish core custom logic from framework bootstrap, plumbing, vendor code, generated code and legacy parked material; explain that distinction through the findings you emit
- when the evidence shows that a path is part of the core custom logic, make that explicit in `description`, `executive_description` or `key_evidence` so the final report can surface it in the Scope chapter
- reason about exploitability and reachability conservatively; if the evidence is incomplete, keep the item as `Candidate`
- anchor every finding to concrete code evidence already present in the context payload

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
- `evidence_sources`

Rules:
- include only findings that are grounded in the supplied deep review bundle, code snippets and tool-backed anchors
- do not invent files, code paths, sinks, sources or authorization gaps that are not visible in the payload
- use `Validated` only when the evidence contains a concrete code path, sink or missing guard that would survive technical challenge
- when the evidence shows a plausible but incomplete weakness, keep `validation_status` as `Candidate`
- if there is not enough evidence for a defensible finding, omit it
- `finding_id` must follow `TLF-<AREA>-<NNN>`
- `finding_type` must be one of: `Vulnerability`, `Control Gap`, `Configuration Issue`, `Architecture Weakness`, `Logic Defect`, `Non-compliance`
- `evidence_confidence` must be `High`, `Medium`, or `Low`
- keep the seven numeric dimensions in the 1-5 range
- keep `classification` to `Red Flag`, `Negotiation Relevant`, `Integration Item`, or `Observation`
- `affected_asset` must identify the file path and, when the evidence supports it, the relevant component or handler
- `taxonomy` must be specific and grounded, for example `CWE-639`, `CWE-89`, `OWASP ASVS 5.0 V4`, `OWASP WSTG-ATHZ-04`
- `evidence_sources` must reference the tool or snippet anchor that supports the conclusion
- do not turn generic security hotspots into findings unless the code snippets justify it
- prefer fewer, stronger findings over a long speculative list
