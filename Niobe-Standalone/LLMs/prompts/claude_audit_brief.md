Read the context payload and produce the body of an AI Technical Intelligence Review in Markdown.

You must return only sections 1 to 12. Do not include:
- the document title
- the cover page
- the index / indice
- appendices
- HTML

Use exactly these top-level headings:
- ## 1. EXECUTIVE SUMMARY
- ## 2. SCOPE, METODOLOGIA E LIMITAZIONI
- ## 3. TOPOLOGIA E HEATMAP DEL RISCHIO
- ## 4. INTELLIGENCE ARCHITETTURALE
- ## 5. SECURITY VIEW
- ## 6. DATI, DIPENDENZE E SUPPLY CHAIN
- ## 7. ANALISI OSS (Open Source Scan)
- ## 8. MATURITÀ DEVOPS
- ## 9. DEBITO TECNICO E MANUTENIBILITA
- ## 10. ANALISI DI COMPLIANCE
- ## 11. ANALISI DEI FINDING
- ## 12. CONCLUSIONI

Use numbered `###` subsections only from section 2 onward. Section 1 must remain a single executive chapter in continuous prose, with no subsection headings.

Rules:
- produce a complete, dense, decision-grade report body suitable for a formal Tecnolife deliverable
- write the entire report in Italian, with professional and consultative tone
- behave as a senior cybersecurity engineer operating at government-grade rigor for a formal technical due-diligence audit
- do not emit placeholders, `etc`, `to be confirmed`, drafting notes, HTML entities such as `&#39;`, or instructions to the renderer
- keep the rendered document compatible with a primary accent color `#1B365D`
- section 1 must be an executive-business summary that explains what was done, why, for whom, how the evidence was collected, why the work is auditable, what the logical AI pipeline is, what the overall rating is, what the main vulnerabilities are, which CWE/CVE families matter most, and which alerts the business should keep in mind immediately
- when you describe the AI pipeline, use exactly this wording: `Normalizzazione, Clustering, Triage, Reporting`
- if the context supports it, explain that the audit execution model is containerizzato e rootless without turning this into tooling marketing copy
- before discussing risks in depth, identify the components that implementano la business logic custom dell'applicativo e trattali come focus primario della review, senza ignorare altre superfici materialmente rilevanti
- use the tool outputs, codebase metrics, tree-sitter evidence, deep review bundle and reference documents to justify why those components are considered core/custom instead of inferring this loosely
- section 2 must contain at least these subsections:
  - `### 2.1 Valore probatorio dell'analisi`
  - `### 2.2 Regole di ingaggio (RoE)`
  - `### 2.3 Obiettivi e richieste del cliente`
  - `### 2.4 Core Application Logic`
  - `### 2.5 Deliverable promessi e limiti`
- in `2.1 Valore probatorio dell'analisi`, explain in detail the forensic reliability model: SHA-512 hashing, evidence manifest, boot ID, machine ID, monotonic clock, detached GPG signatures, OpenTimestamps, host/container correlation and evidence sealing; make the explanation clear, rigorous and audit-resilient
- in `2.3 Obiettivi e richieste del cliente`, do not write generic phrases such as `il cliente ha richiesto`; instead use wording equivalent to `Su richiesta del cliente, il presente servizio di Digital Audit è applicato al repository di riferimento "..." con hash "..."`
- if `reference_documents.hld_text` is available, use it as the main baseline for RoE, objectives, compliance references, scoring language, glossary semantics, candidate/validated finding language and disclaimer language
- if `reference_documents.engagement` is available, use it to describe recipients, objectives and deliverables
- if `reference_documents.horis_pdf_path` is available, use it only as inspiration for the style of topology, mindmap and diagram narrative; do not copy its prose and do not treat it as methodological content
- if `reference_documents.template_docx_path` is available, treat `template.docx` as the only canonical graphic reference for layout, headers, footers, logo presence, page rhythm and visual hierarchy
- always treat `manifest.source` as the human-readable repository of reference and `manifest.repo_sha512` as the repository hash; mention `/scan` only as an internal execution mount path when strictly necessary
- sections 3, 5, 6, 9, 10 and 11 must be rich enough to sustain the corresponding tables, figures and callouts of the final template without looking sparse
- in section 3, keep labels short and clean so figures can render with readable nodes and connectors that route around nodes instead of crossing them
- section 5 must remain a standards-grounded application-security section, not a generic OWASP Top 10 heading
- section 5 must include a paragraph named `### Compliance References` that explains why the selected frameworks and standards are relevant to this engagement and how they were used
- section 6, section 9, section 10 and section 11 should each contain at least one concise executive-ready dashboard, matrix or business-facing summary block when the evidence supports it
- section 7 must perform an OSS provenance analysis: identify all open-source licenses present in the codebase and its dependencies, with particular attention to copyleft and restrictive licenses (GPL, AGPL, SSPL, EUPL, MPL, etc.) and undeclared OSS snippets embedded in proprietary code; leverage ScanCode, FOSSology and SBOM CycloneDX evidence from the tool outputs when available; include an executive dashboard or matrix of license risk with columns: **Componente**, **Licenza**, **Tipo** (permissive / weak-copyleft / strong-copyleft / proprietary / unknown), **Livello di Rischio** (Alto / Medio / Basso); flag any component whose license terms may conflict with the project's distribution model or with obligations arising from downstream dependencies
> Nota: per ricerche avanzate di OSS provenance, in caso di dubbi sulla provenienza di snippet di codice, si consiglia l'utilizzo di strumenti specializzati come BlackDuck.
- section 9 should describe technical debt in an executive and business-readable way, not only as engineering commentary
- section 10 must perform a deep compliance analysis based on code, dependencies and outputs; use DORA only if the application clearly belongs to the credit or financial domain, otherwise do not force it
- section 10 must include a subsection `### 10.5 Matrice di Compliance` containing a Markdown table with columns: **Framework**, **Articolo/Sezione**, **Requisito**, **Status**, **Gap**; the Status column must use one of: `Conforme`, `Non Conforme`, `Parziale`, `Da Verificare`; the Gap column must contain a concise description of the compliance gap or write `—` if conforme; every record in the Framework column must be **bold**; cite the exact article, section, annex or clause (e.g. Art. 32 GDPR, Annex II CRA, Art. 6(1) DORA, §PR.DS NIST CSF 2.0, V5.3.4 OWASP ASVS 5.0); verify accuracy by cross-referencing the context and reference documents
- immediately after the compliance matrix table, include a legend block that explains the four status values: `Conforme`, `Non Conforme`, `Parziale`, `Da Verificare` with precise definitions
- the compliance analysis must cover at minimum the following frameworks when the evidence supports relevance: GDPR (Reg. UE 2016/679), DPA / Art. 28 GDPR, TIA, CRA (Reg. UE 2024/2847), EU AI Act (Reg. UE 2024/1689), DORA (Reg. UE 2022/2554), NIS2 (Reg. UE 2022/2555), ISO/IEC 27001:2022, ISO/IEC 27005:2022, ISO/IEC 27034-1:2011, ISO 31000:2018, NIST CSF 2.0, NIST SP 800-30 Rev. 1, NIST SP 800-161r1, NIST SP 800-218 (SSDF), NIST SP 800-61r3, NIST IR 8286, OWASP ASVS 5.0, OWASP WSTG, FIRST CVSS v4.0, FIRST EPSS, CISA KEV, MITRE CWE, MITRE CVE, MITRE CAPEC, MITRE ATT&CK
- section 11 must begin with a short HLD-aligned explanation of what a finding is, distinguishing Candidate Finding from Validated Finding, and then present a ranked set of materially relevant findings with evidence, affected assets, transaction relevance and remediation posture expressed only in relative windows
- never state exact calendar dates for remediation
- do not emit effort in days, effort columns, or day-based effort estimates in tables
- do not mention `Rapid Review`, `Full Review` or similar labels anywhere in the final body
- do not list tree-sitter or compliance screening as standalone tools; instead describe them as internal analysis layers in the methodology narrative
- clearly distinguish tool-backed findings from LLM-only candidate hypotheses
- when `deep_review_findings` are present, use them to ground exploitability, transaction relevance and code-path realism in sections 5, 9, 10 and 11
- if the evidence is incomplete, group the open points into a single clearly argued paragraph rather than scattering weak caveats across the document
- section 12 must include a concluding paragraph named `### Call to action`
- number all materially relevant `###` subsections so the final index can point to a stable, linkable structure
- sections 6, 9, 10 and 11 must each contain at least one executive-ready dashboard, matrix or business-facing summary block, using Markdown tables with clear column headers; prefer structured visual blocks over long prose when presenting comparative, ranked or scored data
- the legend appendix produced by the template must include at minimum every term defined in the HLD baseline glossary, plus every term introduced by this report (Candidate Finding, Validated Finding, Inherent Risk, Residual Risk, Transaction Materiality, Final Score, Grade A-E, Red Flag, Negotiation Relevant, Integration Item, Observation, Control Gap, Logic Defect, Architecture Weakness, evidence_confidence, SHA-512, GPG, timestamping in blockchain, Normalizzazione, Clustering, Triage, Reporting); each definition must be rigorous, unambiguous and written in formal juridical register so it can withstand audit challenge without interpretive drift
- in the Risk Register and in section 11 finding cards, when referencing compliance frameworks cite the exact article, section or clause number rather than just the framework name
