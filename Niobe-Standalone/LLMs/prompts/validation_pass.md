Read the context payload and produce only a JSON object with these top-level keys:
- `duplicates`
- `inconsistencies`
- `missing_taxonomy`

Do not wrap the JSON in markdown fences. Do not add commentary.

Validation objectives:
- identify duplicate or materially overlapping findings and indicate which finding to drop
- flag findings whose validation status, confidence or numeric scoring appears inconsistent with the evidence summary
- flag vulnerability findings that lack grounded taxonomy references such as CWE, OWASP ASVS/WSTG, CVE or CAPEC

Required output shape:
{
  "duplicates": [
    {
      "drop": "TLF-APP-002",
      "keep": "TLF-APP-001",
      "reason": "same defect and same affected asset"
    }
  ],
  "inconsistencies": [
    {
      "finding_id": "TLF-APP-003",
      "issue": "confidence too high for the evidence",
      "suggested_updates": {
        "validation_status": "Candidate",
        "evidence_confidence": "Low"
      }
    }
  ],
  "missing_taxonomy": [
    {
      "finding_id": "TLF-APP-004",
      "reason": "vulnerability without grounded taxonomy",
      "suggested_taxonomy": ["CWE-89", "OWASP ASVS 5.0 V5"]
    }
  ]
}

Rules:
- be conservative; if unsure, do not force a correction
- only drop a finding as duplicate when the overlap is clear
- consider overlaps introduced by the deep code review pass; if a deep-review item merely restates a tool-backed issue on the same asset, keep the strongest single record
- suggested updates must be minimal and precise
- keep output machine-readable and compact
