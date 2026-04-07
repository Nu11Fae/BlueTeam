from __future__ import annotations

from dataclasses import dataclass


SECURITY_VIEW_STANDARDS = [
    "OWASP ASVS 5.0",
    "OWASP WSTG",
    "OWASP Risk Rating Methodology",
    "NIST SP 800-218 (SSDF)",
    "FIRST CVSS v4.0",
    "FIRST EPSS",
    "CISA KEV",
    "MITRE CWE",
    "MITRE CVE",
    "MITRE CAPEC",
    "MITRE ATT&CK",
]

COMPLIANCE_STANDARDS = [
    "GDPR",
    "DPA / Art. 28 GDPR",
    "TIA",
    "CRA",
    "EU AI Act",
    "DORA",
    "NIS2",
    "ISO/IEC 27001:2022",
    "ISO/IEC 27005:2022",
    "ISO/IEC 27034-1:2011",
    "NIST CSF 2.0",
    "NIST SP 1303",
    "NIST SP 800-30 Rev. 1",
    "NIST IR 8286 Rev. 1",
    "NIST IR 8286A Rev. 1",
    "NIST IR 8286B-upd1",
    "NIST SP 800-161r1",
    "NIST SP 800-221",
    "NIST SP 800-34r1",
    "NIST SP 800-61r3",
]

SCORING_DIMENSIONS = {
    "likelihood": {
        "label": "Likelihood",
        "scale": {
            1: "improbable",
            2: "unlikely",
            3: "plausible",
            4: "probable",
            5: "very likely / easily exploitable",
        },
    },
    "technical_impact": {
        "label": "Technical Impact",
        "scale": {
            1: "minimal impact",
            2: "limited impact",
            3: "significant but contained",
            4: "high impact",
            5: "critical / serious compromise",
        },
    },
    "business_impact": {
        "label": "Business Impact",
        "scale": {
            1: "non-critical component",
            2: "secondary",
            3: "important",
            4: "business-critical",
            5: "core business / core process",
        },
    },
    "control_weakness": {
        "label": "Control Weakness",
        "scale": {
            1: "strong controls",
            2: "good controls",
            3: "partial controls",
            4: "weak controls",
            5: "absent or ineffective controls",
        },
    },
    "compliance_exposure": {
        "label": "Compliance Exposure",
        "scale": {
            1: "irrelevant",
            2: "low",
            3: "moderate",
            4: "high",
            5: "very high / concrete regulatory exposure",
        },
    },
    "remediation_effort": {
        "label": "Remediation Effort",
        "scale": {
            1: "simple fix",
            2: "small fix",
            3: "medium fix",
            4: "complex fix",
            5: "redesign / structural intervention",
        },
    },
    "transaction_impact": {
        "label": "Transaction Impact",
        "scale": {
            1: "no deal impact",
            2: "marginal note",
            3: "needs attention",
            4: "can influence negotiation / remediation plan",
            5: "can influence signing, closing, price, CP/CV, TSA",
        },
    },
    "evidence_confidence": {
        "label": "Evidence Confidence",
        "scale": {
            "Low": "low confidence",
            "Medium": "medium confidence",
            "High": "high confidence",
        },
    },
}

RISK_REGISTER_HEADERS = [
    "Finding ID",
    "Title",
    "Finding Type",
    "Affected Asset",
    "Taxonomy",
    "Description",
    "Evidence Reference / Evidence Summary",
    "Validation Status",
    "Evidence Confidence",
    "Likelihood",
    "Technical Impact",
    "Business Impact",
    "Control Weakness",
    "Compliance Exposure",
    "Remediation Effort",
    "Transaction Impact",
    "Inherent Risk",
    "Residual Risk",
    "Transaction Materiality",
    "Final Score",
    "Grade",
    "Classification (Red Flag / Negotiation Relevant / Integration Item / Observation)",
    "Suggested Action",
]

EXECUTIVE_HEADERS = [
    "Finding ID",
    "Title",
    "Affected Asset",
    "Taxonomy / Standard Mapping",
    "Validation Status",
    "Evidence Confidence",
    "Residual Risk",
    "Final Score",
    "Grade",
    "Classification",
    "Executive Description",
    "Key Evidence",
    "Suggested Action",
]

CLASSIFICATIONS = [
    "Red Flag",
    "Negotiation Relevant",
    "Integration Item",
    "Observation",
]


@dataclass(frozen=True, slots=True)
class ScoringModel:
    inherent_likelihood_w: float = 0.35
    inherent_tech_w: float = 0.40
    inherent_business_w: float = 0.25
    residual_inherent_w: float = 0.70
    residual_control_w: float = 0.30
    materiality_transaction_w: float = 0.50
    materiality_compliance_w: float = 0.25
    materiality_remediation_w: float = 0.25


SCORING_MODEL = ScoringModel()

GRADE_BANDS = [
    ("A", 1.0, 1.8),
    ("B", 1.9, 2.6),
    ("C", 2.7, 3.4),
    ("D", 3.5, 4.2),
    ("E", 4.3, 5.0),
]

RED_FLAG_CRITERIA = [
    "Compromise in progress or highly plausible",
    "Critical vulnerability supported by internal attack-path evidence or external scoreboards such as OWASP ASVS or CVSS",
    "Systemic ICAM weakness including weak hardening or broken authentication/authorization",
    "Absence of reliable recovery on critical services",
    "Restrictive OSS licensing or supply-chain blockers that can create contractual impasse",
    "Non-conformity exposing the client to substantial regulatory risk",
    "Architectural constraints that preclude secure or economically sustainable integration",
    "Severe concurrency or scalability defects that can lead to race conditions or attacker-driven escalation",
]


def score_grade(final_score: float) -> str:
    rounded = round(final_score, 1)
    for grade, minimum, maximum in GRADE_BANDS:
        if minimum <= rounded <= maximum:
            return grade
    if rounded < GRADE_BANDS[0][1]:
        return GRADE_BANDS[0][0]
    return GRADE_BANDS[-1][0]


def scoring_payload() -> dict[str, object]:
    return {
        "dimensions": SCORING_DIMENSIONS,
        "weights": {
            "inherent": {
                "likelihood": SCORING_MODEL.inherent_likelihood_w,
                "technical_impact": SCORING_MODEL.inherent_tech_w,
                "business_impact": SCORING_MODEL.inherent_business_w,
            },
            "residual": {
                "inherent_risk": SCORING_MODEL.residual_inherent_w,
                "control_weakness": SCORING_MODEL.residual_control_w,
            },
            "transaction_materiality": {
                "transaction_impact": SCORING_MODEL.materiality_transaction_w,
                "compliance_exposure": SCORING_MODEL.materiality_compliance_w,
                "remediation_effort": SCORING_MODEL.materiality_remediation_w,
            },
        },
        "grade_bands": [
            {"grade": grade, "min": minimum, "max": maximum}
            for grade, minimum, maximum in GRADE_BANDS
        ],
        "red_flag_criteria": RED_FLAG_CRITERIA,
        "classifications": CLASSIFICATIONS,
    }
