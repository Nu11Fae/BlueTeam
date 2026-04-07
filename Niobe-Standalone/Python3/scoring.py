from __future__ import annotations

from typing import Any

from .hld_baseline import CLASSIFICATIONS, RED_FLAG_CRITERIA, SCORING_DIMENSIONS
from .models import Finding
from .settings import AppSettings, get_settings


def _settings(settings: AppSettings | None) -> AppSettings:
    return settings or get_settings()


def inherent_risk(finding: Finding, settings: AppSettings | None = None) -> float:
    weights = _settings(settings).scoring_weights["inherent"]
    return round(
        weights["likelihood"] * finding.likelihood
        + weights["technical_impact"] * finding.technical_impact
        + weights["business_impact"] * finding.business_impact,
        2,
    )


def residual_risk(finding: Finding, settings: AppSettings | None = None) -> float:
    weights = _settings(settings).scoring_weights["residual"]
    return round(
        weights["inherent_risk"] * inherent_risk(finding, settings)
        + weights["control_weakness"] * finding.control_weakness,
        2,
    )


def transaction_materiality(finding: Finding, settings: AppSettings | None = None) -> float:
    weights = _settings(settings).scoring_weights["transaction_materiality"]
    return round(
        weights["transaction_impact"] * finding.transaction_impact
        + weights["compliance_exposure"] * finding.compliance_exposure
        + weights["remediation_effort"] * finding.remediation_effort,
        2,
    )


def final_score(finding: Finding, settings: AppSettings | None = None) -> float:
    return round(max(residual_risk(finding, settings), transaction_materiality(finding, settings)), 2)


def assign_grade(score: float, settings: AppSettings | None = None) -> str:
    thresholds = _settings(settings).grade_thresholds
    rounded = round(score, 1)
    for threshold in thresholds:
        minimum = float(threshold["min"])
        maximum = float(threshold["max"])
        if minimum <= rounded <= maximum:
            return str(threshold["grade"])
    if rounded < float(thresholds[0]["min"]):
        return str(thresholds[0]["grade"])
    return str(thresholds[-1]["grade"])


def _match_rule(rule: dict[str, Any], finding: Finding, grade: str) -> bool:
    conditions = rule.get("conditions", {})
    if not isinstance(conditions, dict):
        return False
    if "grade" in conditions and str(conditions["grade"]) != grade:
        return False
    if "grades" in conditions and grade not in {str(item) for item in conditions["grades"]}:
        return False
    if "min_transaction_impact" in conditions and finding.transaction_impact < int(conditions["min_transaction_impact"]):
        return False
    if "validation_status" in conditions and finding.validation_status != str(conditions["validation_status"]):
        return False
    if "finding_type" in conditions and finding.finding_type != str(conditions["finding_type"]):
        return False
    return True


def classify_finding(finding: Finding, settings: AppSettings | None = None) -> str:
    resolved_settings = _settings(settings)
    grade = assign_grade(final_score(finding, resolved_settings), resolved_settings)
    for rule in resolved_settings.classification_rules:
        if isinstance(rule, dict) and _match_rule(rule, finding, grade):
            return str(rule.get("classification", "Observation"))
    if grade == "E":
        return "Red Flag"
    if grade == "D" and finding.transaction_impact >= 4:
        return "Negotiation Relevant"
    if grade in {"C", "D"}:
        return "Integration Item"
    return "Observation"


def scoring_payload(settings: AppSettings | None = None) -> dict[str, object]:
    resolved_settings = _settings(settings)
    return {
        "dimensions": SCORING_DIMENSIONS,
        "weights": resolved_settings.scoring_weights,
        "grade_bands": resolved_settings.grade_thresholds,
        "red_flag_criteria": RED_FLAG_CRITERIA,
        "classifications": CLASSIFICATIONS,
        "classification_rules": resolved_settings.classification_rules,
    }
