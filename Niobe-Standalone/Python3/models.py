from __future__ import annotations

import re
from typing import Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator


FINDING_TYPES = (
    "Vulnerability",
    "Control Gap",
    "Configuration Issue",
    "Architecture Weakness",
    "Logic Defect",
    "Non-compliance",
)

VALIDATION_STATES = ("Candidate", "Validated")
CONFIDENCE_VALUES = ("High", "Medium", "Low")
COMPLIANCE_STATES = {"Gap", "Partial", "Aligned", "N/A"}
FINDING_ID_PATTERN = re.compile(r"^TLF-[A-Z0-9]+-\d{3}$")


def _normalize_text(value: object, fallback: str = "") -> str:
    text = str(value or fallback).strip()
    return re.sub(r"\s+", " ", text)


def _as_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"[\n;,]+", str(value))
    return [_normalize_text(item) for item in items if _normalize_text(item)]


class Finding(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    finding_id: str = Field(validation_alias=AliasChoices("finding_id", "id"))
    title: str
    finding_type: Literal[
        "Vulnerability",
        "Control Gap",
        "Configuration Issue",
        "Architecture Weakness",
        "Logic Defect",
        "Non-compliance",
    ] = "Control Gap"
    affected_asset: str = ""
    taxonomy: list[str] = Field(default_factory=list)
    description: str
    evidence_summary: str
    validation_status: Literal["Candidate", "Validated"] = "Candidate"
    evidence_confidence: Literal["High", "Medium", "Low"] = "Medium"
    likelihood: int = Field(default=3, ge=1, le=5)
    technical_impact: int = Field(default=3, ge=1, le=5)
    business_impact: int = Field(default=3, ge=1, le=5)
    control_weakness: int = Field(default=3, ge=1, le=5)
    compliance_exposure: int = Field(default=3, ge=1, le=5)
    remediation_effort: int = Field(default=3, ge=1, le=5)
    transaction_impact: int = Field(default=3, ge=1, le=5)
    classification: str | None = None
    suggested_action: str = "Place under tracked remediation."
    executive_description: str = ""
    key_evidence: str = ""
    compliance_map: dict[str, str] = Field(default_factory=dict)
    evidence_sources: list[str] = Field(default_factory=list)
    llm_only: bool = False

    @field_validator("finding_id", mode="before")
    @classmethod
    def validate_finding_id(cls, value: object) -> str:
        candidate = _normalize_text(value, "TLF-DA-001").upper()
        if not FINDING_ID_PATTERN.fullmatch(candidate):
            return "TLF-DA-001"
        return candidate

    @field_validator("title", "affected_asset", "description", "evidence_summary", "suggested_action", "executive_description", "key_evidence", mode="before")
    @classmethod
    def normalize_text_fields(cls, value: object) -> str:
        return _normalize_text(value)

    @field_validator("finding_type", mode="before")
    @classmethod
    def normalize_finding_type(cls, value: object) -> str:
        candidate = _normalize_text(value, "Control Gap").lower()
        mapping = {
            "vulnerability": "Vulnerability",
            "control gap": "Control Gap",
            "configuration issue": "Configuration Issue",
            "architecture weakness": "Architecture Weakness",
            "logic defect": "Logic Defect",
            "non-compliance": "Non-compliance",
            "non compliance": "Non-compliance",
        }
        return mapping.get(candidate, "Control Gap")

    @field_validator("validation_status", mode="before")
    @classmethod
    def normalize_validation_status(cls, value: object) -> str:
        candidate = _normalize_text(value, "Candidate").lower()
        return "Validated" if candidate == "validated" else "Candidate"

    @field_validator("evidence_confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, value: object) -> str:
        candidate = _normalize_text(value, "Medium").lower()
        mapping = {"high": "High", "medium": "Medium", "low": "Low"}
        return mapping.get(candidate, "Medium")

    @field_validator("taxonomy", mode="before")
    @classmethod
    def normalize_taxonomy(cls, value: object) -> list[str]:
        return _as_list(value)

    @field_validator("evidence_sources", mode="before")
    @classmethod
    def normalize_evidence_sources(cls, value: object) -> list[str]:
        return _as_list(value)

    @field_validator("compliance_map", mode="before")
    @classmethod
    def normalize_compliance_map(cls, value: object) -> dict[str, str]:
        if not isinstance(value, dict):
            return {}
        normalized: dict[str, str] = {}
        for key, raw in value.items():
            state = _normalize_text(raw, "N/A")
            normalized_state = next((item for item in COMPLIANCE_STATES if item.lower() == state.lower()), "N/A")
            normalized[_normalize_text(key)] = normalized_state
        return normalized

    @model_validator(mode="after")
    def apply_contestability_rules(self) -> "Finding":
        if not self.executive_description:
            self.executive_description = self.description
        if not self.key_evidence:
            self.key_evidence = self.evidence_summary
        if not self.affected_asset or not self.taxonomy:
            self.validation_status = "Candidate"
        if self.validation_status == "Candidate":
            self.llm_only = self.llm_only or not self.evidence_sources
        return self
