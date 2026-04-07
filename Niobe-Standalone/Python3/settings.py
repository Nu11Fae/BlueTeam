from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .hld_baseline import CLASSIFICATIONS, COMPLIANCE_STANDARDS, GRADE_BANDS


ROOT = Path(os.environ["NIOBE_APP_ROOT"]).resolve() if os.environ.get("NIOBE_APP_ROOT") else Path(__file__).resolve().parent.parent
STORAGE_ROOT = ROOT / "storage"

DEFAULT_SCORING_WEIGHTS: dict[str, dict[str, float]] = {
    "inherent": {
        "likelihood": 0.35,
        "technical_impact": 0.40,
        "business_impact": 0.25,
    },
    "residual": {
        "inherent_risk": 0.70,
        "control_weakness": 0.30,
    },
    "transaction_materiality": {
        "transaction_impact": 0.50,
        "compliance_exposure": 0.25,
        "remediation_effort": 0.25,
    },
}

DEFAULT_GRADE_THRESHOLDS: list[dict[str, Any]] = [
    {"grade": grade, "min": minimum, "max": maximum}
    for grade, minimum, maximum in GRADE_BANDS
]

DEFAULT_CLASSIFICATION_RULES: list[dict[str, Any]] = [
    {"classification": "Red Flag", "conditions": {"grade": "E"}},
    {"classification": "Negotiation Relevant", "conditions": {"grade": "D", "min_transaction_impact": 4}},
    {"classification": "Integration Item", "conditions": {"grades": ["C", "D"]}},
    {"classification": "Observation", "conditions": {"grades": ["A", "B"]}},
]

DEFAULT_TOOL_TOGGLES = {
    "syft": True,
    "semgrep_code": True,
    "semgrep_sca": True,
    "gitleaks": True,
    "scancode": True,
    "sonarqube": False,
    "fossology": False,
    "tree_sitter": True,
    "dependency_check": True,
}

DEFAULT_COMPLIANCE_SCREENING = {
    "enabled": False,
    "frameworks": list(COMPLIANCE_STANDARDS),
}

DEFAULT_DEEP_REVIEW = {
    "enabled": True,
    "max_files_to_scan": 220,
    "max_assets": 14,
    "max_snippets_per_asset": 3,
    "context_radius": 3,
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _load_yaml_config(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"invalid Niobe config payload in {path}")
    return payload


def _default_config_payload() -> dict[str, Any]:
    return {
        "scoring_weights": DEFAULT_SCORING_WEIGHTS,
        "grade_thresholds": DEFAULT_GRADE_THRESHOLDS,
        "classification_rules": DEFAULT_CLASSIFICATION_RULES,
        "tools": DEFAULT_TOOL_TOGGLES,
        "compliance_screening": DEFAULT_COMPLIANCE_SCREENING,
        "deep_review": DEFAULT_DEEP_REVIEW,
        "compliance_frameworks": list(COMPLIANCE_STANDARDS),
    }


@dataclass(slots=True)
class AppSettings:
    database_url: str = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + str((STORAGE_ROOT / "niobe.db").resolve()),
    )
    api_host: str = os.environ.get("NIOBE_API_HOST", "0.0.0.0")
    api_port: int = int(os.environ.get("NIOBE_API_PORT", "8080"))
    auth_secret: str = os.environ.get("NIOBE_AUTH_SECRET", "")
    storage_root: Path = STORAGE_ROOT
    frontend_root: Path = ROOT / "ControlPlane_beta" / "web"
    template_root: Path = ROOT / "templates"
    prompt_root: Path = ROOT / "LLMs" / "prompts"
    seed_root: Path = ROOT / "templates"
    reference_root: Path = ROOT / "templates"
    reports_root: Path = ROOT / "reports"
    default_heartbeat_timeout: int = int(os.environ.get("NIOBE_HEARTBEAT_TIMEOUT", "90"))
    config_path: Path | None = field(
        default_factory=lambda: Path(os.environ["NIOBE_CONFIG_PATH"]).expanduser().resolve()
        if os.environ.get("NIOBE_CONFIG_PATH", "").strip()
        else None
    )
    scoring_weights: dict[str, dict[str, float]] = field(default_factory=lambda: _default_config_payload()["scoring_weights"])
    grade_thresholds: list[dict[str, Any]] = field(default_factory=lambda: list(_default_config_payload()["grade_thresholds"]))
    classification_rules: list[dict[str, Any]] = field(default_factory=lambda: list(_default_config_payload()["classification_rules"]))
    compliance_frameworks: list[str] = field(default_factory=lambda: list(COMPLIANCE_STANDARDS))
    compliance_screening_enabled: bool = False
    compliance_screening: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_COMPLIANCE_SCREENING))
    deep_review: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_DEEP_REVIEW))
    tool_toggles: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_TOOL_TOGGLES))

    def __post_init__(self) -> None:
        payload = _deep_merge(_default_config_payload(), _load_yaml_config(self.config_path))
        self.scoring_weights = payload["scoring_weights"]
        self.grade_thresholds = payload["grade_thresholds"]
        self.classification_rules = payload["classification_rules"]
        self.compliance_frameworks = list(payload.get("compliance_frameworks", COMPLIANCE_STANDARDS))
        self.compliance_screening = payload.get("compliance_screening", dict(DEFAULT_COMPLIANCE_SCREENING))
        self.deep_review = payload.get("deep_review", dict(DEFAULT_DEEP_REVIEW))
        if self.compliance_screening.get("frameworks"):
            self.compliance_frameworks = list(self.compliance_screening["frameworks"])
        else:
            self.compliance_screening["frameworks"] = list(self.compliance_frameworks)
        self.compliance_screening_enabled = bool(self.compliance_screening.get("enabled", False))
        self.tool_toggles = {
            key: bool(value)
            for key, value in payload.get("tools", DEFAULT_TOOL_TOGGLES).items()
        }
        for key in ("sonarqube", "fossology"):
            env_key = f"NIOBE_TOOL_{key.upper()}"
            env_val = os.environ.get(env_key, "").strip().lower()
            if env_val in {"1", "true", "yes", "on"}:
                self.tool_toggles[key] = True

    def ensure_dirs(self) -> None:
        standalone_mode = os.environ.get("NIOBE_STANDALONE_MODE", "").strip().lower() in {"1", "true", "yes", "on"}
        control_plane_mode = os.environ.get("NIOBE_CONTROL_PLANE_MODE", "").strip().lower() in {"1", "true", "yes", "on"}
        if control_plane_mode:
            for path in (
                self.storage_root,
                self.reports_root,
                self.storage_root / "uploads",
                self.storage_root / "deliverables",
            ):
                path.mkdir(parents=True, exist_ok=True)
            return
        if standalone_mode:
            return
        self.reports_root.mkdir(parents=True, exist_ok=True)

    def require_auth_secret(self) -> None:
        if self.auth_secret:
            return
        if self.database_url.startswith("sqlite:///"):
            self.auth_secret = secrets.token_urlsafe(48)
            return
        raise RuntimeError("NIOBE_AUTH_SECRET must be provided at runtime for the control plane stack")

    def tool_enabled(self, key: str, default: bool = True) -> bool:
        return bool(self.tool_toggles.get(key, default))

    def settings_payload(self) -> dict[str, Any]:
        return {
            "config_path": str(self.config_path) if self.config_path else None,
            "scoring_weights": self.scoring_weights,
            "grade_thresholds": self.grade_thresholds,
            "classification_rules": self.classification_rules,
            "compliance_frameworks": self.compliance_frameworks,
            "compliance_screening": self.compliance_screening,
            "deep_review": self.deep_review,
            "tools": self.tool_toggles,
        }

    def settings_hash(self) -> str:
        encoded = json.dumps(self.settings_payload(), sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def set_runtime_config(config_path: Path | None) -> None:
    if config_path is None:
        os.environ.pop("NIOBE_CONFIG_PATH", None)
        return
    os.environ["NIOBE_CONFIG_PATH"] = str(config_path.expanduser().resolve())


def get_settings() -> AppSettings:
    settings = AppSettings()
    settings.ensure_dirs()
    return settings
