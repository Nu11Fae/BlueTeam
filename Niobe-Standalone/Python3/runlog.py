from __future__ import annotations

import json
import subprocess
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Finding
from .scoring import assign_grade, classify_finding, final_score
from .settings import AppSettings


def _git_commit(path: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return "no-git"


def _json_lookup(payload: Any, *keys: Any) -> str:
    current = payload
    for key in keys:
        if isinstance(key, int):
            if not isinstance(current, list) or key >= len(current):
                return "unknown"
            current = current[key]
            continue
        if not isinstance(current, dict):
            return "unknown"
        current = current.get(key)
    return str(current) if current else "unknown"


def collect_tool_versions(reports_dir: Path) -> list[dict[str, str]]:
    def read_payload(name: str) -> Any:
        path = reports_dir / name
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    syft_cdx = read_payload("sbom.cyclonedx.json")
    syft_json = read_payload("sbom.syft.json")
    semgrep_code = read_payload("semgrep-code.json")
    semgrep_sca = read_payload("semgrep-sca.json")
    gitleaks = read_payload("gitleaks.json")
    scancode = read_payload("scancode.json")
    sonarqube = read_payload("sonarqube.json")
    fossology = read_payload("fossology.json")
    return [
        {"name": "syft-cyclonedx", "version": _json_lookup(syft_cdx, "metadata", "tools", "components", 0, "version")},
        {"name": "syft-json", "version": _json_lookup(syft_json, "descriptor", "version")},
        {"name": "semgrep-code", "version": _json_lookup(semgrep_code, "version")},
        {"name": "semgrep-sca", "version": _json_lookup(semgrep_sca, "version")},
        {"name": "gitleaks", "version": _json_lookup(gitleaks, "version")},
        {"name": "scancode", "version": _json_lookup(scancode, "headers", 0, "tool_version")},
        {"name": "sonarqube", "version": _json_lookup(sonarqube, "scanner_version")},
        {"name": "fossology", "version": _json_lookup(fossology, "version")},
    ]


def build_run_log(
    *,
    run_root: Path,
    repo_path: Path,
    reports_dir: Path,
    settings: AppSettings,
    llm_provider: str,
    model_id: str,
    findings: list[Finding],
    duration_seconds: float,
) -> dict[str, object]:
    grade_distribution = Counter(assign_grade(final_score(finding, settings), settings) for finding in findings)
    classification_distribution = Counter(classify_finding(finding, settings) for finding in findings)
    return {
        "run_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "repo_path": str(repo_path),
        "repo_commit": _git_commit(repo_path),
        "tools_executed": collect_tool_versions(reports_dir),
        "model_id": model_id or llm_provider,
        "settings_hash": settings.settings_hash(),
        "findings_count": len(findings),
        "grades_distribution": dict(grade_distribution),
        "classification_distribution": dict(classification_distribution),
        "duration_seconds": round(duration_seconds, 2),
        "run_root": str(run_root),
    }


def write_run_log(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path
