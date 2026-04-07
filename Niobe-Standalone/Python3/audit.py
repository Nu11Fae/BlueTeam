from __future__ import annotations

import atexit
import contextlib
import json
import os
import re
import signal
import shutil
import subprocess
import tarfile
import threading
import time
import zipfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import httpx

from .claude import build_prompt, run_llm
from .deep_review import collect_deep_review_bundle
from .detect import RepoProfile, build_exclude_args, detect_repo_profile
from .hld_baseline import COMPLIANCE_STANDARDS, SECURITY_VIEW_STANDARDS
from .installer import AUDIT_RUNNER_IMAGE, ensure_audit_runner_image
from .metrics import collect_codebase_metrics
from .provenance import collect_manifest, sign_delivery, sign_directory_tree, write_manifest
from .reference_docs import load_reference_bundle
from .reporting import TITLE, _body_markdown_from_report, extract_report_sections, render_docx, render_pdf, render_report, render_supporting_pdf
from .risk_register import build_risk_score_artifact, export_risk_register, load_llm_findings
from .runlog import build_run_log, write_run_log
from .scoring import scoring_payload
from .settings import AppSettings, get_settings
from .tree_sitter_analysis import collect_tree_sitter_analysis


_active_containers: list[str] = []
_active_containers_lock = threading.Lock()
_cleanup_paths: list[Path] = []


def _register_container(container_id: str) -> None:
    with _active_containers_lock:
        _active_containers.append(container_id)


def _unregister_container(container_id: str) -> None:
    with _active_containers_lock:
        if container_id in _active_containers:
            _active_containers.remove(container_id)


def _clean_pycache(root: Path | None = None) -> None:
    target = root or Path(__file__).resolve().parent
    for cache_dir in target.rglob("__pycache__"):
        shutil.rmtree(cache_dir, ignore_errors=True)


def _clean_generated_metadata(root: Path | None = None) -> None:
    target = (root or Path(__file__).resolve().parent.parent).resolve()
    for name in ("niobe_digital_audit.egg-info",):
        path = target / name
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)


def _shutdown_handler(signum: int, frame: object) -> None:
    with _active_containers_lock:
        for cid in _active_containers:
            subprocess.run(["docker", "kill", cid], capture_output=True, check=False)
        _active_containers.clear()
    for path in _cleanup_paths:
        if path.exists() and path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
    _clean_pycache()
    _clean_generated_metadata()
    raise SystemExit(1)


signal.signal(signal.SIGINT, _shutdown_handler)
signal.signal(signal.SIGTERM, _shutdown_handler)


@dataclass(slots=True)
class AuditPaths:
    run_root: Path
    runtime: Path
    reports: Path
    delivery: Path
    signatures: Path


@dataclass(slots=True)
class PreparedAudit:
    paths: AuditPaths
    manifest_path: Path
    summary_path: Path
    prompt_path: Path
    context_path: Path
    llm_provider: str
    tool_results: dict[str, object]
    standalone: bool


@dataclass(slots=True)
class AuditResult:
    paths: AuditPaths
    manifest_path: Path
    attestation_path: Path
    summary_path: Path
    llm_provider: str
    llm_result: dict[str, object]
    tool_results: dict[str, object]
    standalone: bool


TOOL_RUNNERS = {"docker", "native"}
RUN_CONTEXT_FILE = "run-context.json"
SUMMARY_FILE = "audit-summary.json"
PROMPT_FILE = "llm-prompt.md"
LLM_OUTPUT_FILE = "llm-debrief.md"
RISK_REGISTER_PROMPT_FILE = "risk-register-prompt.md"
RISK_REGISTER_LLM_FILE = "risk-register.findings.json"
RISK_REGISTER_JSON_FILE = "risk_register.json"
RISK_REGISTER_WORKBOOK_FILE = "Risk Register.xlsx"
RISK_SCORE_ARTIFACT_FILE = "Risk Score Artifact.md"
OSS_PROVENANCE_FILE = "OSS Provenance Report (Copyleft Risk).md"
TREE_SITTER_FILE = "tree-sitter-analysis.json"
ATTESTATION_FILE = "activity-attestation.json"
CODEBASE_METRICS_FILE = "codebase-metrics.json"
MANIFEST_FILE = "evidence-manifest.json"
RUNTIME_DIR_NAME = ".runtime"
COMPLIANCE_FILE = "compliance-artifact.md"
COMPLIANCE_DELIVERY_FILE = "Compliance Artifact.md"
BUNDLE_FILE = "AI_DA.zip"
BUNDLE_SIGNATURE_FILE = "AI_DA.zip.asc"
TOOL_FINDINGS_FILE = "tool-findings.json"
DEEP_REVIEW_BUNDLE_FILE = "deep-review-bundle.json"
DEEP_REVIEW_PROMPT_FILE = "deep-review-prompt.md"
DEEP_REVIEW_LLM_FILE = "deep-review.findings.json"
VALIDATION_PROMPT_FILE = "validation-pass-prompt.md"
VALIDATION_OUTPUT_FILE = "validation-pass.json"
RUN_LOG_FILE = "run_log.json"
DELIVERY_MANIFEST_FILE = "manifest.json"
REPORT_MARKDOWN_FILE = "AI Technical Intelligence Review.md"
REPORT_DOCX_FILE = "AI Technical Intelligence Review.docx"
REPORT_PDF_FILE = "AI Technical Intelligence Review.pdf"
FAILBACK_PDF_FILE = "failback.pdf"

CLIENT_REPORT_ARTIFACTS = {
    "sbom.syft.json",
    "semgrep-code.json",
    "semgrep-sca.json",
    "gitleaks.json",
    "gitleaks.log",
    "scancode.json",
    "scancode.log",
    "sonarqube.json",
    "fossology.json",
    "dependency-check-report.json",
    "dependency-check-report.html",
}


def _now_utc() -> str:
    return datetime.now(UTC).isoformat()


def _notify(callback: Callable[[str, str], None] | None, message: str, level: str = "info") -> None:
    if callback:
        callback(message, level)


def _purge_legacy_delivery_layout(delivery: Path) -> None:
    legacy_reports = delivery / "reports"
    if legacy_reports.exists():
        shutil.rmtree(legacy_reports, ignore_errors=True)


def _reset_standalone_run_root(run_root: Path) -> None:
    if not run_root.exists():
        return
    for directory in (run_root / RUNTIME_DIR_NAME, run_root / "Reports", run_root / "Delivery"):
        shutil.rmtree(directory, ignore_errors=True)
    for artifact in run_root.glob("AI_DA.zip*"):
        with contextlib.suppress(OSError):
            artifact.unlink()


def prepare_run(target: Path, standalone: bool = False) -> AuditPaths:
    settings = get_settings()
    configured_run_root = os.environ.get("NIOBE_RUN_ROOT", "").strip()
    if standalone:
        run_root = Path(configured_run_root).expanduser().resolve() if configured_run_root else (target / "temp-delivery")
        _reset_standalone_run_root(run_root)
    else:
        run_root = settings.reports_root / time.strftime("run-%Y%m%d-%H%M%S")
    runtime = run_root / RUNTIME_DIR_NAME
    reports = run_root / "Reports"
    delivery = run_root / "Delivery"
    signatures = delivery / "signatures"
    for path in (run_root, runtime, reports, delivery, signatures):
        path.mkdir(parents=True, exist_ok=True)
    _purge_legacy_delivery_layout(delivery)
    return AuditPaths(run_root=run_root, runtime=runtime, reports=reports, delivery=delivery, signatures=signatures)


def load_run_paths(run_root: Path) -> AuditPaths:
    run_root = run_root.resolve()
    runtime = run_root / RUNTIME_DIR_NAME
    reports = run_root / "Reports"
    delivery = run_root / "Delivery"
    signatures = delivery / "signatures"
    for path in (run_root, runtime, reports, delivery, signatures):
        path.mkdir(parents=True, exist_ok=True)
    _purge_legacy_delivery_layout(delivery)
    return AuditPaths(run_root=run_root, runtime=runtime, reports=reports, delivery=delivery, signatures=signatures)


def _runtime_file(paths: AuditPaths, name: str) -> Path:
    return paths.runtime / name


def _cleanup_runtime(paths: AuditPaths) -> None:
    keep_runtime = os.environ.get("NIOBE_KEEP_RUNTIME", "").strip().lower()
    if keep_runtime in {"1", "true", "yes", "on"}:
        return
    shutil.rmtree(paths.runtime, ignore_errors=True)
    _clean_pycache()
    _clean_generated_metadata()


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_json_loose(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    raw_text = path.read_text(encoding="utf-8").strip()
    if not raw_text:
        return {}
    try:
        payload = json.loads(raw_text)
        return payload if isinstance(payload, dict) else {}
    except json.JSONDecodeError:
        match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", raw_text, flags=re.DOTALL)
        if match:
            try:
                payload = json.loads(match.group(1))
                return payload if isinstance(payload, dict) else {}
            except json.JSONDecodeError:
                return {}
    return {}


def _run_tool(cmd: list[str], output_path: Path) -> dict[str, object]:
    started_ns = time.monotonic_ns()
    started_at = _now_utc()
    if not cmd:
        if not output_path.exists():
            output_path.write_text("tool skipped\n", encoding="utf-8")
        return {
            "command": [],
            "returncode": 0,
            "output": str(output_path),
            "ok": True,
            "skipped": True,
            "started_at_utc": started_at,
            "completed_at_utc": _now_utc(),
            "duration_ms": round((time.monotonic_ns() - started_ns) / 1_000_000, 2),
        }
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        output_path.write_text(result.stdout or result.stderr, encoding="utf-8")
        return {
            "command": cmd,
            "returncode": result.returncode,
            "output": str(output_path),
            "ok": result.returncode == 0,
            "started_at_utc": started_at,
            "completed_at_utc": _now_utc(),
            "duration_ms": round((time.monotonic_ns() - started_ns) / 1_000_000, 2),
        }
    except OSError as exc:
        output_path.write_text(str(exc), encoding="utf-8")
        return {
            "command": cmd,
            "returncode": 127,
            "output": str(output_path),
            "ok": False,
            "started_at_utc": started_at,
            "completed_at_utc": _now_utc(),
            "duration_ms": round((time.monotonic_ns() - started_ns) / 1_000_000, 2),
            "error": str(exc),
        }


def _emit(url: str | None, token: str | None, endpoint: str, payload: dict[str, object]) -> None:
    if not url or not token:
        return
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                f"{url.rstrip('/')}{endpoint}",
                headers={"X-Agent-Key": token},
                json=payload,
            )
            response.raise_for_status()
    except httpx.HTTPError:
        return


def _copy_if_exists(src: Path, dst: Path) -> None:
    if src.exists():
        shutil.copy2(src, dst)


def _host_target_root() -> Path | None:
    raw = os.environ.get("NIOBE_HOST_TARGET", "").strip()
    if not raw:
        return None
    return Path(raw).resolve()


def _host_run_root() -> Path | None:
    raw = os.environ.get("NIOBE_HOST_RUN_ROOT", "").strip()
    if not raw:
        return None
    return Path(raw).resolve()


def _display_path(path: Path | str) -> str:
    candidate = Path(str(path))
    host_target = _host_target_root()
    host_run_root = _host_run_root()
    try:
        scan_root = Path("/scan")
        if host_target and candidate.is_absolute() and candidate == scan_root:
            return str(host_target)
        if host_target and candidate.is_absolute() and scan_root in candidate.parents:
            return str(host_target / candidate.relative_to(scan_root))
    except ValueError:
        pass
    try:
        delivery_root = Path("/delivery")
        if host_run_root and candidate.is_absolute() and candidate == delivery_root:
            return str(host_run_root)
        if host_run_root and candidate.is_absolute() and delivery_root in candidate.parents:
            return str(host_run_root / candidate.relative_to(delivery_root))
    except ValueError:
        pass
    return str(candidate)


def _tool_label(name: str) -> str:
    labels = {
        "syft-cyclonedx": "CycloneDX SBOM",
        "syft-json": "Syft JSON SBOM",
        "semgrep-code": "Semgrep Code report",
        "semgrep-sca": "Semgrep Supply Chain report",
        "gitleaks": "Gitleaks secret scan",
        "scancode": "ScanCode compliance report",
        "sonarqube": "SonarQube CLI evidence",
        "fossology": "FOSSology evidence",
        "dependency-check-update": "OWASP Dependency-Check NVD update",
        "dependency-check": "OWASP Dependency-Check scan",
    }
    return labels.get(name, name)


def _tool_started_message(name: str) -> str:
    return f"Starting {_tool_label(name)}."


def _tool_completed_message(name: str, result: dict[str, object], preferred_artifact: Path | None = None) -> tuple[str, str]:
    raw_output = str(result.get("output", "")).strip()
    output_ref = preferred_artifact if preferred_artifact and preferred_artifact.exists() else Path(raw_output) if raw_output else (preferred_artifact or Path("."))
    displayed = _display_path(output_ref)
    label = _tool_label(name)
    if result.get("skipped"):
        return (f"{label} skipped: {displayed}", "warning")
    if result.get("ok"):
        return (f"{label} generated successfully: {displayed}", "success")
    return (f"{label} failed: {displayed}", "error")


def _create_evidence_bundle(run_root: Path, delivery_dir: Path, reports_dir: Path) -> Path:
    bundle_path = run_root / BUNDLE_FILE
    if bundle_path.exists():
        bundle_path.unlink()
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in sorted(run_root.rglob("*")):
            if item.is_dir():
                continue
            # Skip the bundle itself and its signatures to avoid recursion
            if item == bundle_path:
                continue
            if item.name.endswith((".asc", ".ots")) and item.stem.startswith(BUNDLE_FILE):
                continue
            archive.write(item, arcname=str(item.relative_to(run_root)))
    return bundle_path


def _extract_markdown_section(markdown_text: str, section_number: str) -> str:
    for section in extract_report_sections(markdown_text):
        title = str(section.get("title", ""))
        if title.startswith(f"{section_number}. "):
            return str(section.get("body_markdown", "")).strip()
    return ""


def _write_supporting_markdown_artifact(
    output_path: Path,
    title: str,
    section_body: str,
    evidence_lines: list[str],
    baseline_lines: list[str] | None = None,
) -> Path:
    lines = [f"# {title}", ""]
    if baseline_lines:
        lines.extend(["## HLD Baseline", ""])
        lines.extend([f"- {line}" for line in baseline_lines])
        lines.append("")
    if section_body:
        lines.extend(["## Analytical Body", "", section_body.strip(), ""])
    lines.extend(["## Supporting Evidence", ""])
    lines.extend([f"- {line}" for line in evidence_lines])
    output_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return output_path


def _stub_artifact(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _safe_project_key(project_name: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in project_name.lower()).strip("-") or "digital-audit"


def _auth_headers(token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def _container_command(
    image: str,
    target: Path,
    reports: Path,
    args: list[str],
    env: dict[str, str] | None = None,
) -> list[str]:
    platform = os.environ.get("NIOBE_AUDIT_PLATFORM", "").strip()
    command = [
        "docker",
        "run",
        "--rm",
    ]
    if platform:
        command.extend(["--platform", platform])
    command.extend(
        [
            "-v",
            f"{target}:/scan:ro",
            "-v",
            f"{reports}:/reports",
        ]
    )
    for key, value in (env or {}).items():
        if value:
            command.extend(["-e", f"{key}={value}"])
    command.append(image)
    command.extend(args)
    return command


def _delivery_kind(relative_path: Path) -> str:
    if relative_path.parts and relative_path.parts[0] == "signatures":
        return "signature"
    name = relative_path.name.lower()
    if name in {MANIFEST_FILE, DELIVERY_MANIFEST_FILE}:
        return "manifest"
    if name == ATTESTATION_FILE:
        return "attestation"
    if name == CODEBASE_METRICS_FILE:
        return "codebase-metrics"
    if name == "semgrep-code.json":
        return "semgrep-code"
    if name == "semgrep-sca.json":
        return "semgrep-sca"
    if name == "gitleaks.json":
        return "gitleaks"
    if name == "scancode.json":
        return "scancode"
    if name == "sonarqube.json":
        return "sonarqube"
    if name == "fossology.json":
        return "fossology"
    if name == "dependency-check-report.json":
        return "dependency-check"
    if name == "sbom.cyclonedx.json":
        return "sbom-cyclonedx"
    if name == "sbom.syft.json":
        return "sbom-syft"
    if name == "ai technical intelligence review.docx":
        return "review-docx"
    if name == "ai technical intelligence review.pdf":
        return "review-pdf"
    if name == "ai technical intelligence review.html":
        return "review-html"
    if name == "ai technical intelligence review.md":
        return "review-markdown"
    if name == "risk register.xlsx":
        return "risk-register"
    if name == RISK_REGISTER_JSON_FILE.lower():
        return "risk-register-json"
    if name == "risk score artifact.md":
        return "risk-score-artifact"
    if name == "oss provenance report (copyleft risk).md":
        return "oss-provenance-report"
    if name == "oss provenance report (copyleft risk).pdf":
        return "oss-provenance-report-pdf"
    if name == "compliance artifact.md":
        return "compliance-artifact"
    if name == "compliance artifact.pdf":
        return "compliance-artifact-pdf"
    if name == "tree-sitter-analysis.json":
        return "tree-sitter-analysis"
    if name == DEEP_REVIEW_BUNDLE_FILE.lower():
        return "deep-review-bundle"
    if name == DEEP_REVIEW_PROMPT_FILE.lower():
        return "deep-review-prompt"
    if name == DEEP_REVIEW_LLM_FILE.lower():
        return "deep-review-findings"
    if name == RUN_LOG_FILE.lower():
        return "run-log"
    if name == BUNDLE_FILE.lower():
        return "evidence-bundle"
    if name == BUNDLE_SIGNATURE_FILE.lower():
        return "evidence-bundle-signature"
    if name.endswith(".xlsx") and "risk" in name:
        return "risk-register"
    if name.endswith(".xlsx") and "gantt" in name:
        return "planning-workbook"
    return relative_path.suffix.lstrip(".") or "artifact"


def _tool_command(
    tool_runner: str,
    audit_image: str,
    target: Path,
    reports: Path,
    args: list[str],
    env: dict[str, str] | None = None,
) -> list[str]:
    if tool_runner == "docker":
        return _container_command(audit_image, target, reports, args, env)
    return args


def _tool_enabled(settings: AppSettings, key: str) -> bool:
    return settings.tool_enabled(key, default=True)


def _append_tool_finding(index: dict[str, list[dict[str, object]]], path_value: str, payload: dict[str, object]) -> None:
    normalized_path = path_value.strip().replace("\\", "/")
    if not normalized_path:
        return
    index.setdefault(normalized_path, []).append(payload)


def _extract_tool_findings(reports: Path) -> dict[str, list[dict[str, object]]]:
    findings: dict[str, list[dict[str, object]]] = {}

    semgrep_path = reports / "semgrep-code.json"
    if semgrep_path.exists():
        try:
            payload = json.loads(semgrep_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
        for item in payload.get("results", []):
            if not isinstance(item, dict):
                continue
            taxonomy = []
            metadata = item.get("extra", {}).get("metadata", {}) if isinstance(item.get("extra"), dict) else {}
            for key in ("cwe", "owasp"):
                value = metadata.get(key)
                if isinstance(value, list):
                    taxonomy.extend(str(entry) for entry in value if entry)
                elif value:
                    taxonomy.append(str(value))
            _append_tool_finding(
                findings,
                str(item.get("path", "")),
                {
                    "tool": "semgrep-code",
                    "path": str(item.get("path", "")),
                    "rule": str(item.get("check_id", "")),
                    "summary": str(item.get("extra", {}).get("message", "")) if isinstance(item.get("extra"), dict) else "",
                    "taxonomy": taxonomy,
                },
            )

    semgrep_sca_path = reports / "semgrep-sca.json"
    if semgrep_sca_path.exists():
        try:
            payload = json.loads(semgrep_sca_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
        for item in payload.get("results", []):
            if not isinstance(item, dict):
                continue
            _append_tool_finding(
                findings,
                str(item.get("path", "")),
                {
                    "tool": "semgrep-sca",
                    "path": str(item.get("path", "")),
                    "rule": str(item.get("check_id", "")),
                    "summary": str(item.get("extra", {}).get("message", "")) if isinstance(item.get("extra"), dict) else "",
                    "taxonomy": [],
                },
            )

    gitleaks_path = reports / "gitleaks.json"
    if gitleaks_path.exists():
        try:
            payload = json.loads(gitleaks_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
        leaks = payload if isinstance(payload, list) else payload.get("findings", [])
        for item in leaks:
            if not isinstance(item, dict):
                continue
            path_value = str(item.get("File") or item.get("file") or item.get("path") or "")
            taxonomy = [str(item.get("RuleID") or item.get("ruleID") or item.get("rule_id") or "gitleaks")]
            _append_tool_finding(
                findings,
                path_value,
                {
                    "tool": "gitleaks",
                    "path": path_value,
                    "rule": taxonomy[0],
                    "summary": str(item.get("Description") or item.get("description") or "secret pattern detected"),
                    "taxonomy": taxonomy,
                },
            )

    scancode_path = reports / "scancode.json"
    if scancode_path.exists():
        try:
            payload = json.loads(scancode_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
        for item in payload.get("files", []):
            if not isinstance(item, dict):
                continue
            licenses = item.get("license_detections") or item.get("licenses") or []
            if not licenses:
                continue
            taxonomy = []
            for entry in licenses:
                if not isinstance(entry, dict):
                    continue
                expression = entry.get("license_expression") or entry.get("spdx_license_expression")
                if expression:
                    taxonomy.append(str(expression))
            _append_tool_finding(
                findings,
                str(item.get("path", "")),
                {
                    "tool": "scancode",
                    "path": str(item.get("path", "")),
                    "title": "OSS/license evidence",
                    "summary": ", ".join(taxonomy) or "license evidence available",
                    "taxonomy": taxonomy,
                },
            )

    sonarqube_path = reports / "sonarqube.json"
    if sonarqube_path.exists():
        try:
            payload = json.loads(sonarqube_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
        for item in payload.get("issues", []):
            if not isinstance(item, dict):
                continue
            component = str(item.get("component", ""))
            path_value = component.split(":", 1)[1] if ":" in component else component
            taxonomy = [str(item.get("rule", ""))] if item.get("rule") else []
            _append_tool_finding(
                findings,
                path_value,
                {
                    "tool": "sonarqube",
                    "path": path_value,
                    "rule": str(item.get("rule", "")),
                    "summary": str(item.get("message", "")),
                    "taxonomy": taxonomy,
                },
            )
    return findings


def _semgrep_supports_supply_chain(
    tool_runner: str,
    audit_image: str,
    target: Path,
    reports: Path,
) -> bool:
    help_cmd = _tool_command(
        tool_runner,
        audit_image,
        target,
        reports,
        ["sh", "-lc", "semgrep scan --help 2>/dev/null"],
    )
    try:
        result = subprocess.run(help_cmd, capture_output=True, text=True, check=False)
    except OSError:
        return False
    return "--supply-chain" in result.stdout


def _run_sonarqube_suite(
    target: Path,
    reports: Path,
    project_name: str,
    tool_runner: str,
    audit_image: str,
) -> dict[str, object]:
    sonar_host = os.environ.get("SONAR_HOST_URL")
    sonar_token = os.environ.get("SONAR_TOKEN", "")
    if not sonar_host:
        artifact = _stub_artifact(
            reports / "sonarqube.json",
            {"skipped": True, "reason": "SONAR_HOST_URL not set; set SONAR_HOST_URL to enable SonarQube analysis"},
        )
        return {"command": [], "returncode": 0, "output": str(artifact), "ok": True, "artifact_ready": True}

    # Connectivity check: verify the SonarQube server is reachable before running the scanner
    try:
        with httpx.Client(timeout=10.0) as probe:
            health = probe.get(f"{sonar_host.rstrip('/')}/api/system/status", headers=_auth_headers(sonar_token))
            if health.status_code != 200:
                artifact = _stub_artifact(
                    reports / "sonarqube.json",
                    {"skipped": True, "reason": f"SonarQube server returned HTTP {health.status_code} on connectivity check"},
                )
                return {"command": [], "returncode": 0, "output": str(artifact), "ok": True, "artifact_ready": True}
    except (httpx.HTTPError, OSError) as exc:
        artifact = _stub_artifact(
            reports / "sonarqube.json",
            {"skipped": True, "reason": f"SonarQube server unreachable: {exc}"},
        )
        return {"command": [], "returncode": 0, "output": str(artifact), "ok": True, "artifact_ready": True}

    project_key = _safe_project_key(project_name)
    log_path = reports / "sonar-scanner.log"
    scan_root = "/scan" if tool_runner == "docker" else str(target)
    scanner_cmd = [
        "sonar-scanner",
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.sources={scan_root}",
        f"-Dsonar.host.url={sonar_host}",
        f"-Dsonar.token={sonar_token}",
    ]
    scanner_timeout = int(os.environ.get("NIOBE_SONAR_TIMEOUT", "600"))
    tool_cmd = _tool_command(tool_runner, audit_image, target, reports, scanner_cmd)
    started_ns = time.monotonic_ns()
    started_at = _now_utc()
    try:
        proc = subprocess.run(tool_cmd, capture_output=True, text=True, timeout=scanner_timeout)
        log_path.write_text(proc.stdout or proc.stderr, encoding="utf-8")
        result: dict[str, object] = {
            "command": tool_cmd,
            "returncode": proc.returncode,
            "output": str(log_path),
            "ok": proc.returncode == 0,
            "started_at_utc": started_at,
            "completed_at_utc": _now_utc(),
            "duration_ms": round((time.monotonic_ns() - started_ns) / 1_000_000, 2),
        }
    except subprocess.TimeoutExpired:
        log_path.write_text(f"sonar-scanner timed out after {scanner_timeout}s\n", encoding="utf-8")
        result = {
            "command": tool_cmd,
            "returncode": 124,
            "output": str(log_path),
            "ok": False,
            "started_at_utc": started_at,
            "completed_at_utc": _now_utc(),
            "duration_ms": round((time.monotonic_ns() - started_ns) / 1_000_000, 2),
            "error": f"timeout after {scanner_timeout}s",
        }
    except OSError as exc:
        log_path.write_text(str(exc), encoding="utf-8")
        result = {
            "command": tool_cmd,
            "returncode": 127,
            "output": str(log_path),
            "ok": False,
            "started_at_utc": started_at,
            "completed_at_utc": _now_utc(),
            "duration_ms": round((time.monotonic_ns() - started_ns) / 1_000_000, 2),
            "error": str(exc),
        }
    payload: dict[str, object] = {
        "project_key": project_key,
        "log_path": str(log_path),
        "scanner_ok": result["ok"],
        "scanner_version": "unknown",
    }
    if log_path.exists():
        match = re.search(r"SonarScanner\s+([^\s]+)", log_path.read_text(encoding="utf-8", errors="ignore"))
        if match:
            payload["scanner_version"] = match.group(1)
    try:
        with httpx.Client(timeout=20.0) as client:
            headers = _auth_headers(sonar_token)
            issues = client.get(
                f"{sonar_host.rstrip('/')}/api/issues/search",
                params={"componentKeys": project_key, "ps": 200},
                headers=headers,
            )
            measures = client.get(
                f"{sonar_host.rstrip('/')}/api/measures/component",
                params={
                    "component": project_key,
                    "metricKeys": "bugs,vulnerabilities,code_smells,coverage,duplicated_lines_density,complexity",
                },
                headers=headers,
            )
            quality_gate = client.get(
                f"{sonar_host.rstrip('/')}/api/qualitygates/project_status",
                params={"projectKey": project_key},
                headers=headers,
            )
            if issues.status_code == 200:
                payload["issues"] = issues.json().get("issues", [])
            if measures.status_code == 200:
                payload["measures"] = measures.json().get("component", {}).get("measures", [])
            if quality_gate.status_code == 200:
                payload["quality_gate"] = quality_gate.json().get("projectStatus", {})
    except httpx.HTTPError as exc:
        payload["api_error"] = str(exc)
    # Ensure the artifact is always created, even if empty, so downstream never crashes
    artifact = _stub_artifact(reports / "sonarqube.json", payload)
    result["artifact_ready"] = artifact.exists() and artifact.stat().st_size > 0
    result["output"] = str(artifact)
    return result


def _tar_target(target: Path, archive_path: Path) -> Path:
    excluded = {"temp-delivery", "Delivery", "Reports", "reports", ".git", "__pycache__"}
    with tarfile.open(archive_path, "w:gz") as tar:
        def _filter(member: tarfile.TarInfo) -> tarfile.TarInfo | None:
            parts = Path(member.name).parts
            if any(part in excluded for part in parts):
                return None
            return member

        tar.add(target, arcname=target.name, filter=_filter)
    return archive_path


def _poll_fossology_jobs(client: httpx.Client, base_url: str, token: str, upload_id: int, timeout_seconds: int = 900) -> list[dict[str, object]]:
    started = time.monotonic()
    last_jobs: list[dict[str, object]] = []
    while time.monotonic() - started < timeout_seconds:
        response = client.get(
            f"{base_url}/repo/api/v1/jobs",
            params={"upload": upload_id},
            headers=_auth_headers(token),
        )
        response.raise_for_status()
        last_jobs = response.json()
        if last_jobs and all(job.get("status") == "Completed" for job in last_jobs):
            return last_jobs
        time.sleep(5)
    return last_jobs


def _run_fossology_suite(target: Path, reports: Path, project_name: str) -> dict[str, object]:
    base_url = os.environ.get("FOSSOLOGY_URL")
    token = os.environ.get("FOSSOLOGY_TOKEN")
    folder_id = os.environ.get("FOSSOLOGY_FOLDER_ID", "1")
    if not (base_url and token):
        artifact = _stub_artifact(
            reports / "fossology.json",
            {"skipped": True, "reason": "FOSSOLOGY_URL or FOSSOLOGY_TOKEN missing"},
        )
        return {"command": [], "returncode": 0, "output": str(artifact), "ok": True, "artifact_ready": True}

    archive_path = reports / "fossology-upload.tar.gz"
    _tar_target(target, archive_path)
    started_ns = time.monotonic_ns()
    started_at = _now_utc()
    payload: dict[str, object] = {"archive": str(archive_path), "started_at_utc": started_at}
    try:
        with httpx.Client(timeout=60.0) as client:
            with archive_path.open("rb") as handle:
                upload = client.post(
                    f"{base_url.rstrip('/')}/repo/api/v1/uploads",
                    headers={
                        **_auth_headers(token),
                        "folderId": folder_id,
                        "uploadDescription": f"Digital Audit upload for {project_name}",
                        "uploadType": "file",
                        "public": "public",
                    },
                    files={"fileInput": (archive_path.name, handle, "application/gzip")},
                )
            upload.raise_for_status()
            upload_id = int(upload.json()["message"])
            payload["upload_id"] = upload_id
            schedule = client.post(
                f"{base_url.rstrip('/')}/repo/api/v1/jobs",
                headers={
                    **_auth_headers(token),
                    "folderId": folder_id,
                    "uploadId": str(upload_id),
                },
                json={
                    "analysis": {
                        "bucket": True,
                        "copyright_email_author": True,
                        "ecc": True,
                        "keyword": True,
                        "mime": True,
                        "monk": True,
                        "nomos": True,
                        "package": True,
                    },
                    "decider": {
                        "nomos_monk": True,
                        "bulk_reused": True,
                        "new_scanner": True,
                    },
                },
            )
            schedule.raise_for_status()
            payload["job_id"] = schedule.json()["message"]
            payload["jobs"] = _poll_fossology_jobs(client, base_url.rstrip("/"), token, upload_id)
            summary = client.get(
                f"{base_url.rstrip('/')}/repo/api/v1/uploads/{upload_id}/summary",
                headers=_auth_headers(token),
            )
            licenses = client.get(
                f"{base_url.rstrip('/')}/repo/api/v1/uploads/{upload_id}/licenses",
                params={"agent": "nomos,monk,ojo", "containers": "true"},
                headers=_auth_headers(token),
            )
            payload["summary"] = summary.json() if summary.status_code == 200 else {"status_code": summary.status_code}
            payload["licenses"] = licenses.json() if licenses.status_code == 200 else {"status_code": licenses.status_code}
            report_trigger = client.get(
                f"{base_url.rstrip('/')}/repo/api/v1/report",
                headers={
                    **_auth_headers(token),
                    "reportFormat": "unifiedreport",
                    "uploadId": str(upload_id),
                },
            )
            if report_trigger.status_code == 200:
                report_path = report_trigger.json().get("message", "")
                payload["report_path"] = report_path
                if report_path:
                    download_target = report_path if report_path.startswith("http") else f"{base_url.rstrip('/')}/{report_path.lstrip('/')}"
                    download = client.get(download_target)
                    if download.status_code == 200:
                        report_file = reports / "fossology-unifiedreport.txt"
                        report_file.write_bytes(download.content)
                        payload["report_file"] = str(report_file)
    except (httpx.HTTPError, ValueError) as exc:
        payload["error"] = str(exc)
    payload["completed_at_utc"] = _now_utc()
    artifact = _stub_artifact(reports / "fossology.json", payload)
    return {
        "command": ["fossology-rest"],
        "returncode": 0 if "error" not in payload else 1,
        "output": str(artifact),
        "ok": "error" not in payload,
        "artifact_ready": artifact.exists() and artifact.stat().st_size > 0,
        "duration_ms": round((time.monotonic_ns() - started_ns) / 1_000_000, 2),
        "started_at_utc": started_at,
        "completed_at_utc": _now_utc(),
    }


def _upload_delivery(control_plane_url: str | None, agent_key: str | None, delivery_dir: Path) -> None:
    if not control_plane_url or not agent_key:
        return
    try:
        with httpx.Client(timeout=30.0) as client:
            for artifact in sorted(delivery_dir.rglob("*")):
                if artifact.is_dir():
                    continue
                relative_path = artifact.relative_to(delivery_dir)
                if any(part.startswith(".") for part in relative_path.parts):
                    continue
                with artifact.open("rb") as handle:
                    response = client.post(
                        f"{control_plane_url.rstrip('/')}/api/deliverables/upload",
                        headers={"X-Agent-Key": agent_key},
                        data={"kind": _delivery_kind(relative_path)},
                        files={"file": (relative_path.as_posix(), handle, "application/octet-stream")},
                    )
                    response.raise_for_status()
    except httpx.HTTPError:
        return


def _tool_plan(
    target: Path,
    profile: RepoProfile,
    reports: Path,
    tool_runner: str,
    audit_image: str,
    settings: AppSettings,
) -> list[tuple[str, list[str], Path, Path]]:
    exclude_args = build_exclude_args(profile)
    scan_root = "/scan" if tool_runner == "docker" else str(target)
    reports_root = "/reports" if tool_runner == "docker" else str(reports)
    syft_excludes: list[str] = []
    for excluded in sorted({".git", "temp-delivery", "Reports", "reports", "Delivery"} | {path.name for path in profile.candidate_exclusions}):
        syft_excludes.extend(["--exclude", f"**/{excluded}/**"])
    scancode_ignores: list[str] = []
    for excluded in sorted({".git", "temp-delivery", "Reports", "reports", "Delivery"} | {path.name for path in profile.candidate_exclusions}):
        scancode_ignores.extend(["--ignore", f"*/{excluded}/*"])
    semgrep_sca_artifact = reports / "semgrep-sca.json"
    if _tool_enabled(settings, "semgrep_sca") and _semgrep_supports_supply_chain(tool_runner, audit_image, target, reports):
        semgrep_sca_command = _tool_command(
            tool_runner,
            audit_image,
            target,
            reports,
            ["semgrep", "scan", "--config", "auto", "--json", "--supply-chain", *exclude_args, scan_root],
        )
    else:
        _stub_artifact(
            semgrep_sca_artifact,
            {
                "skipped": True,
                "reason": "installed Semgrep CLI does not expose --supply-chain" if _tool_enabled(settings, "semgrep_sca") else "disabled by configuration",
                "coverage_state": "partial",
            },
        )
        semgrep_sca_command = []
    gitleaks_artifact = reports / "gitleaks.json"
    plan: list[tuple[str, list[str], Path, Path]] = []
    if _tool_enabled(settings, "syft"):
        plan.extend(
            [
                (
                    "syft-cyclonedx",
                    _tool_command(
                        tool_runner,
                        audit_image,
                        target,
                        reports,
                        ["syft", f"dir:{scan_root}", *syft_excludes, "-o", "cyclonedx-json"],
                    ),
                    reports / "sbom.cyclonedx.json",
                    reports / "sbom.cyclonedx.json",
                ),
                (
                    "syft-json",
                    _tool_command(
                        tool_runner,
                        audit_image,
                        target,
                        reports,
                        ["syft", f"dir:{scan_root}", *syft_excludes, "-o", "json"],
                    ),
                    reports / "sbom.syft.json",
                    reports / "sbom.syft.json",
                ),
            ]
        )
    if _tool_enabled(settings, "semgrep_code"):
        plan.append(
            (
                "semgrep-code",
                _tool_command(
                    tool_runner,
                    audit_image,
                    target,
                    reports,
                    ["semgrep", "scan", "--config", "auto", "--json", *exclude_args, scan_root],
                ),
                reports / "semgrep-code.json",
                reports / "semgrep-code.json",
            )
        )
    plan.append(("semgrep-sca", semgrep_sca_command, semgrep_sca_artifact, semgrep_sca_artifact))
    if _tool_enabled(settings, "gitleaks"):
        plan.append(
            (
                "gitleaks",
                _tool_command(
                    tool_runner,
                    audit_image,
                    target,
                    reports,
                    [
                        "gitleaks",
                        "detect",
                        "--source",
                        scan_root,
                        "--no-git",
                        "--report-format",
                        "json",
                        "--report-path",
                        f"{reports_root}/gitleaks.json",
                        "--no-banner",
                        "--redact",
                        "--exit-code",
                        "0",
                    ],
                ),
                reports / "gitleaks.log",
                gitleaks_artifact,
            )
        )
    else:
        _stub_artifact(gitleaks_artifact, {"skipped": True, "reason": "disabled by configuration"})
    if _tool_enabled(settings, "scancode"):
        plan.append(
            (
                "scancode",
                _tool_command(
                    tool_runner,
                    audit_image,
                    target,
                    reports,
                    ["scancode", "--license", "--copyright", *scancode_ignores, "--json-pp", f"{reports_root}/scancode.json", scan_root],
                ),
                reports / "scancode.log",
                reports / "scancode.json",
            )
        )
    if _tool_enabled(settings, "dependency_check"):
        project_key = "".join(c if c.isalnum() else "-" for c in str(target.name).lower()).strip("-") or "digital-audit"
        nvd_data = os.environ.get("NIOBE_NVD_DATA", "/opt/dependency-check-data")
        plan.append(
            (
                "dependency-check-update",
                _tool_command(
                    tool_runner,
                    audit_image,
                    target,
                    reports,
                    ["dependency-check", "--updateonly", "--data", nvd_data],
                ),
                reports / "dependency-check-update.log",
                reports / "dependency-check-update.log",
            )
        )
        plan.append(
            (
                "dependency-check",
                _tool_command(
                    tool_runner,
                    audit_image,
                    target,
                    reports,
                    [
                        "dependency-check",
                        "--scan", scan_root,
                        "--format", "JSON",
                        "--format", "HTML",
                        "--out", reports_root,
                        "--data", nvd_data,
                        "--noupdate",
                        "--project", project_key,
                    ],
                ),
                reports / "dependency-check-report.log",
                reports / "dependency-check-report.json",
            )
        )
    return plan


def _repo_profile_payload(profile: RepoProfile) -> dict[str, object]:
    return {
        "root": str(profile.root),
        "languages": profile.languages,
        "frameworks": profile.frameworks,
        "source_paths": [str(path) for path in profile.source_paths],
        "candidate_exclusions": [str(path) for path in profile.candidate_exclusions],
        "notes": profile.notes,
    }


def _prompt_context_payload(
    paths: AuditPaths,
    repo_profile_payload: dict[str, object],
    settings: AppSettings,
    summary: dict[str, object] | None = None,
) -> dict[str, object]:
    resolved_summary = summary or _read_json(_runtime_file(paths, SUMMARY_FILE))
    codebase_metrics = _read_json(_runtime_file(paths, CODEBASE_METRICS_FILE))
    tree_sitter_analysis = _read_json(_runtime_file(paths, TREE_SITTER_FILE)) if (_runtime_file(paths, TREE_SITTER_FILE)).exists() else {}
    tool_findings = _read_json(_runtime_file(paths, TOOL_FINDINGS_FILE)) if (_runtime_file(paths, TOOL_FINDINGS_FILE)).exists() else {}
    reference_documents = load_reference_bundle(
        settings.reference_root,
        str(resolved_summary.get("client_name", "")),
        str(resolved_summary.get("project_name", "")),
    )
    manifest_path = paths.delivery / MANIFEST_FILE
    deep_review_bundle_path = _runtime_file(paths, DEEP_REVIEW_BUNDLE_FILE)
    deep_review_findings_path = _runtime_file(paths, DEEP_REVIEW_LLM_FILE)
    return {
        "summary": resolved_summary,
        "repo_profile": repo_profile_payload,
        "codebase_metrics_path": str(_runtime_file(paths, CODEBASE_METRICS_FILE)),
        "codebase_metrics": codebase_metrics,
        "tree_sitter_path": str(_runtime_file(paths, TREE_SITTER_FILE)),
        "tree_sitter_analysis": tree_sitter_analysis,
        "tool_findings": tool_findings,
        "tool_findings_path": str(_runtime_file(paths, TOOL_FINDINGS_FILE)),
        "manifest_path": str(manifest_path),
        "deep_review_bundle_path": str(deep_review_bundle_path),
        "deep_review_bundle": _read_json(deep_review_bundle_path) if deep_review_bundle_path.exists() else {},
        "deep_review_findings_path": str(deep_review_findings_path),
        "deep_review_findings": _read_json_loose(deep_review_findings_path) if deep_review_findings_path.exists() else {},
        "reference_documents": reference_documents,
        "hld_security_baseline": SECURITY_VIEW_STANDARDS,
        "hld_compliance_baseline": COMPLIANCE_STANDARDS,
        "hld_scoring_model": scoring_payload(settings),
        "compliance_screening": settings.compliance_screening,
    }


def _write_analysis_prompts(
    paths: AuditPaths,
    repo_profile_payload: dict[str, object],
    settings: AppSettings,
    summary: dict[str, object] | None = None,
) -> tuple[Path, Path]:
    prompt_context = _prompt_context_payload(paths, repo_profile_payload, settings, summary=summary)
    prompt_path = build_prompt(
        settings.prompt_root / "claude_system.md",
        settings.prompt_root / "claude_audit_brief.md",
        prompt_context,
        _runtime_file(paths, PROMPT_FILE),
    )
    risk_register_prompt_path = build_prompt(
        settings.prompt_root / "claude_system.md",
        settings.prompt_root / "risk_register_brief.md",
        prompt_context,
        _runtime_file(paths, RISK_REGISTER_PROMPT_FILE),
        extra_prompt_paths=[settings.prompt_root / "compliance_screen.md"] if settings.compliance_screening_enabled else None,
    )
    return prompt_path, risk_register_prompt_path


def _summary_payload(
    project_name: str,
    client_name: str,
    profile: RepoProfile,
    tool_results: dict[str, object],
    manifest: dict[str, object],
    codebase_metrics: dict[str, object],
    tree_sitter_analysis: dict[str, object],
) -> dict[str, object]:
    tree_sitter_highlight = "Tree-sitter analysis unavailable."
    if tree_sitter_analysis.get("available"):
        tree_sitter_highlight = (
            f"Tree-sitter parsed {tree_sitter_analysis.get('files_parsed', 0)} core files and emitted "
            f"{len(tree_sitter_analysis.get('risk_highlights', []))} structural highlights."
        )
    return {
        "project_name": project_name,
        "client_name": client_name,
        "executive_summary": (
            "Single-LLM Digital Audit completed after deterministic collection, tool execution, "
            "repo hashing and evidence sealing."
        ),
        "highlights": [
            f"Languages detected: {', '.join(profile.languages) or 'undetermined'}",
            f"Core code lines counted: {codebase_metrics['code_lines']} across {codebase_metrics['files']} source files",
            f"Candidate exclusions: {', '.join(path.name for path in profile.candidate_exclusions) or 'none'}",
            "Outputs validated only after tool completion, artifact presence checks and manifest generation.",
            tree_sitter_highlight,
        ],
        "risk_distribution": {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
        },
        "tool_results": tool_results,
        "manifest": manifest,
        "codebase_metrics": codebase_metrics,
        "tree_sitter_analysis": tree_sitter_analysis,
        "llm": {"skipped": True, "reason": "awaiting host-side LLM execution"},
    }


def _write_compliance_artifact(paths: AuditPaths, project_name: str, client_name: str, output_path: Path | None = None) -> Path:
    artifact = output_path or (paths.reports / COMPLIANCE_FILE)
    artifact.write_text(
        "\n".join(
            [
                "# Compliance Artifact",
                "",
                f"- **Project:** {project_name}",
                f"- **Client:** {client_name}",
                "",
                "---",
                "",
                "## EXECUTIVE SUMMARY",
                "",
                (
                    f"This document presents the compliance posture for the **{project_name}** project "
                    f"delivered to **{client_name}**. The assessment is based on automated static analysis, "
                    "licence scanning, code-quality evidence, and correlated LLM-assisted validation. "
                    "Findings herein should be read in conjunction with the AI Technical Intelligence Review "
                    "and the signed delivery pack."
                ),
                "",
                "---",
                "",
                "## DEPENDENCY AND LICENSE OVERVIEW",
                "",
                "The dependency and licence landscape was evaluated using the following evidence sources:",
                "",
                f"- **ScanCode** — `{paths.reports / 'scancode.json'}`",
                f"- **FOSSology** — `{paths.reports / 'fossology.json'}`",
                f"- **SonarQube** — `{paths.reports / 'sonarqube.json'}`",
                "- **Structural analysis** — tree-sitter + scoped metrics (runtime only)",
                "- **Reasoning layer** — clustered LLM validation and code review (runtime only)",
                "",
                "---",
                "",
                "## HLD Baseline",
                "",
                *[f"- {item}" for item in COMPLIANCE_STANDARDS],
                "",
                "---",
                "",
                "## COMPLIANCE DASHBOARD",
                "",
                "| Framework | Status | Notes |",
                "|-----------|--------|-------|",
                "| *Populate from assessment* | | |",
                "",
                "---",
                "",
                "## Supporting Evidence",
                "",
                "All evidence artefacts listed above are machine-generated and archived alongside this document. "
                "This artifact should be correlated with the AI Technical Intelligence Review and signed delivery pack.",
            ]
        ),
        encoding="utf-8",
    )
    return artifact


def _write_oss_provenance_artifact(paths: AuditPaths, project_name: str, client_name: str, output_path: Path | None = None) -> Path:
    artifact = output_path or (paths.reports / OSS_PROVENANCE_FILE)
    artifact.write_text(
        "\n".join(
            [
                "# OSS Provenance Report (Copyleft Risk)",
                "",
                f"- **Project:** {project_name}",
                f"- **Client:** {client_name}",
                "",
                "---",
                "",
                "## EXECUTIVE SUMMARY",
                "",
                (
                    f"This report documents the open-source provenance and copyleft risk profile for "
                    f"the **{project_name}** project delivered to **{client_name}**. The analysis "
                    "leverages SBOM generation, licence scanning, and software composition analysis "
                    "to identify components with potential licensing obligations. Findings should be "
                    "read alongside the AI Technical Intelligence Review supply-chain section and the "
                    "signed delivery pack."
                ),
                "",
                "---",
                "",
                "## DEPENDENCY GRAPH",
                "",
                "The dependency graph is generated from SBOM evidence produced during the audit run. "
                "The following artefacts were used:",
                "",
                f"- **CycloneDX SBOM** — `{paths.reports / 'sbom.cyclonedx.json'}`",
                f"- **Syft JSON SBOM** — `{paths.reports / 'sbom.syft.json'}`",
                "",
                "---",
                "",
                "## LICENSE RISK MATRIX",
                "",
                "| Component | License | Risk Level | Action |",
                "|-----------|---------|------------|--------|",
                "| *Populate from assessment* | | | |",
                "",
                "---",
                "",
                "## Supporting Evidence",
                "",
                f"- **ScanCode** — `{paths.reports / 'scancode.json'}`",
                f"- **FOSSology** — `{paths.reports / 'fossology.json'}`",
                f"- **Semgrep SCA** — `{paths.reports / 'semgrep-sca.json'}`",
                "- **Correlation layer** — clustered LLM review and runtime-only supply-chain adjudication",
                "",
                "---",
                "",
                "> Per ricerche avanzate di OSS provenance si consiglia BlackDuck.",
                "",
                "This artifact must be read together with the AI Technical Intelligence Review supply-chain section and the signed delivery pack.",
            ]
        ),
        encoding="utf-8",
    )
    return artifact


def prepare_audit(
    target: Path,
    project_name: str,
    client_name: str,
    control_plane_url: str | None = None,
    agent_key: str | None = None,
    llm_provider: str = "claude",
    standalone: bool = False,
    tool_runner: str | None = None,
    status_callback: Callable[[str, str], None] | None = None,
) -> PreparedAudit:
    tool_runner = tool_runner or os.environ.get("NIOBE_TOOL_RUNNER", "docker")
    if os.environ.get("NIOBE_INNER_CONTAINER", "").strip().lower() in {"1", "true", "yes", "on"}:
        tool_runner = "native"
    if tool_runner not in TOOL_RUNNERS:
        raise ValueError(f"unsupported tool runner: {tool_runner}")

    target = target.resolve()
    settings = get_settings()
    paths = prepare_run(target, standalone=standalone)
    profile = detect_repo_profile(target)
    run_started_at = _now_utc()
    run_started_ns = int(os.environ.get("NIOBE_RUN_MONOTONIC_START_NS", time.monotonic_ns()))
    _notify(status_callback, f"Workspace prepared successfully: {_display_path(paths.run_root)}", "success")

    audit_image = os.environ.get("NIOBE_AUDIT_IMAGE", AUDIT_RUNNER_IMAGE)
    if tool_runner == "docker":
        _notify(status_callback, "Ensuring the audit runner image is available.", "info")
        ensure_audit_runner_image(audit_image)
        _notify(status_callback, f"Audit runner image ready: {audit_image}", "success")

    source_root = Path(os.environ.get("NIOBE_HOST_SOURCE", str(Path.cwd()))).resolve()
    manifest = collect_manifest(target=target, source=source_root, run_dir=paths.run_root)
    manifest_path = write_manifest(manifest, paths.delivery / MANIFEST_FILE)
    codebase_metrics = collect_codebase_metrics(target, profile)
    codebase_metrics_path = _write_json(_runtime_file(paths, CODEBASE_METRICS_FILE), codebase_metrics)
    tree_sitter_analysis = collect_tree_sitter_analysis(target, profile) if _tool_enabled(settings, "tree_sitter") else {"available": False, "reason": "disabled by configuration"}
    tree_sitter_path = _write_json(_runtime_file(paths, TREE_SITTER_FILE), tree_sitter_analysis)
    _notify(status_callback, f"Evidence manifest generated successfully: {_display_path(manifest_path)}", "success")
    _emit(
        control_plane_url,
        agent_key,
        "/api/heartbeat",
        {"project_name": project_name, "state": "starting", "run_id": paths.run_root.name},
    )

    tool_results: dict[str, object] = {}
    plan = _tool_plan(target, profile, paths.reports, tool_runner, audit_image, settings)
    sequential_prefixes = ("dependency-check",)

    sequential_tools = [(n, c, o, a) for n, c, o, a in plan if any(n.startswith(p) for p in sequential_prefixes)]
    parallel_tools = [(n, c, o, a) for n, c, o, a in plan if not any(n.startswith(p) for p in sequential_prefixes)]

    def _exec_tool(name: str, command: list[str], output_path: Path, expected_artifact: Path) -> tuple[str, dict[str, object]]:
        _notify(status_callback, _tool_started_message(name), "info")
        result = _run_tool(command, output_path)
        result["artifact_ready"] = expected_artifact.exists() and expected_artifact.stat().st_size > 0
        msg, lvl = _tool_completed_message(name, result, expected_artifact)
        _notify(status_callback, msg, lvl)
        _emit(control_plane_url, agent_key, "/api/heartbeat", {"project_name": project_name, "state": "running", "tool": name, "ok": result["ok"]})
        return name, result

    max_workers = min(len(parallel_tools), int(os.environ.get("NIOBE_TOOL_WORKERS", "4")))
    if max_workers > 1 and len(parallel_tools) > 1:
        _notify(status_callback, f"Running {len(parallel_tools)} tools in parallel (max {max_workers} workers).", "info")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_exec_tool, n, c, o, a): n for n, c, o, a in parallel_tools}
            for future in as_completed(futures):
                name, result = future.result()
                tool_results[name] = result
    else:
        for n, c, o, a in parallel_tools:
            name, result = _exec_tool(n, c, o, a)
            tool_results[name] = result

    for n, c, o, a in sequential_tools:
        name, result = _exec_tool(n, c, o, a)
        tool_results[name] = result

    if _tool_enabled(settings, "sonarqube"):
        _notify(status_callback, _tool_started_message("sonarqube"), "info")
        tool_results["sonarqube"] = _run_sonarqube_suite(target, paths.reports, project_name, tool_runner, audit_image)
        sonarqube_message, sonarqube_level = _tool_completed_message("sonarqube", tool_results["sonarqube"], paths.reports / "sonarqube.json")
        _notify(status_callback, sonarqube_message, sonarqube_level)
    else:
        artifact = _stub_artifact(paths.reports / "sonarqube.json", {"skipped": True, "reason": "disabled by configuration"})
        tool_results["sonarqube"] = {"command": [], "returncode": 0, "output": str(artifact), "ok": True, "skipped": True, "artifact_ready": True}
    if _tool_enabled(settings, "fossology"):
        _notify(status_callback, _tool_started_message("fossology"), "info")
        tool_results["fossology"] = _run_fossology_suite(target, paths.reports, project_name)
        fossology_message, fossology_level = _tool_completed_message("fossology", tool_results["fossology"], paths.reports / "fossology.json")
        _notify(status_callback, fossology_message, fossology_level)
    else:
        artifact = _stub_artifact(paths.reports / "fossology.json", {"skipped": True, "reason": "disabled by configuration"})
        tool_results["fossology"] = {"command": [], "returncode": 0, "output": str(artifact), "ok": True, "skipped": True, "artifact_ready": True}

    tool_findings = _extract_tool_findings(paths.reports)
    tool_findings_path = _write_json(_runtime_file(paths, TOOL_FINDINGS_FILE), tool_findings)

    summary = _summary_payload(project_name, client_name, profile, tool_results, manifest, codebase_metrics, tree_sitter_analysis)
    summary_path = _write_json(_runtime_file(paths, SUMMARY_FILE), summary)
    repo_profile_payload = _repo_profile_payload(profile)
    deep_review_bundle = collect_deep_review_bundle(
        target,
        profile,
        tool_findings if isinstance(tool_findings, dict) else {},
        codebase_metrics,
        tree_sitter_analysis if isinstance(tree_sitter_analysis, dict) else {},
        settings,
    )
    deep_review_bundle_path = _write_json(_runtime_file(paths, DEEP_REVIEW_BUNDLE_FILE), deep_review_bundle)
    deep_review_prompt_context = {
        "summary": summary,
        "repo_profile": repo_profile_payload,
        "codebase_metrics": codebase_metrics,
        "tree_sitter_analysis": tree_sitter_analysis,
        "tool_findings": tool_findings,
        "deep_review_bundle": deep_review_bundle,
        "reference_documents": load_reference_bundle(settings.reference_root, client_name, project_name),
        "hld_security_baseline": SECURITY_VIEW_STANDARDS,
        "hld_scoring_model": scoring_payload(settings),
    }
    deep_review_prompt_path = build_prompt(
        settings.prompt_root / "claude_system.md",
        settings.prompt_root / "deep_code_review.md",
        deep_review_prompt_context,
        _runtime_file(paths, DEEP_REVIEW_PROMPT_FILE),
    )
    prompt_path, risk_register_prompt_path = _write_analysis_prompts(paths, repo_profile_payload, settings, summary=summary)
    context_path = _write_json(
        _runtime_file(paths, RUN_CONTEXT_FILE),
        {
            "project_name": project_name,
            "client_name": client_name,
            "control_plane_url": control_plane_url,
            "llm_provider": llm_provider,
            "standalone": standalone,
            "tool_runner": tool_runner,
            "run_started_at_utc": run_started_at,
            "run_started_monotonic_ns": run_started_ns,
            "repo_profile": repo_profile_payload,
            "settings_hash": settings.settings_hash(),
            "settings_payload": settings.settings_payload(),
            "paths": {
                "run_root": str(paths.run_root),
                "runtime": str(paths.runtime),
                "reports": str(paths.reports),
                "delivery": str(paths.delivery),
                "signatures": str(paths.signatures),
            },
            "manifest_path": str(manifest_path),
            "summary_path": str(summary_path),
            "prompt_path": str(prompt_path),
            "risk_register_prompt_path": str(risk_register_prompt_path),
            "codebase_metrics_path": str(codebase_metrics_path),
            "tree_sitter_path": str(tree_sitter_path),
            "tool_findings_path": str(tool_findings_path),
            "deep_review_bundle_path": str(_runtime_file(paths, DEEP_REVIEW_BUNDLE_FILE)),
            "deep_review_prompt_path": str(_runtime_file(paths, DEEP_REVIEW_PROMPT_FILE)),
            "tool_results": tool_results,
        },
    )
    return PreparedAudit(
        paths=paths,
        manifest_path=manifest_path,
        summary_path=summary_path,
        prompt_path=prompt_path,
        context_path=context_path,
        llm_provider=llm_provider,
        tool_results=tool_results,
        standalone=standalone,
    )


def _render_quality_issues(report_docx_path: Path) -> list[str]:
    issues: list[str] = []
    if not report_docx_path.exists():
        return ["missing-docx"]
    try:
        from zipfile import ZipFile
        import re as _re
        with ZipFile(report_docx_path) as archive:
            xml = archive.read("word/document.xml").decode("utf-8", "ignore")
        text = "\n".join(_re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml))
    except Exception:
        return ["docx-read-failed"]
    probes = {
        "placeholder": ["[Titolo del Report / Documento]", "[Placeholder", "p. [__]", "END OF DOCUMENT"],
        "markdown-leak": ["# ", "](#[", "```"],
        "forbidden-draft": ["Draft Review", "Rapid Review", "Full Review"],
        "container-path": ["/scan"],
    }
    lowered = text.lower()
    for label, patterns in probes.items():
        for pattern in patterns:
            if pattern.lower() in lowered:
                issues.append(f"{label}:{pattern}")
                break
    return issues


def _maybe_render_failback(report_markdown: Path, report_docx: Path, delivery_dir: Path, status_callback: Callable[[str, str], None] | None = None) -> Path | None:
    issues = _render_quality_issues(report_docx)
    if len(issues) < 2:
        return None
    failback_path = delivery_dir / FAILBACK_PDF_FILE
    render_supporting_pdf(TITLE, _body_markdown_from_report(report_markdown), failback_path)
    _notify(status_callback, f"Primary PDF layout failed structural QA. Generated failback PDF: {_display_path(failback_path)}", "warning")
    return failback_path


def _resolve_llm_result(paths: AuditPaths, llm_provider: str, explicit: dict[str, object] | None = None) -> dict[str, object]:
    if explicit is not None:
        return explicit
    output_path = _runtime_file(paths, LLM_OUTPUT_FILE)
    if output_path.exists() and output_path.stat().st_size > 0:
        return {"skipped": False, "output": str(output_path), "provider": llm_provider}
    return {"skipped": True, "reason": "llm debrief missing", "output": str(output_path), "provider": llm_provider}


def _purge_ai_outputs(paths: AuditPaths) -> None:
    cleanup_targets = [
        _runtime_file(paths, LLM_OUTPUT_FILE),
        _runtime_file(paths, RISK_REGISTER_LLM_FILE),
        _runtime_file(paths, VALIDATION_OUTPUT_FILE),
        _runtime_file(paths, REPORT_MARKDOWN_FILE),
        paths.delivery / REPORT_DOCX_FILE,
        paths.delivery / REPORT_PDF_FILE,
        paths.delivery / FAILBACK_PDF_FILE,
        paths.delivery / RISK_REGISTER_WORKBOOK_FILE,
        paths.reports / RISK_REGISTER_JSON_FILE,
        paths.reports / RISK_SCORE_ARTIFACT_FILE,
        paths.reports / COMPLIANCE_FILE,
        paths.reports / OSS_PROVENANCE_FILE,
        paths.delivery / COMPLIANCE_DELIVERY_FILE,
        paths.delivery / 'Compliance Artifact.pdf',
        paths.delivery / 'OSS Provenance Report (Copyleft Risk).pdf',
    ]
    for target in cleanup_targets:
        with contextlib.suppress(FileNotFoundError):
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
            else:
                target.unlink(missing_ok=True)


def _llm_pipeline_gate_status(
    llm_result: dict[str, object],
    risk_register_result: dict[str, object] | None,
    validation_result: dict[str, object] | None,
    deep_review_result: dict[str, object] | None,
) -> tuple[bool, str | None]:
    stages: list[tuple[str, dict[str, object] | None, bool]] = [
        ('llm-report-body', llm_result, True),
        ('risk-register', risk_register_result, True),
        ('validation-pass', validation_result, True),
        ('deep-review', deep_review_result, False),
    ]
    for stage_name, result, required in stages:
        if result is None:
            if required:
                return False, f'{stage_name} not executed'
            continue
        if result.get('skipped'):
            return False, f"{stage_name} unavailable: {result.get('reason', 'unknown')}"
    return True, None


def finalize_audit(
    run_root: Path,
    llm_provider: str | None = None,
    control_plane_url: str | None = None,
    agent_key: str | None = None,
    llm_result: dict[str, object] | None = None,
    ai_pipeline_ok: bool = True,
    ai_failure_reason: str | None = None,
    status_callback: Callable[[str, str], None] | None = None,
) -> AuditResult:
    paths = load_run_paths(run_root)
    context = _read_json(_runtime_file(paths, RUN_CONTEXT_FILE))
    manifest = _read_json(paths.delivery / MANIFEST_FILE)
    summary = _read_json(_runtime_file(paths, SUMMARY_FILE))
    codebase_metrics = _read_json(_runtime_file(paths, CODEBASE_METRICS_FILE))
    tree_sitter_path = _runtime_file(paths, TREE_SITTER_FILE)
    tree_sitter_analysis = _read_json(tree_sitter_path) if tree_sitter_path.exists() else {}
    repo_profile = context.get("repo_profile", {})
    project_name = str(context.get("project_name", ""))
    client_name = str(context.get("client_name", ""))
    standalone = bool(context.get("standalone", False))
    effective_provider = llm_provider or str(context.get("llm_provider", "claude"))
    effective_control_plane = control_plane_url or context.get("control_plane_url")
    tool_results = context.get("tool_results", summary.get("tool_results", {}))
    if not isinstance(tool_results, dict):
        tool_results = {}
    tool_findings_path = _runtime_file(paths, TOOL_FINDINGS_FILE)
    tool_findings = _read_json(tool_findings_path) if tool_findings_path.exists() else {}

    resolved_llm_result = _resolve_llm_result(paths, effective_provider, llm_result)
    summary["llm"] = resolved_llm_result
    summary["ai_pipeline"] = {"ok": ai_pipeline_ok, "reason": ai_failure_reason}
    summary_path = _write_json(_runtime_file(paths, SUMMARY_FILE), summary)
    if resolved_llm_result.get("skipped"):
        _notify(status_callback, f"LLM review skipped: {_display_path(_runtime_file(paths, LLM_OUTPUT_FILE))}", "warning")

    start_ns = int(context.get("run_started_monotonic_ns", 0) or 0)
    end_ns = int(os.environ.get("NIOBE_RUN_MONOTONIC_END_NS", time.monotonic_ns()))
    duration_ms = round((end_ns - start_ns) / 1_000_000, 2) if start_ns else 0.0
    attestation_path = _write_json(
        paths.reports / ATTESTATION_FILE,
        {
            "run_started_at_utc": context.get("run_started_at_utc"),
            "run_completed_at_utc": _now_utc(),
            "run_duration_ms": duration_ms,
            "clock_monotonic_start_ns": start_ns,
            "clock_monotonic_end_ns": end_ns,
            "manifest": manifest,
            "repo_sha512": manifest.get("repo_sha512"),
            "codebase_metrics_path": str(_runtime_file(paths, CODEBASE_METRICS_FILE)),
            "tree_sitter_path": str(tree_sitter_path),
            "manifest_path": str(paths.delivery / MANIFEST_FILE),
            "prompt_path": str(_runtime_file(paths, PROMPT_FILE)),
            "llm_output": str(_runtime_file(paths, LLM_OUTPUT_FILE)),
            "delivery_path": str(paths.delivery),
            "signatures_path": str(paths.signatures),
            "tool_findings_path": str(tool_findings_path),
            "standalone": standalone,
            "llm_provider": effective_provider,
            "tool_results": tool_results,
        },
    )

    if not ai_pipeline_ok:
        _purge_ai_outputs(paths)
        _notify(status_callback, f"AI pipeline gated closed: {ai_failure_reason or 'unknown reason'}. Client-facing AI deliverables were not generated.", "warning")

        manifest_delivery_path = paths.delivery / DELIVERY_MANIFEST_FILE
        manifest_delivery_path.write_text(
            json.dumps(
                {
                    "evidence_manifest_path": str(paths.delivery / MANIFEST_FILE),
                    "attestation_path": str(attestation_path),
                    "delivery_path": str(paths.delivery),
                    "reports_path": str(paths.reports),
                    "ai_pipeline": {"ok": False, "reason": ai_failure_reason},
                },
                indent=2,
                sort_keys=True,
                default=str,
            ),
            encoding="utf-8",
        )

        cyclonedx_source = paths.reports / "sbom.cyclonedx.json"
        if cyclonedx_source.exists():
            shutil.copy2(cyclonedx_source, paths.delivery / cyclonedx_source.name)

        sign_directory_tree(paths.reports, paths.reports / "signatures")
        sign_delivery(
            paths.delivery,
            paths.signatures,
            deferred_detached_artifacts=[
                lambda: (_create_evidence_bundle(paths.run_root, paths.delivery, paths.reports), paths.run_root / BUNDLE_SIGNATURE_FILE)
            ],
        )

        _upload_delivery(
            effective_control_plane if isinstance(effective_control_plane, str) else None,
            agent_key,
            paths.delivery,
        )
        _emit(
            effective_control_plane if isinstance(effective_control_plane, str) else None,
            agent_key,
            "/api/events",
            {"kind": "audit", "level": "warning", "message": f"delivery sealed without AI outputs: {ai_failure_reason or 'unknown'}"},
        )
        _emit(
            effective_control_plane if isinstance(effective_control_plane, str) else None,
            agent_key,
            "/api/heartbeat",
            {"project_name": project_name, "state": "completed", "delivery_path": str(paths.delivery)},
        )
        _cleanup_runtime(paths)
        return AuditResult(
            paths=paths,
            manifest_path=paths.delivery / MANIFEST_FILE,
            attestation_path=attestation_path,
            summary_path=summary_path,
            llm_provider=effective_provider,
            llm_result=resolved_llm_result,
            tool_results=tool_results,
            standalone=standalone,
        )

    settings = get_settings()
    deep_review_bundle_path = _runtime_file(paths, DEEP_REVIEW_BUNDLE_FILE)
    deep_review_findings_path = _runtime_file(paths, DEEP_REVIEW_LLM_FILE)
    report_context = {
        "project_name": project_name,
        "client_name": client_name,
        "repo_profile": repo_profile,
        "summary": summary,
        "manifest": manifest,
        "tool_results": tool_results,
        "codebase_metrics": codebase_metrics,
        "tree_sitter_analysis": tree_sitter_analysis,
        "deep_review_bundle": _read_json(deep_review_bundle_path) if deep_review_bundle_path.exists() else {},
        "deep_review_findings": _read_json_loose(deep_review_findings_path) if deep_review_findings_path.exists() else {},
        "llm_output_path": _runtime_file(paths, LLM_OUTPUT_FILE),
        "reference_documents": load_reference_bundle(settings.reference_root, client_name, project_name),
    }

    risk_register_template = settings.seed_root / "risk_register_template.xlsx"
    risk_register_llm_path = _runtime_file(paths, RISK_REGISTER_LLM_FILE)
    validation_path = _runtime_file(paths, VALIDATION_OUTPUT_FILE)
    risk_findings = load_llm_findings(
        risk_register_llm_path,
        tool_findings=tool_findings if isinstance(tool_findings, dict) else {},
        validation_path=validation_path if validation_path.exists() else None,
        supplemental_paths=[deep_review_findings_path] if deep_review_findings_path.exists() else None,
        settings=settings,
    )
    risk_register_workbook_path, risk_register_json_path = export_risk_register(
        risk_register_template,
        paths.delivery,
        risk_findings,
        settings,
    )
    reports_risk_register_json = paths.reports / RISK_REGISTER_JSON_FILE
    if risk_register_json_path.exists():
        reports_risk_register_json.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(risk_register_json_path), str(reports_risk_register_json))
    risk_register_json_path = reports_risk_register_json
    build_risk_score_artifact(paths.reports / RISK_SCORE_ARTIFACT_FILE, risk_findings, settings)
    duration_seconds = round(duration_ms / 1000, 2) if duration_ms else 0.0
    if effective_provider == "claude":
        model_id = os.environ.get("NIOBE_CLAUDE_MODEL") or os.environ.get("ANTHROPIC_MODEL") or "sonnet"
    else:
        model_id = os.environ.get("NIOBE_CODEX_MODEL", "codex")
    run_log_path = write_run_log(
        paths.reports / RUN_LOG_FILE,
        build_run_log(
            run_root=paths.run_root,
            repo_path=Path(str(manifest.get("target", paths.run_root))),
            reports_dir=paths.reports,
            settings=settings,
            llm_provider=effective_provider,
            model_id=model_id,
            findings=risk_findings,
            duration_seconds=duration_seconds,
        ),
    )

    report_context["risk_findings"] = [finding.model_dump() for finding in risk_findings]
    report_markdown = render_report(
        settings.template_root,
        report_context,
        _runtime_file(paths, REPORT_MARKDOWN_FILE),
    )
    report_docx = render_docx(
        report_markdown,
        report_context,
        paths.delivery / REPORT_DOCX_FILE,
    )
    report_pdf_path = paths.delivery / REPORT_PDF_FILE
    render_pdf(
        report_docx,
        report_context,
        report_pdf_path,
        markdown_fallback_path=report_markdown,
    )
    _maybe_render_failback(report_markdown, report_docx, paths.delivery, status_callback=status_callback)

    report_markdown_text = report_markdown.read_text(encoding="utf-8")
    compliance_artifact_path = paths.reports / COMPLIANCE_FILE
    compliance_section = _extract_markdown_section(report_markdown_text, "10")
    if compliance_section:
        _write_supporting_markdown_artifact(
            compliance_artifact_path,
            "Compliance Artifact",
            compliance_section,
            [
                str(paths.reports / "sonarqube.json"),
                str(paths.reports / "scancode.json"),
                str(paths.reports / "fossology.json"),
                "Internal structural analysis layer (runtime-only)",
                "Correlated LLM validation layer (runtime-only)",
            ],
            baseline_lines=COMPLIANCE_STANDARDS,
        )
    else:
        compliance_artifact_path = _write_compliance_artifact(paths, project_name, client_name, output_path=compliance_artifact_path)

    oss_provenance_path = paths.reports / OSS_PROVENANCE_FILE
    supply_chain_section = _extract_markdown_section(report_markdown_text, "6")
    if supply_chain_section:
        _write_supporting_markdown_artifact(
            oss_provenance_path,
            "OSS Provenance Report (Copyleft Risk)",
            supply_chain_section,
            [
                str(paths.reports / "sbom.cyclonedx.json"),
                str(paths.reports / "sbom.syft.json"),
                str(paths.reports / "semgrep-sca.json"),
                str(paths.reports / "scancode.json"),
                str(paths.reports / "fossology.json"),
            ],
            baseline_lines=SECURITY_VIEW_STANDARDS,
        )
    else:
        oss_provenance_path = _write_oss_provenance_artifact(paths, project_name, client_name, output_path=oss_provenance_path)

    manifest_delivery_path = paths.delivery / DELIVERY_MANIFEST_FILE
    manifest_delivery_path.write_text(
        json.dumps(
            {
                "evidence_manifest_path": str(paths.delivery / MANIFEST_FILE),
                "attestation_path": str(attestation_path),
                "run_log_path": str(run_log_path),
                "risk_register_path": str(risk_register_workbook_path),
                "delivery_path": str(paths.delivery),
                "reports_path": str(paths.reports),
            },
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    cyclonedx_source = paths.reports / "sbom.cyclonedx.json"
    if cyclonedx_source.exists():
        shutil.copy2(cyclonedx_source, paths.delivery / cyclonedx_source.name)

    render_supporting_pdf(
        "Compliance Artifact",
        compliance_artifact_path.read_text(encoding="utf-8"),
        paths.delivery / "Compliance Artifact.pdf",
    )
    render_supporting_pdf(
        "OSS Provenance Report (Copyleft Risk)",
        oss_provenance_path.read_text(encoding="utf-8"),
        paths.delivery / "OSS Provenance Report (Copyleft Risk).pdf",
    )

    sign_directory_tree(paths.reports, paths.reports / "signatures")
    sign_delivery(
        paths.delivery,
        paths.signatures,
        deferred_detached_artifacts=[
            lambda: (_create_evidence_bundle(paths.run_root, paths.delivery, paths.reports), paths.run_root / BUNDLE_SIGNATURE_FILE)
        ],
    )

    _upload_delivery(
        effective_control_plane if isinstance(effective_control_plane, str) else None,
        agent_key,
        paths.delivery,
    )
    _emit(
        effective_control_plane if isinstance(effective_control_plane, str) else None,
        agent_key,
        "/api/events",
        {"kind": "audit", "level": "success", "message": "delivery sealed"},
    )
    _emit(
        effective_control_plane if isinstance(effective_control_plane, str) else None,
        agent_key,
        "/api/heartbeat",
        {"project_name": project_name, "state": "completed", "delivery_path": str(paths.delivery)},
    )
    _cleanup_runtime(paths)
    return AuditResult(
        paths=paths,
        manifest_path=paths.delivery / MANIFEST_FILE,
        attestation_path=attestation_path,
        summary_path=summary_path,
        llm_provider=effective_provider,
        llm_result=resolved_llm_result,
        tool_results=tool_results,
        standalone=standalone,
    )


def run_audit(
    target: Path,
    project_name: str,
    client_name: str,
    control_plane_url: str | None = None,
    agent_key: str | None = None,
    llm_provider: str = "claude",
    llm_command_template: str | None = None,
    standalone: bool = False,
    tool_runner: str = "docker",
    status_callback: Callable[[str, str], None] | None = None,
) -> AuditResult:
    settings = get_settings()
    target = target.resolve()
    prepared = prepare_audit(
        target=target,
        project_name=project_name,
        client_name=client_name,
        control_plane_url=control_plane_url,
        agent_key=agent_key,
        llm_provider=llm_provider,
        standalone=standalone,
        tool_runner=tool_runner,
        status_callback=status_callback,
    )
    paths = prepared.paths
    deep_review_result: dict[str, object] | None = None
    risk_register_result: dict[str, object] | None = None
    validation_result: dict[str, object] | None = None
    ai_pipeline_ok = True
    ai_failure_reason: str | None = None

    try:
        deep_review_prompt_path = _runtime_file(paths, DEEP_REVIEW_PROMPT_FILE)
        if deep_review_prompt_path.exists():
            deep_review_result = run_llm(
                deep_review_prompt_path,
                _runtime_file(paths, DEEP_REVIEW_LLM_FILE),
                provider=llm_provider,
                command_template=llm_command_template,
                working_dir=target,
            )
            if deep_review_result.get("skipped"):
                _notify(status_callback, f"Deep code review skipped: {_display_path(_runtime_file(paths, DEEP_REVIEW_LLM_FILE))}", "warning")
            runtime_context = _read_json(prepared.context_path)
            refreshed_prompt_path, refreshed_risk_register_prompt_path = _write_analysis_prompts(
                paths,
                runtime_context.get("repo_profile", {}),
                settings,
            )
            runtime_context["prompt_path"] = str(refreshed_prompt_path)
            runtime_context["risk_register_prompt_path"] = str(refreshed_risk_register_prompt_path)
            runtime_context["deep_review_findings_path"] = str(_runtime_file(paths, DEEP_REVIEW_LLM_FILE))
            prepared.context_path = _write_json(_runtime_file(paths, RUN_CONTEXT_FILE), runtime_context)
            prepared.prompt_path = refreshed_prompt_path

        llm_result = run_llm(
            prepared.prompt_path,
            _runtime_file(paths, LLM_OUTPUT_FILE),
            provider=llm_provider,
            command_template=llm_command_template,
            working_dir=target,
        )
        if llm_result.get("skipped"):
            _notify(status_callback, f"LLM report body failed after retries: {llm_result.get('reason', 'unknown')}. AI deliverables will be withheld.", "error")
            ai_pipeline_ok = False
            ai_failure_reason = f"llm report body unavailable: {llm_result.get('reason', 'unknown')}"
        else:
            risk_register_prompt_path = _runtime_file(paths, RISK_REGISTER_PROMPT_FILE)
            if risk_register_prompt_path.exists():
                risk_register_result = run_llm(
                    risk_register_prompt_path,
                    _runtime_file(paths, RISK_REGISTER_LLM_FILE),
                    provider=llm_provider,
                    command_template=llm_command_template,
                    working_dir=target,
                )
                if risk_register_result.get("skipped"):
                    _notify(status_callback, f"Risk register synthesis skipped: {_display_path(_runtime_file(paths, RISK_REGISTER_LLM_FILE))}", "warning")
                    ai_pipeline_ok = False
                    ai_failure_reason = f"risk register unavailable: {risk_register_result.get('reason', 'unknown')}"
                else:
                    validation_context = {
                        "risk_register_payload": _read_json_loose(_runtime_file(paths, RISK_REGISTER_LLM_FILE)),
                        "tool_findings": _read_json_loose(_runtime_file(paths, TOOL_FINDINGS_FILE)),
                        "deep_review_findings": _read_json_loose(_runtime_file(paths, DEEP_REVIEW_LLM_FILE)),
                        "scoring_model": scoring_payload(settings),
                    }
                    validation_prompt_path = build_prompt(
                        settings.prompt_root / "claude_system.md",
                        settings.prompt_root / "validation_pass.md",
                        validation_context,
                        _runtime_file(paths, VALIDATION_PROMPT_FILE),
                    )
                    validation_result = run_llm(
                        validation_prompt_path,
                        _runtime_file(paths, VALIDATION_OUTPUT_FILE),
                        provider=llm_provider,
                        command_template=llm_command_template,
                        working_dir=target,
                    )
                    if validation_result.get("skipped"):
                        _notify(status_callback, f"Validation pass skipped: {_display_path(_runtime_file(paths, VALIDATION_OUTPUT_FILE))}", "warning")
                        ai_pipeline_ok = False
                        ai_failure_reason = f"validation unavailable: {validation_result.get('reason', 'unknown')}"

        if ai_pipeline_ok:
            ai_pipeline_ok, auto_reason = _llm_pipeline_gate_status(
                llm_result=llm_result,
                risk_register_result=risk_register_result,
                validation_result=validation_result,
                deep_review_result=deep_review_result,
            )
            if not ai_pipeline_ok:
                ai_failure_reason = auto_reason
                _notify(status_callback, f"AI pipeline closed: {ai_failure_reason}.", "warning")
    except (KeyboardInterrupt, SystemExit):
        _purge_ai_outputs(paths)
        _notify(status_callback, "AI pipeline interrupted. Client-facing AI deliverables were withheld.", "warning")
        raise

    if not ai_pipeline_ok:
        _purge_ai_outputs(paths)

    return finalize_audit(
        run_root=paths.run_root,
        llm_provider=llm_provider,
        control_plane_url=control_plane_url,
        agent_key=agent_key,
        llm_result=llm_result,
        ai_pipeline_ok=ai_pipeline_ok,
        ai_failure_reason=ai_failure_reason,
        status_callback=status_callback,
    )
