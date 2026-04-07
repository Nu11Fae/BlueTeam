from __future__ import annotations

import os
import re
from collections import defaultdict
from pathlib import Path

from .detect import DEFAULT_EXCLUDES, RepoProfile
from .metrics import BINARY_SUFFIXES, LANGUAGE_BY_SUFFIX
from .settings import AppSettings, get_settings

CATEGORY_META: dict[str, dict[str, object]] = {
    "idor_authorization_gap": {
        "title": "Potential IDOR or missing object-level authorization",
        "taxonomy": ["CWE-639", "OWASP ASVS 5.0 V4", "OWASP WSTG-ATHZ-04"],
        "priority": 100,
    },
    "sql_injection": {
        "title": "Potential SQL injection or unsafe dynamic query construction",
        "taxonomy": ["CWE-89", "OWASP ASVS 5.0 V5", "OWASP WSTG-INPV-05"],
        "priority": 95,
    },
    "command_injection": {
        "title": "Potential command execution or shell-injection surface",
        "taxonomy": ["CWE-78", "OWASP ASVS 5.0 V5", "OWASP WSTG-INPV-12"],
        "priority": 92,
    },
    "path_traversal": {
        "title": "Potential path traversal or unsafe file-access pattern",
        "taxonomy": ["CWE-22", "OWASP ASVS 5.0 V5", "OWASP WSTG-ATHZ-01"],
        "priority": 88,
    },
    "ssrf": {
        "title": "Potential SSRF or uncontrolled outbound request pattern",
        "taxonomy": ["CWE-918", "OWASP ASVS 5.0 V5", "OWASP WSTG-CLNT-07"],
        "priority": 86,
    },
    "insecure_deserialization": {
        "title": "Potential insecure deserialization or unsafe parser usage",
        "taxonomy": ["CWE-502", "OWASP ASVS 5.0 V8", "OWASP WSTG-INPV-13"],
        "priority": 84,
    },
    "secret_exposure": {
        "title": "Embedded credential or secret material exposure",
        "taxonomy": ["CWE-798", "OWASP ASVS 5.0 V6"],
        "priority": 82,
    },
    "memory_safety": {
        "title": "Potential memory-safety weakness or unsafe low-level primitive",
        "taxonomy": ["CWE-120", "CWE-787", "OWASP ASVS 5.0 V14"],
        "priority": 78,
    },
    "security_hotspot": {
        "title": "Security-relevant hotspot requiring code-level adjudication",
        "taxonomy": ["OWASP ASVS 5.0", "OWASP WSTG"],
        "priority": 60,
    },
}

HIGH_RISK_NAME_TOKENS = {
    "auth",
    "login",
    "user",
    "account",
    "tenant",
    "admin",
    "api",
    "controller",
    "handler",
    "route",
    "router",
    "service",
    "repository",
    "repo",
    "query",
    "sql",
    "db",
    "database",
    "payment",
    "order",
    "customer",
    "session",
}

USER_INPUT_PATTERN = re.compile(
    r"(?i)(req\.|request\.|ctx\.|params?\b|query\b|body\b|form\b|input\(|path_param|route_param|FromRoute|FromQuery|HttpContext|\$_GET|\$_POST|argv|Console\.ReadLine|user_id|account_id|tenant_id|document_id|resource_id|url\b|uri\b|endpoint\b|host\b)"
)
AUTHZ_GUARD_PATTERN = re.compile(
    r"(?i)(authorize|authorise|permission|policy|scope|acl|role|claims|tenant|current_user|currentUser|currentUserId|ensure_owner|ensureOwner|ownership|is_admin|can\(|has_access|require_auth|require_role)"
)
SQL_KEYWORD_PATTERN = re.compile(r"(?i)\b(select|insert|update|delete|merge|drop|alter)\b")
SQL_CALL_PATTERN = re.compile(
    r"(?i)(execute\(|executemany\(|cursor\.execute|query\(|rawquery\(|fromsqlraw\(|executesqlraw\(|sequelize\.query|session\.execute|db\.execute|preparestatement|createquery)"
)
DYNAMIC_SQL_PATTERN = re.compile(r"(?i)(\+|\.format\(|f['\"]|%s|%\(|\$\{|string\.format\()")
ROUTE_OR_ID_PATTERN = re.compile(
    r"(?i)(params?\b|id\b|tenant_id|user_id|account_id|resource_id|document_id|FromRoute|route_param|path_param|req\.params|request\.args|ctx\.params)"
)
OBJECT_FETCH_PATTERN = re.compile(
    r"(?i)(findbyid|findbypk|find_one|first_or_404|repository\.get|getbyid|load\(|fetch\(|where\s*\(|select\b.*\bwhere\b|find\(|get\()"
)
HTTP_CLIENT_PATTERN = re.compile(
    r"(?i)(requests\.(get|post|request)|httpx\.(get|post|request)|urllib\.request|urlopen\(|fetch\(|axios\.(get|post|request)|HttpClient|http\.(Get|Post)|RestTemplate|WebClient|curl_(init|exec))"
)
URL_VAR_PATTERN = re.compile(r"(?i)\b(url|uri|endpoint|host|address|target|callback|webhook|location)\b")
DESERIALIZATION_PATTERN = re.compile(
    r"(?i)(pickle\.loads|yaml\.load\(|marshal\.loads|dill\.loads|jsonpickle\.decode|unserialize\(|BinaryFormatter\.Deserialize|readObject\(|ObjectInputStream)"
)
SAFE_YAML_PATTERN = re.compile(r"(?i)safe_load\(")
COMMAND_PATTERN = re.compile(
    r"(?i)(os\.system\(|subprocess\.(Popen|run|call)|Process\.Start\(|Runtime\.getRuntime\(\)\.exec|shell_exec\(|passthru\(|system\(|exec\(|Command::new)"
)
FILE_IO_PATTERN = re.compile(
    r"(?i)(open\(|read_text\(|write_text\(|Path\.Combine|os\.path\.join|path\.join|File\.(Open|ReadAll|WriteAll)|Files\.(read|write)|fs\.(readFile|writeFile)|send_file|sendFile)"
)
SAFE_PATH_PATTERN = re.compile(r"(?i)(resolve\(|realpath\(|normpath\(|safe_join|Path\.GetFullPath|clean_path)")
MEMORY_SAFETY_PATTERN = re.compile(r"(?i)(strcpy\(|strcat\(|sprintf\(|vsprintf\(|gets\(|memcpy\(|unsafe\s*\{|from_utf8_unchecked)")

TOOL_CATEGORY_HINTS: list[tuple[str, re.Pattern[str]]] = [
    ("sql_injection", re.compile(r"(?i)(cwe-89|sql|injection|fromsqlraw|executesqlraw)")),
    ("idor_authorization_gap", re.compile(r"(?i)(cwe-639|idor|authorization|access control|authz|permission|policy)")),
    ("ssrf", re.compile(r"(?i)(cwe-918|ssrf|server-side request forgery)")),
    ("insecure_deserialization", re.compile(r"(?i)(cwe-502|deserialize|deseriali[sz]e|pickle|unserialize)")),
    ("command_injection", re.compile(r"(?i)(cwe-78|command|shell|process\.start|runtime\.getruntime)")),
    ("path_traversal", re.compile(r"(?i)(cwe-22|path traversal|directory traversal)")),
    ("secret_exposure", re.compile(r"(?i)(secret|credential|token|password|api key|gitleaks)")),
    ("memory_safety", re.compile(r"(?i)(cwe-120|cwe-787|unsafe|buffer|overflow|strcpy|sprintf|memcpy)")),
]


def _skip_path(path: Path, root: Path, candidate_exclusions: set[Path]) -> bool:
    relative = path.relative_to(root)
    if any(part in DEFAULT_EXCLUDES for part in relative.parts):
        return True
    if any(part.startswith(".") and part not in {".config"} for part in relative.parts[:-1]):
        return True
    if any(excluded in path.parents or excluded == path for excluded in candidate_exclusions):
        return True
    return False


def _iter_source_files(target: Path, profile: RepoProfile, max_files: int) -> list[Path]:
    root = target.resolve()
    candidate_exclusions = {path.resolve() for path in profile.candidate_exclusions}
    files: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current_root)
        dirnames[:] = [entry for entry in sorted(dirnames) if not _skip_path(current_path / entry, root, candidate_exclusions)]
        for filename in sorted(filenames):
            path = current_path / filename
            try:
                if path.is_symlink() and not path.exists():
                    continue
                if not path.is_file():
                    continue
            except OSError:
                continue
            if _skip_path(path, root, candidate_exclusions):
                continue
            if path.suffix.lower() in BINARY_SUFFIXES:
                continue
            if path.suffix.lower() not in LANGUAGE_BY_SUFFIX:
                continue
            files.append(path)
            if len(files) >= max_files:
                return files
    return files


def _normalize_tool_path(value: str, root: Path) -> str:
    normalized = value.strip().replace("\\", "/")
    if not normalized:
        return ""
    if normalized.startswith("/scan/"):
        return normalized.split("/scan/", 1)[1].lstrip("/")
    try:
        path = Path(normalized)
        if path.is_absolute():
            return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return normalized.lstrip("./")
    return normalized.lstrip("./")


def _normalize_tool_index(tool_findings: dict[str, list[dict[str, object]]], root: Path) -> dict[str, list[dict[str, object]]]:
    index: dict[str, list[dict[str, object]]] = defaultdict(list)
    for raw_path, entries in tool_findings.items():
        normalized = _normalize_tool_path(raw_path, root)
        if not normalized:
            continue
        for entry in entries:
            tool = str(entry.get("tool", "")).strip().lower()
            if tool not in {"semgrep-code", "sonarqube", "gitleaks"}:
                continue
            index[normalized].append(entry)
    return dict(index)


def _tool_categories(entries: list[dict[str, object]]) -> list[str]:
    categories: set[str] = set()
    for entry in entries:
        haystack = " ".join(str(entry.get(key, "")) for key in ("tool", "rule", "title", "summary"))
        haystack += " " + " ".join(str(item) for item in entry.get("taxonomy", []))
        matched = False
        for category, pattern in TOOL_CATEGORY_HINTS:
            if pattern.search(haystack):
                categories.add(category)
                matched = True
        if not matched:
            categories.add("security_hotspot")
    return sorted(categories)


def _window(lines: list[str], index: int, radius: int) -> tuple[int, int, str, str]:
    start = max(0, index - radius)
    end = min(len(lines), index + radius + 1)
    slice_lines = lines[start:end]
    raw = "\n".join(slice_lines)
    lowered = raw.lower()
    return start + 1, end, raw, lowered


def _render_snippet(lines: list[str], start_line: int, end_line: int) -> str:
    rendered = []
    for line_number in range(start_line, end_line + 1):
        rendered.append(f"{line_number:04d}: {lines[line_number - 1].rstrip()}")
    return "\n".join(rendered).strip()


def _signal(
    category: str,
    rationale: str,
    lines: list[str],
    line_index: int,
    radius: int,
    confidence: str,
) -> dict[str, object]:
    start_line, end_line, _, _ = _window(lines, line_index, radius)
    meta = CATEGORY_META.get(category, CATEGORY_META["security_hotspot"])
    return {
        "category": category,
        "title": str(meta["title"]),
        "line_start": start_line,
        "line_end": end_line,
        "confidence": confidence,
        "rationale": rationale,
        "taxonomy": list(meta["taxonomy"]),
        "snippet": _render_snippet(lines, start_line, end_line),
    }


def _scan_sql_injection(lines: list[str], language: str, radius: int) -> list[dict[str, object]]:
    signals = []
    for index, _ in enumerate(lines):
        _, _, _, lowered = _window(lines, index, radius)
        if not SQL_KEYWORD_PATTERN.search(lowered):
            continue
        if not (SQL_CALL_PATTERN.search(lowered) or "query" in lowered or "sql" in lowered):
            continue
        dynamic = bool(DYNAMIC_SQL_PATTERN.search(lowered))
        user_controlled = bool(USER_INPUT_PATTERN.search(lowered))
        if dynamic or user_controlled:
            confidence = "High" if dynamic and user_controlled else "Medium"
            reason = "Dynamic SQL construction or raw query execution appears to include interpolated or externally influenced input."
            signals.append(_signal("sql_injection", reason, lines, index, radius, confidence))
    return signals


def _scan_idor(lines: list[str], language: str, radius: int) -> list[dict[str, object]]:
    signals = []
    for index, _ in enumerate(lines):
        _, _, _, lowered = _window(lines, index, radius)
        if not ROUTE_OR_ID_PATTERN.search(lowered):
            continue
        if not OBJECT_FETCH_PATTERN.search(lowered):
            continue
        if AUTHZ_GUARD_PATTERN.search(lowered):
            continue
        reason = "Object retrieval appears driven by route/query identifiers without a nearby authorization or ownership check."
        signals.append(_signal("idor_authorization_gap", reason, lines, index, radius, "Medium"))
    return signals


def _scan_ssrf(lines: list[str], language: str, radius: int) -> list[dict[str, object]]:
    signals = []
    for index, _ in enumerate(lines):
        _, _, _, lowered = _window(lines, index, radius)
        if not HTTP_CLIENT_PATTERN.search(lowered):
            continue
        if URL_VAR_PATTERN.search(lowered) or USER_INPUT_PATTERN.search(lowered):
            reason = "Outbound HTTP call appears influenced by runtime-controlled URL, host or endpoint values."
            confidence = "High" if USER_INPUT_PATTERN.search(lowered) else "Medium"
            signals.append(_signal("ssrf", reason, lines, index, radius, confidence))
    return signals


def _scan_deserialization(lines: list[str], language: str, radius: int) -> list[dict[str, object]]:
    signals = []
    for index, _ in enumerate(lines):
        _, _, _, lowered = _window(lines, index, radius)
        if not DESERIALIZATION_PATTERN.search(lowered):
            continue
        if "yaml.load(" in lowered and SAFE_YAML_PATTERN.search(lowered):
            continue
        reason = "Unsafe deserialization or parser primitive is present and may deserialize attacker-controlled content."
        signals.append(_signal("insecure_deserialization", reason, lines, index, radius, "High"))
    return signals


def _scan_command_execution(lines: list[str], language: str, radius: int) -> list[dict[str, object]]:
    signals = []
    for index, _ in enumerate(lines):
        _, _, _, lowered = _window(lines, index, radius)
        if not COMMAND_PATTERN.search(lowered):
            continue
        confidence = "High" if "shell=true" in lowered or USER_INPUT_PATTERN.search(lowered) else "Medium"
        reason = "Process or shell execution primitive is reachable and may be parameterised by runtime-controlled values."
        signals.append(_signal("command_injection", reason, lines, index, radius, confidence))
    return signals


def _scan_path_traversal(lines: list[str], language: str, radius: int) -> list[dict[str, object]]:
    signals = []
    for index, _ in enumerate(lines):
        _, _, _, lowered = _window(lines, index, radius)
        if not FILE_IO_PATTERN.search(lowered):
            continue
        if not (USER_INPUT_PATTERN.search(lowered) or "../" in lowered or "..\\" in lowered):
            continue
        if SAFE_PATH_PATTERN.search(lowered):
            continue
        reason = "File-system access appears to incorporate untrusted path fragments without visible normalization or confinement."
        signals.append(_signal("path_traversal", reason, lines, index, radius, "Medium"))
    return signals


def _scan_memory_safety(lines: list[str], language: str, radius: int) -> list[dict[str, object]]:
    if language not in {"C/C++", "Rust"}:
        return []
    signals = []
    for index, _ in enumerate(lines):
        _, _, _, lowered = _window(lines, index, radius)
        if MEMORY_SAFETY_PATTERN.search(lowered):
            reason = "Unsafe low-level primitive or memory-sensitive construct is present and should be reviewed for boundary safety."
            signals.append(_signal("memory_safety", reason, lines, index, radius, "Medium"))
    return signals


def _dedupe_signals(signals: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, int, int]] = set()
    deduped: list[dict[str, object]] = []
    for signal in signals:
        key = (str(signal["category"]), int(signal["line_start"]), int(signal["line_end"]))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(signal)
    return deduped


def _risk_score(tool_entries: list[dict[str, object]], signals: list[dict[str, object]], risky_calls: list[str], relative: str) -> tuple[int, list[str]]:
    reasons: list[str] = []
    tool_categories = _tool_categories(tool_entries)
    if tool_entries:
        reasons.append(f"{len(tool_entries)} tool-backed evidence item(s)")
    if tool_categories:
        reasons.append(f"tool categories: {', '.join(tool_categories)}")
    if signals:
        reasons.append(f"{len(signals)} heuristic code signal(s)")
    if risky_calls:
        reasons.append(f"tree-sitter risky API markers: {', '.join(risky_calls[:4])}")
    name_tokens = {token for token in HIGH_RISK_NAME_TOKENS if token in relative.lower()}
    if name_tokens:
        reasons.append(f"high-risk path naming: {', '.join(sorted(name_tokens))}")
    score = len(tool_entries) * 5 + len(signals) * 7 + len(risky_calls) * 2 + len(name_tokens)
    return score, reasons


def _cluster_assets(selected_assets: list[dict[str, object]]) -> list[dict[str, object]]:
    clusters: dict[str, dict[str, object]] = {}
    for asset in selected_assets:
        categories = set(asset.get("tool_categories", []))
        categories.update(signal.get("category", "") for signal in asset.get("heuristic_signals", []))
        for category in sorted(filter(None, categories)):
            bucket = clusters.setdefault(
                category,
                {
                    "category": category,
                    "title": CATEGORY_META.get(category, CATEGORY_META["security_hotspot"])["title"],
                    "taxonomy": list(CATEGORY_META.get(category, CATEGORY_META["security_hotspot"])["taxonomy"]),
                    "assets": [],
                    "signal_count": 0,
                    "tool_count": 0,
                    "priority": int(CATEGORY_META.get(category, CATEGORY_META["security_hotspot"])["priority"]),
                },
            )
            bucket["assets"].append(asset["path"])
            bucket["signal_count"] += sum(1 for signal in asset.get("heuristic_signals", []) if signal.get("category") == category)
            bucket["tool_count"] += sum(1 for entry in asset.get("tool_findings", []) if category in _tool_categories([entry]))
    ordered = sorted(
        clusters.values(),
        key=lambda item: (item["priority"], item["signal_count"], item["tool_count"], len(item["assets"])),
        reverse=True,
    )
    rendered: list[dict[str, object]] = []
    for index, cluster in enumerate(ordered, start=1):
        rendered.append(
            {
                "cluster_id": f"CL-{str(cluster['category']).split('_')[0].upper()}-{index:03d}",
                "category": cluster["category"],
                "title": cluster["title"],
                "taxonomy": cluster["taxonomy"],
                "assets": sorted(set(cluster["assets"]))[:8],
                "asset_count": len(set(cluster["assets"])),
                "signal_count": cluster["signal_count"],
                "tool_count": cluster["tool_count"],
                "priority": cluster["priority"],
                "summary": f"{cluster['title']}: {len(set(cluster['assets']))} asset(s), {cluster['signal_count']} heuristic signal(s), {cluster['tool_count']} tool-correlated evidence item(s).",
            }
        )
    return rendered[:10]


def collect_deep_review_bundle(
    target: Path,
    profile: RepoProfile,
    tool_findings: dict[str, list[dict[str, object]]],
    codebase_metrics: dict[str, object],
    tree_sitter_analysis: dict[str, object],
    settings: AppSettings | None = None,
) -> dict[str, object]:
    resolved_settings = settings or get_settings()
    deep_review_settings = dict(getattr(resolved_settings, "deep_review", {}))
    if not deep_review_settings.get("enabled", True):
        return {
            "available": False,
            "reason": "disabled by configuration",
            "selected_assets": [],
            "clusters": [],
        }

    max_files = int(deep_review_settings.get("max_files_to_scan", 220))
    max_assets = int(deep_review_settings.get("max_assets", 14))
    max_snippets = int(deep_review_settings.get("max_snippets_per_asset", 3))
    radius = int(deep_review_settings.get("context_radius", 3))
    files = _iter_source_files(target, profile, max_files=max_files)
    normalized_tool_findings = _normalize_tool_index(tool_findings, target)
    tree_index = {
        str(item.get("path")): item
        for item in tree_sitter_analysis.get("file_summaries", [])
        if isinstance(item, dict) and item.get("path")
    }

    assets: list[dict[str, object]] = []
    for path in files:
        relative = path.relative_to(target.resolve()).as_posix()
        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "Unknown")
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        tool_entries = normalized_tool_findings.get(relative, [])
        signals: list[dict[str, object]] = []
        for scanner in (
            _scan_sql_injection,
            _scan_idor,
            _scan_ssrf,
            _scan_deserialization,
            _scan_command_execution,
            _scan_path_traversal,
            _scan_memory_safety,
        ):
            signals.extend(scanner(lines, language, radius))
        signals = _dedupe_signals(signals)
        tree_payload = tree_index.get(relative, {}) if isinstance(tree_index.get(relative), dict) else {}
        risky_calls = [str(item) for item in tree_payload.get("risky_calls", []) if item][:6]
        selection_score, selection_reasons = _risk_score(tool_entries, signals, risky_calls, relative)
        if selection_score == 0:
            continue
        assets.append(
            {
                "path": relative,
                "component": relative.split("/", 1)[0],
                "language": language,
                "selection_score": selection_score,
                "selection_reasons": selection_reasons,
                "tool_categories": _tool_categories(tool_entries),
                "tool_findings": tool_entries[:8],
                "heuristic_signals": signals[:max_snippets],
                "tree_sitter": tree_payload,
            }
        )

    assets.sort(
        key=lambda item: (int(item["selection_score"]), len(item.get("heuristic_signals", [])), len(item.get("tool_findings", []))),
        reverse=True,
    )
    selected_assets = assets[:max_assets]
    clusters = _cluster_assets(selected_assets)
    review_focus = [cluster["summary"] for cluster in clusters[:6]]
    if not review_focus and selected_assets:
        review_focus = [f"Security hotspots selected for deep review: {', '.join(asset['path'] for asset in selected_assets[:6])}."]

    return {
        "available": bool(selected_assets),
        "target": str(target.resolve()),
        "scanned_files": len(files),
        "selected_assets_count": len(selected_assets),
        "selected_assets": selected_assets,
        "clusters": clusters,
        "review_focus": review_focus,
        "included_paths": codebase_metrics.get("included_paths", []),
        "excluded_paths": codebase_metrics.get("excluded_paths", []),
        "tree_sitter_highlights": tree_sitter_analysis.get("risk_highlights", []),
        "notes": [
            "This bundle is post-correlation evidence for focused code review. It is not a substitute for full manual verification.",
            "LLM review must rely on the provided snippets, cluster summaries and tool-backed anchors, not on speculation.",
        ],
    }
