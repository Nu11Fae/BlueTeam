from __future__ import annotations

import os
from collections import defaultdict
from pathlib import Path

from .detect import DEFAULT_EXCLUDES, RepoProfile


LANGUAGE_BY_SUFFIX = {
    ".cs": ".NET",
    ".rs": "Rust",
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript/TypeScript",
    ".jsx": "JavaScript/TypeScript",
    ".ts": "JavaScript/TypeScript",
    ".tsx": "JavaScript/TypeScript",
    ".go": "Go",
    ".php": "PHP",
    ".c": "C/C++",
    ".h": "C/C++",
    ".hpp": "C/C++",
    ".hh": "C/C++",
    ".cc": "C/C++",
    ".cpp": "C/C++",
    ".cxx": "C/C++",
    ".java": "Java",
    ".kt": "Java",
    ".kts": "Java",
    ".swift": "Swift",
    ".rb": "Ruby",
    ".scala": "Scala",
}

COMMENT_PREFIXES = {
    ".NET": ("//",),
    "Rust": ("//",),
    "Python": ("#",),
    "JavaScript/TypeScript": ("//",),
    "Go": ("//",),
    "PHP": ("//", "#"),
    "C/C++": ("//",),
    "Java": ("//",),
    "Swift": ("//",),
    "Ruby": ("#",),
    "Scala": ("//",),
}

BINARY_SUFFIXES = {
    ".dll",
    ".exe",
    ".so",
    ".dylib",
    ".a",
    ".o",
    ".class",
    ".jar",
    ".war",
    ".ear",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".bin",
    ".wasm",
}


def _language_for_path(path: Path) -> str | None:
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def _source_roots(profile: RepoProfile) -> list[Path]:
    if profile.source_paths:
        return [path for path in profile.source_paths if path.exists()]
    return [profile.root]


def _skip_path(path: Path, root: Path, candidate_exclusions: set[Path]) -> bool:
    relative = path.relative_to(root)
    if any(part in DEFAULT_EXCLUDES for part in relative.parts):
        return True
    if any(part.startswith(".") and part not in {".config"} for part in relative.parts[:-1]):
        return True
    if any(excluded in path.parents or excluded == path for excluded in candidate_exclusions):
        return True
    return False


def _count_lines(path: Path, language: str) -> dict[str, int]:
    total = 0
    blank = 0
    comment = 0
    prefixes = COMMENT_PREFIXES.get(language, ())
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        total += 1
        stripped = raw_line.strip()
        if not stripped:
            blank += 1
            continue
        if any(stripped.startswith(prefix) for prefix in prefixes):
            comment += 1
    return {
        "total_lines": total,
        "blank_lines": blank,
        "comment_lines": comment,
        "code_lines": max(total - blank - comment, 0),
    }


def _iter_metric_files(target: Path, source_root: Path, candidate_exclusions: set[Path]) -> list[Path]:
    files: list[Path] = []
    root = target.resolve()
    source_root = source_root.resolve()
    for current_root, dirnames, filenames in os.walk(source_root, topdown=True, followlinks=False):
        current_path = Path(current_root)
        relative_root = current_path.relative_to(root)
        dirnames[:] = [
            entry
            for entry in sorted(dirnames)
            if not _skip_path(current_path / entry, root, candidate_exclusions)
        ]
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
            files.append(path)
    return files


def collect_codebase_metrics(target: Path, profile: RepoProfile) -> dict[str, object]:
    root = target.resolve()
    candidate_exclusions = {path.resolve() for path in profile.candidate_exclusions}
    totals = {"files": 0, "total_lines": 0, "blank_lines": 0, "comment_lines": 0, "code_lines": 0}
    by_language: dict[str, dict[str, int]] = {}
    path_totals: dict[str, int] = defaultdict(int)
    included_files: list[str] = []

    for source_root in _source_roots(profile):
        for path in _iter_metric_files(root, source_root, candidate_exclusions):
            if path.suffix.lower() in BINARY_SUFFIXES:
                continue
            language = _language_for_path(path)
            if language is None:
                continue
            counts = _count_lines(path, language)
            totals["files"] += 1
            for key, value in counts.items():
                totals[key] += value
            language_bucket = by_language.setdefault(
                language,
                {"files": 0, "total_lines": 0, "blank_lines": 0, "comment_lines": 0, "code_lines": 0},
            )
            language_bucket["files"] += 1
            for key, value in counts.items():
                language_bucket[key] += value
            relative = path.relative_to(root).as_posix()
            included_files.append(relative)
            scope_key = relative.split("/", 1)[0]
            path_totals[scope_key] += counts["code_lines"]

    excluded_paths = sorted({path.relative_to(root).as_posix() for path in candidate_exclusions if path.exists()})
    top_paths = [
        {"path": path, "code_lines": code_lines}
        for path, code_lines in sorted(path_totals.items(), key=lambda item: item[1], reverse=True)
        if code_lines > 0
    ]
    return {
        "root": str(root),
        "files": totals["files"],
        "total_lines": totals["total_lines"],
        "blank_lines": totals["blank_lines"],
        "comment_lines": totals["comment_lines"],
        "code_lines": totals["code_lines"],
        "by_language": by_language,
        "included_paths": [entry["path"] for entry in top_paths[:12]],
        "excluded_paths": excluded_paths,
        "top_paths": top_paths[:20],
        "sample_files": included_files[:50],
    }
