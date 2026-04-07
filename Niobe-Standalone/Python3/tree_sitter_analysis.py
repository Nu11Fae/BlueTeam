from __future__ import annotations

import os
from collections import Counter, defaultdict
from pathlib import Path

from .detect import DEFAULT_EXCLUDES, RepoProfile
from .metrics import BINARY_SUFFIXES, LANGUAGE_BY_SUFFIX


PARSER_BY_SUFFIX = {
    ".cs": "c_sharp",
    ".rs": "rust",
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".java": "java",
    ".rb": "ruby",
}

FUNCTION_NODE_TYPES = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "method_definition", "function"},
    "typescript": {"function_declaration", "method_definition", "function"},
    "tsx": {"function_declaration", "method_definition", "function"},
    "go": {"function_declaration", "method_declaration"},
    "php": {"function_definition", "method_declaration"},
    "rust": {"function_item"},
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "java": {"method_declaration", "constructor_declaration"},
    "c_sharp": {"method_declaration", "constructor_declaration", "local_function_statement"},
    "ruby": {"method"},
}

CLASS_NODE_TYPES = {
    "python": {"class_definition"},
    "javascript": {"class_declaration"},
    "typescript": {"class_declaration", "interface_declaration"},
    "tsx": {"class_declaration", "interface_declaration"},
    "go": {"type_declaration"},
    "php": {"class_declaration", "interface_declaration", "trait_declaration"},
    "rust": {"struct_item", "enum_item", "trait_item", "impl_item"},
    "c": {"struct_specifier", "union_specifier", "enum_specifier"},
    "cpp": {"class_specifier", "struct_specifier", "enum_specifier"},
    "java": {"class_declaration", "interface_declaration", "enum_declaration"},
    "c_sharp": {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration"},
    "ruby": {"class", "module"},
}

IMPORT_NODE_TYPES = {
    "python": {"import_statement", "import_from_statement"},
    "javascript": {"import_statement", "require_call"},
    "typescript": {"import_statement", "require_call"},
    "tsx": {"import_statement", "require_call"},
    "go": {"import_declaration"},
    "php": {"namespace_use_declaration", "require_expression", "include_expression"},
    "rust": {"use_declaration"},
    "java": {"import_declaration"},
    "c_sharp": {"using_directive"},
    "ruby": {"call"},
}

ASYNC_NODE_TYPES = {
    "python": {"async_function_definition", "await"},
    "javascript": {"await_expression"},
    "typescript": {"await_expression"},
    "tsx": {"await_expression"},
    "c_sharp": {"await_expression"},
}

UNSAFE_NODE_TYPES = {
    "rust": {"unsafe_block", "unsafe"},
    "c": {"pointer_declarator"},
    "cpp": {"pointer_declarator", "reference_declarator"},
}

RISKY_CALLS = {
    "Python": {"eval", "exec", "pickle.loads", "subprocess.Popen", "os.system"},
    "JavaScript/TypeScript": {"eval", "Function", "exec", "spawn", "execSync"},
    "PHP": {"unserialize", "eval", "exec", "shell_exec", "system", "passthru"},
    "C/C++": {"strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy"},
    ".NET": {"BinaryFormatter.Deserialize", "Process.Start", "FromSqlRaw", "ExecuteSqlRaw"},
    "Rust": {"from_utf8_unchecked", "Command::new"},
    "Java": {"Runtime.getRuntime", "ProcessBuilder", "readObject"},
}


def _parser(language_name: str):
    get_parser = None
    try:
        from tree_sitter_language_pack import get_parser as language_pack_get_parser
        get_parser = language_pack_get_parser
    except ImportError:
        try:
            from tree_sitter_languages import get_parser as legacy_get_parser
            get_parser = legacy_get_parser
        except ImportError:
            return None
    try:
        return get_parser(language_name)
    except Exception:
        return None


def _skip_path(path: Path, root: Path, candidate_exclusions: set[Path]) -> bool:
    relative = path.relative_to(root)
    if any(part in DEFAULT_EXCLUDES for part in relative.parts):
        return True
    if any(part.startswith(".") and part not in {".config"} for part in relative.parts[:-1]):
        return True
    if any(excluded in path.parents or excluded == path for excluded in candidate_exclusions):
        return True
    return False


def _iter_source_files(target: Path, profile: RepoProfile) -> list[Path]:
    root = target.resolve()
    candidate_exclusions = {path.resolve() for path in profile.candidate_exclusions}
    files: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current_root)
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
            if path.suffix.lower() in BINARY_SUFFIXES:
                continue
            if path.suffix.lower() not in PARSER_BY_SUFFIX:
                continue
            files.append(path)
    return files


def _collect_node_counts(root_node, language_name: str, source_text: bytes) -> dict[str, object]:
    counters = Counter()
    risky_hits: set[str] = set()
    function_nodes = FUNCTION_NODE_TYPES.get(language_name, set())
    class_nodes = CLASS_NODE_TYPES.get(language_name, set())
    import_nodes = IMPORT_NODE_TYPES.get(language_name, set())
    async_nodes = ASYNC_NODE_TYPES.get(language_name, set())
    unsafe_nodes = UNSAFE_NODE_TYPES.get(language_name, set())

    stack = [root_node]
    while stack:
        node = stack.pop()
        node_type = node.type
        if node_type in function_nodes:
            counters["functions"] += 1
        if node_type in class_nodes:
            counters["classes"] += 1
        if node_type in import_nodes:
            counters["imports"] += 1
        if node_type in async_nodes:
            counters["async_markers"] += 1
        if node_type in unsafe_nodes:
            counters["unsafe_markers"] += 1
        if node_type in {"call_expression", "method_invocation", "function_call_expression", "command_name"}:
            snippet = source_text[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
            compact = " ".join(snippet.split())
            if compact:
                risky_hits.add(compact[:160])
        stack.extend(reversed(node.children))
    return {
        "functions": counters["functions"],
        "classes": counters["classes"],
        "imports": counters["imports"],
        "async_markers": counters["async_markers"],
        "unsafe_markers": counters["unsafe_markers"],
        "raw_calls": sorted(risky_hits)[:120],
    }


def _match_risky_calls(language: str, raw_calls: list[str]) -> list[str]:
    patterns = RISKY_CALLS.get(language, set())
    hits: set[str] = set()
    for call in raw_calls:
        for pattern in patterns:
            if pattern in call:
                hits.add(pattern)
    return sorted(hits)


def collect_tree_sitter_analysis(target: Path, profile: RepoProfile) -> dict[str, object]:
    files = _iter_source_files(target, profile)
    if not files:
        return {
            "available": False,
            "files_parsed": 0,
            "reason": "no supported core source files for tree-sitter analysis",
            "languages": {},
            "file_summaries": [],
            "risk_highlights": [],
        }

    file_summaries: list[dict[str, object]] = []
    language_rollup: dict[str, dict[str, object]] = defaultdict(
        lambda: {"files": 0, "functions": 0, "classes": 0, "imports": 0, "async_markers": 0, "unsafe_markers": 0, "risky_calls": []}
    )
    risk_highlights: list[str] = []
    parsed_files = 0
    parser_cache: dict[str, object] = {}

    for path in files[:160]:
        suffix = path.suffix.lower()
        parser_name = PARSER_BY_SUFFIX.get(suffix)
        language_label = LANGUAGE_BY_SUFFIX.get(suffix, "Unknown")
        if not parser_name:
            continue
        parser = parser_cache.get(parser_name)
        if parser is None:
            parser = _parser(parser_name)
            parser_cache[parser_name] = parser
        if parser is None:
            continue
        source_text = path.read_bytes()
        try:
            tree = parser.parse(source_text)
        except Exception:
            continue
        counts = _collect_node_counts(tree.root_node, parser_name, source_text)
        risky_calls = _match_risky_calls(language_label, counts.pop("raw_calls"))
        relative = path.relative_to(target.resolve()).as_posix()
        summary = {
            "path": relative,
            "language": language_label,
            "functions": counts["functions"],
            "classes": counts["classes"],
            "imports": counts["imports"],
            "async_markers": counts["async_markers"],
            "unsafe_markers": counts["unsafe_markers"],
            "risky_calls": risky_calls,
        }
        file_summaries.append(summary)
        parsed_files += 1
        rollup = language_rollup[language_label]
        rollup["files"] += 1
        for key in ("functions", "classes", "imports", "async_markers", "unsafe_markers"):
            rollup[key] += int(summary[key])
        rollup["risky_calls"] = sorted(set(rollup["risky_calls"]) | set(risky_calls))

    for language, payload in sorted(language_rollup.items()):
        if payload["unsafe_markers"]:
            risk_highlights.append(f"{language}: {payload['unsafe_markers']} unsafe or low-level markers detected.")
        if payload["risky_calls"]:
            risk_highlights.append(f"{language}: risky API surface observed -> {', '.join(payload['risky_calls'])}.")
        if payload["async_markers"]:
            risk_highlights.append(f"{language}: {payload['async_markers']} async/concurrency markers detected.")

    return {
        "available": parsed_files > 0,
        "files_parsed": parsed_files,
        "languages": dict(sorted(language_rollup.items())),
        "file_summaries": file_summaries[:60],
        "risk_highlights": risk_highlights[:20],
    }
