from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path


PACKAGE_MANAGERS = ("apt-get", "dnf", "yum", "brew")
DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "vendor",
    "bin",
    "obj",
    "dist",
    "build",
    "coverage",
    "temp-delivery",
    "Delivery",
    "Reports",
    "reports",
    ".pytest_cache",
    ".mypy_cache",
}
LEGACY_HINTS = {"legacy", "archive", "deprecated", "old", "backup", "samples", "fixtures", "docs"}


@dataclass(slots=True)
class HostProfile:
    system: str
    shell: str
    package_manager: str | None
    is_linux: bool
    is_macos: bool
    docker_present: bool
    python_present: bool


@dataclass(slots=True)
class RepoProfile:
    root: Path
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    source_paths: list[Path] = field(default_factory=list)
    candidate_exclusions: list[Path] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def detect_host_profile() -> HostProfile:
    system = platform.system().lower()
    shell = os.environ.get("SHELL", "unknown")
    package_manager = next((pm for pm in PACKAGE_MANAGERS if shutil.which(pm)), None)
    return HostProfile(
        system=system,
        shell=shell,
        package_manager=package_manager,
        is_linux=system == "linux",
        is_macos=system == "darwin",
        docker_present=shutil.which("docker") is not None,
        python_present=shutil.which("python3") is not None,
    )


def detect_repo_profile(target: Path) -> RepoProfile:
    target = target.resolve()
    profile = RepoProfile(root=target)

    def has_any(*names: str) -> bool:
        for name in names:
            if any(target.glob(name)):
                return True
        return False

    if has_any("*.sln"):
        profile.languages.append(".NET")
    if has_any("Cargo.toml"):
        profile.languages.append("Rust")
    if has_any("pyproject.toml", "requirements.txt", "setup.py"):
        profile.languages.append("Python")
    if has_any("package.json", "pnpm-lock.yaml", "yarn.lock"):
        profile.languages.append("JavaScript/TypeScript")
    if has_any("go.mod"):
        profile.languages.append("Go")
    if has_any("composer.json"):
        profile.languages.append("PHP")
    if has_any("CMakeLists.txt", "Makefile", "meson.build"):
        profile.languages.append("C/C++")
    if has_any("pom.xml", "build.gradle", "gradlew"):
        profile.languages.append("Java")

    if (target / "Dockerfile").exists():
        profile.frameworks.append("Docker")
    if (target / "docker-compose.yml").exists() or (target / "compose.yaml").exists():
        profile.frameworks.append("Docker Compose")
    if (target / "src").exists():
        profile.source_paths.append(target / "src")
    if (target / "app").exists():
        profile.source_paths.append(target / "app")
    if not profile.source_paths:
        profile.source_paths.append(target)

    for item in sorted(target.iterdir()):
        if item.name in DEFAULT_EXCLUDES:
            continue
        if item.is_dir() and item.name.lower() in LEGACY_HINTS:
            profile.candidate_exclusions.append(item)

    if "C/C++" in profile.languages:
        profile.notes.append("Include memory-safety checks and unsafe primitive review.")
    if "Python" in profile.languages:
        profile.notes.append("Review concurrency, blocking I/O, multiprocessing and async usage.")
    if "PHP" in profile.languages:
        profile.notes.append("Review deserialization, SSRF, SQLi and dangerous dynamic execution.")
    if ".NET" in profile.languages:
        profile.notes.append("Review authorization, serialization, threading and configuration drift.")
    if "Rust" in profile.languages:
        profile.notes.append("Review unsafe blocks, FFI edges and release profile settings.")

    return profile


def build_exclude_args(profile: RepoProfile) -> list[str]:
    excludes = sorted(DEFAULT_EXCLUDES | {path.name for path in profile.candidate_exclusions})
    args: list[str] = []
    for name in excludes:
        args.extend(["--exclude", name])
    return args
