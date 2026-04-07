from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .detect import HostProfile


ROOT = Path(os.environ["NIOBE_APP_ROOT"]).resolve() if os.environ.get("NIOBE_APP_ROOT") else Path(__file__).resolve().parent.parent
AUDIT_RUNNER_IMAGE = "niobe"


def _run(cmd: list[str], allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, text=True, capture_output=True)
    if result.returncode != 0 and not allow_failure:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr.strip()}")
    return result


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _rootless_target_user() -> str:
    user = (os.environ.get("SUDO_USER") or os.environ.get("USER") or "").strip()
    if not user:
        raise RuntimeError("cannot determine the non-root target user for Docker rootless setup")
    if user == "root":
        raise RuntimeError("run the installer as the target non-root user; the setup elevates with sudo internally")
    return user


def _rootless_socket_candidates(user: str) -> list[str]:
    uid = subprocess.run(["id", "-u", user], capture_output=True, text=True, check=False)
    candidates: list[str] = []
    if uid.returncode == 0:
        resolved_uid = uid.stdout.strip()
        if resolved_uid:
            candidates.append(f"/run/user/{resolved_uid}/docker.sock")
    candidates.append(str(Path.home() / ".docker" / "run" / "docker.sock"))
    return candidates


def _rootless_docker_ready(user: str) -> bool:
    if not command_exists("docker"):
        return False
    for candidate in _rootless_socket_candidates(user):
        env = os.environ.copy()
        env["DOCKER_HOST"] = f"unix://{candidate}"
        result = subprocess.run(
            ["docker", "info", "--format", "{{json .SecurityOptions}}"],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        if result.returncode == 0 and "rootless" in result.stdout.lower():
            return True
    return False


def install_with_package_manager(profile: HostProfile, packages: list[str]) -> None:
    if not profile.package_manager:
        return
    if profile.package_manager == "apt-get":
        _run(["sudo", "apt-get", "update"])
        for package in packages:
            _run(["sudo", "apt-get", "install", "-y", package], allow_failure=True)
    elif profile.package_manager == "dnf":
        for package in packages:
            _run(["sudo", "dnf", "install", "-y", package], allow_failure=True)
    elif profile.package_manager == "yum":
        for package in packages:
            _run(["sudo", "yum", "install", "-y", package], allow_failure=True)
    elif profile.package_manager == "brew":
        for package in packages:
            _run(["brew", "install", package], allow_failure=True)


def ensure_docker(profile: HostProfile) -> str:
    if profile.is_linux:
        user = _rootless_target_user()
        if _rootless_docker_ready(user):
            return f"docker rootless already present for {user}"
        installer = ROOT / "scripts" / "install-docker-rootless"
        if not installer.exists():
            raise RuntimeError(f"missing rootless docker installer: {installer}")
        _run(["sudo", str(installer), user])
        if not _rootless_docker_ready(user):
            raise RuntimeError("docker rootless setup completed but the user socket is not reachable yet")
        return f"docker rootless installed for {user}"
    if command_exists("docker"):
        return "docker already present"
    if profile.is_macos and profile.package_manager == "brew":
        _run(["brew", "install", "--cask", "docker"])
        return "docker installed with Homebrew cask"
    raise RuntimeError("docker installation is only automated for Linux and Homebrew hosts")


def ensure_base_utils(profile: HostProfile, include_optional_analysis: bool = False) -> list[str]:
    results: list[str] = []
    if profile.is_linux and profile.package_manager in {"apt-get", "dnf", "yum"}:
        results.append("linux host kept thin: Docker is expected in rootless mode for the invoking user")
    elif profile.is_macos:
        results.append("macOS host kept thin: Docker is required, tooling stays inside the audit image")
    if command_exists("codex"):
        results.append("codex CLI detected on host")
    else:
        results.append("codex CLI not detected on host")
    if command_exists("claude"):
        results.append("claude CLI detected on host")
    else:
        results.append("claude CLI not detected on host")
    if include_optional_analysis:
        results.append("full profile selected: SonarQube and FOSSology env vars can be passed at runtime")
    return results


def ensure_audit_runner_image(image: str = AUDIT_RUNNER_IMAGE) -> str:
    force_rebuild = (os.environ.get("NIOBE_FORCE_REBUILD") or "").strip().lower() in {"1", "true", "yes", "on"}
    inspect = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
    if inspect.returncode == 0 and not force_rebuild:
        return f"{image} already present"
    dockerfile = ROOT / "Docker" / "Dockerfile.audit"
    platform = (os.environ.get("NIOBE_AUDIT_PLATFORM") or "").strip()
    build_cmd = ["docker", "build"]
    if platform:
        build_cmd.extend(["--platform", platform])
    build_cmd.extend(["-f", str(dockerfile), "-t", image, str(ROOT)])
    result = subprocess.run(
        build_cmd,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"failed to build {image}")
    return f"{image} built from {dockerfile.name}"
