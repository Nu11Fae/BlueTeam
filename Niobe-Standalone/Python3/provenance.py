from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable


def _read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _mac_platform_uuid() -> str | None:
    try:
        result = subprocess.run(
            ["sh", "-lc", "ioreg -rd1 -c IOPlatformExpertDevice | awk -F '\"' '/IOPlatformUUID/ {print $4; exit}'"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    value = result.stdout.strip()
    return value or None


def _split_env_csv(name: str) -> list[str]:
    value = os.environ.get(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _excluded(relative_path: Path, exclude_prefixes: set[str]) -> bool:
    relative = relative_path.as_posix()
    return any(relative == prefix or relative.startswith(f"{prefix}/") for prefix in exclude_prefixes)


def sha512_directory(path: Path, exclude: Iterable[str] | None = None) -> tuple[str, list[str]]:
    digest = hashlib.sha512()
    excluded_prefixes = {item.strip("/ ") for item in (exclude or []) if item.strip("/ ")}
    skipped: list[str] = []
    for root, dirnames, filenames in os.walk(path, topdown=True, followlinks=False):
        root_path = Path(root)
        relative_root = root_path.relative_to(path)
        dirnames[:] = [
            entry
            for entry in sorted(dirnames)
            if not _excluded(relative_root / entry, excluded_prefixes)
        ]
        for filename in sorted(filenames):
            item = root_path / filename
            relative_path = item.relative_to(path)
            if _excluded(relative_path, excluded_prefixes):
                continue
            try:
                if item.is_symlink() and not item.exists():
                    skipped.append(relative_path.as_posix())
                    continue
                if item.is_dir():
                    continue
                relative = relative_path.as_posix().encode("utf-8")
                digest.update(relative)
                digest.update(b"\0")
                digest.update(sha512_file(item).encode("utf-8"))
                digest.update(b"\0")
            except OSError:
                skipped.append(relative_path.as_posix())
    return digest.hexdigest(), skipped


def repo_hash(target: Path, exclude: Iterable[str] | None = None) -> tuple[str, list[str]]:
    if target.is_dir():
        return sha512_directory(target, exclude=exclude)
    return sha512_file(target), []


def _int_env(name: str) -> int | None:
    value = os.environ.get(name, "").strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _float_env(name: str) -> float | None:
    value = os.environ.get(name, "").strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def file_metadata(path: Path, env_prefix: str | None = None) -> dict[str, object]:
    try:
        info = path.stat()
        return {
            "path": str(path),
            "inode": info.st_ino,
            "size": info.st_size,
            "mode": stat.filemode(info.st_mode),
            "mtime": info.st_mtime,
            "exists_on_runner": True,
        }
    except OSError:
        payload: dict[str, object] = {
            "path": str(path),
            "exists_on_runner": False,
        }
        if env_prefix:
            inode = _int_env(f"{env_prefix}_INODE")
            size = _int_env(f"{env_prefix}_SIZE")
            mode = os.environ.get(f"{env_prefix}_MODE", "").strip()
            mtime = _float_env(f"{env_prefix}_MTIME")
            if inode is not None:
                payload["inode"] = inode
            if size is not None:
                payload["size"] = size
            if mode:
                payload["mode"] = mode
            if mtime is not None:
                payload["mtime"] = mtime
            if len(payload) > 2:
                payload["captured_from_host"] = True
        return payload


def _ip_addresses() -> list[str]:
    override = _split_env_csv("NIOBE_IP_ADDRESSES")
    if override:
        return sorted(set(override))
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ":" not in ip and not ip.startswith("127."):
                ips.add(ip)
    except OSError:
        pass
    try:
        output = subprocess.run(["sh", "-lc", "hostname -I 2>/dev/null || true"], capture_output=True, text=True).stdout
        for token in output.split():
            if "." in token:
                ips.add(token)
    except OSError:
        pass
    return sorted(ips)


def collect_manifest(target: Path, source: Path, run_dir: Path) -> dict[str, object]:
    target = target.resolve()
    source = source.resolve()
    run_dir = run_dir.resolve()
    now = datetime.now(UTC)
    hostname = os.environ.get("NIOBE_HOSTNAME") or socket.gethostname()
    cwd = os.environ.get("NIOBE_HOST_CWD", str(Path.cwd()))
    boot_id = os.environ.get("NIOBE_BOOT_ID") or _read_text("/proc/sys/kernel/random/boot_id")
    machine_id = os.environ.get("NIOBE_MACHINE_ID") or _read_text("/etc/machine-id") or _mac_platform_uuid()
    tty_name = os.environ.get("NIOBE_HOST_TTY") or (os.ttyname(0) if os.isatty(0) else "not-a-tty")
    monotonic_ns = os.environ.get("NIOBE_HOST_MONOTONIC_NS") or str(time.monotonic_ns())

    hash_excludes: list[str] = []
    try:
        if run_dir.is_relative_to(target):
            hash_excludes.append(run_dir.relative_to(target).as_posix())
    except ValueError:
        pass
    repo_sha512, hash_skipped = repo_hash(target, exclude=hash_excludes)
    excluded_prefixes = {item.strip("/ ") for item in hash_excludes if item.strip("/ ")}
    file_hash_map: dict[str, str] = {}
    if target.is_dir():
        for root, _, filenames in os.walk(target, followlinks=False):
            for fname in sorted(filenames):
                fpath = Path(root) / fname
                rel = fpath.relative_to(target).as_posix()
                if _excluded(fpath.relative_to(target), excluded_prefixes):
                    continue
                try:
                    file_hash_map[rel] = sha512_file(fpath)
                except OSError:
                    pass
    manifest = {
        "run_id": run_dir.name,
        "created_at_utc": now.isoformat(),
        "clock_monotonic_ns": int(monotonic_ns),
        "hostname": hostname,
        "ip_addresses": _ip_addresses(),
        "cwd": cwd,
        "source": str(source),
        "target": str(target),
        "repo_sha512": repo_sha512,
        "repo_hash_excludes": hash_excludes,
        "repo_hash_skipped_entries": hash_skipped,
        "boot_id": boot_id,
        "machine_id": machine_id,
        "tty": tty_name,
        "target_metadata": file_metadata(target, env_prefix="NIOBE_TARGET"),
        "source_metadata": file_metadata(source, env_prefix="NIOBE_SOURCE"),
        "host_environment": {
            "system": os.environ.get("NIOBE_HOST_OS") or platform.system(),
            "shell": os.environ.get("NIOBE_HOST_SHELL") or os.environ.get("SHELL", "unknown"),
            "analysis_layer": "Digital Audit",
            "containerized": True,
        },
    }
    fs_payload = {
        "fstype": os.environ.get("NIOBE_FSTYPE", ""),
        "uuid": os.environ.get("NIOBE_FILESYSTEM_UUID", ""),
        "source": os.environ.get("NIOBE_FILESYSTEM_SOURCE", ""),
        "target": os.environ.get("NIOBE_FILESYSTEM_TARGET", ""),
    }
    if any(fs_payload.values()):
        manifest["filesystem"] = fs_payload
        manifest["file_hashes"] = file_hash_map
        return manifest
    findmnt = shutil.which("findmnt")
    if findmnt:
        result = subprocess.run(
            [findmnt, "-no", "FSTYPE,UUID,SOURCE,TARGET", "--target", str(target)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            fields = result.stdout.strip().split()
            if len(fields) >= 4:
                manifest["filesystem"] = {
                    "fstype": fields[0],
                    "uuid": fields[1],
                    "source": fields[2],
                    "target": fields[3],
                }
    manifest["file_hashes"] = file_hash_map
    return manifest


def write_manifest(manifest: dict[str, object], path: Path) -> Path:
    preferred = [
        "run_id",
        "created_at_utc",
        "clock_monotonic_ns",
        "hostname",
        "ip_addresses",
        "cwd",
        "source",
        "target",
        "repo_sha512",
        "repo_hash_excludes",
        "repo_hash_skipped_entries",
        "boot_id",
        "machine_id",
        "tty",
        "target_metadata",
        "source_metadata",
        "host_environment",
        "filesystem",
        "file_hashes",
    ]
    ordered = {key: manifest[key] for key in preferred if key in manifest}
    for key, value in manifest.items():
        if key not in ordered:
            ordered[key] = value
    path.write_text(json.dumps(ordered, indent=2, sort_keys=False), encoding="utf-8")
    return path


def timestamp_file(path: Path, signatures_dir: Path) -> Path | None:
    if shutil.which("ots") is None:
        return None
    stamped = signatures_dir / f"{path.name}.ots"
    result = subprocess.run(["ots", "stamp", str(path)], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    generated = Path(str(path) + ".ots")
    if generated.exists():
        generated.replace(stamped)
        return stamped
    return None


def ensure_runtime_gpg_home() -> Path:
    return Path(tempfile.mkdtemp(prefix="niobe-gpg-"))


def generate_runtime_key(gpg_home: Path) -> str:
    result = subprocess.run(
        [
            "gpg",
            "--homedir",
            str(gpg_home),
            "--batch",
            "--passphrase",
            "",
            "--quick-gen-key",
            "Tecnolife <ops@tecnolife.com>",
            "ed25519",
            "sign",
            "1d",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "gpg key generation failed")
    listing = subprocess.run(
        ["gpg", "--homedir", str(gpg_home), "--list-secret-keys", "--with-colons"],
        capture_output=True,
        text=True,
        check=False,
    )
    for line in listing.stdout.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise RuntimeError("could not determine runtime GPG fingerprint")


def _sign_file(
    gpg_home: Path,
    fingerprint: str,
    item: Path,
    signature_path: Path,
    armor: bool = True,
) -> bool:
    command = [
        "gpg",
        "--homedir",
        str(gpg_home),
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--local-user",
        fingerprint,
        "--output",
        str(signature_path),
    ]
    command.extend(["--armor", "--include-key-block", "--detach-sign", str(item)])
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and signature_path.exists()


def sign_delivery(
    delivery_dir: Path,
    signatures_dir: Path,
    detached_artifacts: list[tuple[Path, Path]] | None = None,
    deferred_detached_artifacts: list[Callable[[], tuple[Path, Path]]] | None = None,
) -> dict[str, str]:
    if shutil.which("gpg") is None:
        signatures_dir.mkdir(parents=True, exist_ok=True)
        (signatures_dir / "SIGNING_SKIPPED.txt").write_text("gpg not available\n", encoding="utf-8")
        return {}
    signatures_dir.mkdir(parents=True, exist_ok=True)
    gpg_home = ensure_runtime_gpg_home()
    try:
        fingerprint = generate_runtime_key(gpg_home)
        created: dict[str, str] = {}
        for item in sorted(delivery_dir.iterdir()):
            if item.is_dir():
                continue
            signature_path = signatures_dir / f"{item.name}.asc"
            if _sign_file(gpg_home, fingerprint, item, signature_path, armor=True):
                created[item.name] = signature_path.name
                timestamp_file(item, signatures_dir)
                timestamp_file(signature_path, signatures_dir)
        for item, signature_path in detached_artifacts or []:
            signature_path.parent.mkdir(parents=True, exist_ok=True)
            if _sign_file(gpg_home, fingerprint, item, signature_path, armor=True):
                created[item.name] = str(signature_path.name)
                timestamp_file(item, signature_path.parent)
                timestamp_file(signature_path, signature_path.parent)
        export_result = subprocess.run(
            ["gpg", "--homedir", str(gpg_home), "--armor", "--export", fingerprint],
            capture_output=True,
            text=True,
            check=False,
        )
        if export_result.returncode == 0 and export_result.stdout:
            public_key_path = signatures_dir / "Tecnolife-public-key.asc"
            public_key_path.write_text(export_result.stdout, encoding="utf-8")
            timestamp_file(public_key_path, signatures_dir)
        fingerprint_path = signatures_dir / "runtime_fingerprint.txt"
        fingerprint_path.write_text(fingerprint + "\n", encoding="utf-8")
        timestamp_file(fingerprint_path, signatures_dir)
        for builder in deferred_detached_artifacts or []:
            item, signature_path = builder()
            signature_path.parent.mkdir(parents=True, exist_ok=True)
            if _sign_file(gpg_home, fingerprint, item, signature_path, armor=True):
                created[item.name] = str(signature_path.name)
                timestamp_file(item, signature_path.parent)
                timestamp_file(signature_path, signature_path.parent)
        return created
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def sign_directory_tree(directory: Path, signatures_dir: Path) -> dict[str, str]:
    if not directory.exists():
        return {}
    return sign_delivery(directory, signatures_dir)
