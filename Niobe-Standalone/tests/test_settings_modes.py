import os
from pathlib import Path

from Python3.settings import AppSettings


def test_standalone_mode_does_not_create_storage_dirs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NIOBE_APP_ROOT", str(tmp_path))
    monkeypatch.setenv("NIOBE_STANDALONE_MODE", "1")
    settings = AppSettings()
    settings.ensure_dirs()
    assert not (tmp_path / "storage").exists()
    assert not (tmp_path / "reports").exists()


def test_control_plane_mode_creates_storage_dirs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NIOBE_APP_ROOT", str(tmp_path))
    monkeypatch.setenv("NIOBE_CONTROL_PLANE_MODE", "1")
    settings = AppSettings()
    settings.ensure_dirs()
    assert (tmp_path / "storage").exists()
    assert (tmp_path / "storage" / "uploads").exists()
    assert (tmp_path / "storage" / "deliverables").exists()
