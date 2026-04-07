from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

DOCX_NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _extract_docx_text(path: Path, limit: int = 32000) -> str:
    if not path.exists():
        return ""
    try:
        with zipfile.ZipFile(path) as archive:
            xml_data = archive.read("word/document.xml")
    except (OSError, KeyError, zipfile.BadZipFile):
        return ""
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return ""
    paragraphs: list[str] = []
    for paragraph in root.findall(".//w:p", DOCX_NS):
        parts = [node.text or "" for node in paragraph.findall(".//w:t", DOCX_NS)]
        line = re.sub(r"\s+", " ", "".join(parts)).strip()
        if line:
            paragraphs.append(line)
    return "\n".join(paragraphs)[:limit]


def _find_first(root: Path, *patterns: str) -> Path | None:
    for pattern in patterns:
        matches = sorted(root.rglob(pattern))
        if matches:
            return matches[0]
    return None


def _engagement_payload(reference_root: Path, client_name: str, project_name: str) -> dict[str, Any]:
    engagement_root = reference_root / "engagement"
    if not engagement_root.exists():
        return {}
    client_slug = _slug(client_name)
    project_slug = _slug(project_name)
    candidates = sorted(engagement_root.glob("*.json"))
    preferred: list[Path] = []
    for item in candidates:
        stem = _slug(item.stem)
        if client_slug and client_slug in stem:
            preferred.append(item)
        elif project_slug and project_slug in stem:
            preferred.append(item)
    chosen = preferred[0] if preferred else (candidates[0] if candidates else None)
    return _read_json(chosen) if chosen else {}


def load_reference_bundle(reference_root: Path, client_name: str = "", project_name: str = "") -> dict[str, Any]:
    root = Path(reference_root)
    if not root.exists():
        return {"available": False, "reference_root": str(root)}
    hld_docx = _find_first(root, "*HLD*.docx")
    horis_pdf = _find_first(root, "*HORIS*.pdf")
    template_docx = _find_first(root, "template.docx")
    engagement = _engagement_payload(root, client_name, project_name)
    return {
        "available": any((hld_docx, horis_pdf, template_docx, engagement)),
        "reference_root": str(root),
        "hld_docx_path": str(hld_docx) if hld_docx else "",
        "hld_text": _extract_docx_text(hld_docx) if hld_docx else "",
        "horis_pdf_path": str(horis_pdf) if horis_pdf else "",
        "template_docx_path": str(template_docx) if template_docx else "",
        "canonical_graphic_reference_path": str(template_docx) if template_docx else "",
        "graphic_reference_mode": "docx" if template_docx else "",
        "engagement": engagement,
    }
