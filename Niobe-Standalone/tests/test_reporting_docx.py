from pathlib import Path

from docx import Document

from Python3.reporting import render_docx, render_report


def _context(tmp_path: Path) -> dict[str, object]:
    return {
        "project_name": "Digital Audit",
        "client_name": "Intrum",
        "summary": {"executive_summary": "Executive summary body."},
        "repo_profile": {"languages": ["Python", "JavaScript"], "frameworks": ["FastAPI"], "source_paths": ["src/app"]},
        "codebase_metrics": {"files": 12, "code_lines": 3456, "by_language": {"Python": {"code_lines": 3000}, "JavaScript": {"code_lines": 456}}},
        "tool_results": {},
        "risk_register_payload": [
            {"finding_id": "F-1", "title": "Weak crypto", "grade": "D", "classification": "Red Flag"},
            {"finding_id": "F-2", "title": "Secrets in repo", "grade": "C", "classification": "Integration Item"},
        ],
        "manifest": {"source": str(tmp_path), "target": str(tmp_path)},
        "analysis_target_path": str(tmp_path),
    }


def test_render_docx_generates_structured_output(tmp_path: Path) -> None:
    template_root = Path("templates")
    context = _context(tmp_path)
    md_path = tmp_path / "report.md"
    render_report(template_root, context, md_path)
    out_path = tmp_path / "report.docx"
    render_docx(md_path, context, out_path)
    assert out_path.exists()
    doc = Document(str(out_path))
    all_text = "\n".join(p.text for p in doc.paragraphs)
    assert "Executive rating" in all_text
    assert "KPI di perimetro" in all_text
    assert "Top finding prioritari" in all_text
