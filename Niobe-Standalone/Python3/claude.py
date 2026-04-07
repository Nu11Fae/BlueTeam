from __future__ import annotations

import json
import os
import shutil
import shlex
import subprocess
import time
from pathlib import Path

LLM_MAX_RETRIES = 3
LLM_RETRY_BASE_DELAY = 2


def claude_available() -> bool:
    return shutil.which("claude") is not None


def codex_available() -> bool:
    return shutil.which("codex") is not None


def _normalize_provider(provider: str) -> str | None:
    normalized = provider.strip().lower()
    aliases = {
        "1": "claude",
        "anthropic": "claude",
        "claude": "claude",
        "2": "codex",
        "openai": "codex",
        "codex": "codex",
    }
    return aliases.get(normalized)


def build_prompt(
    system_prompt: Path,
    audit_prompt: Path,
    context: dict[str, object],
    output_path: Path,
    extra_prompt_paths: list[Path] | None = None,
) -> Path:
    prompt = [system_prompt.read_text(encoding="utf-8").strip(), "", audit_prompt.read_text(encoding="utf-8").strip()]
    for extra_path in extra_prompt_paths or []:
        prompt.extend(["", extra_path.read_text(encoding="utf-8").strip()])
    prompt.extend(["", "Context payload:", json.dumps(context, indent=2, sort_keys=True, default=str)])
    output_path.write_text("\n".join(prompt), encoding="utf-8")
    return output_path


def _run_template_command(prompt_path: Path, output_path: Path, command_template: str, env: dict[str, str], working_dir: Path) -> dict[str, object]:
    prompt = prompt_path.read_text(encoding="utf-8")
    rendered = command_template.replace("{prompt_path}", str(prompt_path)).replace("{output_path}", str(output_path)).replace("{working_dir}", str(working_dir))
    last_err = ""
    for attempt in range(LLM_MAX_RETRIES):
        if "{prompt}" in rendered:
            safe = rendered.replace("{prompt}", prompt.replace('"', '\\"'))
            result = subprocess.run(safe, capture_output=True, text=True, env=env, shell=True, cwd=working_dir)
        elif any(token in command_template for token in ("{prompt_path}", "{output_path}", "{working_dir}")):
            result = subprocess.run(rendered, capture_output=True, text=True, env=env, shell=True, cwd=working_dir)
        else:
            argv = shlex.split(command_template)
            result = subprocess.run(argv, capture_output=True, text=True, env=env, input=prompt, cwd=working_dir)
        if result.returncode == 0:
            if not output_path.exists():
                output_path.write_text(result.stdout, encoding="utf-8")
            return {"skipped": False, "output": str(output_path)}
        last_err = result.stderr.strip() or "LLM execution failed"
        if attempt < LLM_MAX_RETRIES - 1:
            time.sleep(LLM_RETRY_BASE_DELAY * (2 ** attempt))
    return {"skipped": True, "reason": last_err}


def run_llm(
    prompt_path: Path,
    output_path: Path,
    provider: str = "claude",
    model: str | None = None,
    command_template: str | None = None,
    working_dir: Path | None = None,
) -> dict[str, object]:
    normalized_provider = _normalize_provider(provider)
    if not normalized_provider:
        return {"skipped": True, "reason": f"unsupported llm provider: {provider}"}
    provider = normalized_provider
    prompt = prompt_path.read_text(encoding="utf-8")
    env = os.environ.copy()
    effective_model = model or os.environ.get("NIOBE_CLAUDE_MODEL") or os.environ.get("ANTHROPIC_MODEL") or "claude-sonnet-4-6"
    effective_working_dir = (working_dir or Path(os.environ.get("NIOBE_LLM_WORKDIR", "") or ".")).expanduser().resolve()

    if provider == "claude":
        if command_template:
            env.setdefault("ANTHROPIC_MODEL", effective_model)
            return _run_template_command(prompt_path, output_path, command_template, env, effective_working_dir)
        if not claude_available():
            return {"skipped": True, "reason": "claude CLI not present"}
        env.setdefault("ANTHROPIC_MODEL", effective_model)
        effort = (os.environ.get("NIOBE_CLAUDE_EFFORT", "").strip().lower() or "medium")
        if effort not in {"low", "medium", "high", "max"}:
            effort = "medium"
        last_err = ""
        command = [
            "claude",
            "--model",
            effective_model,
            "--output-format",
            "text",
            "--permission-mode",
            "plan",
            "--effort",
            effort,
            "-p",
            "Use the piped input as the complete task. Follow it exactly and return only the final answer.",
        ]
        for attempt in range(LLM_MAX_RETRIES):
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                env=env,
                cwd=effective_working_dir,
                input=prompt,
            )
            if result.returncode == 0 and result.stdout.strip():
                output_path.write_text(result.stdout, encoding="utf-8")
                return {"skipped": False, "output": str(output_path)}
            last_err = result.stderr.strip() or "claude execution failed (empty output)"
            if attempt < LLM_MAX_RETRIES - 1:
                time.sleep(LLM_RETRY_BASE_DELAY * (2 ** attempt))
        return {"skipped": True, "reason": last_err}

    if provider == "codex":
        effective_template = command_template or os.environ.get("NIOBE_CODEX_COMMAND_TEMPLATE", "codex exec --skip-git-repo-check -C {working_dir} -o {output_path} - < {prompt_path}")
        if not effective_template:
            return {"skipped": True, "reason": "codex command template missing; set NIOBE_CODEX_COMMAND_TEMPLATE with {prompt_path}"}
        if not codex_available() and "codex" in effective_template.split():
            return {"skipped": True, "reason": "codex CLI not present"}
        return _run_template_command(prompt_path, output_path, effective_template, env, effective_working_dir)

    return {"skipped": True, "reason": f"unsupported llm provider: {provider}"}
