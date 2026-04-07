from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.text import Text

from .audit import finalize_audit, prepare_audit, run_audit
from .detect import detect_host_profile
from .installer import ensure_audit_runner_image, ensure_base_utils, ensure_docker
from .settings import get_settings, set_runtime_config


console = Console()
cli = typer.Typer(add_completion=False, no_args_is_help=False, invoke_without_command=True)
PATH_PATTERN = re.compile(r"(/\S+)")


def _configure_cli_runtime() -> None:
    os.environ["NIOBE_CREATE_CONTROL_PLANE_DIRS"] = "0"
PROVIDER_ALIASES = {
    "1": "claude",
    "anthropic": "claude",
    "claude": "claude",
    "2": "codex",
    "openai": "codex",
    "codex": "codex",
}


@cli.callback(invoke_without_command=True)
def root(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit(0)


def normalize_llm_provider(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    resolved = PROVIDER_ALIASES.get(normalized)
    if not resolved:
        raise typer.Exit("Unsupported llm provider. Use anthropic/claude or openai/codex.")
    return resolved


def _styled_message(message: str, level: str) -> Text:
    styles = {
        "info": "cyan",
        "success": "green",
        "warning": "yellow",
        "error": "bold red",
    }
    style = styles.get(level, "white")
    normalized = re.sub(r":\s+(/\S+)", r":\n  \1", message, count=1)
    text = Text(style=style)
    last = 0
    for match in PATH_PATTERN.finditer(normalized):
        start, end = match.span()
        if start > last:
            text.append(normalized[last:start], style=style)
        text.append(match.group(0), style="bold medium_purple3")
        last = end
    if last < len(normalized):
        text.append(normalized[last:], style=style)
    return text


@cli.command()
def install(
    install_profile: Annotated[str, typer.Option("--profile", help="standalone or full")] = "standalone",
) -> None:
    """Prepare the local Digital Audit toolchain on the scan host."""
    host_profile = detect_host_profile()
    if not host_profile.is_linux and not host_profile.is_macos:
        raise typer.Exit("Windows is intentionally not supported in this phase.")
    console.print(f"[bold gold1]Host[/bold gold1]: {host_profile.system} | shell={host_profile.shell} | pkg={host_profile.package_manager or 'none'}")
    if install_profile not in {"standalone", "full"}:
        raise typer.Exit("Unsupported install profile. Use standalone or full.")
    console.print(f"[cyan]Docker[/cyan]: {ensure_docker(host_profile)}")
    console.print(f"[cyan]Audit Image[/cyan]: {ensure_audit_runner_image()}")
    for item in ensure_base_utils(host_profile, include_optional_analysis=install_profile == "full"):
        console.print(f"[green]{item}[/green]")


@cli.command()
def prepare(
    target: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    project_name: str = typer.Option(..., "--project"),
    client_name: str = typer.Option(..., "--client"),
    config: Path | None = typer.Option(None, "--config", exists=True, file_okay=True, dir_okay=False, resolve_path=True),
    control_plane_url: str | None = typer.Option(None, "--control-plane-url"),
    agent_key: str | None = typer.Option(None, "--agent-key"),
    standalone: bool = typer.Option(False, "--standalone"),
    llm_provider: str = typer.Option("claude", "--llm-provider", help="anthropic/claude or openai/codex"),
) -> None:
    """Run collection and tooling, then stop after generating the LLM prompt."""
    set_runtime_config(config)
    _configure_cli_runtime()
    llm_provider = normalize_llm_provider(llm_provider) or "claude"
    if not standalone and bool(control_plane_url) != bool(agent_key):
        raise typer.Exit("Managed mode requires both --control-plane-url and --agent-key.")

    def status(message: str, level: str) -> None:
        if level in {"warning", "error"}:
            console.print(_styled_message(message, level))

    result = prepare_audit(
        target=target,
        project_name=project_name,
        client_name=client_name,
        control_plane_url=None if standalone else control_plane_url,
        agent_key=None if standalone else agent_key,
        llm_provider=llm_provider,
        standalone=standalone,
        status_callback=status,
    )
    _ = result


@cli.command()
def finalize(
    run_root: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    config: Path | None = typer.Option(None, "--config", exists=True, file_okay=True, dir_okay=False, resolve_path=True),
    llm_provider: str | None = typer.Option(None, "--llm-provider"),
    control_plane_url: str | None = typer.Option(None, "--control-plane-url"),
    agent_key: str | None = typer.Option(None, "--agent-key"),
) -> None:
    """Complete delivery generation using the prepared run context and any LLM output already present."""
    set_runtime_config(config)
    _configure_cli_runtime()
    llm_provider = normalize_llm_provider(llm_provider)

    def status(message: str, level: str) -> None:
        if level in {"warning", "error"}:
            console.print(_styled_message(message, level))

    result = finalize_audit(
        run_root=run_root,
        llm_provider=llm_provider,
        control_plane_url=control_plane_url,
        agent_key=agent_key,
        status_callback=status,
    )
    _ = result


@cli.command()
def audit(
    target: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    project_name: str = typer.Option(..., "--project"),
    client_name: str = typer.Option(..., "--client"),
    config: Path | None = typer.Option(None, "--config", exists=True, file_okay=True, dir_okay=False, resolve_path=True),
    control_plane_url: str | None = typer.Option(None, "--control-plane-url"),
    agent_key: str | None = typer.Option(None, "--agent-key"),
    standalone: bool = typer.Option(False, "--standalone", help="Run without control plane uploads and emit temp-delivery in project root"),
    llm_provider: str = typer.Option("claude", "--llm-provider", help="anthropic/claude or openai/codex"),
    llm_command_template: str | None = typer.Option(None, "--llm-command-template", help="Command template for non-default LLM execution"),
) -> None:
    """Run a lean audit with deterministic evidence capture."""
    set_runtime_config(config)
    _configure_cli_runtime()
    llm_provider = normalize_llm_provider(llm_provider) or "claude"
    if not standalone and bool(control_plane_url) != bool(agent_key):
        raise typer.Exit("Managed mode requires both --control-plane-url and --agent-key.")

    def status(message: str, level: str) -> None:
        if level in {"warning", "error"}:
            console.print(_styled_message(message, level))

    result = run_audit(
        target=target,
        project_name=project_name,
        client_name=client_name,
        control_plane_url=None if standalone else control_plane_url,
        agent_key=None if standalone else agent_key,
        llm_provider=llm_provider,
        llm_command_template=llm_command_template,
        standalone=standalone,
        status_callback=status,
    )
    ok_tools = sum(1 for item in result.tool_results.values() if isinstance(item, dict) and item.get("ok"))
    total_tools = len(result.tool_results)
    console.print("")
    console.print("[bold gold1]Digital Audit Summary[/bold gold1]")
    console.print(_styled_message(f"Target: {target}", "success"))
    console.print(f"[green]Provider[/green]: {result.llm_provider}")
    console.print(f"[green]Tools OK[/green]: {ok_tools}/{total_tools}")
    console.print(_styled_message(f"Reports directory: {result.paths.reports}", "success"))
    console.print(_styled_message(f"Delivery directory: {result.paths.delivery}", "success"))


@cli.command()
def login(
    provider: str = typer.Argument("claude"),
    use_device_code: bool = typer.Option(False, "--use-device-code", help="Use device authentication when supported"),
) -> None:
    """Delegate authentication to the upstream CLI without storing secrets in the repo."""
    normalized = normalize_llm_provider(provider) or "claude"
    if normalized == "codex":
        argv = ["codex", "login"]
        if use_device_code:
            argv.append("--device-auth")
    else:
        if use_device_code:
            console.print("[yellow]Claude Code does not expose a device-code flag. Continuing with the native login flow.[/yellow]")
        argv = ["claude", "auth", "login"]
    if shutil.which(argv[0]) is None:
        raise typer.Exit(f"{argv[0]} not found in PATH")
    result = subprocess.run(argv)
    raise typer.Exit(result.returncode)


@cli.command()
def api() -> None:
    """Run the control-plane API and frontend."""
    from .control_plane import app

    settings = get_settings()
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
