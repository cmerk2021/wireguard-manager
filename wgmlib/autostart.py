"""`wgm autostart` — register a tunnel to come up automatically at system boot.

Implemented with a Windows Scheduled Task (schtasks) that runs `wgm up <tunnel>`
as SYSTEM at startup, with elevated privileges. This survives reboots and is
independent of the interactive session.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _task_name(tunnel: str) -> str:
    return f"WGM Autostart {tunnel}"


def _launch_command(tunnel: str) -> str:
    """Build the command schtasks should run to bring *tunnel* up at boot."""
    if getattr(sys, "frozen", False):
        # Running as the bundled wgm.exe
        exe = Path(sys.executable).resolve()
        return f'"{exe}" up {tunnel} --boot'
    # Running from source: python <script> up <tunnel> --boot
    python = Path(sys.executable).resolve()
    script = Path(sys.argv[0]).resolve()
    return f'"{python}" "{script}" up {tunnel} --boot'


def _task_exists(tunnel: str) -> bool:
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", _task_name(tunnel)],
            capture_output=True, text=True,
        )
    except Exception:
        return False
    return result.returncode == 0


def _enable(wgm, tunnel: str) -> None:
    console = wgm.console
    if tunnel not in (wgm.WGM_CONFIG.get("tunnels") or {}):
        console.print(f"[error]✗[/error] Tunnel '[bold]{tunnel}[/bold]' not found in config.")
        raise wgm.typer.Exit(1)

    cmd = _launch_command(tunnel)
    result = subprocess.run(
        [
            "schtasks", "/Create",
            "/TN", _task_name(tunnel),
            "/TR", cmd,
            "/SC", "ONSTART",
            "/RU", "SYSTEM",
            "/RL", "HIGHEST",
            "/F",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        console.print(f"[error]✗[/error] Could not register autostart for '[bold]{tunnel}[/bold]'.")
        detail = (result.stderr or result.stdout).strip()
        if detail:
            console.print(f"[dim]{detail}[/dim]")
        raise wgm.typer.Exit(1)

    console.print(f"[success]✓[/success] [bold]{tunnel}[/bold] will now start automatically at boot.")
    console.print(f"[dim]Disable with[/dim] [bold]wgm autostart {tunnel} --disable[/bold]")


def _disable(wgm, tunnel: str) -> None:
    console = wgm.console
    if not _task_exists(tunnel):
        console.print(f"[warning]⚠[/warning] Autostart is not enabled for '[bold]{tunnel}[/bold]'.")
        return
    result = subprocess.run(
        ["schtasks", "/Delete", "/TN", _task_name(tunnel), "/F"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        console.print(f"[error]✗[/error] Could not remove autostart for '[bold]{tunnel}[/bold]'.")
        detail = (result.stderr or result.stdout).strip()
        if detail:
            console.print(f"[dim]{detail}[/dim]")
        raise wgm.typer.Exit(1)
    console.print(f"[success]✓[/success] Autostart disabled for [bold]{tunnel}[/bold].")


def run(tunnel: str, disable: bool) -> None:
    import wgm

    console = wgm.console
    if not wgm.is_admin():
        console.print("[error]Error:[/error] Managing autostart requires administrator privileges.")
        console.print("[dim]Run wgm from an elevated terminal (Run as Administrator).[/dim]")
        raise wgm.typer.Exit(1)

    if disable:
        _disable(wgm, tunnel)
    else:
        _enable(wgm, tunnel)
        if _task_exists(tunnel):
            console.print("[dim]A tunnel is autostart-enabled while its scheduled task exists.[/dim]")
