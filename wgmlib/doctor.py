"""`wgm doctor [tunnel]` — full diagnostic suite with fix suggestions.

Without a tunnel it runs general diagnostics (config, WireGuard install,
internet, DNS). With a tunnel it additionally checks that tunnel's config,
endpoint resolution and — if active — its live handshake/health.
"""

from __future__ import annotations

import socket
import subprocess
from dataclasses import dataclass, field

from rich.panel import Panel
from rich.table import Table
from rich import box

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"

_ICON = {
    OK: "[success]✓[/success]",
    WARN: "[warning]⚠[/warning]",
    FAIL: "[error]✗[/error]",
    INFO: "[info]•[/info]",
}


@dataclass
class Check:
    status: str
    title: str
    detail: str = ""
    fixes: list[str] = field(default_factory=list)


def run(tunnel: str | None = None) -> None:
    import wgm

    console = wgm.console
    console.print()
    scope = f"tunnel '[bold]{tunnel}[/bold]'" if tunnel else "general system"
    console.print(Panel.fit(
        f"[bold]WGM Doctor[/bold]  [dim]— {scope} diagnostics[/dim]",
        border_style="cyan",
    ))

    general = _general_checks(wgm)
    _render_section(console, "General", general)

    tunnel_checks: list[Check] = []
    if tunnel:
        tunnel_checks = _tunnel_checks(wgm, tunnel)
        _render_section(console, f"Tunnel: {tunnel}", tunnel_checks)

    _render_summary(console, general + tunnel_checks)


# --------------------------------------------------------------------------- #
# General diagnostics
# --------------------------------------------------------------------------- #

def _general_checks(wgm) -> list[Check]:
    from wgmlib import validation

    checks: list[Check] = []

    # 1. Config parses
    try:
        cfg = wgm.reload_config()
        checks.append(Check(OK, "Config file loads", str(wgm.CONFIG_LOCATION)))
    except Exception as e:
        checks.append(Check(FAIL, "Config file loads", str(e),
                            ["Fix the YAML syntax in your config file.",
                             f"Config path: {wgm.CONFIG_LOCATION}"]))
        return checks

    # 2. Include resolution
    if wgm.INCLUDE_ERRORS:
        checks.append(Check(FAIL, "Included files", "; ".join(wgm.INCLUDE_ERRORS),
                            ["Check that each 'include:' path exists and is valid YAML.",
                             "Paths are relative to the file that references them."]))
    else:
        checks.append(Check(OK, "Included files", "all resolved"))

    # 3. Validation
    issues = validation.validate_config(cfg)
    errors = [i for i in issues if i.is_error]
    warnings = [i for i in issues if not i.is_error]
    if errors:
        checks.append(Check(FAIL, "Config validation",
                            f"{len(errors)} error(s), {len(warnings)} warning(s)",
                            ["Run [bold]wgm config validate[/bold] to see every problem."]))
    elif warnings:
        checks.append(Check(WARN, "Config validation", f"{len(warnings)} warning(s)",
                            ["Run [bold]wgm config validate[/bold] for details."]))
    else:
        checks.append(Check(OK, "Config validation", "no problems"))

    # 4. WireGuard install
    wg_dir = wgm.resolve_wg_dir()
    if wg_dir is None:
        checks.append(Check(FAIL, "WireGuard location", "wireguard_dir not set",
                            ["Run [bold]wgm config edit[/bold] → Settings → WireGuard install folder.",
                             "Default: C:\\Program Files\\WireGuard"]))
    else:
        missing = [exe for exe in ("wg.exe", "wireguard.exe") if not (wg_dir / exe).exists()]
        if missing:
            checks.append(Check(FAIL, "WireGuard binaries", f"missing: {', '.join(missing)} in {wg_dir}",
                                ["Install WireGuard for Windows from https://www.wireguard.com/install/",
                                 "Then confirm the folder with [bold]wgm config edit[/bold]."]))
        else:
            checks.append(Check(OK, "WireGuard binaries", str(wg_dir)))

    # 5. Admin
    if wgm.is_admin():
        checks.append(Check(OK, "Administrator rights", "elevated"))
    else:
        checks.append(Check(WARN, "Administrator rights", "not elevated",
                            ["Bringing tunnels up/down needs an elevated terminal.",
                             "Right-click your terminal → Run as administrator."]))

    # 6. Internet
    if _ping("1.1.1.1"):
        checks.append(Check(OK, "Internet connectivity", "reached 1.1.1.1"))
    else:
        checks.append(Check(FAIL, "Internet connectivity", "could not reach 1.1.1.1",
                            ["Check your network cable / Wi-Fi.",
                             "A VPN full-tunnel that is down can also block traffic — try [bold]wgm down <tunnel>[/bold]."]))

    # 7. DNS
    ok, detail = _resolve("cloudflare.com")
    if ok:
        checks.append(Check(OK, "DNS resolution", f"cloudflare.com → {detail}"))
    else:
        checks.append(Check(FAIL, "DNS resolution", detail,
                            ["Your DNS server may be unreachable.",
                             "Check the DNS settings in your active tunnel or system."]))

    # 8. Active tunnels
    active = wgm.get_active_tunnel_names()
    if active:
        checks.append(Check(INFO, "Active tunnels", ", ".join(sorted(active))))
    else:
        checks.append(Check(INFO, "Active tunnels", "none up"))

    return checks


# --------------------------------------------------------------------------- #
# Tunnel-specific diagnostics
# --------------------------------------------------------------------------- #

def _tunnel_checks(wgm, tunnel: str) -> list[Check]:
    from wgmlib import validation

    checks: list[Check] = []
    cfg = wgm.reload_config()
    tcfg = cfg.get("tunnels", {}).get(tunnel)

    if not tcfg:
        checks.append(Check(FAIL, "Tunnel exists", f"'{tunnel}' not found in config",
                            ["Run [bold]wgm list[/bold] to see configured tunnels.",
                             "Create one with [bold]wgm wizard[/bold]."]))
        return checks
    checks.append(Check(OK, "Tunnel exists", "found in config"))

    # Validate just this tunnel
    resources = cfg.get("wgm", {}).get("resources", {})
    issues = validation._validate_tunnel(
        tunnel, tcfg,
        resources.get("subnet_lists", {}) or {},
        resources.get("dns_profiles", {}) or {},
        resources.get("endpoints", {}) or {},
        lambda p, m: checks.append(Check(FAIL, "Config check", f"{p}: {m}")),
        lambda p, m: checks.append(Check(WARN, "Config check", f"{p}: {m}")),
    )
    if not any(c.title == "Config check" for c in checks):
        checks.append(Check(OK, "Tunnel config", "fields look valid"))

    # Resolve the resolved (ref-expanded) config for endpoint checks
    resolved = wgm.resolve_tunnel_config(tunnel)
    peers = (resolved or {}).get("peers", [])

    # Endpoint resolution
    for i, peer in enumerate(peers):
        ep = peer.get("endpoint")
        if not ep:
            continue
        host, port = _split_endpoint(ep)
        if host is None:
            checks.append(Check(FAIL, f"Endpoint (peer {i + 1})", f"could not parse '{ep}'"))
            continue
        if validation.is_ip(host):
            checks.append(Check(INFO, f"Endpoint (peer {i + 1})", f"{host}:{port} (literal IP)"))
        else:
            ok, detail = _resolve(host)
            if ok:
                checks.append(Check(OK, f"Endpoint DNS (peer {i + 1})", f"{host} → {detail}"))
            else:
                checks.append(Check(FAIL, f"Endpoint DNS (peer {i + 1})", detail,
                                    [f"The server hostname '{host}' does not resolve.",
                                     "Check the spelling of the endpoint or your DNS."]))

    # Live status if active
    active = wgm.get_active_tunnel_names()
    if tunnel not in active:
        checks.append(Check(INFO, "Tunnel state", "down",
                            [f"Bring it up with [bold]wgm up {tunnel}[/bold] (as administrator)."]))
        return checks

    checks.append(Check(OK, "Tunnel state", "up"))

    dump = wgm.wg_dump().get(tunnel)
    if not dump:
        if not wgm.is_admin():
            checks.append(Check(WARN, "Live data", "needs elevation to read peer stats",
                                ["Live handshake/transfer data requires an elevated terminal.",
                                 "Right-click your terminal → Run as administrator, then re-run doctor."]))
        else:
            checks.append(Check(WARN, "Live data", "interface up but no data from wg.exe"))
        return checks

    from wgmlib.format import format_bytes, format_handshake_age, handshake_health

    any_handshake = False
    for p in dump.get("peers", []):
        hs = p.get("latest_handshake", 0)
        health = handshake_health(hs)
        rx = format_bytes(p.get("rx", 0))
        tx = format_bytes(p.get("tx", 0))
        age = format_handshake_age(hs)
        label = p.get("public_key", "")[:16] + "…"
        if health == "healthy":
            any_handshake = True
            checks.append(Check(OK, f"Handshake ({label})", f"{age} · ↓{rx} ↑{tx}"))
        elif health == "stale":
            any_handshake = True
            checks.append(Check(WARN, f"Handshake ({label})", f"{age} (stale) · ↓{rx} ↑{tx}",
                                ["Traffic may be idle. Send some data through the tunnel."]))
        else:
            checks.append(Check(FAIL, f"Handshake ({label})", f"last: {age}",
                                ["No recent handshake — the peer may be unreachable.",
                                 "Verify the server public key and endpoint port (UDP) are open.",
                                 f"Run [bold]wgm doctor {tunnel}[/bold] again after checking the firewall."]))

    # Health-check pings
    for name, ip, ok in wgm._run_ping_health_checks(tunnel):
        if ok:
            checks.append(Check(OK, f"Health check ({name})", f"{ip} reachable"))
        else:
            checks.append(Check(FAIL, f"Health check ({name})", f"{ip} unreachable",
                                ["The tunnel is up but this host does not respond.",
                                 "Check routing/firewall on the remote network."]))

    if not any_handshake and dump.get("peers"):
        checks.append(Check(FAIL, "Overall", "no peer has a recent handshake",
                            ["The tunnel service is running but not passing traffic."]))

    return checks


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _render_section(console, title: str, checks: list[Check]) -> None:
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", padding=(0, 1), show_edge=False)
    table.add_column("", width=2, justify="center")
    table.add_column("Check", style="bold")
    table.add_column("Detail", style="dim", overflow="fold")
    for c in checks:
        table.add_row(_ICON[c.status], c.title, c.detail)
    console.print()
    console.print(Panel(table, title=f"[bold]{title}[/bold]", border_style="cyan", expand=False))

    # Fix hints for anything that failed/warned
    problems = [c for c in checks if c.status in (FAIL, WARN) and c.fixes]
    if problems:
        for c in problems:
            lines = "\n".join(f"    [dim]→[/dim] {f}" for f in c.fixes)
            console.print(f"  {_ICON[c.status]} [bold]{c.title}[/bold]\n{lines}")


def _render_summary(console, checks: list[Check]) -> None:
    fails = sum(1 for c in checks if c.status == FAIL)
    warns = sum(1 for c in checks if c.status == WARN)
    console.print()
    if fails:
        console.print(Panel.fit(
            f"[error]✗ {fails} problem(s)[/error] and [warning]{warns} warning(s)[/warning] found.\n"
            "[dim]Follow the fix steps above, then run doctor again.[/dim]",
            border_style="red",
        ))
    elif warns:
        console.print(Panel.fit(
            f"[warning]⚠ {warns} warning(s)[/warning] — nothing critical.",
            border_style="yellow",
        ))
    else:
        console.print(Panel.fit("[success]✓ All checks passed.[/success]", border_style="green"))


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #

def _ping(host: str) -> bool:
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", "2000", host],
                           capture_output=True, text=True, timeout=6)
        return r.returncode == 0 and "TTL=" in r.stdout
    except Exception:
        return False


def _resolve(host: str) -> tuple[bool, str]:
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return True, ", ".join(ips[:3])
    except Exception as e:
        return False, f"{host} did not resolve ({e.__class__.__name__})"


def _split_endpoint(ep):
    if isinstance(ep, dict):
        return ep.get("host"), ep.get("port")
    if isinstance(ep, str) and ":" in ep:
        host, _, port = ep.rpartition(":")
        return host.strip("[]"), port
    return None, None
