from __future__ import annotations

# ====================
# IMPORTS
# ====================

import copy
import ctypes
import re
import subprocess
import sys

import typer
import os
from version import __version__
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from ruamel.yaml import YAML

# ====================
# GLOBALS
# ====================

app = typer.Typer(help="WGM — WireGuard Manager for Windows")
console = Console()
yaml = YAML()

CONFIG_LOCATION = Path(os.environ["LOCALAPPDATA"]) / "WGM" / "wgm.yaml"
STATE_LOCATION  = Path(os.environ["LOCALAPPDATA"]) / "WGM" / "state.json"
TUNNELS_LOCATION = Path(os.environ["LOCALAPPDATA"]) / "WGM" / "tunnels"
CONFIG_LOCATION.parent.mkdir(parents=True, exist_ok=True)
TUNNELS_LOCATION.mkdir(parents=True, exist_ok=True)
CONFIG_LOCATION.touch(exist_ok=True)
STATE_LOCATION.touch(exist_ok=True)

with open(CONFIG_LOCATION) as _f:
    WGM_CONFIG: dict = yaml.load(_f) or {}

# ====================
# HELPERS
# ====================

def get_wg_dir() -> Path:
    try:
        return Path(WGM_CONFIG["wgm"]["settings"]["wireguard_dir"])
    except (KeyError, TypeError):
        console.print("[bold red]Error:[/bold red] wireguard_dir not set in wgm.yaml under wgm.settings.")
        raise typer.Exit(1)


def ensure_deps():
    """Abort if wg.exe / wireguard.exe are missing."""
    wg_dir = get_wg_dir()
    missing = [exe for exe in ("wg.exe", "wireguard.exe") if not (wg_dir / exe).exists()]
    if missing:
        console.print(
            f"[bold red]Missing in {wg_dir}:[/bold red] {', '.join(missing)}\n"
            "[dim]Make sure WireGuard is installed and wireguard_dir is correct.[/dim]"
        )
        raise typer.Exit(1)


def is_admin() -> bool:
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def require_admin():
    if not is_admin():
        console.print("[bold yellow]⚠  Elevation required. Relaunching as administrator...[/bold yellow]")
        # argv[0] is the exe itself — pass it as the executable, not an argument
        exe = f'"{sys.argv[0]}"'
        args = " ".join([f'"{a}"' for a in sys.argv[1:]])
        wrapped = f'/c {exe} {args} & pause'
        ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", wrapped, None, 1)
        raise typer.Exit(0)


def get_active_tunnel_names() -> set[str]:
    """Return set of currently active tunnel names via `wg show interfaces`."""
    try:
        result = subprocess.run(
            [get_wg_dir() / "wg.exe", "show", "interfaces"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return set(result.stdout.split())
    except Exception:
        pass
    return set()


def parse_wg_show(output: str) -> list[dict]:
    """
    Parse `wg show` / `wg show <iface>` output into a list of tunnel dicts.
    Supports multiple active interfaces in one pass.
    """
    tunnels: list[dict] = []
    current: dict | None = None
    current_peer: dict | None = None

    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue

        # --- New interface block ---
        if line.startswith("interface:"):
            current_peer = None
            current = {
                "interface": {"name": line.split(":", 1)[1].strip()},
                "peers": [],
            }
            tunnels.append(current)
            continue

        if current is None:
            continue

        # --- New peer block ---
        if line.startswith("peer:"):
            current_peer = {"public_key": line.split(":", 1)[1].strip()}
            current["peers"].append(current_peer)
            continue

        # Generic key: value split (safe for IPv6 endpoints)
        val = line.split(":", 1)[1].strip() if ":" in line else ""

        if line.startswith("public key:"):
            target = current_peer if current_peer is not None else current["interface"]
            target["public_key"] = val

        elif line.startswith("private key:"):
            current["interface"]["private_key"] = val

        elif line.startswith("listening port:"):
            try:
                current["interface"]["port"] = int(val)
            except ValueError:
                current["interface"]["port"] = val

        elif current_peer is not None:
            if line.startswith("endpoint:"):
                current_peer["endpoint"] = val
            elif line.startswith("allowed ips:"):
                current_peer["allowed_ips"] = [ip.strip() for ip in val.split(",")]
            elif line.startswith("latest handshake:"):
                current_peer["latest_handshake"] = val
            elif line.startswith("transfer:"):
                # e.g. "transfer: 1.23 KiB received, 4.56 MiB sent"
                matches = re.findall(r"[\d.]+\s\S+", line)
                if len(matches) >= 2:
                    current_peer["transfer_rx"] = matches[0]
                    current_peer["transfer_tx"] = matches[1]
            elif line.startswith("persistent keepalive:"):
                current_peer["keepalive"] = val

    return tunnels


def resolve_refs(cfg: dict):
    """
    Resolve @resource references inside a tunnel config dict (in-place).
    Operate on a deepcopy so the global WGM_CONFIG is never mutated.
    """
    resources  = WGM_CONFIG.get("wgm", {}).get("resources", {})
    subnets    = resources.get("subnet_lists", {})
    dns_profs  = resources.get("dns_profiles", {})
    endpoints  = resources.get("endpoints", {})

    def warn(kind: str, ref: str):
        console.print(f"[bold yellow]Warning:[/bold yellow] Undefined {kind} '@{ref}' — left as-is.")

    iface = cfg.get("interface", {})

    # Resolve DNS profile references
    if isinstance(iface.get("dns"), list):
        resolved: list[str] = []
        for entry in iface["dns"]:
            if isinstance(entry, str) and entry.startswith("@"):
                ref = entry[1:]
                if ref in dns_profs:
                    resolved.extend(dns_profs[ref])
                else:
                    warn("dns_profile", ref)
                    resolved.append(entry)
            else:
                resolved.append(str(entry))
        iface["dns"] = resolved

    # Resolve peer references
    for peer in cfg.get("peers", []):
        if isinstance(peer.get("allowed_ips"), list):
            resolved_ips: list[str] = []
            for ip in peer["allowed_ips"]:
                if isinstance(ip, str) and ip.startswith("@"):
                    ref = ip[1:]
                    if ref in subnets:
                        resolved_ips.extend(subnets[ref])
                    else:
                        warn("subnet_list", ref)
                        resolved_ips.append(ip)
                else:
                    resolved_ips.append(str(ip))
            peer["allowed_ips"] = resolved_ips

        ep = peer.get("endpoint")
        if isinstance(ep, str) and ep.startswith("@"):
            ref = ep[1:]
            if ref in endpoints:
                peer["endpoint"] = endpoints[ref]
            else:
                warn("endpoint", ref)


def generate_config(tunnel: str) -> bool:
    """Write the WireGuard .conf for *tunnel*. Returns False if validation fails."""
    raw_cfg = WGM_CONFIG.get("tunnels", {}).get(tunnel)
    if not raw_cfg:
        console.print(f"[bold red]Error:[/bold red] Tunnel '[bold]{tunnel}[/bold]' not found in config.")
        return False

    cfg = copy.deepcopy(raw_cfg)
    resolve_refs(cfg)

    iface = cfg.get("interface", {})
    private_key = iface.get("private_key", "")
    if not private_key or private_key in ("x", "YOUR_PRIVATE_KEY", ""):
        console.print(f"[bold red]Error:[/bold red] Private key for '[bold]{tunnel}[/bold]' is not configured.")
        return False

    settings = WGM_CONFIG.get("wgm", {}).get("settings", {})
    mtu = iface.get("mtu") or settings.get("default_mtu")

    config_file = TUNNELS_LOCATION / f"{tunnel}.conf"
    with config_file.open("w", encoding="utf-8") as f:
        f.write("[Interface]\n")
        f.write(f"PrivateKey = {private_key}\n")

        addresses = iface.get("addresses", [])
        if addresses:
            f.write(f"Address = {', '.join(str(a) for a in addresses)}\n")
        else:
            console.print("[yellow]Warning:[/yellow] No addresses configured for this interface.")

        if iface.get("dns"):
            f.write(f"DNS = {', '.join(str(d) for d in iface['dns'])}\n")

        if mtu:
            f.write(f"MTU = {mtu}\n")

        for peer in cfg.get("peers", []):
            f.write("\n[Peer]\n")
            f.write(f"PublicKey = {peer['public_key']}\n")

            ep = peer.get("endpoint")
            if ep:
                if isinstance(ep, dict):
                    f.write(f"Endpoint = {ep['host']}:{ep['port']}\n")
                else:
                    f.write(f"Endpoint = {ep}\n")

            if peer.get("allowed_ips"):
                f.write(f"AllowedIPs = {', '.join(str(ip) for ip in peer['allowed_ips'])}\n")

            if peer.get("preshared_key"):
                f.write(f"PresharedKey = {peer['preshared_key']}\n")

            if peer.get("persistent_keepalive"):
                f.write(f"PersistentKeepalive = {peer['persistent_keepalive']}\n")

    return True


# ---------- shared up/down logic (no elevation check — callers handle that) ----------

def _do_up(tunnel: str):
    with console.status(f"Generating config for [bold]{tunnel}[/bold]..."):
        ok = generate_config(tunnel)
    if not ok:
        raise typer.Exit(1)
    console.print("[green]✓[/green] Config written")

    config_file = TUNNELS_LOCATION / f"{tunnel}.conf"
    with console.status(f"Installing tunnel service [bold]{tunnel}[/bold]..."):
        result = subprocess.run(
            [get_wg_dir() / "wireguard.exe", "/installtunnelservice", str(config_file)],
            capture_output=True, text=True,
        )

    if result.returncode == 0:
        console.print(f"[green]✓[/green] Tunnel [bold]{tunnel}[/bold] is [bold green]up[/bold green]")
    else:
        console.print(f"[bold red]✗ Failed to bring up '[bold]{tunnel}[/bold]'[/bold red]")
        if result.stderr.strip():
            console.print(f"[dim]{result.stderr.strip()}[/dim]")
        raise typer.Exit(1)


def _do_down(tunnel: str):
    config_file = TUNNELS_LOCATION / f"{tunnel}.conf"

    with console.status(f"Removing tunnel service [bold]{tunnel}[/bold]..."):
        result = subprocess.run(
            [get_wg_dir() / "wireguard.exe", "/uninstalltunnelservice", tunnel],
            capture_output=True, text=True,
        )

    if result.returncode == 0:
        console.print(f"[green]✓[/green] Tunnel [bold]{tunnel}[/bold] is [bold red]down[/bold red]")
        # Only clean up the .conf after a successful uninstall
        if config_file.exists():
            try:
                config_file.unlink()
                console.print("[dim]Config file cleaned up[/dim]")
            except Exception as e:
                console.print(f"[yellow]Warning:[/yellow] Could not remove config file: {e}")
    else:
        console.print(f"[bold red]✗ Failed to bring down '[bold]{tunnel}[/bold]'[/bold red]")
        if result.stderr.strip():
            console.print(f"[dim]{result.stderr.strip()}[/dim]")
        raise typer.Exit(1)


# ====================
# COMMANDS
# ====================

@app.command()
def version():
    """Show WGM version."""
    console.print(f"[bold]WGM[/bold] v[cyan]{__version__}[/cyan]")


@app.command("list")
def list_tunnels():
    """List all configured tunnels and whether they are currently active."""
    tunnels = WGM_CONFIG.get("tunnels", {})
    if not tunnels:
        console.print("[yellow]No tunnels configured in wgm.yaml.[/yellow]")
        return

    active = get_active_tunnel_names()

    table = Table(box=box.ROUNDED, header_style="bold cyan", show_lines=False)
    table.add_column("Name",        style="bold")
    table.add_column("Description", style="dim")
    table.add_column("Address")
    table.add_column("Peers",       justify="right")
    table.add_column("Status",      justify="center")

    for name, cfg in tunnels.items():
        is_up     = name in active
        status    = "[bold green]● up[/bold green]" if is_up else "[dim]○ down[/dim]"
        addresses = ", ".join(str(a) for a in cfg.get("interface", {}).get("addresses", []))
        n_peers   = str(len(cfg.get("peers", [])))
        desc      = cfg.get("description", "")
        table.add_row(name, desc, addresses, n_peers, status)

    console.print(table)


@app.command()
def up(tunnel: str):
    """Bring up a WireGuard tunnel."""
    require_admin()
    ensure_deps()
    _do_up(tunnel)


@app.command()
def down(tunnel: str):
    """Bring down a WireGuard tunnel."""
    require_admin()
    ensure_deps()
    _do_down(tunnel)


@app.command()
def restart(tunnel: str):
    """Bring a tunnel down then immediately back up (re-reads config)."""
    require_admin()
    ensure_deps()
    _do_down(tunnel)
    _do_up(tunnel)


@app.command()
def status(
    tunnel: str = typer.Argument(None, help="Tunnel name — omit to show all active tunnels"),
):
    """Show live status of active WireGuard tunnel(s)."""
    require_admin()
    ensure_deps()
    wg_dir = get_wg_dir()

    cmd = [wg_dir / "wg.exe", "show"]
    if tunnel:
        cmd.append(tunnel)

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.strip():
        msg = (
            f"Tunnel '[bold]{tunnel}[/bold]' is not active."
            if tunnel else
            "No tunnels are currently active."
        )
        console.print(f"[yellow]{msg}[/yellow]")
        return

    configured = WGM_CONFIG.get("tunnels", {})

    for tdata in parse_wg_show(result.stdout):
        iface = tdata["interface"]
        name  = iface.get("name", "?")
        desc  = configured.get(name, {}).get("description", "")

        title = f"[bold green]● {name}[/bold green]" + (f"  [dim]{desc}[/dim]" if desc else "")
        info  = (
            f"  Public Key : {iface.get('public_key', 'N/A')}\n"
            f"  Port       : {iface.get('port', 'N/A')}"
        )
        console.print(Panel(info, title=title, border_style="green", expand=False))

        peers = tdata["peers"]
        if not peers:
            console.print("  [dim]No peers connected.[/dim]\n")
            continue

        # Map public_key → friendly name from wgm.yaml
        peer_name_map: dict[str, str] = {
            p["public_key"]: p.get("name", "")
            for p in configured.get(name, {}).get("peers", [])
            if "public_key" in p
        }

        table = Table(box=box.SIMPLE_HEAD, header_style="bold", padding=(0, 1))
        table.add_column("Peer")
        table.add_column("Endpoint")
        table.add_column("Allowed IPs")
        table.add_column("Handshake")
        table.add_column("↓ RX")
        table.add_column("↑ TX")
        table.add_column("Keepalive")

        for p in peers:
            pk    = p.get("public_key", "")
            label = peer_name_map.get(pk) or (pk[:20] + "…" if len(pk) > 20 else pk)
            table.add_row(
                label,
                p.get("endpoint", ""),
                "\n".join(p.get("allowed_ips", [])),
                p.get("latest_handshake", ""),
                p.get("transfer_rx", ""),
                p.get("transfer_tx", ""),
                p.get("keepalive", ""),
            )

        console.print(table)
        console.print()


@app.command()
def keygen():
    """Generate a new WireGuard private/public key pair."""
    ensure_deps()
    wg_dir = get_wg_dir()

    priv = subprocess.run([wg_dir / "wg.exe", "genkey"], capture_output=True, text=True)
    if priv.returncode != 0:
        console.print("[red]Failed to generate private key.[/red]")
        raise typer.Exit(1)
    private_key = priv.stdout.strip()

    pub = subprocess.run(
        [wg_dir / "wg.exe", "pubkey"],
        input=private_key, capture_output=True, text=True,
    )
    if pub.returncode != 0:
        console.print("[red]Failed to derive public key.[/red]")
        raise typer.Exit(1)
    public_key = pub.stdout.strip()

    console.print(Panel(
        f"[bold]Private Key[/bold]  [yellow]{private_key}[/yellow]\n"
        f"[bold]Public Key[/bold]   [cyan]{public_key}[/cyan]\n\n"
        "[dim]⚠  Keep your private key secret — never share it.[/dim]",
        title="New Key Pair",
        border_style="cyan",
        expand=False,
    ))


if __name__ == "__main__":
    app()