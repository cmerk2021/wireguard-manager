from __future__ import annotations

# ====================
# IMPORTS
# ====================

import copy
import ctypes
import ipaddress
import re
import subprocess
import sys
import time

import typer
import os
from version import __version__
from pathlib import Path
from rich.console import Console
from rich.theme import Theme
from rich.table import Table
from rich import box
from rich.panel import Panel
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

# ====================
# GLOBALS
# ====================

THEME = Theme({
    "success": "bold green",
    "error":   "bold red",
    "warning": "bold yellow",
    "info":    "cyan",
    "muted":   "dim",
    "heading": "bold cyan",
    "accent":  "magenta",
    "key":     "yellow",
})

app = typer.Typer(
    help="WGM — WireGuard Manager for Windows",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console(theme=THEME)

yaml = YAML()
yaml.preserve_quotes = True
yaml.indent(mapping=2, sequence=4, offset=2)

CONFIG_LOCATION = Path(os.environ["LOCALAPPDATA"]) / "WGM" / "wgm.yaml"
STATE_LOCATION  = Path(os.environ["LOCALAPPDATA"]) / "WGM" / "state.json"
TUNNELS_LOCATION = Path(os.environ["LOCALAPPDATA"]) / "WGM" / "tunnels"
CONFIG_LOCATION.parent.mkdir(parents=True, exist_ok=True)
TUNNELS_LOCATION.mkdir(parents=True, exist_ok=True)
CONFIG_LOCATION.touch(exist_ok=True)
STATE_LOCATION.touch(exist_ok=True)

# Errors encountered while resolving `include:` directives (populated on load).
INCLUDE_ERRORS: list[str] = []


# ====================
# CONFIG LOADING
# ====================

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*, returning plain dicts."""
    result = dict(base) if isinstance(base, dict) else {}
    for key, val in (override or {}).items():
        if key in result and isinstance(result.get(key), dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _resolve_includes(node, base_dir: Path, seen: set):
    """
    Recursively resolve `include:` directives. Wherever a mapping contains an
    `include` key (a path or list of paths), the referenced YAML file(s) are
    loaded and merged in. Local keys take precedence over included ones.
    """
    if isinstance(node, dict):
        out: dict = {}
        include_val = node.get("include")
        for key, val in node.items():
            if key == "include":
                continue
            out[key] = _resolve_includes(val, base_dir, seen)

        if include_val is not None:
            paths = include_val if isinstance(include_val, (list, tuple)) else [include_val]
            merged: dict = {}
            for raw_path in paths:
                inc_path = (base_dir / str(raw_path)).resolve()
                if inc_path in seen:
                    continue
                seen.add(inc_path)
                if not inc_path.exists():
                    INCLUDE_ERRORS.append(f"file not found: {raw_path}")
                    continue
                try:
                    with open(inc_path, encoding="utf-8") as f:
                        data = yaml.load(f) or {}
                except Exception as exc:
                    INCLUDE_ERRORS.append(f"failed to parse {raw_path}: {exc}")
                    continue
                data = _resolve_includes(data, inc_path.parent, seen)
                merged = _deep_merge(merged, data)
            out = _deep_merge(merged, out)
        return out

    if isinstance(node, list):
        return [_resolve_includes(item, base_dir, seen) for item in node]
    return node


def load_merged_config() -> dict:
    """Load wgm.yaml with all `include:` directives resolved (read-only view)."""
    INCLUDE_ERRORS.clear()
    with open(CONFIG_LOCATION, encoding="utf-8") as f:
        raw = yaml.load(f) or {}
    return _resolve_includes(raw, CONFIG_LOCATION.parent, set())


def reload_config() -> dict:
    """Reload the merged config into the module global and return it."""
    global WGM_CONFIG
    WGM_CONFIG = load_merged_config()
    return WGM_CONFIG


def load_raw_config():
    """Load the main wgm.yaml verbatim (round-trip) for editing/saving."""
    with open(CONFIG_LOCATION, encoding="utf-8") as f:
        return yaml.load(f) or CommentedMap()


def save_raw_config(data) -> None:
    """Write *data* back to the main wgm.yaml and refresh the merged view."""
    with open(CONFIG_LOCATION, "w", encoding="utf-8") as f:
        yaml.dump(data, f)
    reload_config()


def ensure_skeleton(raw) -> None:
    """Ensure the wgm/settings/resources/tunnels structure exists (in place)."""
    raw.setdefault("wgm", {})
    raw["wgm"].setdefault("settings", {})
    raw["wgm"].setdefault("resources", {})
    raw.setdefault("tunnels", {})


WGM_CONFIG: dict = load_merged_config()


# ====================
# HELPERS
# ====================

def resolve_wg_dir() -> Path | None:
    """Return the configured WireGuard directory, or None if unset."""
    val = WGM_CONFIG.get("wgm", {}).get("settings", {}).get("wireguard_dir")
    return Path(val) if val else None


def get_wg_dir() -> Path:
    wg_dir = resolve_wg_dir()
    if wg_dir is None:
        console.print("[error]Error:[/error] wireguard_dir not set. Run [bold]wgm config edit[/bold] to set it.")
        raise typer.Exit(1)
    return wg_dir


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
        console.print("[bold red]Error:[/bold red] This command requires administrator privileges.")
        console.print("[dim]Please run wgm from an elevated terminal (Run as Administrator).[/dim]")
        raise typer.Exit(1)


# Map raw WireGuard / Windows service error text to friendly, actionable messages.
# Keys are matched case-insensitively as substrings of the raw stderr output.
_WG_ERROR_MAP: list[tuple[str, str]] = [
    ("does not exist as an installed service",
     "The tunnel does not exist or is not currently up."),
    ("already installed and running",
     "The tunnel is already up."),
    ("already exists",
     "The tunnel is already up."),
    ("access is denied",
     "Access denied — run wgm from an elevated (administrator) terminal."),
    ("the service cannot be started",
     "The tunnel service could not start. Check the config with 'wgm doctor'."),
    ("the service has not been started",
     "The tunnel is not currently up."),
    ("marked for deletion",
     "The tunnel is still shutting down. Wait a moment and try again."),
    ("unable to create configuration",
     "The tunnel configuration is invalid. Run 'wgm config validate' to check it."),
    ("interface name is invalid",
     "The tunnel name is invalid for WireGuard."),
]


def friendly_wg_error(raw: str) -> str:
    """Translate raw WireGuard/service stderr into a clear, human-readable message.

    Falls back to the trimmed raw text (with a leading 'Error:' prefix removed)
    when no known pattern matches.
    """
    text = (raw or "").strip()
    if not text:
        return "The operation failed for an unknown reason."
    low = text.lower()
    for needle, friendly in _WG_ERROR_MAP:
        if needle in low:
            return friendly
    # Strip a redundant leading "Error:" the WireGuard CLI often emits.
    cleaned = re.sub(r"^error:\s*", "", text, flags=re.IGNORECASE).strip()
    return cleaned or "The operation failed for an unknown reason."


def tunnel_service_name(tunnel: str) -> str:
    """Return the Windows service name WireGuard uses for *tunnel*."""
    return f"WireGuardTunnel${tunnel}"


def tunnel_service_exists(tunnel: str) -> bool:
    """Return True if the WireGuard tunnel service is currently installed.

    Uses `sc.exe query`; return code 1060 means the service does not exist.
    """
    try:
        result = subprocess.run(
            ["sc.exe", "query", tunnel_service_name(tunnel)],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        # If we cannot query, fall back to the interfaces list.
        return tunnel in get_active_tunnel_names()
    return result.returncode == 0


def wait_for_service_removed(tunnel: str, timeout: float = 15.0, poll: float = 0.4) -> bool:
    """Block until the tunnel service is fully removed by Windows.

    `wireguard.exe /uninstalltunnelservice` returns immediately but the Service
    Control Manager tears the service down asynchronously (it may sit in a
    "marked for deletion" state). Reinstalling before that completes fails with
    "Tunnel already installed and running". Returns True once gone, False on
    timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not tunnel_service_exists(tunnel):
            return True
        time.sleep(poll)
    return not tunnel_service_exists(tunnel)


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


def wg_dump() -> dict:
    """
    Return machine-readable state via `wg show all dump`, keyed by interface.

    Each value: {name, public_key, private_key, port, peers: [{public_key,
    endpoint, allowed_ips, latest_handshake (int), rx (int), tx (int),
    keepalive}]}. Returns {} if wg.exe is unavailable or nothing is up.
    """
    wg_dir = resolve_wg_dir()
    if wg_dir is None:
        return {}
    try:
        result = subprocess.run(
            [wg_dir / "wg.exe", "show", "all", "dump"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return {}
    if result.returncode != 0:
        return {}

    interfaces: dict = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 5:
            iface, priv, pub, port, _fwmark = parts
            interfaces[iface] = {
                "name": iface,
                "private_key": priv,
                "public_key": pub,
                "port": port,
                "peers": [],
            }
        elif len(parts) == 9:
            iface, pub, _psk, endpoint, allowed, hs, rx, tx, keep = parts
            if iface not in interfaces:
                continue

            def _to_int(v):
                try:
                    return int(v)
                except (TypeError, ValueError):
                    return 0

            interfaces[iface]["peers"].append({
                "public_key": pub,
                "endpoint": "" if endpoint in ("(none)", "") else endpoint,
                "allowed_ips": [a for a in allowed.split(",") if a and a != "(none)"],
                "latest_handshake": _to_int(hs),
                "rx": _to_int(rx),
                "tx": _to_int(tx),
                "keepalive": "" if keep in ("off", "") else keep,
            })
    return interfaces


def generate_keypair() -> tuple[str, str]:
    """Generate a WireGuard (private_key, public_key) pair via wg.exe."""
    wg_dir = get_wg_dir()
    priv = subprocess.run([wg_dir / "wg.exe", "genkey"], capture_output=True, text=True)
    if priv.returncode != 0:
        console.print("[error]Failed to generate private key.[/error]")
        raise typer.Exit(1)
    private_key = priv.stdout.strip()
    return private_key, pubkey_from_private(private_key)


def pubkey_from_private(private_key: str) -> str:
    """Derive the public key for *private_key* via wg.exe. Returns '' on failure."""
    wg_dir = get_wg_dir()
    pub = subprocess.run(
        [wg_dir / "wg.exe", "pubkey"],
        input=private_key, capture_output=True, text=True,
    )
    return pub.stdout.strip() if pub.returncode == 0 else ""


def resolve_tunnel_config(tunnel: str) -> dict | None:
    """Return a deep-copied, @ref-resolved config dict for *tunnel* (no file write)."""
    raw_cfg = WGM_CONFIG.get("tunnels", {}).get(tunnel)
    if not raw_cfg:
        return None
    cfg = copy.deepcopy(raw_cfg)
    resolve_refs(cfg)
    return cfg


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


# ---------- health check helpers ----------

def _wait_for_handshake(tunnel: str, timeout: int = 30, poll_interval: float = 2.0) -> bool:
    """
    Poll `wg show <tunnel>` every *poll_interval* seconds until any peer reports a
    latest handshake, or *timeout* seconds elapse.

    Returns True if a handshake was detected, False on timeout.
    Prints a live status line while waiting.
    """
    wg_dir = get_wg_dir()
    deadline = time.monotonic() + timeout

    with console.status(
        f"[bold]Waiting for handshake[/bold] on [bold]{tunnel}[/bold]… "
        f"(timeout {timeout}s)"
    ) as status:
        while time.monotonic() < deadline:
            elapsed = int(time.monotonic() - (deadline - timeout))
            status.update(
                f"[bold]Waiting for handshake[/bold] on [bold]{tunnel}[/bold]… "
                f"[dim]{elapsed}s / {timeout}s[/dim]"
            )
            try:
                result = subprocess.run(
                    [wg_dir / "wg.exe", "show", tunnel],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    parsed = parse_wg_show(result.stdout)
                    for tdata in parsed:
                        for peer in tdata.get("peers", []):
                            if peer.get("latest_handshake"):
                                return True
            except Exception:
                pass  # wg.exe not ready yet — keep polling

            time.sleep(poll_interval)

    return False


def _print_handshake_tips(tunnel: str):
    """Print a troubleshooting panel when no handshake is observed after timeout."""
    tips = (
        "[bold]Common causes and fixes:[/bold]\n\n"
        "  [cyan]1. Firewall blocking UDP[/cyan]\n"
        "     Ensure port 51820/UDP (or your configured port) is open on the\n"
        "     server firewall and any router/NAT in between.\n\n"
        "  [cyan]2. Wrong peer public key[/cyan]\n"
        "     Double-check the [bold]public_key[/bold] under your peer in wgm.yaml matches\n"
        "     what the server has generated with [bold]wgm keygen[/bold].\n\n"
        "  [cyan]3. Server not listening[/cyan]\n"
        "     Confirm WireGuard is running on the remote end and its tunnel is up.\n\n"
        "  [cyan]4. Endpoint unreachable[/cyan]\n"
        "     Verify the endpoint address/port in wgm.yaml is correct and reachable\n"
        "     from this machine (try [bold]ping[/bold] or [bold]tracert[/bold] to the host).\n\n"
        "  [cyan]5. Clock skew[/cyan]\n"
        "     WireGuard timestamps packets. Large clock differences between peers\n"
        "     can prevent handshakes. Sync your system clock (NTP).\n\n"
        "  [dim]Run [bold]wgm status {tunnel}[/bold] after fixing to see live peer state.[/dim]"
    ).format(tunnel=tunnel)

    console.print(Panel(
        tips,
        title=f"[bold yellow]⚠  No handshake detected on '{tunnel}'[/bold yellow]",
        border_style="yellow",
        expand=False,
    ))


def _prompt_keep_or_down(tunnel: str) -> bool:
    """
    Interactively ask the user whether to keep the tunnel up or bring it down.
    Returns True to keep up, False to bring down.
    """
    console.print()
    console.print(
        "[bold]What would you like to do?[/bold]\n"
        "  [green][k][/green] Keep the tunnel up and troubleshoot manually\n"
        "  [red][d][/red] Bring the tunnel down"
    )
    while True:
        choice = typer.prompt("Choice", default="k").strip().lower()
        if choice in ("k", "keep", ""):
            return True
        if choice in ("d", "down"):
            return False
        console.print("[dim]Please enter 'k' to keep up or 'd' to bring down.[/dim]")


def _run_ping_health_checks(tunnel: str) -> list[tuple[str, str, bool]]:
    """
    For each peer in *tunnel* that has a `health_check_ip`, send a single ICMP
    ping (Windows ping.exe -n 1 -w 2000).

    Returns a list of (peer_name, ip, success) tuples for every peer that has
    a health_check_ip configured. Peers without one are silently skipped.
    """
    raw_cfg = WGM_CONFIG.get("tunnels", {}).get(tunnel, {})
    peers = raw_cfg.get("peers", [])
    results: list[tuple[str, str, bool]] = []

    for peer in peers:
        ip = peer.get("health_check_ip")
        if not ip:
            continue

        name = peer.get("name") or peer.get("public_key", "?")[:20]
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "2000", str(ip)],
                capture_output=True, text=True, timeout=5,
            )
            # ping.exe exits 0 on success; non-zero (or "Request timed out") on failure
            success = result.returncode == 0 and "TTL=" in result.stdout
        except Exception:
            success = False

        results.append((name, str(ip), success))

    return results


def _print_ping_results(results: list[tuple[str, str, bool]]):
    """Render ping health-check results as a compact table."""
    if not results:
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="bold", padding=(0, 1), show_edge=False)
    table.add_column("Peer")
    table.add_column("Health check IP")
    table.add_column("Reachable", justify="center")

    for name, ip, ok in results:
        icon = "[bold green]✓[/bold green]" if ok else "[bold red]✗[/bold red]"
        table.add_row(name, ip, icon)

    console.print(table)


# ---------- shared up/down logic (no elevation check — callers handle that) ----------

def _tunnel_allowed_networks(tunnel: str) -> list:
    """Return the resolved AllowedIPs of *tunnel* as ip_network objects."""
    cfg = resolve_tunnel_config(tunnel)
    nets: list = []
    if not cfg:
        return nets
    for peer in cfg.get("peers", []):
        for ip in peer.get("allowed_ips", []) or []:
            try:
                nets.append(ipaddress.ip_network(str(ip), strict=False))
            except ValueError:
                continue
    return nets


def _active_allowed_networks(exclude: str) -> dict:
    """Map active-tunnel-name -> list of ip_network objects from live `wg` state.

    Only currently-up tunnels are considered; *exclude* is skipped.
    """
    out: dict = {}
    for iface, data in wg_dump().items():
        if iface == exclude:
            continue
        nets: list = []
        for peer in data.get("peers", []):
            for ip in peer.get("allowed_ips", []) or []:
                try:
                    nets.append(ipaddress.ip_network(str(ip), strict=False))
                except ValueError:
                    continue
        if nets:
            out[iface] = nets
    return out


def _check_subnet_overlap(tunnel: str) -> None:
    """Warn if *tunnel*'s routes overlap those of any currently-up tunnel.

    Down tunnels are ignored — only active tunnels can actually conflict for
    routing. This is advisory only and never blocks the operation.
    """
    incoming = _tunnel_allowed_networks(tunnel)
    if not incoming:
        return
    active = _active_allowed_networks(exclude=tunnel)
    if not active:
        return

    conflicts: list[tuple[str, str, str]] = []  # (other_tunnel, incoming_net, other_net)
    for other, other_nets in active.items():
        for a in incoming:
            for b in other_nets:
                if a.version != b.version:
                    continue
                if a.overlaps(b):
                    conflicts.append((other, str(a), str(b)))

    if not conflicts:
        return

    console.print(
        f"[warning]⚠  Routing overlap detected[/warning] — bringing up "
        f"[bold]{tunnel}[/bold] may hijack traffic already routed by another tunnel:"
    )
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", padding=(0, 1), show_edge=False)
    table.add_column("This tunnel")
    table.add_column("Overlaps")
    table.add_column("Active tunnel")
    for other, a, b in conflicts:
        table.add_row(a, "↔", f"{b}  [dim]({other})[/dim]")
    console.print(table)
    console.print(
        "[dim]Both tunnels claim overlapping subnets; the one brought up last wins "
        "for those routes.[/dim]"
    )


def _run_hooks(tunnel: str, phase: str) -> None:
    """Run any configured hook scripts for *tunnel* at the given *phase*.

    Phases: 'pre_up', 'post_up', 'pre_down', 'post_down' (wg-quick style).
    A hook value may be a single command string or a list of commands; each is
    executed through the shell. A non-zero exit is reported but never aborts the
    tunnel operation (matching wg-quick's best-effort PostUp/PostDown behavior).
    """
    raw_cfg = WGM_CONFIG.get("tunnels", {}).get(tunnel, {})
    hooks = raw_cfg.get("hooks") or {}
    if not isinstance(hooks, dict):
        return
    commands = hooks.get(phase)
    if not commands:
        return
    if isinstance(commands, str):
        commands = [commands]

    label = phase.replace("_", "-")
    for cmd in commands:
        cmd = str(cmd)
        if not cmd.strip():
            continue
        console.print(f"[dim]▸ {label}: {cmd}[/dim]")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                env={**os.environ, "WGM_TUNNEL": tunnel},
            )
        except Exception as exc:
            console.print(f"[yellow]⚠[/yellow]  {label} hook failed to run: {exc}")
            continue
        if result.stdout.strip():
            console.print(f"[dim]{result.stdout.strip()}[/dim]")
        if result.returncode != 0:
            err = result.stderr.strip() or f"exited with code {result.returncode}"
            console.print(f"[yellow]⚠[/yellow]  {label} hook: {err}")


def _do_up(tunnel: str, no_prompt: bool = False):
    # Resolve the handshake timeout from config, default 30s
    settings = WGM_CONFIG.get("wgm", {}).get("settings", {})
    handshake_timeout: int = int(settings.get("handshake_timeout", 30))

    # Advisory: warn about routing overlaps with already-active tunnels.
    _check_subnet_overlap(tunnel)

    # A leftover service from a previous session (or an in-progress teardown)
    # would make /installtunnelservice fail with "already installed and running".
    if tunnel_service_exists(tunnel):
        console.print(
            f"[dim]A service for [bold]{tunnel}[/bold] is still present — waiting for it to clear…[/dim]"
        )
        wait_for_service_removed(tunnel)

    _run_hooks(tunnel, "pre_up")

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

    if result.returncode != 0:
        console.print(f"[bold red]✗ Failed to bring up '[bold]{tunnel}[/bold]'[/bold red]")
        console.print(f"[error]{friendly_wg_error(result.stderr)}[/error]")
        raise typer.Exit(1)

    console.print(f"[green]✓[/green] Tunnel service installed")

    # ── Phase 2: wait for handshake ──────────────────────────────────────────
    handshake_ok = _wait_for_handshake(tunnel, timeout=handshake_timeout)

    if handshake_ok:
        console.print(f"[green]✓[/green] Handshake confirmed — tunnel [bold]{tunnel}[/bold] is [bold green]healthy[/bold green]")

        # ── Phase 3: ping health checks (optional, per peer) ─────────────────
        ping_results = _run_ping_health_checks(tunnel)
        if ping_results:
            _print_ping_results(ping_results)
            failures = [r for r in ping_results if not r[2]]
            if failures:
                for name, ip, _ in failures:
                    console.print(
                        f"[yellow]⚠[/yellow]  Health check failed for peer [bold]{name}[/bold] "
                        f"([dim]{ip}[/dim]) — tunnel is up but that host is not reachable."
                    )
            else:
                console.print("[green]✓[/green] All health checks passed")
        _run_hooks(tunnel, "post_up")
    else:
        # No handshake within timeout
        _print_handshake_tips(tunnel)

        # Non-interactive callers (e.g. boot autostart) keep the tunnel up.
        keep = True if no_prompt else _prompt_keep_or_down(tunnel)
        if keep:
            console.print(
                f"\n[yellow]⚠[/yellow]  Tunnel [bold]{tunnel}[/bold] is [bold yellow]up (no handshake)[/bold yellow] — "
                "use [bold]wgm status {tunnel}[/bold] to monitor.".format(tunnel=tunnel)
            )
            _run_hooks(tunnel, "post_up")
        else:
            console.print()
            _do_down(tunnel)


def _do_down(tunnel: str):
    config_file = TUNNELS_LOCATION / f"{tunnel}.conf"

    _run_hooks(tunnel, "pre_down")

    with console.status(f"Removing tunnel service [bold]{tunnel}[/bold]..."):
        result = subprocess.run(
            [get_wg_dir() / "wireguard.exe", "/uninstalltunnelservice", tunnel],
            capture_output=True, text=True,
        )

    if result.returncode == 0:
        # SCM removes the service asynchronously — wait so a following `up`
        # (e.g. from `wgm restart`) doesn't collide with the old service.
        with console.status(f"Waiting for [bold]{tunnel}[/bold] to shut down..."):
            wait_for_service_removed(tunnel)
        console.print(f"[green]✓[/green] Tunnel [bold]{tunnel}[/bold] is [bold red]down[/bold red]")
        # Only clean up the .conf after a successful uninstall
        if config_file.exists():
            try:
                config_file.unlink()
                console.print("[dim]Config file cleaned up[/dim]")
            except Exception as e:
                console.print(f"[yellow]Warning:[/yellow] Could not remove config file: {e}")
        _run_hooks(tunnel, "post_down")
    else:
        console.print(f"[bold red]✗ Failed to bring down '[bold]{tunnel}[/bold]'[/bold red]")
        console.print(f"[error]{friendly_wg_error(result.stderr)}[/error]")
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
        console.print(Panel.fit(
            "[warning]No tunnels configured yet.[/warning]\n"
            "[dim]Create your first one with[/dim] [bold]wgm wizard[/bold]",
            border_style="yellow",
        ))
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
    up_count = sum(1 for n in tunnels if n in active)
    console.print(
        f"[dim]{len(tunnels)} tunnel(s) · [/dim][success]{up_count} up[/success]"
        f"[dim] · {len(tunnels) - up_count} down[/dim]"
    )


@app.command()
def up(
    tunnel: str,
    boot: bool = typer.Option(
        False, "--boot", hidden=True,
        help="Non-interactive mode used by autostart at boot.",
    ),
):
    """Bring up a WireGuard tunnel."""
    require_admin()
    ensure_deps()
    _do_up(tunnel, no_prompt=boot)


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

    # Only tear down if the tunnel is actually up; otherwise a missing-service
    # error would abort before we ever bring it up.
    if tunnel_service_exists(tunnel):
        _do_down(tunnel)
    else:
        console.print(f"[dim]{tunnel} is not currently up — skipping the down step.[/dim]")

    # Ensure the service is fully gone before reinstalling (fixes the race where
    # a stale service made 'up' fail with "already installed and running").
    wait_for_service_removed(tunnel)
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
    private_key, public_key = generate_keypair()
    if not public_key:
        console.print("[error]Failed to derive public key.[/error]")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold]Private Key[/bold]  [key]{private_key}[/key]\n"
        f"[bold]Public Key[/bold]   [info]{public_key}[/info]\n\n"
        "[dim]⚠  Keep your private key secret — never share it.[/dim]",
        title="New Key Pair",
        border_style="cyan",
        expand=False,
    ))


@app.command()
def wizard(
    expert: bool = typer.Option(False, "--expert", "-e", help="Start directly in expert mode."),
):
    """Interactively create a fully working tunnel — no YAML editing required."""
    from wgmlib import wizard as _wizard
    _wizard.run(prefer_expert=expert)


@app.command()
def doctor(
    tunnel: str = typer.Argument(None, help="Tunnel to diagnose — omit for general checks."),
):
    """Run diagnostics with troubleshooting steps (optionally for one tunnel)."""
    from wgmlib import doctor as _doctor
    _doctor.run(tunnel)


@app.command()
def monitor(
    interval: float = typer.Option(1.0, "--interval", "-i", help="Refresh interval in seconds."),
):
    """Live full-screen dashboard of all tunnels (real-time transfer & health)."""
    from wgmlib import monitor as _monitor
    _monitor.run(interval)


@app.command("stat", hidden=True)
def stat(
    interval: float = typer.Option(1.0, "--interval", "-i", help="Refresh interval in seconds."),
):
    """Alias for 'wgm monitor'."""
    from wgmlib import monitor as _monitor
    _monitor.run(interval)


@app.command("import")
def import_config(
    source: str = typer.Argument(..., help="Path to a WireGuard .conf file to import."),
    name: str = typer.Option(None, "--name", "-n", help="Name for the imported tunnel (defaults to the file name)."),
):
    """Import a standard WireGuard .conf file as a WGM tunnel."""
    from wgmlib import portability
    portability.run_import(source, name)


@app.command()
def export(
    tunnel: str = typer.Argument(..., help="Tunnel to export."),
    output: str = typer.Option(None, "--output", "-o", help="Write to this file/folder instead of the screen."),
):
    """Export a tunnel to a standard WireGuard .conf file (for other clients)."""
    from wgmlib import portability
    portability.run_export(tunnel, output)


@app.command()
def autostart(
    tunnel: str = typer.Argument(..., help="Tunnel to start automatically at boot."),
    disable: bool = typer.Option(False, "--disable", "-d", help="Disable autostart for this tunnel."),
):
    """Start a tunnel automatically on system boot (Windows scheduled task)."""
    from wgmlib import autostart as _autostart
    _autostart.run(tunnel, disable)


# Register `wgm config` sub-commands (add / edit / remove / validate / path).
from wgmlib.configcmd import config_app  # noqa: E402
app.add_typer(config_app, name="config")


if __name__ == "__main__":
    app()