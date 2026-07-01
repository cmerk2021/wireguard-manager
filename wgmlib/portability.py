"""Import/export helpers to migrate tunnels to and from standard WireGuard
`.conf` files used by other WireGuard clients (`wgm import` / `wgm export`).
"""

from __future__ import annotations

from pathlib import Path


# --------------------------------------------------------------------------- #
# .conf parsing
# --------------------------------------------------------------------------- #

def _split_csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def parse_conf(text: str) -> dict:
    """Parse a WireGuard `.conf` file body into a WGM tunnel dict.

    Recognizes the standard [Interface] and [Peer] sections. Unknown keys are
    ignored. Returns a dict shaped like a WGM tunnel: {interface, peers, ...}.
    """
    interface: dict = {}
    peers: list[dict] = []
    hooks: dict = {}
    current: dict | None = None
    section: str | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        if line.startswith("[") and line.endswith("]"):
            sec = line[1:-1].strip().lower()
            if sec == "interface":
                section = "interface"
                current = interface
            elif sec == "peer":
                section = "peer"
                current = {}
                peers.append(current)
            else:
                section = None
                current = None
            continue

        if current is None or "=" not in line:
            continue

        key, _, val = line.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if not val:
            continue

        if section == "interface":
            if key == "privatekey":
                interface["private_key"] = val
            elif key == "address":
                interface["addresses"] = _split_csv(val)
            elif key == "dns":
                interface["dns"] = _split_csv(val)
            elif key == "mtu":
                try:
                    interface["mtu"] = int(val)
                except ValueError:
                    pass
            elif key == "listenport":
                try:
                    interface["listen_port"] = int(val)
                except ValueError:
                    pass
            elif key in ("preup", "postup", "predown", "postdown"):
                phase = {"preup": "pre_up", "postup": "post_up",
                         "predown": "pre_down", "postdown": "post_down"}[key]
                hooks.setdefault(phase, []).append(val)
        elif section == "peer":
            if key == "publickey":
                current["public_key"] = val
            elif key == "presharedkey":
                current["preshared_key"] = val
            elif key == "endpoint":
                current["endpoint"] = val
            elif key == "allowedips":
                current["allowed_ips"] = _split_csv(val)
            elif key == "persistentkeepalive":
                try:
                    current["persistent_keepalive"] = int(val)
                except ValueError:
                    pass

    tunnel: dict = {"interface": interface, "peers": peers}
    if hooks:
        # Collapse single-element hook lists to plain strings for cleaner YAML.
        tunnel["hooks"] = {k: (v[0] if len(v) == 1 else v) for k, v in hooks.items()}
    return tunnel


# --------------------------------------------------------------------------- #
# .conf rendering
# --------------------------------------------------------------------------- #

def render_conf(cfg: dict, settings: dict | None = None) -> str:
    """Render a resolved tunnel config dict to standard `.conf` text.

    *cfg* must already have @resource references resolved. Hook scripts are
    emitted as wg-quick PostUp/PostDown directives for maximum portability.
    """
    settings = settings or {}
    iface = cfg.get("interface", {})
    lines: list[str] = ["[Interface]"]

    if iface.get("private_key"):
        lines.append(f"PrivateKey = {iface['private_key']}")
    addresses = iface.get("addresses") or []
    if addresses:
        lines.append(f"Address = {', '.join(str(a) for a in addresses)}")
    if iface.get("dns"):
        lines.append(f"DNS = {', '.join(str(d) for d in iface['dns'])}")
    mtu = iface.get("mtu") or settings.get("default_mtu")
    if mtu:
        lines.append(f"MTU = {mtu}")
    if iface.get("listen_port"):
        lines.append(f"ListenPort = {iface['listen_port']}")

    # Hooks -> wg-quick directives
    hooks = cfg.get("hooks") or {}
    hook_map = {"pre_up": "PreUp", "post_up": "PostUp",
                "pre_down": "PreDown", "post_down": "PostDown"}
    for phase, directive in hook_map.items():
        val = hooks.get(phase)
        if not val:
            continue
        for cmd in (val if isinstance(val, list) else [val]):
            lines.append(f"{directive} = {cmd}")

    for peer in cfg.get("peers", []):
        lines.append("")
        lines.append("[Peer]")
        if peer.get("public_key"):
            lines.append(f"PublicKey = {peer['public_key']}")
        if peer.get("preshared_key"):
            lines.append(f"PresharedKey = {peer['preshared_key']}")
        ep = peer.get("endpoint")
        if ep:
            if isinstance(ep, dict):
                lines.append(f"Endpoint = {ep['host']}:{ep['port']}")
            else:
                lines.append(f"Endpoint = {ep}")
        if peer.get("allowed_ips"):
            lines.append(f"AllowedIPs = {', '.join(str(ip) for ip in peer['allowed_ips'])}")
        if peer.get("persistent_keepalive"):
            lines.append(f"PersistentKeepalive = {peer['persistent_keepalive']}")

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Command implementations
# --------------------------------------------------------------------------- #

def run_import(source: str, name: str | None) -> None:
    import wgm
    from wgmlib import validation
    from rich.prompt import Confirm, Prompt

    console = wgm.console
    src = Path(source).expanduser()
    if not src.exists():
        console.print(f"[error]✗[/error] File not found: [bold]{source}[/bold]")
        raise wgm.typer.Exit(1)

    try:
        text = src.read_text(encoding="utf-8")
    except Exception as exc:
        console.print(f"[error]✗[/error] Could not read {source}: {exc}")
        raise wgm.typer.Exit(1)

    tunnel = parse_conf(text)
    if not tunnel.get("interface", {}).get("private_key"):
        console.print("[error]✗[/error] No [Interface] PrivateKey found — is this a WireGuard config?")
        raise wgm.typer.Exit(1)
    if not tunnel.get("peers"):
        console.print("[warning]⚠[/warning] No [Peer] sections found in the config.")

    raw = wgm.load_raw_config()
    wgm.ensure_skeleton(raw)
    existing = set((raw.get("tunnels") or {}).keys())

    tname = (name or src.stem).strip()
    while True:
        if not tname:
            tname = Prompt.ask("Name for the imported tunnel").strip()
            continue
        if tname in existing:
            if Confirm.ask(f"[warning]A tunnel named '{tname}' exists. Overwrite?[/warning]", default=False):
                break
            tname = Prompt.ask("Choose a different name").strip()
            continue
        break

    raw.setdefault("tunnels", {})[tname] = tunnel
    wgm.save_raw_config(raw)

    console.print(f"[success]✓[/success] Imported [bold]{tname}[/bold] from [dim]{source}[/dim].")

    # Surface any validation issues so the user can fix them before connecting.
    issues = [i for i in validation.validate_config(wgm.reload_config())
              if i.path.startswith(f"tunnels.{tname}")]
    errors = [i for i in issues if i.is_error]
    if errors:
        console.print("[warning]Some fields need attention:[/warning]")
        for i in errors:
            console.print(f"  [error]✗[/error] {i.path}: {i.message}")
        console.print("[dim]Edit with[/dim] [bold]wgm config edit[/bold] [dim]before bringing it up.[/dim]")
    else:
        console.print(f"[dim]Bring it up with[/dim] [bold]wgm up {tname}[/bold]")


def run_export(tunnel: str, output: str | None) -> None:
    import wgm

    console = wgm.console
    cfg = wgm.resolve_tunnel_config(tunnel)
    if not cfg:
        console.print(f"[error]✗[/error] Tunnel '[bold]{tunnel}[/bold]' not found in config.")
        raise wgm.typer.Exit(1)

    settings = wgm.WGM_CONFIG.get("wgm", {}).get("settings", {})
    conf_text = render_conf(cfg, settings)

    if output:
        dest = Path(output).expanduser()
        if dest.is_dir():
            dest = dest / f"{tunnel}.conf"
        try:
            dest.write_text(conf_text, encoding="utf-8")
        except Exception as exc:
            console.print(f"[error]✗[/error] Could not write {dest}: {exc}")
            raise wgm.typer.Exit(1)
        console.print(f"[success]✓[/success] Exported [bold]{tunnel}[/bold] to [dim]{dest}[/dim].")
        console.print("[dim]⚠  This file contains your private key — keep it secret.[/dim]")
    else:
        from rich.panel import Panel
        from rich.syntax import Syntax
        console.print(Panel(
            Syntax(conf_text, "ini", theme="ansi_dark", background_color="default"),
            title=f"[bold]{tunnel}.conf[/bold]",
            border_style="cyan",
            expand=False,
        ))
        console.print("[dim]⚠  Output contains your private key — handle with care.[/dim]")
