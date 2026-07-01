"""`wgm config` sub-commands: add, edit, remove, validate, path.

Lets a user manage settings, resources and tunnel keys/fields without ever
opening the YAML file by hand.
"""

from __future__ import annotations

import typer
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich import box

config_app = typer.Typer(help="Manage WGM configuration (settings, resources, keys).")


# --------------------------------------------------------------------------- #
# Small shared helpers
# --------------------------------------------------------------------------- #

def _ctx():
    import wgm
    from wgmlib import validation
    return wgm, validation, wgm.console


def _pick(console, title: str, options: list[str]) -> str | None:
    if not options:
        return None
    console.print(f"\n[bold cyan]{title}[/bold cyan]")
    for i, opt in enumerate(options, 1):
        console.print(f"  [green]{i}[/green]  {opt}")
    idx = IntPrompt.ask("Select", default=1)
    if 1 <= idx <= len(options):
        return options[idx - 1]
    console.print("[error]✗[/error] Invalid selection.")
    return None


def _prompt_list(console, validation, label, kind, default=None):
    """Prompt for a comma-separated list validated by *kind* ('cidr' or 'ip')."""
    check = validation.is_cidr if kind == "cidr" else validation.is_ip
    while True:
        raw = Prompt.ask(f"{label} [dim](comma-separated)[/dim]", default=default)
        items = [x.strip() for x in (raw or "").split(",") if x.strip()]
        bad = [x for x in items if not check(x)]
        if items and not bad:
            return items
        for b in bad:
            console.print(f"[error]✗[/error] Invalid {kind}: {b}")
        if not items:
            console.print("[warning]⚠[/warning] Enter at least one value.")


# --------------------------------------------------------------------------- #
# validate
# --------------------------------------------------------------------------- #

@config_app.command("validate")
def validate():
    """Validate the config structure and value types."""
    wgm, validation, console = _ctx()
    cfg = wgm.reload_config()

    issues = validation.validate_config(cfg)
    errors = [i for i in issues if i.is_error]
    warnings = [i for i in issues if not i.is_error]

    if wgm.INCLUDE_ERRORS:
        for msg in wgm.INCLUDE_ERRORS:
            console.print(f"[error]✗ include:[/error] {msg}")

    if not issues and not wgm.INCLUDE_ERRORS:
        console.print("[success]✓ Config is valid.[/success] No problems found.")
        return

    if issues:
        table = Table(box=box.SIMPLE_HEAD, header_style="bold")
        table.add_column("")
        table.add_column("Location", style="cyan")
        table.add_column("Problem")
        for i in errors + warnings:
            icon = "[error]✗[/error]" if i.is_error else "[warning]⚠[/warning]"
            table.add_row(icon, i.path, i.message)
        console.print(table)

    console.print(
        f"\n[bold]Summary:[/bold] "
        f"[error]{len(errors)} error(s)[/error], "
        f"[warning]{len(warnings)} warning(s)[/warning]."
    )
    if errors:
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# path
# --------------------------------------------------------------------------- #

@config_app.command("path")
def path():
    """Show the location of the WGM config and data files."""
    wgm, _, console = _ctx()
    table = Table(box=box.SIMPLE_HEAD, header_style="bold")
    table.add_column("File")
    table.add_column("Location", style="cyan")
    table.add_row("Config", str(wgm.CONFIG_LOCATION))
    table.add_row("Tunnels", str(wgm.TUNNELS_LOCATION))
    table.add_row("State", str(wgm.STATE_LOCATION))
    console.print(table)


# --------------------------------------------------------------------------- #
# add
# --------------------------------------------------------------------------- #

@config_app.command("add")
def add():
    """Add a setting, resource (subnet list / DNS profile / endpoint)."""
    wgm, validation, console = _ctx()
    raw = wgm.load_raw_config()
    wgm.ensure_skeleton(raw)

    kind = _pick(console, "What would you like to add?", [
        "Subnet list", "DNS profile", "Endpoint", "Setting",
    ])
    if kind is None:
        return

    resources = raw["wgm"].setdefault("resources", {})

    if kind == "Subnet list":
        name = Prompt.ask("Name [dim](e.g. office_subnets)[/dim]").strip()
        subnets = _prompt_list(console, validation, "Subnets", "cidr", default="10.0.0.0/8")
        resources.setdefault("subnet_lists", {})[name] = subnets
    elif kind == "DNS profile":
        name = Prompt.ask("Name [dim](e.g. internal)[/dim]").strip()
        servers = _prompt_list(console, validation, "DNS servers", "ip", default="1.1.1.1")
        resources.setdefault("dns_profiles", {})[name] = servers
    elif kind == "Endpoint":
        name = Prompt.ask("Name [dim](e.g. office_vpn)[/dim]").strip()
        while True:
            ep = Prompt.ask("Endpoint [dim](host:port)[/dim]").strip()
            if validation.is_host_port(ep):
                break
            console.print("[error]✗[/error] Expected host:port.")
        resources.setdefault("endpoints", {})[name] = ep
    else:  # Setting
        _edit_settings(wgm, validation, console, raw)
        return

    wgm.save_raw_config(raw)
    console.print(f"[success]✓[/success] Added {kind.lower()} [bold]{name}[/bold].")


# --------------------------------------------------------------------------- #
# edit
# --------------------------------------------------------------------------- #

@config_app.command("edit")
def edit():
    """Edit settings, resources, or a tunnel's keys and fields."""
    wgm, validation, console = _ctx()
    raw = wgm.load_raw_config()
    wgm.ensure_skeleton(raw)

    kind = _pick(console, "What would you like to edit?", [
        "Settings", "A tunnel", "Subnet list", "DNS profile", "Endpoint",
    ])
    if kind is None:
        return

    if kind == "Settings":
        _edit_settings(wgm, validation, console, raw)
    elif kind == "A tunnel":
        _edit_tunnel(wgm, validation, console, raw)
    elif kind == "Subnet list":
        _edit_named_resource(wgm, validation, console, raw, "subnet_lists", "cidr")
    elif kind == "DNS profile":
        _edit_named_resource(wgm, validation, console, raw, "dns_profiles", "ip")
    elif kind == "Endpoint":
        _edit_endpoint(wgm, validation, console, raw)


# --------------------------------------------------------------------------- #
# remove
# --------------------------------------------------------------------------- #

@config_app.command("remove")
def remove():
    """Remove a tunnel or resource."""
    wgm, _, console = _ctx()
    raw = wgm.load_raw_config()
    wgm.ensure_skeleton(raw)

    kind = _pick(console, "What would you like to remove?", [
        "A tunnel", "Subnet list", "DNS profile", "Endpoint",
    ])
    if kind is None:
        return

    if kind == "A tunnel":
        container = raw.setdefault("tunnels", {})
        label = "tunnel"
    else:
        rkey = {"Subnet list": "subnet_lists", "DNS profile": "dns_profiles", "Endpoint": "endpoints"}[kind]
        container = raw["wgm"].setdefault("resources", {}).setdefault(rkey, {})
        label = kind.lower()

    names = list(container.keys())
    if not names:
        console.print(f"[warning]No {label}s to remove.[/warning]")
        return
    target = _pick(console, f"Which {label}?", names)
    if target is None:
        return
    if not Confirm.ask(f"[bold red]Remove {label} '{target}'?[/bold red]", default=False):
        console.print("[dim]Cancelled.[/dim]")
        return
    del container[target]
    wgm.save_raw_config(raw)
    console.print(f"[success]✓[/success] Removed {label} [bold]{target}[/bold].")


# --------------------------------------------------------------------------- #
# edit implementations
# --------------------------------------------------------------------------- #

def _edit_settings(wgm, validation, console, raw):
    settings = raw["wgm"].setdefault("settings", {})
    field = _pick(console, "Which setting?", [
        "WireGuard install folder", "Default MTU", "Handshake timeout",
    ])
    if field is None:
        return
    if field == "WireGuard install folder":
        settings["wireguard_dir"] = Prompt.ask(
            "WireGuard folder", default=settings.get("wireguard_dir") or r"C:\Program Files\WireGuard"
        )
    elif field == "Default MTU":
        settings["default_mtu"] = IntPrompt.ask("Default MTU", default=settings.get("default_mtu", 1420))
    else:
        settings["handshake_timeout"] = IntPrompt.ask(
            "Handshake timeout (seconds)", default=settings.get("handshake_timeout", 30)
        )
    wgm.save_raw_config(raw)
    console.print("[success]✓[/success] Settings updated.")


def _edit_named_resource(wgm, validation, console, raw, rkey, kind):
    container = raw["wgm"].setdefault("resources", {}).setdefault(rkey, {})
    names = list(container.keys())
    if not names:
        console.print("[warning]None defined yet — use 'wgm config add'.[/warning]")
        return
    name = _pick(console, "Which one?", names)
    if name is None:
        return
    console.print(f"[dim]Current: {', '.join(str(x) for x in container[name])}[/dim]")
    container[name] = _prompt_list(console, validation, "New values", kind)
    wgm.save_raw_config(raw)
    console.print(f"[success]✓[/success] Updated [bold]{name}[/bold].")


def _edit_endpoint(wgm, validation, console, raw):
    container = raw["wgm"].setdefault("resources", {}).setdefault("endpoints", {})
    names = list(container.keys())
    if not names:
        console.print("[warning]No endpoints defined yet — use 'wgm config add'.[/warning]")
        return
    name = _pick(console, "Which endpoint?", names)
    if name is None:
        return
    console.print(f"[dim]Current: {container[name]}[/dim]")
    while True:
        ep = Prompt.ask("New endpoint [dim](host:port)[/dim]").strip()
        if validation.is_host_port(ep):
            break
        console.print("[error]✗[/error] Expected host:port.")
    container[name] = ep
    wgm.save_raw_config(raw)
    console.print(f"[success]✓[/success] Updated endpoint [bold]{name}[/bold].")


def _edit_tunnel(wgm, validation, console, raw):
    tunnels = raw.setdefault("tunnels", {})
    names = list(tunnels.keys())
    if not names:
        console.print("[warning]No tunnels yet — create one with 'wgm wizard'.[/warning]")
        return
    tname = _pick(console, "Which tunnel?", names)
    if tname is None:
        return
    tunnel = tunnels[tname]
    interface = tunnel.setdefault("interface", {})

    field = _pick(console, f"Edit '{tname}':", [
        "Description",
        "Private key",
        "Interface address(es)",
        "DNS servers",
        "MTU",
        "Server public key",
        "Server endpoint",
        "Allowed IPs (routes)",
        "Persistent keepalive",
        "Health-check IP",
    ])
    if field is None:
        return

    peers = tunnel.setdefault("peers", [])
    peer = peers[0] if peers else None

    if field == "Description":
        tunnel["description"] = Prompt.ask("Description", default=tunnel.get("description", ""))
    elif field == "Private key":
        while True:
            val = Prompt.ask("New private key").strip()
            if validation.is_key(val):
                break
            console.print("[error]✗[/error] Not a valid WireGuard key.")
        interface["private_key"] = val
    elif field == "Interface address(es)":
        interface["addresses"] = _prompt_list(console, validation, "Address(es)", "cidr",
                                               default=", ".join(interface.get("addresses", [])) or "10.0.0.2/24")
    elif field == "DNS servers":
        interface["dns"] = _prompt_list(console, validation, "DNS server(s)", "ip",
                                        default=", ".join(str(d) for d in interface.get("dns", [])) or "1.1.1.1")
    elif field == "MTU":
        interface["mtu"] = IntPrompt.ask("MTU", default=interface.get("mtu", 1420))
    elif peer is None:
        console.print("[error]✗[/error] This tunnel has no peer to edit.")
        return
    elif field == "Server public key":
        while True:
            val = Prompt.ask("Server public key").strip()
            if validation.is_key(val):
                break
            console.print("[error]✗[/error] Not a valid WireGuard key.")
        peer["public_key"] = val
    elif field == "Server endpoint":
        while True:
            val = Prompt.ask("Endpoint [dim](host:port)[/dim]", default=str(peer.get("endpoint", ""))).strip()
            if validation.is_host_port(val):
                break
            console.print("[error]✗[/error] Expected host:port.")
        peer["endpoint"] = val
    elif field == "Allowed IPs (routes)":
        peer["allowed_ips"] = _prompt_list(console, validation, "Allowed IPs", "cidr",
                                           default=", ".join(str(a) for a in peer.get("allowed_ips", [])) or "0.0.0.0/0")
    elif field == "Persistent keepalive":
        peer["persistent_keepalive"] = IntPrompt.ask("Keepalive seconds", default=peer.get("persistent_keepalive", 25))
    elif field == "Health-check IP":
        while True:
            val = Prompt.ask("Health-check IP").strip()
            if validation.is_ip(val):
                break
            console.print("[error]✗[/error] Not a valid IP.")
        peer["health_check_ip"] = val

    wgm.save_raw_config(raw)
    console.print(f"[success]✓[/success] Updated tunnel [bold]{tname}[/bold].")
