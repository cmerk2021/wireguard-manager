"""Interactive tunnel creation wizard (`wgm wizard`).

Guides a user through building a fully functional tunnel — with friendly,
non-technical prompts — and writes it straight into wgm.yaml so the user never
has to edit YAML by hand. Two modes: basic and expert.
"""

from __future__ import annotations

from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich import box

# Allowed-IPs presets
PRESET_FULL = ["0.0.0.0/0", "::/0"]
PRESET_PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# Common DNS presets
DNS_PRESETS = {
    "1": ("Cloudflare (1.1.1.1)", ["1.1.1.1", "1.0.0.1"]),
    "2": ("Google (8.8.8.8)", ["8.8.8.8", "8.8.4.4"]),
    "3": ("Quad9 (9.9.9.9)", ["9.9.9.9", "149.112.112.112"]),
}


def run(prefer_expert: bool = False) -> None:
    import wgm
    from wgmlib import validation

    console = wgm.console

    console.print()
    console.print(Panel.fit(
        "[bold]WireGuard Tunnel Wizard[/bold]\n"
        "[dim]Answer a few questions and WGM will build a ready-to-use tunnel.[/dim]",
        border_style="cyan",
    ))

    # ── First-run: ensure WireGuard directory is set ────────────────────────
    _ensure_wireguard_dir(wgm)

    # ── Mode selection ──────────────────────────────────────────────────────
    if prefer_expert:
        mode = "expert"
    else:
        console.print("\n[bold]Choose a setup mode:[/bold]")
        console.print("  [green]basic[/green]  — just the essentials (recommended)")
        console.print("  [magenta]expert[/magenta] — full control (MTU, keepalive, health checks, PSK)")
        mode = Prompt.ask("Mode", choices=["basic", "expert"], default="basic")
    expert = mode == "expert"

    raw = wgm.load_raw_config()
    wgm.ensure_skeleton(raw)
    existing = set((raw.get("tunnels") or {}).keys())

    # ── Tunnel name ─────────────────────────────────────────────────────────
    console.print("\n[bold cyan]1. Tunnel name[/bold cyan] [dim]— a short label, e.g. 'office' or 'home'[/dim]")
    while True:
        name = Prompt.ask("Tunnel name").strip()
        if not name:
            console.print("[warning]⚠[/warning] Name cannot be empty.")
            continue
        if not name.replace("-", "").replace("_", "").isalnum():
            console.print("[warning]⚠[/warning] Use letters, numbers, '-' or '_' only.")
            continue
        if name in existing:
            console.print(f"[error]✗[/error] A tunnel named '{name}' already exists.")
            continue
        break

    description = Prompt.ask("Description [dim](optional)[/dim]", default="").strip()

    # ── Keypair ─────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]2. Your keys[/bold cyan]")
    console.print("Every tunnel needs a private key. WGM can make one for you,")
    console.print("or you can paste one you already have.")
    have_keys = Prompt.ask(
        "Do you have your own keypair, or should WGM generate one?",
        choices=["generate", "own"],
        default="generate",
    )

    if have_keys == "generate":
        private_key, public_key = wgm.generate_keypair()
        console.print(Panel(
            f"[bold]Your public key[/bold] [dim](give this to the server admin)[/dim]\n"
            f"[cyan]{public_key}[/cyan]",
            title="[success]✓ Keypair generated[/success]",
            border_style="green",
            expand=False,
        ))
    else:
        while True:
            private_key = Prompt.ask("Paste your [bold]private[/bold] key").strip()
            if validation.is_key(private_key):
                break
            console.print("[error]✗[/error] That doesn't look like a valid WireGuard key (44 chars ending in '=').")
        public_key = wgm.pubkey_from_private(private_key)
        if public_key:
            console.print(f"[dim]Derived public key:[/dim] [cyan]{public_key}[/cyan]")

    # ── Interface address ───────────────────────────────────────────────────
    console.print("\n[bold cyan]3. This device's VPN address[/bold cyan]")
    console.print("[dim]The IP address assigned to you inside the VPN, e.g. 10.0.0.2/24[/dim]")
    addresses = _prompt_cidr_list(console, validation, "VPN address", default="10.0.0.2/24")

    # ── Peer / server ───────────────────────────────────────────────────────
    console.print("\n[bold cyan]4. The server (peer)[/bold cyan]")
    while True:
        server_pub = Prompt.ask("Please enter the [bold]server public key[/bold]").strip()
        if validation.is_key(server_pub):
            break
        console.print("[error]✗[/error] That doesn't look like a valid WireGuard key.")

    console.print("[dim]The server's public address, e.g. vpn.example.com:51820[/dim]")
    while True:
        endpoint = Prompt.ask("Server endpoint [dim](host:port)[/dim]").strip()
        if validation.is_host_port(endpoint):
            break
        console.print("[error]✗[/error] Expected the form host:port (e.g. vpn.example.com:51820).")

    peer_name = Prompt.ask("Name for this server [dim](optional)[/dim]", default="Server").strip()

    # ── Allowed IPs preset ──────────────────────────────────────────────────
    console.print("\n[bold cyan]5. What traffic should go through the VPN?[/bold cyan]")
    console.print("  [green]1[/green]  All traffic (full tunnel) [dim]— route everything[/dim]")
    console.print("  [green]2[/green]  All private networks [dim]— 10/8, 172.16/12, 192.168/16[/dim]")
    console.print("  [green]3[/green]  Custom subnets [dim]— you choose[/dim]")
    choice = Prompt.ask("Choice", choices=["1", "2", "3"], default="1")
    if choice == "1":
        allowed_ips = list(PRESET_FULL)
    elif choice == "2":
        allowed_ips = list(PRESET_PRIVATE)
    else:
        allowed_ips = _prompt_cidr_list(console, validation, "Subnet", default="192.168.1.0/24")

    # ── DNS ─────────────────────────────────────────────────────────────────
    dns: list[str] = []
    console.print("\n[bold cyan]6. DNS servers[/bold cyan] [dim](optional)[/dim]")
    if Confirm.ask("Set DNS servers for this tunnel?", default=choice == "1"):
        console.print("  [green]1[/green]  Cloudflare (1.1.1.1)")
        console.print("  [green]2[/green]  Google (8.8.8.8)")
        console.print("  [green]3[/green]  Quad9 (9.9.9.9)")
        console.print("  [green]4[/green]  Custom")
        dns_choice = Prompt.ask("Choice", choices=["1", "2", "3", "4"], default="1")
        if dns_choice in DNS_PRESETS:
            dns = list(DNS_PRESETS[dns_choice][1])
        else:
            dns = _prompt_ip_list(console, validation, "DNS server", default="1.1.1.1")

    # ── Expert-only options ─────────────────────────────────────────────────
    mtu = None
    keepalive = None
    preshared_key = None
    health_check_ip = None

    if expert:
        console.print("\n[bold magenta]7. Advanced options[/bold magenta]")
        if Confirm.ask("Set a custom MTU?", default=False):
            mtu = IntPrompt.ask("MTU", default=1420)
        if Confirm.ask("Enable persistent keepalive? [dim](recommended behind NAT)[/dim]", default=True):
            keepalive = IntPrompt.ask("Keepalive seconds", default=25)
        if Confirm.ask("Use a pre-shared key for extra security?", default=False):
            while True:
                preshared_key = Prompt.ask("Paste the pre-shared key").strip()
                if validation.is_key(preshared_key):
                    break
                console.print("[error]✗[/error] Not a valid pre-shared key.")
        if Confirm.ask("Add a health-check IP? [dim](pinged through the tunnel after connect)[/dim]", default=False):
            while True:
                health_check_ip = Prompt.ask("Health-check IP").strip()
                if validation.is_ip(health_check_ip):
                    break
                console.print("[error]✗[/error] Not a valid IP address.")
    else:
        # Basic mode: sensible default keepalive for reliability behind NAT.
        keepalive = 25

    # ── Build tunnel dict ───────────────────────────────────────────────────
    interface: dict = {"private_key": private_key, "addresses": addresses}
    if dns:
        interface["dns"] = dns
    if mtu:
        interface["mtu"] = mtu

    peer: dict = {
        "name": peer_name,
        "public_key": server_pub,
        "endpoint": endpoint,
        "allowed_ips": allowed_ips,
    }
    if preshared_key:
        peer["preshared_key"] = preshared_key
    if keepalive:
        peer["persistent_keepalive"] = keepalive
    if health_check_ip:
        peer["health_check_ip"] = health_check_ip

    tunnel = {"interface": interface, "peers": [peer]}
    if description:
        tunnel = {"description": description, **tunnel}

    # ── Summary & confirm ───────────────────────────────────────────────────
    _print_summary(console, name, description, public_key, addresses,
                   peer_name, server_pub, endpoint, allowed_ips, dns,
                   mtu, keepalive, preshared_key, health_check_ip)

    if not Confirm.ask("\n[bold]Save this tunnel?[/bold]", default=True):
        console.print("[warning]Cancelled — nothing was saved.[/warning]")
        return

    raw.setdefault("tunnels", {})[name] = tunnel
    wgm.save_raw_config(raw)
    console.print(f"\n[success]✓[/success] Tunnel [bold]{name}[/bold] saved to your config.")

    # ── Offer to bring it up ────────────────────────────────────────────────
    if Confirm.ask(f"Bring [bold]{name}[/bold] up now?", default=False):
        if not wgm.is_admin():
            console.print(
                "[warning]⚠[/warning] Bringing a tunnel up needs administrator rights.\n"
                f"[dim]Open an elevated terminal and run:[/dim] [bold]wgm up {name}[/bold]"
            )
            return
        wgm.ensure_deps()
        wgm._do_up(name)
    else:
        console.print(f"[dim]When ready, run:[/dim] [bold]wgm up {name}[/bold]")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _ensure_wireguard_dir(wgm) -> None:
    from pathlib import Path

    console = wgm.console
    raw = wgm.load_raw_config()
    wgm.ensure_skeleton(raw)
    settings = raw["wgm"]["settings"]
    if settings.get("wireguard_dir"):
        return

    default = Path(r"C:\Program Files\WireGuard")
    console.print("\n[bold cyan]WireGuard location[/bold cyan]")
    console.print("[dim]WGM needs to know where WireGuard is installed.[/dim]")
    guess = str(default) if default.exists() else ""
    path = Prompt.ask("WireGuard install folder", default=guess or None)
    settings["wireguard_dir"] = path
    wgm.save_raw_config(raw)
    console.print(f"[success]✓[/success] Saved WireGuard location: [dim]{path}[/dim]")


def _prompt_cidr_list(console, validation, label: str, default: str) -> list[str]:
    console.print(f"[dim]Enter one or more (comma-separated). Example: {default}[/dim]")
    while True:
        raw = Prompt.ask(label, default=default)
        items = [x.strip() for x in raw.split(",") if x.strip()]
        bad = [x for x in items if not validation.is_cidr(x)]
        if items and not bad:
            return items
        for b in bad:
            console.print(f"[error]✗[/error] Invalid CIDR: {b}")
        if not items:
            console.print("[warning]⚠[/warning] Please enter at least one value.")


def _prompt_ip_list(console, validation, label: str, default: str) -> list[str]:
    while True:
        raw = Prompt.ask(f"{label}(s) [dim](comma-separated)[/dim]", default=default)
        items = [x.strip() for x in raw.split(",") if x.strip()]
        bad = [x for x in items if not validation.is_ip(x)]
        if items and not bad:
            return items
        for b in bad:
            console.print(f"[error]✗[/error] Invalid IP: {b}")


def _print_summary(console, name, description, public_key, addresses, peer_name,
                   server_pub, endpoint, allowed_ips, dns, mtu, keepalive,
                   preshared_key, health_check_ip) -> None:
    table = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 2))
    table.add_column("Field", style="bold cyan", justify="right")
    table.add_column("Value")

    table.add_row("Name", name)
    if description:
        table.add_row("Description", description)
    if public_key:
        table.add_row("Public key", f"[cyan]{public_key}[/cyan]")
    table.add_row("Address", ", ".join(addresses))
    table.add_row("Server", f"{peer_name} [dim]({endpoint})[/dim]")
    table.add_row("Server key", f"[cyan]{server_pub}[/cyan]")
    table.add_row("Routes", ", ".join(allowed_ips))
    if dns:
        table.add_row("DNS", ", ".join(dns))
    if mtu:
        table.add_row("MTU", str(mtu))
    if keepalive:
        table.add_row("Keepalive", f"{keepalive}s")
    if preshared_key:
        table.add_row("Pre-shared key", "[dim]set[/dim]")
    if health_check_ip:
        table.add_row("Health check", health_check_ip)

    console.print()
    console.print(Panel(table, title="[bold]Review your tunnel[/bold]", border_style="cyan", expand=False))
