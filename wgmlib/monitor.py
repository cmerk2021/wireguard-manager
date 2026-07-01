"""`wgm monitor` (alias `wgm stat`) — a live, full-screen dashboard of every
tunnel, htop-style: real-time transfer rates, handshake freshness and totals.
"""

from __future__ import annotations

import time
from datetime import datetime

import typer
from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from wgmlib.format import format_bytes, format_rate, format_handshake_age, handshake_health

_HEALTH_STYLE = {"healthy": "green", "stale": "yellow", "dead": "red"}


def run(interval: float = 1.0) -> None:
    import wgm
    from rich.live import Live

    console = wgm.console
    if not wgm.is_admin():
        console.print(
            "[warning]⚠[/warning] Live tunnel stats require administrator rights.\n"
            "[dim]Open an elevated terminal (Run as administrator) and try again.[/dim]"
        )
        raise typer.Exit(1)

    interval = max(0.5, float(interval))
    prev: dict[tuple[str, str], tuple[int, int, float]] = {}

    try:
        with Live(console=console, screen=True, refresh_per_second=8, transient=True) as live:
            while True:
                dump = wgm.wg_dump()
                now = time.time()
                renderable, prev = _build(wgm, dump, prev, now)
                live.update(renderable)
                time.sleep(interval)
    except KeyboardInterrupt:
        pass
    console.print("[dim]Monitor stopped.[/dim]")


def _build(wgm, dump: dict, prev: dict, now: float):
    configured = wgm.reload_config().get("tunnels", {})
    peer_names = _peer_name_maps(configured)

    new_prev: dict = {}
    total_rx_rate = total_tx_rate = 0.0
    total_rx = total_tx = 0

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", expand=True, padding=(0, 1))
    table.add_column("Tunnel", style="bold")
    table.add_column("Peer")
    table.add_column("Endpoint", overflow="fold")
    table.add_column("Handshake")
    table.add_column("↓ Total", justify="right")
    table.add_column("↑ Total", justify="right")
    table.add_column("↓ Rate", justify="right")
    table.add_column("↑ Rate", justify="right")

    active = set(dump.keys())

    for iface, data in sorted(dump.items()):
        peers = data.get("peers", [])
        if not peers:
            table.add_row(f"[green]● {iface}[/green]", "[dim]no peers[/dim]", "", "", "", "", "", "")
            continue
        for idx, p in enumerate(peers):
            pub = p.get("public_key", "")
            key = (iface, pub)
            rx, tx = int(p.get("rx", 0)), int(p.get("tx", 0))
            total_rx += rx
            total_tx += tx

            rx_rate = tx_rate = 0.0
            if key in prev:
                prx, ptx, pt = prev[key]
                dt = max(1e-6, now - pt)
                rx_rate = max(0.0, (rx - prx) / dt)
                tx_rate = max(0.0, (tx - ptx) / dt)
                total_rx_rate += rx_rate
                total_tx_rate += tx_rate
            new_prev[key] = (rx, tx, now)

            hs = p.get("latest_handshake", 0)
            health = handshake_health(hs, now)
            hs_text = Text(format_handshake_age(hs, now), style=_HEALTH_STYLE[health])

            label = peer_names.get(iface, {}).get(pub) or (pub[:14] + "…")
            tunnel_cell = f"[green]● {iface}[/green]" if idx == 0 else ""

            table.add_row(
                tunnel_cell,
                label,
                p.get("endpoint", "") or "[dim]—[/dim]",
                hs_text,
                format_bytes(rx),
                format_bytes(tx),
                format_rate(rx_rate),
                format_rate(tx_rate),
            )

    # Configured-but-down tunnels
    for name in configured:
        if name not in active:
            table.add_row(f"[dim]○ {name}[/dim]", "[dim]down[/dim]", "", "", "", "", "", "")

    # Header
    stamp = datetime.now().strftime("%H:%M:%S")
    header = Table.grid(expand=True)
    header.add_column(justify="left")
    header.add_column(justify="right")
    header.add_row(
        "[bold cyan]WGM Monitor[/bold cyan]  [dim]live tunnel dashboard[/dim]",
        f"[dim]{stamp}[/dim]",
    )

    summary = (
        f"[bold]{len(active)}[/bold] up / [bold]{len(configured)}[/bold] configured    "
        f"[dim]│[/dim]    ↓ [green]{format_rate(total_rx_rate)}[/green] "
        f"[dim]({format_bytes(total_rx)})[/dim]    "
        f"↑ [magenta]{format_rate(total_tx_rate)}[/magenta] "
        f"[dim]({format_bytes(total_tx)})[/dim]"
    )

    footer = Align.center("[dim]Press [bold]Ctrl+C[/bold] to quit[/dim]")

    body = Group(
        header,
        Align.center(summary),
        "",
        table,
    )
    panel = Panel(body, border_style="cyan", box=box.ROUNDED, padding=(1, 2))
    return Group(panel, footer), new_prev


def _peer_name_maps(configured: dict) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for tname, tcfg in configured.items():
        m: dict[str, str] = {}
        for peer in (tcfg or {}).get("peers", []) or []:
            if isinstance(peer, dict) and peer.get("public_key"):
                m[peer["public_key"]] = peer.get("name", "")
        out[tname] = m
    return out
