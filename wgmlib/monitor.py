"""`wgm monitor` (alias `wgm stat`) — a live, full-screen dashboard of every
tunnel, htop-style: real-time transfer rates, handshake freshness and totals.
"""

from __future__ import annotations

import time
from collections import deque
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

# Vertical block ramp (eighths), from empty to full — used to build the
# btop-style area graph one row at a time.
_BLOCKS = " ▁▂▃▄▅▆▇█"
# How many samples of rate history to keep for the graphs.
_HISTORY = 240
# Height of each throughput graph, in text rows.
_GRAPH_HEIGHT = 8

# Vertical color gradients (bottom → top), btop-style. Low throughput is a cool
# calm hue, ramping to a hot/bright hue at the peak.
_RX_GRADIENT = [(0x0d, 0x5c, 0x33), (0x22, 0xc5, 0x5e), (0xd9, 0xf9, 0x5b)]
_TX_GRADIENT = [(0x2a, 0x3d, 0x8f), (0x63, 0x7c, 0xff), (0xe0, 0x7c, 0xff)]


def _lerp_gradient(stops: list[tuple[int, int, int]], t: float) -> str:
    """Interpolate a multi-stop RGB gradient at position *t* in [0, 1] → '#rrggbb'."""
    if t <= 0:
        r, g, b = stops[0]
        return f"#{r:02x}{g:02x}{b:02x}"
    if t >= 1:
        r, g, b = stops[-1]
        return f"#{r:02x}{g:02x}{b:02x}"
    span = len(stops) - 1
    pos = t * span
    i = int(pos)
    frac = pos - i
    r1, g1, b1 = stops[i]
    r2, g2, b2 = stops[i + 1]
    r = round(r1 + (r2 - r1) * frac)
    g = round(g1 + (g2 - g1) * frac)
    b = round(b1 + (b2 - b1) * frac)
    return f"#{r:02x}{g:02x}{b:02x}"


def _area_graph(values, width: int, height: int, peak: float,
                gradient: list[tuple[int, int, int]]) -> list[Text]:
    """Render *values* as a tall, gradient-filled area graph.

    Returns *height* Text rows (top-to-bottom). Each row is a single gradient
    color (cool at the base, hot at the crest) so tall columns fade upward,
    mimicking btop's usage meters.
    """
    if width <= 0 or height <= 0:
        return [Text("") for _ in range(max(0, height))]

    recent = list(values)[-width:]
    if len(recent) < width:
        recent = [0.0] * (width - len(recent)) + recent
    scale = peak if peak > 0 else 1.0

    rows: list[Text] = []
    for r in range(height - 1, -1, -1):  # top row first
        color = _lerp_gradient(gradient, r / (height - 1) if height > 1 else 1.0)
        chars: list[str] = []
        for v in recent:
            frac = min(1.0, max(0.0, v / scale))
            total_eighths = frac * height * 8.0
            cell = total_eighths - r * 8.0
            cell = 0 if cell <= 0 else (8 if cell >= 8 else int(round(cell)))
            chars.append(_BLOCKS[cell])
        rows.append(Text("".join(chars), style=color))
    return rows


def _graph_block(label: str, hist, width: int, height: int,
                 gradient: list[tuple[int, int, int]], accent: str) -> Group:
    """One labelled throughput graph (header line + area graph)."""
    peak = max(hist) if hist else 0.0
    now = hist[-1] if hist else 0.0

    header = Table.grid(expand=True)
    header.add_column(justify="left")
    header.add_column(justify="right")
    header.add_row(
        f"[bold {accent}]{label}[/bold {accent}]  [{accent}]{format_rate(now)}[/{accent}]",
        f"[dim]peak[/dim] [{accent}]{format_rate(peak)}[/{accent}]",
    )

    graph_rows = _area_graph(hist, width, height, peak, gradient)
    return Group(header, *graph_rows)


def _graph_panel(rx_hist, tx_hist, width: int) -> Panel:
    """Build a panel with two tall gradient area graphs (download / upload)."""
    graph_w = max(10, width - 4)

    body = Group(
        _graph_block("↓ RX", rx_hist, graph_w, _GRAPH_HEIGHT, _RX_GRADIENT, "green"),
        "",
        _graph_block("↑ TX", tx_hist, graph_w, _GRAPH_HEIGHT, _TX_GRADIENT, "magenta"),
    )
    return Panel(body, title="[bold]Throughput[/bold]", border_style="cyan",
                 box=box.ROUNDED, padding=(1, 1))


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
    rx_hist: deque = deque(maxlen=_HISTORY)
    tx_hist: deque = deque(maxlen=_HISTORY)

    try:
        with Live(console=console, screen=True, refresh_per_second=8, transient=True) as live:
            while True:
                dump = wgm.wg_dump()
                now = time.time()
                renderable, prev = _build(wgm, dump, prev, now, rx_hist, tx_hist)
                live.update(renderable)
                time.sleep(interval)
    except KeyboardInterrupt:
        pass
    console.print("[dim]Monitor stopped.[/dim]")


def _build(wgm, dump: dict, prev: dict, now: float, rx_hist: deque, tx_hist: deque):
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

    # Record aggregate rates for the throughput graphs.
    rx_hist.append(total_rx_rate)
    tx_hist.append(total_tx_rate)
    graph_width = wgm.console.size.width - 8

    footer = Align.center("[dim]Press [bold]Ctrl+C[/bold] to quit[/dim]")

    body = Group(
        header,
        Align.center(summary),
        "",
        _graph_panel(rx_hist, tx_hist, graph_width),
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
