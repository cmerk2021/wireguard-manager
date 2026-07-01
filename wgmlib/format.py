"""Formatting helpers shared across WGM (byte sizes, transfer rates, handshake age)."""

from __future__ import annotations

import time

_UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]


def format_bytes(n: float) -> str:
    """Human-readable byte size, e.g. 1536 -> '1.50 KiB'."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "0 B"
    if n < 1024:
        return f"{int(n)} B"
    size = n
    for unit in _UNITS[1:]:
        size /= 1024.0
        if size < 1024 or unit == _UNITS[-1]:
            return f"{size:.2f} {unit}"
    return f"{size:.2f} {_UNITS[-1]}"


def format_rate(bytes_per_sec: float) -> str:
    """Human-readable transfer rate, e.g. '1.20 MiB/s'."""
    if bytes_per_sec <= 0:
        return "—"
    return f"{format_bytes(bytes_per_sec)}/s"


def format_handshake_age(ts: int, now: float | None = None) -> str:
    """
    Convert a unix timestamp (as reported by `wg show ... dump`) into a friendly
    'x seconds ago' string. Returns 'never' for 0/None.
    """
    if not ts:
        return "never"
    now = time.time() if now is None else now
    delta = int(now - ts)
    if delta < 0:
        delta = 0
    if delta < 5:
        return "just now"
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        m = delta // 60
        s = delta % 60
        return f"{m}m {s}s ago" if s else f"{m}m ago"
    if delta < 86400:
        h = delta // 3600
        m = (delta % 3600) // 60
        return f"{h}h {m}m ago" if m else f"{h}h ago"
    d = delta // 86400
    return f"{d}d ago"


def handshake_health(ts: int, now: float | None = None) -> str:
    """
    Classify a handshake timestamp into a rich style token:
      'healthy'  -> last handshake < 3 min ago
      'stale'    -> 3-5 min ago (keepalive window)
      'dead'     -> older / never
    """
    if not ts:
        return "dead"
    now = time.time() if now is None else now
    delta = now - ts
    if delta < 180:
        return "healthy"
    if delta < 300:
        return "stale"
    return "dead"
