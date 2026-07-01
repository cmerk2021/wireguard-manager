"""Configuration validation for WGM.

Validates the structure and value types of the merged WGM config and returns a
list of issues. Used by `wgm config validate` and `wgm doctor`.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# WireGuard keys are base64-encoded 32-byte values -> 44 chars ending in '='.
_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_PLACEHOLDER_KEYS = {"", "x", "your_private_key", "peer_public_key", "your_public_key"}


@dataclass
class Issue:
    severity: str  # "error" | "warning"
    path: str
    message: str

    @property
    def is_error(self) -> bool:
        return self.severity == "error"


# --------------------------------------------------------------------------- #
# Primitive type checks
# --------------------------------------------------------------------------- #

def is_key(value) -> bool:
    return isinstance(value, str) and bool(_KEY_RE.match(value.strip()))


def is_placeholder_key(value) -> bool:
    return not isinstance(value, str) or value.strip().lower() in _PLACEHOLDER_KEYS


def is_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def is_cidr(value) -> bool:
    try:
        ipaddress.ip_network(str(value), strict=False)
        return True
    except ValueError:
        return False


def is_port(value) -> bool:
    try:
        p = int(value)
    except (TypeError, ValueError):
        return False
    return 1 <= p <= 65535


def is_host_port(value) -> bool:
    """Validate 'host:port' where host is a hostname/IP (IPv6 allowed in [...])."""
    if not isinstance(value, str) or ":" not in value:
        return False
    host, _, port = value.rpartition(":")
    if not host or not is_port(port):
        return False
    host = host.strip("[]")
    if is_ip(host):
        return True
    # hostname
    return bool(re.match(r"^(?=.{1,253}$)([A-Za-z0-9_-]{1,63}\.)*[A-Za-z0-9_-]{1,63}$", host))


def is_positive_int(value) -> bool:
    try:
        return int(value) >= 0
    except (TypeError, ValueError):
        return False


# --------------------------------------------------------------------------- #
# Config validation
# --------------------------------------------------------------------------- #

def validate_config(cfg: dict) -> list[Issue]:
    """Validate a merged WGM config dict. Returns a list of Issue objects."""
    issues: list[Issue] = []

    def err(path: str, msg: str):
        issues.append(Issue("error", path, msg))

    def warn(path: str, msg: str):
        issues.append(Issue("warning", path, msg))

    if not isinstance(cfg, dict):
        err("(root)", "Config root must be a mapping.")
        return issues

    wgm = cfg.get("wgm")
    if wgm is None:
        warn("wgm", "Missing top-level 'wgm' section (settings/resources).")
        wgm = {}
    elif not isinstance(wgm, dict):
        err("wgm", "'wgm' must be a mapping.")
        wgm = {}

    # ---- settings ----
    settings = wgm.get("settings") or {}
    if not isinstance(settings, dict):
        err("wgm.settings", "'settings' must be a mapping.")
        settings = {}
    else:
        if "wireguard_dir" not in settings:
            warn("wgm.settings.wireguard_dir", "Not set — WGM cannot locate wg.exe/wireguard.exe.")
        elif not isinstance(settings["wireguard_dir"], str):
            err("wgm.settings.wireguard_dir", "Must be a string path.")
        for key in ("default_mtu", "handshake_timeout"):
            if key in settings and not is_positive_int(settings[key]):
                err(f"wgm.settings.{key}", f"Must be an integer, got {settings[key]!r}.")
        if "default_mtu" in settings and is_positive_int(settings["default_mtu"]):
            mtu = int(settings["default_mtu"])
            if not (576 <= mtu <= 9000):
                warn("wgm.settings.default_mtu", f"Unusual MTU {mtu} (typical range 1280-1500).")

    # ---- resources ----
    resources = wgm.get("resources") or {}
    subnet_lists = {}
    dns_profiles = {}
    endpoints = {}
    if resources and not isinstance(resources, dict):
        err("wgm.resources", "'resources' must be a mapping.")
    elif resources:
        subnet_lists = resources.get("subnet_lists") or {}
        dns_profiles = resources.get("dns_profiles") or {}
        endpoints = resources.get("endpoints") or {}

        for name, subnets in (subnet_lists.items() if isinstance(subnet_lists, dict) else []):
            path = f"wgm.resources.subnet_lists.{name}"
            if not isinstance(subnets, list):
                err(path, "Must be a list of CIDRs.")
                continue
            for s in subnets:
                if not is_cidr(s):
                    err(path, f"Invalid CIDR: {s!r}")

        for name, servers in (dns_profiles.items() if isinstance(dns_profiles, dict) else []):
            path = f"wgm.resources.dns_profiles.{name}"
            if not isinstance(servers, list):
                err(path, "Must be a list of IP addresses.")
                continue
            for s in servers:
                if not is_ip(s):
                    err(path, f"Invalid DNS IP: {s!r}")

        for name, ep in (endpoints.items() if isinstance(endpoints, dict) else []):
            path = f"wgm.resources.endpoints.{name}"
            if isinstance(ep, dict):
                if not ep.get("host") or not is_port(ep.get("port")):
                    err(path, "Endpoint mapping needs a 'host' and valid 'port'.")
            elif not is_host_port(ep):
                err(path, f"Invalid endpoint (expected 'host:port'): {ep!r}")

    # ---- tunnels ----
    tunnels = cfg.get("tunnels") or {}
    if not tunnels:
        warn("tunnels", "No tunnels configured.")
    elif not isinstance(tunnels, dict):
        err("tunnels", "'tunnels' must be a mapping of name -> tunnel.")
    else:
        for name, t in tunnels.items():
            _validate_tunnel(name, t, subnet_lists, dns_profiles, endpoints, err, warn)

    return issues


def _validate_tunnel(name, t, subnet_lists, dns_profiles, endpoints, err, warn):
    base = f"tunnels.{name}"
    if not isinstance(t, dict):
        err(base, "Tunnel must be a mapping.")
        return

    iface = t.get("interface")
    if not isinstance(iface, dict):
        err(f"{base}.interface", "Missing or invalid 'interface' block.")
        iface = {}

    # private key
    pk = iface.get("private_key")
    if pk is None:
        err(f"{base}.interface.private_key", "Missing private key.")
    elif is_placeholder_key(pk):
        err(f"{base}.interface.private_key", "Placeholder/empty private key — run 'wgm keygen'.")
    elif not is_key(pk):
        err(f"{base}.interface.private_key", "Not a valid 44-character WireGuard key.")

    # addresses
    addrs = iface.get("addresses")
    if not addrs:
        err(f"{base}.interface.addresses", "At least one interface address (CIDR) is required.")
    elif not isinstance(addrs, list):
        err(f"{base}.interface.addresses", "Must be a list of CIDRs.")
    else:
        for a in addrs:
            if not is_cidr(a):
                err(f"{base}.interface.addresses", f"Invalid address CIDR: {a!r}")

    # dns
    dns = iface.get("dns")
    if dns is not None:
        if not isinstance(dns, list):
            err(f"{base}.interface.dns", "Must be a list of IPs or @dns_profile refs.")
        else:
            for d in dns:
                if isinstance(d, str) and d.startswith("@"):
                    if d[1:] not in dns_profiles:
                        warn(f"{base}.interface.dns", f"Undefined dns_profile ref '{d}'.")
                elif not is_ip(d):
                    err(f"{base}.interface.dns", f"Invalid DNS entry: {d!r}")

    # mtu
    if "mtu" in iface and not is_positive_int(iface["mtu"]):
        err(f"{base}.interface.mtu", f"Must be an integer, got {iface['mtu']!r}.")

    # peers
    peers = t.get("peers")
    if not peers:
        err(f"{base}.peers", "At least one peer is required.")
        return
    if not isinstance(peers, list):
        err(f"{base}.peers", "Must be a list of peers.")
        return

    for i, peer in enumerate(peers):
        ppath = f"{base}.peers[{i}]"
        if not isinstance(peer, dict):
            err(ppath, "Peer must be a mapping.")
            continue

        pub = peer.get("public_key")
        if pub is None:
            err(f"{ppath}.public_key", "Missing peer public key.")
        elif is_placeholder_key(pub):
            err(f"{ppath}.public_key", "Placeholder/empty public key.")
        elif not is_key(pub):
            err(f"{ppath}.public_key", "Not a valid 44-character WireGuard key.")

        if peer.get("preshared_key") is not None and not is_key(peer["preshared_key"]):
            err(f"{ppath}.preshared_key", "Not a valid 44-character WireGuard key.")

        ep = peer.get("endpoint")
        if ep is None:
            warn(f"{ppath}.endpoint", "No endpoint — this peer cannot initiate a connection.")
        elif isinstance(ep, str) and ep.startswith("@"):
            if ep[1:] not in endpoints:
                warn(f"{ppath}.endpoint", f"Undefined endpoint ref '{ep}'.")
        elif isinstance(ep, dict):
            if not ep.get("host") or not is_port(ep.get("port")):
                err(f"{ppath}.endpoint", "Endpoint mapping needs 'host' and valid 'port'.")
        elif not is_host_port(ep):
            err(f"{ppath}.endpoint", f"Invalid endpoint (expected 'host:port'): {ep!r}")

        allowed = peer.get("allowed_ips")
        if not allowed:
            err(f"{ppath}.allowed_ips", "At least one allowed IP (CIDR) is required.")
        elif not isinstance(allowed, list):
            err(f"{ppath}.allowed_ips", "Must be a list of CIDRs or @subnet_list refs.")
        else:
            for a in allowed:
                if isinstance(a, str) and a.startswith("@"):
                    if a[1:] not in subnet_lists:
                        warn(f"{ppath}.allowed_ips", f"Undefined subnet_list ref '{a}'.")
                elif not is_cidr(a):
                    err(f"{ppath}.allowed_ips", f"Invalid CIDR: {a!r}")

        if peer.get("persistent_keepalive") is not None and not is_positive_int(peer["persistent_keepalive"]):
            err(f"{ppath}.persistent_keepalive", "Must be an integer (seconds).")

        hc = peer.get("health_check_ip")
        if hc is not None and not is_ip(hc):
            err(f"{ppath}.health_check_ip", f"Must be a plain IP address, got {hc!r}.")
