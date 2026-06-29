# WGM — WireGuard Manager

A richer WireGuard experience for Windows. WGM wraps the standard WireGuard client with a declarative YAML config, reusable resources, and a polished CLI so you spend less time editing `.conf` files and more time connected.

---

## Why WGM?

WireGuard's native tooling is minimal by design. WGM builds on top of it:

- **Human-readable YAML config** instead of flat `.conf` files
- **Reusable resources** — define subnet lists, DNS profiles, and endpoints once, reference them across any tunnel
- **Rich terminal output** — colored status tables, live peer stats, panels with transfer data
- **Safe key handling** — generate key pairs in one command, validation catches missing or placeholder keys before any tunnel comes up
- **Seamless elevation** — automatically relaunches as administrator when needed; no manual UAC prompts

---

## Requirements

- Windows 10/11
- [WireGuard for Windows](https://www.wireguard.com/install/) (`wg.exe` and `wireguard.exe`)

---

## Installation

<!-- TODO: add download link / release instructions -->

No additional dependencies required — WGM ships as a standalone `.exe`.

Once installed, all commands are available as:

```
wgm <command>
```

---

## Configuration

WGM stores everything under `%LOCALAPPDATA%\WGM\`:

| Path | Purpose |
|---|---|
| `wgm.yaml` | Main config (settings, resources, tunnels) |
| `tunnels\` | Generated `.conf` files (managed by WGM) |
| `state.json` | Internal state |

### wgm.yaml structure

```yaml
wgm:
  settings:
    wireguard_dir: "C:\\Program Files\\WireGuard"
    default_mtu: 1420

  resources:
    subnet_lists:
      all_traffic:
        - "0.0.0.0/0"
        - "::/0"
      office_subnets:
        - "10.0.0.0/8"
        - "192.168.1.0/24"

    dns_profiles:
      internal:
        - "10.0.0.53"
        - "10.0.0.54"
      public:
        - "1.1.1.1"
        - "8.8.8.8"

    endpoints:
      office_vpn: "vpn.example.com:51820"
      backup_vpn: "vpn2.example.com:51820"

tunnels:
  office:
    description: "Office VPN — full tunnel"
    interface:
      private_key: "YOUR_PRIVATE_KEY"
      addresses:
        - "10.10.0.2/24"
      dns:
        - "@internal"        # resolves to dns_profiles.internal
    peers:
      - name: "Office Gateway"
        public_key: "PEER_PUBLIC_KEY"
        endpoint: "@office_vpn"       # resolves to endpoints.office_vpn
        allowed_ips:
          - "@all_traffic"            # resolves to subnet_lists.all_traffic
        persistent_keepalive: 25

  split:
    description: "Split-tunnel — office subnets only"
    interface:
      private_key: "YOUR_PRIVATE_KEY"
      addresses:
        - "10.10.0.3/24"
    peers:
      - name: "Office Gateway"
        public_key: "PEER_PUBLIC_KEY"
        endpoint: "@office_vpn"
        allowed_ips:
          - "@office_subnets"         # only route office traffic
```

### Resource references

Prefix any value with `@` to reference a named resource. WGM resolves references at tunnel-up time and prints a warning (rather than failing) for any undefined reference, so you can still bring up other tunnels.

| Reference type | Used in | Config key |
|---|---|---|
| `@subnet_list_name` | peer `allowed_ips` | `wgm.resources.subnet_lists` |
| `@dns_profile_name` | interface `dns` | `wgm.resources.dns_profiles` |
| `@endpoint_name` | peer `endpoint` | `wgm.resources.endpoints` |

---

## Commands

### `wgm list`

List all configured tunnels with their status, addresses, and peer count.

```
$ wgm list
╭──────────┬──────────────────────────┬─────────────┬───────┬─────────╮
│ Name     │ Description              │ Address     │ Peers │ Status  │
├──────────┼──────────────────────────┼─────────────┼───────┼─────────┤
│ office   │ Office VPN — full tunnel │ 10.10.0.2/24│   1   │ ● up    │
│ split    │ Split-tunnel             │ 10.10.0.3/24│   1   │ ○ down  │
╰──────────┴──────────────────────────┴─────────────┴───────┴─────────╯
```

---

### `wgm up <tunnel>`

Bring up a tunnel. WGM will:

1. Resolve all `@resource` references
2. Validate the config (catches missing/placeholder private keys)
3. Write a `.conf` to the tunnels directory
4. Install the WireGuard tunnel service

Requires administrator privileges — WGM will relaunch elevated automatically if needed.

```
$ wgm up office
✓ Config written
✓ Tunnel office is up
```

---

### `wgm down <tunnel>`

Bring down a tunnel and clean up its generated `.conf` file.

```
$ wgm down office
✓ Tunnel office is down
  Config file cleaned up
```

---

### `wgm restart <tunnel>`

Bring a tunnel down then immediately back up. Useful after editing `wgm.yaml` to apply changes without manually running `down` and `up`.

```
$ wgm restart office
✓ Tunnel office is down
  Config file cleaned up
✓ Config written
✓ Tunnel office is up
```

---

### `wgm status [tunnel]`

Show live stats for one or all active tunnels: public key, listening port, and per-peer endpoint, allowed IPs, last handshake, and transfer data.

```
$ wgm status office
╭─ ● office  Office VPN — full tunnel ────────────────────────────────╮
│   Public Key : abc123...                                             │
│   Port       : 51820                                                 │
╰──────────────────────────────────────────────────────────────────────╯

 Peer            Endpoint               Allowed IPs   Handshake     ↓ RX       ↑ TX
 Office Gateway  vpn.example.com:51820  0.0.0.0/0     2 minutes ago 14.3 MiB   2.1 MiB
```

Omit the tunnel name to show all currently active tunnels.

---

### `wgm keygen`

Generate a new WireGuard private/public key pair. Paste the private key into your `wgm.yaml` and share the public key with your peer.

```
$ wgm keygen
╭─ New Key Pair ──────────────────────────────────────────────────────╮
│ Private Key  <your-private-key>                                      │
│ Public Key   <your-public-key>                                       │
│                                                                      │
│ ⚠  Keep your private key secret — never share it.                   │
╰──────────────────────────────────────────────────────────────────────╯
```

---

### `wgm version`

Print the installed WGM version.

---

## How it works

```
wgm.yaml  ──resolve refs──▶  in-memory config  ──generate──▶  tunnel.conf
                                                                    │
                                                         wireguard.exe /installtunnelservice
```

WGM never edits your `wgm.yaml`. The generated `.conf` files in the `tunnels\` directory are ephemeral — they are written on `up` and deleted on `down`.

---

## Tips

**Use `default_mtu`** under `wgm.settings` to apply a consistent MTU across all tunnels without repeating it per-interface. A per-tunnel `mtu` under the interface block takes precedence.

**Name your peers** with a `name` key in the peer list. WGM uses this label in `status` output instead of a truncated public key.

**Placeholder keys**: WGM treats the values `x`, `YOUR_PRIVATE_KEY`, and empty string as unconfigured and will refuse to bring that tunnel up with a clear error — no silent failures.

---

## License

MIT