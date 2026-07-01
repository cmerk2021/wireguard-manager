# WGM — WireGuard Manager

A richer WireGuard experience for Windows. WGM wraps the standard WireGuard client with a declarative YAML config, reusable resources, and a polished CLI so you spend less time editing `.conf` files and more time connected.

> **You never have to touch YAML.** The interactive `wgm wizard` builds tunnels for you, and `wgm config` edits keys, resources and settings — all from friendly prompts.

---

## Why WGM?

WireGuard's native tooling is minimal by design. WGM builds on top of it:

- **Zero-YAML setup** — `wgm wizard` walks you through a fully working tunnel with plain-language questions (basic & expert modes)
- **Full config management** — `wgm config add/edit/remove` manages settings, resources and keys without opening a file
- **Human-readable YAML config** when you *do* want it, instead of flat `.conf` files
- **Reusable resources** — define subnet lists, DNS profiles, and endpoints once, reference them across any tunnel
- **Split your config** — pull tunnels or resources into separate files with `include:`
- **Rich terminal output** — colored status tables, live peer stats, panels with transfer data
- **Live dashboard** — `wgm monitor` is an htop-style, full-screen view of every tunnel with real-time transfer rates and **live throughput graphs**
- **Hook scripts** — run `pre_up` / `post_up` / `pre_down` / `post_down` commands around each tunnel, wg-quick style
- **Migration made easy** — `wgm import config.conf` pulls in configs from any WireGuard client, and `wgm export <tunnel>` writes a standard `.conf` back out
- **Boot autostart** — `wgm autostart <tunnel>` registers a tunnel to come up automatically at system startup
- **Overlap detection** — `wgm up` warns when a tunnel's routes overlap those of another tunnel that's already up
- **Built-in diagnostics** — `wgm doctor` runs a full health suite (config, internet, DNS, endpoint resolution, handshakes) with step-by-step fixes
- **Validation** — `wgm config validate` type-checks every field (IPs, CIDRs, ports, keys) before you connect
- **Safe key handling** — generate key pairs in one command; validation catches missing or placeholder keys before any tunnel comes up
- **Health-aware `up`** — polls for a WireGuard handshake after the tunnel service starts, warns with troubleshooting tips if none arrives, and optionally pings a host behind each peer to confirm end-to-end reachability

---

## Requirements

- Windows 10/11
- [WireGuard for Windows](https://www.wireguard.com/install/) (`wg.exe` and `wireguard.exe`)

---

## Installation

### CMAM Install (Recommended)

If you have [CMAM](https://github.com/cmerk2021/CMAM) installed, just run:

```
cmam install wgm
```

### Manual Install

Alternatively, download `wgm.exe` from the latest release to a folder that is in your PATH.

No additional dependencies required — WGM ships as a standalone `.exe`.

Once installed, all commands are available as:

```
wgm <command>
```

### Run from source

```
pip install -r requirements.txt
python wgm.py <command>
```

To build a standalone executable:

```
pyinstaller --onefile --name wgm wgm.py
```

---

## Quick start

```
wgm wizard        # create your first tunnel (no YAML required)
wgm up <name>     # connect (run as administrator)
wgm monitor       # watch it live
wgm doctor <name> # diagnose if something's off
```

---

## Configuration

WGM stores everything under `%LOCALAPPDATA%\WGM\`:

| Path | Purpose |
|---|---|
| `wgm.yaml` | Main config (settings, resources, tunnels) |
| `tunnels\` | Generated `.conf` files (managed by WGM) |
| `state.json` | Internal state |

You rarely need to open `wgm.yaml` directly — `wgm wizard` and `wgm config` manage it for you — but it's plain YAML if you prefer.

### wgm.yaml structure

```yaml
wgm:
  settings:
    wireguard_dir: "C:\\Program Files\\WireGuard"
    default_mtu: 1420
    handshake_timeout: 30   # seconds to wait for first handshake on `wgm up`

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
        health_check_ip: "10.0.0.1"  # pinged after handshake to confirm reachability

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
        health_check_ip: "10.0.0.1"
```

### Resource references

Prefix any value with `@` to reference a named resource. WGM resolves references at tunnel-up time and prints a warning (rather than failing) for any undefined reference, so you can still bring up other tunnels.

| Reference type | Used in | Config key |
|---|---|---|
| `@subnet_list_name` | peer `allowed_ips` | `wgm.resources.subnet_lists` |
| `@dns_profile_name` | interface `dns` | `wgm.resources.dns_profiles` |
| `@endpoint_name` | peer `endpoint` | `wgm.resources.endpoints` |

### Splitting your config with `include:`

Any mapping in your config may contain an `include:` key pointing at one or more other YAML files. WGM loads each referenced file and merges its contents in place. This lets you keep per-tunnel or per-site config in separate files.

```yaml
# wgm.yaml
wgm:
  settings:
    wireguard_dir: "C:\\Program Files\\WireGuard"

include:
  - "./tunnels/office.yaml"
  - "./tunnels/home.yaml"
```

```yaml
# tunnels/office.yaml
tunnels:
  office:
    description: "Office VPN"
    interface:
      private_key: "..."
      addresses: ["10.10.0.2/24"]
    peers:
      - public_key: "..."
        endpoint: "vpn.example.com:51820"
        allowed_ips: ["0.0.0.0/0"]
```

Rules:

- `include:` accepts a single path or a list of paths.
- Paths are **relative to the file that declares them**.
- Included files are deep-merged; keys defined locally take precedence over included ones.
- Includes may be nested (an included file can include others). Cycles are detected and ignored.
- WGM's write commands (`wizard`, `config …`) always save to the **main** `wgm.yaml`. Included files are read-only from WGM's perspective — edit those by hand.

> Run `wgm config validate` or `wgm doctor` and WGM will report any include path that can't be found or parsed.

---

## Commands

> **New here?** Just run `wgm wizard` \u2014 it creates a working tunnel for you. Everything below is available once you want finer control.

### `wgm wizard`

Interactively create a fully functional tunnel without ever touching YAML. The wizard asks plain-language questions and writes the result straight into your config.

Two modes:

- **basic** \u2014 just the essentials: name, keys, address, server, and what traffic to route.
- **expert** \u2014 everything in basic, plus MTU, persistent keepalive, pre-shared key, and a health-check IP.

Start it with either:

```\nwgm wizard          # asks you to choose basic or expert\nwgm wizard --expert # jump straight into expert mode\n```\n\nHighlights of the flow:\n\n- **Keys** \u2014 \u201cDo you have your own keypair, or should WGM generate one?\u201d If generated, WGM shows the **public key** to hand to your server admin and stores the private key for you.\n- **Traffic presets** \u2014 choose what goes through the VPN:\n  - **All traffic (full tunnel)** \u2014 `0.0.0.0/0, ::/0`\n  - **All private networks** \u2014 `10/8, 172.16/12, 192.168/16`\n  - **Custom subnets** \u2014 enter your own CIDRs\n- **DNS presets** \u2014 Cloudflare, Google, Quad9, or custom.\n- Every value is validated as you type, so you can't save a broken tunnel.\n- A review panel summarizes everything before saving, and WGM offers to bring the tunnel up immediately.\n\nOn first run the wizard also asks where WireGuard is installed (auto-detecting `C:\\Program Files\\WireGuard`) and remembers it.\n\n---\n\n### `wgm config`\n\nManage everything in your config without editing YAML.\n\n| Command | What it does |\n|---|---|\n| `wgm config add` | Add a subnet list, DNS profile, endpoint, or setting |\n| `wgm config edit` | Edit settings, a resource, or any of a tunnel's fields (including keys, address, routes, endpoint, keepalive, MTU, health check) |\n| `wgm config remove` | Remove a tunnel or resource |\n| `wgm config validate` | Type-check the whole config (see below) |\n| `wgm config path` | Show where the config and data files live |\n\nAll of these are menu-driven \u2014 pick an option by number and answer the prompts. Your existing formatting and comments in `wgm.yaml` are preserved on save.\n\n---\n\n### `wgm config validate`\n\nValidate the structure and value types of your config. WGM checks that every field is the right type \u2014 integers where integers belong, valid IP addresses, CIDRs, ports, `host:port` endpoints, and 44-character WireGuard keys \u2014 and that every `@reference` and `include:` path resolves.\n\n```\n$ wgm config validate\n     Location                          Problem\n \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n \u2717   tunnels.office.interface.private_key   Placeholder/empty private key \u2014 run 'wgm keygen'.\n \u26a0   tunnels.office.peers[0].endpoint       Undefined endpoint ref '@office_vpn'.\n\nSummary: 1 error(s), 1 warning(s).\n```\n\nExits with a non-zero status if any **errors** are found, so it's safe to use in scripts.\n\n---\n\n### `wgm list`", "oldString": "## Commands\n\n### `wgm list`"}]

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

Bring up a tunnel. WGM runs three phases:

**Phase 1 — Install**

1. Resolve all `@resource` references
2. Validate the config (catches missing/placeholder private keys)
3. Write a `.conf` to the tunnels directory
4. Install the WireGuard tunnel service

Before installing, WGM checks the tunnel's `AllowedIPs` against every tunnel that is **currently up** and warns if their routed subnets overlap (down tunnels are ignored). The warning is advisory — the tunnel still comes up, but you're told which routes will be taken over.

**Phase 2 — Handshake check**

After the service starts, WGM polls `wg show <tunnel>` every 2 seconds waiting for any peer to report a handshake. The timeout defaults to 30 seconds and is configurable via `wgm.settings.handshake_timeout`.

- If a handshake is detected in time, the tunnel is reported as **healthy**.
- If the timeout expires with no handshake, WGM prints a warning panel with common causes and fixes, then prompts you to keep the tunnel up for manual troubleshooting or bring it straight back down.

**Phase 3 — Ping health checks** *(optional)*

For each peer that has a `health_check_ip` set, WGM sends a single ICMP ping to that address through the tunnel. Results are shown in a compact table. A failed ping is a warning, not a fatal error — the tunnel is up and the handshake succeeded, so the issue is host-level reachability rather than the VPN itself.

Requires administrator privileges.

```
$ wgm up office
✓ Config written
✓ Tunnel service installed
✓ Handshake confirmed — tunnel office is healthy

 Peer            Health check IP   Reachable
 Office Gateway  10.0.0.1          ✓
✓ All health checks passed
```

Example when no handshake arrives:

```
$ wgm up office
✓ Config written
✓ Tunnel service installed
╭─ ⚠  No handshake detected on 'office' ──────────────────────────────╮
│ Common causes and fixes:                                             │
│                                                                      │
│   1. Firewall blocking UDP                                           │
│      Ensure port 51820/UDP is open on the server and any NAT.       │
│   2. Wrong peer public key                                           │
│      ...                                                             │
╰──────────────────────────────────────────────────────────────────────╯

What would you like to do?
  [k] Keep the tunnel up and troubleshoot manually
  [d] Bring the tunnel down
Choice [k]:
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

Bring a tunnel down then immediately back up. Useful after editing `wgm.yaml` to apply changes without manually running `down` and `up`. The handshake check and ping health checks run as part of the `up` phase.

Windows removes a tunnel service asynchronously, so WGM waits for the old service to fully disappear before reinstalling. This prevents the *"Tunnel already installed and running"* error that could otherwise leave a tunnel stuck between states. If the tunnel isn't up when you run `restart`, the down step is skipped automatically.

```
$ wgm restart office
✓ Tunnel office is down
  Config file cleaned up
✓ Config written
✓ Tunnel service installed
✓ Handshake confirmed — tunnel office is healthy
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

### `wgm monitor` (alias `wgm stat`)

A live, full-screen dashboard of every tunnel \u2014 htop-style. Shows each peer's endpoint, handshake freshness (green/yellow/red), cumulative transfer, and **real-time transfer rates** computed between refreshes, plus a running total across all tunnels. A **throughput panel** draws live sparkline graphs of the aggregate download (green) and upload (magenta) rates, with running peaks. Configured-but-down tunnels are listed too.

```\nwgm monitor              # refresh every second\nwgm monitor --interval 2 # refresh every 2 seconds\n```\n\nPress **Ctrl+C** to quit. Requires administrator privileges (WireGuard only exposes live peer stats to elevated processes).\n\n---\n\n### `wgm doctor [tunnel]`\n\nRun a full diagnostic suite with troubleshooting steps for anything that fails.\n\n**General diagnostics** (no tunnel name):\n\n- Config file loads and parses\n- All `include:` files resolve\n- Config validation (errors/warnings)\n- WireGuard binaries are present\n- Administrator rights\n- Internet connectivity\n- DNS resolution\n- Which tunnels are currently active\n\n**Tunnel diagnostics** (`wgm doctor <tunnel>`) adds:\n\n- The tunnel exists and its fields are valid\n- The endpoint resolves \u2014 if it's a domain, WGM shows the resolved IP(s)\n- If the tunnel is up: per-peer handshake freshness and transfer, plus any configured `health_check_ip` pings\n\nEach failed or warned check is followed by concrete fix steps, and a summary panel tells you whether everything passed.\n\n```\n$ wgm doctor office\n\u256d\u2500 General \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256e\n\u2502  \u2713  Config file loads       ...\\WGM\\wgm.yaml                    \u2502\n\u2502  \u2713  WireGuard binaries      C:\\Program Files\\WireGuard          \u2502\n\u2502  \u2713  Internet connectivity   reached 1.1.1.1                     \u2502\n\u2502  \u2713  DNS resolution          cloudflare.com \u2192 104.16.132.229      \u2502\n\u2570\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f\n\u256d\u2500 Tunnel: office \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256e\n\u2502  \u2713  Endpoint DNS (peer 1)   vpn.example.com \u2192 203.0.113.10        \u2502\n\u2502  \u2713  Handshake (abc123\u2026)     12s ago \u00b7 \u219314.3 MiB \u21912.1 MiB          \u2502\n\u2570\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f\n```\n\n---\n\n### `wgm keygen`", "oldString": "Omit the tunnel name to show all currently active tunnels.

---

### `wgm keygen`"}]

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

### `wgm import <config.conf>`

Import a standard WireGuard `.conf` file (from the official app, `wg-quick`, or any other client) as a WGM tunnel. WGM parses the `[Interface]` and `[Peer]` sections, converts any `PostUp`/`PostDown`/`PreUp`/`PreDown` directives into WGM hooks, and saves the result into `wgm.yaml`. After importing, any invalid fields are reported so you can fix them before connecting.

```
wgm import .\office.conf                 # tunnel name defaults to the file name
wgm import .\office.conf --name office   # choose a name
```

---

### `wgm export <tunnel>`

Export a tunnel back to a standard WireGuard `.conf` file — handy for moving to another client or device. All `@resource` references are resolved and hooks are emitted as `PostUp`/`PostDown` directives for portability.

```
wgm export office                # print the .conf to the screen
wgm export office -o .\out       # write out\office.conf
wgm export office -o office.conf # write to a specific file
```

> ⚠ Exported files contain your private key — handle them with care.

---

### `wgm autostart <tunnel>`

Register a tunnel to start automatically at system boot. WGM creates a Windows scheduled task that brings the tunnel up as `SYSTEM` at startup (non-interactively). Requires administrator privileges.

```
wgm autostart office            # enable autostart at boot
wgm autostart office --disable  # remove autostart
```

---

### Hook scripts

Like `wg-quick`, each tunnel can run commands at four points in its lifecycle. WGM executes them itself (WireGuard for Windows doesn't run hooks natively), so they work on Windows out of the box. Add a `hooks:` block to any tunnel:

```yaml
tunnels:
  office:
    interface:
      private_key: "..."
      addresses: ["10.10.0.2/24"]
    hooks:
      pre_up:    "echo bringing office up"
      post_up:   "route add 10.20.0.0 mask 255.255.0.0 10.10.0.1"
      pre_down:  "echo bringing office down"
      post_down: "route delete 10.20.0.0"
    peers:
      - public_key: "..."
        endpoint: "vpn.example.com:51820"
        allowed_ips: ["0.0.0.0/0"]
```

- Each hook may be a single command string or a list of commands.
- Commands run through the shell; the `WGM_TUNNEL` environment variable is set to the tunnel name.
- Hooks are best-effort — a failing hook is reported as a warning but never aborts the tunnel operation.
- You can also edit hooks interactively via `wgm config edit` → *A tunnel* → *Hook scripts*.

---

### `wgm version`

Print the installed WGM version.

---

## How it works

```
wgm.yaml  ──includes──▶  merged config  ──resolve refs──▶  in-memory config  ──generate──▶  tunnel.conf
                                                                                                 │
                                                                      wireguard.exe /installtunnelservice
                                                                                                 │
                                                                                    poll wg show (handshake?)
                                                                                                 │
                                                                                 ping health_check_ip (per peer)
```

On load, WGM merges any `include:` files into a single view, then resolves `@resource` references. WGM never edits your `wgm.yaml` on `up`/`down`; the generated `.conf` files in the `tunnels\` directory are ephemeral — written on `up` and deleted on `down`. The only commands that write to your config are `wgm wizard` and `wgm config …`, and they preserve your existing formatting and comments.

---

## Tips

**Start with `wgm wizard`.** It's the fastest way to a working tunnel and you never touch YAML. Use `wgm config edit` afterwards to tweak anything.

**Run `wgm doctor` when something's wrong.** It checks the whole chain — config, internet, DNS, endpoint resolution, handshakes — and prints concrete fix steps.

**Validate before you connect.** `wgm config validate` type-checks every field and resolves every `@reference` and `include:` path, so you catch typos before bringing a tunnel up.

**Split large configs** with `include:` — keep each site or tunnel in its own file and pull them together from `wgm.yaml`.

**Use `default_mtu`** under `wgm.settings` to apply a consistent MTU across all tunnels without repeating it per-interface. A per-tunnel `mtu` under the interface block takes precedence.

**Name your peers** with a `name` key in the peer list. WGM uses this label in `status`, `monitor`, and health check results instead of a truncated public key.

**`health_check_ip`** should be a host reachable *through* the tunnel — typically a gateway, internal DNS server, or any always-on host on the remote network. WGM pings it over the tunnel after a successful handshake, so a failure here points to a routing or firewall issue on the remote side rather than the VPN connection itself.

**`handshake_timeout`** defaults to 30 seconds. WireGuard initiates a handshake roughly 5 seconds after the tunnel comes up; 30 seconds gives plenty of margin for slow networks. Raise it if you're on a high-latency link, lower it if you want faster failure feedback.

**Placeholder keys**: WGM treats the values `x`, `YOUR_PRIVATE_KEY`, and empty string as unconfigured and will refuse to bring that tunnel up with a clear error — no silent failures.

---

## Command reference

| Command | Description |
|---|---|
| `wgm wizard [--expert]` | Interactively create a tunnel |
| `wgm list` | List tunnels and their status |
| `wgm up <tunnel>` | Bring a tunnel up (admin) |
| `wgm down <tunnel>` | Bring a tunnel down (admin) |
| `wgm restart <tunnel>` | Down then up (admin) |
| `wgm status [tunnel]` | Live status of active tunnel(s) (admin) |
| `wgm monitor [--interval N]` | Full-screen live dashboard (admin) |
| `wgm doctor [tunnel]` | Run diagnostics with fixes |
| `wgm keygen` | Generate a key pair |
| `wgm config add` | Add a resource or setting |
| `wgm config edit` | Edit settings, resources, or a tunnel |
| `wgm config remove` | Remove a tunnel or resource |
| `wgm config validate` | Type-check the config |
| `wgm config path` | Show config/data file locations |
| `wgm version` | Show the WGM version |

---

## License

MIT
