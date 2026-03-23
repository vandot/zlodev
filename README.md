# zlodev

Local reverse proxy with TLS termination, custom DNS, and a terminal UI.

zlodev sits between your browser and your local dev server, providing HTTPS with a real certificate, a custom domain (`https://dev.lo`), and a TUI for inspecting, intercepting, and replaying HTTP traffic.

## Features

- **HTTPS reverse proxy** — TLS termination with auto-generated CA and domain certificates
- **Multi-app routing** — route by subdomain (`api.dev.lo`) or path prefix (`/api`) to local ports or external hosts
- **Custom DNS** — resolves `*.lo` to localhost, no `/etc/hosts` editing
- **Terminal UI** — live request list with method, path, status, timing, and body size
- **Request interception** — hold, inspect, edit, accept, or drop requests with optional pattern matching
- **Request replay** — re-send any completed request
- **Copy as curl** — copy any request as a `curl` command
- **HAR export** — export captured traffic as HTTP Archive files
- **Request starring** — star important requests so they survive ring buffer overflow
- **Search/filter** — filter requests by path
- **WebSocket passthrough** — transparent proxying of WebSocket upgrades
- **Cross-platform** — macOS, Linux, and Windows

## Install

### Pre-built binary

Pre-built binaries have no external dependencies — single binary, nothing to install.

```sh
curl -fsSL https://raw.githubusercontent.com/vandot/zlodev/main/install.sh | sh
```

### Build from source

Building from source requires [Zig](https://ziglang.org/download/) 0.15.1. No other dependencies — BoringSSL is compiled from source automatically.

```sh
git clone https://github.com/vandot/zlodev.git
cd zlodev
zig build -Doptimize=ReleaseSafe
```

The binary is at `zig-out/bin/zlodev`.

On Linux, grant the binary permission to bind to privileged ports (80, 443) without root:

```sh
sudo setcap cap_net_bind_service=+eip zig-out/bin/zlodev
```

#### Build options

| Option | Description | Default |
|--------|-------------|---------|
| `-Dversion=STRING` | Version string | `dev` |
| `-Dmax-entries=N` | Max request entries in ring buffer | `500` |

## Quick start

### macOS / Linux

```sh
# 1. Install certificates and DNS resolver (one-time setup, requires sudo)
zlodev install

# 2. Start your dev server (e.g. on port 3000)
npm run dev &

# 3. Start zlodev
zlodev start
```

Your app is now available at `https://dev.lo`. The TUI shows live traffic.

### Windows

Run all commands in an **elevated terminal** (Run as Administrator).

```powershell
# 1. Install certificates and DNS resolver
zlodev install

# 2. Start your dev server, then start zlodev
zlodev start
```

> **Note:** Disable "Use secure DNS" in your browser (Edge: Settings → Privacy → Security → toggle off "Use secure DNS") for DNS resolution to work.

## Usage

### Commands

```
zlodev install              install certificates and DNS
zlodev install --cert       install certificates only
zlodev install --dns        install DNS only
zlodev uninstall            uninstall certificates and DNS
zlodev uninstall --cert     uninstall certificates only
zlodev uninstall --dns      uninstall DNS only
zlodev start                start proxy + DNS + TUI
zlodev start --dns          start DNS server only (log mode)
```

### Options

```
-p=PORT, --port=PORT       target port [auto-detect or 3000]
-b=ADDR, --bind=ADDR       listen address [default 0.0.0.0]
--route=PATTERN=PORT       route by subdomain or path (repeatable)
-c=PATH, --config=PATH     config file path [default .zlodev]
--max-body=SIZE            max request body size [default 10M]
--no-tui                   disable TUI, log to stderr
-l, --local                use .local domain (mDNS)
-f, --force                force reinstall
-v, --version              show version
-h, --help                 show help
```

`SIZE` accepts suffixes: `K` (KB), `M` (MB), `G` (GB). Example: `--max-body=50M`

### Config file

Place a `.zlodev` file in your project directory instead of repeating CLI flags:

```
port=3000
bind=127.0.0.1
route=api=3001
route=/webhooks=8080
intercept=POST /api
no-tui
```

zlodev reads `.zlodev` from the current directory on `start`. Use `-c=PATH` to specify a different location. CLI arguments override config file values.

Supported options: `port`, `p`, `bind`, `b`, `route`, `max-body`, `intercept`, `no-tui`, `local`, `l`, `dns`.

### Routing

Route requests to different backend ports by subdomain or path prefix:

```sh
# Subdomain routing — no "/" prefix
zlodev start --route=api=3001 --route=dashboard=4200

# api.dev.lo      → 127.0.0.1:3001
# dashboard.dev.lo → 127.0.0.1:4200
# dev.lo          → 127.0.0.1:3000 (default)

# Path routing — "/" prefix
zlodev start --route=/api=3001 --route=/admin=8080

# dev.lo/api/*    → 127.0.0.1:3001
# dev.lo/admin/*  → 127.0.0.1:8080
# dev.lo/*        → 127.0.0.1:3000 (default)

# Mix both
zlodev start --route=api=3001 --route=/webhooks=8080

# External upstream — route to remote services
zlodev start --route=api=staging.api.example.com
zlodev start --route=/payments=payments.stripe.com:443

# api.dev.lo → staging.api.example.com:443 (TLS)
# dev.lo/payments/* → payments.stripe.com:443 (TLS)
```

Priority: subdomain match > longest path prefix > default port.

External routes connect via TLS, rewrite the `Host` header to the upstream hostname, and rewrite `Set-Cookie` domain attributes to `dev.lo` so cookies work correctly in the browser. If no port is specified, defaults to 443.

> **Note:** Subdomain routes are not supported in local mode (`-l`), since mDNS does not support arbitrary subdomains.

### Port auto-detection

If `--port` is not specified, zlodev detects the port from:

1. `PORT=` in `.env` file
2. Framework config files (e.g. `next.config.js` → 3000, `vite.config.ts` → 5173)
3. Falls back to 3000

### Local network (mDNS)

```sh
# Use .local domain for access from mobile devices on the same network
zlodev install -l
zlodev start -l
# -> https://yourhostname.local
```

### Headless mode

```sh
# Run without TUI, logs to stderr (useful for scripts/CI)
zlodev start --no-tui
```

### Intercept

Press `i` in the TUI to enable intercept mode. You'll be prompted for a pattern — matching requests are held for inspection while all others pass through normally.

- **Empty pattern** — intercepts all requests
- **Path pattern** — `intercept=/api` matches any request with `/api` in the path
- **Method pattern** — `intercept=POST` matches all POST requests
- **Combined** — `intercept=POST /api` matches POST requests to `/api`

Pattern matching is case-insensitive. Press `i` again to disable intercept and release all held requests.

You can also set a default intercept pattern in your `.zlodev` config file:

```
intercept=POST /api
```

## TUI keybindings

### List view

| Key | Action |
|-----|--------|
| `j` / `k` | Scroll up / down |
| `G` | Go to end |
| `g` | Go to top |
| `s` | Toggle autoscroll |
| `Enter` | Open detail view |
| `/` | Search / filter by path |
| `Esc` | Clear filter |
| `*` | Star / unstar request (survives buffer overflow) |
| `i` | Intercept (prompts for pattern / toggles off) |
| `a` | Accept held request |
| `A` | Accept all held requests |
| `d` | Drop held request / delete completed request |
| `c` | Copy request as curl command |
| `e` | Edit request |
| `r` | Edit & replay request |
| `R` | Quick replay (no edit) |
| `E` | Export traffic as HAR file |
| `C` | Clear all requests |
| `?` | Toggle help overlay |
| `q` | Quit |

### Detail view

| Key | Action |
|-----|--------|
| `n` / `p` | Next / previous request |
| `b` | Toggle body display |
| `a` | Accept held request |
| `q` / `Esc` | Back to list |

## How it works

1. **DNS** — A lightweight DNS server resolves `*.lo` queries to `127.0.0.1`. On macOS it registers via `/etc/resolver/`, on Linux via `systemd-resolved`, on Windows via NRPT rules.

2. **Certificates** — On `install`, zlodev generates a local CA and domain certificate, then adds the CA to your system trust store. The CA is unique to your machine.

3. **Proxy** — An HTTPS reverse proxy accepts connections on port 443, terminates TLS, and forwards plain HTTP to your dev server. Responses are relayed back over TLS.

4. **HTTP server** — A plain HTTP server on port 80 serves the CA certificate download page (for mobile devices) and redirects other requests to HTTPS.

## Troubleshooting

### Port 443 already in use

Another process is using port 443. Check with:
```sh
# macOS
sudo lsof -i :443
# Linux
sudo ss -tlnp | grep :443
# Windows (elevated terminal)
netstat -an | findstr ":443"
```

### Permission denied on ports 80/443 (Linux)

On Linux, binding to ports below 1024 requires elevated privileges. Instead of running as root, zlodev uses Linux file capabilities. The install script sets this automatically, but if you built from source:

```sh
sudo setcap cap_net_bind_service=+eip $(which zlodev)
```

This grants only the specific capability to bind privileged ports — no other root access.

### Certificate not trusted

Re-run the install with force:
```sh
zlodev install -f
```

### DNS not resolving

Check if the DNS resolver is installed:
```sh
# macOS
cat /etc/resolver/lo
# Linux
resolvectl query dev.lo
# Windows (elevated PowerShell)
Resolve-DnsName dev.lo
```

If missing, reinstall DNS:
```sh
zlodev install -d
```

On Windows, make sure "Use secure DNS" is disabled in your browser — Chromium browsers bypass the system DNS resolver when this is enabled.

### Mobile device can't connect

1. Make sure the phone is on the same network
2. Start zlodev with `--local` flag: `zlodev start -l`
3. Open `http://yourhostname.local/ca` on the phone to install the CA certificate
4. Follow the platform-specific instructions on the download page

## Uninstall

```sh
zlodev uninstall
```

This removes the CA from your system trust store, deletes generated certificates, and removes the DNS resolver configuration.

## License

MIT
