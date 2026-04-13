# Show HN: Zlodev -- Local HTTPS reverse proxy with auto-certs and a terminal UI

**URL to submit:** https://zlodev.vandot.rs

**Text body (paste into the HN text field):**

I kept setting up the same stack for every project -- mkcert for certs, /etc/hosts for DNS, nginx or Caddy for the reverse proxy. I knew it was possible to combine all of it into a single binary and make it simpler, so I built lodev in Nim a while back. Recently I rewrote it from scratch in Zig as zlodev, adding a terminal UI for inspecting traffic.

One command (`zlodev install && zlodev start --port=3000`) gives you `https://dev.lo` -- it auto-generates a CA, installs it in your system trust store, runs a DNS server for `*.lo`, and proxies to your local dev server with TLS termination.

The TUI lets you inspect traffic in real time, intercept and edit requests/responses before they reach your backend, replay requests, and export to HAR. Routing supports subdomains (`api.dev.lo -> :3001`), path prefixes (`/api -> :3001`), and external upstreams.

Single binary, no dependencies. Works on macOS, Linux, and Windows. MIT licensed.

GitHub: https://github.com/vandot/zlodev

---

**Timing:** Post Tuesday-Thursday, 8-10am US Eastern.

**After posting:** Stay online ~2 hours to answer comments. Be genuine, technical, and helpful. Don't be defensive about comparisons to other tools.
