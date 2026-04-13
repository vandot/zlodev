# Reddit Launch Posts

## /r/webdev

**Title:** I built a local HTTPS reverse proxy that gives you https://dev.lo with one command

**Body:**

I kept setting up the same stack for every project -- mkcert for certs, /etc/hosts for DNS, nginx for the reverse proxy. I knew all of that could live in a single binary, so I originally built this in Nim. Recently I rewrote it from scratch in Zig as zlodev, adding a terminal UI for live traffic inspection.

Run `zlodev install && zlodev start --port=3000` and you get `https://dev.lo` pointing at your local server. It auto-generates certificates, installs them in your system trust store, and runs its own DNS so `*.lo` resolves to localhost.

The TUI lets you intercept requests, edit them before they hit your backend, replay them, and export to HAR. Supports routing by subdomain (`api.dev.lo`) or path prefix (`/api`).

Website: https://zlodev.vandot.rs
GitHub: https://github.com/vandot/zlodev

Happy to answer any questions!

---

## /r/selfhosted

**Title:** zlodev -- self-hosted local HTTPS proxy with auto-certs, DNS, and a terminal UI

**Body:**

I built a local dev proxy that replaces the typical mkcert + hosts file + nginx setup with a single binary. Originally wrote it in Nim, recently rewrote it in Zig with a terminal UI for inspecting and intercepting traffic.

It generates its own CA, manages DNS for `*.lo`, and gives you a TUI for inspecting and intercepting traffic. No cloud, no accounts, no dependencies. Single binary, MIT licensed. Works on macOS, Linux, and Windows.

Website: https://zlodev.vandot.rs
GitHub: https://github.com/vandot/zlodev

---

## /r/programming (only if HN got 50+ upvotes or front page)

**Title:** Show r/programming: zlodev -- Local HTTPS reverse proxy with TLS, DNS, and a TUI (written in Zig)

**Body:**

zlodev is a local reverse proxy that gives you `https://dev.lo` with one command. It handles CA generation, system trust store installation, DNS resolution for `*.lo`, and TLS termination -- replacing the typical mkcert + /etc/hosts + nginx stack.

I originally built this in Nim as lodev, then rewrote it from scratch in Zig with a terminal UI for live traffic inspection. Single binary, no runtime dependencies.

The TUI lets you inspect, intercept, edit, and replay HTTP traffic in real time.

Website: https://zlodev.vandot.rs
GitHub: https://github.com/vandot/zlodev

---

**Posting schedule:**
- Day 1: /r/webdev (primary target, largest audience)
- Day 2: /r/selfhosted
- Day 3+: /r/programming (only if HN did well)
