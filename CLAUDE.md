# CLAUDE.md

## Project overview

zlodev = local reverse proxy w/ TLS termination, custom DNS, terminal UI. Sits between browser and local dev server. Provides HTTPS w/ auto-generated certs at `https://dev.lo`, plus TUI for inspect/intercept/replay HTTP traffic. Domain hardcoded to `dev.lo` — no custom domains or TLDs.

Zig 0.15.2. BoringSSL (compiled from source) for TLS, libvaxis for TUI.

## Build & test

```sh
zig build                            # build (output: zig-out/bin/zlodev)
zig build -Doptimize=ReleaseSafe     # release build
zig test src/dns.zig                 # run DNS unit tests
zig test src/har.zig                 # run HAR + requests tests
zig test src/proxy.zig               # run proxy tests
zig test src/intercept.zig           # run intercept tests
zig test src/requests.zig            # run requests tests
zig test src/http_wire.zig           # run HTTP wire parsing tests
zig test src/hold.zig                # run hold coordinator tests
zig test src/jsonfmt.zig             # run JSON formatting tests
zig test src/subprocess.zig          # run subprocess/log ring tests
zig test src/search.zig              # run search tests
zig test src/clipboard.zig           # run clipboard tests
zig test tests/install.zig           # run install/uninstall tests
zig test tests/integration.zig       # run integration tests (needs running zlodev + httpbin, see CI)
```

No `zig build test` step — tests run per-file w/ `zig test src/<file>.zig`.

## Architecture

```
main.zig          CLI parsing, config file loading, command dispatch, thread orchestration
proxy.zig         HTTPS reverse proxy (TLS termination, upstream forwarding, replay, route resolution)
http_wire.zig     HTTP/1.1 wire format (header inspection, chunked decoding, body streaming, header forwarding) — pure, no sockets/TLS
hold.zig          Hold coordinator for one intercepted entry (owns ring pin + intercept slot: begin → awaitDecision → accept/drop)
jsonfmt.zig       JSON pretty/compact reserialization for TUI body views and edited bodies
tui.zig           Terminal UI (vaxis-based, list/detail/edit views, split-pane logs, route colors)
subprocess.zig    Dev server launcher & log capture (process spawn, pipe reading, ANSI strip, log ring buffer)
dns.zig           UDP DNS server (resolves *.lo → 127.0.0.1)
http_server.zig   HTTP server on port 80 (CA cert download page, HTTPS redirect)
cert.zig          Certificate generation and system trust store management (BoringSSL)
requests.zig      Thread-safe ring buffer for captured request/response entries
intercept.zig     Request interception (pattern matching, hold/accept/drop with thread sync, dropAll/getPendingCount)
shutdown.zig      Global atomic shutdown flag + signal handlers (SIGINT/SIGTERM)
log.zig           Structured logging (stderr or file when TUI is active, mutex-protected writes)
search.zig        Entry search/filter logic
clipboard.zig     Copy-as-curl and case-insensitive string helpers
har.zig           HAR (HTTP Archive) export
sys.zig           System command helpers (sudo, tmp files, dir checks)
compat.zig        Cross-platform compatibility (Windows socket I/O, networking init)
```

## Key design decisions

- **Thread model**: proxy = 64-thread pool (4MB stacks on x86_64, 1MB elsewhere), HTTP server = 8 threads, DNS single-threaded, subprocess = 2 reader threads (stdout/stderr). All loops use `poll()` w/ 1s timeout + `shutdown.isRunning()` check.
- **Ring buffers**: 
  - `requests.zig`: HTTP entries in fixed-size ring (`max_entries`, default 500). Entries ~69KB each (fixed-size arrays for headers/body). Pinned entries (intercepted, WebSocket, starred) skipped on overwrite. `copyEntry()` gives mutex-protected copies for TUI replay. `lock()`/`unlock()` expose mutex for external callers (e.g. TUI edits). `clearAll()` calls `intercept.dropAll()`, waits for pending entries drain.
  - `subprocess.zig`: dev server log lines in fixed-size ring (`max_log_lines`, default 5000). `LogLine` entries (~4KB each) heap-allocated only when `--command` used. Oldest lines evicted unconditionally on overflow. Mutex-protected; `copyRange()` gives thread-safe window reads for TUI.
- **TLS**: BoringSSL via `@cImport` (OpenSSL API-compatible). `SSL_set_fd` uses `BIO_NOCLOSE` — caller must close socket after `SSL_free`.
- **Entry lifecycle**: Normal requests use `push()`. Intercepted requests/responses go through `hold.zig`: `hold.begin()` calls `pushAndPin()` + acquires intercept slot, `awaitDecision()` blocks until operator decides, then exactly one of `accept()`/`drop()` finalizes ring state (`finishEntry()` / `finishResponseIntercept()` unpin). TUI edits held entries in-place via `requests.editHeld()`, which classifies entry's `Phase` (`request`, `request_held`, `response_held`, `response_done`). Starred entries (`*` key) set `pinned=true` via `toggleStar()` to survive overflow; `starred` separate bool from `pinned` so unstar doesn't break intercept pins.
- **Replay**: Connects to proxy's own TLS endpoint (127.0.0.1:443) so request goes full proxy path, captured naturally.
- **Chunked encoding**: State machine parser (`chunkedStep` in `http_wire.zig`, driven by `pumpChunked`) decodes chunks for body capture while forwarding raw chunked data to client. Invalid hex → `.parse_error` state; all forwarding loops check this alongside `.done`.
- **Routing**: `--route=api=3001` (subdomain), `--route=/api=3001` (path prefix). `resolveRoute()` in proxy.zig matches Host header for subdomains, longest prefix for paths, else default port. Each entry stores `route_index` for TUI color-coding. Routes can target external hosts (`--route=api=staging.example.com:443`) — sets `Route.hostname`; proxy connects via outbound TLS w/ SNI, rewrites `Host` header to upstream, rewrites `Set-Cookie Domain=` to proxy domain.
- **Config file**: `.zlodev` in project dir, parsed by `readConfigFile()` in main.zig. One option per line (same keys as CLI). CLI args override. Only read for `start` command. Supports `intercept=PATTERN` (default intercept pattern) and `command=SHELL_CMD` (dev server integration).
- **Intercept patterns**: `intercept.zig` stores pattern (`pattern_buf`/`pattern_len` w/ `pattern_mutex`) and `Phase` (`.both`, `.request`, `.response`). `shouldInterceptRequest`/`shouldInterceptResponse` do case-insensitive substring match against method, path, or combined "METHOD PATH". Empty pattern matches all. Prefix `req:` = requests only, `resp:` = responses only, no prefix = both. TUI prompts for pattern on `i` key. Config file can set default.
- **Response intercept**: On `shouldInterceptResponse` match, proxy buffers entire response body (no streaming), stores in entry w/ `resp_intercepted=true`, pins, waits. TUI shows "RESP" in status column. `e` opens response editor (status, headers, body). On accept, `forwardResponseFromEntry` sends (maybe edited) response w/ corrected `Content-Length`. `finishResponseIntercept` unpins w/o overwriting response data.
- **Windows**: `compat.SocketStream` wraps Winsock `recv`/`send` (std.net.Stream uses ReadFile, broken for sockets on Windows). `socketToFd`/`fdToSocket` handle SOCKET↔c_int conversion. TUI skips `queryTerminal` on Windows to avoid spurious key events. Subprocess uses job objects for process-group cleanup; closing job handle atomically kills all children, no graceful signal.
- **Dev server integration**: `subprocess.zig` spawns shell command (`sh -c` Unix, `cmd /c` Windows), captures stdout/stderr into log ring, strips ANSI escapes on ingest, splits bytes on `\n` into fixed-length lines. Reader threads check `shutdown.isRunning()` for graceful shutdown. TUI split-pane (60% requests, 40% logs) toggled w/ `l`; focus switch w/ `Tab`; autoscroll per-pane via `s`. Restart w/ `R` sends SIGTERM (3s grace) then SIGKILL on Unix, or closes job handle on Windows.

## Code conventions

- Structured log format: `component=X op=Y field=value`
- Error handling: functions return `!void` or `!T`; errors logged w/ context before propagating
- BoringSSL interop via `@cImport` — C types/functions through `ssl_c.*` (proxy) or `c.*` (cert)
- TUI renders every 50ms via `std.Thread.sleep`, not event-driven
- HTTP header parsing in `http_wire.zig`; header name compares use `std.ascii.startsWithIgnoreCase` (no hand-rolled helpers)
- `isChunkedEncoding` (http_wire.zig) splits Transfer-Encoding by comma, checks each token (handles `gzip, chunked`)
- HTTP server sets `SO_RCVTIMEO` (5s) on accepted connections — prevents slow-client thread exhaustion
- HTTP server rejects paths containing `\r` or `\n` — prevents CRLF injection in redirects
- DNS server sets AA (Authoritative Answer) flag, rejects compression pointers in queries
- `cert.zig` uses atomic write (temp file + rename) for git CA bundle modification
- `clipboard.zig` detects truncation during curl command build, skips clipboard copy if truncated

## Important notes

- `Entry` ~69KB. Never pass by value to threads — heap-allocate w/ `page_allocator.create()`, callee `destroy()`.
- `sudoCmd` switches on `Term` variants — process may exit via signal, not just exit code.
- Log muted before spawning server threads in TUI mode — stops stderr leaking through alt screen buffer.
- `max_body_len` (32KB) and `max_header_len` (2KB) = compile-time constants in `requests.zig`.
- CLI flag `-c` = `--config`, not `--cert`. `-d` removed — use `--dns` and `--cert` (no short forms).
- Subdomain routes blocked in local mode (`-l`) — mDNS doesn't support arbitrary subdomains.
- `start --dns` can't combine w/ other start options (port, bind, routes, etc.).
- `--command` can't combine w/ `--dns` (no TUI for logs) or `--no-tui` (no pane for output).
- Error messages use full flag names (`--dns` and `--cert`, not `-d` and `-c`).
- Proxy rejects intercepted requests w/ truncated bodies (413) instead of forwarding partial data.
- After `sslSendError`, always `return` (never `continue` in keep-alive loop) — TLS state may be corrupted.
- `forwardResponseFromEntry` always emits `Content-Length`, even for zero-length bodies.
- TUI split-pane uses `win.child()` for clipping; requests pane rendered into child window w/ `draw_footer=false` so footer not drawn mid-split.
- macOS CI runs on `macos-15`, not `macos-latest`: Zig 0.15.x can't link against macOS 26 SDK. Unpin after moving to Zig 0.16+.
