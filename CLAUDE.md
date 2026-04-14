# CLAUDE.md

## Project overview

zlodev = local reverse proxy + TLS termination + custom DNS + terminal UI. Sits between browser + dev server. Provides HTTPS with auto-generated certs at `https://dev.lo`, TUI for inspect/intercept/replay HTTP traffic. Domain hardcoded to `dev.lo` — no custom domains or TLDs.

Written in Zig 0.15.1. Uses BoringSSL (compiled from source) for TLS, libvaxis for terminal UI.

## Build & test

```sh
zig build                            # build (output: zig-out/bin/zlodev)
zig build -Doptimize=ReleaseSafe     # release build
zig test src/dns.zig                 # run DNS unit tests
zig test src/har.zig                 # run HAR + requests tests
zig test src/proxy.zig               # run proxy tests
zig test src/intercept.zig           # run intercept tests
zig test src/requests.zig            # run requests tests
```

No `zig build test` step — tests run per-file with `zig test src/<file>.zig`.

## Architecture

```
main.zig          CLI parsing, config file loading, command dispatch, thread orchestration
proxy.zig         HTTPS reverse proxy (TLS termination, upstream forwarding, replay, route resolution)
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

- **Thread model**: proxy = 64-thread pool (256KB stacks), HTTP server = 8 threads, DNS = single-threaded, subprocess = 2 reader threads (stdout/stderr). All loops use `poll()` with 1s timeout + `shutdown.isRunning()` check.
- **Ring buffers**: 
  - `requests.zig`: stores HTTP entries in fixed-size ring (`max_entries`, default 500). Entries ~69KB each (fixed-size arrays for headers/body). Pinned entries (intercepted, WebSocket, starred) skipped during overwrite. `copyEntry()` provides mutex-protected entry copies for TUI replay. `lock()`/`unlock()` expose mutex for external callers (e.g. TUI edits). `clearAll()` calls `intercept.dropAll()` + waits for pending entries to drain.
  - `subprocess.zig`: stores dev server log lines in fixed-size ring (`max_log_lines`, default 5000). `LogLine` entries (~4KB each) heap-allocated only when `--command` used. Oldest lines unconditionally evicted on overflow. Protected by mutex; `copyRange()` provides thread-safe window reads for TUI display.
- **TLS**: BoringSSL via `@cImport` (API-compatible with OpenSSL). `SSL_set_fd` uses `BIO_NOCLOSE` — caller must close socket after `SSL_free`.
- **Entry lifecycle**: Normal requests use `push()`. Intercepted requests use `pushAndPin()` → `finishEntry()` (which unpins). TUI can edit pinned entries in-place before accepting. Starred entries (`*` key) set `pinned=true` via `toggleStar()` to survive ring buffer overflow; `starred` = separate bool from `pinned` so unstarring doesn't interfere with intercept pins.
- **Replay**: Connects to proxy's own TLS endpoint (127.0.0.1:443) so request goes through full proxy path + gets captured naturally.
- **Chunked encoding**: State machine parser (`chunkedStep`) decodes chunks for body capture while forwarding raw chunked data to client. Invalid hex digits transition to `.parse_error` state, + all forwarding loops check for this alongside `.done`.
- **Routing**: `--route=api=3001` (subdomain) + `--route=/api=3001` (path prefix). `resolveRoute()` in proxy.zig matches Host header for subdomains, longest prefix for paths, falls back to default port. Each entry stores `route_index` for TUI color-coding. Routes can target external hosts (`--route=api=staging.example.com:443`) — `Route.hostname` field set, proxy connects via outbound TLS with SNI, rewrites `Host` header to upstream + rewrites `Set-Cookie Domain=` to proxy domain.
- **Config file**: `.zlodev` in project directory, parsed by `readConfigFile()` in main.zig. One option per line (same keys as CLI). CLI args override config values. Only read for `start` command. Supports `intercept=PATTERN` for default intercept pattern + `command=SHELL_CMD` for dev server integration.
- **Intercept patterns**: `intercept.zig` stores pattern (`pattern_buf`/`pattern_len` with `pattern_mutex`) + `Phase` (`.both`, `.request`, `.response`). `shouldInterceptRequest`/`shouldInterceptResponse` do case-insensitive substring match against method, path, or combined "METHOD PATH". Empty pattern matches all. Prefix `req:` intercepts only requests, `resp:` only responses, no prefix = both. TUI prompts for pattern on `i` key. Config file can set default pattern.
- **Response intercept**: When `shouldInterceptResponse` matches, proxy buffers entire response body (instead of streaming), stores it in entry with `resp_intercepted=true`, pins + waits. TUI shows "RESP" in status column. `e` opens response editor (status, headers, body). On accept, `forwardResponseFromEntry` sends (possibly edited) response with corrected `Content-Length`. `finishResponseIntercept` unpins without overwriting response data.
- **Windows**: `compat.SocketStream` wraps Winsock `recv`/`send` (std.net.Stream uses ReadFile which doesn't work with sockets on Windows). `socketToFd`/`fdToSocket` handle SOCKET↔c_int conversion. TUI skips `queryTerminal` on Windows to avoid spurious key events. Subprocess uses job objects for process-group cleanup; closing job handle atomically terminates all child processes with no graceful signal.
- **Dev server integration**: `subprocess.zig` spawns shell command (`sh -c` on Unix, `cmd /c` on Windows), captures stdout/stderr into log ring, strips ANSI escape sequences on ingest, splits bytes on `\n` into fixed-length lines. Reader threads check `shutdown.isRunning()` to participate in graceful shutdown. TUI split-pane (60% requests, 40% logs) toggled with `l` key; focus switches with `Tab`; autoscroll = per-pane via `s` key. Restart with `R` key sends SIGTERM (3s grace) then SIGKILL on Unix, or closes job handle on Windows.

## Code conventions

- Structured log format: `component=X op=Y field=value`
- Error handling: functions return `!void` or `!T`, errors are logged with context before propagating
- BoringSSL interop via `@cImport` — C types/functions accessed through `ssl_c.*` (proxy) or `c.*` (cert)
- TUI renders at 50ms intervals via `std.Thread.sleep`, not event-driven
- All string comparisons for HTTP headers use `startsWithIgnoreCase` (defined locally in proxy.zig + http_server.zig)
- `isChunkedEncoding` splits Transfer-Encoding by comma + checks each token (handles `gzip, chunked`)
- HTTP server sets `SO_RCVTIMEO` (5s) on accepted connections to prevent slow-client thread exhaustion
- HTTP server rejects paths containing `\r` or `\n` to prevent CRLF injection in redirects
- DNS server sets AA (Authoritative Answer) flag + rejects compression pointers in queries
- `cert.zig` uses atomic write (temp file + rename) for git CA bundle modification
- `clipboard.zig` detects truncation during curl command building + skips clipboard copy if truncated

## Important notes

- `Entry` = ~69KB. Never pass by value to threads — heap-allocate with `page_allocator.create()` + let callee `destroy()`.
- `sudoCmd` uses switch on `Term` variants — process may exit via signal, not exit code.
- Log is muted before spawning server threads in TUI mode to prevent stderr leaking through alt screen buffer.
- `max_body_len` (32KB) + `max_header_len` (2KB) = compile-time constants in `requests.zig`.
- CLI flag `-c` = `--config`, not `--cert`. `-d` removed — use `--dns` + `--cert` (no short forms).
- Subdomain routes blocked in local mode (`-l`) since mDNS doesn't support arbitrary subdomains.
- `start --dns` cannot combine with other start options (port, bind, routes, etc.).
- `--command` cannot combine with `--dns` (no TUI to display logs) or `--no-tui` (no pane for output).
- Error messages use full flag names (`--dns` + `--cert`, not `-d` + `-c`).
- Proxy rejects intercepted requests with truncated bodies (413 status) rather than forwarding partial data.
- After `sslSendError`, always `return` (never `continue` in keep-alive loop) since TLS state may be corrupted.
- `forwardResponseFromEntry` always emits `Content-Length`, even for zero-length bodies.
- TUI split-pane layout uses `win.child()` for clipping; requests pane rendered into child window with `draw_footer=false` to avoid footer-drawing in middle of split.