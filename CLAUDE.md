# CLAUDE.md

## Project overview

zlodev = local reverse proxy with TLS termination, custom DNS, terminal UI. Sits between browser and local dev server. Gives HTTPS with auto-generated certs at `https://dev.lo`, plus TUI to inspect/intercept/replay HTTP traffic. Domain hardcoded to `dev.lo`: no custom domains or TLDs.

Written in Zig 0.17.0. BoringSSL (compiled from source) for TLS, libvaxis for terminal UI.

## Build & test

```sh
zig build                            # build (output: zig-out/bin/zlodev)
zig build -Doptimize=ReleaseSafe     # release build
zig test src/dns.zig                 # run DNS unit tests
zig test src/har.zig                 # run HAR + requests tests
zig build test-c                     # run proxy + cert tests (they import BoringSSL headers)
zig test src/intercept.zig           # run intercept tests
zig test src/requests.zig            # run requests tests
zig test src/http_wire.zig           # run HTTP wire parsing tests
zig test src/hold.zig                # run hold coordinator tests
zig test src/jsonfmt.zig             # run JSON formatting tests
zig test src/subprocess.zig          # run subprocess/log ring tests
zig test src/search.zig              # run search tests
zig test src/clipboard.zig           # run clipboard tests
zig test src/rt.zig                  # run runtime (Io, timestamps, worker slots) tests
zig test src/compat.zig              # run socket layer tests
zig test src/http_server.zig         # run HTTP server tests
zig test src/shutdown.zig            # run shutdown/signal tests
zig test tests/install.zig           # run install/uninstall tests
zig test tests/integration.zig       # run integration tests (needs running zlodev + httpbin, see CI)
```

No `zig build test` step. Tests run per-file with `zig test src/<file>.zig`, except `proxy.zig` and `cert.zig`: they need translated BoringSSL headers, run via `zig build test-c`.

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
compat.zig        Cross-platform socket layer (Winsock on Windows, BSD sockets on POSIX: bind/listen/accept/connect/UDP, poll, SocketStream)
rt.zig            Process-wide std.Io handle, timestamps, sleep, worker spawn + slot caps
win32.zig         Win32/Winsock bindings Zig 0.17 std no longer exposes (console, sockets, job objects)
```

## Key design decisions

- **Thread model**: `main` creates one `std.Io.Threaded` (4MB stacks on x86_64, 1MB elsewhere, unlimited concurrency), installs via `rt.setIo`. `rt.io()` returns it (or `std.testing.io` under tests). Proxy and HTTP server run each connection as `Io.Group` task, capped by `rt.acquireWorkerSlot` at 64 and 8. At cap, accept waits for free slot (excess connections queue in listen backlog). DNS single-threaded. Subprocess uses 2 reader threads (stdout/stderr). All loops use `poll()` with 1s timeout + `shutdown.isRunning()` check.
- **Ring buffers**: 
  - `requests.zig`: HTTP entries in fixed-size ring (`max_entries`, default 500). Entries ~69KB each (fixed-size arrays for headers/body). Pinned entries (intercepted, WebSocket, starred) skipped on overwrite. `copyEntry()` gives mutex-protected entry copies for TUI replay. `lock()`/`unlock()` expose mutex for external callers (e.g. TUI edits). `clearAll()` calls `intercept.dropAll()`, waits for pending entries to drain.
  - `subprocess.zig`: dev server log lines in fixed-size ring (`max_log_lines`, default 5000). `LogLine` entries (~4KB each) heap-allocated only when `--command` used. Oldest lines evicted unconditionally on overflow. Mutex-protected; `copyRange()` gives thread-safe window reads for TUI display.
- **TLS**: BoringSSL headers translated in `build.zig` (`addBoringSslHeaders` → `b.addTranslateC`, imported as `ssl_c`/`cert_c` modules; API-compatible with OpenSSL). `SSL_set_fd` uses `BIO_NOCLOSE`: caller must close socket after `SSL_free`.
- **Entry lifecycle**: Normal requests use `push()`. Intercepted requests and responses go through `hold.zig`: `hold.begin()` calls `pushAndPin()` and acquires intercept slot, `awaitDecision()` blocks until operator decides, then exactly one of `accept()`/`drop()` finalizes ring state (`finishEntry()` / `finishResponseIntercept()` unpin). TUI edits held entries in-place via `requests.editHeld()`, which classifies entry's `Phase` (`request`, `request_held`, `response_held`, `response_done`). Starred entries (`*` key) set `pinned=true` via `toggleStar()` to survive ring overflow. `starred` separate bool from `pinned` so unstar doesn't break intercept pins.
- **Replay**: Connects to proxy's own TLS endpoint (127.0.0.1:443) so request goes through full proxy path, gets captured naturally.
- **Chunked encoding**: State machine parser (`chunkedStep` in `http_wire.zig`, driven by `pumpChunked`) decodes chunks for body capture while forwarding raw chunked data to client. Invalid hex digits → `.parse_error` state; all forwarding loops check it alongside `.done`.
- **Routing**: `--route=api=3001` (subdomain) and `--route=/api=3001` (path prefix). `resolveRoute()` in proxy.zig matches Host header for subdomains, longest prefix for paths, falls back to default port. Each entry stores `route_index` for TUI color-coding. Routes can target external hosts (`--route=api=staging.example.com:443`): `Route.hostname` set, proxy connects via outbound TLS with SNI, rewrites `Host` header to upstream, rewrites `Set-Cookie Domain=` to proxy domain.
- **Config file**: `.zlodev` in project dir, parsed by `readConfigFile()` in main.zig. One option per line (same keys as CLI). CLI args override config. Read only for `start` command. Supports `intercept=PATTERN` for default intercept pattern and `command=SHELL_CMD` for dev server integration.
- **Intercept patterns**: `intercept.zig` stores pattern (`pattern_buf`/`pattern_len` with `pattern_mutex`) and `Phase` (`.both`, `.request`, `.response`). `shouldInterceptRequest`/`shouldInterceptResponse` do case-insensitive substring match on method, path, or combined "METHOD PATH". Empty pattern matches all. Prefix `req:` = requests only, `resp:` = responses only, no prefix = both. TUI prompts for pattern on `i` key. Config file can set default pattern.
- **Response intercept**: When `shouldInterceptResponse` matches, proxy buffers whole response body (no streaming), stores in entry with `resp_intercepted=true`, pins, waits. TUI shows "RESP" in status column. `e` opens response editor (status, headers, body). On accept, `forwardResponseFromEntry` sends (possibly edited) response with corrected `Content-Length`. `finishResponseIntercept` unpins without overwriting response data.
- **Sockets**: all networking through `compat.zig`, not `std.Io.net`. On Windows `std.Io.net` returns AFD handles that Winsock calls (`WSAPoll`, `recv`/`send`) and BoringSSL's `SSL_set_fd` reject. Sockets created close-on-exec (`WSA_FLAG_NO_HANDLE_INHERIT` on Windows) so `--command` children don't inherit listeners. Winsock started lazily on first socket. `SO_REUSEADDR` set on POSIX only: on Windows it lets second bind steal taken port instead of failing with `AddressInUse`.
- **Windows**: `compat.SocketStream` wraps Winsock `recv`/`send`. `socketToFd`/`fdToSocket` handle SOCKET↔c_int conversion. TUI skips `queryTerminal` on Windows to avoid spurious key events. Subprocess puts `cmd.exe` in kill-on-close job object (`win32.assignToKillJob`). Stop calls `TerminateJobObject`, kills whole tree, no graceful signal (falls back to `TerminateProcess` if job setup failed).
- **Dev server integration**: `subprocess.zig` spawns shell command (`sh -c` on Unix, `cmd /c` on Windows), captures stdout/stderr into log ring, strips ANSI escapes on ingest, splits bytes on `\n` into fixed-length lines. Reader threads check `shutdown.isRunning()` for graceful shutdown. TUI split-pane (60% requests, 40% logs) toggled with `l` key; focus switch with `Tab`; autoscroll per-pane via `s` key. On Unix child spawns in own process group (`pgid = 0`, stored as `child_pgid`). Restart with `R` key sends SIGTERM to group (3s grace) then SIGKILL. Signals stored group even if shell already exited, since its children may outlive it. On Windows terminates job.

## Code conventions

- Structured log format: `component=X op=Y field=value`
- Error handling: functions return `!void` or `!T`; errors logged with context before propagating
- BoringSSL interop via translate-c modules: C types/functions through `ssl_c.*` (proxy) or `c.*` (cert)
- TUI renders at 50ms intervals via `rt.sleepMs`, not event-driven
- HTTP header parsing lives in `http_wire.zig`; header name comparisons use `std.ascii.startsWithIgnoreCase` (no hand-rolled helpers)
- `isChunkedEncoding` (http_wire.zig) splits Transfer-Encoding by comma, checks each token (handles `gzip, chunked`)
- HTTP server sets `SO_RCVTIMEO` (5s) on accepted connections to prevent slow-client thread exhaustion
- HTTP server rejects paths with `\r` or `\n` to prevent CRLF injection in redirects
- DNS server sets AA (Authoritative Answer) flag, rejects compression pointers in queries
- `cert.zig` uses atomic write (temp file + rename) for git CA bundle modification
- `clipboard.zig` detects truncation during curl command building, skips clipboard copy if truncated

## Important notes

- `Entry` ~69KB. Never pass by value to threads: heap-allocate with `page_allocator.create()`, callee `destroy()`.
- `sudoCmd` switches on `Term` variants: process may exit via signal, not just exit code.
- Log muted before spawning server threads in TUI mode so stderr doesn't leak through alt screen buffer.
- `max_body_len` (32KB) and `max_header_len` (2KB) = compile-time constants in `requests.zig`.
- CLI flag `-c` is `--config`, not `--cert`. `-d` removed: use `--dns` and `--cert` (no short forms).
- Subdomain routes blocked in local mode (`-l`): mDNS doesn't support arbitrary subdomains.
- `start --dns` can't combine with other start options (port, bind, routes, etc.).
- `--command` can't combine with `--dns` (no TUI to show logs) or `--no-tui` (no pane for output).
- Error messages use full flag names (`--dns` and `--cert`, not `-d` and `-c`).
- Proxy rejects intercepted requests with truncated bodies (413 status), no forwarding partial data.
- After `sslSendError`, always `return` (never `continue` in keep-alive loop): TLS state may be corrupted.
- `forwardResponseFromEntry` always emits `Content-Length`, even for zero-length bodies.
- TUI split-pane layout uses `win.child()` for clipping; requests pane rendered into child window with `draw_footer=false` so footer not drawn mid-split.