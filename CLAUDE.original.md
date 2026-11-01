# CLAUDE.md

## Project overview

zlodev is a local reverse proxy with TLS termination, custom DNS, and a terminal UI. It sits between the browser and a local dev server, providing HTTPS with auto-generated certificates at `https://dev.lo`, and a TUI for inspecting/intercepting/replaying HTTP traffic. The domain is hardcoded to `dev.lo` — no custom domains or TLDs.

Written in Zig 0.17.0, uses BoringSSL (compiled from source) for TLS and libvaxis for the terminal UI.

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

There is no `zig build test` step — tests are run per-file with `zig test src/<file>.zig`, except `proxy.zig` and `cert.zig`, which need the translated BoringSSL headers and run via `zig build test-c`.

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

- **Thread model**: `main` creates one `std.Io.Threaded` (4MB stacks on x86_64, 1MB elsewhere, unlimited concurrency) and installs it via `rt.setIo`; `rt.io()` returns it (or `std.testing.io` under tests). Proxy and HTTP server run each connection as an `Io.Group` task, capped by `rt.acquireWorkerSlot` at 64 and 8 — at the cap, accept waits for a free slot (excess connections queue in the listen backlog), DNS is single-threaded, subprocess uses 2 reader threads (stdout/stderr). All loops use `poll()` with 1s timeout + `shutdown.isRunning()` check.
- **Ring buffers**: 
  - `requests.zig`: stores HTTP entries in a fixed-size ring (`max_entries`, default 500). Entries are ~69KB each (fixed-size arrays for headers/body). Pinned entries (intercepted, WebSocket, starred) are skipped during overwrite. `copyEntry()` provides mutex-protected entry copies for TUI replay. `lock()`/`unlock()` expose the mutex for external callers (e.g. TUI edits). `clearAll()` calls `intercept.dropAll()` and waits for pending entries to drain.
  - `subprocess.zig`: stores dev server log lines in a fixed-size ring (`max_log_lines`, default 5000). `LogLine` entries (~4KB each) are heap-allocated only when `--command` is used. Oldest lines are unconditionally evicted on overflow. Protected by mutex; `copyRange()` provides thread-safe window reads for TUI display.
- **TLS**: BoringSSL headers translated in `build.zig` (`addBoringSslHeaders` → `b.addTranslateC`, imported as `ssl_c`/`cert_c` modules; API-compatible with OpenSSL). `SSL_set_fd` uses `BIO_NOCLOSE` — the caller must close the socket after `SSL_free`.
- **Entry lifecycle**: Normal requests use `push()`. Intercepted requests and responses go through `hold.zig`: `hold.begin()` calls `pushAndPin()` and acquires an intercept slot, `awaitDecision()` blocks until the operator decides, then exactly one of `accept()`/`drop()` finalizes ring state (`finishEntry()` / `finishResponseIntercept()` unpin). The TUI edits held entries in-place via `requests.editHeld()`, which classifies the entry's `Phase` (`request`, `request_held`, `response_held`, `response_done`). Starred entries (`*` key) set `pinned=true` via `toggleStar()` to survive ring buffer overflow; `starred` is a separate bool from `pinned` so unstarring doesn't interfere with intercept pins.
- **Replay**: Connects to the proxy's own TLS endpoint (127.0.0.1:443) so the request goes through the full proxy path and gets captured naturally.
- **Chunked encoding**: A state machine parser (`chunkedStep` in `http_wire.zig`, driven by `pumpChunked`) decodes chunks for body capture while forwarding raw chunked data to the client. Invalid hex digits transition to `.parse_error` state, and all forwarding loops check for this alongside `.done`.
- **Routing**: `--route=api=3001` (subdomain) and `--route=/api=3001` (path prefix). `resolveRoute()` in proxy.zig matches Host header for subdomains, longest prefix for paths, falls back to default port. Each entry stores `route_index` for TUI color-coding. Routes can target external hosts (`--route=api=staging.example.com:443`) — the `Route.hostname` field is set, and the proxy connects via outbound TLS with SNI, rewrites `Host` header to upstream, and rewrites `Set-Cookie Domain=` to the proxy domain.
- **Config file**: `.zlodev` in project directory, parsed by `readConfigFile()` in main.zig. One option per line (same keys as CLI). CLI args override config values. Only read for `start` command. Supports `intercept=PATTERN` for default intercept pattern and `command=SHELL_CMD` for dev server integration.
- **Intercept patterns**: `intercept.zig` stores a pattern (`pattern_buf`/`pattern_len` with `pattern_mutex`) and a `Phase` (`.both`, `.request`, `.response`). `shouldInterceptRequest`/`shouldInterceptResponse` do case-insensitive substring match against method, path, or combined "METHOD PATH". Empty pattern matches all. Prefix `req:` intercepts only requests, `resp:` only responses, no prefix = both. TUI prompts for pattern on `i` key. Config file can set a default pattern.
- **Response intercept**: When `shouldInterceptResponse` matches, the proxy buffers the entire response body (instead of streaming), stores it in the entry with `resp_intercepted=true`, pins, and waits. The TUI shows "RESP" in the status column. `e` opens the response editor (status, headers, body). On accept, `forwardResponseFromEntry` sends the (possibly edited) response with corrected `Content-Length`. `finishResponseIntercept` unpins without overwriting response data.
- **Sockets**: all networking goes through `compat.zig`, not `std.Io.net` — on Windows `std.Io.net` returns AFD handles that Winsock calls (`WSAPoll`, `recv`/`send`) and BoringSSL's `SSL_set_fd` reject. Sockets are created close-on-exec (`WSA_FLAG_NO_HANDLE_INHERIT` on Windows) so `--command` children don't inherit listeners. Winsock is started lazily on first socket. `SO_REUSEADDR` is set on POSIX only — on Windows it lets a second bind steal a taken port instead of failing with `AddressInUse`.
- **Windows**: `compat.SocketStream` wraps Winsock `recv`/`send`. `socketToFd`/`fdToSocket` handle SOCKET↔c_int conversion. TUI skips `queryTerminal` on Windows to avoid spurious key events. Subprocess puts `cmd.exe` in a kill-on-close job object (`win32.assignToKillJob`); stop calls `TerminateJobObject`, killing the whole tree with no graceful signal (falls back to `TerminateProcess` if job setup failed).
- **Dev server integration**: `subprocess.zig` spawns a shell command (`sh -c` on Unix, `cmd /c` on Windows), captures stdout/stderr into the log ring, strips ANSI escape sequences on ingest, and splits bytes on `\n` into fixed-length lines. Reader threads check `shutdown.isRunning()` to participate in graceful shutdown. TUI split-pane (60% requests, 40% logs) is toggled with `l` key; focus switches with `Tab`; autoscroll is per-pane via `s` key. On Unix the child spawns in its own process group (`pgid = 0`, stored as `child_pgid`); restart with `R` key sends SIGTERM to the group (3s grace) then SIGKILL — signalling the stored group even if the shell already exited, since its children may outlive it. On Windows it terminates the job.

## Code conventions

- Structured log format: `component=X op=Y field=value`
- Error handling: functions return `!void` or `!T`, errors are logged with context before propagating
- BoringSSL interop via translate-c modules — C types/functions accessed through `ssl_c.*` (proxy) or `c.*` (cert)
- TUI renders at 50ms intervals via `rt.sleepMs`, not event-driven
- HTTP header parsing lives in `http_wire.zig`; header name comparisons use `std.ascii.startsWithIgnoreCase` (no hand-rolled helpers)
- `isChunkedEncoding` (http_wire.zig) splits Transfer-Encoding by comma and checks each token (handles `gzip, chunked`)
- HTTP server sets `SO_RCVTIMEO` (5s) on accepted connections to prevent slow-client thread exhaustion
- HTTP server rejects paths containing `\r` or `\n` to prevent CRLF injection in redirects
- DNS server sets the AA (Authoritative Answer) flag and rejects compression pointers in queries
- `cert.zig` uses atomic write (temp file + rename) for git CA bundle modification
- `clipboard.zig` detects truncation during curl command building and skips clipboard copy if truncated

## Important notes

- `Entry` is ~69KB. Never pass by value to threads — heap-allocate with `page_allocator.create()` and let the callee `destroy()`.
- `sudoCmd` uses a switch on `Term` variants — the process may exit via signal, not just exit code.
- Log is muted before spawning server threads in TUI mode to prevent stderr leaking through the alt screen buffer.
- The `max_body_len` (32KB) and `max_header_len` (2KB) are compile-time constants in `requests.zig`.
- CLI flag `-c` is `--config`, not `--cert`. `-d` is removed — use `--dns` and `--cert` (no short forms).
- Subdomain routes are blocked in local mode (`-l`) since mDNS doesn't support arbitrary subdomains.
- `start --dns` cannot be combined with other start options (port, bind, routes, etc.).
- `--command` cannot be combined with `--dns` (no TUI to display logs) or `--no-tui` (no pane for output).
- Error messages use full flag names (`--dns` and `--cert`, not `-d` and `-c`).
- Proxy rejects intercepted requests with truncated bodies (413 status) rather than forwarding partial data.
- After `sslSendError`, always `return` (never `continue` in keep-alive loop) since the TLS state may be corrupted.
- `forwardResponseFromEntry` always emits `Content-Length`, even for zero-length bodies.
- TUI split-pane layout uses `win.child()` for clipping; requests pane is rendered into the child window with `draw_footer=false` to avoid footer-drawing in the middle of the split.
