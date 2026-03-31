# CLAUDE.md

## Project overview

zlodev is a local reverse proxy with TLS termination, custom DNS, and a terminal UI. It sits between the browser and a local dev server, providing HTTPS with auto-generated certificates at `https://dev.lo`, and a TUI for inspecting/intercepting/replaying HTTP traffic. The domain is hardcoded to `dev.lo` — no custom domains or TLDs.

Written in Zig 0.15.1, uses BoringSSL (compiled from source) for TLS and libvaxis for the terminal UI.

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

There is no `zig build test` step — tests are run per-file with `zig test src/<file>.zig`.

## Architecture

```
main.zig          CLI parsing, config file loading, command dispatch, thread orchestration
proxy.zig         HTTPS reverse proxy (TLS termination, upstream forwarding, replay, route resolution)
tui.zig           Terminal UI (vaxis-based, list/detail/edit views, route colors)
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

- **Thread model**: proxy uses a 64-thread pool (256KB stacks), HTTP server uses 8 threads, DNS is single-threaded. All loops use `poll()` with 1s timeout + `shutdown.isRunning()` check.
- **Ring buffer**: `requests.zig` stores entries in a fixed-size ring (`max_entries`, default 500). Entries are ~69KB each (fixed-size arrays for headers/body). Pinned entries (intercepted, WebSocket, starred) are skipped during overwrite. `copyEntry()` provides mutex-protected entry copies for TUI replay. `lock()`/`unlock()` expose the mutex for external callers (e.g. TUI edits). `clearAll()` calls `intercept.dropAll()` and waits for pending entries to drain.
- **TLS**: BoringSSL via `@cImport` (API-compatible with OpenSSL). `SSL_set_fd` uses `BIO_NOCLOSE` — the caller must close the socket after `SSL_free`.
- **Entry lifecycle**: Normal requests use `push()`. Intercepted requests use `pushAndPin()` → `finishEntry()` (which unpins). The TUI can edit pinned entries in-place before accepting. Starred entries (`*` key) set `pinned=true` via `toggleStar()` to survive ring buffer overflow; `starred` is a separate bool from `pinned` so unstarring doesn't interfere with intercept pins.
- **Replay**: Connects to the proxy's own TLS endpoint (127.0.0.1:443) so the request goes through the full proxy path and gets captured naturally.
- **Chunked encoding**: A state machine parser (`chunkedStep`) decodes chunks for body capture while forwarding raw chunked data to the client. Invalid hex digits transition to `.parse_error` state, and all forwarding loops check for this alongside `.done`.
- **Routing**: `--route=api=3001` (subdomain) and `--route=/api=3001` (path prefix). `resolveRoute()` in proxy.zig matches Host header for subdomains, longest prefix for paths, falls back to default port. Each entry stores `route_index` for TUI color-coding. Routes can target external hosts (`--route=api=staging.example.com:443`) — the `Route.hostname` field is set, and the proxy connects via outbound TLS with SNI, rewrites `Host` header to upstream, and rewrites `Set-Cookie Domain=` to the proxy domain.
- **Config file**: `.zlodev` in project directory, parsed by `readConfigFile()` in main.zig. One option per line (same keys as CLI). CLI args override config values. Only read for `start` command. Supports `intercept=PATTERN` for default intercept pattern.
- **Intercept patterns**: `intercept.zig` stores a pattern (`pattern_buf`/`pattern_len` with `pattern_mutex`) and a `Phase` (`.both`, `.request`, `.response`). `shouldInterceptRequest`/`shouldInterceptResponse` do case-insensitive substring match against method, path, or combined "METHOD PATH". Empty pattern matches all. Prefix `req:` intercepts only requests, `resp:` only responses, no prefix = both. TUI prompts for pattern on `i` key. Config file can set a default pattern.
- **Response intercept**: When `shouldInterceptResponse` matches, the proxy buffers the entire response body (instead of streaming), stores it in the entry with `resp_intercepted=true`, pins, and waits. The TUI shows "RESP" in the status column. `e` opens the response editor (status, headers, body). On accept, `forwardResponseFromEntry` sends the (possibly edited) response with corrected `Content-Length`. `finishResponseIntercept` unpins without overwriting response data.
- **Windows**: `compat.SocketStream` wraps Winsock `recv`/`send` (std.net.Stream uses ReadFile which doesn't work with sockets on Windows). `socketToFd`/`fdToSocket` handle SOCKET↔c_int conversion. TUI skips `queryTerminal` on Windows to avoid spurious key events.

## Code conventions

- Structured log format: `component=X op=Y field=value`
- Error handling: functions return `!void` or `!T`, errors are logged with context before propagating
- BoringSSL interop via `@cImport` — C types/functions accessed through `ssl_c.*` (proxy) or `c.*` (cert)
- TUI renders at 50ms intervals via `std.Thread.sleep`, not event-driven
- All string comparisons for HTTP headers use `startsWithIgnoreCase` (defined locally in proxy.zig and http_server.zig)
- `isChunkedEncoding` splits Transfer-Encoding by comma and checks each token (handles `gzip, chunked`)
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
- Error messages use full flag names (`--dns` and `--cert`, not `-d` and `-c`).
- Proxy rejects intercepted requests with truncated bodies (413 status) rather than forwarding partial data.
- After `sslSendError`, always `return` (never `continue` in keep-alive loop) since the TLS state may be corrupted.
- `forwardResponseFromEntry` always emits `Content-Length`, even for zero-length bodies.
