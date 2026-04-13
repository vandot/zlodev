# Integration Testing Phase 2 Design

## Overview

End-to-end integration tests for zlodev using hurl as the test engine, httpbin as the upstream mock server, and curl for DNS verification. Tests run on macOS, Linux, and Windows (minimal) in CI.

## Prerequisites

### /health endpoint

A new `GET /health` endpoint on both port 80 (http_server.zig) and port 443 (proxy.zig):

- Returns `200 OK` with `Content-Type: text/plain` and body `ok`
- On port 80: returns 200 directly (does NOT redirect to HTTPS like other paths)
- On port 443: checked after request line parsing but before Entry construction, intercept matching, and upstream connection in `handleConnection`
- Must bypass intercept pattern matching (prevents deadlock when intercept pattern matches all)
- Must not be logged to the ring buffer (avoids polluting captured entries)
- Available in all modes (TUI, `--no-tui`, `--local`)
- Used by test harness to poll for startup readiness

### Dependencies

- **httpbin** (macOS/Linux): Installed via `pip install httpbin gunicorn` inside a virtualenv. Pin versions for reproducibility.
- **hurl** (macOS/Linux): Installed via `brew install hurl` on macOS, pinned binary download on Linux.
- **curl**: Pre-installed on all CI runners (macOS, Linux, Windows).
- **libcap2-bin** (Linux): `sudo apt-get install -y libcap2-bin` for `setcap`.

## CI Pipeline Flow

Integration tests run as new jobs that depend on existing build-and-test jobs (unit tests must pass first). The CI workflow installs dependencies, then the Zig test file (`tests/integration.zig`) orchestrates everything else -- process lifecycle, hurl invocation, curl checks, and cleanup via `defer`.

```
build-and-test-{platform}  ->  integration-test-{platform}
```

### macOS / Linux Sequence

CI steps:
1. Build zlodev
2. Install hurl, create virtualenv, pip install httpbin + gunicorn
3. Linux only: `sudo apt-get install -y libcap2-bin && sudo setcap 'cap_net_bind_service=+ep' ./zig-out/bin/zlodev`
4. Run `zig test tests/integration.zig`

The Zig test file executes:

```
1.  Start httpbin on port 9000: gunicorn httpbin:app -b 0.0.0.0:9000
2.  Poll http://localhost:9000/get every 200ms, timeout 60s

--- Local mode (mDNS) ---

3.  zlodev install --local
4.  Start proxy: zlodev start --local --no-tui --port=9000
5.  Poll https://$(hostname).local/health every 200ms, timeout 30s
6.  Curl smoke test: curl https://$(hostname).local/get (verify 200)
7.  Stop proxy (SIGTERM via child.kill())
8.  zlodev uninstall --local
    (Skip steps 3-8 gracefully on Linux if mDNS unavailable)

--- Default mode (dev.lo) ---

9.  zlodev install
10. Start second httpbin on port 9001: SCRIPT_NAME=/api gunicorn httpbin:app -b 0.0.0.0:9001
11. Start third httpbin on port 9002: gunicorn httpbin:app -b 0.0.0.0:9002
12. Poll http://localhost:9001/api/get every 200ms, timeout 60s
13. Poll http://localhost:9002/get every 200ms, timeout 60s
14. Start proxy: zlodev start --no-tui --port=9000 \
      --route=/api=9001 --route=api=9002 \
      --route=remote=httpbin.org:443
15. Poll https://dev.lo/health every 200ms, timeout 30s
16. Run hurl tests (5 files in tests/hurl/)
17. Curl test: curl https://dev.lo/get (no --resolve, no --cacert)
18. Stop proxy (SIGTERM via child.kill()) + httpbin instances
19. zlodev uninstall
```

All cleanup (kill processes, uninstall) uses `defer` in Zig to guarantee execution on test failure.

### Windows Sequence

Minimal integration -- no httpbin, no hurl. Only curl against `/health`. gunicorn is Unix-only, so httpbin cannot run on Windows.

```
1. Build zlodev
2. zlodev install
3. Start proxy: zlodev start --no-tui (no upstream needed)
4. Poll https://dev.lo/health every 200ms, timeout 30s
5. curl https://dev.lo/health -> 200, body "ok" (proves TLS + DNS + trust store)
6. curl http://dev.lo/health -> 200 (proves port 80 works)
7. Stop proxy via child.kill() (TerminateProcess -- hard kill; graceful shutdown not tested on Windows)
8. zlodev uninstall
```

## httpbin Instances

Three httpbin instances serve different roles:

| Port | SCRIPT_NAME | Purpose | Routes to |
|------|-------------|---------|-----------|
| 9000 | (none) | Default upstream | `--port=9000` |
| 9001 | `/api` | Path routing upstream | `--route=/api=9001` |
| 9002 | (none) | Subdomain routing upstream | `--route=api=9002` |

Path routing forwards the full URI unchanged (e.g., `GET /api/get` -> upstream receives `GET /api/get`), so the path-routed httpbin needs `SCRIPT_NAME=/api` to handle the prefix. Subdomain routing forwards the URI as-is without a prefix (e.g., `GET /get`), so it needs a plain httpbin.

## Hurl Test Files

All files live in `tests/hurl/`. Each file targets one feature area. Hurl output (stdout/stderr) is inherited by the Zig test runner so it appears in CI logs on failure.

### proxy.hurl -- Basic proxy functionality

- `GET https://dev.lo/get` -> 200, body contains httpbin echo JSON
- `POST https://dev.lo/post` with JSON body -> 200, response echoes posted data
- `GET https://dev.lo/status/404` -> 404 (proxy preserves upstream status codes)
- `GET https://dev.lo/response-headers?X-Custom=hello` -> response has `X-Custom: hello`
- `GET https://dev.lo/stream/5` -> 200, body is non-empty (chunked transfer encoding)

### redirect.hurl -- HTTP to HTTPS redirect

- `GET http://dev.lo/get` -> 302, `Location` header contains `https://dev.lo/get`

### path-routing.hurl -- Path-based routing

- `GET https://dev.lo/api/get` -> 200, hits httpbin on port 9001 (SCRIPT_NAME=/api)
- `GET https://dev.lo/other` -> 200, hits default upstream on port 9000

### subdomain-routing.hurl -- Subdomain-based routing

- `GET https://api.dev.lo/get` -> 200, hits httpbin on port 9002

### remote.hurl -- External endpoint routing

- `GET https://remote.dev.lo/get` -> 200, response contains httpbin.org JSON
- Run as separate hurl invocation; exit code ignored if httpbin.org is unreachable

## Test Orchestration

The Zig test file (`tests/integration.zig`) handles:

- Starting/stopping httpbin instances (via `std.process.Child`)
- Starting/stopping zlodev proxy (SIGTERM via `child.kill()` on POSIX, TerminateProcess on Windows)
- Running `zlodev install`/`uninstall` commands
- Polling `/health` for proxy readiness (every 200ms, timeout 30s)
- Polling httpbin directly for upstream readiness (every 200ms, timeout 60s)
- Invoking hurl with the test files (stdout/stderr inherited for CI logs)
- Running the curl DNS verification
- Cleanup on failure via `defer` (kill processes, uninstall)

This follows the same pattern as `tests/install.zig` -- Zig manages process lifecycle, external tools (hurl, curl) perform the actual HTTP testing. The CI workflow only installs dependencies and runs `zig test tests/integration.zig`.

## What is NOT tested

- **WebSocket**: Hurl doesn't support WebSocket natively. Deferred to Phase 3.
- **HAR export**: TUI-only feature. Requires Phase 3 tmux-based tests.
- **Intercept**: Requires TUI interaction. Deferred to Phase 3.
- **install -f**: Already covered by `tests/install.zig`, not repeated here.

## CI Matrix

```yaml
integration-test:
  needs: [build-and-test-linux, build-and-test-macos, build-and-test-windows]
  strategy:
    matrix:
      include:
        - os: ubuntu-latest    # full: hurl + httpbin + curl
        - os: macos-latest     # full: hurl + httpbin + curl
        - os: windows-latest   # minimal: curl /health only
```
