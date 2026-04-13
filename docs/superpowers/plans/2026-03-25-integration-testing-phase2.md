# Integration Testing Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add end-to-end integration tests using hurl + httpbin + curl, and implement a `/health` endpoint as a prerequisite.

**Architecture:** The `/health` endpoint is added to both `http_server.zig` (port 80) and `proxy.zig` (port 443) as an early return before any upstream logic. A Zig test orchestrator (`tests/integration.zig`) manages process lifecycle (httpbin, zlodev proxy), runs hurl test files and curl, and cleans up via `defer`. CI gets new integration-test jobs per platform.

**Tech Stack:** Zig 0.15.1, hurl, httpbin (Python/gunicorn), curl, GitHub Actions

**Spec:** `docs/superpowers/specs/2026-03-25-integration-testing-phase2-design.md`

---

### Task 1: Add /health endpoint to http_server.zig (port 80)

**Files:**
- Modify: `src/http_server.zig:116-139` (the path dispatch in `handleRequest`)

The `/health` endpoint on port 80 must return `200 OK` directly without redirecting to HTTPS. It goes before the catch-all HTTPS redirect.

- [ ] **Step 1: Write the failing test**

Create a test in `src/http_server.zig` or verify manually. Since `http_server.zig` has no existing tests and the function takes a `std.net.Stream`, we'll verify this via the integration test later. For now, implement the change.

- [ ] **Step 2: Add /health check to handleRequest**

In `src/http_server.zig`, in the `handleRequest` function, add a check for `/health` before the HTTPS redirect (line 129, the `else` block). Insert between the `/ca.pem` check and the `else`:

```zig
    } else if (std.mem.eql(u8, path, "/health")) {
        const health_response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        stream.writeAll(health_response) catch return;
```

The full dispatch chain becomes: `/ca` → `/ca.cer` → `/ca.pem` → `/health` → else (redirect).

- [ ] **Step 3: Verify it compiles**

Run: `zig build`
Expected: Clean build, no errors.

- [ ] **Step 4: Commit**

```bash
git add src/http_server.zig
git commit -m "add /health endpoint on port 80 (http_server)"
```

---

### Task 2: Add /health endpoint to proxy.zig (port 443)

**Files:**
- Modify: `src/proxy.zig:324-327` (after URI parsing, before route resolution)

The `/health` endpoint on port 443 must return 200 directly over SSL, bypassing route resolution, Entry construction, intercept matching, ring buffer logging, and upstream connection.

- [ ] **Step 1: Identify insertion point**

In `handleConnection` (line 274), after the request line is parsed and `uri` is available (line 324), but before the keep-alive/route/entry logic (line 329+).

- [ ] **Step 2: Add /health early return**

Insert after line 327 (`log.info` for the request), before line 329 (keep-alive check):

```zig
        // Health check — return immediately, bypass everything
        if (std.mem.eql(u8, uri, "/health")) {
            const health_response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            sslWriteAll(ssl, health_response);
            return;
        }
```

Note: This uses `return` (not `continue`) because it also sets `Connection: close`. This is intentional — health checks don't need keep-alive, and it simplifies the flow. The `defer` block in `handleConnection` handles SSL shutdown and stream close.

- [ ] **Step 3: Verify it compiles**

Run: `zig build`
Expected: Clean build, no errors.

- [ ] **Step 4: Run existing proxy unit tests**

Run: `zig test src/proxy.zig`
Expected: All existing tests pass (the health endpoint doesn't affect them).

- [ ] **Step 5: Commit**

```bash
git add src/proxy.zig
git commit -m "add /health endpoint on port 443 (proxy)"
```

---

### Task 3: Create hurl test files

**Files:**
- Create: `tests/hurl/proxy.hurl`
- Create: `tests/hurl/redirect.hurl`
- Create: `tests/hurl/path-routing.hurl`
- Create: `tests/hurl/subdomain-routing.hurl`
- Create: `tests/hurl/remote.hurl`

- [ ] **Step 1: Create tests/hurl/proxy.hurl**

```hurl
# Basic GET — httpbin echoes request info
GET https://dev.lo/get
HTTP 200
[Asserts]
jsonpath "$.url" exists

# POST with JSON body — httpbin echoes posted data
POST https://dev.lo/post
Content-Type: application/json
{"message": "hello from zlodev"}
HTTP 200
[Asserts]
jsonpath "$.json.message" == "hello from zlodev"

# Status code preservation
GET https://dev.lo/status/404
HTTP 404

# Response header forwarding
GET https://dev.lo/response-headers?X-Custom=hello
HTTP 200
[Asserts]
header "X-Custom" == "hello"

# Chunked transfer encoding
GET https://dev.lo/stream/5
HTTP 200
[Asserts]
body contains "url"
```

- [ ] **Step 2: Create tests/hurl/redirect.hurl**

```hurl
# HTTP to HTTPS redirect
GET http://dev.lo/get
HTTP 302
[Asserts]
header "Location" == "https://dev.lo/get"
```

- [ ] **Step 3: Create tests/hurl/path-routing.hurl**

```hurl
# Path route /api hits httpbin on port 9001 (SCRIPT_NAME=/api)
GET https://dev.lo/api/get
HTTP 200
[Asserts]
jsonpath "$.url" contains "/api/get"

# Non-matching path hits default upstream on port 9000
GET https://dev.lo/get
HTTP 200
[Asserts]
jsonpath "$.url" exists
```

- [ ] **Step 4: Create tests/hurl/subdomain-routing.hurl**

```hurl
# Subdomain route api.dev.lo hits httpbin on port 9002
GET https://api.dev.lo/get
HTTP 200
[Asserts]
jsonpath "$.url" exists
```

- [ ] **Step 5: Create tests/hurl/remote.hurl**

```hurl
# Remote endpoint routing to httpbin.org
GET https://remote.dev.lo/get
HTTP 200
[Asserts]
jsonpath "$.url" exists
```

- [ ] **Step 6: Commit**

```bash
git add tests/hurl/
git commit -m "add hurl integration test files"
```

---

### Task 4: Create the Zig integration test orchestrator

**Files:**
- Create: `tests/integration.zig`

This is the largest task. The file follows the pattern of `tests/install.zig` — using `std.process.Child` for process management and `std.testing` for assertions. All cleanup uses `defer`.

- [ ] **Step 1: Create tests/integration.zig with helper functions**

```zig
const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const binary_path = switch (builtin.os.tag) {
    .windows => "zig-out\\bin\\zlodev.exe",
    else => "zig-out/bin/zlodev",
};

const hostname_max = if (builtin.os.tag == .windows) 256 else std.posix.HOST_NAME_MAX;

fn runCmd(argv: []const []const u8) !std.process.Child.Term {
    var child = std.process.Child.init(argv, testing.allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    try child.spawn();
    return child.wait();
}

fn runCmdExpectSuccess(argv: []const []const u8) !void {
    const term = try runCmd(argv);
    try testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, term);
}

fn startBackground(argv: []const []const u8, env: ?*const std.process.EnvMap) !std.process.Child {
    var child = std.process.Child.init(argv, testing.allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    if (env) |e| child.env_map = e;
    try child.spawn();
    return child;
}

fn killProcess(child: *std.process.Child) void {
    _ = child.kill() catch {};
    _ = child.wait() catch {};
}

fn getHostname(buf: *[hostname_max]u8) []const u8 {
    if (builtin.os.tag == .windows) {
        const name = std.process.getEnvVarOwned(testing.allocator, "COMPUTERNAME") catch return "localhost";
        defer testing.allocator.free(name);
        const len = @min(name.len, buf.len);
        @memcpy(buf[0..len], name[0..len]);
        return buf[0..len];
    }
    const hostname = std.posix.gethostname(buf) catch return "unknown";
    if (std.mem.endsWith(u8, hostname, ".local")) {
        return hostname[0 .. hostname.len - 6];
    }
    return hostname;
}

/// Poll a URL until it returns HTTP 200, or timeout.
/// Uses curl with --insecure to skip cert verification during polling.
/// Poll a URL until it returns HTTP 200, or timeout.
/// Set insecure=true for HTTPS polling before trust store may be visible.
fn pollUrl(url: []const u8, timeout_ms: u64, insecure: bool) !void {
    const start = std.time.milliTimestamp();
    while (true) {
        const term = if (insecure)
            runCmd(&.{ "curl", "-sf", "--insecure", "--max-time", "2", "-o", "/dev/null", url })
        else
            runCmd(&.{ "curl", "-sf", "--max-time", "2", "-o", "/dev/null", url });
        if (term) |t| {
            if (std.meta.eql(t, std.process.Child.Term{ .Exited = 0 })) return;
        } else |_| {}
        const elapsed: u64 = @intCast(std.time.milliTimestamp() - start);
        if (elapsed > timeout_ms) return error.PollTimeout;
        std.Thread.sleep(200 * std.time.ns_per_ms);
    }
}
```

- [ ] **Step 2: Add Windows-only /health test**

```zig
test "windows: health endpoint" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    // Install
    try runCmdExpectSuccess(&.{ binary_path, "install" });
    defer { _ = runCmd(&.{ binary_path, "uninstall" }) catch {}; }

    // Start proxy (no upstream needed for /health)
    var proxy = try startBackground(&.{ binary_path, "start", "--no-tui" }, null);
    defer killProcess(&proxy);

    // Poll for readiness
    try pollUrl("https://dev.lo/health", 30_000, true);

    // Test HTTPS /health
    try runCmdExpectSuccess(&.{ "curl", "-sf", "https://dev.lo/health" });

    // Test HTTP /health
    try runCmdExpectSuccess(&.{ "curl", "-sf", "http://dev.lo/health" });
}
```

- [ ] **Step 3: Add local mode (mDNS) smoke test**

```zig
test "local mode: mDNS smoke test" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    // Start httpbin on port 9000
    var httpbin = try startBackground(&.{ "gunicorn", "httpbin:app", "-b", "0.0.0.0:9000" }, null);
    defer killProcess(&httpbin);
    try pollUrl("http://localhost:9000/get", 60_000, false);

    // Install --local
    try runCmdExpectSuccess(&.{ binary_path, "install", "-l" });
    defer { _ = runCmd(&.{ binary_path, "uninstall", "-l" }) catch {}; }

    // Start proxy
    var proxy = try startBackground(&.{ binary_path, "start", "--local", "--no-tui", "--port=9000" }, null);
    defer killProcess(&proxy);

    // Build URL: hostname.local
    var hostname_buf: [hostname_max]u8 = undefined;
    const hostname = getHostname(&hostname_buf);
    var url_buf: [512]u8 = undefined;
    const health_url = try std.fmt.bufPrint(&url_buf, "https://{s}.local/health", .{hostname});

    // Poll — if mDNS doesn't work (Linux CI), skip gracefully
    pollUrl(health_url, 30_000, true) catch |e| {
        if (e == error.PollTimeout) {
            std.debug.print("mDNS not available, skipping local mode test\n", .{});
            return;
        }
        return e;
    };

    // Smoke test
    var get_url_buf: [512]u8 = undefined;
    const get_url = try std.fmt.bufPrint(&get_url_buf, "https://{s}.local/get", .{hostname});
    try runCmdExpectSuccess(&.{ "curl", "-sf", get_url });
}
```

- [ ] **Step 4: Add default mode (dev.lo) integration test**

```zig
test "dev.lo: full integration" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    // Start httpbin instances
    var httpbin1 = try startBackground(&.{ "gunicorn", "httpbin:app", "-b", "0.0.0.0:9000" }, null);
    defer killProcess(&httpbin1);

    // Use sh -c to set SCRIPT_NAME while inheriting the full environment
    var httpbin2 = try startBackground(&.{ "sh", "-c", "SCRIPT_NAME=/api gunicorn httpbin:app -b 0.0.0.0:9001" }, null);
    defer killProcess(&httpbin2);

    var httpbin3 = try startBackground(&.{ "gunicorn", "httpbin:app", "-b", "0.0.0.0:9002" }, null);
    defer killProcess(&httpbin3);

    // Wait for all httpbin instances
    try pollUrl("http://localhost:9000/get", 60_000, false);
    try pollUrl("http://localhost:9001/api/get", 60_000, false);
    try pollUrl("http://localhost:9002/get", 60_000, false);

    // Install
    try runCmdExpectSuccess(&.{ binary_path, "install" });
    defer { _ = runCmd(&.{ binary_path, "uninstall" }) catch {}; }

    // Start proxy with routes
    var proxy = try startBackground(&.{
        binary_path,          "start",
        "--no-tui",           "--port=9000",
        "--route=/api=9001",  "--route=api=9002",
        "--route=remote=httpbin.org:443",
    }, null);
    defer killProcess(&proxy);

    // Poll for proxy readiness
    try pollUrl("https://dev.lo/health", 30_000, true);

    // Run hurl test files
    try runCmdExpectSuccess(&.{ "hurl", "--test", "tests/hurl/proxy.hurl" });
    try runCmdExpectSuccess(&.{ "hurl", "--test", "tests/hurl/redirect.hurl" });
    try runCmdExpectSuccess(&.{ "hurl", "--test", "tests/hurl/path-routing.hurl" });
    try runCmdExpectSuccess(&.{ "hurl", "--test", "tests/hurl/subdomain-routing.hurl" });

    // Remote test — allowed to fail (httpbin.org may be down)
    const remote_term = try runCmd(&.{ "hurl", "--test", "tests/hurl/remote.hurl" });
    if (!std.meta.eql(remote_term, std.process.Child.Term{ .Exited = 0 })) {
        std.debug.print("WARNING: remote.hurl failed (httpbin.org may be unreachable), continuing\n", .{});
    }

    // Curl DNS verification — no --resolve, no --cacert
    try runCmdExpectSuccess(&.{ "curl", "-sf", "https://dev.lo/get" });
}
```

- [ ] **Step 5: Verify it compiles**

Run: `zig build`
Then: `zig test tests/integration.zig --help` (just check it parses)
Expected: No compile errors.

- [ ] **Step 6: Commit**

```bash
git add tests/integration.zig
git commit -m "add integration test orchestrator"
```

---

### Task 5: Update CI workflow

**Files:**
- Modify: `.github/workflows/ci.yml`

Add three new jobs: `integration-test-linux`, `integration-test-macos`, `integration-test-windows`.

- [ ] **Step 1: Add integration-test-linux job**

Append to `.github/workflows/ci.yml`:

```yaml
  integration-test-linux:
    needs: build-and-test-linux
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Zig
        uses: mlugg/setup-zig@v2
        with:
          version: 0.15.1

      - name: Build
        run: zig build

      - name: Install hurl
        run: |
          curl -sSL https://github.com/Orange-OpenSource/hurl/releases/download/6.0.0/hurl_6.0.0_amd64.deb -o /tmp/hurl.deb
          sudo dpkg -i /tmp/hurl.deb

      - name: Install httpbin
        run: |
          python3 -m venv .venv
          .venv/bin/pip install httpbin==0.10.2 gunicorn==23.0.0

      - name: Setup capabilities
        run: |
          sudo apt-get install -y libcap2-bin
          sudo setcap 'cap_net_bind_service=+ep' ./zig-out/bin/zlodev

      - name: Run integration tests
        timeout-minutes: 10
        run: |
          export PATH="$(pwd)/.venv/bin:$PATH"
          zig test tests/integration.zig
```

- [ ] **Step 2: Add integration-test-macos job**

```yaml
  integration-test-macos:
    needs: build-and-test-macos
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set HostName to match LocalHostName
        run: sudo scutil --set HostName "$(scutil --get LocalHostName)"

      - name: Install Zig
        uses: mlugg/setup-zig@v2
        with:
          version: 0.15.1

      - name: Build
        run: zig build

      - name: Install hurl
        run: brew install hurl

      - name: Install httpbin
        run: |
          python3 -m venv .venv
          .venv/bin/pip install httpbin==0.10.2 gunicorn==23.0.0

      - name: Run integration tests
        timeout-minutes: 10
        run: |
          export PATH="$(pwd)/.venv/bin:$PATH"
          zig test tests/integration.zig
```

- [ ] **Step 3: Add integration-test-windows job**

```yaml
  integration-test-windows:
    needs: build-and-test-windows
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Zig
        uses: mlugg/setup-zig@v2
        with:
          version: 0.15.1

      - name: Build
        run: zig build

      - name: Run integration tests
        timeout-minutes: 10
        run: zig test tests/integration.zig
```

- [ ] **Step 4: Add .github/workflows/ to CI trigger paths**

Add `'.github/workflows/**'` to the `paths` list for both `push` and `pull_request` triggers so CI changes themselves trigger a run:

```yaml
on:
  push:
    branches:
      - main
    paths:
      - 'src/**'
      - 'build.zig'
      - 'build.zig.zon'
      - 'tests/**'
      - '.github/workflows/**'
  pull_request:
    paths:
      - 'src/**'
      - 'build.zig'
      - 'build.zig.zon'
      - 'tests/**'
      - '.github/workflows/**'
```

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "add integration test jobs to CI workflow"
```

---

### Task 6: Local verification and cleanup

- [ ] **Step 1: Run full local test (macOS)**

If on macOS with hurl and httpbin installed:

```bash
zig build && zig test tests/integration.zig
```

Expected: All non-skipped tests pass. The local mode test runs the mDNS smoke test. The dev.lo test runs all hurl files and curl.

- [ ] **Step 2: Verify hurl files work standalone**

With zlodev running manually (`zlodev start --no-tui --port=9000`):

```bash
hurl --test tests/hurl/proxy.hurl
hurl --test tests/hurl/redirect.hurl
```

Expected: Tests pass.

- [ ] **Step 3: Final commit with any fixups**

```bash
git add -A
git commit -m "fix: integration test adjustments from local verification"
```
