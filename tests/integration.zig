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

fn startBackground(argv: []const []const u8) !std.process.Child {
    var child = std.process.Child.init(argv, testing.allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
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

const null_dev = if (builtin.os.tag == .windows) "NUL" else "/dev/null";

/// Poll a URL until it returns HTTP 200, or timeout.
/// Set insecure=true for HTTPS polling before trust store may be visible.
fn pollUrl(url: []const u8, timeout_ms: u64, insecure: bool) !void {
    const start = std.time.milliTimestamp();
    while (true) {
        const term = if (insecure)
            runCmd(&.{ "curl", "-sf", "--insecure", "--max-time", "2", "-o", null_dev, url })
        else
            runCmd(&.{ "curl", "-sf", "--max-time", "2", "-o", null_dev, url });
        if (term) |t| {
            if (std.meta.eql(t, std.process.Child.Term{ .Exited = 0 })) return;
        } else |_| {}
        const elapsed: u64 = @intCast(std.time.milliTimestamp() - start);
        if (elapsed > timeout_ms) return error.PollTimeout;
        std.Thread.sleep(200 * std.time.ns_per_ms);
    }
}

// --- Windows: minimal /health test ---

test "windows: health endpoint" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    // Install (force to handle leftover state from previous runs)
    try runCmdExpectSuccess(&.{ binary_path, "install", "-f" });
    defer {
        _ = runCmd(&.{ binary_path, "uninstall" }) catch {};
    }

    // Construct CA path for --cacert (Windows curl/Schannel may not see user cert store)
    var ca_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ca_path = blk: {
        const local_app_data = std.process.getEnvVarOwned(testing.allocator, "LocalAppData") catch return error.SkipZigTest;
        defer testing.allocator.free(local_app_data);
        break :blk std.fmt.bufPrint(&ca_buf, "{s}/zlodev/dev.lo/zlodevCA.pem", .{local_app_data}) catch return error.SkipZigTest;
    };

    // Start proxy (no upstream needed for /health)
    var proxy = try startBackground(&.{ binary_path, "start", "--no-tui" });
    defer killProcess(&proxy);

    // Poll for readiness
    try pollUrl("https://dev.lo/health", 30_000, true);

    // Test HTTPS /health (use --cacert to explicitly trust the CA)
    try runCmdExpectSuccess(&.{ "curl", "-sf", "--cacert", ca_path, "https://dev.lo/health" });

    // Test HTTP /health
    try runCmdExpectSuccess(&.{ "curl", "-sf", "http://dev.lo/health" });
}

// --- Local mode (mDNS) smoke test ---

test "local mode: mDNS smoke test" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    // Start httpbin on port 9000
    var httpbin = try startBackground(&.{ "gunicorn", "httpbin:app", "-b", "0.0.0.0:9000" });
    defer killProcess(&httpbin);
    try pollUrl("http://localhost:9000/get", 60_000, false);

    // Install --local (force to handle leftover state from previous runs)
    try runCmdExpectSuccess(&.{ binary_path, "install", "-l", "-f" });
    defer {
        _ = runCmd(&.{ binary_path, "uninstall", "-l" }) catch {};
    }

    // Start proxy
    var proxy = try startBackground(&.{ binary_path, "start", "--local", "--no-tui", "--port=9000" });
    defer killProcess(&proxy);

    // Build URL: hostname.local
    var hostname_buf: [hostname_max]u8 = undefined;
    const hostname = getHostname(&hostname_buf);
    var url_buf: [512]u8 = undefined;
    const health_url = std.fmt.bufPrint(&url_buf, "https://{s}.local/health", .{hostname}) catch return error.SkipZigTest;

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
    const get_url = std.fmt.bufPrint(&get_url_buf, "https://{s}.local/get", .{hostname}) catch return error.SkipZigTest;
    try runCmdExpectSuccess(&.{ "curl", "-sf", get_url });
}

// --- Default mode (dev.lo) full integration ---

test "dev.lo: full integration" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    // Start httpbin instances
    var httpbin1 = try startBackground(&.{ "gunicorn", "httpbin:app", "-b", "0.0.0.0:9000" });
    defer killProcess(&httpbin1);

    // Use sh -c to set SCRIPT_NAME while inheriting the full environment
    var httpbin2 = try startBackground(&.{ "sh", "-c", "SCRIPT_NAME=/api gunicorn httpbin:app -b 0.0.0.0:9001" });
    defer killProcess(&httpbin2);

    var httpbin3 = try startBackground(&.{ "gunicorn", "httpbin:app", "-b", "0.0.0.0:9002" });
    defer killProcess(&httpbin3);

    // Wait for all httpbin instances
    try pollUrl("http://localhost:9000/get", 60_000, false);
    try pollUrl("http://localhost:9001/api/get", 60_000, false);
    try pollUrl("http://localhost:9002/get", 60_000, false);

    // Install (force to handle leftover state from previous runs)
    try runCmdExpectSuccess(&.{ binary_path, "install", "-f" });
    defer {
        _ = runCmd(&.{ binary_path, "uninstall" }) catch {};
    }

    // Start proxy with routes
    var proxy = try startBackground(&.{
        binary_path,         "start",
        "--no-tui",          "--port=9000",
        "--route=/api=9001", "--route=api=9002",
        "--route=remote=httpbin.org:443",
    });
    defer killProcess(&proxy);

    // Flush systemd-resolved cache — install restarts resolved before the DNS
    // server is running, so it may cache the server as unreachable.
    if (builtin.os.tag == .linux) {
        _ = runCmd(&.{ "resolvectl", "flush-caches" }) catch {};
    }

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
