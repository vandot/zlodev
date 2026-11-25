//! cloudflared quick-tunnel process for `start --share`: preflight checks,
//! spawn, and stderr scraping for the public URL (published into share.zig).
const std = @import("std");
const builtin = @import("builtin");
const sep = std.fs.path.sep_str;
const log = @import("log.zig");
const rt = @import("rt.zig");
const shutdown = @import("shutdown.zig");
const share = @import("share.zig");
const child = @import("child.zig");
const subprocess = @import("subprocess.zig");

pub const PreflightError = error{ CloudflaredNotFound, CloudflaredConfigPresent };

const path_sep: u8 = if (builtin.os.tag == .windows) ';' else ':';
const exe_name = if (builtin.os.tag == .windows) "cloudflared.exe" else "cloudflared";

fn isFile(path: []const u8) bool {
    const st = std.Io.Dir.cwd().statFile(rt.io(), path, .{}) catch return false;
    return st.kind == .file;
}

/// First directory in `path_env` holding an existing file `name`.
pub fn findInPath(path_env: []const u8, name: []const u8, buf: []u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, path_env, path_sep);
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const p = std.fmt.bufPrint(buf, "{s}" ++ sep ++ "{s}", .{ dir, name }) catch continue;
        if (isFile(p)) return p;
    }
    return null;
}

// Mirrors cloudflared's config.DefaultConfigSearchDirectories.
const home_dirs = [_][]const u8{ ".cloudflared", ".cloudflare-warp", "cloudflare-warp" };
const posix_system_dirs = [_][]const u8{ "/etc/cloudflared", "/usr/local/etc/cloudflared" };
const config_names = [_][]const u8{ "config.yml", "config.yaml" };

fn findConfigFileIn(home: []const u8, system_dirs: []const []const u8, buf: []u8) ?[]const u8 {
    if (home.len > 0) {
        for (home_dirs) |d| {
            for (config_names) |n| {
                const p = std.fmt.bufPrint(buf, "{s}" ++ sep ++ "{s}" ++ sep ++ "{s}", .{ home, d, n }) catch continue;
                if (isFile(p)) return p;
            }
        }
    }
    for (system_dirs) |d| {
        for (config_names) |n| {
            const p = std.fmt.bufPrint(buf, "{s}" ++ sep ++ "{s}", .{ d, n }) catch continue;
            if (isFile(p)) return p;
        }
    }
    return null;
}

/// A cloudflared config file that makes `tunnel` use ingress rules instead of `--url`.
pub fn findConfigFile(home: []const u8, buf: []u8) ?[]const u8 {
    const sys_dirs: []const []const u8 = if (builtin.os.tag == .windows) &.{} else &posix_system_dirs;
    return findConfigFileIn(home, sys_dirs, buf);
}

pub fn installHint() []const u8 {
    return switch (builtin.os.tag) {
        .macos => "brew install cloudflared",
        .windows => "winget install --id Cloudflare.cloudflared",
        else => "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/",
    };
}

/// Locate cloudflared and refuse when a config file exists. Returns the path (in `buf`).
pub fn preflight(buf: []u8) PreflightError![]const u8 {
    const env = rt.env_map orelse return error.CloudflaredNotFound;
    const path_env = env.get("PATH") orelse return error.CloudflaredNotFound;
    const found = findInPath(path_env, exe_name, buf) orelse return error.CloudflaredNotFound;
    const home = env.get(if (builtin.os.tag == .windows) "USERPROFILE" else "HOME") orelse "";
    var cfg_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (findConfigFile(home, &cfg_buf)) |cfg| {
        log.info("component=tunnel op=preflight config={s}", .{cfg});
        return error.CloudflaredConfigPresent;
    }
    return found;
}

/// Where cloudflared should send traffic: the proxy's HTTPS listener.
pub fn targetAddr(bind: []const u8, buf: []u8) []const u8 {
    if (std.mem.eql(u8, bind, "0.0.0.0") or std.mem.startsWith(u8, bind, "127.")) return "127.0.0.1";
    if (std.mem.indexOfScalar(u8, bind, ':') != null) {
        return std.fmt.bufPrint(buf, "[{s}]", .{bind}) catch bind;
    }
    return bind;
}

var group: child.ChildGroup = .{};
var running = std.atomic.Value(bool).init(false);
var stopping = std.atomic.Value(bool).init(false);
var reader: ?std.Thread = null;

pub fn start(cloudflared_path: []const u8, target: []const u8) !void {
    var url_buf: [256]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://{s}:443", .{target});
    try startArgv(&.{ cloudflared_path, "tunnel", "--no-autoupdate", "--url", url, "--no-tls-verify" });
}

fn startArgv(argv: []const []const u8) !void {
    share.begin(rt.milliTimestamp());
    stopping.store(false, .release);
    try group.spawn(argv, .ignore, .pipe);
    errdefer {
        if (builtin.os.tag != .windows) std.posix.kill(-group.pgid, .KILL) catch {};
        group.release();
    }
    running.store(true, .release);
    errdefer running.store(false, .release);
    log.info("component=tunnel op=start argv0={s}", .{argv[0]});
    reader = try std.Thread.spawn(.{}, readerThread, .{group.child.?.stderr.?});
}

fn onLine(_: void, line: []const u8) void {
    log.info("component=tunnel op=output line={s}", .{line});
    if (share.extractQuickTunnelHost(line)) |host| {
        if (share.publishHost(host)) log.info("component=tunnel op=ready url=https://{s}", .{host});
    }
}

fn readerThread(pipe: std.Io.File) void {
    var ansi = subprocess.AnsiStripper{};
    var splitter = subprocess.LineSplitter{};
    var read_buf: [4096]u8 = undefined;
    var stripped_buf: [4096]u8 = undefined;

    while (shutdown.isRunning()) {
        const n = pipe.readStreaming(rt.io(), &.{&read_buf}) catch break;
        if (n == 0) break;
        var len: usize = 0;
        for (read_buf[0..n]) |byte| ansi.feed(byte, &stripped_buf, &len);
        splitter.feed(stripped_buf[0..len], {}, onLine);
    }
    splitter.flush({}, onLine);

    if (group.child) |*proc| {
        if (proc.wait(rt.io())) |term| {
            const code: i64 = switch (term) {
                .exited => |c| @as(i64, c),
                .signal, .stopped => |s| -@as(i64, @intFromEnum(s)),
                .unknown => -1,
            };
            log.info("component=tunnel op=exit code={d}", .{code});
            if (!stopping.load(.acquire) and shutdown.isRunning()) share.markExited(code);
        } else |err| {
            log.info("component=tunnel op=wait error={s}", .{@errorName(err)});
            if (!stopping.load(.acquire) and shutdown.isRunning()) share.markExited(-1);
        }
    }
    running.store(false, .release);
}

/// Stop cloudflared. Safe when never started or already exited.
pub fn stop() void {
    if (group.child == null) return;
    stopping.store(true, .release);
    group.terminate(3000, &running);
    if (reader) |t| t.join();
    reader = null;
    group.release();
}

fn waitStatus(want: share.Status, timeout_ms: i64) bool {
    const deadline = rt.milliTimestamp() + timeout_ms;
    while (rt.milliTimestamp() < deadline) {
        if (share.snapshot().status == want) return true;
        rt.sleepMs(20);
    }
    return share.snapshot().status == want;
}

fn makeFile(dir: std.Io.Dir, sub: []const u8) !void {
    const f = try dir.createFile(rt.io(), sub, .{});
    f.close(rt.io());
}

fn tmpPath(buf: []u8, tmp: *const std.testing.TmpDir) ![]const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache" ++ sep ++ "tmp" ++ sep ++ "{s}", .{&tmp.sub_path});
}

test "findInPath returns the first match" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeFile(tmp.dir, exe_name);
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpPath(&dir_buf, &tmp);
    var path_buf: [320]u8 = undefined;
    const path_env = try std.fmt.bufPrint(&path_buf, "/nonexistent-zlodev{c}{s}", .{ path_sep, dir });
    var buf: [512]u8 = undefined;
    const found = findInPath(path_env, exe_name, &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.endsWith(u8, found, exe_name));
    try std.testing.expect(findInPath("", exe_name, &buf) == null);
}

test "findConfigFile finds ~/.cloudflared/config.yml" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(rt.io(), ".cloudflared");
    try makeFile(tmp.dir, ".cloudflared" ++ sep ++ "config.yml");
    var home_buf: [256]u8 = undefined;
    const home = try tmpPath(&home_buf, &tmp);
    var buf: [512]u8 = undefined;
    const found = findConfigFileIn(home, &.{}, &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.endsWith(u8, found, "config.yml"));
}

test "findConfigFile null when absent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var home_buf: [256]u8 = undefined;
    const home = try tmpPath(&home_buf, &tmp);
    var buf: [512]u8 = undefined;
    try std.testing.expect(findConfigFileIn(home, &.{}, &buf) == null);
}

test "targetAddr" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("127.0.0.1", targetAddr("0.0.0.0", &buf));
    try std.testing.expectEqualStrings("127.0.0.1", targetAddr("127.0.0.5", &buf));
    try std.testing.expectEqualStrings("192.168.1.4", targetAddr("192.168.1.4", &buf));
    try std.testing.expectEqualStrings("[::1]", targetAddr("::1", &buf));
}

test "start publishes the URL from stderr" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    share.resetForTest();
    defer share.resetForTest();
    try startArgv(&.{ "/bin/sh", "-c", "echo '|  https://a-b.trycloudflare.com  |' >&2; sleep 30" });
    defer stop();
    try std.testing.expect(waitStatus(.ready, 2000));
    try std.testing.expectEqualStrings("a-b.trycloudflare.com", share.snapshot().getHost());
}

test "stop kills cloudflared before URL" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    share.resetForTest();
    defer share.resetForTest();
    try startArgv(&.{ "/bin/sh", "-c", "sleep 30" });
    const pgid = group.pgid;
    try std.testing.expect(share.snapshot().status == .starting);
    stop();
    try std.testing.expect(share.snapshot().status == .starting);
    const gone_by = rt.milliTimestamp() + 5000;
    while (true) {
        std.posix.kill(-pgid, @enumFromInt(0)) catch |e| switch (e) {
            error.ProcessNotFound => break,
            error.PermissionDenied => {}, // macOS zombies until reaped
            else => return e,
        };
        if (rt.milliTimestamp() > gone_by) return error.GroupStillAlive;
        rt.sleepMs(20);
    }
    stop(); // second stop is a no-op
}

test "exit is reported" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    share.resetForTest();
    defer share.resetForTest();
    try startArgv(&.{ "/bin/sh", "-c", "exit 3" });
    defer stop();
    try std.testing.expect(waitStatus(.exited, 3000));
    try std.testing.expect(std.mem.indexOf(u8, share.snapshot().getReason(), "code 3") != null);
}
