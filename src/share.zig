const std = @import("std");
const rt = @import("rt.zig");
const testing = std.testing;

pub const Status = enum(u8) { off, starting, ready, failed, exited };

pub const max_host_len = 128;
pub const max_reason_len = 192;

const start_timeout_ms: i64 = 30_000;
const tunnel_suffix = ".trycloudflare.com";

pub const Snapshot = struct {
    status: Status,
    host: [max_host_len]u8,
    host_len: u8,
    reason: [max_reason_len]u8,
    reason_len: u8,

    pub fn getHost(self: *const Snapshot) []const u8 {
        return self.host[0..self.host_len];
    }

    pub fn getReason(self: *const Snapshot) []const u8 {
        return self.reason[0..self.reason_len];
    }
};

var mutex: std.Io.Mutex = .init;
var state: Snapshot = .{
    .status = .off,
    .host = undefined,
    .host_len = 0,
    .reason = undefined,
    .reason_len = 0,
};
var start_ms: i64 = 0;
// Set (release) once host bytes are final; they are never written again until
// resetForTest, so readers that acquire-load it may read them without the mutex.
var host_published = std.atomic.Value(bool).init(false);

fn setReason(msg: []const u8) void {
    const n = @min(msg.len, max_reason_len);
    @memcpy(state.reason[0..n], msg[0..n]);
    state.reason_len = @intCast(n);
}

pub fn begin(now_ms: i64) void {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    state.status = .starting;
    state.host_len = 0;
    state.reason_len = 0;
    start_ms = now_ms;
    host_published.store(false, .release);
}

pub fn publishHost(host: []const u8) void {
    if (host.len == 0 or host.len > max_host_len) return;
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    if (host_published.load(.monotonic)) return;
    if (state.status != .starting and state.status != .failed) return;
    @memcpy(state.host[0..host.len], host);
    state.host_len = @intCast(host.len);
    state.reason_len = 0;
    state.status = .ready;
    host_published.store(true, .release);
}

pub fn fail(reason: []const u8) void {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    if (state.status == .ready or state.status == .exited) return;
    state.status = .failed;
    setReason(reason);
}

pub fn markExited(code: i64) void {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    state.status = .exited;
    var buf: [max_reason_len]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "cloudflared exited (code {d}) \u{2014} see zlodev.log", .{code}) catch "cloudflared exited \u{2014} see zlodev.log";
    setReason(msg);
}

pub fn checkTimeout(now_ms: i64) void {
    mutex.lockUncancelable(rt.io());
    const timed_out = state.status == .starting and now_ms - start_ms >= start_timeout_ms;
    mutex.unlock(rt.io());
    if (timed_out) fail("no URL from cloudflared after 30s \u{2014} see zlodev.log");
}

pub fn snapshot() Snapshot {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    return state;
}

pub fn publicHost() ?[]const u8 {
    if (!host_published.load(.acquire)) return null;
    return state.host[0..state.host_len];
}

pub fn isPublicHost(host_header: []const u8) bool {
    const h = publicHost() orelse return false;
    return hostMatches(host_header, h);
}

pub fn resetForTest() void {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    state.status = .off;
    state.host_len = 0;
    state.reason_len = 0;
    start_ms = 0;
    host_published.store(false, .release);
}

/// Strips an optional `:port` from `header_host` and compares case-insensitively.
pub fn hostMatches(header_host: []const u8, public: []const u8) bool {
    if (public.len == 0) return false;
    const h = if (std.mem.lastIndexOfScalar(u8, header_host, ':')) |i| header_host[0..i] else header_host;
    return std.ascii.eqlIgnoreCase(h, public);
}

fn isHostChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '.';
}

/// Finds `https://<label>.trycloudflare.com` in a cloudflared log line and
/// returns the host. Rejects look-alike domains and extra labels.
pub fn extractQuickTunnelHost(line: []const u8) ?[]const u8 {
    const scheme = "https://";
    const at = std.mem.indexOf(u8, line, scheme) orelse return null;
    const start = at + scheme.len;
    var end = start;
    while (end < line.len and isHostChar(line[end])) end += 1;
    if (end < line.len) {
        const c = line[end];
        if (c != '/' and c != '|' and !std.ascii.isWhitespace(c)) return null;
    }
    const host = line[start..end];
    if (host.len <= tunnel_suffix.len or host.len > max_host_len) return null;
    const label_len = host.len - tunnel_suffix.len;
    if (!std.ascii.eqlIgnoreCase(host[label_len..], tunnel_suffix)) return null;
    for (host[0..label_len]) |c| {
        if (c == '.') return null;
    }
    return host;
}

test "extractQuickTunnelHost finds the URL in cloudflared's banner" {
    const line = "2026-11-25T10:00:00Z INF |  https://quiet-river-fox.trycloudflare.com                                     |";
    try testing.expectEqualStrings("quiet-river-fox.trycloudflare.com", extractQuickTunnelHost(line).?);
}
test "extractQuickTunnelHost ignores lines without a tunnel URL" {
    try testing.expect(extractQuickTunnelHost("INF Requesting new quick Tunnel on trycloudflare.com...") == null);
    try testing.expect(extractQuickTunnelHost("") == null);
}
test "extractQuickTunnelHost rejects look-alikes" {
    try testing.expect(extractQuickTunnelHost("https://x.trycloudflare.com.evil.io/") == null);
    try testing.expect(extractQuickTunnelHost("https://trycloudflare.com") == null);
    try testing.expect(extractQuickTunnelHost("https://a_b.trycloudflare.com") == null);
}
test "hostMatches strips port and ignores case" {
    try testing.expect(hostMatches("Quiet-River-Fox.TryCloudflare.com:443", "quiet-river-fox.trycloudflare.com"));
    try testing.expect(!hostMatches("dev.lo", "quiet-river-fox.trycloudflare.com"));
    try testing.expect(!hostMatches("", "quiet-river-fox.trycloudflare.com"));
}
test "state: begin, publish, first host wins" {
    resetForTest();
    begin(0);
    try testing.expectEqual(Status.starting, snapshot().status);
    try testing.expect(!isPublicHost("a.trycloudflare.com"));
    publishHost("a.trycloudflare.com");
    publishHost("b.trycloudflare.com");
    try testing.expectEqualStrings("a.trycloudflare.com", snapshot().getHost());
    try testing.expect(isPublicHost("A.trycloudflare.com:443"));
}
test "state: timeout fails, late URL recovers" {
    resetForTest();
    begin(1000);
    checkTimeout(30_999);
    try testing.expectEqual(Status.starting, snapshot().status);
    checkTimeout(31_000);
    try testing.expectEqual(Status.failed, snapshot().status);
    publishHost("a.trycloudflare.com");
    try testing.expectEqual(Status.ready, snapshot().status);
}
test "state: exit reports code" {
    resetForTest();
    begin(0);
    markExited(1);
    const s = snapshot();
    try testing.expectEqual(Status.exited, s.status);
    try testing.expect(std.mem.indexOf(u8, s.getReason(), "code 1") != null);
}
