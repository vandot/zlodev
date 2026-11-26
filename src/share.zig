const std = @import("std");
const rt = @import("rt.zig");
const testing = std.testing;

pub const Status = enum(u8) { off, starting, verifying, ready, failed, exited };

pub const max_host_len = 128;
pub const max_reason_len = 192;

const start_timeout_ms: i64 = 30_000;
const verify_timeout_ms: i64 = 60_000;
/// Probe this long after the URL appears even if cloudflared never logged its
/// registered connection (its wording may change).
const probe_fallback_ms: i64 = 5_000;
const max_hint_len = 64;
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

    /// The URL was never verified within the deadline: shown and copyable only as
    /// unverified, next to the failure reason.
    pub fn hasUnverifiedUrl(self: *const Snapshot) bool {
        return self.status == .failed and self.host_len > 0;
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
var verify_start_ms: i64 = 0;
// Last probe outcome in words, for the verify-timeout reason (mutex).
var probe_hint: [max_hint_len]u8 = undefined;
var probe_hint_len: usize = 0;
// The end-to-end check can't run: publishHost goes straight to ready (mutex).
var verify_skipped = false;
// cloudflared reported a registered tunnel connection.
var connected = std.atomic.Value(bool).init(false);
// Set (release) once host bytes are final; they are never written again until
// begin/resetForTest, so readers that acquire-load it may read them without the mutex.
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
    probe_hint_len = 0;
    verify_skipped = false;
    host_published.store(false, .release);
    connected.store(false, .release);
}

/// Returns true when the host took effect (first host wins). Moves to `verifying`;
/// the URL is shown only after `markVerified`.
pub fn publishHost(host: []const u8) bool {
    return publishHostAt(host, rt.milliTimestamp());
}

fn publishHostAt(host: []const u8, now_ms: i64) bool {
    if (host.len == 0 or host.len > max_host_len) return false;
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    if (host_published.load(.monotonic)) return false;
    if (state.status != .starting and state.status != .failed) return false;
    @memcpy(state.host[0..host.len], host);
    state.host_len = @intCast(host.len);
    state.reason_len = 0;
    state.status = if (verify_skipped) .ready else .verifying;
    verify_start_ms = now_ms;
    host_published.store(true, .release);
    return true;
}

/// The URL passed the end-to-end check. True when this moved the state to ready.
pub fn markVerified() bool {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    if (state.status != .verifying and state.status != .failed) return false;
    if (!host_published.load(.monotonic)) return false;
    state.status = .ready;
    state.reason_len = 0;
    return true;
}

/// The check can't run (its thread failed to start): show the URL unverified as
/// soon as it appears, or right away if it already has.
pub fn skipVerification() void {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    verify_skipped = true;
    if (host_published.load(.monotonic) and (state.status == .verifying or state.status == .failed)) {
        state.status = .ready;
        state.reason_len = 0;
    }
}

/// Remember the last probe outcome (short words, e.g. `TLS check failed`) for the
/// verify-timeout reason.
pub fn setProbeHint(hint: []const u8) void {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    const n = @min(hint.len, max_hint_len);
    @memcpy(probe_hint[0..n], hint[0..n]);
    probe_hint_len = n;
}

/// True when the URL should be checked now: it is published but not ready, and
/// cloudflared registered its connection or the URL is 5s old.
pub fn shouldProbe(now_ms: i64) bool {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    if (!host_published.load(.monotonic)) return false;
    if (state.status != .verifying and state.status != .failed) return false;
    return connected.load(.acquire) or now_ms - verify_start_ms >= probe_fallback_ms;
}

pub fn markConnected() void {
    connected.store(true, .release);
}

pub fn isConnected() bool {
    return connected.load(.acquire);
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
    const msg = std.fmt.bufPrint(&buf, "cloudflared exited (code {d}); see zlodev.log", .{code}) catch "cloudflared exited; see zlodev.log";
    setReason(msg);
}

pub fn checkTimeout(now_ms: i64) void {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    // Check and set under one lock so a concurrent publishHost can't be overwritten.
    if (state.status == .starting and now_ms - start_ms >= start_timeout_ms) {
        state.status = .failed;
        setReason("no URL from cloudflared after 30s; see zlodev.log");
    } else if (state.status == .verifying and now_ms - verify_start_ms >= verify_timeout_ms) {
        var buf: [max_reason_len]u8 = undefined;
        const host = state.host[0..state.host_len];
        const msg = if (probe_hint_len > 0)
            std.fmt.bufPrint(&buf, "https://{s} isn't reachable yet after 60s ({s}); see zlodev.log", .{ host, probe_hint[0..probe_hint_len] }) catch "the URL isn't reachable yet after 60s; see zlodev.log"
        else
            std.fmt.bufPrint(&buf, "Cloudflare hasn't routed https://{s} yet after 60s; see zlodev.log", .{host}) catch "Cloudflare hasn't routed the URL yet after 60s; see zlodev.log";
        state.status = .failed;
        setReason(msg);
    }
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
    verify_start_ms = 0;
    probe_hint_len = 0;
    verify_skipped = false;
    host_published.store(false, .release);
    connected.store(false, .release);
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
/// returns the host. Rejects look-alike domains, extra labels, the `api` label
/// (error lines mention api.trycloudflare.com) and hosts followed by a path.
pub fn extractQuickTunnelHost(line: []const u8) ?[]const u8 {
    const scheme = "https://";
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, line, from, scheme)) |at| {
        const start = at + scheme.len;
        from = start;
        var end = start;
        while (end < line.len and isHostChar(line[end])) end += 1;
        if (end < line.len) {
            const c = line[end];
            if (c != '|' and !std.ascii.isWhitespace(c)) continue;
        }
        const host = line[start..end];
        if (host.len <= tunnel_suffix.len or host.len > max_host_len) continue;
        const label_len = host.len - tunnel_suffix.len;
        if (!std.ascii.eqlIgnoreCase(host[label_len..], tunnel_suffix)) continue;
        const label = host[0..label_len];
        if (std.mem.indexOfScalar(u8, label, '.') != null) continue;
        if (std.ascii.eqlIgnoreCase(label, "api")) continue;
        return host;
    }
    return null;
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
test "extractQuickTunnelHost rejects api host from error lines" {
    const err_line = "2026-11-25T10:00:00Z ERR failed to request quick Tunnel: Post \"https://api.trycloudflare.com/tunnel\": dial tcp: lookup api.trycloudflare.com: no such host";
    try testing.expect(extractQuickTunnelHost(err_line) == null);
    try testing.expect(extractQuickTunnelHost("https://api.trycloudflare.com") == null);
    try testing.expect(extractQuickTunnelHost("https://x.trycloudflare.com/path") == null);
    try testing.expectEqualStrings("real-one.trycloudflare.com", extractQuickTunnelHost("see https://api.trycloudflare.com/x then https://real-one.trycloudflare.com ok").?);
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
    try testing.expect(publishHost("a.trycloudflare.com"));
    try testing.expect(!publishHost("b.trycloudflare.com"));
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
    try testing.expect(publishHost("a.trycloudflare.com"));
    try testing.expectEqual(Status.verifying, snapshot().status);
    try testing.expect(markVerified());
    try testing.expectEqual(Status.ready, snapshot().status);
}
test "state: publish moves to verifying" {
    resetForTest();
    begin(0);
    try testing.expect(publishHost("a.trycloudflare.com"));
    const s = snapshot();
    try testing.expectEqual(Status.verifying, s.status);
    try testing.expectEqualStrings("a.trycloudflare.com", s.getHost());
}
test "state: markVerified moves to ready" {
    resetForTest();
    begin(0);
    try testing.expect(!markVerified());
    try testing.expect(publishHost("a.trycloudflare.com"));
    try testing.expect(isPublicHost("a.trycloudflare.com"));
    try testing.expect(markVerified());
    try testing.expectEqual(Status.ready, snapshot().status);
    try testing.expect(isPublicHost("a.trycloudflare.com"));
    try testing.expect(!markVerified());
}
test "state: verify timeout fails with the URL in the reason" {
    resetForTest();
    begin(0);
    try testing.expect(publishHostAt("a.trycloudflare.com", 5000));
    checkTimeout(64_999);
    try testing.expectEqual(Status.verifying, snapshot().status);
    checkTimeout(65_000);
    const s = snapshot();
    try testing.expectEqual(Status.failed, s.status);
    try testing.expectEqualStrings("Cloudflare hasn't routed https://a.trycloudflare.com yet after 60s; see zlodev.log", s.getReason());
    try testing.expectEqualStrings("a.trycloudflare.com", s.getHost());
    try testing.expect(isPublicHost("a.trycloudflare.com"));
}
test "state: late verify recovers" {
    resetForTest();
    begin(0);
    try testing.expect(publishHostAt("a.trycloudflare.com", 0));
    checkTimeout(60_000);
    try testing.expectEqual(Status.failed, snapshot().status);
    try testing.expect(markVerified());
    const s = snapshot();
    try testing.expectEqual(Status.ready, s.status);
    try testing.expectEqual(@as(usize, 0), s.getReason().len);
}
test "state: connected flag" {
    resetForTest();
    try testing.expect(!isConnected());
    markConnected();
    try testing.expect(isConnected());
    begin(0);
    try testing.expect(!isConnected());
    markConnected();
    resetForTest();
    try testing.expect(!isConnected());
}
test "state: exit reports code" {
    resetForTest();
    begin(0);
    markExited(1);
    const s = snapshot();
    try testing.expectEqual(Status.exited, s.status);
    try testing.expect(std.mem.indexOf(u8, s.getReason(), "code 1") != null);
}

test "state: checkTimeout never fails a state that already moved on" {
    resetForTest();
    begin(0);
    try testing.expect(publishHostAt("a.trycloudflare.com", 100_000));
    checkTimeout(100_000 + 59_999); // start deadline long past, but we are verifying
    try testing.expectEqual(Status.verifying, snapshot().status);
    try testing.expect(markVerified());
    checkTimeout(1_000_000);
    try testing.expectEqual(Status.ready, snapshot().status);
}

test "state: verify timeout reason names the last probe result" {
    resetForTest();
    begin(0);
    try testing.expect(publishHostAt("a.trycloudflare.com", 0));
    setProbeHint("couldn't reach 1.1.1.1");
    checkTimeout(60_000);
    const s = snapshot();
    try testing.expectEqual(Status.failed, s.status);
    try testing.expectEqualStrings("https://a.trycloudflare.com isn't reachable yet after 60s (couldn't reach 1.1.1.1); see zlodev.log", s.getReason());
    try testing.expect(s.hasUnverifiedUrl());
    // begin clears the hint.
    begin(0);
    try testing.expect(publishHostAt("a.trycloudflare.com", 0));
    checkTimeout(60_000);
    try testing.expect(std.mem.startsWith(u8, snapshot().getReason(), "Cloudflare hasn't routed"));
}
test "state: hasUnverifiedUrl only when failed with a host" {
    resetForTest();
    begin(0);
    try testing.expect(!snapshot().hasUnverifiedUrl());
    checkTimeout(30_000);
    try testing.expect(!snapshot().hasUnverifiedUrl()); // failed, no host
    try testing.expect(publishHostAt("a.trycloudflare.com", 30_000));
    try testing.expect(!snapshot().hasUnverifiedUrl()); // verifying
    checkTimeout(90_000);
    try testing.expect(snapshot().hasUnverifiedUrl());
    try testing.expect(markVerified());
    try testing.expect(!snapshot().hasUnverifiedUrl());
}
test "state: shouldProbe after connect or 5s after the URL" {
    resetForTest();
    begin(0);
    try testing.expect(!shouldProbe(100_000)); // no URL yet
    try testing.expect(publishHostAt("a.trycloudflare.com", 1000));
    try testing.expect(!shouldProbe(5999));
    try testing.expect(shouldProbe(6000));
    markConnected();
    try testing.expect(shouldProbe(1000));
    checkTimeout(61_000);
    try testing.expect(shouldProbe(61_000)); // failed with host: keep checking
    try testing.expect(markVerified());
    try testing.expect(!shouldProbe(70_000));
}
test "state: skipVerification marks the URL ready when it appears" {
    resetForTest();
    begin(0);
    skipVerification();
    try testing.expect(publishHost("a.trycloudflare.com"));
    try testing.expectEqual(Status.ready, snapshot().status);
    // Already verifying: moves to ready right away.
    resetForTest();
    begin(0);
    try testing.expect(publishHost("a.trycloudflare.com"));
    skipVerification();
    try testing.expectEqual(Status.ready, snapshot().status);
    // begin clears it.
    begin(0);
    try testing.expect(publishHost("b.trycloudflare.com"));
    try testing.expectEqual(Status.verifying, snapshot().status);
}
