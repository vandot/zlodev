const std = @import("std");
const rt = @import("rt.zig");
const requests = @import("requests.zig");
const http_wire = @import("http_wire.zig");

pub const CopyResult = enum { copied, truncated, missing };

/// Copy a request as a curl command to the clipboard. Refuses (`.truncated`) when
/// the capture is cut, since the command would send something else.
/// The curl command for `entry` in `out`, or null when it doesn't fit. The URL
/// keeps the captured Host when it is the zlodev domain or a subdomain of it.
pub fn buildCurl(entry: *const requests.Entry, domain: []const u8, out: []u8) ?[]const u8 {
    var pos: usize = 0;
    var truncated = false;

    const append = struct {
        fn f(b: []u8, p: *usize, data: []const u8, trunc: *bool) void {
            const space = b.len - p.*;
            const n = @min(data.len, space);
            @memcpy(b[p.*..][0..n], data[0..n]);
            p.* += n;
            if (n < data.len) trunc.* = true;
        }
    }.f;

    const appendByte = struct {
        fn f(b: []u8, p: *usize, ch: u8, trunc: *bool) void {
            if (p.* < b.len) {
                b[p.*] = ch;
                p.* += 1;
            } else {
                trunc.* = true;
            }
        }
    }.f;

    append(out, &pos, "curl -k", &truncated);

    // Method (skip -X for GET since it's the default)
    const method = entry.getMethod();
    if (!std.mem.eql(u8, method, "GET")) {
        append(out, &pos, " -X ", &truncated);
        append(out, &pos, method, &truncated);
    }

    // Headers
    const hdrs = entry.getReqHeaders();
    var hdr_iter = std.mem.splitSequence(u8, hdrs, "\r\n");
    while (hdr_iter.next()) |header| {
        if (header.len == 0) continue;
        if (header.len >= 5 and containsIgnoreCase(header[0..5], "host:")) continue;
        append(out, &pos, " -H '", &truncated);
        for (header) |ch| {
            if (ch == '\'') {
                append(out, &pos, "'\\''", &truncated);
            } else {
                appendByte(out, &pos, ch, &truncated);
            }
        }
        appendByte(out, &pos, '\'', &truncated);
    }

    // Body
    const body = entry.getReqBody();
    if (body.len > 0) {
        append(out, &pos, " --data-raw '", &truncated);
        for (body) |ch| {
            if (ch == '\'') {
                append(out, &pos, "'\\''", &truncated);
            } else {
                appendByte(out, &pos, ch, &truncated);
            }
        }
        appendByte(out, &pos, '\'', &truncated);
    }

    // URL
    const captured_host = http_wire.getHeaderValue(entry.getReqHeaders(), "host:") orelse "";
    const host_only = if (std.mem.indexOfScalar(u8, captured_host, ':')) |c| captured_host[0..c] else captured_host;
    const url_host = if (http_wire.sameSiteHost(host_only, domain)) host_only else domain;
    append(out, &pos, " 'https://", &truncated);
    append(out, &pos, url_host, &truncated);
    append(out, &pos, entry.getPath(), &truncated);
    appendByte(out, &pos, '\'', &truncated);

    // A command that didn't fit would send something else.
    if (truncated) return null;
    return out[0..pos];

}

/// Pipe text to the platform clipboard tool. False when none is available.
pub fn copyText(text: []const u8) bool {
    const clip_cmd: []const []const u8 = switch (@import("builtin").os.tag) {
        .macos => &.{"pbcopy"},
        .linux => &.{ "xclip", "-selection", "clipboard" },
        .windows => &.{"clip.exe"},
        else => return false,
    };
    var child = std.process.spawn(rt.io(), .{ .argv = clip_cmd, .stdin = .pipe, .stdout = .ignore, .stderr = .ignore }) catch return false;
    if (child.stdin) |stdin| {
        stdin.writeStreamingAll(rt.io(), text) catch {};
        stdin.close(rt.io());
        child.stdin = null;
    }
    _ = child.wait(rt.io()) catch {};
    return true;
}

pub fn copyAsCurl(alloc: std.mem.Allocator, logical: usize, domain: []const u8) CopyResult {
    _ = alloc; // std.process.spawn no longer takes an allocator
    var entry_copy: requests.Entry = undefined;
    if (!requests.copyEntry(logical, &entry_copy)) return .missing;
    const entry = &entry_copy;
    if (entry.requestTruncated()) return .truncated;

    var buf: [65536]u8 = undefined;
    const cmd = buildCurl(entry, domain, &buf) orelse return .truncated;

    if (!copyText(cmd)) return .missing;
    return .copied;
}

pub fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return std.ascii.findIgnoreCase(haystack, needle) != null;
}

// --- Unit Tests ---

const testing = std.testing;

test "containsIgnoreCase exact match" {
    try testing.expect(containsIgnoreCase("hello", "hello"));
}

test "containsIgnoreCase substring" {
    try testing.expect(containsIgnoreCase("hello world", "world"));
    try testing.expect(containsIgnoreCase("hello world", "lo wo"));
}

test "containsIgnoreCase case insensitive" {
    try testing.expect(containsIgnoreCase("Hello World", "hello"));
    try testing.expect(containsIgnoreCase("hello", "HELLO"));
    try testing.expect(containsIgnoreCase("Content-Type", "content-type"));
}

test "containsIgnoreCase no match" {
    try testing.expect(!containsIgnoreCase("hello", "xyz"));
    try testing.expect(!containsIgnoreCase("abc", "abcd"));
}

test "containsIgnoreCase needle longer than haystack" {
    try testing.expect(!containsIgnoreCase("hi", "hello"));
}

test "containsIgnoreCase empty needle" {
    // Empty needle — end = haystack.len + 1, first iteration matches
    try testing.expect(containsIgnoreCase("hello", ""));
}

test "containsIgnoreCase both empty" {
    try testing.expect(containsIgnoreCase("", ""));
}

test "containsIgnoreCase single char" {
    try testing.expect(containsIgnoreCase("abc", "B"));
    try testing.expect(!containsIgnoreCase("abc", "D"));
}

test "copyAsCurl refuses a truncated capture" {
    var e = requests.Entry{ .req_body_truncated = true, .timestamp = 1 };
    const m = "POST";
    @memcpy(e.method[0..m.len], m);
    e.method_len = m.len;
    requests.push(e);
    try testing.expectEqual(CopyResult.truncated, copyAsCurl(testing.allocator, requests.getCount() - 1, "dev.lo"));
}

fn curlEntry(method: []const u8, path: []const u8, headers: []const u8, body: []const u8) requests.Entry {
    var e = requests.Entry{};
    @memcpy(e.method[0..method.len], method);
    e.method_len = @intCast(method.len);
    @memcpy(e.path[0..path.len], path);
    e.path_len = @intCast(path.len);
    @memcpy(e.req_headers[0..headers.len], headers);
    e.req_headers_len = @intCast(headers.len);
    @memcpy(e.req_body[0..body.len], body);
    e.req_body_len = @intCast(body.len);
    return e;
}

test "buildCurl sends the body with --data-raw" {
    const e = curlEntry("POST", "/up", "Host: dev.lo\r\n", "@/etc/passwd");
    var buf: [1024]u8 = undefined;
    const cmd = buildCurl(&e, "dev.lo", &buf).?;
    try std.testing.expect(std.mem.indexOf(u8, cmd, " --data-raw '@/etc/passwd'") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, " -d ") == null);
}

test "buildCurl keeps a subdomain from the captured Host" {
    const e = curlEntry("GET", "/v1", "Host: api.dev.lo\r\n", "");
    var buf: [1024]u8 = undefined;
    try std.testing.expect(std.mem.endsWith(u8, buildCurl(&e, "dev.lo", &buf).?, " 'https://api.dev.lo/v1'"));
}

test "buildCurl falls back to the domain for a foreign Host" {
    const e = curlEntry("GET", "/v1", "Host: evil.com\r\n", "");
    var buf: [1024]u8 = undefined;
    try std.testing.expect(std.mem.endsWith(u8, buildCurl(&e, "dev.lo", &buf).?, " 'https://dev.lo/v1'"));
}

test "buildCurl strips the port from the Host" {
    const e = curlEntry("GET", "/", "Host: api.dev.lo:443\r\n", "");
    var buf: [1024]u8 = undefined;
    try std.testing.expect(std.mem.endsWith(u8, buildCurl(&e, "dev.lo", &buf).?, " 'https://api.dev.lo/'"));
}
