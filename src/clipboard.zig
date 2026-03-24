const std = @import("std");
const requests = @import("requests.zig");

/// Copy a request as a curl command to the clipboard.
pub fn copyAsCurl(alloc: std.mem.Allocator, logical: usize, domain: []const u8) void {
    const entry = requests.getOne(logical) orelse return;

    var buf: [65536]u8 = undefined;
    var pos: usize = 0;

    const append = struct {
        fn f(b: []u8, p: *usize, data: []const u8) void {
            const space = b.len - p.*;
            const n = @min(data.len, space);
            @memcpy(b[p.*..][0..n], data[0..n]);
            p.* += n;
        }
    }.f;

    const appendByte = struct {
        fn f(b: []u8, p: *usize, ch: u8) void {
            if (p.* < b.len) {
                b[p.*] = ch;
                p.* += 1;
            }
        }
    }.f;

    append(&buf, &pos, "curl -k");

    // Method (skip -X for GET since it's the default)
    const method = entry.getMethod();
    if (!std.mem.eql(u8, method, "GET")) {
        append(&buf, &pos, " -X ");
        append(&buf, &pos, method);
    }

    // Headers
    const hdrs = entry.getReqHeaders();
    var hdr_iter = std.mem.splitSequence(u8, hdrs, "\r\n");
    while (hdr_iter.next()) |header| {
        if (header.len == 0) continue;
        if (header.len >= 5 and containsIgnoreCase(header[0..5], "host:")) continue;
        append(&buf, &pos, " -H '");
        for (header) |ch| {
            if (ch == '\'') {
                append(&buf, &pos, "'\\''");
            } else {
                appendByte(&buf, &pos, ch);
            }
        }
        appendByte(&buf, &pos, '\'');
    }

    // Body
    const body = entry.getReqBody();
    if (body.len > 0) {
        append(&buf, &pos, " -d '");
        for (body) |ch| {
            if (ch == '\'') {
                append(&buf, &pos, "'\\''");
            } else {
                appendByte(&buf, &pos, ch);
            }
        }
        appendByte(&buf, &pos, '\'');
    }

    // URL
    append(&buf, &pos, " 'https://");
    append(&buf, &pos, domain);
    append(&buf, &pos, entry.getPath());
    appendByte(&buf, &pos, '\'');

    // Pipe to clipboard (platform-specific)
    const clip_cmd: []const []const u8 = switch (@import("builtin").os.tag) {
        .macos => &.{"pbcopy"},
        .linux => &.{ "xclip", "-selection", "clipboard" },
        .windows => &.{"clip.exe"},
        else => return,
    };
    var child = std.process.Child.init(clip_cmd, alloc);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return;
    if (child.stdin) |*stdin| {
        stdin.writeAll(buf[0..pos]) catch {};
        stdin.close();
        child.stdin = null;
    }
    _ = child.wait() catch {};
}

pub fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    const end = haystack.len - needle.len + 1;
    for (0..end) |i| {
        var match = true;
        for (0..needle.len) |j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
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
