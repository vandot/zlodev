const std = @import("std");
const testing = std.testing;

/// How a command-line argument relates to a value flag such as `-p`/`--port`.
pub const FlagMatch = union(enum) { none, value: []const u8, needs_next };

/// `--port=3000` → value "3000"; `--port` alone → needs_next (value is the next
/// argument); anything else → none.
pub fn matchFlag(arg: []const u8, short: ?[]const u8, long: []const u8) FlagMatch {
    const names = [_]?[]const u8{ short, long };
    for (names) |maybe| {
        const name = maybe orelse continue;
        if (std.mem.eql(u8, arg, name)) return .needs_next;
        if (arg.len > name.len and arg[name.len] == '=' and std.mem.startsWith(u8, arg, name))
            return .{ .value = arg[name.len + 1 ..] };
    }
    return .none;
}

/// Parse a size with optional suffix K, M or G (case-insensitive) into bytes.
/// Null for empty, malformed or overflowing input.
pub fn parseSize(val: []const u8) ?usize {
    if (val.len == 0) return null;
    const mult: usize = switch (val[val.len - 1]) {
        'K', 'k' => 1024,
        'M', 'm' => 1024 * 1024,
        'G', 'g' => 1024 * 1024 * 1024,
        else => 1,
    };
    const digits = if (mult == 1) val else val[0 .. val.len - 1];
    const n = std.fmt.parseInt(usize, digits, 10) catch return null;
    return std.math.mul(usize, n, mult) catch null;
}

// --- Tests ---


test "matchFlag takes an inline value" {
    try testing.expectEqualStrings("3000", matchFlag("--port=3000", "-p", "--port").value);
    try testing.expectEqualStrings("3000", matchFlag("-p=3000", "-p", "--port").value);
}

test "matchFlag asks for the next argument when the flag stands alone" {
    try testing.expect(matchFlag("--port", "-p", "--port") == .needs_next);
    try testing.expect(matchFlag("-p", "-p", "--port") == .needs_next);
}

test "matchFlag ignores other arguments" {
    try testing.expect(matchFlag("--portal", "-p", "--port") == .none);
    try testing.expect(matchFlag("start", "-p", "--port") == .none);
    try testing.expect(matchFlag("-p", null, "--port") == .none);
}

test "parseSize reads suffixes" {
    try testing.expectEqual(@as(?usize, 10 * 1024 * 1024), parseSize("10M"));
    try testing.expectEqual(@as(?usize, 512 * 1024), parseSize("512k"));
    try testing.expectEqual(@as(?usize, 42), parseSize("42"));
    try testing.expectEqual(@as(?usize, null), parseSize(""));
    try testing.expectEqual(@as(?usize, null), parseSize("M"));
}

test "parseSize rejects values that overflow" {
    try testing.expectEqual(@as(?usize, null), parseSize("99999999999999999999G"));
    try testing.expectEqual(@as(?usize, null), parseSize("18446744073709551615K"));
}
