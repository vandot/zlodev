//! JSON reserialization for the TUI body views: detect, parse, and re-emit JSON
//! into a caller-owned buffer — pretty (indented) for display, compact (minified)
//! for forwarding an edited body. std-only, so it is unit-testable without the TUI.
//!
//! The caller owns `dest`, which is why two body panes can be formatted in the same
//! frame without clobbering each other — unlike a shared module-level scratch buffer.
const std = @import("std");

/// Re-emit `src` as JSON with whitespace `ws` into `dest`, returning the number of
/// bytes written, or null if `src` is not a JSON object/array (leading `{` or `[`
/// after optional whitespace). `dest` is untouched when null is returned; output is
/// clamped to `dest.len`.
fn emit(alloc: std.mem.Allocator, src: []const u8, dest: []u8, comptime ws: anytype) ?usize {
    if (src.len == 0) return null;
    const first = for (src) |ch| {
        if (ch != ' ' and ch != '\t' and ch != '\n' and ch != '\r') break ch;
    } else return null;
    if (first != '{' and first != '[') return null;

    const parsed = std.json.parseFromSlice(std.json.Value, alloc, src, .{}) catch return null;
    defer parsed.deinit();
    const out = std.json.Stringify.valueAlloc(alloc, parsed.value, .{ .whitespace = ws }) catch return null;
    defer alloc.free(out);

    const len = @min(out.len, dest.len);
    @memcpy(dest[0..len], out[0..len]);
    return len;
}

/// Pretty-print `src` (2-space indent) into `dest`. Null if `src` is not JSON.
pub fn pretty(alloc: std.mem.Allocator, src: []const u8, dest: []u8) ?usize {
    return emit(alloc, src, dest, .indent_2);
}

/// Minify `src` into `dest`. Null if `src` is not JSON.
pub fn compact(alloc: std.mem.Allocator, src: []const u8, dest: []u8) ?usize {
    return emit(alloc, src, dest, .minified);
}

// --- Unit Tests ---

const testing = std.testing;

test "pretty indents a JSON object into the caller buffer" {
    var buf: [128]u8 = undefined;
    const len = pretty(testing.allocator, "{\"a\":1,\"b\":2}", &buf).?;
    try testing.expectEqualStrings("{\n  \"a\": 1,\n  \"b\": 2\n}", buf[0..len]);
}

test "compact minifies a JSON object into the caller buffer" {
    var buf: [128]u8 = undefined;
    const len = compact(testing.allocator, "{\n  \"a\": 1,\n  \"b\": 2\n}", &buf).?;
    try testing.expectEqualStrings("{\"a\":1,\"b\":2}", buf[0..len]);
}

test "non-JSON bodies return null and leave dest untouched" {
    var buf: [16]u8 = undefined;
    @memcpy(buf[0..5], "guard");
    try testing.expect(pretty(testing.allocator, "hello world", &buf) == null);
    try testing.expect(pretty(testing.allocator, "", &buf) == null);
    try testing.expect(compact(testing.allocator, "not json", &buf) == null);
    try testing.expectEqualStrings("guard", buf[0..5]); // dest untouched on null
}

test "leading whitespace before the brace is tolerated" {
    var buf: [64]u8 = undefined;
    const len = compact(testing.allocator, "  \n\t[1,2,3]", &buf).?;
    try testing.expectEqualStrings("[1,2,3]", buf[0..len]);
}

test "invalid JSON after a brace returns null" {
    var buf: [64]u8 = undefined;
    try testing.expect(pretty(testing.allocator, "{not valid", &buf) == null);
}

test "two buffers formatted independently do not clobber each other" {
    // The regression this module exists to prevent: a shared scratch made the
    // request body pane render the response body's bytes.
    var req: [64]u8 = undefined;
    var resp: [64]u8 = undefined;
    const rq = pretty(testing.allocator, "{\"req\":1}", &req).?;
    const rs = pretty(testing.allocator, "{\"resp\":2}", &resp).?;
    try testing.expectEqualStrings("{\n  \"req\": 1\n}", req[0..rq]);
    try testing.expectEqualStrings("{\n  \"resp\": 2\n}", resp[0..rs]);
}

test "output is clamped to dest length" {
    var small: [4]u8 = undefined;
    const len = compact(testing.allocator, "{\"a\":1}", &small).?;
    try testing.expectEqual(@as(usize, 4), len);
    try testing.expectEqualStrings("{\"a\"", small[0..len]);
}
