const std = @import("std");
const rt = @import("rt.zig");
const sep = std.fs.path.sep_str;
const compat = @import("compat.zig");
const builtin = @import("builtin");

pub fn sudoCmd(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    _ = allocator;
    var child = try std.process.spawn(rt.io(), .{ .argv = argv, .stdout = .inherit, .stderr = .inherit });
    const term = try child.wait(rt.io());
    switch (term) {
        .exited => |code| {
            if (code != 0) return error.CommandFailed;
        },
        else => return error.CommandFailed,
    }
}

pub const RunResult = enum { ok, failed, missing };

/// Run a command as the current user with all output discarded. `missing` means
/// the binary isn't on PATH, so callers can tell "not installed" from "failed".
pub fn runUserCmd(argv: []const []const u8) RunResult {
    var child = std.process.spawn(rt.io(), .{ .argv = argv, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore }) catch |e| return switch (e) {
        error.FileNotFound => .missing,
        else => .failed,
    };
    const term = child.wait(rt.io()) catch return .failed;
    return switch (term) {
        .exited => |code| if (code == 0) .ok else .failed,
        else => .failed,
    };
}

/// Run a command and capture its stdout output. Returns allocated slice (caller must free).
/// Returns null if the command fails or produces no output.
pub fn runCmdOutput(allocator: std.mem.Allocator, argv: []const []const u8) ?[]const u8 {
    const res = std.process.run(allocator, rt.io(), .{ .argv = argv }) catch return null;
    allocator.free(res.stderr);
    const ok = switch (res.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok or res.stdout.len == 0) {
        allocator.free(res.stdout);
        return null;
    }
    return res.stdout;
}

pub fn dirExists(path: []const u8) bool {
    std.Io.Dir.accessAbsolute(rt.io(), path, .{}) catch return false;
    return true;
}

/// Write `content` to a new private temp file `<tmp>/zlodev_<name>_<random>`
/// (exclusive create, 0600), for handing to `sudo install`. Caller frees the
/// path and calls `removeTmpFile` when done.
pub fn writeTmpFile(allocator: std.mem.Allocator, name: []const u8, content: []const u8) ![]const u8 {
    var rnd: [8]u8 = undefined;
    rt.io().random(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);
    const path = try std.fmt.allocPrint(allocator, "{s}" ++ sep ++ "zlodev_{s}_{s}", .{ compat.getTmpDir(), name, &hex });
    errdefer allocator.free(path);
    const perms: std.Io.File.Permissions = if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);
    const file = try std.Io.Dir.createFileAbsolute(rt.io(), path, .{ .exclusive = true, .permissions = perms });
    defer file.close(rt.io());
    try file.writeStreamingAll(rt.io(), content);
    return path;
}

pub fn removeTmpFile(path: []const u8) void {
    std.Io.Dir.deleteFileAbsolute(rt.io(), path) catch {};
}

/// Base directory for zlodev's certs and log.
pub fn dataDir(buf: []u8) ![]const u8 {
    switch (builtin.os.tag) {
        .macos => {
            const home = compat.getenv("HOME") orelse return error.NoHomeDir;
            return std.fmt.bufPrint(buf, "{s}" ++ sep ++ "Library/Application Support/zlodev", .{home});
        },
        .windows => {
            const local_env = compat.getenv("LocalAppData") orelse return error.NoLocalAppData;
            return std.fmt.bufPrint(buf, "{s}" ++ sep ++ "zlodev", .{local_env});
        },
        else => {
            // Linux
            const xdg = compat.getenv("XDG_DATA_HOME");
            if (xdg) |data_home| {
                return std.fmt.bufPrint(buf, "{s}" ++ sep ++ "zlodev", .{data_home});
            }
            const home = compat.getenv("HOME") orelse return error.NoHomeDir;
            return std.fmt.bufPrint(buf, "{s}" ++ sep ++ ".local/share/zlodev", .{home});
        },
    }
}

const testing = std.testing;

test "writeTmpFile gives each call its own private file" {
    const a = try writeTmpFile(testing.allocator, "t", "one");
    defer testing.allocator.free(a);
    defer removeTmpFile(a);
    const b = try writeTmpFile(testing.allocator, "t", "two");
    defer testing.allocator.free(b);
    defer removeTmpFile(b);
    try testing.expect(!std.mem.eql(u8, a, b));
    const base = std.fs.path.basename(a);
    try testing.expect(std.mem.startsWith(u8, base, "zlodev_t_"));
    try testing.expectEqual(@as(usize, "zlodev_t_".len + 16), base.len);
    const content = try std.Io.Dir.cwd().readFileAlloc(rt.io(), a, testing.allocator, .limited(64));
    defer testing.allocator.free(content);
    try testing.expectEqualStrings("one", content);
    if (builtin.os.tag != .windows) {
        const st = try std.Io.Dir.cwd().statFile(rt.io(), a, .{});
        try testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);
    }
}

test "removeTmpFile deletes the file" {
    const a = try writeTmpFile(testing.allocator, "rm", "x");
    defer testing.allocator.free(a);
    removeTmpFile(a);
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(rt.io(), a, .{}));
}

test "dataDir ends in zlodev" {
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = try dataDir(&buf);
    try testing.expect(std.mem.endsWith(u8, dir, "zlodev"));
}
