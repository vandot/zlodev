const std = @import("std");
const compat = @import("compat.zig");

pub fn sudoCmd(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    var child = std.process.Child.init(argv, allocator);
    child.stderr_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    const term = try child.spawnAndWait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) return error.CommandFailed;
        },
        else => return error.CommandFailed,
    }
}

/// Run a command and capture its stdout output. Returns allocated slice (caller must free).
/// Returns null if the command fails or produces no output.
pub fn runCmdOutput(allocator: std.mem.Allocator, argv: []const []const u8) ?[]const u8 {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    child.stdin_behavior = .Ignore;
    child.spawn() catch return null;
    const stdout_file = child.stdout.?;
    var read_buf: [4096]u8 = undefined;
    var result = std.ArrayListUnmanaged(u8){};
    while (true) {
        const n = stdout_file.read(&read_buf) catch break;
        if (n == 0) break;
        result.appendSlice(allocator, read_buf[0..n]) catch break;
    }
    const term = child.wait() catch {
        result.deinit(allocator);
        return null;
    };
    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                result.deinit(allocator);
                return null;
            }
        },
        else => {
            result.deinit(allocator);
            return null;
        },
    }
    if (result.items.len == 0) {
        result.deinit(allocator);
        return null;
    }
    return result.items;
}

pub fn dirExists(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

pub fn writeTmpFile(allocator: std.mem.Allocator, name: []const u8, content: []const u8) ![]const u8 {
    const tmp = compat.getTmpDir();
    const path = try std.fmt.allocPrint(allocator, "{s}/zlodev_{s}", .{ tmp, name });
    errdefer allocator.free(path);
    const file = try std.fs.createFileAbsolute(path, .{});
    defer file.close();
    try file.writeAll(content);
    return path;
}
