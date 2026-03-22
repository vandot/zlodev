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
