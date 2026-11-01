const std = @import("std");
const rt = @import("rt.zig");
const sep = std.fs.path.sep_str;
const compat = @import("compat.zig");

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

pub fn writeTmpFile(allocator: std.mem.Allocator, name: []const u8, content: []const u8) ![]const u8 {
    const tmp = compat.getTmpDir();
    const path = try std.fmt.allocPrint(allocator, "{s}" ++ sep ++ "zlodev_{s}", .{ tmp, name });
    errdefer allocator.free(path);
    const file = try std.Io.Dir.createFileAbsolute(rt.io(), path, .{});
    defer file.close(rt.io());
    try file.writeStreamingAll(rt.io(), content);
    return path;
}
