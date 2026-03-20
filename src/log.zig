const std = @import("std");
const builtin = @import("builtin");

var muted: bool = false;
var log_file: ?std.fs.File = null;

pub fn mute() void {
    muted = true;
}

pub fn unmute() void {
    muted = false;
}

fn getHomeDir() ?[]const u8 {
    if (builtin.os.tag == .windows) {
        return std.posix.getenv("USERPROFILE") orelse std.posix.getenv("LOCALAPPDATA");
    }
    return std.posix.getenv("HOME");
}

pub fn initLogFile() void {
    const home = getHomeDir() orelse return;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = std.fmt.bufPrint(&path_buf, "{s}/.zlodev", .{home}) catch return;
    std.fs.makeDirAbsolute(dir_path) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return,
    };
    var file_buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = std.fmt.bufPrint(&file_buf, "{s}/.zlodev/zlodev.log", .{home}) catch return;
    log_file = std.fs.createFileAbsolute(file_path, .{ .truncate = false }) catch return;
    // Seek to end for append
    if (log_file) |f| {
        f.seekFromEnd(0) catch {};
    }
}

pub fn deinitLogFile() void {
    if (log_file) |f| {
        f.close();
        log_file = null;
    }
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    if (muted) return;
    var buf: [20]u8 = undefined;
    const ts = timestamp(&buf);
    std.debug.print("[{s}] INFO " ++ fmt ++ "\n", .{ts} ++ args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    var buf: [20]u8 = undefined;
    const ts = timestamp(&buf);
    if (muted) {
        // Write to log file when TUI is active
        if (log_file) |f| {
            var line_buf: [4096]u8 = undefined;
            const line = std.fmt.bufPrint(&line_buf, "[{s}] ERROR " ++ fmt ++ "\n", .{ts} ++ args) catch return;
            f.writeAll(line) catch {};
        }
    } else {
        std.debug.print("[{s}] ERROR " ++ fmt ++ "\n", .{ts} ++ args);
    }
}

fn timestamp(buf: *[20]u8) []const u8 {
    const epoch = std.time.timestamp();
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(epoch) };
    const day = es.getDaySeconds();
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}", .{
        yd.year,
        @intFromEnum(md.month),
        md.day_index + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
        day.getSecondsIntoMinute(),
    }) catch return "????-??-??T??:??:??";
}
