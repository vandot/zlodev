const std = @import("std");
const sep = std.fs.path.sep_str;
const builtin = @import("builtin");
const compat = @import("compat.zig");
const rt = @import("rt.zig");

var muted: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var log_file: ?std.Io.File = null;
// Append position in log_file; std.Io.File has no seek, so writes are positional.
var log_offset: u64 = 0;
var log_mutex: std.Io.Mutex = .init;

pub fn mute() void {
    muted.store(true, .release);
}

pub fn unmute() void {
    muted.store(false, .release);
}

fn getHomeDir() ?[]const u8 {
    if (builtin.os.tag == .windows) {
        return compat.getenv("USERPROFILE") orelse compat.getenv("LOCALAPPDATA");
    }
    return compat.getenv("HOME");
}

pub fn initLogFile() void {
    const home = getHomeDir() orelse return;
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_path = std.fmt.bufPrint(&path_buf, "{s}" ++ sep ++ ".zlodev", .{home}) catch return;
    std.Io.Dir.createDirAbsolute(rt.io(), dir_path, .default_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return,
    };
    var file_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const file_path = std.fmt.bufPrint(&file_buf, "{s}" ++ sep ++ ".zlodev" ++ sep ++ "zlodev.log", .{home}) catch return;
    log_file = std.Io.Dir.createFileAbsolute(rt.io(), file_path, .{ .truncate = false }) catch return;
    // Append after existing content
    if (log_file) |f| {
        log_offset = f.length(rt.io()) catch 0;
    }
}

pub fn deinitLogFile() void {
    if (log_file) |f| {
        f.close(rt.io());
        log_file = null;
    }
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    if (muted.load(.acquire)) return;
    var buf: [20]u8 = undefined;
    const ts = timestamp(&buf);
    std.debug.print("[{s}] INFO " ++ fmt ++ "\n", .{ts} ++ args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    var buf: [20]u8 = undefined;
    const ts = timestamp(&buf);
    if (muted.load(.acquire)) {
        // Write to log file when TUI is active
        if (log_file) |f| {
            var line_buf: [4096]u8 = undefined;
            const line = std.fmt.bufPrint(&line_buf, "[{s}] ERROR " ++ fmt ++ "\n", .{ts} ++ args) catch return;
            log_mutex.lockUncancelable(rt.io());
            defer log_mutex.unlock(rt.io());
            f.writePositionalAll(rt.io(), line, log_offset) catch return;
            log_offset += line.len;
        }
    } else {
        std.debug.print("[{s}] ERROR " ++ fmt ++ "\n", .{ts} ++ args);
    }
}

fn timestamp(buf: *[20]u8) []const u8 {
    const epoch = rt.timestamp();
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
