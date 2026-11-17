const std = @import("std");
const sep = std.fs.path.sep_str;
const rt = @import("rt.zig");
const sys = @import("sys.zig");

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

const max_log_bytes = 1024 * 1024;

/// Open `<dir>/zlodev.log` for appending, creating `dir`. A log over `max_bytes`
/// is moved to `zlodev.log.1` first (one old copy kept).
fn openLogIn(dir: []const u8, max_bytes: u64) ?std.Io.File {
    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(rt.io(), dir) catch return null;
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}" ++ sep ++ "zlodev.log", .{dir}) catch return null;
    if (cwd.statFile(rt.io(), path, .{})) |st| {
        if (st.size > max_bytes) {
            var old_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const old = std.fmt.bufPrint(&old_buf, "{s}.1", .{path}) catch return null;
            cwd.rename(path, cwd, old, rt.io()) catch {};
        }
    } else |_| {}
    const f = cwd.createFile(rt.io(), path, .{ .truncate = false }) catch return null;
    log_offset = f.length(rt.io()) catch 0;
    return f;
}

/// Errors in TUI mode go to `<data dir>/zlodev.log` (same dir as the certs).
pub fn initLogFile() void {
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = sys.dataDir(&dir_buf) catch return;
    log_file = openLogIn(dir, max_log_bytes);
}

pub fn deinitLogFile() void {
    if (log_file) |f| {
        f.close(rt.io());
        log_file = null;
    }
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    if (muted.load(.acquire)) return;
    var buf: [21]u8 = undefined;
    const ts = timestamp(&buf);
    std.debug.print("[{s}] INFO " ++ fmt ++ "\n", .{ts} ++ args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    var buf: [21]u8 = undefined;
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

fn timestamp(buf: *[21]u8) []const u8 {
    const epoch = rt.timestamp();
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(epoch) };
    const day = es.getDaySeconds();
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,
        @intFromEnum(md.month),
        md.day_index + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
        day.getSecondsIntoMinute(),
    }) catch return "????-??-??T??:??:??Z";
}

const testing = std.testing;

fn tmpPath(buf: []u8, tmp: *const std.testing.TmpDir, name: []const u8) ![]const u8 {
    if (name.len == 0) return std.fmt.bufPrint(buf, ".zig-cache" ++ sep ++ "tmp" ++ sep ++ "{s}", .{&tmp.sub_path});
    return std.fmt.bufPrint(buf, ".zig-cache" ++ sep ++ "tmp" ++ sep ++ "{s}" ++ sep ++ "{s}", .{ &tmp.sub_path, name });
}

test "openLogIn creates the dir and appends" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [256]u8 = undefined;
    const dir = try tmpPath(&buf, &tmp, "a" ++ sep ++ "b");
    const f = openLogIn(dir, 1024 * 1024) orelse return error.TestUnexpectedResult;
    f.close(rt.io());
    try tmp.dir.access(rt.io(), "a" ++ sep ++ "b" ++ sep ++ "zlodev.log", .{});
}

test "openLogIn rotates a log over the limit to zlodev.log.1" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(rt.io(), .{ .sub_path = "zlodev.log", .data = "0123456789" });
    var buf: [256]u8 = undefined;
    const f = openLogIn(try tmpPath(&buf, &tmp, ""), 5) orelse return error.TestUnexpectedResult;
    f.close(rt.io());
    const old = try tmp.dir.readFileAlloc(rt.io(), "zlodev.log.1", testing.allocator, .limited(64));
    defer testing.allocator.free(old);
    try testing.expectEqualStrings("0123456789", old);
    const st = try tmp.dir.statFile(rt.io(), "zlodev.log", .{});
    try testing.expectEqual(@as(u64, 0), st.size);
}

test "openLogIn keeps a small log and appends after it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(rt.io(), .{ .sub_path = "zlodev.log", .data = "abc" });
    var buf: [256]u8 = undefined;
    const f = openLogIn(try tmpPath(&buf, &tmp, ""), 1024) orelse return error.TestUnexpectedResult;
    f.close(rt.io());
    try testing.expectEqual(@as(u64, 3), log_offset);
}

test "timestamp ends in Z" {
    var buf: [21]u8 = undefined;
    const ts = timestamp(&buf);
    try testing.expectEqual(@as(usize, 20), ts.len);
    try testing.expectEqual(@as(u8, 'Z'), ts[ts.len - 1]);
}
