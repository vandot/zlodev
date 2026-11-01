//! Process-wide runtime handles. Zig 0.17 routes sleep, time, sync, files,
//! sockets and processes through `std.Io`; `main` installs one instance here
//! so call sites don't need an `io` parameter threaded through every layer.
//! Under `zig test`, `io()` returns `std.testing.io` without any setup.
const std = @import("std");
const builtin = @import("builtin");

var global_io: ?std.Io = null;

/// Environment map from `std.process.Init`, needed by libvaxis. Set by main.
pub var env_map: ?*std.process.Environ.Map = null;

pub fn setIo(io_: std.Io) void {
    global_io = io_;
}

pub fn io() std.Io {
    if (builtin.is_test) return std.testing.io;
    return global_io orelse @panic("rt.io() used before rt.setIo()");
}

pub fn milliTimestamp() i64 {
    return std.Io.Timestamp.now(io(), .real).toMilliseconds();
}

pub fn timestamp() i64 {
    return std.Io.Timestamp.now(io(), .real).toSeconds();
}

pub fn sleepMs(ms: u64) void {
    io().sleep(.fromMilliseconds(@intCast(ms)), .awake) catch {};
}

/// Run `work(args)` on a worker thread from `group`; if the Io's concurrency
/// limit is reached, run `reject(reject_args)` inline instead (closes the socket).
pub fn spawnWorker(
    io_: std.Io,
    group: *std.Io.Group,
    comptime work: anytype,
    args: std.meta.ArgsTuple(@TypeOf(work)),
    comptime reject: anytype,
    reject_args: std.meta.ArgsTuple(@TypeOf(reject)),
) void {
    group.concurrent(io_, work, args) catch {
        @call(.auto, reject, reject_args);
    };
}

/// Reserve one of `max` worker slots in `counter`, waiting while all are busy
/// (the old std.Thread.Pool queued excess work; here excess connections wait
/// in the listen backlog). Returns false without reserving if `running()`
/// turns false while waiting. Release with `counter.fetchSub(1, .acq_rel)`.
pub fn acquireWorkerSlot(counter: *std.atomic.Value(u32), max: u32, running: *const fn () bool) bool {
    while (running()) {
        var cur = counter.load(.acquire);
        while (cur < max) {
            cur = counter.cmpxchgWeak(cur, cur + 1, .acq_rel, .acquire) orelse return true;
        }
        sleepMs(5);
    }
    return false;
}

test "milliTimestamp is wall clock and monotone enough" {
    const a = milliTimestamp();
    sleepMs(5);
    const b = milliTimestamp();
    try std.testing.expect(a > 1_700_000_000_000); // after 2023-11
    try std.testing.expect(b - a >= 4);
}

test "timestamp seconds matches millis" {
    const s = timestamp();
    const ms = milliTimestamp();
    try std.testing.expect(@abs(@divTrunc(ms, 1000) - s) <= 1);
}

test "spawnWorker closes the connection when concurrency is unavailable" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    var group: std.Io.Group = .init;
    var closed = false;
    const Ctx = struct {
        fn work(_: *bool) void {}
        fn reject(flag: *bool) void {
            flag.* = true;
        }
    };
    spawnWorker(threaded.io(), &group, Ctx.work, .{&closed}, Ctx.reject, .{&closed});
    group.await(threaded.io()) catch {};
    try std.testing.expect(closed);
}

test "acquireWorkerSlot waits for a free slot instead of failing" {
    var counter: std.atomic.Value(u32) = .init(2);
    const Releaser = struct {
        fn run(c: *std.atomic.Value(u32)) void {
            sleepMs(50);
            _ = c.fetchSub(1, .acq_rel);
        }
        fn alwaysRunning() bool {
            return true;
        }
    };
    const t = try std.Thread.spawn(.{}, Releaser.run, .{&counter});
    defer t.join();
    const start = milliTimestamp();
    try std.testing.expect(acquireWorkerSlot(&counter, 2, Releaser.alwaysRunning));
    try std.testing.expect(milliTimestamp() - start >= 40);
    try std.testing.expectEqual(@as(u32, 2), counter.load(.acquire));
}

test "acquireWorkerSlot gives up when shutdown is requested" {
    var counter: std.atomic.Value(u32) = .init(1);
    const Stopped = struct {
        fn running() bool {
            return false;
        }
    };
    try std.testing.expect(!acquireWorkerSlot(&counter, 1, Stopped.running));
    try std.testing.expectEqual(@as(u32, 1), counter.load(.acquire));
}
