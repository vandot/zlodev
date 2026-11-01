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
