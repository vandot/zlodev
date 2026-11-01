const std = @import("std");
const builtin = @import("builtin");
const win32 = @import("win32.zig");

var running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true);

pub fn isRunning() bool {
    return running.load(.acquire);
}

pub fn requestShutdown() void {
    running.store(false, .release);
}

pub fn installSignalHandlers() void {
    if (builtin.os.tag == .windows) {
        _ = win32.SetConsoleCtrlHandler(&handleCtrl, win32.TRUE);
    } else {
        const posix = std.posix;
        const act = posix.Sigaction{
            .handler = .{ .handler = handleSignal },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        posix.sigaction(.INT, &act, null);
        posix.sigaction(.TERM, &act, null);
    }
}

fn handleSignal(_: std.posix.SIG) callconv(.c) void {
    requestShutdown();
}

fn handleCtrl(_: win32.DWORD) callconv(.winapi) win32.BOOL {
    requestShutdown();
    return win32.TRUE;
}

test "installSignalHandlers routes SIGTERM to requestShutdown" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    installSignalHandlers();
    defer running.store(true, .release);
    try std.posix.raise(.TERM);
    try std.testing.expect(!isRunning());
}
