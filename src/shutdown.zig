const std = @import("std");
const builtin = @import("builtin");

var running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true);

pub fn isRunning() bool {
    return running.load(.acquire);
}

pub fn requestShutdown() void {
    running.store(false, .release);
}

pub fn installSignalHandlers() void {
    if (builtin.os.tag == .windows) {
        std.os.windows.SetConsoleCtrlHandler(&handleCtrl, true) catch {};
    } else {
        const posix = std.posix;
        const act = posix.Sigaction{
            .handler = .{ .handler = handleSignal },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.INT, &act, null);
        posix.sigaction(posix.SIG.TERM, &act, null);
    }
}

fn handleSignal(_: c_int) callconv(.c) void {
    requestShutdown();
}

fn handleCtrl(_: std.os.windows.DWORD) callconv(.winapi) std.os.windows.BOOL {
    requestShutdown();
    return std.os.windows.TRUE;
}
