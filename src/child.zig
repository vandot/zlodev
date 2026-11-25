const std = @import("std");
const builtin = @import("builtin");
const rt = @import("rt.zig");
const win32 = @import("win32.zig");

/// A spawned child that owns its whole process tree: own process group on
/// POSIX, kill-on-close job object on Windows. Lets stop reach grandchildren.
pub const ChildGroup = struct {
    child: ?std.process.Child = null,
    // Process group of the child (== its pid, set at spawn). Kept separately
    // because wait() clears child.id, but group members can outlive the
    // leader. Unused on Windows.
    pgid: i32 = 0,
    // Windows job object holding the child tree. Unused on other platforms.
    job: ?std.os.windows.HANDLE = null,

    pub fn spawn(
        self: *ChildGroup,
        argv: []const []const u8,
        stdout: std.process.SpawnOptions.StdIo,
        stderr: std.process.SpawnOptions.StdIo,
    ) !void {
        const c = try std.process.spawn(rt.io(), .{
            .argv = argv,
            // The TUI owns the terminal; a background-group child reading it gets SIGTTIN.
            .stdin = .ignore,
            .stdout = stdout,
            .stderr = stderr,
            // Own process group so stop can signal grandchildren (npm workers).
            .pgid = if (builtin.os.tag == .windows) null else 0,
        });
        if (builtin.os.tag == .windows) {
            self.job = win32.assignToKillJob(c.id.?);
        } else {
            self.pgid = @intCast(c.id.?);
        }
        self.child = c;
    }

    /// Ask the whole group to end. POSIX: SIGTERM, wait up to `grace_ms` for
    /// `running` to clear, then SIGKILL. Windows: terminate the job at once.
    /// The stored group is signalled even if the leader was already reaped.
    pub fn terminate(self: *ChildGroup, grace_ms: u32, running: *const std.atomic.Value(bool)) void {
        const c = if (self.child) |*cp| cp else return;
        if (builtin.os.tag == .windows) {
            // No graceful signal on Windows: terminate the whole job,
            // falling back to the direct child.
            if (self.job) |job| {
                _ = win32.TerminateJobObject(job, 1);
            } else if (c.id) |id| {
                _ = win32.TerminateProcess(id, 1);
            }
        } else {
            std.posix.kill(-self.pgid, .TERM) catch {};
        }

        const deadline = rt.milliTimestamp() + grace_ms;
        while (running.load(.acquire) and rt.milliTimestamp() < deadline) {
            rt.sleepMs(50);
        }

        if (running.load(.acquire)) {
            if (builtin.os.tag != .windows) {
                std.posix.kill(-self.pgid, .KILL) catch {};
            }
        }
    }

    /// Drop handles and forget the child. Call after threads using it joined.
    pub fn release(self: *ChildGroup) void {
        if (builtin.os.tag == .windows) {
            if (self.job) |job| std.os.windows.CloseHandle(job);
        }
        self.job = null;
        self.child = null;
        self.pgid = 0;
    }
};

const Waiter = struct {
    group: *ChildGroup,
    running: *std.atomic.Value(bool),

    fn run(w: Waiter) void {
        if (w.group.child) |*c| _ = c.wait(rt.io()) catch {};
        w.running.store(false, .release);
    }
};

test "terminate kills the whole group" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var group: ChildGroup = .{};
    try group.spawn(&.{ "/bin/sh", "-c", "sleep 30 & sleep 30" }, .ignore, .ignore);
    const pgid = group.pgid;
    try std.testing.expect(pgid > 0);

    var running = std.atomic.Value(bool).init(true);
    const t = try std.Thread.spawn(.{}, Waiter.run, .{Waiter{ .group = &group, .running = &running }});
    group.terminate(3000, &running);
    t.join();
    group.release();
    try std.testing.expect(group.child == null);
    try std.testing.expectEqual(@as(i32, 0), group.pgid);

    const gone_by = rt.milliTimestamp() + 5000;
    while (true) {
        std.posix.kill(-pgid, @enumFromInt(0)) catch |e| switch (e) {
            error.ProcessNotFound => break,
            // macOS: killed members are zombies until launchd reaps them.
            error.PermissionDenied => {},
            else => return e,
        };
        if (rt.milliTimestamp() > gone_by) return error.GroupStillAlive;
        rt.sleepMs(20);
    }
}
