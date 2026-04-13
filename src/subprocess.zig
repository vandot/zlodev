const std = @import("std");
const log = @import("log.zig");
const shutdown = @import("shutdown.zig");
const builtin = @import("builtin");

const AnsiStripper = struct {
    state: enum { normal, esc, csi, osc, osc_esc } = .normal,

    fn feed(self: *AnsiStripper, byte: u8, out: []u8, out_len: *usize) void {
        switch (self.state) {
            .normal => {
                if (byte == 0x1b) {
                    self.state = .esc;
                } else {
                    if (out_len.* < out.len) {
                        out[out_len.*] = byte;
                        out_len.* += 1;
                    }
                }
            },
            .esc => {
                if (byte == '[') {
                    self.state = .csi;
                } else if (byte == ']') {
                    self.state = .osc;
                } else {
                    // Two-byte escape sequence (e.g. ESC c) — drop both bytes
                    self.state = .normal;
                }
            },
            .csi => {
                // CSI params are 0x30-0x3F, intermediates 0x20-0x2F, final 0x40-0x7E
                if (byte >= 0x40 and byte <= 0x7E) {
                    self.state = .normal;
                }
                // else: still consuming CSI parameter/intermediate bytes
            },
            .osc => {
                if (byte == 0x07) {
                    // BEL terminates OSC
                    self.state = .normal;
                } else if (byte == 0x1b) {
                    self.state = .osc_esc;
                }
                // else: still consuming OSC body
            },
            .osc_esc => {
                // ESC \ (ST) terminates OSC; anything else — return to normal
                self.state = .normal;
            },
        }
    }
};

test "ansi strip - plain text passes through" {
    var s = AnsiStripper{};
    var buf: [64]u8 = undefined;
    var len: usize = 0;
    for ("hello world") |b| s.feed(b, &buf, &len);
    try std.testing.expectEqualStrings("hello world", buf[0..len]);
}

test "ansi strip - SGR removed" {
    var s = AnsiStripper{};
    var buf: [64]u8 = undefined;
    var len: usize = 0;
    // ESC[31m hello ESC[0m
    for ("\x1b[31mhello\x1b[0m") |b| s.feed(b, &buf, &len);
    try std.testing.expectEqualStrings("hello", buf[0..len]);
}

test "ansi strip - CSI erase and cursor sequences removed" {
    var s = AnsiStripper{};
    var buf: [64]u8 = undefined;
    var len: usize = 0;
    for ("\x1b[2Khello\x1b[?25l") |b| s.feed(b, &buf, &len);
    try std.testing.expectEqualStrings("hello", buf[0..len]);
}

test "ansi strip - OSC title removed (BEL terminator)" {
    var s = AnsiStripper{};
    var buf: [64]u8 = undefined;
    var len: usize = 0;
    for ("\x1b]0;my title\x07hello") |b| s.feed(b, &buf, &len);
    try std.testing.expectEqualStrings("hello", buf[0..len]);
}

test "ansi strip - OSC title removed (ST terminator)" {
    var s = AnsiStripper{};
    var buf: [64]u8 = undefined;
    var len: usize = 0;
    for ("\x1b]0;my title\x1b\\hello") |b| s.feed(b, &buf, &len);
    try std.testing.expectEqualStrings("hello", buf[0..len]);
}

test "ansi strip - bare ESC two-byte sequence removed" {
    var s = AnsiStripper{};
    var buf: [64]u8 = undefined;
    var len: usize = 0;
    for ("\x1bchello") |b| s.feed(b, &buf, &len);
    try std.testing.expectEqualStrings("hello", buf[0..len]);
}

pub const max_line_len: usize = 4096;

const LineSplitter = struct {
    pending: [max_line_len]u8 = undefined,
    pending_len: usize = 0,

    const OutputLine = struct {
        bytes: []const u8,
    };

    /// Process a chunk of bytes. Calls `callback` for each complete line.
    fn feed(self: *LineSplitter, chunk: []const u8, context: anytype, callback: fn (@TypeOf(context), []const u8) void) void {
        for (chunk) |byte| {
            if (byte == '\n') {
                // Emit the pending line, stripping trailing \r
                const len = if (self.pending_len > 0 and self.pending[self.pending_len - 1] == '\r')
                    self.pending_len - 1
                else
                    self.pending_len;
                callback(context, self.pending[0..len]);
                self.pending_len = 0;
            } else {
                if (self.pending_len >= max_line_len) {
                    // Hard split: emit current pending, start new line
                    callback(context, self.pending[0..max_line_len]);
                    self.pending_len = 0;
                }
                self.pending[self.pending_len] = byte;
                self.pending_len += 1;
            }
        }
    }

    /// Flush any remaining pending bytes as a line.
    fn flush(self: *LineSplitter, context: anytype, callback: fn (@TypeOf(context), []const u8) void) void {
        if (self.pending_len > 0) {
            callback(context, self.pending[0..self.pending_len]);
            self.pending_len = 0;
        }
    }
};

const TestCollector = struct {
    lines: [32]struct { buf: [max_line_len]u8 = undefined, len: usize = 0 } = undefined,
    count: usize = 0,

    fn collect(self: *TestCollector, data: []const u8) void {
        if (self.count < 32) {
            @memcpy(self.lines[self.count].buf[0..data.len], data);
            self.lines[self.count].len = data.len;
            self.count += 1;
        }
    }

    fn getLine(self: *const TestCollector, i: usize) []const u8 {
        return self.lines[i].buf[0..self.lines[i].len];
    }
};

test "line split - simple newline" {
    var ls = LineSplitter{};
    var tc = TestCollector{};
    ls.feed("hello\nworld\n", &tc, TestCollector.collect);
    try std.testing.expectEqual(@as(usize, 2), tc.count);
    try std.testing.expectEqualStrings("hello", tc.getLine(0));
    try std.testing.expectEqualStrings("world", tc.getLine(1));
}

test "line split - CRLF stripped" {
    var ls = LineSplitter{};
    var tc = TestCollector{};
    ls.feed("hello\r\nworld\r\n", &tc, TestCollector.collect);
    try std.testing.expectEqual(@as(usize, 2), tc.count);
    try std.testing.expectEqualStrings("hello", tc.getLine(0));
    try std.testing.expectEqualStrings("world", tc.getLine(1));
}

test "line split - no trailing newline held in pending" {
    var ls = LineSplitter{};
    var tc = TestCollector{};
    ls.feed("hello", &tc, TestCollector.collect);
    try std.testing.expectEqual(@as(usize, 0), tc.count);
    ls.flush(&tc, TestCollector.collect);
    try std.testing.expectEqual(@as(usize, 1), tc.count);
    try std.testing.expectEqualStrings("hello", tc.getLine(0));
}

test "line split - cross-chunk" {
    var ls = LineSplitter{};
    var tc = TestCollector{};
    ls.feed("hel", &tc, TestCollector.collect);
    try std.testing.expectEqual(@as(usize, 0), tc.count);
    ls.feed("lo\n", &tc, TestCollector.collect);
    try std.testing.expectEqual(@as(usize, 1), tc.count);
    try std.testing.expectEqualStrings("hello", tc.getLine(0));
}

test "line split - long line hard split" {
    var ls = LineSplitter{};
    var tc = TestCollector{};
    // Feed a line of max_line_len + 10 bytes with no newline, then newline
    var big: [max_line_len + 10]u8 = undefined;
    @memset(&big, 'A');
    big[big.len - 1] = '\n';
    ls.feed(&big, &tc, TestCollector.collect);
    try std.testing.expectEqual(@as(usize, 2), tc.count);
    try std.testing.expectEqual(max_line_len, tc.getLine(0).len);
    // Remaining 9 bytes (10 - 1 for \n)
    try std.testing.expectEqual(@as(usize, 9), tc.getLine(1).len);
}

// ---------------------------------------------------------------------------
// Log Ring Buffer
// ---------------------------------------------------------------------------

pub const max_log_lines: usize = if (@import("builtin").is_test) 8 else 5000;

pub const LogSource = enum(u1) { stdout, stderr };

pub const LogLine = struct {
    bytes: [max_line_len]u8 = undefined,
    len: u16 = 0,
    source: LogSource = .stdout,
    synthetic: bool = false,
    seq: u64 = 0,
};

var ring_mutex: std.Thread.Mutex = .{};
var ring: []LogLine = &.{};
var ring_write_pos: usize = 0;
var ring_count: usize = 0;
var ring_seq: u64 = 0;
var ring_allocated: bool = false;

fn appendLine(data: []const u8, source: LogSource, is_synthetic: bool) void {
    ring_mutex.lock();
    defer ring_mutex.unlock();

    const slot = &ring[ring_write_pos];
    const copy_len = @min(data.len, max_line_len);
    @memcpy(slot.bytes[0..copy_len], data[0..copy_len]);
    slot.len = @intCast(copy_len);
    slot.source = source;
    slot.synthetic = is_synthetic;
    slot.seq = ring_seq;
    ring_seq += 1;

    ring_write_pos = (ring_write_pos + 1) % ring.len;
    if (ring_count < ring.len) {
        ring_count += 1;
    }
}

pub fn getLineCount() usize {
    ring_mutex.lock();
    defer ring_mutex.unlock();
    return ring_count;
}

pub fn copyRange(dest: []LogLine, start_idx: usize, max_count: usize) usize {
    ring_mutex.lock();
    defer ring_mutex.unlock();

    if (ring_count == 0) return 0;

    const clamped_start = @min(start_idx, ring_count);
    const available = ring_count - clamped_start;
    const to_copy = @min(available, @min(max_count, dest.len));

    // ring_write_pos points to the next write slot.
    // The oldest entry is at (ring_write_pos - ring_count) mod len.
    const oldest = if (ring_write_pos >= ring_count)
        ring_write_pos - ring_count
    else
        ring.len - (ring_count - ring_write_pos);

    for (0..to_copy) |i| {
        const idx = (oldest + clamped_start + i) % ring.len;
        dest[i] = ring[idx];
    }

    return to_copy;
}

pub fn clearAll() void {
    ring_mutex.lock();
    defer ring_mutex.unlock();
    ring_count = 0;
    ring_write_pos = 0;
}

// ---------------------------------------------------------------------------
// Process Lifecycle
// ---------------------------------------------------------------------------

var command_buf: [1024]u8 = undefined;
var command_len: usize = 0;
var child_process: ?std.process.Child = null;
var stdout_thread: ?std.Thread = null;
var stderr_thread: ?std.Thread = null;
var process_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var has_allocator: bool = false;
var stored_allocator: std.mem.Allocator = undefined;
var readerDoneCount: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

pub fn start(allocator: std.mem.Allocator, command: []const u8) !void {
    stored_allocator = allocator;
    has_allocator = true;
    const copy_len = @min(command.len, command_buf.len);
    @memcpy(command_buf[0..copy_len], command[0..copy_len]);
    command_len = copy_len;

    // Allocate ring buffer if not already allocated
    if (!ring_allocated) {
        const heap_ring = try std.heap.page_allocator.alloc(LogLine, max_log_lines);
        @memset(heap_ring, LogLine{});
        ring = heap_ring;
        ring_allocated = true;
    }

    try spawnChild();
}

pub fn restart() void {
    stopChild();
    spawnChild() catch |e| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "[zlodev] failed to restart: {any}", .{e}) catch "[zlodev] failed to restart";
        appendLine(msg, .stdout, true);
    };
}

pub fn stop() void {
    stopChild();
    if (ring_allocated) {
        std.heap.page_allocator.free(ring);
        ring = &.{};
        ring_allocated = false;
    }
}

pub fn isRunning() bool {
    return process_running.load(.acquire);
}

fn spawnChild() !void {
    const cmd = command_buf[0..command_len];

    var child = std.process.Child.init(
        &.{ "/bin/sh", "-c", cmd },
        if (has_allocator) stored_allocator else std.heap.page_allocator,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();
    if (builtin.os.tag != .windows) {
        // Make child its own process group leader so we can signal
        // the entire group (including grandchildren like npm workers)
        std.posix.setpgid(@intCast(child.id), @intCast(child.id)) catch {};
    }
    child_process = child;
    process_running.store(true, .release);
    readerDoneCount.store(0, .release);

    log.info("component=subprocess op=start command={s}", .{cmd});

    // Spawn reader threads
    stdout_thread = try std.Thread.spawn(.{}, readerThread, .{ child.stdout.?, .stdout });
    errdefer {
        // stderr_thread spawn failed — clean up child and stdout reader
        if (builtin.os.tag != .windows) {
            std.posix.kill(-@as(i32, @intCast(child.id)), std.posix.SIG.KILL) catch {};
        }
        if (stdout_thread) |t| t.join();
        stdout_thread = null;
        child_process = null;
        process_running.store(false, .release);
    }
    stderr_thread = try std.Thread.spawn(.{}, readerThread, .{ child.stderr.?, .stderr });
}

const ReaderContext = struct {
    source: LogSource,
};

fn readerAppendLine(ctx: *const ReaderContext, line: []const u8) void {
    appendLine(line, ctx.source, false);
}

fn readerThread(pipe: std.fs.File, source: LogSource) void {
    var ansi = AnsiStripper{};
    var splitter = LineSplitter{};
    var read_buf: [4096]u8 = undefined;
    var stripped_buf: [4096]u8 = undefined;
    const ctx = ReaderContext{ .source = source };

    while (shutdown.isRunning() and process_running.load(.acquire)) {
        const n = pipe.read(&read_buf) catch break;
        if (n == 0) break;

        // Strip ANSI escapes
        var stripped_len: usize = 0;
        for (read_buf[0..n]) |byte| {
            ansi.feed(byte, &stripped_buf, &stripped_len);
        }

        // Split into lines and append to ring
        splitter.feed(stripped_buf[0..stripped_len], &ctx, readerAppendLine);
    }

    // Flush any remaining pending bytes
    splitter.flush(&ctx, readerAppendLine);

    // If both pipes are closed, the child has exited — inject exit line
    // Only one thread should do this; use an atomic flag
    if (readerDoneCount.fetchAdd(1, .acq_rel) == 1) {
        // Both readers done — wait for child and inject exit line
        if (child_process) |*child| {
            const term = child.wait() catch |e| {
                var buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "[zlodev] wait failed: {any}", .{e}) catch "[zlodev] wait failed";
                appendLine(msg, .stdout, true);
                process_running.store(false, .release);
                return;
            };
            const code: i64 = switch (term) {
                .Exited => |c| @as(i64, c),
                .Signal => |s| -@as(i64, @intCast(s)),
                .Stopped => |s| -@as(i64, @intCast(s)),
                .Unknown => -1,
            };
            var buf: [64]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "[zlodev] exited (code {d})", .{code}) catch "[zlodev] exited";
            appendLine(msg, .stdout, true);
        }
        process_running.store(false, .release);
    }
}

fn stopChild() void {
    if (child_process) |*child| {
        // Send SIGTERM (on Unix) / terminate (on Windows)
        const pid = child.id;
        if (builtin.os.tag == .windows) {
            const w = std.os.windows;
            _ = w.kernel32.TerminateProcess(child.id, 1);
        } else {
            std.posix.kill(-@as(i32, @intCast(pid)), std.posix.SIG.TERM) catch {};
        }

        // Wait up to 3 seconds for exit
        const deadline = std.time.milliTimestamp() + 3000;
        while (process_running.load(.acquire) and std.time.milliTimestamp() < deadline) {
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }

        // Force kill if still running
        if (process_running.load(.acquire)) {
            if (builtin.os.tag != .windows) {
                std.posix.kill(-@as(i32, @intCast(pid)), std.posix.SIG.KILL) catch {};
            }
        }

        // Join reader threads
        if (stdout_thread) |t| t.join();
        if (stderr_thread) |t| t.join();

        stdout_thread = null;
        stderr_thread = null;
        child_process = null;
        readerDoneCount.store(0, .release);
    }
}

test "ring - append and read back" {
    // Use a small test-only static ring
    var static_ring: [max_log_lines]LogLine = @splat(LogLine{});
    ring = &static_ring;
    ring_write_pos = 0;
    ring_count = 0;
    ring_seq = 0;

    appendLine("hello", .stdout, false);
    appendLine("world", .stderr, false);

    try std.testing.expectEqual(@as(usize, 2), getLineCount());

    var dest: [8]LogLine = undefined;
    const n = copyRange(&dest, 0, 8);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("hello", dest[0].bytes[0..dest[0].len]);
    try std.testing.expectEqual(LogSource.stdout, dest[0].source);
    try std.testing.expectEqualStrings("world", dest[1].bytes[0..dest[1].len]);
    try std.testing.expectEqual(LogSource.stderr, dest[1].source);

    // Reset for other tests
    clearAll();
}

test "ring - overflow evicts oldest" {
    var static_ring: [max_log_lines]LogLine = @splat(LogLine{});
    ring = &static_ring;
    ring_write_pos = 0;
    ring_count = 0;
    ring_seq = 0;

    // Fill ring + 3 extra
    for (0..max_log_lines + 3) |i| {
        var buf: [8]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "line{d}", .{i}) catch "?";
        appendLine(s, .stdout, false);
    }

    try std.testing.expectEqual(max_log_lines, getLineCount());

    var dest: [max_log_lines]LogLine = undefined;
    const n = copyRange(&dest, 0, max_log_lines);
    try std.testing.expectEqual(max_log_lines, n);

    // First line should be "line3" (0,1,2 were evicted)
    try std.testing.expectEqualStrings("line3", dest[0].bytes[0..dest[0].len]);

    clearAll();
}

test "ring - seq is monotonic" {
    var static_ring: [max_log_lines]LogLine = @splat(LogLine{});
    ring = &static_ring;
    ring_write_pos = 0;
    ring_count = 0;
    ring_seq = 0;

    appendLine("a", .stdout, false);
    appendLine("b", .stdout, false);
    appendLine("c", .stdout, false);

    var dest: [8]LogLine = undefined;
    const n = copyRange(&dest, 0, 8);
    try std.testing.expect(n == 3);
    try std.testing.expect(dest[0].seq < dest[1].seq);
    try std.testing.expect(dest[1].seq < dest[2].seq);

    clearAll();
}

test "ring - synthetic flag" {
    var static_ring: [max_log_lines]LogLine = @splat(LogLine{});
    ring = &static_ring;
    ring_write_pos = 0;
    ring_count = 0;
    ring_seq = 0;

    appendLine("[zlodev] exited (code 1)", .stdout, true);
    var dest: [1]LogLine = undefined;
    const n = copyRange(&dest, 0, 1);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expect(dest[0].synthetic);

    clearAll();
}
