# Command Runner and Logs Pane — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `command=` option that launches a dev-server process alongside zlodev, captures its output, and displays it in a split-pane TUI.

**Architecture:** A new `subprocess.zig` module handles process lifecycle, pipe reading, ANSI stripping, and a log ring buffer. `main.zig` gains a `--command` flag and config key. `tui.zig` gains a split-pane layout with per-pane autoscroll and focus routing.

**Tech Stack:** Zig 0.15.1, std.process.Child for process spawning, std.Thread for reader threads, std.posix for process groups and signals.

**Spec:** `docs/superpowers/specs/2026-04-11-command-logs-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `src/subprocess.zig` | Create | ANSI strip, line split, log ring buffer, process spawn/kill, reader threads |
| `src/main.zig` | Modify | `--command` CLI flag, `command=` config key, validation, wiring in `doStart` |
| `src/tui.zig` | Modify | Split-pane layout, focus model, per-pane autoscroll, keybindings, drawLogs, drawBorder |

**No changes needed to `build.zig`** — Zig resolves `@import("subprocess.zig")` automatically from the root module.

## Known Conflict: `R` Key

`R` is currently "quick replay" in list view (`tui.zig:575`) and detail view (`tui.zig:643`). The spec assigns `R` to "restart child process."

**Resolution:** `R` is focus-dependent in list view:
- `focus == .logs` and command configured → restart child
- `focus == .requests` or no command → quick replay (existing behavior)

In detail view (fullscreen, no logs pane), `R` remains quick replay. This preserves backward compatibility for all existing users.

---

### Task 1: ANSI Strip State Machine

**Files:**
- Create: `src/subprocess.zig`

The ANSI stripper is a pure function with no dependencies — build and test it first.

- [ ] **Step 1: Write the failing tests for ANSI stripping**

In `src/subprocess.zig`, create the `AnsiStripper` struct and test cases. The stripper processes one byte at a time, outputting non-escape bytes into a provided buffer.

```zig
const AnsiStripper = struct {
    state: enum { normal, esc, csi, osc, osc_esc } = .normal,

    fn feed(self: *AnsiStripper, byte: u8, out: []u8, out_len: *usize) void {
        // TODO: implement
        _ = self;
        _ = byte;
        _ = out;
        _ = out_len;
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig test src/subprocess.zig`
Expected: FAIL — `feed` is a no-op stub.

- [ ] **Step 3: Implement the ANSI strip state machine**

Replace the `feed` body with:

```zig
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig test src/subprocess.zig`
Expected: All 6 tests PASS.

---

### Task 2: Line Splitter

**Files:**
- Modify: `src/subprocess.zig`

The line splitter takes a chunk of bytes (already ANSI-stripped), splits on `\n`, strips trailing `\r`, and hard-splits lines longer than `max_line_len`. It maintains a pending-line buffer between calls.

- [ ] **Step 1: Write the failing tests for line splitting**

Add to `src/subprocess.zig`:

```zig
pub const max_line_len: usize = 4096;

const LineSplitter = struct {
    pending: [max_line_len]u8 = undefined,
    pending_len: usize = 0,

    const OutputLine = struct {
        bytes: []const u8,
    };

    /// Process a chunk of bytes. Calls `callback` for each complete line.
    fn feed(self: *LineSplitter, chunk: []const u8, context: anytype, callback: fn (@TypeOf(context), []const u8) void) void {
        _ = self;
        _ = chunk;
        _ = context;
        _ = callback;
    }

    /// Flush any remaining pending bytes as a line.
    fn flush(self: *LineSplitter, context: anytype, callback: fn (@TypeOf(context), []const u8) void) void {
        _ = self;
        _ = context;
        _ = callback;
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig test src/subprocess.zig`
Expected: FAIL — `feed` and `flush` are stubs.

- [ ] **Step 3: Implement the line splitter**

```zig
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

fn flush(self: *LineSplitter, context: anytype, callback: fn (@TypeOf(context), []const u8) void) void {
    if (self.pending_len > 0) {
        callback(context, self.pending[0..self.pending_len]);
        self.pending_len = 0;
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig test src/subprocess.zig`
Expected: All tests PASS (ANSI tests + line split tests).

---

### Task 3: Log Ring Buffer

**Files:**
- Modify: `src/subprocess.zig`

A fixed-size ring of `LogLine` structs, heap-allocated, protected by a mutex. Supports append, `copyRange`, `getLineCount`, and `clearAll`.

- [ ] **Step 1: Write the failing tests for the ring buffer**

Add to `src/subprocess.zig`:

```zig
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
    // TODO
    _ = data;
    _ = source;
    _ = is_synthetic;
}

pub fn getLineCount() usize {
    ring_mutex.lock();
    defer ring_mutex.unlock();
    return ring_count;
}

pub fn copyRange(dest: []LogLine, start_idx: usize, max_count: usize) usize {
    // TODO
    _ = dest;
    _ = start_idx;
    _ = max_count;
    return 0;
}

pub fn clearAll() void {
    ring_mutex.lock();
    defer ring_mutex.unlock();
    ring_count = 0;
    ring_write_pos = 0;
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig test src/subprocess.zig`
Expected: FAIL — `appendLine` and `copyRange` are stubs.

- [ ] **Step 3: Implement the ring buffer**

```zig
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig test src/subprocess.zig`
Expected: All tests PASS.

---

### Task 4: Process Spawn, Read, and Kill

**Files:**
- Modify: `src/subprocess.zig`

This task wires the ANSI stripper and line splitter to pipe-reading threads, and implements the spawn/stop/restart lifecycle. This code is harder to unit-test (requires real processes), so it relies on manual integration testing in Task 9.

- [ ] **Step 1: Add public API and process state**

Add the following module-level state and public functions to `src/subprocess.zig`. The command is stored so `restart()` can respawn:

```zig
const log = @import("log.zig");
const shutdown = @import("shutdown.zig");
const builtin = @import("builtin");

var command_buf: [1024]u8 = undefined;
var command_len: usize = 0;
var child_process: ?std.process.Child = null;
var stdout_thread: ?std.Thread = null;
var stderr_thread: ?std.Thread = null;
var process_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var has_allocator: bool = false;
var stored_allocator: std.mem.Allocator = undefined;

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
```

- [ ] **Step 2: Implement `spawnChild` (Unix path)**

```zig
fn spawnChild() !void {
    const cmd = command_buf[0..command_len];

    var child = std.process.Child.init(
        &.{ "/bin/sh", "-c", cmd },
        if (has_allocator) stored_allocator else std.heap.page_allocator,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();
    child_process = child;
    process_running.store(true, .release);

    log.info("component=subprocess op=start command={s}", .{cmd});

    // Spawn reader threads
    stdout_thread = try std.Thread.spawn(.{}, readerThread, .{ child.stdout.?, .stdout });
    stderr_thread = try std.Thread.spawn(.{}, readerThread, .{ child.stderr.?, .stderr });
}
```

Note: `std.process.Child` handles the platform differences. On Unix, we should ideally use `setsid` for process-group cleanup. Check if `std.process.Child` supports a pre-exec hook or if we need `std.posix.fork` directly. If `std.process.Child` doesn't expose pre-exec hooks, we have two options:
- Use `std.posix.fork` + `setsid` + `execvp` manually (more control, more code).
- Use `std.process.Child` and kill with `std.posix.kill(pid, SIG.TERM)` targeting the process directly (simpler, but won't kill subchildren like node spawned by npm).

**Decision for implementation:** Start with `std.process.Child` + direct kill. If npm/node orphan processes are observed during manual testing, upgrade to manual `fork`/`setsid`. Document this in code as a known v1 limitation.

- [ ] **Step 3: Implement `readerThread`**

```zig
fn readerThread(pipe: std.fs.File, source: LogSource) void {
    var ansi = AnsiStripper{};
    var splitter = LineSplitter{};
    var read_buf: [4096]u8 = undefined;
    var stripped_buf: [4096]u8 = undefined;

    while (shutdown.isRunning() and process_running.load(.acquire)) {
        const n = pipe.read(&read_buf) catch break;
        if (n == 0) break;

        // Strip ANSI escapes
        var stripped_len: usize = 0;
        for (read_buf[0..n]) |byte| {
            ansi.feed(byte, &stripped_buf, &stripped_len);
        }

        // Split into lines and append to ring
        const src = source;
        splitter.feed(stripped_buf[0..stripped_len], .{ .source = src }, struct {
            fn emit(ctx: struct { source: LogSource }, line: []const u8) void {
                appendLine(line, ctx.source, false);
            }
        }.emit);
    }

    // Flush any remaining pending bytes
    const src = source;
    splitter.flush(.{ .source = src }, struct {
        fn emit(ctx: struct { source: LogSource }, line: []const u8) void {
            appendLine(line, ctx.source, false);
        }
    }.emit);

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

var readerDoneCount: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
```

- [ ] **Step 4: Implement `stopChild`**

```zig
fn stopChild() void {
    if (child_process) |*child| {
        // Send SIGTERM (on Unix) / terminate (on Windows)
        const pid = child.id;
        if (builtin.os.tag == .windows) {
            if (child.id != 0) {
                const w = std.os.windows;
                _ = w.kernel32.TerminateProcess(child.id, 1);
            }
        } else {
            std.posix.kill(@intCast(pid), std.posix.SIG.TERM) catch {};
        }

        // Wait up to 3 seconds for exit
        const deadline = std.time.milliTimestamp() + 3000;
        while (process_running.load(.acquire) and std.time.milliTimestamp() < deadline) {
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }

        // Force kill if still running
        if (process_running.load(.acquire)) {
            if (builtin.os.tag != .windows) {
                std.posix.kill(@intCast(pid), std.posix.SIG.KILL) catch {};
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
```

- [ ] **Step 5: Verify compilation**

Run: `zig build`
Expected: Compiles with no errors (subprocess.zig is not yet imported from main.zig, but we can verify the file compiles via `zig test src/subprocess.zig` which implicitly compiles everything).

Run: `zig test src/subprocess.zig`
Expected: All existing tests still PASS.

---

### Task 5: CLI and Config Parsing

**Files:**
- Modify: `src/main.zig:62-109` (argument loop)
- Modify: `src/main.zig:728-736` (`ConfigResult`)
- Modify: `src/main.zig:738-790` (`readConfigFile`)

- [ ] **Step 1: Add `command` to `ConfigResult`**

In `src/main.zig`, add to the `ConfigResult` struct (line ~735):

```zig
command: ?[]const u8 = null,
```

- [ ] **Step 2: Add `--command` CLI flag parsing**

In the argument loop (line ~62), add a new `else if` branch after the `--force` check (line ~98), before the version/help checks:

```zig
} else if (flagValue(arg, null, "--command")) |val| {
    command_str = val;
    command_set = true;
```

Add these variables near the top of `main()` alongside the existing flag variables (around line ~37):

```zig
var command_str: ?[]const u8 = null;
var command_set = false;
```

- [ ] **Step 3: Add `command=` config file parsing**

In `readConfigFile` (line ~757 in the while loop), add a new branch:

```zig
} else if (lineValue(line, "command")) |val| {
    if (result.command != null) {
        std.debug.print("config: duplicate command option\n", .{});
        std.process.exit(1);
    }
    const trimmed = std.mem.trim(u8, val, " \t");
    if (trimmed.len == 0) {
        std.debug.print("config: empty command value\n", .{});
        std.process.exit(1);
    }
    result.command = allocator.dupe(u8, trimmed) catch null;
```

- [ ] **Step 4: Wire config `command` to the runtime, with CLI override**

In the config-reading block of `main()` (around line ~113-136), add after the intercept pattern line (~129):

```zig
if (!command_set) if (cfg.command) |c| {
    command_str = c;
};
```

- [ ] **Step 5: Validate `--command` empty value and invalid combinations**

After the existing dns-only validation (line ~138-144), add:

```zig
// Validate command option
if (command_str) |cmd| {
    const trimmed = std.mem.trim(u8, cmd, " \t");
    if (trimmed.len == 0) {
        std.debug.print("--command value cannot be empty\n", .{});
        std.process.exit(1);
    }
    if (dns_only) {
        std.debug.print("--command cannot be combined with --dns\n", .{});
        std.process.exit(1);
    }
    if (no_tui) {
        std.debug.print("--command cannot be combined with --no-tui\n", .{});
        std.process.exit(1);
    }
}
```

- [ ] **Step 6: Add `command` parameter to `doStart` and pass it through**

Modify the `doStart` function signature (line ~328) to add `command: ?[]const u8` as the last parameter:

```zig
fn doStart(
    allocator: std.mem.Allocator,
    full_domain: []const u8,
    local: bool,
    tld: []const u8,
    target_port: u16,
    bind_addr: []const u8,
    no_tui: bool,
    max_request_body: usize,
    routes: []const proxy.Route,
    command: ?[]const u8,
) !void {
```

Update the call site (line ~192):

```zig
try doStart(allocator, full_domain, local, tld, target_port, bind_addr, no_tui, max_body, routes[0..route_count], command_str);
```

- [ ] **Step 7: Wire subprocess.start/stop in doStart**

Add `const subprocess = @import("subprocess.zig");` at the top of `main.zig`.

After the proxy thread spawn (around line ~437) and before the `if (no_tui)` check (line ~439), add:

```zig
// Start subprocess if command is configured
if (command) |cmd| {
    subprocess.start(allocator, cmd) catch |e| {
        log.err("component=subprocess op=start error={any}", .{e});
    };
}
```

After `shutdown.requestShutdown()` (line ~459) and **before** the proxy/HTTP/DNS thread joins (lines 460-462), add `subprocess.stop()`. This ordering matters: `requestShutdown()` causes reader threads to exit their poll loop (they check `shutdown.isRunning()`), then `stop()` sends SIGTERM and joins reader threads, then the server threads join.

```zig
shutdown.requestShutdown();
if (command != null) subprocess.stop();
proxy_thread.join();
http_thread.join();
if (dns_thread) |dt| dt.join();
```

Also pass `command != null` to `tui.run()` — this is wired in Task 6.

- [ ] **Step 8: Update printHelp**

Add `--command=CMD` to the help text in `printHelp()` (find it in main.zig).

- [ ] **Step 9: Verify compilation**

Run: `zig build`
Expected: Compiles. May need to temporarily adjust `tui.run()` call if the signature change in Task 6 hasn't been done yet — if so, just pass the extra parameter and handle it as a no-op in tui.zig for now.

---

### Task 6: TUI State Changes (Autoscroll Split, New Variables)

**Files:**
- Modify: `src/tui.zig:363` (`run()` signature)
- Modify: `src/tui.zig:400-403` (state variables)
- Modify: `src/tui.zig:770` (autoscroll usage in list view)
- Modify: `src/tui.zig:785` (`drawHeader` call)
- Modify: `src/tui.zig:828` (`drawHeader` signature)
- Modify: `src/tui.zig:928` (`drawRequests` signature)

- [ ] **Step 1: Add `has_command` parameter to `tui.run()`**

Change the signature at line 363:

```zig
pub fn run(alloc: std.mem.Allocator, domain: []const u8, target_port: u16, routes: []const proxy.Route, has_command: bool) !void {
```

Update the call in `main.zig:450`:

```zig
tui.run(allocator, full_domain, target_port, routes, command != null) catch |e| {
```

- [ ] **Step 2: Add new state variables in `run()`**

After existing state vars (around line 402-424), add:

```zig
var logs_visible: bool = has_command;
const Focus = enum { requests, logs };
var focus: Focus = .requests;
var logs_scroll: usize = 0;
var logs_autoscroll: bool = true;
```

Rename the existing `autoscroll` (line 402) to `req_autoscroll`:

```zig
var req_autoscroll: bool = true;
```

- [ ] **Step 3: Update all references to `autoscroll` → `req_autoscroll`**

Search `tui.zig` for every use of `autoscroll` and rename to `req_autoscroll`. Key locations:
- Line 500: `autoscroll = !autoscroll` → handled by the new `s` key logic (Task 8)
- Line 614: `autoscroll = !autoscroll` (detail view) → `req_autoscroll = !req_autoscroll`
- Line 770: `if (autoscroll and ...` → `if (req_autoscroll and ...`
- Line 785: `drawHeader(... autoscroll ...)` → `drawHeader(... req_autoscroll ...)`
- Line 803: `drawDetail(... autoscroll ...)` → pass `req_autoscroll`
- Line 936: `drawRequests(... autoscroll ...)` → `drawRequests(... req_autoscroll ...)`
- Line 951: `drawFooter(win, autoscroll, ...` → `drawFooter(win, req_autoscroll, ...`

All function signatures that take `autoscroll: bool` keep the parameter name but receive `req_autoscroll` from the caller. No signature changes needed on `drawHeader`, `drawRequests`, etc. — they just receive the correct value.

- [ ] **Step 4: Verify compilation**

Run: `zig build`
Expected: Compiles with no errors. The `logs_visible`, `focus`, `logs_scroll`, `logs_autoscroll` variables are unused at this point — Zig may warn but should still compile. If Zig errors on unused vars, add `_ = logs_visible; _ = focus; _ = logs_scroll; _ = logs_autoscroll;` temporarily.

---

### Task 7: Layout and Drawing (drawBorder, drawLogs, Split)

**Files:**
- Modify: `src/tui.zig` — add `drawBorder`, `drawLogs`, modify draw loop in `run()`

- [ ] **Step 1: Add `@import` for subprocess**

At the top of `tui.zig` (around line 7), add:

```zig
const subprocess = @import("subprocess.zig");
```

- [ ] **Step 2: Implement `drawBorder`**

Add after `drawFooter` (around line 1393):

```zig
fn drawBorder(win: vaxis.Window, y: u16, label: []const u8, focused: bool) void {
    const color: vaxis.Color = if (focused)
        .{ .rgb = .{ 0x5f, 0xaf, 0xff } }
    else
        .{ .rgb = .{ 0x4a, 0x4a, 0x4a } };

    // Draw horizontal line
    for (0..win.width) |x| {
        writeAscii(win, @intCast(x), y, "-", .{ .fg = color });
    }

    // Draw centered label
    if (label.len > 0 and win.width > label.len + 4) {
        const label_x: u16 = @intCast((win.width - label.len) / 2);
        writeAscii(win, label_x, y, label, .{ .fg = color, .bold = focused });
    }
}
```

- [ ] **Step 3: Implement `drawLogs`**

Add after `drawBorder`:

```zig
fn drawLogs(win: vaxis.Window, start_row: u16, pane_height: u16, logs_auto: bool, scroll: usize) void {
    const dim_red: vaxis.Color = .{ .rgb = .{ 0xc9, 0x5f, 0x5f } };
    const yellow: vaxis.Color = .{ .rgb = .{ 0xd2, 0x9e, 0x22 } };
    const default_fg: vaxis.Color = .{ .rgb = .{ 0xc9, 0xd1, 0xd9 } };

    const total_lines = subprocess.getLineCount();
    if (total_lines == 0) {
        printAt(win, 2, start_row, "no log output yet", .{ .fg = .{ .rgb = .{ 0x6e, 0x76, 0x81 } } });
        return;
    }

    const visible = @min(pane_height, total_lines);

    // Determine which lines to show
    const display_start: usize = if (logs_auto)
        total_lines -| visible
    else
        @min(scroll, total_lines -| visible);

    var line_buf: [128]subprocess.LogLine = undefined;
    const fetched = subprocess.copyRange(&line_buf, display_start, visible);

    for (0..fetched) |i| {
        const row = start_row + @as(u16, @intCast(i));
        if (row >= win.height -| 1) break;

        const line = &line_buf[i];
        const text = line.bytes[0..line.len];
        const truncated = text[0..@min(text.len, win.width -| 2)];

        const style: vaxis.Style = if (line.synthetic)
            .{ .fg = yellow, .bold = true }
        else if (line.source == .stderr)
            .{ .fg = dim_red }
        else
            .{ .fg = default_fg };

        writeAscii(win, 2, row, truncated, style);
    }
}
```

- [ ] **Step 4: Modify the draw loop for split-pane layout**

In `run()`, replace the `.list` draw block (around line 784-796) with:

```zig
.list => {
    const header_rows = drawHeader(win, domain, proxy_text, ca_text, raw_count, req_autoscroll, routes);
    const footer_h: u16 = 2; // footer + search/intercept bar
    const body_h = if (win.height > header_rows + footer_h) win.height - header_rows - footer_h else 1;

    if (logs_visible) {
        // Split layout: 60% requests, 40% logs, 2 rows for borders
        const border_rows: u16 = 2;
        const usable = if (body_h > border_rows) body_h - border_rows else 1;
        const req_h: u16 = @max(1, usable * 60 / 100);
        const logs_h: u16 = if (usable > req_h) usable - req_h else 1;

        // Requests border + pane
        drawBorder(win, header_rows, "", focus == .requests);
        const req_start = header_rows + 1;

        // Create a child window for the requests pane so drawRequests is clipped
        const req_win = win.child(.{
            .x_off = 0,
            .y_off = req_start,
            .width = win.width,
            .height = req_h,
        });
        // Adjust scroll to keep cursor visible within req_h
        if (cursor < scroll_offset) {
            scroll_offset = cursor;
        } else if (cursor >= scroll_offset + req_h) {
            scroll_offset = cursor - req_h + 1;
        }
        // Pass req_win with start_row=0 (drawing relative to the child window)
        drawRequests(req_win, buf_slice, &filter_map, filtered_count, 0, scroll_offset, cursor, req_autoscroll, show_help, search_mode, search_term, intercept_mode, intercept_buf[0..intercept_len]);

        // Logs border + pane
        const logs_border_y = req_start + req_h;
        var label_buf: [32]u8 = undefined;
        const label = if (logs_autoscroll)
            (std.fmt.bufPrint(&label_buf, " logs (autoscroll) ", .{}) catch " logs ")
        else
            " logs ";
        drawBorder(win, logs_border_y, label, focus == .logs);
        drawLogs(win, logs_border_y + 1, logs_h, logs_autoscroll, logs_scroll);
    } else {
        // Original single-pane layout (unchanged from current code)
        const available_rows = if (win.height > header_rows + 2) win.height - header_rows - 2 else 1;
        if (cursor < scroll_offset) {
            scroll_offset = cursor;
        } else if (cursor >= scroll_offset + available_rows) {
            scroll_offset = cursor - available_rows + 1;
        }
        drawRequests(win, buf_slice, &filter_map, filtered_count, header_rows, scroll_offset, cursor, req_autoscroll, show_help, search_mode, search_term, intercept_mode, intercept_buf[0..intercept_len]);
    }
},
```

**Important:** `drawRequests` currently draws its own footer/search bar/intercept bar at `win.height - 1`. When using a child window in split mode, `req_win.height` is `req_h`, so the footer will be drawn at the bottom of the requests pane — which is correct for split mode. However, in split mode the footer/search/intercept bars should be drawn in the main `win` below the logs pane, not inside `req_win`. The implementer should extract footer/search/intercept bar drawing out of `drawRequests` into the `run()` draw loop, or conditionally skip drawing them inside `drawRequests` when in split mode (e.g., pass a `draw_footer: bool` parameter). The footer in the main window should be drawn at `win.height - 1` regardless of split mode.

This is the most complex task. Take time to get the clipping right.

- [ ] **Step 5: Verify compilation and visual sanity**

Run: `zig build`
Expected: Compiles.

Manual visual check: `zig-out/bin/zlodev start --command="echo hello"` should show the split layout. This will be thoroughly tested in Task 9.

---

### Task 8: Keybinding Changes

**Files:**
- Modify: `src/tui.zig:492-594` (list view key handling)

- [ ] **Step 1: Add `l` key — toggle logs pane**

In the list view key handling (after `key.matches('q', .{})` around line 494), add:

```zig
if (key.matches('l', .{}) and has_command) {
    logs_visible = !logs_visible;
    if (!logs_visible) focus = .requests;
    continue;
}
```

- [ ] **Step 2: Add `Tab` key — switch focus**

In the list view key handling. Note: `Tab` is already used in `.edit` view for field switching (line 701), but in `.list` view it's unused. Add:

```zig
if (key.matches(vaxis.Key.tab, .{}) and logs_visible) {
    focus = if (focus == .requests) .logs else .requests;
    continue;
}
```

- [ ] **Step 3: Make `j`/`k`/`g`/`G` focus-dependent**

Replace the existing `j`/`k` handlers (lines 502-505) with:

```zig
if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
    if (focus == .logs and logs_visible) {
        logs_scroll +|= 1;
        logs_autoscroll = false;
    } else {
        cursor +|= 1;
    }
}
if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
    if (focus == .logs and logs_visible) {
        logs_scroll -|= 1;
        logs_autoscroll = false;
    } else {
        cursor -|= 1;
    }
}
```

Replace `G`/`g` handlers (lines 506-509):

```zig
if (key.matches('G', .{})) {
    if (focus == .logs and logs_visible) {
        const total = subprocess.getLineCount();
        logs_scroll = total;
    } else {
        cursor = std.math.maxInt(usize);
    }
}
if (key.matches('g', .{})) {
    if (focus == .logs and logs_visible) {
        logs_scroll = 0;
    } else {
        cursor = 0;
    }
}
```

- [ ] **Step 4: Make `s` focus-dependent**

Replace the existing `s` handler (line 500-501):

```zig
if (key.matches('s', .{})) {
    if (focus == .logs and logs_visible) {
        logs_autoscroll = !logs_autoscroll;
    } else {
        req_autoscroll = !req_autoscroll;
    }
}
```

- [ ] **Step 5: Make `R` focus-dependent in list view**

The existing `R` handler at line 575 does quick replay. Replace it with:

```zig
if (key.matches('R', .{})) {
    if (focus == .logs and logs_visible and has_command) {
        subprocess.restart();
        const msg = "Restarting...";
        @memcpy(flash_buf[0..msg.len], msg);
        flash_len = msg.len;
        flash_time = std.time.milliTimestamp();
    } else if (filtered_count > 0) {
        replayEntry(filter_map[cursor]);
        const msg = "Replayed!";
        @memcpy(flash_buf[0..msg.len], msg);
        flash_len = msg.len;
        flash_time = std.time.milliTimestamp();
    }
}
```

The detail view `R` handler (line 643) stays unchanged — detail is always fullscreen, no logs focus.

- [ ] **Step 6: Verify compilation**

Run: `zig build`
Expected: Compiles with no errors.

---

### Task 9: Help Overlay and Footer Updates

**Files:**
- Modify: `src/tui.zig:1388-1508` (footer, help overlay)

- [ ] **Step 1: Update footer to show logs-related keys**

In `drawFooter` (line 1388), modify to conditionally show extra keys:

```zig
fn drawFooter(win: vaxis.Window, _: bool, show_help: bool, has_cmd: bool) void {
    const dim: vaxis.Color = .{ .rgb = .{ 0x6e, 0x76, 0x81 } };
    const footer_row = win.height -| 1;
    if (has_cmd) {
        printAt(win, 2, footer_row, "? help  l: logs  tab: focus  R: restart", .{ .fg = dim });
    } else {
        printAt(win, 2, footer_row, "? help", .{ .fg = dim });
    }
    if (show_help) drawHelpOverlay(win, .list);
}
```

Update all `drawFooter` call sites to pass `has_command`.

- [ ] **Step 2: Add logs keys to help overlay**

In `drawHelpOverlay` (line 1410), add a logs section. Add new entries to the `list_keys` array:

```zig
.{ .key = "l", .desc = "toggle logs pane" },
.{ .key = "Tab", .desc = "switch focus (req/logs)" },
```

Also update the `R` entry description to note the focus behavior when a command is configured:

```zig
.{ .key = "R", .desc = "replay / restart (focus)" },
```

- [ ] **Step 3: Verify compilation**

Run: `zig build`
Expected: Compiles.

---

### Task 10: Integration Testing and Polish

**Files:**
- All modified files

This task is manual testing per the spec's testing strategy.

- [ ] **Step 1: Test basic command execution**

Run: `sudo zig-out/bin/zlodev start --command="sh -c 'while true; do echo tick; sleep 1; done'"`

Verify:
- Logs pane visible on launch at bottom 40%
- Lines appear at ~1 Hz
- Border shows "logs (autoscroll)"
- Requests pane border is bright (focused), logs border is dim

- [ ] **Step 2: Test focus switching and scrolling**

Press `Tab` — verify border colors swap.
Press `j`/`k` while focused on logs — verify scroll and autoscroll disables.
Press `s` while focused on logs — verify logs autoscroll toggles independently.
Press `g` — jump to top of logs.
Press `G` — jump to bottom of logs.
Press `Tab` back to requests — verify `j`/`k` scroll requests again.

- [ ] **Step 3: Test `l` toggle**

Press `l` — logs pane hides, layout returns to single-pane (identical to current TUI).
Press `l` — logs pane reappears with prior state.

- [ ] **Step 4: Test process exit and restart**

Run: `sudo zig-out/bin/zlodev start --command="sh -c 'echo hi; exit 7'"`

Verify:
- `hi` line appears
- `[zlodev] exited (code 7)` appears in yellow/bold
- Process is not auto-restarted
- `Tab` to logs, press `R` — child respawns, new output appears

- [ ] **Step 5: Test failed command**

Run: `sudo zig-out/bin/zlodev start --command="nonexistent-binary-xyz"`

Verify:
- Error message appears in logs pane
- TUI is fully usable

- [ ] **Step 6: Test invalid combinations**

Run: `sudo zig-out/bin/zlodev start --dns --command="echo hi"`
Expected: Error message, exit code 1.

Run: `sudo zig-out/bin/zlodev start --no-tui --command="echo hi"`
Expected: Error message, exit code 1.

- [ ] **Step 7: Test detail view hides everything**

With command running and logs visible, press `Enter` on a request.
Verify: detail view is fullscreen, no logs pane visible.
Press `Esc` — verify split layout is restored.

- [ ] **Step 8: Test quit cleans up child**

Run with `--command="npm run dev"` (or any long-running process).
Press `q` to quit.
Verify: no orphan child processes remain (`ps aux | grep npm`).

- [ ] **Step 9: Test config file support**

Create `.zlodev` with:
```
port=3001
command=echo from-config
```

Run: `sudo zig-out/bin/zlodev start`
Verify: logs pane shows "from-config".

Run: `sudo zig-out/bin/zlodev start --command="echo from-cli"`
Verify: CLI value overrides config — shows "from-cli".

- [ ] **Step 10: Test terminal resize**

While logs are visible, resize the terminal window.
Verify: layout recomputes, no crash, scroll offsets stay reasonable.
