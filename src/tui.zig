const std = @import("std");
const rt = @import("rt.zig");
const win32 = @import("win32.zig");
const builtin = @import("builtin");
const vaxis = @import("vaxis");
const requests = @import("requests.zig");
const intercept = @import("intercept.zig");
const proxy = @import("proxy.zig");
const jsonfmt = @import("jsonfmt.zig");
const har = @import("har.zig");
const clipboard = @import("clipboard.zig");
const search = @import("search.zig");
const subprocess = @import("subprocess.zig");
const shutdown = @import("shutdown.zig");
const share = @import("share.zig");

pub const Event = union(enum) {
    key_press: vaxis.Key,
    winsize: vaxis.Winsize,
};

pub const panic = vaxis.panic_handler;

const View = enum { list, detail, edit };

const Focus = enum { requests, logs };

const EditField = enum(u8) { method = 0, path = 1, headers = 2, body = 3 };

const CommitOutcome = enum { accepted, replayed, failed };

const EditState = struct {
    active: bool = false,
    field: EditField = .method,
    hold: ?requests.EditableHold = null,
    // Editable buffers
    method_buf: [7]u8 = @splat(0),
    method_len: usize = 0,
    path_buf: [512]u8 = @splat(0),
    path_len: usize = 0,
    headers_buf: [requests.max_header_len]u8 = @splat(0),
    headers_len: usize = 0,
    body_buf: [requests.max_body_len]u8 = @splat(0),
    body_len: usize = 0,
    // Cursor position (byte offset into active field)
    cursor: usize = 0,
    // Scroll offset for multi-line fields
    scroll: usize = 0,
    intercepted: bool = false,
    resp_edit: bool = false, // true when editing response (vs request)

    fn activeSlice(self: *EditState) []u8 {
        return switch (self.field) {
            .method => self.method_buf[0..self.method_len],
            .path => self.path_buf[0..self.path_len],
            .headers => self.headers_buf[0..self.headers_len],
            .body => self.body_buf[0..self.body_len],
        };
    }

    fn activeLen(self: *const EditState) usize {
        return switch (self.field) {
            .method => self.method_len,
            .path => self.path_len,
            .headers => self.headers_len,
            .body => self.body_len,
        };
    }

    fn activeCap(self: *const EditState) usize {
        return switch (self.field) {
            .method => self.method_buf.len,
            .path => self.path_buf.len,
            .headers => self.headers_buf.len,
            .body => self.body_buf.len,
        };
    }

    fn setLen(self: *EditState, new_len: usize) void {
        switch (self.field) {
            .method => self.method_len = new_len,
            .path => self.path_len = new_len,
            .headers => self.headers_len = new_len,
            .body => self.body_len = new_len,
        }
    }

    fn isMultiline(self: *const EditState) bool {
        return self.field == .headers or self.field == .body;
    }

    fn insertChar(self: *EditState, ch: u8) void {
        const len = self.activeLen();
        if (len >= self.activeCap()) return;
        const buf = switch (self.field) {
            .method => &self.method_buf,
            .path => &self.path_buf,
            .headers => &self.headers_buf,
            .body => &self.body_buf,
        };
        // Shift right
        var i = len;
        while (i > self.cursor) : (i -= 1) {
            buf[i] = buf[i - 1];
        }
        buf[self.cursor] = ch;
        self.setLen(len + 1);
        self.cursor += 1;
    }

    fn insertNewline(self: *EditState) void {
        const len = self.activeLen();
        if (len + 2 > self.activeCap()) return;
        const buf = switch (self.field) {
            .method => &self.method_buf,
            .path => &self.path_buf,
            .headers => &self.headers_buf,
            .body => &self.body_buf,
        };
        // Shift right by 2 for \r\n
        var i = len + 1;
        while (i > self.cursor + 1) : (i -= 1) {
            buf[i] = buf[i - 2];
        }
        buf[self.cursor] = '\r';
        buf[self.cursor + 1] = '\n';
        self.setLen(len + 2);
        self.cursor += 2;
    }

    fn deleteBack(self: *EditState) void {
        if (self.cursor == 0) return;
        const len = self.activeLen();
        const buf = switch (self.field) {
            .method => &self.method_buf,
            .path => &self.path_buf,
            .headers => &self.headers_buf,
            .body => &self.body_buf,
        };
        // Check if deleting \r\n pair
        const del_count: usize = if (self.cursor >= 2 and buf[self.cursor - 2] == '\r' and buf[self.cursor - 1] == '\n') 2 else 1;
        // Shift left
        var i = self.cursor - del_count;
        while (i < len - del_count) : (i += 1) {
            buf[i] = buf[i + del_count];
        }
        self.setLen(len - del_count);
        self.cursor -= del_count;
    }

    fn deleteForward(self: *EditState) void {
        const len = self.activeLen();
        if (self.cursor >= len) return;
        const buf = switch (self.field) {
            .method => &self.method_buf,
            .path => &self.path_buf,
            .headers => &self.headers_buf,
            .body => &self.body_buf,
        };
        const del_count: usize = if (self.cursor + 1 < len and buf[self.cursor] == '\r' and buf[self.cursor + 1] == '\n') 2 else 1;
        var i = self.cursor;
        while (i < len - del_count) : (i += 1) {
            buf[i] = buf[i + del_count];
        }
        self.setLen(len - del_count);
    }

    fn nextField(self: *EditState) void {
        self.field = switch (self.field) {
            .method => if (self.resp_edit) .headers else .path,
            .path => .headers,
            .headers => .body,
            .body => .method,
        };
        self.cursor = self.activeLen();
        self.scroll = 0;
    }

    fn prevField(self: *EditState) void {
        self.field = switch (self.field) {
            .method => .body,
            .path => .method,
            .headers => if (self.resp_edit) .method else .path,
            .body => .headers,
        };
        self.cursor = self.activeLen();
        self.scroll = 0;
    }

    fn loadFromEntry(self: *EditState, alloc: std.mem.Allocator, entry: *const requests.Entry, hold: requests.EditableHold, is_intercepted: bool) void {
        self.hold = hold;
        self.intercepted = is_intercepted;
        self.resp_edit = false;
        self.field = .method;
        self.cursor = 0;
        self.scroll = 0;
        self.method_len = entry.method_len;
        @memcpy(self.method_buf[0..entry.method_len], entry.method[0..entry.method_len]);
        self.path_len = entry.path_len;
        @memcpy(self.path_buf[0..entry.path_len], entry.path[0..entry.path_len]);
        self.headers_len = entry.req_headers_len;
        @memcpy(self.headers_buf[0..entry.req_headers_len], entry.req_headers[0..entry.req_headers_len]);
        // Try to pretty-print JSON body, else load it raw.
        const raw_body = entry.req_body[0..entry.req_body_len];
        if (jsonfmt.pretty(alloc, raw_body, &self.body_buf)) |len| {
            self.body_len = len;
        } else {
            self.body_len = entry.req_body_len;
            @memcpy(self.body_buf[0..entry.req_body_len], raw_body);
        }
        self.active = true;
    }

    /// Write the edited buffers back to the held entry through the hold, which
    /// re-checks the entry is still held before touching it. Returns false if the
    /// hold was resolved out from under the editor (nothing written).
    fn applyToEntry(self: *const EditState, alloc: std.mem.Allocator) bool {
        const hold = self.hold orelse return false;
        // Compact the (pretty-printed) body once, into a temp; ring ops do the locked write.
        var body_tmp: [requests.max_body_len]u8 = undefined;
        const body_slice: []const u8 = if (jsonfmt.compact(alloc, self.body_buf[0..self.body_len], &body_tmp)) |len|
            body_tmp[0..len]
        else
            self.body_buf[0..self.body_len];
        if (self.resp_edit) {
            // method_buf holds the status code string; keep the current status if unparseable.
            const status = std.fmt.parseInt(u16, self.method_buf[0..self.method_len], 10) catch hold.currentStatus();
            return hold.commitResponse(status, self.headers_buf[0..self.headers_len], body_slice);
        } else {
            return hold.commitRequest(self.method_buf[0..self.method_len], self.path_buf[0..self.path_len], self.headers_buf[0..self.headers_len], body_slice);
        }
    }

    fn loadResponseFromEntry(self: *EditState, alloc: std.mem.Allocator, entry: *const requests.Entry, hold: requests.EditableHold) void {
        self.hold = hold;
        self.intercepted = true;
        self.resp_edit = true;
        self.field = .method; // method_buf holds status code
        self.cursor = 0;
        self.scroll = 0;
        // Store status code as string in method_buf
        var status_buf: [7]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{entry.status}) catch "0";
        @memcpy(self.method_buf[0..status_str.len], status_str);
        self.method_len = status_str.len;
        // Path is unused for response edit
        self.path_len = 0;
        // Response headers
        self.headers_len = entry.resp_headers_len;
        @memcpy(self.headers_buf[0..entry.resp_headers_len], entry.resp_headers[0..entry.resp_headers_len]);
        // Response body (try to pretty-print JSON, else load it raw).
        const raw_body = entry.resp_body[0..entry.resp_body_len];
        if (jsonfmt.pretty(alloc, raw_body, &self.body_buf)) |len| {
            self.body_len = len;
        } else {
            self.body_len = entry.resp_body_len;
            @memcpy(self.body_buf[0..entry.resp_body_len], raw_body);
        }
        self.active = true;
    }

    /// Open the editor for the entry at `logical` (the `e` action). Resolves the
    /// index, classifies the phase, snapshots the held entry off the lock, and loads
    /// it in request- or response-edit mode. Returns false (caller stays in list) for
    /// a missing entry or a completed response, which can't be edited.
    fn open(self: *EditState, alloc: std.mem.Allocator, logical: usize) bool {
        const hold = requests.editHeld(logical) orelse return false; // missing or response_done
        var snap: requests.Entry = undefined;
        hold.snapshot(&snap);
        switch (hold.phase) {
            .response_held => self.loadResponseFromEntry(alloc, &snap, hold),
            .request_held => self.loadFromEntry(alloc, &snap, hold, true),
            .request => self.loadFromEntry(alloc, &snap, hold, false),
            .response_done => unreachable, // editHeld returns null for this
        }
        return true;
    }

    /// Open the editor in replay mode (the `r` action): only plain request entries
    /// qualify. Returns false for anything held or response-oriented.
    fn openForReplay(self: *EditState, alloc: std.mem.Allocator, logical: usize) bool {
        const hold = requests.editHeld(logical) orelse return false;
        if (hold.phase != .request) return false; // only plain request entries replay
        var snap: requests.Entry = undefined;
        hold.snapshot(&snap);
        if (snap.requestTruncated()) return false; // would replay something else
        self.loadFromEntry(alloc, &snap, hold, false);
        return true;
    }

    /// Commit the edit (Ctrl-S). Intercepted entries are written back and accepted;
    /// completed entries are replayed with the edited values on a detached thread.
    fn commit(self: *const EditState, alloc: std.mem.Allocator) CommitOutcome {
        if (self.intercepted) {
            // Accept only if the write landed; a false return means the hold was
            // already resolved, so there is nothing left to accept.
            if (self.applyToEntry(alloc)) {
                if (self.hold) |h| h.accept();
            }
            return .accepted;
        }
        const replay_entry = std.heap.page_allocator.create(requests.Entry) catch return .failed;
        replay_entry.* = requests.Entry{ .timestamp = 0 };
        @memcpy(replay_entry.method[0..self.method_len], self.method_buf[0..self.method_len]);
        replay_entry.method_len = @intCast(self.method_len);
        @memcpy(replay_entry.path[0..self.path_len], self.path_buf[0..self.path_len]);
        replay_entry.path_len = @intCast(self.path_len);
        @memcpy(replay_entry.req_headers[0..self.headers_len], self.headers_buf[0..self.headers_len]);
        replay_entry.req_headers_len = @intCast(self.headers_len);
        @memcpy(replay_entry.req_body[0..self.body_len], self.body_buf[0..self.body_len]);
        replay_entry.req_body_len = @intCast(self.body_len);
        const thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, proxy.replay, .{replay_entry}) catch {
            std.heap.page_allocator.destroy(replay_entry);
            return .failed;
        };
        thread.detach();
        return .replayed;
    }

    /// Get cursor row and column from byte offset in a multi-line buffer
    fn cursorRowCol(self: *const EditState) struct { row: usize, col: usize } {
        const slice = switch (self.field) {
            .method => self.method_buf[0..self.method_len],
            .path => self.path_buf[0..self.path_len],
            .headers => self.headers_buf[0..self.headers_len],
            .body => self.body_buf[0..self.body_len],
        };
        var row: usize = 0;
        var col: usize = 0;
        for (0..self.cursor) |i| {
            if (i < slice.len and slice[i] == '\n') {
                row += 1;
                col = 0;
            } else if (i < slice.len and slice[i] == '\r') {
                // Skip carriage return — don't count as visible column
            } else {
                col += 1;
            }
        }
        return .{ .row = row, .col = col };
    }

    fn moveUp(self: *EditState) void {
        const slice = self.activeSlice();
        const rc = self.cursorRowCol();
        if (rc.row == 0) return;
        // Find start of current line
        var line_start = self.cursor;
        while (line_start > 0 and slice[line_start - 1] != '\n') : (line_start -= 1) {}
        // Find start of previous line
        var prev_line_start = if (line_start >= 2) line_start - 2 else 0;
        while (prev_line_start > 0 and slice[prev_line_start - 1] != '\n') : (prev_line_start -= 1) {}
        // Previous line length
        const prev_line_end = if (line_start >= 2) line_start - 2 else line_start;
        const prev_line_len = prev_line_end - prev_line_start;
        self.cursor = prev_line_start + @min(rc.col, prev_line_len);
    }

    fn moveDown(self: *EditState) void {
        const slice = self.activeSlice();
        const len = self.activeLen();
        // Find end of current line (\n or end of buffer)
        var pos = self.cursor;
        while (pos < len and slice[pos] != '\n') : (pos += 1) {}
        if (pos >= len) return; // already on last line
        // pos is at \n, next line starts at pos+1
        const next_line_start = pos + 1;
        // Find end of next line
        var next_line_end = next_line_start;
        while (next_line_end < len and slice[next_line_end] != '\r' and slice[next_line_end] != '\n') : (next_line_end += 1) {}
        const next_line_len = next_line_end - next_line_start;
        // Find current column
        var line_start = self.cursor;
        while (line_start > 0 and slice[line_start - 1] != '\n') : (line_start -= 1) {}
        const col = self.cursor - line_start;
        self.cursor = next_line_start + @min(col, next_line_len);
    }
};

/// Side effects reached from key handling that leave the process
/// (clipboard, files, network, child process). Tests swap them for fakes.
const Effects = struct {
    copyText: *const fn ([]const u8) bool = clipboard.copyText,
    copyAsCurl: *const fn (std.mem.Allocator, usize, []const u8) clipboard.CopyResult = clipboard.copyAsCurl,
    exportHar: *const fn ([]const u8, []const u8, bool, *[64]u8) ?usize = har.exportHar,
    replay: *const fn (usize) bool = replayEntry,
    restartSubprocess: *const fn () void = subprocess.restart,
};

/// Everything key handling and the per-frame refresh read or write.
/// Large (filter_map, edit_state): lives on run()'s stack, always passed by pointer.
const TuiState = struct {
    alloc: std.mem.Allocator,
    domain: []const u8,
    version: []const u8,
    routes: []const proxy.Route,
    has_command: bool,
    effects: Effects = .{},

    cursor: usize = 0,
    scroll_offset: usize = 0,
    req_autoscroll: bool = true,
    logs_visible: bool,
    focus: Focus = .requests,
    logs_scroll: usize = 0,
    logs_autoscroll: bool = true,
    view: View = .list,
    detail_scroll: usize = 0,
    detail_index: usize = 0,
    show_help: bool = false,
    show_body: bool = false,
    edit_state: EditState = .{},
    search_mode: bool = false,
    search_buf: [128]u8 = @splat(0),
    search_len: usize = 0,
    intercept_mode: bool = false,
    intercept_buf: [intercept.max_pattern_len]u8 = @splat(0),
    intercept_len: usize = 0,
    flash_buf: [128]u8 = undefined,
    flash_len: usize = 0,
    flash_time: i64 = 0, // timestamp when flash message was set
    har_fname_buf: [64]u8 = undefined,
    // On Windows, discard key events until after the first render — terminal
    // init can produce spurious events from escape sequence responses.
    accepting_input: bool = (builtin.os.tag != .windows),

    summaries: []requests.Summary,
    summary_count: usize = 0,
    // Maps filtered index -> index in summaries (= logical index)
    filter_map: [requests.max_entries]usize = undefined,
    filtered_count: usize = 0,
};

const KeyResult = enum { none, quit };

/// Applies one key press to the TUI state. `.quit` means leave the TUI.
fn handleKey(st: *TuiState, key: vaxis.Key) KeyResult {
    if (!st.accepting_input) return .none;

    // Search mode input handling
    if (st.search_mode) {
        if (key.matches(vaxis.Key.escape, .{})) {
            // Cancel search, clear filter
            st.search_mode = false;
            st.search_len = 0;
            st.cursor = 0;
            st.scroll_offset = 0;
        } else if (key.matches(vaxis.Key.enter, .{})) {
            // Confirm search, keep filter
            st.search_mode = false;
            st.cursor = 0;
            st.scroll_offset = 0;
        } else if (key.matches(vaxis.Key.backspace, .{})) {
            st.search_len -|= 1;
            st.cursor = 0;
            st.scroll_offset = 0;
        } else if (key.text) |text| {
            if (st.search_len + text.len <= st.search_buf.len) {
                @memcpy(st.search_buf[st.search_len .. st.search_len + text.len], text);
                st.search_len += text.len;
                st.cursor = 0;
                st.scroll_offset = 0;
            }
        }
        return .none;
    }

    // Intercept pattern input mode
    if (st.intercept_mode) {
        if (key.matches(vaxis.Key.escape, .{})) {
            st.intercept_mode = false;
            st.intercept_len = 0;
        } else if (key.matches(vaxis.Key.enter, .{})) {
            st.intercept_mode = false;
            intercept.enableWithPattern(st.intercept_buf[0..st.intercept_len]);
        } else if (key.matches(vaxis.Key.backspace, .{})) {
            st.intercept_len -|= 1;
        } else if (key.text) |text| {
            if (st.intercept_len + text.len <= st.intercept_buf.len) {
                @memcpy(st.intercept_buf[st.intercept_len .. st.intercept_len + text.len], text);
                st.intercept_len += text.len;
            }
        }
        return .none;
    }

    if (key.matches('?', .{})) {
        st.show_help = !st.show_help;
        return .none;
    }
    if (st.show_help and key.matches(vaxis.Key.escape, .{})) {
        st.show_help = false;
        return .none;
    }
    if (key.matches('l', .{}) and st.has_command) {
        st.logs_visible = !st.logs_visible;
        if (!st.logs_visible) st.focus = .requests;
        return .none;
    }
    if (key.matches(vaxis.Key.tab, .{}) and st.logs_visible and st.view != .edit) {
        st.focus = if (st.focus == .requests) .logs else .requests;
        return .none;
    }

    switch (st.view) {
        .list => {
            if (key.matches('q', .{})) return .quit;
            if (key.matches('/', .{})) {
                st.search_mode = true;
                st.search_len = 0;
                return .none;
            }
            if (key.matches('s', .{})) {
                if (st.focus == .logs and st.logs_visible) {
                    st.logs_autoscroll = !st.logs_autoscroll;
                } else {
                    st.req_autoscroll = !st.req_autoscroll;
                }
            }
            if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
                if (st.focus == .logs and st.logs_visible) {
                    st.logs_scroll +|= 1;
                    st.logs_autoscroll = false;
                } else {
                    st.cursor +|= 1;
                }
            }
            if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
                if (st.focus == .logs and st.logs_visible) {
                    st.logs_scroll -|= 1;
                    st.logs_autoscroll = false;
                } else {
                    st.cursor -|= 1;
                }
            }
            if (key.matches('G', .{})) {
                if (st.focus == .logs and st.logs_visible) {
                    const total = subprocess.getLineCount();
                    st.logs_scroll = total;
                } else {
                    st.cursor = st.filtered_count -| 1;
                }
            }
            if (key.matches('g', .{})) {
                if (st.focus == .logs and st.logs_visible) {
                    st.logs_scroll = 0;
                } else {
                    st.cursor = 0;
                }
            }
            if (key.matches(vaxis.Key.escape, .{})) {
                // Clear filter
                st.search_len = 0;
                st.cursor = 0;
                st.scroll_offset = 0;
            }
            if (key.matches(vaxis.Key.enter, .{})) {
                // Map filtered cursor to real logical index
                st.detail_index = search.selectedIndex(&st.filter_map, st.filtered_count, st.cursor) orelse return .none;
                st.detail_scroll = 0;
                st.view = .detail;
            }
            if (key.matches('i', .{})) {
                if (intercept.isEnabled()) {
                    intercept.toggle();
                } else {
                    st.intercept_mode = true;
                    st.intercept_len = 0;
                }
            }
            if (key.matches('a', .{}))
                acceptEntry(search.selectedIndex(&st.filter_map, st.filtered_count, st.cursor) orelse return .none);
            if (key.matches('A', .{}))
                intercept.acceptAll();
            if (key.matches('C', .{}))
                requests.clearAll();
            if (key.matches('*', .{})) {
                const bi = requests.logicalToBackingIndex(search.selectedIndex(&st.filter_map, st.filtered_count, st.cursor) orelse return .none) orelse return .none;
                requests.toggleStar(bi);
            }
            if (key.matches('d', .{}))
                dropOrDeleteEntry(search.selectedIndex(&st.filter_map, st.filtered_count, st.cursor) orelse return .none);
            if (key.matches('c', .{})) {
                const sel = search.selectedIndex(&st.filter_map, st.filtered_count, st.cursor) orelse return .none;
                const msg: []const u8 = switch (st.effects.copyAsCurl(st.alloc, sel, st.domain)) {
                    .copied => "Copied as curl!",
                    .truncated => "Request too large to copy: captured copy is truncated",
                    .missing => "",
                };
                @memcpy(st.flash_buf[0..msg.len], msg);
                st.flash_len = msg.len;
                st.flash_time = rt.milliTimestamp();
            }
            if (key.matches('u', .{})) {
                const msg = shareCopyFlash(&st.effects);
                if (msg.len > 0) {
                    @memcpy(st.flash_buf[0..msg.len], msg);
                    st.flash_len = msg.len;
                    st.flash_time = rt.milliTimestamp();
                }
            }
            if (key.matches('E', .{}) or key.matches('e', .{ .ctrl = true })) {
                const redact = key.matches('E', .{});
                if (st.effects.exportHar(st.version, st.domain, redact, &st.har_fname_buf)) |fname_len| {
                    const note = if (redact) " (cookies and auth redacted; Ctrl+E for full)" else " (full, includes cookies and auth)";
                    const flash = std.fmt.bufPrint(&st.flash_buf, "Exported {s}{s}", .{ st.har_fname_buf[0..fname_len], note }) catch st.flash_buf[0..0];
                    st.flash_len = flash.len;
                } else {
                    const msg = "Export failed";
                    @memcpy(st.flash_buf[0..msg.len], msg);
                    st.flash_len = msg.len;
                }
                st.flash_time = rt.milliTimestamp();
            }
            if (key.matches('r', .{})) {
                const sel = search.selectedIndex(&st.filter_map, st.filtered_count, st.cursor) orelse return .none;
                if (st.edit_state.openForReplay(st.alloc, sel)) {
                    st.view = .edit;
                } else if (sel < st.summary_count and st.summaries[sel].request_truncated) {
                    const msg = "Request too large to replay: captured copy is truncated";
                    @memcpy(st.flash_buf[0..msg.len], msg);
                    st.flash_len = msg.len;
                    st.flash_time = rt.milliTimestamp();
                }
            }
            if (key.matches('R', .{})) {
                if (st.focus == .logs and st.logs_visible and st.has_command) {
                    st.effects.restartSubprocess();
                    const msg = "Restarting...";
                    @memcpy(st.flash_buf[0..msg.len], msg);
                    st.flash_len = msg.len;
                    st.flash_time = rt.milliTimestamp();
                } else if (search.selectedIndex(&st.filter_map, st.filtered_count, st.cursor)) |sel| {
                    const msg: []const u8 = if (st.effects.replay(sel)) "Replayed!" else "Request too large to replay: captured copy is truncated";
                    @memcpy(st.flash_buf[0..msg.len], msg);
                    st.flash_len = msg.len;
                    st.flash_time = rt.milliTimestamp();
                }
            }
            if (key.matches('e', .{})) {
                if (st.edit_state.open(st.alloc, search.selectedIndex(&st.filter_map, st.filtered_count, st.cursor) orelse return .none)) st.view = .edit;
            }
        },
        .detail => {
            if (key.matches('q', .{}) or key.matches(vaxis.Key.escape, .{})) {
                st.view = .list;
            } else if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
                st.detail_scroll +|= 1;
            } else if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
                st.detail_scroll -|= 1;
            } else if (key.matches('n', .{}) or key.matches(vaxis.Key.right, .{})) {
                st.cursor +|= 1;
                st.detail_scroll = 0;
            } else if (key.matches('p', .{}) or key.matches(vaxis.Key.left, .{})) {
                st.cursor -|= 1;
                st.detail_scroll = 0;
            } else if (key.matches('G', .{})) {
                st.detail_scroll = std.math.maxInt(usize);
            } else if (key.matches('g', .{})) {
                st.detail_scroll = 0;
            } else if (key.matches('s', .{})) {
                st.req_autoscroll = !st.req_autoscroll;
            } else if (key.matches('i', .{})) {
                if (intercept.isEnabled()) {
                    intercept.toggle();
                } else {
                    st.intercept_mode = true;
                    st.intercept_len = 0;
                }
            } else if (key.matches('*', .{})) {
                const bi = requests.logicalToBackingIndex(st.detail_index) orelse return .none;
                requests.toggleStar(bi);
            } else if (key.matches('a', .{})) {
                acceptEntry(st.detail_index);
            } else if (key.matches('d', .{})) {
                dropOrDeleteEntry(st.detail_index);
            } else if (key.matches('c', .{})) {
                const msg: []const u8 = switch (st.effects.copyAsCurl(st.alloc, st.detail_index, st.domain)) {
                    .copied => "Copied as curl!",
                    .truncated => "Request too large to copy: captured copy is truncated",
                    .missing => "",
                };
                @memcpy(st.flash_buf[0..msg.len], msg);
                st.flash_len = msg.len;
                st.flash_time = rt.milliTimestamp();
            } else if (key.matches('u', .{})) {
                const msg = shareCopyFlash(&st.effects);
                if (msg.len > 0) {
                    @memcpy(st.flash_buf[0..msg.len], msg);
                    st.flash_len = msg.len;
                    st.flash_time = rt.milliTimestamp();
                }
            } else if (key.matches('r', .{})) {
                if (st.edit_state.openForReplay(st.alloc, st.detail_index)) {
                    st.view = .edit;
                } else if (st.detail_index < st.summary_count and st.summaries[st.detail_index].request_truncated) {
                    const msg = "Request too large to replay: captured copy is truncated";
                    @memcpy(st.flash_buf[0..msg.len], msg);
                    st.flash_len = msg.len;
                    st.flash_time = rt.milliTimestamp();
                }
            } else if (key.matches('R', .{})) {
                const msg: []const u8 = if (st.effects.replay(st.detail_index)) "Replayed!" else "Request too large to replay: captured copy is truncated";
                @memcpy(st.flash_buf[0..msg.len], msg);
                st.flash_len = msg.len;
                st.flash_time = rt.milliTimestamp();
            } else if (key.matches('b', .{})) {
                st.show_body = !st.show_body;
                st.detail_scroll = 0;
            } else if (key.matches('e', .{})) {
                if (st.edit_state.open(st.alloc, st.detail_index)) st.view = .edit;
            }
        },
        .edit => {
            if (key.matches(vaxis.Key.escape, .{})) {
                // Cancel edit
                st.edit_state.active = false;
                st.view = .list;
            } else if (key.matches('s', .{ .ctrl = true })) {
                if (st.edit_state.commit(st.alloc) == .replayed) {
                    const msg = "Replayed!";
                    @memcpy(st.flash_buf[0..msg.len], msg);
                    st.flash_len = msg.len;
                    st.flash_time = rt.milliTimestamp();
                }
                st.edit_state.active = false;
                st.view = .list;
            } else if (key.matches(vaxis.Key.tab, .{})) {
                st.edit_state.nextField();
            } else if (key.matches(vaxis.Key.tab, .{ .shift = true })) {
                st.edit_state.prevField();
            } else if (key.matches(vaxis.Key.left, .{})) {
                st.edit_state.cursor -|= 1;
            } else if (key.matches(vaxis.Key.right, .{})) {
                if (st.edit_state.cursor < st.edit_state.activeLen())
                    st.edit_state.cursor += 1;
            } else if (key.matches(vaxis.Key.home, .{})) {
                st.edit_state.cursor = 0;
            } else if (key.matches(vaxis.Key.end, .{})) {
                st.edit_state.cursor = st.edit_state.activeLen();
            } else if (key.matches(vaxis.Key.up, .{})) {
                if (st.edit_state.isMultiline()) {
                    st.edit_state.moveUp();
                }
            } else if (key.matches(vaxis.Key.down, .{})) {
                if (st.edit_state.isMultiline()) {
                    st.edit_state.moveDown();
                }
            } else if (key.matches(vaxis.Key.backspace, .{})) {
                st.edit_state.deleteBack();
            } else if (key.matches(vaxis.Key.delete, .{})) {
                st.edit_state.deleteForward();
            } else if (key.matches(vaxis.Key.enter, .{})) {
                if (st.edit_state.isMultiline()) {
                    st.edit_state.insertNewline();
                } else {
                    st.edit_state.nextField();
                }
            } else if (key.text) |text| {
                for (text) |ch| {
                    if (ch >= 32 and ch < 127) {
                        st.edit_state.insertChar(ch);
                    }
                }
            }
        },
    }
    return .none;
}

/// Per-frame refresh: copies summaries from the ring, applies the search
/// filter into filter_map, clamps the cursor to the filtered list.
fn refreshFrame(st: *TuiState) void {
    st.summary_count = requests.getSummaries(st.summaries);
    const raw_count = st.summary_count;
    const search_term = st.search_buf[0..st.search_len];
    st.filtered_count = 0;
    if (st.search_len > 0) {
        for (0..raw_count) |i| {
            if (search.entryMatchesSearch(&st.summaries[i], search_term)) {
                st.filter_map[st.filtered_count] = i;
                st.filtered_count += 1;
            }
        }
    } else {
        for (0..raw_count) |i| {
            st.filter_map[i] = i;
        }
        st.filtered_count = raw_count;
    }

    // Clamp cursor to filtered list (key handlers read it through search.selectedIndex)
    if (st.filtered_count > 0) {
        if (st.cursor >= st.filtered_count) st.cursor = st.filtered_count - 1;
    } else {
        st.cursor = 0;
    }
}

pub fn run(alloc: std.mem.Allocator, domain: []const u8, target_port: u16, routes: []const proxy.Route, has_command: bool, cert_warning: ?[]const u8, dns_warning: ?[]const u8, version: []const u8) !void {
    const proxy_text = try std.fmt.allocPrint(alloc, "https -> 127.0.0.1:{d}", .{target_port});
    defer alloc.free(proxy_text);
    const ca_text = try std.fmt.allocPrint(alloc, "http://{s}/ca", .{domain});
    defer alloc.free(ca_text);

    var tty_buf: [4096]u8 = undefined;
    var tty = try vaxis.Tty.init(rt.io(), &tty_buf);
    defer tty.deinit();

    var vx = try vaxis.init(rt.io(), alloc, rt.env_map.?, .{});
    defer {
        vx.deinit(alloc, tty.writer());
        tty.writer().flush() catch {};
        if (builtin.os.tag == .windows) {
            // vx.deinit sends escape sequences that trigger terminal responses.
            // Wait briefly for responses to arrive, then flush the console input
            // buffer before tty.deinit() re-enables ECHO_INPUT — otherwise the
            // response bytes (e.g. "0n") get echoed to the terminal.
            rt.sleepMs(50);
            if (win32.GetStdHandle(win32.STD_INPUT_HANDLE)) |h| _ = win32.FlushConsoleInputBuffer(h);
        }
    }

    var loop: vaxis.Loop(Event) = .init(rt.io(), &tty, &vx);
    try loop.start();
    defer loop.stop();

    try vx.enterAltScreen(tty.writer());
    // Skip terminal query on Windows — the response bytes leak through as
    // spurious key events and as "0n" printed on exit.
    if (builtin.os.tag != .windows) {
        try vx.queryTerminal(tty.writer(), .fromSeconds(1));
    }

    var st: TuiState = .{
        .alloc = alloc,
        .domain = domain,
        .version = version,
        .routes = routes,
        .has_command = has_command,
        .logs_visible = has_command,
        // Heap: [max_entries]Summary is ~300 KB, too big for a 1 MB main-thread stack.
        .summaries = try std.heap.page_allocator.alloc(requests.Summary, requests.max_entries),
    };
    defer std.heap.page_allocator.free(st.summaries);
    var last_count: usize = 0;
    const detail_entry = try std.heap.page_allocator.create(requests.Entry);
    defer std.heap.page_allocator.destroy(detail_entry);

    // SIGINT/SIGTERM set the shutdown flag; quit like `q` does.
    while (shutdown.isRunning()) {
        while (try loop.tryEvent()) |event| {
            switch (event) {
                .key_press => |key| {
                    if (key.matches('c', .{ .ctrl = true })) return;
                    if (handleKey(&st, key) == .quit) return;
                },
                .winsize => |ws| try vx.resize(alloc, tty.writer(), ws),
            }
        }

        const current_count = requests.getCount();

        const win = vx.window();
        win.clear();

        refreshFrame(&st);
        const raw_count = st.summary_count;
        const search_term = st.search_buf[0..st.search_len];

        if (st.req_autoscroll and current_count > last_count and st.filtered_count > 0) {
            st.cursor = st.filtered_count - 1;
            if (st.view == .detail) st.detail_scroll = 0;
        }
        last_count = current_count;

        share.checkTimeout(rt.milliTimestamp());

        switch (st.view) {
            .list => {
                const req_focused = !st.logs_visible or st.focus == .requests;
                const header_rows = drawHeader(win, domain, proxy_text, ca_text, cert_warning, dns_warning, raw_count, st.req_autoscroll, routes, req_focused);
                const footer_h: u16 = 2; // footer + search/intercept bar
                const body_h = if (win.height > header_rows + footer_h) win.height - header_rows - footer_h else 1;

                if (st.logs_visible) {
                    // Split layout: 60% requests, 40% logs, 1 row for border between panes
                    const border_rows: u16 = 1;
                    const usable = if (body_h > border_rows) body_h - border_rows else 1;
                    const req_h: u16 = @max(1, usable * 60 / 100);
                    const logs_h: u16 = if (usable > req_h) usable - req_h else 1;

                    const req_start = header_rows;

                    // Create a child window for the requests pane so drawRequests is clipped
                    const req_win = win.child(.{
                        .x_off = 0,
                        .y_off = req_start,
                        .width = win.width,
                        .height = req_h,
                    });
                    // Adjust scroll to keep cursor visible within req_h
                    if (st.cursor < st.scroll_offset) {
                        st.scroll_offset = st.cursor;
                    } else if (st.cursor >= st.scroll_offset + req_h) {
                        st.scroll_offset = st.cursor - req_h + 1;
                    }
                    // Pass req_win with start_row=0 (drawing relative to the child window), draw_footer=false
                    drawRequests(req_win, st.summaries[0..st.summary_count], &st.filter_map, st.filtered_count, 0, st.scroll_offset, st.cursor, st.req_autoscroll, st.show_help, st.search_mode, search_term, st.intercept_mode, st.intercept_buf[0..st.intercept_len], false, has_command);

                    // Logs border + pane
                    const logs_border_y = req_start + req_h;
                    var label_buf: [32]u8 = undefined;
                    const label = if (st.logs_autoscroll)
                        (std.fmt.bufPrint(&label_buf, " logs (autoscroll) ", .{}) catch " logs ")
                    else
                        " logs ";
                    drawBorder(win, logs_border_y, label, st.focus == .logs);
                    drawLogs(win, logs_border_y + 1, logs_h, st.logs_autoscroll, st.logs_scroll);

                    // Draw footer in main window below logs pane
                    if (st.intercept_mode)
                        drawInterceptBar(win, st.intercept_buf[0..st.intercept_len])
                    else if (st.search_mode or search_term.len > 0)
                        drawSearchBar(win, st.search_mode, search_term)
                    else
                        drawFooter(win, st.req_autoscroll, st.show_help, has_command);
                } else {
                    // Original single-pane layout (unchanged)
                    const available_rows = if (win.height > header_rows + 2) win.height - header_rows - 2 else 1;
                    if (st.cursor < st.scroll_offset) {
                        st.scroll_offset = st.cursor;
                    } else if (st.cursor >= st.scroll_offset + available_rows) {
                        st.scroll_offset = st.cursor - available_rows + 1;
                    }
                    drawRequests(win, st.summaries[0..st.summary_count], &st.filter_map, st.filtered_count, header_rows, st.scroll_offset, st.cursor, st.req_autoscroll, st.show_help, st.search_mode, search_term, st.intercept_mode, st.intercept_buf[0..st.intercept_len], true, has_command);
                }
            },
            .detail => {
                // Resolve filtered cursor to real logical index
                if (st.filtered_count > 0) {
                    st.detail_index = st.filter_map[st.cursor];
                }
                const entry: ?*const requests.Entry = if (st.filtered_count > 0 and requests.copyEntry(st.detail_index, detail_entry)) detail_entry else null;
                drawDetail(alloc, win, entry, st.detail_index, raw_count, st.req_autoscroll, &st.detail_scroll, st.show_help, st.show_body);
            },
            .edit => {
                drawEdit(win, &st.edit_state);
            },
        }

        // Flash message (top-right, visible for 2 seconds)
        if (st.flash_len > 0) {
            const now = rt.milliTimestamp();
            if (now - st.flash_time < 2000) {
                const col: u16 = @intCast(win.width -| (st.flash_len + 2));
                const green: vaxis.Color = .{ .rgb = .{ 0x3f, 0xb9, 0x50 } };
                writeAscii(win, col, 0, st.flash_buf[0..st.flash_len], .{ .fg = green, .bold = true });
            } else {
                st.flash_len = 0;
            }
        }

        try vx.render(tty.writer());
        st.accepting_input = true;
        rt.sleepMs(50);
    }
}

/// Flash text for the `u` key: copies the share URL when the tunnel is ready.
fn shareCopyFlash(effects: *const Effects) []const u8 {
    const snap = share.snapshot();
    switch (snap.status) {
        .off => return "",
        .ready => {
            var url_buf: [share.max_host_len + 8]u8 = undefined;
            const url = std.fmt.bufPrint(&url_buf, "https://{s}", .{snap.getHost()}) catch return "Share not ready";
            return if (effects.copyText(url)) "Copied share URL!" else "Clipboard unavailable";
        },
        else => return "Share not ready",
    }
}

fn drawShareRows(win: vaxis.Window, start_row: u16, routes: []const proxy.Route) u16 {
    const snap = share.snapshot();
    if (snap.status == .off) return start_row;
    const dim: vaxis.Color = .{ .rgb = .{ 0x6e, 0x76, 0x81 } };
    const blue: vaxis.Color = .{ .rgb = .{ 0x58, 0xa6, 0xff } };
    const yellow: vaxis.Color = .{ .rgb = .{ 0xe3, 0xb3, 0x41 } };
    var row = start_row;

    printAt(win, 2, row, "SHARE", .{ .fg = dim });
    switch (snap.status) {
        .starting => printAt(win, 11, row, "starting…", .{ .fg = dim }),
        .verifying => printAt(win, 11, row, "starting… waiting for Cloudflare", .{ .fg = dim }),
        .ready => {
            var url_buf: [share.max_host_len + 8]u8 = undefined;
            const url = std.fmt.bufPrint(&url_buf, "https://{s}", .{snap.getHost()}) catch "";
            writeAscii(win, 11, row, url, .{ .fg = blue });
            printAt(win, 11 + @as(u16, @intCast(url.len)), row, "  u: copy · public: anyone with this URL can reach your dev server", .{ .fg = yellow });
        },
        else => writeAscii(win, 11, row, snap.getReason(), .{ .fg = yellow, .bold = true }),
    }
    row += 1;

    if (snap.status == .starting or snap.status == .verifying or snap.status == .ready) {
        for (routes) |route| {
            const h = route.hostname orelse continue;
            if (route.kind != .path) continue;
            var buf: [192]u8 = undefined;
            const text = std.fmt.bufPrint(&buf, "public visitors can reach: {s} -> {s}:{d}", .{ route.pattern, h, route.port }) catch continue;
            writeAscii(win, 11, row, text, .{ .fg = yellow });
            row += 1;
        }
    }
    return row;
}

fn drawHeader(win: vaxis.Window, domain: []const u8, proxy_text: []const u8, ca_text: []const u8, cert_warning: ?[]const u8, dns_warning: ?[]const u8, req_count: usize, autoscroll: bool, routes: []const proxy.Route, req_focused: bool) u16 {
    const green: vaxis.Color = .{ .rgb = .{ 0x3f, 0xb9, 0x50 } };
    const dim: vaxis.Color = .{ .rgb = .{ 0x6e, 0x76, 0x81 } };
    const white: vaxis.Color = .{ .rgb = .{ 0xe1, 0xe4, 0xe8 } };
    const blue: vaxis.Color = .{ .rgb = .{ 0x58, 0xa6, 0xff } };

    var row: u16 = 1;

    printAt(win, 2, row, "zlodev", .{ .fg = white, .bold = true });
    row += 2;

    printAt(win, 2, row, "STATUS", .{ .fg = dim });
    printAt(win, 11, row, "running", .{ .fg = green, .bold = true });
    row += 1;

    printAt(win, 2, row, "DOMAIN", .{ .fg = dim });
    printAt(win, 11, row, domain, .{ .fg = blue });
    row += 1;

    printAt(win, 2, row, "PROXY", .{ .fg = dim });
    printAt(win, 11, row, proxy_text, .{ .fg = white });
    row += 1;

    // Show routes if configured
    for (routes, 0..) |route, i| {
        var route_buf: [128]u8 = undefined;
        const target_host = route.hostname orelse "127.0.0.1";
        const route_text = switch (route.kind) {
            .subdomain => std.fmt.bufPrint(&route_buf, "{s}.{s} -> {s}:{d}", .{ route.pattern, domain, target_host, route.port }) catch "",
            .path => std.fmt.bufPrint(&route_buf, "{s} -> {s}:{d}", .{ route.pattern, target_host, route.port }) catch "",
        };
        const color = route_palette[i % route_palette.len];
        printAt(win, 2, row, "ROUTE", .{ .fg = dim });
        writeAscii(win, 11, row, route_text, .{ .fg = color });
        row += 1;
    }

    printAt(win, 2, row, "CA", .{ .fg = dim });
    printAt(win, 11, row, ca_text, .{ .fg = blue });
    row += 1;

    // Stays for the session: the old leaf keeps working only until it expires.
    if (cert_warning) |warning| {
        const yellow: vaxis.Color = .{ .rgb = .{ 0xe3, 0xb3, 0x41 } };
        printAt(win, 2, row, "CERT", .{ .fg = dim });
        writeAscii(win, 11, row, warning, .{ .fg = yellow, .bold = true });
        row += 1;
    }
    // Checked once at start: rerunning install --dns while zlodev runs fixes it.
    if (dns_warning) |warning| {
        const yellow: vaxis.Color = .{ .rgb = .{ 0xe3, 0xb3, 0x41 } };
        printAt(win, 2, row, "DNS", .{ .fg = dim });
        writeAscii(win, 11, row, warning, .{ .fg = yellow, .bold = true });
        row += 1;
    }
    row = drawShareRows(win, row, routes);
    row += 1;

    // Requests header
    printAt(win, 2, row, "REQUESTS", .{ .fg = dim });
    var count_buf: [32]u8 = undefined;
    const count_text = std.fmt.bufPrint(&count_buf, " ({d})", .{req_count}) catch "";
    writeAscii(win, 10, row, count_text, .{ .fg = dim });
    var indicator_pos: u16 = 10 + @as(u16, @intCast(count_text.len)) + 1;
    if (autoscroll) {
        printAt(win, indicator_pos, row, "autoscroll", .{ .fg = .{ .rgb = .{ 0x3f, 0xb9, 0x50 } } });
        indicator_pos += 11;
    }
    if (intercept.isEnabled()) {
        const orange: vaxis.Color = .{ .rgb = .{ 0xd2, 0x9e, 0x22 } };
        printAt(win, indicator_pos, row, "intercept", .{ .fg = orange });
        var ipos = indicator_pos + 9;
        // Show phase and active pattern
        const i_phase = intercept.getPhase();
        if (i_phase != .both) {
            writeAscii(win, ipos, row, ":", .{ .fg = orange });
            ipos += 1;
            const phase_str = if (i_phase == .request) "req" else "resp";
            writeAscii(win, ipos, row, phase_str, .{ .fg = orange });
            ipos += @as(u16, @intCast(phase_str.len));
        }
        var pat_buf: [intercept.max_pattern_len]u8 = undefined;
        const pat = intercept.getPattern(&pat_buf);
        if (pat.len > 0) {
            writeAscii(win, ipos, row, ":", .{ .fg = orange });
            ipos += 1;
            writeAscii(win, ipos, row, pat, .{ .fg = orange });
            ipos += @as(u16, @intCast(pat.len));
        }
        const pending = intercept.getPendingCount();
        if (pending > 0) {
            var pending_buf: [32]u8 = undefined;
            const pending_text = std.fmt.bufPrint(&pending_buf, " ({d} held)", .{pending}) catch "";
            writeAscii(win, ipos, row, pending_text, .{ .fg = orange });
        }
    }
    row += 1;

    printAt(win, 2, row, "METHOD", .{ .fg = dim });
    printAt(win, 11, row, "STATUS", .{ .fg = dim });
    printAt(win, 19, row, "TIME", .{ .fg = dim });
    printAt(win, 28, row, "SIZE", .{ .fg = dim });
    printAt(win, 36, row, "PATH", .{ .fg = dim });
    row += 1;

    // Separator — focus color when requests pane is active
    if (row < win.height) {
        const sep_color: vaxis.Color = if (req_focused)
            .{ .rgb = .{ 0x5f, 0xaf, 0xff } }
        else
            .{ .rgb = .{ 0x4a, 0x4a, 0x4a } };
        const sep_width = win.width -| 2;
        for (0..sep_width) |i| {
            writeAscii(win, 2 + @as(u16, @intCast(i)), row, "-", .{ .fg = sep_color });
        }
        row += 1;
    }

    return row;
}

fn drawRequests(
    win: vaxis.Window,
    rows: []const requests.Summary,
    filter_map: []const usize,
    filtered_count: usize,
    start_row: u16,
    scroll_offset: usize,
    cursor: usize,
    autoscroll: bool,
    show_help: bool,
    search_mode: bool,
    search_term: []const u8,
    imode: bool,
    iterm: []const u8,
    draw_footer: bool,
    has_cmd: bool,
) void {
    if (filtered_count == 0) {
        const msg = if (search_term.len > 0) "no matching requests" else "no requests yet";
        printAt(win, 2, start_row, msg, .{ .fg = .{ .rgb = .{ 0x6e, 0x76, 0x81 } } });
        if (draw_footer) {
            if (imode)
                drawInterceptBar(win, iterm)
            else if (search_mode or search_term.len > 0)
                drawSearchBar(win, search_mode, search_term)
            else
                drawFooter(win, autoscroll, show_help, has_cmd);
        }
        return;
    }

    const available_rows = if (win.height > start_row + 2) win.height - start_row - 2 else 1;
    const visible = @min(available_rows, filtered_count -| scroll_offset);

    for (0..visible) |i| {
        const idx = scroll_offset + i;
        if (idx >= filtered_count) break;
        const entry = &rows[filter_map[idx]];
        const row = start_row + @as(u16, @intCast(i));
        if (row >= win.height -| 1) break;

        const selected = (idx == cursor);
        if (selected) {
            const sel_width = win.width -| 1;
            const sel_win = win.child(.{
                .x_off = 1,
                .y_off = @intCast(row),
                .width = sel_width,
                .height = 1,
            });
            sel_win.fill(.{
                .style = .{ .bg = .{ .rgb = .{ 0x1c, 0x2b, 0x3a } } },
            });
        }

        drawRequestLine(win, row, entry, selected);
    }

    if (draw_footer) {
        if (imode)
            drawInterceptBar(win, iterm)
        else if (search_mode or search_term.len > 0)
            drawSearchBar(win, search_mode, search_term)
        else
            drawFooter(win, autoscroll, show_help, has_cmd);
    }
}

fn drawRequestLine(win: vaxis.Window, row: u16, entry: *const requests.Summary, selected: bool) void {
    const dim: vaxis.Color = .{ .rgb = .{ 0x6e, 0x76, 0x81 } };
    const bg: vaxis.Color = if (selected) .{ .rgb = .{ 0x1c, 0x2b, 0x3a } } else .default;

    if (entry.starred) {
        writeAscii(win, 0, row, "*", .{ .fg = .{ .rgb = .{ 0xd2, 0x9e, 0x22 } }, .bg = bg, .bold = true });
    }
    if (selected) {
        printAt(win, 1, row, ">", .{ .fg = .{ .rgb = .{ 0x58, 0xa6, 0xff } }, .bg = bg, .bold = true });
    }

    const method_color = methodColor(entry.getMethod());
    if (entry.resp_intercepted) {
        printAt(win, 2, row, "↳", .{ .fg = dim, .bg = bg });
        writeAscii(win, 4, row, entry.getMethod(), .{ .fg = method_color, .bg = bg });
    } else {
        writeAscii(win, 2, row, entry.getMethod(), .{ .fg = method_color, .bg = bg, .bold = true });
    }

    // Came through the share tunnel: the free cell right before the path.
    if (entry.shared) writeAscii(win, 35, row, "^", .{ .fg = .{ .rgb = .{ 0xe3, 0xb3, 0x41 } }, .bg = bg, .bold = true });

    const orange: vaxis.Color = .{ .rgb = .{ 0xd2, 0x9e, 0x22 } };
    const red: vaxis.Color = .{ .rgb = .{ 0xf8, 0x51, 0x49 } };

    if (entry.state == .intercepted) {
        const hold_label = if (entry.resp_intercepted) "RESP" else "HOLD";
        writeAscii(win, 11, row, hold_label, .{ .fg = orange, .bg = bg, .bold = true });
    } else if (entry.state == .dropped) {
        writeAscii(win, 11, row, "DROP", .{ .fg = red, .bg = bg, .bold = true });
    } else if (entry.too_large_to_intercept) {
        writeAscii(win, 11, row, "BIG", .{ .fg = orange, .bg = bg, .bold = true });
    } else {
        var status_buf: [6]u8 = undefined;
        const status_text = std.fmt.bufPrint(&status_buf, "{d}", .{entry.status}) catch "?";
        const status_color = statusColor(entry.status);
        writeAscii(win, 11, row, status_text, .{ .fg = status_color, .bg = bg });
        // Answered by zlodev itself (upstream down, timeout, too large): mark it.
        if (entry.error_len > 0) writeAscii(win, 11 + @as(u16, @intCast(status_text.len)), row, "!", .{ .fg = red, .bg = bg, .bold = true });
    }

    var dur_buf: [16]u8 = undefined;
    const dur_text = if (entry.state == .intercepted) blk: {
        // Show live elapsed time for held requests
        const now = rt.milliTimestamp();
        const held_ms: u64 = if (now > entry.timestamp) @intCast(now - entry.timestamp) else 0;
        break :blk if (held_ms >= 1000)
            std.fmt.bufPrint(&dur_buf, "{d}s", .{held_ms / 1000}) catch "?"
        else
            std.fmt.bufPrint(&dur_buf, "{d}ms", .{held_ms}) catch "?";
    } else if (entry.duration_ms >= 1000)
        std.fmt.bufPrint(&dur_buf, "{d}s", .{entry.duration_ms / 1000}) catch "?"
    else
        std.fmt.bufPrint(&dur_buf, "{d}ms", .{entry.duration_ms}) catch "?";
    writeAscii(win, 19, row, dur_text, .{ .fg = dim, .bg = bg });

    // Show response body size: the full size as relayed (the capture holds at most 32KB)
    var size_buf: [10]u8 = undefined;
    const body_len = @max(entry.resp_body_total, entry.resp_body_len);
    const size_text = if (body_len == 0)
        "0B"
    else if (body_len >= 1048576)
        std.fmt.bufPrint(&size_buf, "{d}MB", .{body_len / 1048576}) catch ""
    else if (body_len >= 1024)
        std.fmt.bufPrint(&size_buf, "{d}KB", .{body_len / 1024}) catch ""
    else
        std.fmt.bufPrint(&size_buf, "{d}B", .{body_len}) catch "";
    writeAscii(win, 28, row, size_text, .{ .fg = dim, .bg = bg });

    const path = entry.getPath();
    const max_path = win.width -| 38;
    const display_path = if (path.len > max_path) path[0..max_path] else path;
    const path_color = routeColor(entry.route_index);
    writeAscii(win, 36, row, display_path, .{ .fg = path_color, .bg = bg });
}

fn drawDetail(alloc: std.mem.Allocator, win: vaxis.Window, entry: ?*const requests.Entry, index: usize, total_count: usize, autoscroll: bool, detail_scroll: *usize, show_help: bool, show_body: bool) void {
    const dim: vaxis.Color = .{ .rgb = .{ 0x6e, 0x76, 0x81 } };
    const white: vaxis.Color = .{ .rgb = .{ 0xe1, 0xe4, 0xe8 } };
    const blue: vaxis.Color = .{ .rgb = .{ 0x58, 0xa6, 0xff } };

    if (entry == null) {
        printAt(win, 2, 1, "request not found", .{ .fg = dim });
        drawDetailFooter(win, 0, 0, 0, false, show_help);
        return;
    }
    const e = entry.?;

    // Build lines into a fixed buffer
    var lines: [2048]DetailLine = undefined;
    var line_count: usize = 0;

    // Title line
    var title_buf: [64]u8 = undefined;
    const title = std.fmt.bufPrint(&title_buf, "Request {d}/{d}", .{ index + 1, total_count }) catch "Request";
    lines[line_count] = .{ .text = title, .style = .{ .fg = white, .bold = true } };
    line_count += 1;
    lines[line_count] = .{ .text = "", .style = .{} };
    line_count += 1;

    // Method + Path
    lines[line_count] = .{ .text = "REQUEST", .style = .{ .fg = blue, .bold = true } };
    line_count += 1;

    var method_path_buf: [600]u8 = undefined;
    var req_trunc_buf: [64]u8 = undefined;
    var resp_trunc_buf: [64]u8 = undefined;
    var error_buf: [200]u8 = undefined;
    const method_path = std.fmt.bufPrint(&method_path_buf, "{s} {s}", .{ e.getMethod(), e.getPath() }) catch "";
    lines[line_count] = .{ .text = method_path, .style = .{ .fg = white } };
    line_count += 1;
    if (e.path_truncated) {
        lines[line_count] = .{ .text = "... path truncated in view", .style = .{ .fg = dim } };
        line_count += 1;
    }
    lines[line_count] = .{ .text = "", .style = .{} };
    line_count += 1;

    // Status + Duration
    var status_buf: [32]u8 = undefined;
    const status_text = std.fmt.bufPrint(&status_buf, "Status: {d}", .{e.status}) catch "";
    lines[line_count] = .{ .text = status_text, .style = .{ .fg = statusColor(e.status) } };
    line_count += 1;

    var dur_buf: [32]u8 = undefined;
    const dur_text = if (e.duration_ms >= 1000)
        std.fmt.bufPrint(&dur_buf, "Duration: {d}s", .{e.duration_ms / 1000}) catch ""
    else
        std.fmt.bufPrint(&dur_buf, "Duration: {d}ms", .{e.duration_ms}) catch "";
    lines[line_count] = .{ .text = dur_text, .style = .{ .fg = dim } };
    line_count += 1;
    lines[line_count] = .{ .text = "", .style = .{} };
    line_count += 1;

    // Request headers
    const req_hdrs = e.getReqHeaders();
    if (req_hdrs.len > 0) {
        lines[line_count] = .{ .text = "REQUEST HEADERS", .style = .{ .fg = blue, .bold = true } };
        line_count += 1;
        line_count = splitHeaderLines(req_hdrs, &lines, line_count, .{ .fg = dim });
        if (e.req_headers_truncated) {
            lines[line_count] = .{ .text = "... truncated in view", .style = .{ .fg = dim } };
            line_count += 1;
        }
        lines[line_count] = .{ .text = "", .style = .{} };
        line_count += 1;
    }

    // zlodev answered this request itself: say why, above the (empty) response.
    if (e.error_len > 0) {
        const red: vaxis.Color = .{ .rgb = .{ 0xf8, 0x51, 0x49 } };
        const reason = std.fmt.bufPrint(&error_buf, "zlodev: {s}", .{e.getError()}) catch "zlodev: request failed";
        pushLine(&lines, &line_count, .{ .text = reason, .style = .{ .fg = red, .bold = true } });
        pushLine(&lines, &line_count, .{ .text = "", .style = .{} });
    }

    // Response headers
    const resp_hdrs = e.getRespHeaders();
    if (resp_hdrs.len > 0) {
        lines[line_count] = .{ .text = "RESPONSE HEADERS", .style = .{ .fg = blue, .bold = true } };
        line_count += 1;
        line_count = splitHeaderLines(resp_hdrs, &lines, line_count, .{ .fg = dim });
        if (e.resp_headers_truncated) {
            lines[line_count] = .{ .text = "... truncated in view", .style = .{ .fg = dim } };
            line_count += 1;
        }
    }

    // Bodies (toggled with 'b')
    if (show_body) {
        const req_body = e.getReqBody();
        if (req_body.len > 0) {
            pushLine(&lines, &line_count, .{ .text = "", .style = .{} });
            pushLine(&lines, &line_count, .{ .text = "REQUEST BODY", .style = .{ .fg = blue, .bold = true } });
            line_count = splitBodyLines(alloc, req_body, &req_body_scratch, &lines, line_count, .{ .fg = white });
            if (e.req_body_truncated) {
                pushLine(&lines, &line_count, .{ .text = std.fmt.bufPrint(&req_trunc_buf, "... truncated in view ({d} bytes total)", .{e.req_body_total}) catch "... truncated in view", .style = .{ .fg = dim } });
            }
        }

        const resp_body = e.getRespBody();
        if (resp_body.len > 0) {
            pushLine(&lines, &line_count, .{ .text = "", .style = .{} });
            pushLine(&lines, &line_count, .{ .text = "RESPONSE BODY", .style = .{ .fg = blue, .bold = true } });
            line_count = splitBodyLines(alloc, resp_body, &resp_body_scratch, &lines, line_count, .{ .fg = white });
            if (e.resp_body_truncated) {
                pushLine(&lines, &line_count, .{ .text = std.fmt.bufPrint(&resp_trunc_buf, "... truncated in view ({d} bytes total)", .{e.resp_body_total}) catch "... truncated in view", .style = .{ .fg = dim } });
            }
        }
    }

    // Clamp scroll
    const available_rows: usize = if (win.height > 2) win.height - 2 else 1;
    const max_scroll: usize = if (line_count > available_rows) line_count - available_rows else 0;
    if (detail_scroll.* > max_scroll)
        detail_scroll.* = max_scroll;

    // Render lines
    const visible = @min(available_rows, line_count -| detail_scroll.*);
    for (0..visible) |i| {
        const row: u16 = 1 + @as(u16, @intCast(i));
        if (row >= win.height -| 1) break;
        const line = lines[detail_scroll.* + i];
        writeAscii(win, 2, row, line.text, line.style);
    }

    drawDetailFooter(win, detail_scroll.*, max_scroll, line_count, autoscroll, show_help);
}

const DetailLine = struct {
    text: []const u8,
    style: vaxis.Style,
};

fn splitHeaderLines(headers: []const u8, lines: []DetailLine, start: usize, style: vaxis.Style) usize {
    var pos = start;
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |line| {
        if (pos >= lines.len) break;
        if (line.len == 0) continue;
        lines[pos] = .{ .text = line, .style = style };
        pos += 1;
    }
    return pos;
}

/// Backing store for pretty-printed JSON whose lines a DetailLine slice references.
/// Must outlive the draw, hence the fixed size; sized to hold an indented body.
const BodyScratch = [requests.max_body_len * 2]u8;

/// One scratch buffer per body pane, so the request and response bodies of the same
/// entry can both be pretty-printed in a frame without sharing storage. Single TUI
/// render thread, so no locking is needed.
var req_body_scratch: BodyScratch = undefined;
var resp_body_scratch: BodyScratch = undefined;

/// Split a response/request body into DetailLines. JSON is pretty-printed into the
/// caller-owned `scratch` (whose bytes the returned lines reference, so it must live
/// until the lines are rendered); anything else is split raw. Taking `scratch` as a
/// parameter — rather than a shared module buffer — lets the request and response
/// panes be formatted in the same frame without one clobbering the other's lines.
fn splitBodyLines(alloc: std.mem.Allocator, body: []const u8, scratch: []u8, lines: []DetailLine, start: usize, style: vaxis.Style) usize {
    if (jsonfmt.pretty(alloc, body, scratch)) |len|
        return splitRawBodyLines(scratch[0..len], lines, start, style);
    return splitRawBodyLines(body, lines, start, style);
}

fn splitRawBodyLines(body: []const u8, lines: []DetailLine, start: usize, style: vaxis.Style) usize {
    var pos = start;
    var iter = std.mem.splitScalar(u8, body, '\n');
    while (iter.next()) |line| {
        if (pos >= lines.len) break;
        const trimmed = if (line.len > 0 and line[line.len - 1] == '\r') line[0 .. line.len - 1] else line;
        lines[pos] = .{ .text = trimmed, .style = style };
        pos += 1;
    }
    return pos;
}

fn drawEdit(win: vaxis.Window, es: *EditState) void {
    const dim: vaxis.Color = .{ .rgb = .{ 0x6e, 0x76, 0x81 } };
    const white: vaxis.Color = .{ .rgb = .{ 0xe1, 0xe4, 0xe8 } };
    const blue: vaxis.Color = .{ .rgb = .{ 0x58, 0xa6, 0xff } };
    const yellow: vaxis.Color = .{ .rgb = .{ 0xd2, 0x9e, 0x22 } };
    const field_bg: vaxis.Color = .{ .rgb = .{ 0x16, 0x1b, 0x22 } };
    const active_bg: vaxis.Color = .{ .rgb = .{ 0x1c, 0x2b, 0x3a } };

    var row: u16 = 1;
    const title = if (es.resp_edit) "EDIT RESPONSE" else if (es.intercepted) "EDIT REQUEST" else "REPLAY REQUEST";
    printAt(win, 2, row, title, .{ .fg = yellow, .bold = true });
    row += 2;

    // Helper to draw a field label + content
    const FieldDesc = struct { label: []const u8, field: EditField, multiline: bool };
    const req_fields = [_]FieldDesc{
        .{ .label = "METHOD", .field = .method, .multiline = false },
        .{ .label = "PATH", .field = .path, .multiline = false },
        .{ .label = "HEADERS", .field = .headers, .multiline = true },
        .{ .label = "BODY", .field = .body, .multiline = true },
    };
    const resp_fields = [_]FieldDesc{
        .{ .label = "STATUS", .field = .method, .multiline = false },
        .{ .label = "HEADERS", .field = .headers, .multiline = true },
        .{ .label = "BODY", .field = .body, .multiline = true },
    };
    const fields: []const FieldDesc = if (es.resp_edit) &resp_fields else &req_fields;

    for (fields) |f| {
        if (row >= win.height -| 2) break;
        const is_active = (es.field == f.field);
        const label_color = if (is_active) blue else dim;
        printAt(win, 2, row, f.label, .{ .fg = label_color, .bold = is_active });
        row += 1;

        const content = switch (f.field) {
            .method => es.method_buf[0..es.method_len],
            .path => es.path_buf[0..es.path_len],
            .headers => es.headers_buf[0..es.headers_len],
            .body => es.body_buf[0..es.body_len],
        };
        const bg = if (is_active) active_bg else field_bg;

        if (f.multiline) {
            // Calculate which lines to show
            const max_lines: usize = if (f.field == .headers) 8 else 8;
            var line_starts: [512]usize = undefined;
            var line_count: usize = 0;
            line_starts[0] = 0;
            line_count = 1;
            for (content, 0..) |ch, idx| {
                if (ch == '\n' and line_count < line_starts.len) {
                    line_starts[line_count] = idx + 1;
                    line_count += 1;
                }
            }

            // Find cursor line for scroll
            var cursor_line: usize = 0;
            if (is_active) {
                for (0..line_count) |li| {
                    const start = line_starts[li];
                    const end = if (li + 1 < line_count) line_starts[li + 1] else content.len + 1;
                    if (es.cursor >= start and es.cursor < end) {
                        cursor_line = li;
                        break;
                    }
                }
                if (es.cursor >= content.len and line_count > 0) cursor_line = line_count - 1;
                // Adjust scroll
                if (cursor_line < es.scroll) es.scroll = cursor_line;
                if (cursor_line >= es.scroll + max_lines) es.scroll = cursor_line - max_lines + 1;
            }

            const vis_lines = @min(max_lines, line_count -| es.scroll);
            for (0..vis_lines) |li| {
                if (row >= win.height -| 2) break;
                const line_idx = es.scroll + li;
                const start = line_starts[line_idx];
                const end = if (line_idx + 1 < line_count) line_starts[line_idx + 1] else content.len;
                // Trim \r\n from display
                var display_end = end;
                if (display_end > start and content[display_end - 1] == '\n') display_end -= 1;
                if (display_end > start and content[display_end - 1] == '\r') display_end -= 1;
                const line_text = content[start..display_end];

                // Fill background
                const fw = win.width -| 3;
                const field_win = win.child(.{ .x_off = 3, .y_off = @intCast(row), .width = fw, .height = 1 });
                field_win.fill(.{ .style = .{ .bg = bg } });

                writeAscii(win, 3, row, line_text, .{ .fg = white, .bg = bg });

                // Draw cursor
                if (is_active and line_idx == cursor_line) {
                    const col_in_line = es.cursor - start;
                    const cursor_col: u16 = 3 + @as(u16, @intCast(@min(col_in_line, line_text.len)));
                    writeAscii(win, cursor_col, row, "_", .{ .fg = yellow, .bg = bg });
                }
                row += 1;
            }

            if (line_count == 0) {
                const fw = win.width -| 3;
                const field_win = win.child(.{ .x_off = 3, .y_off = @intCast(row), .width = fw, .height = 1 });
                field_win.fill(.{ .style = .{ .bg = bg } });
                if (is_active) writeAscii(win, 3, row, "_", .{ .fg = yellow, .bg = bg });
                row += 1;
            }
        } else {
            // Single line field
            const fw = win.width -| 3;
            const field_win = win.child(.{ .x_off = 3, .y_off = @intCast(row), .width = fw, .height = 1 });
            field_win.fill(.{ .style = .{ .bg = bg } });

            writeAscii(win, 3, row, content, .{ .fg = white, .bg = bg });
            if (is_active) {
                const cursor_col: u16 = 3 + @as(u16, @intCast(@min(es.cursor, content.len)));
                writeAscii(win, cursor_col, row, "_", .{ .fg = yellow, .bg = bg });
            }
            row += 1;
        }
        row += 1; // spacing between fields
    }

    // Footer
    const footer_row = win.height -| 1;
    const action = if (es.intercepted) "Ctrl+S accept" else "Ctrl+S replay";
    var footer_buf: [128]u8 = undefined;
    const footer_text = std.fmt.bufPrint(&footer_buf, "Tab next  Shift+Tab prev  {s}  Esc cancel", .{action}) catch "";
    writeAscii(win, 2, footer_row, footer_text, .{ .fg = dim });
}

fn drawInterceptBar(win: vaxis.Window, pattern: []const u8) void {
    const footer_row = win.height -| 1;
    const white: vaxis.Color = .{ .rgb = .{ 0xe1, 0xe4, 0xe8 } };
    const orange: vaxis.Color = .{ .rgb = .{ 0xd2, 0x9e, 0x22 } };

    writeAscii(win, 2, footer_row, "intercept:", .{ .fg = orange, .bold = true });
    writeAscii(win, 12, footer_row, pattern, .{ .fg = white });
    writeAscii(win, 12 + @as(u16, @intCast(pattern.len)), footer_row, "_", .{ .fg = orange });
}

fn drawSearchBar(win: vaxis.Window, search_mode: bool, search_term: []const u8) void {
    const footer_row = win.height -| 1;
    const dim: vaxis.Color = .{ .rgb = .{ 0x6e, 0x76, 0x81 } };
    const white: vaxis.Color = .{ .rgb = .{ 0xe1, 0xe4, 0xe8 } };
    const yellow: vaxis.Color = .{ .rgb = .{ 0xd2, 0x9e, 0x22 } };

    if (search_mode) {
        writeAscii(win, 2, footer_row, "/", .{ .fg = yellow, .bold = true });
        writeAscii(win, 3, footer_row, search_term, .{ .fg = white });
        // Cursor indicator
        writeAscii(win, 3 + @as(u16, @intCast(search_term.len)), footer_row, "_", .{ .fg = yellow });
    } else {
        // Filter active but not typing
        writeAscii(win, 2, footer_row, "/", .{ .fg = yellow });
        writeAscii(win, 3, footer_row, search_term, .{ .fg = dim });
        const clear_pos = 4 + @as(u16, @intCast(search_term.len));
        writeAscii(win, clear_pos, footer_row, "(Esc clear)", .{ .fg = dim });
    }
}

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

fn drawDetailFooter(win: vaxis.Window, scroll: usize, _: usize, total_lines: usize, _: bool, show_help: bool) void {
    const dim: vaxis.Color = .{ .rgb = .{ 0x6e, 0x76, 0x81 } };
    const footer_row = win.height -| 1;
    if (total_lines > 0) {
        var buf: [32]u8 = undefined;
        const pos_text = std.fmt.bufPrint(&buf, "? help  [{d}/{d}]", .{ scroll + 1, total_lines }) catch "? help";
        printAt(win, 2, footer_row, pos_text, .{ .fg = dim });
    } else {
        printAt(win, 2, footer_row, "? help", .{ .fg = dim });
    }
    if (show_help) drawHelpOverlay(win, .detail);
}

const HelpContext = enum { list, detail };

fn drawHelpOverlay(win: vaxis.Window, ctx: HelpContext) void {
    const dim: vaxis.Color = .{ .rgb = .{ 0x6e, 0x76, 0x81 } };
    const white: vaxis.Color = .{ .rgb = .{ 0xe1, 0xe4, 0xe8 } };
    const blue: vaxis.Color = .{ .rgb = .{ 0x58, 0xa6, 0xff } };
    const bg: vaxis.Color = .{ .rgb = .{ 0x0d, 0x11, 0x17 } };
    const border_color: vaxis.Color = .{ .rgb = .{ 0x30, 0x36, 0x3d } };

    const Entry = struct { key: []const u8, desc: []const u8 };

    const common_keys = [_]Entry{
        .{ .key = "j/k", .desc = "scroll" },
        .{ .key = "G", .desc = "go to end" },
        .{ .key = "g", .desc = "go to top" },
        .{ .key = "s", .desc = "toggle autoscroll" },
        .{ .key = "*", .desc = "star / unstar request" },
        .{ .key = "i", .desc = "intercept (pattern prompt / off)" },
        .{ .key = "d", .desc = "drop / delete" },
        .{ .key = "c", .desc = "copy as curl" },
        .{ .key = "u", .desc = "copy share URL" },
        .{ .key = "e", .desc = "edit request / response" },
        .{ .key = "r", .desc = "edit & replay" },
        .{ .key = "R", .desc = "replay / restart (focus)" },
        .{ .key = "E", .desc = "export HAR (secrets redacted)" },
        .{ .key = "Ctrl+E", .desc = "export HAR (full)" },
        .{ .key = "?", .desc = "close help" },
    };

    const list_keys = [_]Entry{
        .{ .key = "/", .desc = "search" },
        .{ .key = "Esc", .desc = "clear filter" },
        .{ .key = "Enter", .desc = "detail view" },
        .{ .key = "C", .desc = "clear all" },
        .{ .key = "a", .desc = "accept held" },
        .{ .key = "A", .desc = "accept all held" },
        .{ .key = "l", .desc = "toggle logs pane" },
        .{ .key = "Tab", .desc = "switch focus (req/logs)" },
        .{ .key = "q", .desc = "quit" },
    };

    const detail_keys = [_]Entry{
        .{ .key = "n/p", .desc = "next / prev request" },
        .{ .key = "b", .desc = "toggle body" },
        .{ .key = "a", .desc = "accept held" },
        .{ .key = "q/Esc", .desc = "back to list" },
    };

    const ctx_keys = if (ctx == .list) &list_keys else &detail_keys;
    const total = common_keys.len + ctx_keys.len;

    // Calculate overlay dimensions
    const box_w: u16 = 44;
    const box_h: u16 = @intCast(@min(total + 2, win.height -| 2)); // +2 for top border + bottom border
    const start_x: u16 = if (win.width > box_w) (win.width - box_w) / 2 else 0;
    const start_y: u16 = if (win.height > box_h) (win.height - box_h) / 2 else 0;

    // Draw background
    for (0..box_h) |dy| {
        const y: u16 = start_y + @as(u16, @intCast(dy));
        if (y >= win.height) break;
        for (0..box_w) |dx| {
            const x: u16 = start_x + @as(u16, @intCast(dx));
            if (x >= win.width) break;
            printAt(win, x, y, " ", .{ .bg = bg });
        }
    }

    // Top border
    {
        var border_buf: [48]u8 = undefined;
        const border_len = @min(box_w, border_buf.len);
        @memset(border_buf[0..border_len], '-');
        writeAscii(win, start_x, start_y, border_buf[0..border_len], .{ .fg = border_color, .bg = bg });
    }

    // Title
    const title = " Keybindings ";
    const title_x = start_x + (box_w -| @as(u16, @intCast(title.len))) / 2;
    writeAscii(win, title_x, start_y, title, .{ .fg = blue, .bg = bg, .bold = true });

    // Keys
    var row: u16 = start_y + 1;
    for (&common_keys) |entry| {
        if (row >= start_y + box_h - 1) break;
        writeAscii(win, start_x + 2, row, entry.key, .{ .fg = white, .bg = bg, .bold = true });
        writeAscii(win, start_x + 9, row, entry.desc, .{ .fg = dim, .bg = bg });
        row += 1;
    }
    for (ctx_keys) |entry| {
        if (row >= start_y + box_h - 1) break;
        writeAscii(win, start_x + 2, row, entry.key, .{ .fg = white, .bg = bg, .bold = true });
        writeAscii(win, start_x + 9, row, entry.desc, .{ .fg = dim, .bg = bg });
        row += 1;
    }

    // Bottom border
    {
        const bottom_y = start_y + box_h - 1;
        var border_buf: [48]u8 = undefined;
        const border_len = @min(box_w, border_buf.len);
        @memset(border_buf[0..border_len], '-');
        writeAscii(win, start_x, bottom_y, border_buf[0..border_len], .{ .fg = border_color, .bg = bg });
    }
}

fn methodColor(method: []const u8) vaxis.Color {
    if (std.mem.eql(u8, method, "GET")) return .{ .rgb = .{ 0x58, 0xa6, 0xff } };
    if (std.mem.eql(u8, method, "POST")) return .{ .rgb = .{ 0x3f, 0xb9, 0x50 } };
    if (std.mem.eql(u8, method, "PUT")) return .{ .rgb = .{ 0xd2, 0x9e, 0x22 } };
    if (std.mem.eql(u8, method, "PATCH")) return .{ .rgb = .{ 0xd2, 0x9e, 0x22 } };
    if (std.mem.eql(u8, method, "DELETE")) return .{ .rgb = .{ 0xf8, 0x51, 0x49 } };
    return .{ .rgb = .{ 0x8b, 0x94, 0x9e } };
}

fn statusColor(status: u16) vaxis.Color {
    if (status >= 200 and status < 300) return .{ .rgb = .{ 0x3f, 0xb9, 0x50 } };
    if (status >= 300 and status < 400) return .{ .rgb = .{ 0x58, 0xa6, 0xff } };
    if (status >= 400 and status < 500) return .{ .rgb = .{ 0xd2, 0x9e, 0x22 } };
    if (status >= 500) return .{ .rgb = .{ 0xf8, 0x51, 0x49 } };
    return .{ .rgb = .{ 0x8b, 0x94, 0x9e } };
}

// Distinct colors for route-matched paths in the request list.
// Index 0 is for the first --route, index 1 for the second, etc.
// Default (unrouted) paths stay white.
const route_palette = [_]vaxis.Color{
    .{ .rgb = .{ 0xbc, 0x8c, 0xff } }, // purple
    .{ .rgb = .{ 0x39, 0xd3, 0x53 } }, // green
    .{ .rgb = .{ 0xf0, 0x88, 0x3e } }, // orange
    .{ .rgb = .{ 0x58, 0xa6, 0xff } }, // blue
    .{ .rgb = .{ 0xf4, 0x78, 0x67 } }, // coral
    .{ .rgb = .{ 0x56, 0xd3, 0x64 } }, // lime
    .{ .rgb = .{ 0xe2, 0xb7, 0x14 } }, // gold
    .{ .rgb = .{ 0x6c, 0xb6, 0xff } }, // light blue
};

fn routeColor(route_index: u8) vaxis.Color {
    const white: vaxis.Color = .{ .rgb = .{ 0xe1, 0xe4, 0xe8 } };
    if (route_index == 0xff) return white;
    return route_palette[route_index % route_palette.len];
}

/// Write ASCII text character-by-character using writeCell.
/// Each character uses a comptime grapheme slice, so no dangling stack references.
fn writeAscii(win: vaxis.Window, x: u16, y: u16, text: []const u8, style: vaxis.Style) void {
    if (y >= win.height) return;
    for (text, 0..) |ch, i| {
        const col = x +| @as(u16, @intCast(i));
        if (col >= win.width) break;
        win.writeCell(@intCast(col), @intCast(y), .{
            .char = .{ .grapheme = grapheme(ch), .width = 1 },
            .style = style,
        });
    }
}

/// printAt for string literals and heap-allocated strings (stable references only).
fn printAt(win: vaxis.Window, x: u16, y: u16, text: []const u8, style: vaxis.Style) void {
    if (y >= win.height or x >= win.width) return;
    const child = win.child(.{
        .x_off = @intCast(x),
        .y_off = @intCast(y),
        .width = win.width -| x,
        .height = 1,
    });
    const segment: vaxis.Segment = .{ .text = text, .style = style };
    _ = child.print(&.{segment}, .{ .wrap = .none });
}

/// Returns a static slice for any byte value. Since the backing array is comptime,
/// the slices are valid for the lifetime of the program.
fn grapheme(ch: u8) []const u8 {
    const S = struct {
        const table: [256][1]u8 = blk: {
            var t: [256][1]u8 = undefined;
            for (0..256) |i| {
                t[i] = .{@as(u8, @intCast(i))};
            }
            break :blk t;
        };
    };
    return &S.table[ch];
}

/// Accept an intercepted request at the given logical index.
fn acceptEntry(logical: usize) void {
    const backing_idx = requests.logicalToBackingIndex(logical) orelse return;
    switch (requests.phaseOf(backing_idx)) {
        .request_held, .response_held => {},
        else => return,
    }
    intercept.resolve(backing_idx, .accept);
}

/// Drop an intercepted request or delete a completed request at the given logical index.
fn dropOrDeleteEntry(logical: usize) void {
    const backing_idx = requests.logicalToBackingIndex(logical) orelse return;
    switch (requests.phaseOf(backing_idx)) {
        .request_held, .response_held => intercept.resolve(backing_idx, .drop),
        // remove() no-ops on already-deleted entries.
        else => requests.remove(backing_idx),
    }
}

/// Append to the detail view's line buffer; once a long body has filled it, extra
/// lines (headings, truncation notes) are dropped instead of indexing past the end.
fn pushLine(lines: []DetailLine, count: *usize, line: DetailLine) void {
    if (count.* >= lines.len) return;
    lines[count.*] = line;
    count.* += 1;
}

/// Replay an entry on a detached thread. Returns false only when refused because
/// the captured request is truncated (replaying it would send something else).
fn replayEntry(logical: usize) bool {
    const copy = std.heap.page_allocator.create(requests.Entry) catch return true;
    if (!requests.copyEntry(logical, copy)) {
        std.heap.page_allocator.destroy(copy);
        return true;
    }
    if (copy.state == .intercepted or copy.resp_intercepted) {
        std.heap.page_allocator.destroy(copy);
        return true;
    }
    if (copy.requestTruncated()) {
        std.heap.page_allocator.destroy(copy);
        return false;
    }
    const thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, proxy.replay, .{
        copy,
    }) catch {
        std.heap.page_allocator.destroy(copy);
        return true;
    };
    thread.detach();
    return true;
}

// ---------------------------------------------------------------- tests

const TestScreen = struct {
    screen: vaxis.Screen,

    fn init(cols: u16, rows: u16) !TestScreen {
        return .{ .screen = try vaxis.Screen.init(std.testing.allocator, .{
            .rows = rows,
            .cols = cols,
            .x_pixel = 0,
            .y_pixel = 0,
        }) };
    }

    fn deinit(self: *TestScreen) void {
        self.screen.deinit(std.testing.allocator);
    }

    fn window(self: *TestScreen) vaxis.Window {
        return .{
            .x_off = 0,
            .y_off = 0,
            .parent_x_off = 0,
            .parent_y_off = 0,
            .width = self.screen.width,
            .height = self.screen.height,
            .screen = &self.screen,
        };
    }

    /// Concatenated cell graphemes of one row (empty cell = space), right-trimmed.
    /// Cells hold borrowed grapheme slices: draw code must pass stable text (see
    /// `printAt`). A test that reads garbage here has found a real draw bug.
    fn rowText(self: *TestScreen, row: u16, buf: []u8) []const u8 {
        var n: usize = 0;
        var col: u16 = 0;
        while (col < self.screen.width) : (col += 1) {
            const cell = self.screen.readCell(col, row) orelse break;
            const g = if (cell.char.grapheme.len == 0) " " else cell.char.grapheme;
            if (n + g.len > buf.len) @panic("rowText buffer too small");
            @memcpy(buf[n..][0..g.len], g);
            n += g.len;
            // The cell after a wide character is its continuation.
            if (cell.char.width == 2) col += 1;
        }
        return std.mem.trimEnd(u8, buf[0..n], " ");
    }

    /// True when any row contains `needle`.
    fn hasText(self: *TestScreen, needle: []const u8) bool {
        var buf: [1024]u8 = undefined;
        var row: u16 = 0;
        while (row < self.screen.height) : (row += 1) {
            if (std.mem.indexOf(u8, self.rowText(row, &buf), needle) != null) return true;
        }
        return false;
    }

    /// Number of rows containing `needle`.
    fn countText(self: *TestScreen, needle: []const u8) usize {
        var buf: [1024]u8 = undefined;
        var n: usize = 0;
        var row: u16 = 0;
        while (row < self.screen.height) : (row += 1) {
            if (std.mem.indexOf(u8, self.rowText(row, &buf), needle) != null) n += 1;
        }
        return n;
    }

    fn cellText(self: *TestScreen, col: u16, row: u16) []const u8 {
        const cell = self.screen.readCell(col, row) orelse return "";
        return cell.char.grapheme;
    }
};

test "tui: drawRequestLine shows method and path" {
    var ts = try TestScreen.init(120, 5);
    defer ts.deinit();
    var sum: requests.Summary = .{};
    @memcpy(sum.method[0..3], "GET");
    sum.method_len = 3;
    const path = "/api/x";
    @memcpy(sum.path[0..path.len], path);
    sum.path_len = path.len;
    sum.status = 200;

    drawRequestLine(ts.window(), 0, &sum, false);

    var buf: [1024]u8 = undefined;
    const text = ts.rowText(0, &buf);
    try std.testing.expect(std.mem.indexOf(u8, text, "GET") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "200") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "/api/x") != null);
}

fn testSummary(method: []const u8, path: []const u8, status: u16) requests.Summary {
    var sum: requests.Summary = .{};
    @memcpy(sum.method[0..method.len], method);
    sum.method_len = @intCast(method.len);
    @memcpy(sum.path[0..path.len], path);
    sum.path_len = @intCast(path.len);
    sum.status = status;
    return sum;
}

fn testHeader(win: vaxis.Window, cert: ?[]const u8, dns: ?[]const u8, routes: []const proxy.Route) u16 {
    return drawHeader(win, "dev.lo", "https://dev.lo -> :3000", "installed", cert, dns, 0, false, routes, true);
}

test "tui: header row count matches rows drawn" {
    share.resetForTest();
    defer share.resetForTest();
    var ts = try TestScreen.init(120, 24);
    defer ts.deinit();
    const base = testHeader(ts.window(), null, null, &.{});
    var buf: [1024]u8 = undefined;
    var last: u16 = 0;
    var row: u16 = 0;
    while (row < 24) : (row += 1) {
        if (ts.rowText(row, &buf).len > 0) last = row;
    }
    try std.testing.expect(base > last);

    var ts2 = try TestScreen.init(120, 24);
    defer ts2.deinit();
    const routes = [_]proxy.Route{.{ .kind = .path, .pattern = "/api", .port = 3001 }};
    const more = testHeader(ts2.window(), "cert expiring", "dns missing", &routes);
    try std.testing.expectEqual(base + 3, more);
    try std.testing.expect(ts2.hasText("ROUTE"));
    try std.testing.expect(ts2.hasText("CERT"));
    try std.testing.expect(ts2.hasText("DNS"));
}

test "tui: SHARE row absent when share is off" {
    share.resetForTest();
    defer share.resetForTest();
    var ts = try TestScreen.init(120, 24);
    defer ts.deinit();
    _ = testHeader(ts.window(), null, null, &.{});
    try std.testing.expect(!ts.hasText("SHARE"));
}

test "tui: SHARE row shows starting" {
    share.resetForTest();
    defer share.resetForTest();
    share.begin(0);
    var ts = try TestScreen.init(120, 24);
    defer ts.deinit();
    _ = testHeader(ts.window(), null, null, &.{});
    try std.testing.expect(ts.hasText("SHARE"));
    try std.testing.expect(ts.hasText("starting"));
}

test "tui: SHARE row shows waiting for Cloudflare" {
    share.resetForTest();
    defer share.resetForTest();
    share.begin(0);
    _ = share.publishHost("a-b.trycloudflare.com");
    var ts = try TestScreen.init(160, 24);
    defer ts.deinit();
    _ = testHeader(ts.window(), null, null, &.{});
    try std.testing.expect(ts.hasText("starting… waiting for Cloudflare"));
    try std.testing.expect(!ts.hasText("a-b.trycloudflare.com"));
}

test "tui: SHARE row shows the URL when ready" {
    share.resetForTest();
    defer share.resetForTest();
    share.begin(0);
    _ = share.publishHost("a-b.trycloudflare.com");
    _ = share.markVerified();
    var ts = try TestScreen.init(160, 24);
    defer ts.deinit();
    _ = testHeader(ts.window(), null, null, &.{});
    try std.testing.expect(ts.hasText("https://a-b.trycloudflare.com"));
    try std.testing.expect(ts.hasText("u: copy"));
}

test "tui: SHARE row shows failure and exit reasons" {
    share.resetForTest();
    defer share.resetForTest();
    share.begin(0);
    share.fail("boom");
    {
        var ts = try TestScreen.init(120, 24);
        defer ts.deinit();
        _ = testHeader(ts.window(), null, null, &.{});
        try std.testing.expect(ts.hasText("boom"));
    }
    share.resetForTest();
    share.begin(0);
    share.markExited(3);
    {
        var ts = try TestScreen.init(120, 24);
        defer ts.deinit();
        _ = testHeader(ts.window(), null, null, &.{});
        try std.testing.expect(ts.hasText("code 3"));
    }
}

test "tui: SHARE lists external path routes while verifying" {
    share.resetForTest();
    defer share.resetForTest();
    share.begin(0);
    _ = share.publishHost("a-b.trycloudflare.com");
    const routes = [_]proxy.Route{.{ .kind = .path, .pattern = "/api", .port = 443, .hostname = "staging.example.com" }};
    var ts = try TestScreen.init(120, 24);
    defer ts.deinit();
    const end = drawShareRows(ts.window(), 0, &routes);
    try std.testing.expectEqual(@as(u16, 2), end);
    try std.testing.expect(ts.hasText("/api -> staging.example.com:443"));
}

test "tui: SHARE lists external path routes only" {
    share.resetForTest();
    defer share.resetForTest();
    share.begin(0);
    const routes = [_]proxy.Route{
        .{ .kind = .path, .pattern = "/api", .port = 443, .hostname = "staging.example.com" },
        .{ .kind = .subdomain, .pattern = "api", .port = 443, .hostname = "staging.example.com" },
        .{ .kind = .path, .pattern = "/x", .port = 3001 },
    };
    var ts = try TestScreen.init(120, 24);
    defer ts.deinit();
    const end = drawShareRows(ts.window(), 0, &routes);
    try std.testing.expectEqual(@as(u16, 2), end);
    try std.testing.expectEqual(@as(usize, 1), ts.countText("public visitors can reach"));
    try std.testing.expect(ts.hasText("/api"));
    try std.testing.expect(!ts.hasText("/x"));
    try std.testing.expect(!ts.hasText("api."));
}

test "tui: request line markers" {
    var ts = try TestScreen.init(120, 5);
    defer ts.deinit();
    var sum = testSummary("GET", "/a", 200);
    sum.starred = true;
    drawRequestLine(ts.window(), 0, &sum, true);
    try std.testing.expectEqualStrings("*", ts.cellText(0, 0));
    try std.testing.expectEqualStrings(">", ts.cellText(1, 0));

    var err = testSummary("GET", "/a", 502);
    err.error_len = 5;
    drawRequestLine(ts.window(), 1, &err, false);
    var buf: [1024]u8 = undefined;
    try std.testing.expectEqualStrings("502!", ts.rowText(1, &buf)[11..15]);
}

test "tui: shared marker at column 35" {
    var ts = try TestScreen.init(120, 5);
    defer ts.deinit();
    var sum = testSummary("GET", "/a", 200);
    sum.shared = true;
    drawRequestLine(ts.window(), 0, &sum, false);
    try std.testing.expectEqualStrings("^", ts.cellText(35, 0));

    const plain = testSummary("GET", "/b", 200);
    drawRequestLine(ts.window(), 2, &plain, false);
    try std.testing.expect(!std.mem.eql(u8, "^", ts.cellText(35, 2)));

    var held = testSummary("OPTIONS", "/a", 0);
    held.shared = true;
    held.resp_intercepted = true;
    held.state = .intercepted;
    drawRequestLine(ts.window(), 1, &held, false);
    try std.testing.expectEqualStrings("^", ts.cellText(35, 1));
    var buf: [1024]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(u8, ts.rowText(1, &buf), "RESP") != null);
}

test "tui: hold, drop and big labels" {
    var ts = try TestScreen.init(120, 5);
    defer ts.deinit();
    var held = testSummary("GET", "/a", 0);
    held.state = .intercepted;
    drawRequestLine(ts.window(), 0, &held, false);
    var dropped = testSummary("GET", "/a", 0);
    dropped.state = .dropped;
    drawRequestLine(ts.window(), 1, &dropped, false);
    var big = testSummary("GET", "/a", 200);
    big.too_large_to_intercept = true;
    drawRequestLine(ts.window(), 2, &big, false);
    var buf: [1024]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(u8, ts.rowText(0, &buf), "HOLD") != null);
    try std.testing.expect(std.mem.indexOf(u8, ts.rowText(1, &buf), "DROP") != null);
    try std.testing.expect(std.mem.indexOf(u8, ts.rowText(2, &buf), "BIG") != null);
}

test "tui: help lists share and curl keys" {
    inline for (.{ HelpContext.list, HelpContext.detail }) |ctx| {
        var ts = try TestScreen.init(100, 40);
        defer ts.deinit();
        drawHelpOverlay(ts.window(), ctx);
        try std.testing.expect(ts.hasText("copy share URL"));
        try std.testing.expect(ts.hasText("copy as curl"));
    }
}

// ---------------------------------------------------------------- key tests

const KeyRec = struct {
    var copy_calls: usize = 0;
    var copied_buf: [256]u8 = undefined;
    var copied_len: usize = 0;
    var copy_result: bool = true;
    var curl_calls: usize = 0;
    var curl_index: usize = 0;

    fn reset() void {
        copy_calls = 0;
        copied_len = 0;
        copy_result = true;
        curl_calls = 0;
        curl_index = 0;
    }

    fn copyText(text: []const u8) bool {
        copy_calls += 1;
        copied_len = @min(text.len, copied_buf.len);
        @memcpy(copied_buf[0..copied_len], text[0..copied_len]);
        return copy_result;
    }

    fn copied() []const u8 {
        return copied_buf[0..copied_len];
    }

    fn copyAsCurl(_: std.mem.Allocator, logical: usize, _: []const u8) clipboard.CopyResult {
        curl_calls += 1;
        curl_index = logical;
        return .copied;
    }

    fn exportHar(_: []const u8, _: []const u8, _: bool, _: *[64]u8) ?usize {
        return null;
    }

    fn replay(_: usize) bool {
        return true;
    }

    fn restart() void {}
};

/// State wired to the recorder effects. Caller owns `summaries`
/// (`requests.max_entries` long, heap: ~300 KB).
fn testState(summaries: []requests.Summary) TuiState {
    KeyRec.reset();
    return .{
        .alloc = std.testing.allocator,
        .domain = "dev.lo",
        .version = "test",
        .routes = &.{},
        .has_command = false,
        .logs_visible = false,
        .summaries = summaries,
        .accepting_input = true,
        .effects = .{
            .copyText = KeyRec.copyText,
            .copyAsCurl = KeyRec.copyAsCurl,
            .exportHar = KeyRec.exportHar,
            .replay = KeyRec.replay,
            .restartSubprocess = KeyRec.restart,
        },
    };
}

/// A printable key as vaxis builds it: codepoint plus text.
fn pk(comptime cp: u8) vaxis.Key {
    return .{ .codepoint = cp, .text = &[_]u8{cp} };
}

fn nk(cp: u21) vaxis.Key {
    return .{ .codepoint = cp };
}

fn testSummaries() ![]requests.Summary {
    return std.testing.allocator.alloc(requests.Summary, requests.max_entries);
}

fn pushPath(path: []const u8) void {
    var e: requests.Entry = .{};
    @memcpy(e.method[0..3], "GET");
    e.method_len = 3;
    @memcpy(e.path[0..path.len], path);
    e.path_len = @intCast(path.len);
    e.status = 200;
    requests.push(e);
}

test "tui: q quits from the list" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    try std.testing.expectEqual(KeyResult.quit, handleKey(&st, pk('q')));
    try std.testing.expectEqual(KeyResult.none, handleKey(&st, pk('x')));
}

test "tui: help toggles with ? and closes with Escape" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    _ = handleKey(&st, pk('?'));
    try std.testing.expect(st.show_help);
    _ = handleKey(&st, pk('?'));
    try std.testing.expect(!st.show_help);
    _ = handleKey(&st, pk('?'));
    _ = handleKey(&st, nk(vaxis.Key.escape));
    try std.testing.expect(!st.show_help);
}

test "tui: search typing, backspace, escape and enter" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    _ = handleKey(&st, pk('/'));
    try std.testing.expect(st.search_mode);
    _ = handleKey(&st, pk('a'));
    _ = handleKey(&st, pk('b'));
    try std.testing.expectEqualStrings("ab", st.search_buf[0..st.search_len]);
    _ = handleKey(&st, nk(vaxis.Key.backspace));
    try std.testing.expectEqual(@as(usize, 1), st.search_len);
    st.cursor = 1;
    _ = handleKey(&st, nk(vaxis.Key.enter));
    try std.testing.expect(!st.search_mode);
    try std.testing.expectEqual(@as(usize, 1), st.search_len);
    try std.testing.expectEqual(@as(usize, 0), st.cursor);

    _ = handleKey(&st, pk('/'));
    _ = handleKey(&st, pk('x'));
    _ = handleKey(&st, nk(vaxis.Key.escape));
    try std.testing.expect(!st.search_mode);
    try std.testing.expectEqual(@as(usize, 0), st.search_len);
}

test "tui: search input stops at buffer size" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    _ = handleKey(&st, pk('/'));
    for (0..130) |_| _ = handleKey(&st, pk('a'));
    try std.testing.expectEqual(@as(usize, 128), st.search_len);
}

test "tui: intercept prompt enables the pattern on Enter" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    defer {
        if (intercept.isEnabled()) intercept.toggle();
        intercept.setPattern("");
    }

    _ = handleKey(&st, pk('i'));
    try std.testing.expect(st.intercept_mode);
    _ = handleKey(&st, pk('/'));
    _ = handleKey(&st, pk('a'));
    _ = handleKey(&st, pk('p'));
    _ = handleKey(&st, pk('i'));
    _ = handleKey(&st, nk(vaxis.Key.enter));
    try std.testing.expect(!st.intercept_mode);
    try std.testing.expect(intercept.isEnabled());
    var pbuf: [intercept.max_pattern_len]u8 = undefined;
    try std.testing.expectEqualStrings("/api", intercept.getPattern(&pbuf));
    intercept.toggle();

    _ = handleKey(&st, pk('i'));
    _ = handleKey(&st, pk('x'));
    _ = handleKey(&st, nk(vaxis.Key.escape));
    try std.testing.expect(!st.intercept_mode);
    try std.testing.expect(!intercept.isEnabled());
}

test "tui: u with share off leaves the flash alone" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    share.resetForTest();
    defer share.resetForTest();
    @memcpy(st.flash_buf[0..5], "hello");
    st.flash_len = 5;
    _ = handleKey(&st, pk('u'));
    try std.testing.expectEqualStrings("hello", st.flash_buf[0..st.flash_len]);
    try std.testing.expectEqual(@as(usize, 0), KeyRec.copy_calls);
}

test "tui: u before the URL says not ready" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    share.resetForTest();
    defer share.resetForTest();
    share.begin(0);
    _ = handleKey(&st, pk('u'));
    try std.testing.expectEqualStrings("Share not ready", st.flash_buf[0..st.flash_len]);
    try std.testing.expect(st.flash_time != 0);
    try std.testing.expectEqual(@as(usize, 0), KeyRec.copy_calls);
}

test "tui: u while verifying says not ready" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    share.resetForTest();
    defer share.resetForTest();
    share.begin(0);
    _ = share.publishHost("a-b.trycloudflare.com");
    _ = handleKey(&st, pk('u'));
    try std.testing.expectEqualStrings("Share not ready", st.flash_buf[0..st.flash_len]);
    try std.testing.expectEqual(@as(usize, 0), KeyRec.copy_calls);
}

test "tui: u copies the share URL" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    share.resetForTest();
    defer share.resetForTest();
    share.begin(0);
    _ = share.publishHost("a-b.trycloudflare.com");
    _ = share.markVerified();
    _ = handleKey(&st, pk('u'));
    try std.testing.expectEqualStrings("https://a-b.trycloudflare.com", KeyRec.copied());
    try std.testing.expectEqualStrings("Copied share URL!", st.flash_buf[0..st.flash_len]);
    try std.testing.expect(st.flash_time != 0);
}

test "tui: u reports a missing clipboard tool" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    share.resetForTest();
    defer share.resetForTest();
    share.begin(0);
    _ = share.publishHost("a-b.trycloudflare.com");
    _ = share.markVerified();
    KeyRec.copy_result = false;
    _ = handleKey(&st, pk('u'));
    try std.testing.expectEqualStrings("Clipboard unavailable", st.flash_buf[0..st.flash_len]);
}

test "tui: u in detail view copies the share URL" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    share.resetForTest();
    defer share.resetForTest();
    share.begin(0);
    _ = share.publishHost("a-b.trycloudflare.com");
    _ = share.markVerified();
    st.view = .detail;
    _ = handleKey(&st, pk('u'));
    try std.testing.expectEqualStrings("https://a-b.trycloudflare.com", KeyRec.copied());
    try std.testing.expectEqualStrings("Copied share URL!", st.flash_buf[0..st.flash_len]);
}

test "tui: c copies the selected entry as curl" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    requests.clearAll();
    defer requests.clearAll();
    pushPath("/one");
    pushPath("/two");
    refreshFrame(&st);
    st.cursor = 1;
    _ = handleKey(&st, pk('c'));
    try std.testing.expectEqual(@as(usize, 1), KeyRec.curl_calls);
    try std.testing.expectEqual(search.selectedIndex(&st.filter_map, st.filtered_count, 1).?, KeyRec.curl_index);
    try std.testing.expectEqualStrings("Copied as curl!", st.flash_buf[0..st.flash_len]);
}

test "tui: star toggles on the selected entry" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    requests.clearAll();
    defer requests.clearAll();
    pushPath("/one");
    refreshFrame(&st);
    _ = handleKey(&st, pk('*'));
    refreshFrame(&st);
    try std.testing.expect(st.summaries[0].starred);
    _ = handleKey(&st, pk('*'));
    refreshFrame(&st);
    try std.testing.expect(!st.summaries[0].starred);
}

test "tui: l and Tab only act with a dev server" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    _ = handleKey(&st, pk('l'));
    try std.testing.expect(!st.logs_visible);

    st.has_command = true;
    _ = handleKey(&st, pk('l'));
    try std.testing.expect(st.logs_visible);
    _ = handleKey(&st, nk(vaxis.Key.tab));
    try std.testing.expectEqual(Focus.logs, st.focus);
    _ = handleKey(&st, nk(vaxis.Key.tab));
    try std.testing.expectEqual(Focus.requests, st.focus);

    st.view = .edit;
    _ = handleKey(&st, nk(vaxis.Key.tab));
    try std.testing.expectEqual(Focus.requests, st.focus);

    st.view = .list;
    st.focus = .logs;
    _ = handleKey(&st, pk('l'));
    try std.testing.expect(!st.logs_visible);
    try std.testing.expectEqual(Focus.requests, st.focus);
    _ = handleKey(&st, nk(vaxis.Key.tab));
    try std.testing.expectEqual(Focus.requests, st.focus);
}

test "tui: j k g G move within the list" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    requests.clearAll();
    defer requests.clearAll();
    pushPath("/1");
    pushPath("/2");
    pushPath("/3");
    refreshFrame(&st);
    for (0..5) |_| _ = handleKey(&st, pk('j'));
    refreshFrame(&st);
    try std.testing.expectEqual(@as(usize, 2), st.cursor);
    _ = handleKey(&st, pk('k'));
    try std.testing.expectEqual(@as(usize, 1), st.cursor);
    _ = handleKey(&st, pk('g'));
    try std.testing.expectEqual(@as(usize, 0), st.cursor);
    _ = handleKey(&st, pk('G'));
    try std.testing.expectEqual(@as(usize, 2), st.cursor);
}

test "tui: list keys on an empty list are harmless" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    requests.clearAll();
    defer requests.clearAll();
    refreshFrame(&st);
    _ = handleKey(&st, pk('G'));
    try std.testing.expectEqual(@as(usize, 0), st.cursor);
    _ = handleKey(&st, nk(vaxis.Key.enter));
    try std.testing.expectEqual(View.list, st.view);
    try std.testing.expectEqual(KeyResult.none, handleKey(&st, pk('a')));
}

test "tui: refreshFrame clamps cursor to the filtered list" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    requests.clearAll();
    defer requests.clearAll();
    pushPath("/1");
    pushPath("/2");
    pushPath("/3");
    refreshFrame(&st);
    st.cursor = 2;
    requests.clearAll();
    pushPath("/1");
    refreshFrame(&st);
    try std.testing.expectEqual(@as(usize, 0), st.cursor);

    @memcpy(st.search_buf[0..3], "zzz");
    st.search_len = 3;
    refreshFrame(&st);
    try std.testing.expectEqual(@as(usize, 0), st.filtered_count);
    try std.testing.expectEqual(@as(usize, 0), st.cursor);
}

test "tui: keys ignored until accepting input" {
    const sums = try testSummaries();
    defer std.testing.allocator.free(sums);
    var st = testState(sums);
    st.accepting_input = false;
    try std.testing.expectEqual(KeyResult.none, handleKey(&st, pk('q')));
    _ = handleKey(&st, pk('?'));
    try std.testing.expect(!st.show_help);
}
