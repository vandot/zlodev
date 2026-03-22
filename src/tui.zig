const std = @import("std");
const builtin = @import("builtin");
const vaxis = @import("vaxis");
const requests = @import("requests.zig");
const intercept = @import("intercept.zig");
const proxy = @import("proxy.zig");
const har = @import("har.zig");
const clipboard = @import("clipboard.zig");
const search = @import("search.zig");

pub const Event = union(enum) {
    key_press: vaxis.Key,
    winsize: vaxis.Winsize,
};

pub const panic = vaxis.panic_handler;

const View = enum { list, detail, edit };

const EditField = enum(u8) { method = 0, path = 1, headers = 2, body = 3 };

const EditState = struct {
    active: bool = false,
    field: EditField = .method,
    backing_idx: usize = 0,
    // Editable buffers
    method_buf: [7]u8 = .{0} ** 7,
    method_len: usize = 0,
    path_buf: [512]u8 = .{0} ** 512,
    path_len: usize = 0,
    headers_buf: [requests.max_header_len]u8 = .{0} ** requests.max_header_len,
    headers_len: usize = 0,
    body_buf: [requests.max_body_len]u8 = .{0} ** requests.max_body_len,
    body_len: usize = 0,
    // Cursor position (byte offset into active field)
    cursor: usize = 0,
    // Scroll offset for multi-line fields
    scroll: usize = 0,
    intercepted: bool = false,

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
            .method => .path,
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
            .headers => .path,
            .body => .headers,
        };
        self.cursor = self.activeLen();
        self.scroll = 0;
    }

    fn loadFromEntry(self: *EditState, alloc: std.mem.Allocator, entry: *const requests.Entry, backing_idx: usize, is_intercepted: bool) void {
        self.backing_idx = backing_idx;
        self.intercepted = is_intercepted;
        self.field = .method;
        self.cursor = 0;
        self.scroll = 0;
        self.method_len = entry.method_len;
        @memcpy(self.method_buf[0..entry.method_len], entry.method[0..entry.method_len]);
        self.path_len = entry.path_len;
        @memcpy(self.path_buf[0..entry.path_len], entry.path[0..entry.path_len]);
        self.headers_len = entry.req_headers_len;
        @memcpy(self.headers_buf[0..entry.req_headers_len], entry.req_headers[0..entry.req_headers_len]);
        // Try to pretty-print JSON body
        const raw_body = entry.req_body[0..entry.req_body_len];
        if (prettyPrintJson(alloc, raw_body)) |pretty| {
            defer alloc.free(pretty);
            const len = @min(pretty.len, self.body_buf.len);
            @memcpy(self.body_buf[0..len], pretty[0..len]);
            self.body_len = len;
        } else {
            self.body_len = entry.req_body_len;
            @memcpy(self.body_buf[0..entry.req_body_len], raw_body);
        }
        self.active = true;
    }

    fn prettyPrintJson(alloc: std.mem.Allocator, body: []const u8) ?[]const u8 {
        if (body.len == 0) return null;
        const first = for (body) |ch| {
            if (ch != ' ' and ch != '\t' and ch != '\n' and ch != '\r') break ch;
        } else return null;
        if (first != '{' and first != '[') return null;
        const parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch return null;
        defer parsed.deinit();
        return std.json.Stringify.valueAlloc(alloc, parsed.value, .{ .whitespace = .indent_2 }) catch null;
    }

    fn applyToEntry(self: *const EditState) void {
        const entry = requests.getByBackingIndex(self.backing_idx);
        @memcpy(entry.method[0..self.method_len], self.method_buf[0..self.method_len]);
        entry.method_len = @intCast(self.method_len);
        @memcpy(entry.path[0..self.path_len], self.path_buf[0..self.path_len]);
        entry.path_len = @intCast(self.path_len);
        @memcpy(entry.req_headers[0..self.headers_len], self.headers_buf[0..self.headers_len]);
        entry.req_headers_len = @intCast(self.headers_len);
        @memcpy(entry.req_body[0..self.body_len], self.body_buf[0..self.body_len]);
        entry.req_body_len = @intCast(self.body_len);
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
        const rc = self.cursorRowCol();
        _ = rc;
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

pub fn run(alloc: std.mem.Allocator, domain: []const u8, target_port: u16) !void {
    const proxy_text = try std.fmt.allocPrint(alloc, "https -> 127.0.0.1:{d}", .{target_port});
    defer alloc.free(proxy_text);
    const ca_text = try std.fmt.allocPrint(alloc, "http://{s}/ca", .{domain});
    defer alloc.free(ca_text);

    var tty_buf: [4096]u8 = undefined;
    var tty = try vaxis.Tty.init(&tty_buf);
    defer tty.deinit();

    var vx = try vaxis.init(alloc, .{});
    defer {
        vx.deinit(alloc, tty.writer());
        tty.writer().flush() catch {};
        if (builtin.os.tag == .windows) {
            // vx.deinit sends escape sequences that trigger terminal responses.
            // Wait briefly for responses to arrive, then flush the console input
            // buffer before tty.deinit() re-enables ECHO_INPUT — otherwise the
            // response bytes (e.g. "0n") get echoed to the terminal.
            std.Thread.sleep(50 * std.time.ns_per_ms);
            const c = @cImport(@cInclude("windows.h"));
            _ = c.FlushConsoleInputBuffer(c.GetStdHandle(c.STD_INPUT_HANDLE));
        }
    }

    var loop: vaxis.Loop(Event) = .{ .tty = &tty, .vaxis = &vx };
    try loop.init();
    try loop.start();
    defer loop.stop();

    try vx.enterAltScreen(tty.writer());
    // Skip terminal query on Windows — the response bytes leak through as
    // spurious key events and as "0n" printed on exit.
    if (builtin.os.tag != .windows) {
        try vx.queryTerminal(tty.writer(), 1 * std.time.ns_per_s);
    }

    var cursor: usize = 0;
    var scroll_offset: usize = 0;
    var autoscroll: bool = true;
    var last_count: usize = 0;
    var view: View = .list;
    var detail_scroll: usize = 0;
    var detail_index: usize = 0;
    var show_help: bool = false;
    // On Windows, discard key events until after the first render — terminal
    // init can produce spurious events from escape sequence responses.
    var accepting_input: bool = (builtin.os.tag != .windows);
    var show_body: bool = false;
    var edit_state: EditState = .{};
    var search_mode: bool = false;
    var search_buf: [128]u8 = .{0} ** 128;
    var search_len: usize = 0;
    var filtered_count: usize = 0;
    // Maps filtered index -> original index in ptr_buf
    var filter_map: [requests.max_entries]usize = undefined;
    var flash_time: i64 = 0; // timestamp when flash message was set
    var flash_buf: [64]u8 = undefined;
    var flash_len: usize = 0;
    var har_fname_buf: [64]u8 = undefined;

    var ptr_buf: [requests.max_entries]*const requests.Entry = undefined;

    while (true) {
        while (loop.tryEvent()) |event| {
            switch (event) {
                .key_press => |key| {
                    if (key.matches('c', .{ .ctrl = true })) return;
                    if (!accepting_input) continue;

                    // Search mode input handling
                    if (search_mode) {
                        if (key.matches(vaxis.Key.escape, .{})) {
                            // Cancel search, clear filter
                            search_mode = false;
                            search_len = 0;
                            cursor = 0;
                            scroll_offset = 0;
                        } else if (key.matches(vaxis.Key.enter, .{})) {
                            // Confirm search, keep filter
                            search_mode = false;
                            cursor = 0;
                            scroll_offset = 0;
                        } else if (key.matches(vaxis.Key.backspace, .{})) {
                            search_len -|= 1;
                            cursor = 0;
                            scroll_offset = 0;
                        } else if (key.text) |text| {
                            if (search_len + text.len <= search_buf.len) {
                                @memcpy(search_buf[search_len .. search_len + text.len], text);
                                search_len += text.len;
                                cursor = 0;
                                scroll_offset = 0;
                            }
                        }
                        continue;
                    }

                    if (key.matches('?', .{})) {
                        show_help = !show_help;
                        continue;
                    }
                    if (show_help and key.matches(vaxis.Key.escape, .{})) {
                        show_help = false;
                        continue;
                    }

                    switch (view) {
                        .list => {
                            if (key.matches('q', .{})) return;
                            if (key.matches('/', .{})) {
                                search_mode = true;
                                search_len = 0;
                                continue;
                            }
                            if (key.matches('s', .{}))
                                autoscroll = !autoscroll;
                            if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{}))
                                cursor +|= 1;
                            if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{}))
                                cursor -|= 1;
                            if (key.matches('G', .{}))
                                cursor = std.math.maxInt(usize);
                            if (key.matches('g', .{}))
                                cursor = 0;
                            if (key.matches(vaxis.Key.escape, .{})) {
                                // Clear filter
                                search_len = 0;
                                cursor = 0;
                                scroll_offset = 0;
                            }
                            if (key.matches(vaxis.Key.enter, .{}) and filtered_count > 0) {
                                // Map filtered cursor to real logical index
                                detail_index = filter_map[cursor];
                                detail_scroll = 0;
                                view = .detail;
                            }
                            if (key.matches('i', .{}))
                                intercept.toggle();
                            if (key.matches('a', .{}) and filtered_count > 0)
                                acceptEntry(filter_map[cursor]);
                            if (key.matches('A', .{}))
                                intercept.acceptAll();
                            if (key.matches('C', .{}))
                                requests.clearAll();
                            if (key.matches('d', .{}) and filtered_count > 0)
                                dropOrDeleteEntry(filter_map[cursor]);
                            if (key.matches('c', .{}) and filtered_count > 0) {
                                clipboard.copyAsCurl(alloc, filter_map[cursor], domain);
                                const msg = "Copied as curl!";
                                @memcpy(flash_buf[0..msg.len], msg);
                                flash_len = msg.len;
                                flash_time = std.time.milliTimestamp();
                            }
                            if (key.matches('E', .{})) {
                                var export_buf: [requests.max_entries]*const requests.Entry = undefined;
                                const export_slice: []*const requests.Entry = &export_buf;
                                const export_count = requests.getRange(export_slice, 0, requests.max_entries);
                                if (har.exportHar(export_slice, export_count, domain, &har_fname_buf)) |fname_len| {
                                    const prefix = "Exported ";
                                    @memcpy(flash_buf[0..prefix.len], prefix);
                                    const nlen = @min(fname_len, flash_buf.len - prefix.len);
                                    @memcpy(flash_buf[prefix.len..][0..nlen], har_fname_buf[0..nlen]);
                                    flash_len = prefix.len + nlen;
                                } else {
                                    const msg = "Export failed";
                                    @memcpy(flash_buf[0..msg.len], msg);
                                    flash_len = msg.len;
                                }
                                flash_time = std.time.milliTimestamp();
                            }
                            if (key.matches('r', .{}) and filtered_count > 0) {
                                // Open edit view in replay mode
                                const real_idx = filter_map[cursor];
                                const backing_idx = requests.logicalToBackingIndex(real_idx) orelse continue;
                                const e = requests.getByBackingIndex(backing_idx);
                                if (e.state == .intercepted) continue;
                                edit_state.loadFromEntry(alloc, e, backing_idx, false);
                                view = .edit;
                            }
                            if (key.matches('R', .{}) and filtered_count > 0) {
                                replayEntry(filter_map[cursor]);
                                const msg = "Replayed!";
                                @memcpy(flash_buf[0..msg.len], msg);
                                flash_len = msg.len;
                                flash_time = std.time.milliTimestamp();
                            }
                            if (key.matches('e', .{}) and filtered_count > 0) {
                                const real_idx = filter_map[cursor];
                                const backing_idx = requests.logicalToBackingIndex(real_idx) orelse continue;
                                const e = requests.getByBackingIndex(backing_idx);
                                edit_state.loadFromEntry(alloc, e, backing_idx, e.state == .intercepted);
                                view = .edit;
                            }
                        },
                        .detail => {
                            if (key.matches('q', .{}) or key.matches(vaxis.Key.escape, .{})) {
                                view = .list;
                            } else if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
                                detail_scroll +|= 1;
                            } else if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
                                detail_scroll -|= 1;
                            } else if (key.matches('n', .{}) or key.matches(vaxis.Key.right, .{})) {
                                cursor +|= 1;
                                detail_scroll = 0;
                            } else if (key.matches('p', .{}) or key.matches(vaxis.Key.left, .{})) {
                                cursor -|= 1;
                                detail_scroll = 0;
                            } else if (key.matches('G', .{})) {
                                detail_scroll = std.math.maxInt(usize);
                            } else if (key.matches('g', .{})) {
                                detail_scroll = 0;
                            } else if (key.matches('s', .{})) {
                                autoscroll = !autoscroll;
                            } else if (key.matches('i', .{})) {
                                intercept.toggle();
                            } else if (key.matches('a', .{})) {
                                acceptEntry(detail_index);
                            } else if (key.matches('d', .{})) {
                                dropOrDeleteEntry(detail_index);
                            } else if (key.matches('c', .{})) {
                                clipboard.copyAsCurl(alloc, detail_index, domain);
                                const msg = "Copied as curl!";
                                @memcpy(flash_buf[0..msg.len], msg);
                                flash_len = msg.len;
                                flash_time = std.time.milliTimestamp();
                            } else if (key.matches('r', .{})) {
                                // Open edit view in replay mode
                                const backing_idx = requests.logicalToBackingIndex(detail_index) orelse continue;
                                const e = requests.getByBackingIndex(backing_idx);
                                if (e.state != .intercepted) {
                                    edit_state.loadFromEntry(alloc, e, backing_idx, false);
                                    view = .edit;
                                }
                            } else if (key.matches('R', .{})) {
                                replayEntry(detail_index);
                                const msg = "Replayed!";
                                @memcpy(flash_buf[0..msg.len], msg);
                                flash_len = msg.len;
                                flash_time = std.time.milliTimestamp();
                            } else if (key.matches('b', .{})) {
                                show_body = !show_body;
                                detail_scroll = 0;
                            } else if (key.matches('e', .{})) {
                                const backing_idx = requests.logicalToBackingIndex(detail_index) orelse continue;
                                const e = requests.getByBackingIndex(backing_idx);
                                edit_state.loadFromEntry(alloc, e, backing_idx, e.state == .intercepted);
                                view = .edit;
                            }
                        },
                        .edit => {
                            if (key.matches(vaxis.Key.escape, .{})) {
                                // Cancel edit
                                edit_state.active = false;
                                view = .list;
                            } else if (key.matches('s', .{ .ctrl = true })) {
                                if (edit_state.intercepted) {
                                    // Intercepted: apply edits to entry and accept
                                    edit_state.applyToEntry();
                                    const slot = intercept.findByBackingIndex(edit_state.backing_idx);
                                    if (slot) |s| intercept.setDecision(s, .accept);
                                } else {
                                    // Completed: replay with edited values
                                    const replay_entry = std.heap.page_allocator.create(requests.Entry) catch break;
                                    replay_entry.* = requests.Entry{ .timestamp = 0 };
                                    @memcpy(replay_entry.method[0..edit_state.method_len], edit_state.method_buf[0..edit_state.method_len]);
                                    replay_entry.method_len = @intCast(edit_state.method_len);
                                    @memcpy(replay_entry.path[0..edit_state.path_len], edit_state.path_buf[0..edit_state.path_len]);
                                    replay_entry.path_len = @intCast(edit_state.path_len);
                                    @memcpy(replay_entry.req_headers[0..edit_state.headers_len], edit_state.headers_buf[0..edit_state.headers_len]);
                                    replay_entry.req_headers_len = @intCast(edit_state.headers_len);
                                    @memcpy(replay_entry.req_body[0..edit_state.body_len], edit_state.body_buf[0..edit_state.body_len]);
                                    replay_entry.req_body_len = @intCast(edit_state.body_len);
                                    const thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, proxy.replay, .{
                                        replay_entry,
                                    }) catch {
                                        std.heap.page_allocator.destroy(replay_entry);
                                        break;
                                    };
                                    thread.detach();
                                    const msg = "Replayed!";
                                    @memcpy(flash_buf[0..msg.len], msg);
                                    flash_len = msg.len;
                                    flash_time = std.time.milliTimestamp();
                                }
                                edit_state.active = false;
                                view = .list;
                            } else if (key.matches(vaxis.Key.tab, .{})) {
                                edit_state.nextField();
                            } else if (key.matches(vaxis.Key.tab, .{ .shift = true })) {
                                edit_state.prevField();
                            } else if (key.matches(vaxis.Key.left, .{})) {
                                edit_state.cursor -|= 1;
                            } else if (key.matches(vaxis.Key.right, .{})) {
                                if (edit_state.cursor < edit_state.activeLen())
                                    edit_state.cursor += 1;
                            } else if (key.matches(vaxis.Key.home, .{})) {
                                edit_state.cursor = 0;
                            } else if (key.matches(vaxis.Key.end, .{})) {
                                edit_state.cursor = edit_state.activeLen();
                            } else if (key.matches(vaxis.Key.up, .{})) {
                                if (edit_state.isMultiline()) {
                                    edit_state.moveUp();
                                }
                            } else if (key.matches(vaxis.Key.down, .{})) {
                                if (edit_state.isMultiline()) {
                                    edit_state.moveDown();
                                }
                            } else if (key.matches(vaxis.Key.backspace, .{})) {
                                edit_state.deleteBack();
                            } else if (key.matches(vaxis.Key.delete, .{})) {
                                edit_state.deleteForward();
                            } else if (key.matches(vaxis.Key.enter, .{})) {
                                if (edit_state.isMultiline()) {
                                    edit_state.insertNewline();
                                } else {
                                    edit_state.nextField();
                                }
                            } else if (key.text) |text| {
                                for (text) |ch| {
                                    if (ch >= 32 and ch < 127) {
                                        edit_state.insertChar(ch);
                                    }
                                }
                            }
                        },
                    }
                },
                .winsize => |ws| try vx.resize(alloc, tty.writer(), ws),
            }
        }

        const current_count = requests.getCount();

        const win = vx.window();
        win.clear();

        // Build filter map (used by both views)
        const buf_slice: []*const requests.Entry = &ptr_buf;
        const raw_count = requests.getRange(buf_slice, 0, current_count);
        const search_term = search_buf[0..search_len];
        filtered_count = 0;
        if (search_len > 0) {
            for (0..raw_count) |i| {
                if (search.entryMatchesSearch(buf_slice[i], search_term)) {
                    filter_map[filtered_count] = i;
                    filtered_count += 1;
                }
            }
        } else {
            for (0..raw_count) |i| {
                filter_map[i] = i;
            }
            filtered_count = raw_count;
        }

        if (autoscroll and current_count > last_count and filtered_count > 0) {
            cursor = filtered_count - 1;
            if (view == .detail) detail_scroll = 0;
        }
        last_count = current_count;

        // Clamp cursor to filtered list
        if (filtered_count > 0) {
            if (cursor >= filtered_count) cursor = filtered_count - 1;
        } else {
            cursor = 0;
        }

        switch (view) {
            .list => {
                const header_rows = drawHeader(win, domain, proxy_text, ca_text, raw_count, autoscroll);
                const available_rows = if (win.height > header_rows + 2) win.height - header_rows - 2 else 1;

                // Adjust scroll to keep cursor visible
                if (cursor < scroll_offset) {
                    scroll_offset = cursor;
                } else if (cursor >= scroll_offset + available_rows) {
                    scroll_offset = cursor - available_rows + 1;
                }

                drawRequests(win, buf_slice, &filter_map, filtered_count, header_rows, scroll_offset, cursor, autoscroll, show_help, search_mode, search_term);
            },
            .detail => {
                // Resolve filtered cursor to real logical index
                if (filtered_count > 0) {
                    detail_index = filter_map[cursor];
                }
                const entry = if (filtered_count > 0) requests.getOne(detail_index) else null;
                drawDetail(alloc, win, entry, detail_index, raw_count, autoscroll, &detail_scroll, show_help, show_body);
            },
            .edit => {
                drawEdit(win, &edit_state);
            },
        }

        // Flash message (top-right, visible for 2 seconds)
        if (flash_len > 0) {
            const now = std.time.milliTimestamp();
            if (now - flash_time < 2000) {
                const col: u16 = @intCast(win.width -| (flash_len + 2));
                const green: vaxis.Color = .{ .rgb = .{ 0x3f, 0xb9, 0x50 } };
                writeAscii(win, col, 0, flash_buf[0..flash_len], .{ .fg = green, .bold = true });
            } else {
                flash_len = 0;
            }
        }

        try vx.render(tty.writer());
        accepting_input = true;
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }
}

fn drawHeader(win: vaxis.Window, domain: []const u8, proxy_text: []const u8, ca_text: []const u8, req_count: usize, autoscroll: bool) u16 {
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

    printAt(win, 2, row, "CA", .{ .fg = dim });
    printAt(win, 11, row, ca_text, .{ .fg = blue });
    row += 2;

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
        const pending = intercept.getPendingCount();
        if (pending > 0) {
            var pending_buf: [32]u8 = undefined;
            const pending_text = std.fmt.bufPrint(&pending_buf, " ({d} held)", .{pending}) catch "";
            writeAscii(win, indicator_pos + 9, row, pending_text, .{ .fg = orange });
        }
    }
    row += 1;

    printAt(win, 2, row, "METHOD", .{ .fg = dim });
    printAt(win, 11, row, "STATUS", .{ .fg = dim });
    printAt(win, 19, row, "TIME", .{ .fg = dim });
    printAt(win, 28, row, "SIZE", .{ .fg = dim });
    printAt(win, 36, row, "PATH", .{ .fg = dim });
    row += 1;

    // Separator
    if (row < win.height) {
        const sep_width = win.width -| 2;
        for (0..sep_width) |i| {
            writeAscii(win, 2 + @as(u16, @intCast(i)), row, "-", .{ .fg = .{ .rgb = .{ 0x30, 0x36, 0x3d } } });
        }
        row += 1;
    }

    return row;
}

fn drawRequests(
    win: vaxis.Window,
    ptr_buf: []*const requests.Entry,
    filter_map: []const usize,
    filtered_count: usize,
    start_row: u16,
    scroll_offset: usize,
    cursor: usize,
    autoscroll: bool,
    show_help: bool,
    search_mode: bool,
    search_term: []const u8,
) void {
    if (filtered_count == 0) {
        const msg = if (search_term.len > 0) "no matching requests" else "no requests yet";
        printAt(win, 2, start_row, msg, .{ .fg = .{ .rgb = .{ 0x6e, 0x76, 0x81 } } });
        if (search_mode or search_term.len > 0)
            drawSearchBar(win, search_mode, search_term)
        else
            drawFooter(win, autoscroll, show_help);
        return;
    }

    const available_rows = if (win.height > start_row + 2) win.height - start_row - 2 else 1;
    const visible = @min(available_rows, filtered_count -| scroll_offset);

    for (0..visible) |i| {
        const idx = scroll_offset + i;
        if (idx >= filtered_count) break;
        const entry = ptr_buf[filter_map[idx]];
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

    if (search_mode or search_term.len > 0)
        drawSearchBar(win, search_mode, search_term)
    else
        drawFooter(win, autoscroll, show_help);
}

fn drawRequestLine(win: vaxis.Window, row: u16, entry: *const requests.Entry, selected: bool) void {
    const white: vaxis.Color = .{ .rgb = .{ 0xe1, 0xe4, 0xe8 } };
    const dim: vaxis.Color = .{ .rgb = .{ 0x6e, 0x76, 0x81 } };
    const bg: vaxis.Color = if (selected) .{ .rgb = .{ 0x1c, 0x2b, 0x3a } } else .default;

    if (selected) {
        printAt(win, 1, row, ">", .{ .fg = .{ .rgb = .{ 0x58, 0xa6, 0xff } }, .bg = bg, .bold = true });
    }

    const method_color = methodColor(entry.getMethod());
    writeAscii(win, 2, row, entry.getMethod(), .{ .fg = method_color, .bg = bg, .bold = true });

    const orange: vaxis.Color = .{ .rgb = .{ 0xd2, 0x9e, 0x22 } };
    const red: vaxis.Color = .{ .rgb = .{ 0xf8, 0x51, 0x49 } };

    if (entry.state == .intercepted) {
        writeAscii(win, 11, row, "HOLD", .{ .fg = orange, .bg = bg, .bold = true });
    } else if (entry.state == .dropped) {
        writeAscii(win, 11, row, "DROP", .{ .fg = red, .bg = bg, .bold = true });
    } else {
        var status_buf: [6]u8 = undefined;
        const status_text = std.fmt.bufPrint(&status_buf, "{d}", .{entry.status}) catch "?";
        const status_color = statusColor(entry.status);
        writeAscii(win, 11, row, status_text, .{ .fg = status_color, .bg = bg });
    }

    var dur_buf: [16]u8 = undefined;
    const dur_text = if (entry.state == .intercepted) blk: {
        // Show live elapsed time for held requests
        const now = std.time.milliTimestamp();
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

    // Show response body size
    var size_buf: [10]u8 = undefined;
    const body_len = entry.resp_body_len;
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
    writeAscii(win, 36, row, display_path, .{ .fg = white, .bg = bg });
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
    const method_path = std.fmt.bufPrint(&method_path_buf, "{s} {s}", .{ e.getMethod(), e.getPath() }) catch "";
    lines[line_count] = .{ .text = method_path, .style = .{ .fg = white } };
    line_count += 1;
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
        lines[line_count] = .{ .text = "", .style = .{} };
        line_count += 1;
    }

    // Response headers
    const resp_hdrs = e.getRespHeaders();
    if (resp_hdrs.len > 0) {
        lines[line_count] = .{ .text = "RESPONSE HEADERS", .style = .{ .fg = blue, .bold = true } };
        line_count += 1;
        line_count = splitHeaderLines(resp_hdrs, &lines, line_count, .{ .fg = dim });
    }

    // Bodies (toggled with 'b')
    if (show_body) {
        const req_body = e.getReqBody();
        if (req_body.len > 0) {
            lines[line_count] = .{ .text = "", .style = .{} };
            line_count += 1;
            lines[line_count] = .{ .text = "REQUEST BODY", .style = .{ .fg = blue, .bold = true } };
            line_count += 1;
            line_count = splitBodyLines(alloc, req_body, &lines, line_count, .{ .fg = white });
        }

        const resp_body = e.getRespBody();
        if (resp_body.len > 0) {
            lines[line_count] = .{ .text = "", .style = .{} };
            line_count += 1;
            lines[line_count] = .{ .text = "RESPONSE BODY", .style = .{ .fg = blue, .bold = true } };
            line_count += 1;
            line_count = splitBodyLines(alloc, resp_body, &lines, line_count, .{ .fg = white });
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

/// Static buffer to hold pretty-printed JSON between frames (lines reference into it).
var json_pretty_buf: [requests.max_body_len * 2]u8 = .{0} ** (requests.max_body_len * 2);
var json_pretty_len: usize = 0;

fn splitBodyLines(alloc: std.mem.Allocator, body: []const u8, lines: []DetailLine, start: usize, style: vaxis.Style) usize {
    // Quick check: only try JSON parsing if body starts with { or [
    const first = for (body) |ch| {
        if (ch != ' ' and ch != '\t' and ch != '\n' and ch != '\r') break ch;
    } else 0;
    if (first != '{' and first != '[')
        return splitRawBodyLines(body, lines, start, style);

    // Try JSON pretty-print using std.json
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch
        return splitRawBodyLines(body, lines, start, style);
    defer parsed.deinit();

    const pretty = std.json.Stringify.valueAlloc(alloc, parsed.value, .{ .whitespace = .indent_2 }) catch
        return splitRawBodyLines(body, lines, start, style);
    defer alloc.free(pretty);

    // Copy into static buffer so lines can reference it after this function returns
    const len = @min(pretty.len, json_pretty_buf.len);
    @memcpy(json_pretty_buf[0..len], pretty[0..len]);
    json_pretty_len = len;

    return splitRawBodyLines(json_pretty_buf[0..len], lines, start, style);
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
    const title = if (es.intercepted) "EDIT REQUEST" else "REPLAY REQUEST";
    printAt(win, 2, row, title, .{ .fg = yellow, .bold = true });
    row += 2;

    // Helper to draw a field label + content
    const fields = [_]struct { label: []const u8, field: EditField, multiline: bool }{
        .{ .label = "METHOD", .field = .method, .multiline = false },
        .{ .label = "PATH", .field = .path, .multiline = false },
        .{ .label = "HEADERS", .field = .headers, .multiline = true },
        .{ .label = "BODY", .field = .body, .multiline = true },
    };

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

fn drawFooter(win: vaxis.Window, _: bool, show_help: bool) void {
    const dim: vaxis.Color = .{ .rgb = .{ 0x6e, 0x76, 0x81 } };
    const footer_row = win.height -| 1;
    printAt(win, 2, footer_row, "? help", .{ .fg = dim });
    if (show_help) drawHelpOverlay(win, .list);
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
        .{ .key = "i", .desc = "toggle intercept" },
        .{ .key = "d", .desc = "drop / delete" },
        .{ .key = "c", .desc = "copy as curl" },
        .{ .key = "e", .desc = "edit request" },
        .{ .key = "r", .desc = "edit & replay" },
        .{ .key = "R", .desc = "quick replay" },
        .{ .key = "E", .desc = "export HAR" },
        .{ .key = "?", .desc = "close help" },
    };

    const list_keys = [_]Entry{
        .{ .key = "/", .desc = "search" },
        .{ .key = "Esc", .desc = "clear filter" },
        .{ .key = "Enter", .desc = "detail view" },
        .{ .key = "C", .desc = "clear all" },
        .{ .key = "a", .desc = "accept held" },
        .{ .key = "A", .desc = "accept all held" },
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
    const box_w: u16 = 36;
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
        writeAscii(win, start_x + 14, row, entry.desc, .{ .fg = dim, .bg = bg });
        row += 1;
    }
    for (ctx_keys) |entry| {
        if (row >= start_y + box_h - 1) break;
        writeAscii(win, start_x + 2, row, entry.key, .{ .fg = white, .bg = bg, .bold = true });
        writeAscii(win, start_x + 14, row, entry.desc, .{ .fg = dim, .bg = bg });
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
    const entry = requests.getByBackingIndex(backing_idx);
    if (entry.state != .intercepted) return;
    const slot = intercept.findByBackingIndex(backing_idx) orelse return;
    intercept.setDecision(slot, .accept);
}

/// Drop an intercepted request or delete a completed request at the given logical index.
fn dropOrDeleteEntry(logical: usize) void {
    const backing_idx = requests.logicalToBackingIndex(logical) orelse return;
    const entry = requests.getByBackingIndex(backing_idx);
    if (entry.state == .intercepted) {
        const slot = intercept.findByBackingIndex(backing_idx) orelse return;
        intercept.setDecision(slot, .drop);
    } else if (entry.state != .deleted) {
        requests.remove(backing_idx);
    }
}

/// Replay a completed request by re-sending it to upstream.
fn replayEntry(logical: usize) void {
    const entry = requests.getOne(logical) orelse return;
    if (entry.state == .intercepted) return; // can't replay a held request
    const copy = std.heap.page_allocator.create(requests.Entry) catch return;
    copy.* = entry.*;
    const thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, proxy.replay, .{
        copy,
    }) catch {
        std.heap.page_allocator.destroy(copy);
        return;
    };
    thread.detach();
}
