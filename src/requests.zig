const std = @import("std");
const root = @import("root");

pub const max_entries: usize = if (@hasDecl(root, "build_options"))
    root.build_options.max_entries
else if (@import("builtin").is_test)
    10
else
    500;
pub const max_header_len = 2048;
pub const max_body_len = 32768;

pub const EntryState = enum(u8) {
    normal = 0,
    intercepted = 1,
    accepted = 2,
    dropped = 3,
    deleted = 4,
};

pub const Entry = struct {
    method: [7]u8 = .{0} ** 7,
    method_len: u8 = 0,
    path: [512]u8 = .{0} ** 512,
    path_len: u16 = 0,
    status: u16 = 0,
    duration_ms: u64 = 0,
    timestamp: i64 = 0,
    req_headers: [max_header_len]u8 = .{0} ** max_header_len,
    req_headers_len: u16 = 0,
    resp_headers: [max_header_len]u8 = .{0} ** max_header_len,
    resp_headers_len: u16 = 0,
    req_body: [max_body_len]u8 = .{0} ** max_body_len,
    req_body_len: u32 = 0,
    resp_body: [max_body_len]u8 = .{0} ** max_body_len,
    resp_body_len: u32 = 0,
    req_body_truncated: bool = false,
    resp_body_truncated: bool = false,
    state: EntryState = .normal,
    pinned: bool = false,
    starred: bool = false,
    route_index: u8 = 0xff, // 0xff = no route match, otherwise index into routes

    pub fn getMethod(self: *const Entry) []const u8 {
        return self.method[0..self.method_len];
    }

    pub fn getPath(self: *const Entry) []const u8 {
        return self.path[0..self.path_len];
    }

    pub fn getReqHeaders(self: *const Entry) []const u8 {
        return self.req_headers[0..self.req_headers_len];
    }

    pub fn getRespHeaders(self: *const Entry) []const u8 {
        return self.resp_headers[0..self.resp_headers_len];
    }

    pub fn getReqBody(self: *const Entry) []const u8 {
        return self.req_body[0..self.req_body_len];
    }

    pub fn getRespBody(self: *const Entry) []const u8 {
        return self.resp_body[0..self.resp_body_len];
    }
};

var mutex: std.Thread.Mutex = .{};
var entries: [max_entries]*Entry = undefined;
var entries_backing: [max_entries]Entry = @splat(Entry{});
var count: usize = 0;
var live_count: usize = 0;
var write_pos: usize = 0;
var initialized: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn ensureInit() void {
    if (initialized.load(.acquire)) return;
    for (0..max_entries) |i| {
        entries[i] = &entries_backing[i];
    }
    initialized.store(true, .release);
}

pub fn push(entry: Entry) void {
    mutex.lock();
    defer mutex.unlock();
    ensureInit();
    // Skip pinned entries
    var attempts: usize = 0;
    while (entries_backing[write_pos].pinned and attempts < max_entries) {
        write_pos = (write_pos + 1) % max_entries;
        attempts += 1;
    }
    if (attempts >= max_entries) return; // All pinned, drop entry
    // If overwriting a live (non-deleted) entry, decrement live count
    if (count >= max_entries and entries_backing[write_pos].state != .deleted) {
        live_count -|= 1;
    }
    entries_backing[write_pos] = entry;
    live_count += 1;
    write_pos = (write_pos + 1) % max_entries;
    if (count < max_entries) count += 1;
}

/// Push an entry and pin it so it won't be overwritten. Returns the backing index, or null if all slots are pinned.
pub fn pushAndPin(entry: Entry) ?usize {
    mutex.lock();
    defer mutex.unlock();
    ensureInit();
    // Skip pinned entries
    var attempts: usize = 0;
    while (entries_backing[write_pos].pinned and attempts < max_entries) {
        write_pos = (write_pos + 1) % max_entries;
        attempts += 1;
    }
    if (attempts >= max_entries) return null;
    // If overwriting a live (non-deleted) entry, decrement live count
    if (count >= max_entries and entries_backing[write_pos].state != .deleted) {
        live_count -|= 1;
    }
    entries_backing[write_pos] = entry;
    entries_backing[write_pos].pinned = true;
    live_count += 1;
    const idx = write_pos;
    write_pos = (write_pos + 1) % max_entries;
    if (count < max_entries) count += 1;
    return idx;
}

/// Direct access by backing array index (for updating entries in-place).
pub fn getByBackingIndex(idx: usize) *Entry {
    return &entries_backing[idx];
}

/// Update a pinned entry in-place (thread-safe) and unpin it.
/// req_body is not updated here — it's already set during pushAndPin (and may have been edited).
pub fn finishEntry(idx: usize, status: u16, duration_ms: u64, resp_headers: []const u8, resp_body: []const u8) void {
    mutex.lock();
    defer mutex.unlock();
    const e = &entries_backing[idx];
    e.status = status;
    e.duration_ms = duration_ms;
    const rh_len = @min(resp_headers.len, max_header_len);
    @memcpy(e.resp_headers[0..rh_len], resp_headers[0..rh_len]);
    e.resp_headers_len = @intCast(rh_len);
    const rsb_len = @min(resp_body.len, max_body_len);
    @memcpy(e.resp_body[0..rsb_len], resp_body[0..rsb_len]);
    e.resp_body_len = @intCast(rsb_len);
    e.pinned = false;
}

/// Clear the pinned flag on an entry.
pub fn unpin(idx: usize) void {
    mutex.lock();
    defer mutex.unlock();
    entries_backing[idx].pinned = false;
}

/// Toggle the starred flag on an entry. Starred entries are pinned to survive ring buffer overflow.
pub fn toggleStar(idx: usize) void {
    mutex.lock();
    defer mutex.unlock();
    const e = &entries_backing[idx];
    e.starred = !e.starred;
    if (e.starred) {
        e.pinned = true;
    } else if (e.state != .intercepted) {
        e.pinned = false;
    }
}

/// Mark an entry as deleted by backing index.
pub fn remove(idx: usize) void {
    mutex.lock();
    defer mutex.unlock();
    if (entries_backing[idx].state != .deleted) {
        live_count -|= 1;
    }
    entries_backing[idx].state = .deleted;
}

/// Clear all entries.
pub fn clearAll() void {
    mutex.lock();
    defer mutex.unlock();
    for (0..max_entries) |i| {
        entries_backing[i].state = .deleted;
        entries_backing[i].pinned = false;
        entries_backing[i].starred = false;
    }
    count = 0;
    live_count = 0;
    write_pos = 0;
}

/// Convert a logical index (0 = oldest, skipping deleted) to a backing array index.
pub fn logicalToBackingIndex(logical: usize) ?usize {
    mutex.lock();
    defer mutex.unlock();
    if (count == 0) return null;
    const ring_start = if (count >= max_entries) write_pos else 0;
    var seen: usize = 0;
    for (0..count) |i| {
        const idx = (ring_start + i) % max_entries;
        if (entries_backing[idx].state == .deleted) continue;
        if (seen == logical) return idx;
        seen += 1;
    }
    return null;
}

/// Get a range of non-deleted entries for display. Returns count written.
pub fn getRange(buf: []*const Entry, offset: usize, limit: usize) usize {
    mutex.lock();
    defer mutex.unlock();
    ensureInit();
    if (count == 0) return 0;
    const ring_start = if (count >= max_entries) write_pos else 0;
    var written: usize = 0;
    var skipped: usize = 0;
    for (0..count) |i| {
        const idx = (ring_start + i) % max_entries;
        if (entries_backing[idx].state == .deleted) continue;
        if (skipped < offset) {
            skipped += 1;
            continue;
        }
        if (written >= limit) break;
        buf[written] = &entries_backing[idx];
        written += 1;
    }
    return written;
}

/// Get a single entry by logical index (0 = oldest, skipping deleted).
pub fn getOne(index: usize) ?*const Entry {
    mutex.lock();
    defer mutex.unlock();
    ensureInit();
    if (count == 0) return null;
    const ring_start = if (count >= max_entries) write_pos else 0;
    var seen: usize = 0;
    for (0..count) |i| {
        const idx = (ring_start + i) % max_entries;
        if (entries_backing[idx].state == .deleted) continue;
        if (seen == index) return &entries_backing[idx];
        seen += 1;
    }
    return null;
}

pub fn getCount() usize {
    mutex.lock();
    defer mutex.unlock();
    return live_count;
}

// --- Unit Tests ---

const testing = std.testing;

fn makeEntry(method: []const u8, path: []const u8, status: u16) Entry {
    var e = Entry{};
    const m_len: u8 = @intCast(@min(method.len, e.method.len));
    @memcpy(e.method[0..m_len], method[0..m_len]);
    e.method_len = m_len;
    const p_len: u16 = @intCast(@min(path.len, e.path.len));
    @memcpy(e.path[0..p_len], path[0..p_len]);
    e.path_len = p_len;
    e.status = status;
    return e;
}

test "Entry getters" {
    var e = makeEntry("GET", "/hello", 200);
    e.timestamp = 1000;
    e.duration_ms = 42;

    try testing.expectEqualStrings("GET", e.getMethod());
    try testing.expectEqualStrings("/hello", e.getPath());
    try testing.expectEqual(@as(u16, 200), e.status);

    // Headers and body default empty
    try testing.expectEqual(@as(usize, 0), e.getReqHeaders().len);
    try testing.expectEqual(@as(usize, 0), e.getRespHeaders().len);
    try testing.expectEqual(@as(usize, 0), e.getReqBody().len);
    try testing.expectEqual(@as(usize, 0), e.getRespBody().len);
}

test "Entry with headers and body" {
    var e = Entry{};
    const hdrs = "Content-Type: text/plain\r\nHost: dev.lo";
    @memcpy(e.req_headers[0..hdrs.len], hdrs);
    e.req_headers_len = @intCast(hdrs.len);
    const body = "hello world";
    @memcpy(e.req_body[0..body.len], body);
    e.req_body_len = @intCast(body.len);

    try testing.expectEqualStrings(hdrs, e.getReqHeaders());
    try testing.expectEqualStrings(body, e.getReqBody());
}

test "push and getCount" {
    clearAll();
    try testing.expectEqual(@as(usize, 0), getCount());

    push(makeEntry("GET", "/a", 200));
    try testing.expectEqual(@as(usize, 1), getCount());

    push(makeEntry("POST", "/b", 201));
    try testing.expectEqual(@as(usize, 2), getCount());
}

test "getOne returns entries in order" {
    clearAll();
    push(makeEntry("GET", "/first", 200));
    push(makeEntry("POST", "/second", 201));

    const first = getOne(0) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("GET", first.getMethod());
    try testing.expectEqualStrings("/first", first.getPath());

    const second = getOne(1) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("POST", second.getMethod());
    try testing.expectEqualStrings("/second", second.getPath());

    // Out of bounds
    try testing.expect(getOne(2) == null);
}

test "getRange basic" {
    clearAll();
    push(makeEntry("GET", "/a", 200));
    push(makeEntry("POST", "/b", 201));
    push(makeEntry("PUT", "/c", 204));

    var buf: [10]*const Entry = undefined;
    const n = getRange(&buf, 0, 10);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualStrings("/a", buf[0].getPath());
    try testing.expectEqualStrings("/b", buf[1].getPath());
    try testing.expectEqualStrings("/c", buf[2].getPath());
}

test "getRange with offset and limit" {
    clearAll();
    push(makeEntry("GET", "/a", 200));
    push(makeEntry("POST", "/b", 201));
    push(makeEntry("PUT", "/c", 204));

    var buf: [10]*const Entry = undefined;

    // offset=1, limit=1 → only /b
    const n = getRange(&buf, 1, 1);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("/b", buf[0].getPath());
}

test "remove marks entry as deleted" {
    clearAll();
    push(makeEntry("GET", "/a", 200));
    push(makeEntry("POST", "/b", 201));
    try testing.expectEqual(@as(usize, 2), getCount());

    // Remove first entry (backing index via logicalToBackingIndex)
    const idx = logicalToBackingIndex(0) orelse return error.TestUnexpectedResult;
    remove(idx);

    try testing.expectEqual(@as(usize, 1), getCount());
    // getOne(0) should now be /b (skips deleted)
    const first = getOne(0) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("/b", first.getPath());
}

test "clearAll resets everything" {
    clearAll();
    push(makeEntry("GET", "/a", 200));
    push(makeEntry("POST", "/b", 201));
    try testing.expectEqual(@as(usize, 2), getCount());

    clearAll();
    try testing.expectEqual(@as(usize, 0), getCount());
    try testing.expect(getOne(0) == null);
}

test "pushAndPin and unpin" {
    clearAll();
    const idx = pushAndPin(makeEntry("GET", "/pinned", 200)) orelse return error.TestUnexpectedResult;

    try testing.expectEqual(@as(usize, 1), getCount());
    const e = getByBackingIndex(idx);
    try testing.expect(e.pinned);
    try testing.expectEqualStrings("/pinned", e.getPath());

    unpin(idx);
    try testing.expect(!getByBackingIndex(idx).pinned);
}

test "finishEntry updates fields and unpins" {
    clearAll();
    const idx = pushAndPin(makeEntry("POST", "/api", 0)) orelse return error.TestUnexpectedResult;

    const resp_hdrs = "Content-Type: application/json";
    const resp_body = "{\"ok\":true}";
    finishEntry(idx, 200, 55, resp_hdrs, resp_body);

    const e = getByBackingIndex(idx);
    try testing.expectEqual(@as(u16, 200), e.status);
    try testing.expectEqual(@as(u64, 55), e.duration_ms);
    try testing.expectEqualStrings(resp_hdrs, e.getRespHeaders());
    try testing.expectEqualStrings(resp_body, e.getRespBody());
    try testing.expect(!e.pinned);
}

test "ring buffer wraps and overwrites oldest" {
    clearAll();
    // Fill the buffer
    for (0..max_entries) |i| {
        var path_buf: [16]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/{d}", .{i}) catch unreachable;
        var e = makeEntry("GET", path, 200);
        e.timestamp = @intCast(i);
        push(e);
    }
    try testing.expectEqual(@as(usize, max_entries), getCount());

    // Oldest should be /0
    const oldest = getOne(0) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(i64, 0), oldest.timestamp);

    // Push one more — should overwrite /0
    var new = makeEntry("GET", "/new", 201);
    new.timestamp = 9999;
    push(new);

    // Count stays at max_entries
    try testing.expectEqual(@as(usize, max_entries), getCount());
    // Oldest is now /1
    const new_oldest = getOne(0) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(i64, 1), new_oldest.timestamp);
    // Newest is /new
    const newest = getOne(max_entries - 1) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(i64, 9999), newest.timestamp);
}

test "push skips pinned entries" {
    clearAll();
    // Pin the first slot
    const idx = pushAndPin(makeEntry("GET", "/pinned", 200)) orelse return error.TestUnexpectedResult;
    _ = idx;

    // Fill remaining slots
    for (1..max_entries) |i| {
        var e = makeEntry("GET", "/filler", 200);
        e.timestamp = @intCast(i);
        push(e);
    }

    // Push one more — should skip the pinned slot and overwrite the next unpinned one
    var overflow = makeEntry("GET", "/overflow", 200);
    overflow.timestamp = 8888;
    push(overflow);

    // Pinned entry should still be there
    const pinned = getByBackingIndex(0);
    try testing.expect(pinned.pinned);
    try testing.expectEqualStrings("/pinned", pinned.getPath());
}

test "pushAndPin returns null when all slots pinned" {
    clearAll();
    // Pin all slots
    for (0..max_entries) |_| {
        _ = pushAndPin(makeEntry("GET", "/p", 200));
    }
    // Next pushAndPin should return null
    try testing.expect(pushAndPin(makeEntry("GET", "/fail", 200)) == null);
}

test "logicalToBackingIndex skips deleted" {
    clearAll();
    push(makeEntry("GET", "/a", 200));
    push(makeEntry("POST", "/b", 201));
    push(makeEntry("PUT", "/c", 204));

    // Delete /b (logical index 1)
    const b_idx = logicalToBackingIndex(1) orelse return error.TestUnexpectedResult;
    remove(b_idx);

    // Logical 0 = /a, logical 1 = /c (skipped deleted /b)
    const idx0 = logicalToBackingIndex(0) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("/a", getByBackingIndex(idx0).getPath());
    const idx1 = logicalToBackingIndex(1) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("/c", getByBackingIndex(idx1).getPath());

    // Logical 2 should be null
    try testing.expect(logicalToBackingIndex(2) == null);
}

test "getRange skips deleted entries" {
    clearAll();
    push(makeEntry("GET", "/a", 200));
    push(makeEntry("POST", "/b", 201));
    push(makeEntry("PUT", "/c", 204));

    // Delete /b
    const idx = logicalToBackingIndex(1) orelse return error.TestUnexpectedResult;
    remove(idx);

    var buf: [10]*const Entry = undefined;
    const n = getRange(&buf, 0, 10);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("/a", buf[0].getPath());
    try testing.expectEqualStrings("/c", buf[1].getPath());
}

test "logicalToBackingIndex empty" {
    clearAll();
    try testing.expect(logicalToBackingIndex(0) == null);
}

test "truncation flags default false" {
    const e = Entry{};
    try testing.expect(!e.req_body_truncated);
    try testing.expect(!e.resp_body_truncated);
}

test "truncation flags preserved through push" {
    clearAll();
    var e = makeEntry("POST", "/upload", 200);
    e.req_body_truncated = true;
    push(e);

    const stored = getOne(0) orelse return error.TestUnexpectedResult;
    try testing.expect(stored.req_body_truncated);
    try testing.expect(!stored.resp_body_truncated);
}

test "truncation flags preserved through pushAndPin" {
    clearAll();
    var e = makeEntry("POST", "/data", 200);
    e.resp_body_truncated = true;
    const idx = pushAndPin(e) orelse return error.TestUnexpectedResult;

    const stored = getByBackingIndex(idx);
    try testing.expect(stored.resp_body_truncated);
    try testing.expect(!stored.req_body_truncated);
    unpin(idx);
}

test "toggleStar pins and unpins" {
    clearAll();
    push(makeEntry("GET", "/star-test", 200));
    const backing_idx = logicalToBackingIndex(0) orelse return error.TestUnexpectedResult;
    const e = getByBackingIndex(backing_idx);

    try testing.expect(!e.starred);
    try testing.expect(!e.pinned);

    toggleStar(backing_idx);
    try testing.expect(e.starred);
    try testing.expect(e.pinned);

    toggleStar(backing_idx);
    try testing.expect(!e.starred);
    try testing.expect(!e.pinned);
}

test "toggleStar unstar keeps pinned if intercepted" {
    clearAll();
    const idx = pushAndPin(makeEntry("GET", "/intercept-star", 200)) orelse return error.TestUnexpectedResult;
    const e = getByBackingIndex(idx);
    e.state = .intercepted;

    toggleStar(idx);
    try testing.expect(e.starred);
    try testing.expect(e.pinned);

    // Unstar — should stay pinned because intercepted
    toggleStar(idx);
    try testing.expect(!e.starred);
    try testing.expect(e.pinned);

    unpin(idx);
}
