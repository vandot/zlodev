const std = @import("std");
const root = @import("root");
const intercept = @import("intercept.zig");

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

/// Classification of an entry by intercept phase + hold state. Derived from the
/// (state, resp_intercepted) pair so callers don't re-derive it inline. See phaseOf.
pub const Phase = enum {
    request, // request capture, not held
    request_held, // held at the request phase, awaiting a decision
    response_held, // held at the response phase, awaiting a decision
    response_done, // settled response capture (read-only)
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
    resp_intercepted: bool = false, // true when intercepted at response phase (vs request phase)

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

/// Direct access by backing array index. Internal: callers mutate ring-resident
/// entries only through the transition/edit ops, and read them via phaseOf/snapshot.
fn getByBackingIndex(idx: usize) *Entry {
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
    if (!e.starred) e.pinned = false;
}

/// Finish a response-intercepted entry. Response data is already in the entry (and may have been edited).
/// Just updates duration and unpins.
pub fn finishResponseIntercept(idx: usize, duration_ms: u64) void {
    mutex.lock();
    defer mutex.unlock();
    const e = &entries_backing[idx];
    e.duration_ms = duration_ms;
    if (!e.starred) e.pinned = false;
}

/// Clear the pinned flag on an entry.
pub fn unpin(idx: usize) void {
    mutex.lock();
    defer mutex.unlock();
    if (!entries_backing[idx].starred) entries_backing[idx].pinned = false;
}

/// Classify a ring-resident entry by phase + hold state (locked read).
/// The read counterpart to the transition ops below.
pub fn phaseOf(idx: usize) Phase {
    mutex.lock();
    defer mutex.unlock();
    return phaseOfEntry(&entries_backing[idx]);
}

fn phaseOfEntry(e: *const Entry) Phase {
    if (e.resp_intercepted) {
        return if (e.state == .intercepted) .response_held else .response_done;
    }
    return if (e.state == .intercepted) .request_held else .request;
}

/// Current status of a ring-resident entry (locked read).
pub fn statusOf(idx: usize) u16 {
    mutex.lock();
    defer mutex.unlock();
    return entries_backing[idx].status;
}

/// Copy a ring-resident entry (by backing index) into caller storage, under the mutex.
/// Used where a held entry must be read off the lock (e.g. forwarding, TUI edit load).
pub fn snapshotByBackingIndex(idx: usize, dest: *Entry) void {
    mutex.lock();
    defer mutex.unlock();
    dest.* = entries_backing[idx];
}

/// Mark a held entry accepted. The pin is kept until a finish op runs.
pub fn markAccepted(idx: usize) void {
    mutex.lock();
    defer mutex.unlock();
    entries_backing[idx].state = .accepted;
}

/// Mark a held entry dropped and record how long it was held.
pub fn markDropped(idx: usize, duration_ms: u64) void {
    mutex.lock();
    defer mutex.unlock();
    const e = &entries_backing[idx];
    e.state = .dropped;
    e.duration_ms = duration_ms;
}

/// Release a request-phase hold back to a normal capture (intercept skipped/declined).
pub fn releaseHold(idx: usize) void {
    mutex.lock();
    defer mutex.unlock();
    entries_backing[idx].state = .normal;
}

/// Release a response-phase entry back to a normal capture (intercept skipped).
pub fn releaseResponseHold(idx: usize, duration_ms: u64) void {
    mutex.lock();
    defer mutex.unlock();
    const e = &entries_backing[idx];
    e.state = .normal;
    e.resp_intercepted = false;
    e.duration_ms = duration_ms;
}

/// Finish an entry that was accepted but left dangling on an error exit:
/// only acts if still pinned (not starred) and in the accepted state.
pub fn finishIfDangling(idx: usize, status: u16, duration_ms: u64) void {
    mutex.lock();
    defer mutex.unlock();
    const e = &entries_backing[idx];
    if (e.pinned and !e.starred and e.state == .accepted) {
        e.status = status;
        e.duration_ms = duration_ms;
        e.resp_headers_len = 0;
        e.resp_body_len = 0;
        e.pinned = false;
    }
}

/// A handle to a ring entry opened for editing by the TUI. Bundles the backing
/// index with the phase observed at open time, so the editor never passes a raw
/// index around and every write re-checks, under the lock, that the entry is still
/// held in the expected phase before touching it. Obtain one via `editHeld`.
pub const EditableHold = struct {
    idx: usize,
    phase: Phase,

    /// Copy the held entry into caller storage (locked), e.g. to load the editor.
    pub fn snapshot(self: EditableHold, dest: *Entry) void {
        snapshotByBackingIndex(self.idx, dest);
    }

    /// Status currently recorded on the entry — the response editor's fallback when
    /// the typed status code is unparseable.
    pub fn currentStatus(self: EditableHold) u16 {
        return statusOf(self.idx);
    }

    /// Apply edited request fields, but only if the entry is still held at the
    /// request phase. Slices are clamped. Returns false if the hold was resolved
    /// since it was opened (in which case nothing is written).
    pub fn commitRequest(self: EditableHold, method: []const u8, path: []const u8, headers: []const u8, body: []const u8) bool {
        mutex.lock();
        defer mutex.unlock();
        const e = &entries_backing[self.idx];
        if (e.state != .intercepted or e.resp_intercepted) return false;
        const m = @min(method.len, e.method.len);
        @memcpy(e.method[0..m], method[0..m]);
        e.method_len = @intCast(m);
        const p = @min(path.len, e.path.len);
        @memcpy(e.path[0..p], path[0..p]);
        e.path_len = @intCast(p);
        const h = @min(headers.len, max_header_len);
        @memcpy(e.req_headers[0..h], headers[0..h]);
        e.req_headers_len = @intCast(h);
        const b = @min(body.len, max_body_len);
        @memcpy(e.req_body[0..b], body[0..b]);
        e.req_body_len = @intCast(b);
        return true;
    }

    /// Apply edited response fields, but only if the entry is still held at the
    /// response phase. Slices are clamped. Returns false if the hold was resolved.
    pub fn commitResponse(self: EditableHold, status: u16, headers: []const u8, body: []const u8) bool {
        mutex.lock();
        defer mutex.unlock();
        const e = &entries_backing[self.idx];
        if (e.state != .intercepted or !e.resp_intercepted) return false;
        e.status = status;
        const h = @min(headers.len, max_header_len);
        @memcpy(e.resp_headers[0..h], headers[0..h]);
        e.resp_headers_len = @intCast(h);
        const b = @min(body.len, max_body_len);
        @memcpy(e.resp_body[0..b], body[0..b]);
        e.resp_body_len = @intCast(b);
        e.resp_body_truncated = false;
        return true;
    }

    /// Resolve the intercept hold with accept, releasing the blocked proxy thread.
    pub fn accept(self: EditableHold) void {
        intercept.resolve(self.idx, .accept);
    }
};

/// Open an editable handle on the entry at a logical index. Returns null for a
/// missing entry or a settled response (`response_done`, read-only). The phase is
/// captured so the caller can pick request- vs response-edit mode and so commits can
/// detect a hold that was resolved meanwhile.
pub fn editHeld(logical: usize) ?EditableHold {
    const idx = logicalToBackingIndex(logical) orelse return null;
    mutex.lock();
    defer mutex.unlock();
    const ph = phaseOfEntry(&entries_backing[idx]);
    if (ph == .response_done) return null;
    return EditableHold{ .idx = idx, .phase = ph };
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
    // First, drop all pending intercepts to wake blocked proxy threads.
    intercept.dropAll();

    // Spin-wait for proxy threads to process drops and release their slots (up to 100ms).
    var wait_iters: usize = 0;
    while (intercept.getPendingCount() > 0 and wait_iters < 100) : (wait_iters += 1) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    mutex.lock();
    defer mutex.unlock();
    for (0..max_entries) |i| {
        entries_backing[i].state = .deleted;
        entries_backing[i].pinned = false;
        entries_backing[i].starred = false;
        entries_backing[i].resp_intercepted = false;
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

/// Copy an entry by logical index into caller-provided storage, under the mutex.
/// Returns true if the entry was found and copied, false otherwise.
pub fn copyEntry(logical: usize, dest: *Entry) bool {
    mutex.lock();
    defer mutex.unlock();
    ensureInit();
    if (count == 0) return false;
    const ring_start = if (count >= max_entries) write_pos else 0;
    var seen: usize = 0;
    for (0..count) |i| {
        const idx = (ring_start + i) % max_entries;
        if (entries_backing[idx].state == .deleted) continue;
        if (seen == logical) {
            dest.* = entries_backing[idx];
            return true;
        }
        seen += 1;
    }
    return false;
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

test "finishEntry preserves pin when starred" {
    clearAll();
    const idx = pushAndPin(makeEntry("POST", "/api", 0)) orelse return error.TestUnexpectedResult;
    const e = getByBackingIndex(idx);

    // Star the entry while intercepted
    toggleStar(idx);
    try testing.expect(e.starred);
    try testing.expect(e.pinned);

    // Finish — should stay pinned because starred
    finishEntry(idx, 200, 50, "Content-Type: text/plain", "ok");
    try testing.expect(e.pinned);
    try testing.expect(e.starred);
    try testing.expectEqual(@as(u16, 200), e.status);
}

test "finishEntry unpins when not starred" {
    clearAll();
    const idx = pushAndPin(makeEntry("POST", "/api", 0)) orelse return error.TestUnexpectedResult;
    const e = getByBackingIndex(idx);
    try testing.expect(!e.starred);
    try testing.expect(e.pinned);

    finishEntry(idx, 200, 50, "", "");
    try testing.expect(!e.pinned);
}

test "finishResponseIntercept updates duration and unpins" {
    clearAll();
    const idx = pushAndPin(makeEntry("GET", "/resp", 200)) orelse return error.TestUnexpectedResult;
    const e = getByBackingIndex(idx);
    e.resp_intercepted = true;

    // Set some response data that should be preserved
    const resp_body = "response body";
    @memcpy(e.resp_body[0..resp_body.len], resp_body);
    e.resp_body_len = @intCast(resp_body.len);

    finishResponseIntercept(idx, 123);
    try testing.expectEqual(@as(u64, 123), e.duration_ms);
    try testing.expect(!e.pinned);
    // Response data preserved
    try testing.expectEqualStrings(resp_body, e.getRespBody());
}

test "finishResponseIntercept preserves pin when starred" {
    clearAll();
    const idx = pushAndPin(makeEntry("GET", "/resp-star", 200)) orelse return error.TestUnexpectedResult;
    const e = getByBackingIndex(idx);
    e.resp_intercepted = true;

    toggleStar(idx);
    try testing.expect(e.starred);

    finishResponseIntercept(idx, 99);
    try testing.expect(e.pinned); // stays pinned because starred
    try testing.expectEqual(@as(u64, 99), e.duration_ms);
}

test "resp_intercepted flag" {
    clearAll();
    var e = makeEntry("GET", "/test", 200);
    try testing.expect(!e.resp_intercepted);

    e.resp_intercepted = true;
    push(e);

    const stored = getOne(0) orelse return error.TestUnexpectedResult;
    try testing.expect(stored.resp_intercepted);
}

test "clearAll resets resp_intercepted and starred" {
    clearAll();
    var e = makeEntry("GET", "/test", 200);
    e.resp_intercepted = true;
    e.starred = true;
    push(e);

    clearAll();
    // After clearAll, backing entries should have flags reset
    const backing = getByBackingIndex(0);
    try testing.expect(!backing.resp_intercepted);
    try testing.expect(!backing.starred);
}

test "starred entry survives ring buffer overflow" {
    clearAll();
    // Push and star first entry
    push(makeEntry("GET", "/starred", 200));
    const star_idx = logicalToBackingIndex(0) orelse return error.TestUnexpectedResult;
    toggleStar(star_idx);

    // Fill remaining slots and overflow
    for (0..max_entries + 5) |i| {
        var e = makeEntry("GET", "/filler", 200);
        e.timestamp = @intCast(i + 100);
        push(e);
    }

    // Starred entry should still exist
    const starred = getByBackingIndex(star_idx);
    try testing.expect(starred.starred);
    try testing.expect(starred.pinned);
    try testing.expectEqualStrings("/starred", starred.getPath());
}

test "unpin preserves pinned flag on starred entries" {
    clearAll();
    // Push and pin an entry
    const e = Entry{ .timestamp = 1 };
    const idx = pushAndPin(e).?;

    // Star the entry
    toggleStar(idx);
    const entry = getByBackingIndex(idx);
    try testing.expect(entry.starred);
    try testing.expect(entry.pinned);

    // Unpin should NOT clear pinned because it's starred
    unpin(idx);
    try testing.expect(entry.pinned);

    // Unstar, then unpin should clear pinned
    toggleStar(idx);
    try testing.expect(!entry.pinned);
}

test "phaseOf classifies the (state, resp_intercepted) pair" {
    const cases = [_]struct { state: EntryState, resp: bool, want: Phase }{
        .{ .state = .normal, .resp = false, .want = .request },
        .{ .state = .accepted, .resp = false, .want = .request },
        .{ .state = .dropped, .resp = false, .want = .request },
        .{ .state = .intercepted, .resp = false, .want = .request_held },
        .{ .state = .intercepted, .resp = true, .want = .response_held },
        .{ .state = .normal, .resp = true, .want = .response_done },
        .{ .state = .accepted, .resp = true, .want = .response_done },
    };
    for (cases) |c| {
        var e = Entry{};
        e.state = c.state;
        e.resp_intercepted = c.resp;
        try testing.expectEqual(c.want, phaseOfEntry(&e));
    }
}

test "transition ops set the consistent pair" {
    clearAll();
    const idx = pushAndPin(Entry{ .timestamp = 1 }).?;

    markAccepted(idx);
    try testing.expectEqual(EntryState.accepted, getByBackingIndex(idx).state);

    markDropped(idx, 42);
    try testing.expectEqual(EntryState.dropped, getByBackingIndex(idx).state);
    try testing.expectEqual(@as(u64, 42), getByBackingIndex(idx).duration_ms);

    // Response hold release clears both the state and the resp marker atomically.
    getByBackingIndex(idx).state = .intercepted;
    getByBackingIndex(idx).resp_intercepted = true;
    releaseResponseHold(idx, 7);
    try testing.expectEqual(EntryState.normal, getByBackingIndex(idx).state);
    try testing.expect(!getByBackingIndex(idx).resp_intercepted);
    try testing.expectEqual(@as(u64, 7), getByBackingIndex(idx).duration_ms);
}

test "finishIfDangling only finishes accepted, pinned, unstarred entries" {
    clearAll();
    const idx = pushAndPin(Entry{ .timestamp = 1 }).?;

    // Not accepted yet → no-op, still pinned.
    finishIfDangling(idx, 502, 1);
    try testing.expect(getByBackingIndex(idx).pinned);

    // Accepted + pinned → finishes (status set, unpinned).
    markAccepted(idx);
    finishIfDangling(idx, 502, 1);
    try testing.expectEqual(@as(u16, 502), getByBackingIndex(idx).status);
    try testing.expect(!getByBackingIndex(idx).pinned);
}

test "EditableHold.commitRequest applies while held, no-ops once resolved" {
    clearAll();
    var e = Entry{ .timestamp = 1, .state = .intercepted };
    @memcpy(e.method[0..3], "GET");
    e.method_len = 3;
    const idx = pushAndPin(e).?;
    const hold = EditableHold{ .idx = idx, .phase = .request_held };

    try testing.expect(hold.commitRequest("POST", "/x", "H: 1\r\n", "body"));
    var snap: Entry = undefined;
    hold.snapshot(&snap);
    try testing.expectEqualStrings("POST", snap.getMethod());
    try testing.expectEqualStrings("/x", snap.getPath());
    try testing.expectEqualStrings("body", snap.getReqBody());

    // Once the hold is resolved (no longer .intercepted), commits must not write.
    markAccepted(idx);
    try testing.expect(!hold.commitRequest("PUT", "/y", "", ""));
    hold.snapshot(&snap);
    try testing.expectEqualStrings("POST", snap.getMethod()); // unchanged
}

test "EditableHold commits are gated by request vs response phase" {
    clearAll();
    const rq_idx = pushAndPin(Entry{ .timestamp = 1, .state = .intercepted, .resp_intercepted = false }).?;
    const rq_hold = EditableHold{ .idx = rq_idx, .phase = .request_held };
    try testing.expect(rq_hold.commitRequest("POST", "/x", "", ""));
    try testing.expect(!rq_hold.commitResponse(200, "", "")); // wrong phase, rejected

    const rs_idx = pushAndPin(Entry{ .timestamp = 2, .state = .intercepted, .resp_intercepted = true }).?;
    const rs_hold = EditableHold{ .idx = rs_idx, .phase = .response_held };
    try testing.expect(rs_hold.commitResponse(404, "X: y\r\n", "nope"));
    try testing.expect(!rs_hold.commitRequest("GET", "/", "", "")); // wrong phase, rejected
}
