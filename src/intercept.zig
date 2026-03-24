const std = @import("std");

pub const max_pending = 256;

pub const Decision = enum(u8) {
    pending = 0,
    accept = 1,
    drop = 2,
};

pub const PendingEntry = struct {
    active: bool = false,
    backing_index: usize = 0,
    event: std.Thread.ResetEvent = .{},
    decision: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),
};

pub const max_pattern_len = 128;

pub const Phase = enum(u8) {
    both = 0,
    request = 1,
    response = 2,
};

var enabled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var slots: [max_pending]PendingEntry = @splat(PendingEntry{});
var mutex: std.Thread.Mutex = .{};

// Intercept pattern — substring match against "METHOD PATH"
var pattern_buf: [max_pattern_len]u8 = .{0} ** max_pattern_len;
var pattern_len: usize = 0;
var phase: Phase = .both;
var pattern_mutex: std.Thread.Mutex = .{};

pub fn isEnabled() bool {
    return enabled.load(.acquire);
}

pub fn toggle() void {
    const current = enabled.load(.acquire);
    if (current) {
        // Disabling — clear pattern and phase
        setPattern("");
    }
    enabled.store(!current, .release);
}

/// Enable intercept with a specific pattern. Empty pattern = match all.
/// Supports "req:PATTERN" (request only), "resp:PATTERN" (response only), or "PATTERN" (both).
pub fn enableWithPattern(pat: []const u8) void {
    setPattern(pat);
    enabled.store(true, .release);
}

pub fn setPattern(pat: []const u8) void {
    pattern_mutex.lock();
    defer pattern_mutex.unlock();
    // Parse phase prefix
    var actual_pat = pat;
    var p: Phase = .both;
    if (startsWithIgnoreCase(pat, "req:")) {
        p = .request;
        actual_pat = pat[4..];
    } else if (startsWithIgnoreCase(pat, "resp:")) {
        p = .response;
        actual_pat = pat[5..];
    }
    phase = p;
    const len = @min(actual_pat.len, max_pattern_len);
    @memcpy(pattern_buf[0..len], actual_pat[0..len]);
    pattern_len = len;
}

fn startsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    for (0..needle.len) |i| {
        if (std.ascii.toLower(haystack[i]) != std.ascii.toLower(needle[i])) return false;
    }
    return true;
}

pub fn getPattern(buf: *[max_pattern_len]u8) []const u8 {
    pattern_mutex.lock();
    defer pattern_mutex.unlock();
    @memcpy(buf[0..pattern_len], pattern_buf[0..pattern_len]);
    return buf[0..pattern_len];
}

pub fn getPhase() Phase {
    pattern_mutex.lock();
    defer pattern_mutex.unlock();
    return phase;
}

/// Check if a request should be intercepted (phase must be .request or .both).
pub fn shouldInterceptRequest(method: []const u8, path: []const u8) bool {
    if (!enabled.load(.acquire)) return false;
    pattern_mutex.lock();
    defer pattern_mutex.unlock();
    if (phase == .response) return false;
    return matchesPattern(method, path);
}

/// Check if a response should be intercepted (phase must be .response or .both).
pub fn shouldInterceptResponse(method: []const u8, path: []const u8) bool {
    if (!enabled.load(.acquire)) return false;
    pattern_mutex.lock();
    defer pattern_mutex.unlock();
    if (phase == .request) return false;
    return matchesPattern(method, path);
}

/// Internal pattern matching — must be called with pattern_mutex held.
fn matchesPattern(method: []const u8, path: []const u8) bool {
    if (pattern_len == 0) return true;

    const pat = pattern_buf[0..pattern_len];

    if (containsIgnoreCase(method, pat)) return true;
    if (containsIgnoreCase(path, pat)) return true;

    // Build "METHOD PATH" for combined match
    var combined: [520]u8 = undefined;
    if (method.len + 1 + path.len <= combined.len) {
        @memcpy(combined[0..method.len], method);
        combined[method.len] = ' ';
        @memcpy(combined[method.len + 1 ..][0..path.len], path);
        const full = combined[0 .. method.len + 1 + path.len];
        if (containsIgnoreCase(full, pat)) return true;
    }

    return false;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    if (needle.len == 0) return true;
    const end = haystack.len - needle.len + 1;
    for (0..end) |i| {
        var match = true;
        for (0..needle.len) |j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/// Acquire a free intercept slot. Returns null if all slots are occupied.
pub fn acquire() ?*PendingEntry {
    mutex.lock();
    defer mutex.unlock();
    for (&slots) |*slot| {
        if (!slot.active) {
            slot.active = true;
            slot.decision = std.atomic.Value(u8).init(0);
            slot.event = .{};
            return slot;
        }
    }
    return null;
}

/// Release a slot back to the pool. Must be called after the proxy thread wakes up.
pub fn release(slot: *PendingEntry) void {
    mutex.lock();
    defer mutex.unlock();
    slot.active = false;
    slot.backing_index = 0;
}

/// Store a decision and wake the blocked proxy thread.
pub fn setDecision(slot: *PendingEntry, d: Decision) void {
    slot.decision.store(@intFromEnum(d), .release);
    slot.event.set();
}

pub fn getDecision(slot: *PendingEntry) Decision {
    const val = slot.decision.load(.acquire);
    return @enumFromInt(val);
}

/// Accept all pending intercepted entries (requests and responses).
pub fn acceptAll() void {
    mutex.lock();
    defer mutex.unlock();
    for (&slots) |*slot| {
        if (slot.active) {
            slot.decision.store(@intFromEnum(Decision.accept), .release);
            slot.event.set();
        }
    }
}

/// Count active (held) slots.
pub fn getPendingCount() usize {
    mutex.lock();
    defer mutex.unlock();
    var n: usize = 0;
    for (&slots) |*slot| {
        if (slot.active) n += 1;
    }
    return n;
}

/// Find the intercept slot for a given backing index. Returns null if not found.
pub fn findByBackingIndex(backing_idx: usize) ?*PendingEntry {
    mutex.lock();
    defer mutex.unlock();
    for (&slots) |*slot| {
        if (slot.active and slot.backing_index == backing_idx) {
            return slot;
        }
    }
    return null;
}

/// Release all active slots (for testing).
fn releaseAll() void {
    mutex.lock();
    defer mutex.unlock();
    for (&slots) |*slot| {
        slot.active = false;
        slot.backing_index = 0;
    }
}

// --- Unit Tests ---

const testing = std.testing;

test "toggle enables and disables" {
    // Ensure clean state
    enabled.store(false, .release);
    try testing.expect(!isEnabled());
    toggle();
    try testing.expect(isEnabled());
    toggle();
    try testing.expect(!isEnabled());
}

test "acquire and release slot" {
    releaseAll();
    const slot = acquire() orelse return error.TestUnexpectedResult;
    try testing.expect(slot.active);
    try testing.expectEqual(Decision.pending, getDecision(slot));
    try testing.expectEqual(@as(usize, 1), getPendingCount());

    release(slot);
    try testing.expect(!slot.active);
    try testing.expectEqual(@as(usize, 0), getPendingCount());
}

test "acquire returns null when all slots full" {
    releaseAll();
    // Fill all slots
    for (0..max_pending) |_| {
        _ = acquire();
    }
    try testing.expect(acquire() == null);
    try testing.expectEqual(@as(usize, max_pending), getPendingCount());
    releaseAll();
}

test "setDecision and getDecision" {
    releaseAll();
    const slot = acquire() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Decision.pending, getDecision(slot));

    setDecision(slot, .accept);
    try testing.expectEqual(Decision.accept, getDecision(slot));

    release(slot);
}

test "setDecision drop" {
    releaseAll();
    const slot = acquire() orelse return error.TestUnexpectedResult;
    setDecision(slot, .drop);
    try testing.expectEqual(Decision.drop, getDecision(slot));
    release(slot);
}

test "acceptAll wakes all pending" {
    releaseAll();
    const s1 = acquire() orelse return error.TestUnexpectedResult;
    const s2 = acquire() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 2), getPendingCount());

    acceptAll();

    try testing.expectEqual(Decision.accept, getDecision(s1));
    try testing.expectEqual(Decision.accept, getDecision(s2));
    release(s1);
    release(s2);
}

test "findByBackingIndex" {
    releaseAll();
    const slot = acquire() orelse return error.TestUnexpectedResult;
    slot.backing_index = 42;

    const found = findByBackingIndex(42) orelse return error.TestUnexpectedResult;
    try testing.expect(found == slot);
    try testing.expect(findByBackingIndex(99) == null);
    release(slot);
}

test "shouldInterceptRequest with empty pattern matches all" {
    enabled.store(true, .release);
    setPattern("");
    try testing.expect(shouldInterceptRequest("GET", "/api/users"));
    try testing.expect(shouldInterceptRequest("POST", "/login"));
    enabled.store(false, .release);
}

test "shouldInterceptRequest with path pattern" {
    enabled.store(true, .release);
    setPattern("/api");
    try testing.expect(shouldInterceptRequest("GET", "/api/users"));
    try testing.expect(!shouldInterceptRequest("GET", "/login"));
    enabled.store(false, .release);
}

test "shouldInterceptRequest with method pattern" {
    enabled.store(true, .release);
    setPattern("POST");
    try testing.expect(shouldInterceptRequest("POST", "/anything"));
    try testing.expect(!shouldInterceptRequest("GET", "/anything"));
    enabled.store(false, .release);
}

test "shouldInterceptRequest with combined pattern" {
    enabled.store(true, .release);
    setPattern("POST /api");
    try testing.expect(shouldInterceptRequest("POST", "/api/auth"));
    try testing.expect(!shouldInterceptRequest("GET", "/api/auth"));
    try testing.expect(!shouldInterceptRequest("POST", "/login"));
    enabled.store(false, .release);
}

test "shouldInterceptRequest case insensitive" {
    enabled.store(true, .release);
    setPattern("post /API");
    try testing.expect(shouldInterceptRequest("POST", "/api/auth"));
    enabled.store(false, .release);
}

test "shouldInterceptRequest returns false when disabled" {
    enabled.store(false, .release);
    setPattern("/api");
    try testing.expect(!shouldInterceptRequest("GET", "/api/users"));
}

test "req: prefix intercepts only requests" {
    enabled.store(true, .release);
    setPattern("req:/api");
    try testing.expect(shouldInterceptRequest("GET", "/api/users"));
    try testing.expect(!shouldInterceptResponse("GET", "/api/users"));
    try testing.expectEqual(Phase.request, getPhase());
    enabled.store(false, .release);
}

test "resp: prefix intercepts only responses" {
    enabled.store(true, .release);
    setPattern("resp:/api");
    try testing.expect(!shouldInterceptRequest("GET", "/api/users"));
    try testing.expect(shouldInterceptResponse("GET", "/api/users"));
    try testing.expectEqual(Phase.response, getPhase());
    enabled.store(false, .release);
}

test "no prefix intercepts both" {
    enabled.store(true, .release);
    setPattern("/api");
    try testing.expect(shouldInterceptRequest("GET", "/api/users"));
    try testing.expect(shouldInterceptResponse("GET", "/api/users"));
    try testing.expectEqual(Phase.both, getPhase());
    enabled.store(false, .release);
}

test "empty pattern with resp: intercepts all responses" {
    enabled.store(true, .release);
    setPattern("resp:");
    try testing.expect(!shouldInterceptRequest("GET", "/anything"));
    try testing.expect(shouldInterceptResponse("GET", "/anything"));
    enabled.store(false, .release);
}

test "toggle clears pattern" {
    enabled.store(false, .release);
    setPattern("test");
    toggle(); // enable
    try testing.expect(isEnabled());
    var buf: [max_pattern_len]u8 = undefined;
    try testing.expectEqualStrings("test", getPattern(&buf));
    toggle(); // disable — should clear
    try testing.expect(!isEnabled());
    try testing.expectEqualStrings("", getPattern(&buf));
}

test "multiple acquire and release cycle" {
    releaseAll();
    var acquired: [4]*PendingEntry = undefined;
    for (0..4) |i| {
        acquired[i] = acquire() orelse return error.TestUnexpectedResult;
        acquired[i].backing_index = i;
    }
    try testing.expectEqual(@as(usize, 4), getPendingCount());

    // Release middle ones
    release(acquired[1]);
    release(acquired[2]);
    try testing.expectEqual(@as(usize, 2), getPendingCount());

    // Re-acquire should succeed
    const new_slot = acquire() orelse return error.TestUnexpectedResult;
    try testing.expect(new_slot.active);
    release(new_slot);
    release(acquired[0]);
    release(acquired[3]);
}
