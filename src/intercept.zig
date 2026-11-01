const std = @import("std");
const rt = @import("rt.zig");

pub const max_pending = 256;

pub const Decision = enum(u8) {
    pending = 0,
    accept = 1,
    drop = 2,
};

pub const PendingEntry = struct {
    active: bool = false,
    backing_index: usize = 0,
    event: std.Io.Event = .unset,
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
var mutex: std.Io.Mutex = .init;

// Intercept pattern — substring match against "METHOD PATH"
var pattern_buf: [max_pattern_len]u8 = @splat(0);
var pattern_len: usize = 0;
var phase: Phase = .both;
var pattern_mutex: std.Io.Mutex = .init;

pub fn isEnabled() bool {
    return enabled.load(.acquire);
}

pub fn toggle() void {
    var current = enabled.load(.acquire);
    while (true) {
        if (current) {
            // Disabling — clear pattern and phase
            setPattern("");
        }
        if (enabled.cmpxchgWeak(current, !current, .acq_rel, .acquire)) |actual| {
            current = actual;
        } else break;
    }
}

/// Enable intercept with a specific pattern. Empty pattern = match all.
/// Supports "req:PATTERN" (request only), "resp:PATTERN" (response only), or "PATTERN" (both).
pub fn enableWithPattern(pat: []const u8) void {
    setPattern(pat);
    enabled.store(true, .release);
}

pub fn setPattern(pat: []const u8) void {
    pattern_mutex.lockUncancelable(rt.io());
    defer pattern_mutex.unlock(rt.io());
    // Parse phase prefix
    var actual_pat = pat;
    var p: Phase = .both;
    if (std.ascii.startsWithIgnoreCase(pat, "req:")) {
        p = .request;
        actual_pat = pat[4..];
    } else if (std.ascii.startsWithIgnoreCase(pat, "resp:")) {
        p = .response;
        actual_pat = pat[5..];
    }
    phase = p;
    const len = @min(actual_pat.len, max_pattern_len);
    @memcpy(pattern_buf[0..len], actual_pat[0..len]);
    pattern_len = len;
}

pub fn getPattern(buf: *[max_pattern_len]u8) []const u8 {
    pattern_mutex.lockUncancelable(rt.io());
    defer pattern_mutex.unlock(rt.io());
    @memcpy(buf[0..pattern_len], pattern_buf[0..pattern_len]);
    return buf[0..pattern_len];
}

pub fn getPhase() Phase {
    pattern_mutex.lockUncancelable(rt.io());
    defer pattern_mutex.unlock(rt.io());
    return phase;
}

/// Check if a request should be intercepted (phase must be .request or .both).
pub fn shouldInterceptRequest(method: []const u8, path: []const u8) bool {
    if (!enabled.load(.acquire)) return false;
    pattern_mutex.lockUncancelable(rt.io());
    defer pattern_mutex.unlock(rt.io());
    if (phase == .response) return false;
    return matchesPattern(method, path);
}

/// Check if a response should be intercepted (phase must be .response or .both).
pub fn shouldInterceptResponse(method: []const u8, path: []const u8) bool {
    if (!enabled.load(.acquire)) return false;
    pattern_mutex.lockUncancelable(rt.io());
    defer pattern_mutex.unlock(rt.io());
    if (phase == .request) return false;
    return matchesPattern(method, path);
}

/// Internal pattern matching — must be called with pattern_mutex held.
fn matchesPattern(method: []const u8, path: []const u8) bool {
    if (pattern_len == 0) return true;

    const pat = pattern_buf[0..pattern_len];

    if (std.ascii.findIgnoreCase(method, pat) != null) return true;
    if (std.ascii.findIgnoreCase(path, pat) != null) return true;

    // Build "METHOD PATH" for combined match
    var combined: [520]u8 = undefined;
    if (method.len + 1 + path.len <= combined.len) {
        @memcpy(combined[0..method.len], method);
        combined[method.len] = ' ';
        @memcpy(combined[method.len + 1 ..][0..path.len], path);
        const full = combined[0 .. method.len + 1 + path.len];
        if (std.ascii.findIgnoreCase(full, pat) != null) return true;
    }

    return false;
}

/// Acquire a free intercept slot and register it to a ring backing index.
/// Returns null if all slots are occupied.
pub fn acquire(backing_idx: usize) ?*PendingEntry {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    for (&slots) |*slot| {
        if (!slot.active) {
            slot.active = true;
            slot.decision = std.atomic.Value(u8).init(0);
            slot.event = .unset;
            slot.backing_index = backing_idx;
            return slot;
        }
    }
    return null;
}

/// Release a slot back to the pool. Must be called after the proxy thread wakes up.
pub fn release(slot: *PendingEntry) void {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    slot.active = false;
    slot.backing_index = 0;
}

/// Block until a decision is stored on the slot, then reset the event and
/// release the slot. The single proxy-side entry point for waiting on a hold.
pub fn awaitAndRelease(slot: *PendingEntry) Decision {
    slot.event.waitUncancelable(rt.io());
    const d = getDecision(slot);
    slot.event.reset();
    release(slot);
    return d;
}

/// Resolve a held entry by backing index from the UI side: store the decision
/// and wake the blocked proxy thread. No-op if no active slot matches.
pub fn resolve(backing_idx: usize, d: Decision) void {
    const slot = findByBackingIndex(backing_idx) orelse return;
    setDecision(slot, d);
}

/// Store a decision and wake the blocked proxy thread.
fn setDecision(slot: *PendingEntry, d: Decision) void {
    slot.decision.store(@intFromEnum(d), .release);
    slot.event.set(rt.io());
}

fn getDecision(slot: *PendingEntry) Decision {
    const val = slot.decision.load(.acquire);
    return @enumFromInt(val);
}

/// Accept all pending intercepted entries (requests and responses).
pub fn acceptAll() void {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    for (&slots) |*slot| {
        if (slot.active) {
            slot.decision.store(@intFromEnum(Decision.accept), .release);
            slot.event.set(rt.io());
        }
    }
}

/// Drop all pending intercepts — sets decision to drop and signals all active slots.
/// Used by clearAll() to wake blocked proxy threads before clearing entries.
pub fn dropAll() void {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    for (&slots) |*s| {
        if (s.active) {
            s.decision.store(@intFromEnum(Decision.drop), .release);
            s.event.set(rt.io());
        }
    }
}

/// Count active (held) slots.
pub fn getPendingCount() usize {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    var n: usize = 0;
    for (&slots) |*slot| {
        if (slot.active) n += 1;
    }
    return n;
}

/// Find the intercept slot for a given backing index. Returns null if not found.
fn findByBackingIndex(backing_idx: usize) ?*PendingEntry {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
    for (&slots) |*slot| {
        if (slot.active and slot.backing_index == backing_idx) {
            return slot;
        }
    }
    return null;
}

/// Release all active slots (for testing).
fn releaseAll() void {
    mutex.lockUncancelable(rt.io());
    defer mutex.unlock(rt.io());
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
    const slot = acquire(0) orelse return error.TestUnexpectedResult;
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
        _ = acquire(0);
    }
    try testing.expect(acquire(0) == null);
    try testing.expectEqual(@as(usize, max_pending), getPendingCount());
    releaseAll();
}

test "setDecision and getDecision" {
    releaseAll();
    const slot = acquire(0) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Decision.pending, getDecision(slot));

    setDecision(slot, .accept);
    try testing.expectEqual(Decision.accept, getDecision(slot));

    release(slot);
}

test "setDecision drop" {
    releaseAll();
    const slot = acquire(0) orelse return error.TestUnexpectedResult;
    setDecision(slot, .drop);
    try testing.expectEqual(Decision.drop, getDecision(slot));
    release(slot);
}

test "acceptAll wakes all pending" {
    releaseAll();
    const s1 = acquire(0) orelse return error.TestUnexpectedResult;
    const s2 = acquire(0) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 2), getPendingCount());

    acceptAll();

    try testing.expectEqual(Decision.accept, getDecision(s1));
    try testing.expectEqual(Decision.accept, getDecision(s2));
    release(s1);
    release(s2);
}

test "findByBackingIndex" {
    releaseAll();
    const slot = acquire(42) orelse return error.TestUnexpectedResult;

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
        acquired[i] = acquire(i) orelse return error.TestUnexpectedResult;
    }
    try testing.expectEqual(@as(usize, 4), getPendingCount());

    // Release middle ones
    release(acquired[1]);
    release(acquired[2]);
    try testing.expectEqual(@as(usize, 2), getPendingCount());

    // Re-acquire should succeed
    const new_slot = acquire(0) orelse return error.TestUnexpectedResult;
    try testing.expect(new_slot.active);
    release(new_slot);
    release(acquired[0]);
    release(acquired[3]);
}

test "dropAll signals all active slots" {
    releaseAll();
    const s = acquire(0).?;
    try std.testing.expect(s.active);
    try std.testing.expectEqual(@as(usize, 1), getPendingCount());

    dropAll();
    try std.testing.expectEqual(@as(u8, @intFromEnum(Decision.drop)), s.decision.load(.acquire));

    s.event.waitUncancelable(rt.io());
    s.event.reset();
    release(s);
    try std.testing.expectEqual(@as(usize, 0), getPendingCount());
}
