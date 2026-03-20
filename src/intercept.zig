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

var enabled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var slots: [max_pending]PendingEntry = @splat(PendingEntry{});
var mutex: std.Thread.Mutex = .{};

pub fn isEnabled() bool {
    return enabled.load(.acquire);
}

pub fn toggle() void {
    const current = enabled.load(.acquire);
    enabled.store(!current, .release);
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

/// Accept all pending intercepted requests.
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
