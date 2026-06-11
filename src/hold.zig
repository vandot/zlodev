const std = @import("std");
const requests = @import("requests.zig");
const intercept = @import("intercept.zig");

/// A coordinator over a single intercepted entry: it owns both the ring pin and
/// the intercept slot for the lifetime of an operator hold, so proxy.zig never
/// drives the acquire/register/wait/reset/release protocol by hand.
///
/// Lifecycle: `begin` pins the entry and acquires a slot; `awaitDecision` blocks
/// until the operator resolves it (and releases the slot on return); then exactly
/// one of `accept` / `drop` finalizes the ring state for the chosen decision.
pub const Hold = struct {
    idx: usize,
    slot: *intercept.PendingEntry,
    started: i64,

    /// Block until the operator decides. Resets + releases the slot internally.
    pub fn awaitDecision(self: *const Hold) intercept.Decision {
        return intercept.awaitAndRelease(self.slot);
    }

    /// Accept: mark the ring entry accepted. The caller still forwards/finishes
    /// per phase (request continues upstream; response is forwarded then finished).
    pub fn accept(self: *const Hold) void {
        requests.markAccepted(self.idx);
    }

    /// Drop: record how long the entry was held, mark it dropped, and unpin.
    pub fn drop(self: *const Hold) void {
        requests.markDropped(self.idx, elapsedSince(self.started));
        requests.unpin(self.idx);
    }

    /// Backing index of the held ring entry.
    pub fn index(self: *const Hold) usize {
        return self.idx;
    }
};

/// Begin a hold on an already state-tagged entry: pin it into the ring and acquire
/// an intercept slot. Returns null if the ring is full of pins or every slot is
/// busy; on the no-slot case the pinned entry is restored to a normal capture so
/// the caller can fall back to forwarding it untouched.
pub fn begin(entry: *const requests.Entry, is_response: bool, started: i64) ?Hold {
    const idx = requests.pushAndPin(entry.*) orelse return null;
    const slot = intercept.acquire(idx) orelse {
        if (is_response) requests.releaseResponseHold(idx, 0) else requests.releaseHold(idx);
        requests.unpin(idx);
        return null;
    };
    return Hold{ .idx = idx, .slot = slot, .started = started };
}

fn elapsedSince(t: i64) u64 {
    const e = std.time.milliTimestamp() - t;
    return if (e > 0) @intCast(e) else 0;
}

// --- Unit Tests ---

const testing = std.testing;

test "begin pins and registers; resolve round-trips through awaitDecision" {
    requests.clearAll();
    const e = requests.Entry{ .timestamp = 1 };
    const h = begin(&e, false, std.time.milliTimestamp()).?;

    // Resolve before awaiting: the event is already set, so awaitDecision returns at once.
    intercept.resolve(h.index(), .accept);
    try testing.expectEqual(intercept.Decision.accept, h.awaitDecision());
    try testing.expectEqual(@as(usize, 0), intercept.getPendingCount());
}

test "drop decision finalizes the ring entry" {
    requests.clearAll();
    const e = requests.Entry{ .timestamp = 1 };
    const h = begin(&e, true, std.time.milliTimestamp() - 5).?;

    intercept.resolve(h.index(), .drop);
    try testing.expectEqual(intercept.Decision.drop, h.awaitDecision());
    h.drop();
    try testing.expectEqual(@as(usize, 0), intercept.getPendingCount());
}
