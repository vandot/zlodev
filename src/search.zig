const std = @import("std");
const requests = @import("requests.zig");
const clipboard = @import("clipboard.zig");

pub fn entryMatchesSearch(entry: *const requests.Entry, term: []const u8) bool {
    if (term.len == 0) return true;
    // Match against path (case-insensitive)
    const path = entry.getPath();
    if (clipboard.containsIgnoreCase(path, term)) return true;
    // Match against method
    const method = entry.getMethod();
    if (clipboard.containsIgnoreCase(method, term)) return true;
    // Match against status code
    var status_buf: [6]u8 = undefined;
    const status_text = std.fmt.bufPrint(&status_buf, "{d}", .{entry.status}) catch "";
    if (std.mem.indexOf(u8, status_text, term) != null) return true;
    // Match against state labels
    if (entry.state == .intercepted and clipboard.containsIgnoreCase("HOLD", term)) return true;
    if (entry.state == .dropped and clipboard.containsIgnoreCase("DROP", term)) return true;
    return false;
}

// --- Unit Tests ---

const testing = std.testing;

fn makeTestEntry(method: []const u8, path: []const u8, status: u16, state: requests.EntryState) requests.Entry {
    var e = requests.Entry{};
    const m_len: u8 = @intCast(@min(method.len, e.method.len));
    @memcpy(e.method[0..m_len], method[0..m_len]);
    e.method_len = m_len;
    const p_len: u16 = @intCast(@min(path.len, e.path.len));
    @memcpy(e.path[0..p_len], path[0..p_len]);
    e.path_len = p_len;
    e.status = status;
    e.state = state;
    return e;
}

test "empty search matches everything" {
    var e = makeTestEntry("GET", "/api", 200, .normal);
    try testing.expect(entryMatchesSearch(&e, ""));
}

test "search matches path" {
    var e = makeTestEntry("GET", "/api/users", 200, .normal);
    try testing.expect(entryMatchesSearch(&e, "/api"));
    try testing.expect(entryMatchesSearch(&e, "users"));
    try testing.expect(!entryMatchesSearch(&e, "/login"));
}

test "search matches path case insensitive" {
    var e = makeTestEntry("GET", "/API/Users", 200, .normal);
    try testing.expect(entryMatchesSearch(&e, "api"));
    try testing.expect(entryMatchesSearch(&e, "USERS"));
}

test "search matches method" {
    var e = makeTestEntry("POST", "/anything", 200, .normal);
    try testing.expect(entryMatchesSearch(&e, "POST"));
    try testing.expect(entryMatchesSearch(&e, "post"));
    try testing.expect(!entryMatchesSearch(&e, "GET"));
}

test "search matches status code" {
    var e = makeTestEntry("GET", "/api", 404, .normal);
    try testing.expect(entryMatchesSearch(&e, "404"));
    try testing.expect(entryMatchesSearch(&e, "40"));
    try testing.expect(!entryMatchesSearch(&e, "200"));
}

test "search matches HOLD for intercepted" {
    var e = makeTestEntry("GET", "/api", 200, .intercepted);
    try testing.expect(entryMatchesSearch(&e, "HOLD"));
    try testing.expect(entryMatchesSearch(&e, "hold"));
}

test "search matches DROP for dropped" {
    var e = makeTestEntry("GET", "/api", 200, .dropped);
    try testing.expect(entryMatchesSearch(&e, "DROP"));
    try testing.expect(entryMatchesSearch(&e, "drop"));
}

test "HOLD does not match normal entries" {
    var e = makeTestEntry("GET", "/api", 200, .normal);
    try testing.expect(!entryMatchesSearch(&e, "HOLD"));
}

test "DROP does not match normal entries" {
    var e = makeTestEntry("GET", "/api", 200, .normal);
    try testing.expect(!entryMatchesSearch(&e, "DROP"));
}
