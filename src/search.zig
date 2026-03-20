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
