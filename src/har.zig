const std = @import("std");
const requests = @import("requests.zig");

/// Export visible requests as a HAR file. Writes filename to fname_out, returns length or null on failure.
pub fn exportHar(entries: []*const requests.Entry, entry_count: usize, domain: []const u8, fname_out: *[64]u8) ?usize {
    // Generate filename with timestamp
    const now_ms = std.time.milliTimestamp();
    const now_s: u64 = if (now_ms > 0) @intCast(@divTrunc(now_ms, 1000)) else 0;
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = now_s };
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch_secs.getDaySeconds();

    const fname = std.fmt.bufPrint(fname_out, "zlodev_{d:0>4}{d:0>2}{d:0>2}_{d:0>2}{d:0>2}{d:0>2}.har", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    }) catch return null;

    const file = std.fs.cwd().createFile(fname, .{}) catch return null;
    defer file.close();
    const wr = struct {
        fn writeAll(f: std.fs.File, data: []const u8) !void {
            try f.writeAll(data);
        }
        fn writeByte(f: std.fs.File, byte: u8) !void {
            try f.writeAll(&.{byte});
        }
    };

    wr.writeAll(file, "{\"log\":{\"version\":\"1.2\",\"creator\":{\"name\":\"zlodev\",\"version\":\"1.0\"},\"entries\":[") catch return null;

    for (0..entry_count) |fi| {
        const entry = entries[fi];
        if (fi > 0) wr.writeByte(file, ',') catch return null;

        // startedDateTime
        const ts_s: u64 = if (entry.timestamp > 0) @intCast(@divTrunc(entry.timestamp, 1000)) else 0;
        const ts_ms: u64 = if (entry.timestamp > 0) @intCast(@mod(entry.timestamp, 1000)) else 0;
        const es = std.time.epoch.EpochSeconds{ .secs = ts_s };
        const ed = es.getEpochDay();
        const yd = ed.calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();

        var dt_buf: [32]u8 = undefined;
        const dt = std.fmt.bufPrint(&dt_buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
            yd.year, md.month.numeric(), md.day_index + 1,
            ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(), ts_ms,
        }) catch "1970-01-01T00:00:00.000Z";

        wr.writeAll(file, "{\"startedDateTime\":\"") catch return null;
        wr.writeAll(file, dt) catch return null;
        wr.writeAll(file, "\",\"time\":") catch return null;
        var time_buf: [20]u8 = undefined;
        wr.writeAll(file, std.fmt.bufPrint(&time_buf, "{d}", .{entry.duration_ms}) catch "0") catch return null;

        // Request
        wr.writeAll(file, ",\"request\":{\"method\":\"") catch return null;
        wr.writeAll(file, entry.getMethod()) catch return null;
        wr.writeAll(file, "\",\"url\":\"https://") catch return null;
        writeJsonEscapedFile(file, domain) catch return null;
        writeJsonEscapedFile(file, entry.getPath()) catch return null;
        wr.writeAll(file, "\",\"httpVersion\":\"HTTP/1.1\",\"cookies\":[],\"queryString\":[],\"headersSize\":-1,\"bodySize\":") catch return null;
        var bs_buf: [12]u8 = undefined;
        wr.writeAll(file, std.fmt.bufPrint(&bs_buf, "{d}", .{entry.req_body_len}) catch "0") catch return null;

        // Request headers
        wr.writeAll(file, ",\"headers\":[") catch return null;
        writeHeadersJsonFile(file, entry.getReqHeaders()) catch return null;
        wr.writeByte(file, ']') catch return null;

        // Request body (postData)
        const req_body = entry.getReqBody();
        if (req_body.len > 0) {
            wr.writeAll(file, ",\"postData\":{\"mimeType\":\"\",\"text\":\"") catch return null;
            writeJsonEscapedFile(file, req_body) catch return null;
            wr.writeAll(file, "\"}") catch return null;
        }
        wr.writeByte(file, '}') catch return null;

        // Response
        wr.writeAll(file, ",\"response\":{\"status\":") catch return null;
        var st_buf: [6]u8 = undefined;
        wr.writeAll(file, std.fmt.bufPrint(&st_buf, "{d}", .{entry.status}) catch "0") catch return null;
        wr.writeAll(file, ",\"statusText\":\"\",\"httpVersion\":\"HTTP/1.1\",\"cookies\":[],\"redirectURL\":\"\",\"headersSize\":-1,\"bodySize\":") catch return null;
        var rbs_buf: [12]u8 = undefined;
        wr.writeAll(file, std.fmt.bufPrint(&rbs_buf, "{d}", .{entry.resp_body_len}) catch "0") catch return null;

        // Response headers
        wr.writeAll(file, ",\"headers\":[") catch return null;
        writeHeadersJsonFile(file, entry.getRespHeaders()) catch return null;
        wr.writeByte(file, ']') catch return null;

        // Response content
        wr.writeAll(file, ",\"content\":{\"size\":") catch return null;
        wr.writeAll(file, std.fmt.bufPrint(&rbs_buf, "{d}", .{entry.resp_body_len}) catch "0") catch return null;
        wr.writeAll(file, ",\"mimeType\":\"\",\"text\":\"") catch return null;
        writeJsonEscapedFile(file, entry.getRespBody()) catch return null;
        wr.writeAll(file, "\"}}") catch return null;

        // Timings + cache
        wr.writeAll(file, ",\"cache\":{},\"timings\":{\"send\":-1,\"wait\":-1,\"receive\":-1}}") catch return null;
    }

    wr.writeAll(file, "]}}") catch return null;

    return fname.len;
}

fn writeJsonEscapedFile(f: std.fs.File, data: []const u8) !void {
    for (data) |ch| {
        switch (ch) {
            '"' => try f.writeAll("\\\""),
            '\\' => try f.writeAll("\\\\"),
            '\n' => try f.writeAll("\\n"),
            '\r' => try f.writeAll("\\r"),
            '\t' => try f.writeAll("\\t"),
            else => {
                if (ch < 0x20) {
                    var esc_buf: [6]u8 = undefined;
                    const esc = std.fmt.bufPrint(&esc_buf, "\\u{x:0>4}", .{ch}) catch continue;
                    try f.writeAll(esc);
                } else {
                    try f.writeAll(&.{ch});
                }
            },
        }
    }
}

fn writeHeadersJsonFile(f: std.fs.File, raw_headers: []const u8) !void {
    var iter = std.mem.splitSequence(u8, raw_headers, "\r\n");
    var first = true;
    while (iter.next()) |header| {
        if (header.len == 0) continue;
        if (!first) try f.writeAll(",");
        first = false;
        if (std.mem.indexOf(u8, header, ": ")) |sep| {
            try f.writeAll("{\"name\":\"");
            try writeJsonEscapedFile(f, header[0..sep]);
            try f.writeAll("\",\"value\":\"");
            try writeJsonEscapedFile(f, header[sep + 2 ..]);
            try f.writeAll("\"}");
        } else {
            try f.writeAll("{\"name\":\"");
            try writeJsonEscapedFile(f, header);
            try f.writeAll("\",\"value\":\"\"}");
        }
    }
}

// --- Unit Tests ---

const testing = std.testing;

/// Helper: write JSON-escaped text to a buffer via a temp file, return the result.
fn escapeToString(input: []const u8, buf: []u8) ![]const u8 {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try tmp.dir.createFile("esc_test", .{ .read = true });
    defer f.close();
    try writeJsonEscapedFile(f, input);
    try f.seekTo(0);
    const n = try f.readAll(buf);
    return buf[0..n];
}

/// Helper: write headers JSON to a buffer via a temp file, return the result.
fn headersToString(input: []const u8, buf: []u8) ![]const u8 {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try tmp.dir.createFile("hdr_test", .{ .read = true });
    defer f.close();
    try writeHeadersJsonFile(f, input);
    try f.seekTo(0);
    const n = try f.readAll(buf);
    return buf[0..n];
}

test "writeJsonEscapedFile plain text" {
    var buf: [256]u8 = undefined;
    const result = try escapeToString("hello world", &buf);
    try testing.expectEqualStrings("hello world", result);
}

test "writeJsonEscapedFile escapes quotes and backslashes" {
    var buf: [256]u8 = undefined;
    const result = try escapeToString("say \"hello\" and \\path", &buf);
    try testing.expectEqualStrings("say \\\"hello\\\" and \\\\path", result);
}

test "writeJsonEscapedFile escapes control characters" {
    var buf: [256]u8 = undefined;
    const result = try escapeToString("line1\nline2\r\tend", &buf);
    try testing.expectEqualStrings("line1\\nline2\\r\\tend", result);
}

test "writeJsonEscapedFile escapes low control chars" {
    var buf: [256]u8 = undefined;
    const result = try escapeToString(&.{0x01}, &buf);
    // Should produce \u0001
    try testing.expectEqualStrings("\\u0001", result);
}

test "writeJsonEscapedFile empty input" {
    var buf: [256]u8 = undefined;
    const result = try escapeToString("", &buf);
    try testing.expectEqualStrings("", result);
}

test "writeHeadersJsonFile single header" {
    var buf: [512]u8 = undefined;
    const result = try headersToString("Content-Type: text/html", &buf);
    try testing.expectEqualStrings("{\"name\":\"Content-Type\",\"value\":\"text/html\"}", result);
}

test "writeHeadersJsonFile multiple headers" {
    var buf: [1024]u8 = undefined;
    const result = try headersToString("Host: dev.lo\r\nAccept: */*", &buf);
    try testing.expectEqualStrings(
        "{\"name\":\"Host\",\"value\":\"dev.lo\"},{\"name\":\"Accept\",\"value\":\"*/*\"}",
        result,
    );
}

test "writeHeadersJsonFile header without value separator" {
    var buf: [512]u8 = undefined;
    const result = try headersToString("MalformedHeader", &buf);
    try testing.expectEqualStrings("{\"name\":\"MalformedHeader\",\"value\":\"\"}", result);
}

test "writeHeadersJsonFile empty input" {
    var buf: [256]u8 = undefined;
    const result = try headersToString("", &buf);
    try testing.expectEqualStrings("", result);
}

test "writeHeadersJsonFile skips empty lines" {
    var buf: [1024]u8 = undefined;
    const result = try headersToString("Host: dev.lo\r\n\r\nAccept: */*", &buf);
    try testing.expectEqualStrings(
        "{\"name\":\"Host\",\"value\":\"dev.lo\"},{\"name\":\"Accept\",\"value\":\"*/*\"}",
        result,
    );
}

test "exportHar produces valid JSON structure" {
    var e1 = requests.Entry{};
    const m = "GET";
    @memcpy(e1.method[0..m.len], m);
    e1.method_len = m.len;
    const p = "/test";
    @memcpy(e1.path[0..p.len], p);
    e1.path_len = p.len;
    e1.status = 200;
    e1.duration_ms = 15;
    e1.timestamp = 1700000000000; // 2023-11-14T22:13:20Z

    const rh = "Content-Type: application/json";
    @memcpy(e1.resp_headers[0..rh.len], rh);
    e1.resp_headers_len = @intCast(rh.len);
    const rb = "{\"ok\":true}";
    @memcpy(e1.resp_body[0..rb.len], rb);
    e1.resp_body_len = @intCast(rb.len);

    var entry_ptrs: [1]*const requests.Entry = .{&e1};

    var fname_buf: [64]u8 = undefined;
    const fname_len = exportHar(&entry_ptrs, 1, "dev.lo", &fname_buf) orelse {
        return error.TestUnexpectedResult;
    };
    const fname = fname_buf[0..fname_len];
    defer std.fs.cwd().deleteFile(fname) catch {};

    const file = std.fs.cwd().openFile(fname, .{}) catch return error.TestUnexpectedResult;
    defer file.close();
    const content = file.readToEndAlloc(testing.allocator, 1024 * 1024) catch return error.TestUnexpectedResult;
    defer testing.allocator.free(content);

    // Verify it starts and ends correctly
    try testing.expect(std.mem.startsWith(u8, content, "{\"log\":{\"version\":\"1.2\""));
    try testing.expect(std.mem.endsWith(u8, content, "]}}"));

    // Verify key fields are present
    try testing.expect(std.mem.indexOf(u8, content, "\"method\":\"GET\"") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"url\":\"https://dev.lo/test\"") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"status\":200") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"time\":15") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"name\":\"Content-Type\"") != null);
    try testing.expect(std.mem.indexOf(u8, content, "{\\\"ok\\\":true}") != null);
}

test "exportHar with empty entries" {
    var entry_ptrs: [0]*const requests.Entry = .{};

    var fname_buf: [64]u8 = undefined;
    const fname_len = exportHar(&entry_ptrs, 0, "dev.lo", &fname_buf) orelse {
        return error.TestUnexpectedResult;
    };
    const fname = fname_buf[0..fname_len];
    defer std.fs.cwd().deleteFile(fname) catch {};

    const file = std.fs.cwd().openFile(fname, .{}) catch return error.TestUnexpectedResult;
    defer file.close();
    const content = file.readToEndAlloc(testing.allocator, 1024 * 1024) catch return error.TestUnexpectedResult;
    defer testing.allocator.free(content);

    try testing.expectEqualStrings("{\"log\":{\"version\":\"1.2\",\"creator\":{\"name\":\"zlodev\",\"version\":\"1.0\"},\"entries\":[]}}", content);
}

test "exportHar filename format" {
    var e = requests.Entry{};
    e.method_len = 0;
    var entry_ptrs: [1]*const requests.Entry = .{&e};

    var fname_buf: [64]u8 = undefined;
    const fname_len = exportHar(&entry_ptrs, 1, "dev.lo", &fname_buf) orelse {
        return error.TestUnexpectedResult;
    };
    const fname = fname_buf[0..fname_len];
    defer std.fs.cwd().deleteFile(fname) catch {};

    // Filename should match pattern: zlodev_YYYYMMDD_HHMMSS.har
    try testing.expect(std.mem.startsWith(u8, fname, "zlodev_"));
    try testing.expect(std.mem.endsWith(u8, fname, ".har"));
    try testing.expectEqual(@as(usize, 26), fname.len);
}
