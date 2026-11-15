//! HTTP/1.1 wire format: header inspection and chunked transfer-encoding decoding.
//! Pure functions over byte buffers — no sockets, no TLS — so the parsing and the
//! chunked state machine are unit-testable without standing up a connection.
const std = @import("std");

pub const ConnectionHeader = enum { keep_alive, close, none };

pub const ChunkState = enum {
    size,
    size_ext,
    size_cr,
    data,
    data_cr,
    data_lf,
    trailer_start,
    trailer_line,
    trailer_line_cr,
    trailer_end_cr,
    done,
    parse_error,
};

pub fn getHeaderValue(headers: []const u8, comptime name: []const u8) ?[]const u8 {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |line| {
        if (std.ascii.startsWithIgnoreCase(line, name)) {
            return std.mem.trim(u8, line[name.len..], " \t");
        }
    }
    return null;
}

pub fn getConnectionHeader(headers: []const u8) ConnectionHeader {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |line| {
        if (std.ascii.startsWithIgnoreCase(line, "connection:")) {
            const value = std.mem.trim(u8, line["connection:".len..], " \t");
            if (std.ascii.startsWithIgnoreCase(value, "close")) return .close;
            if (std.ascii.startsWithIgnoreCase(value, "keep-alive")) return .keep_alive;
        }
    }
    return .none;
}

pub fn getContentLength(headers: []const u8) ?usize {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |line| {
        if (std.ascii.startsWithIgnoreCase(line, "content-length:")) {
            const value = std.mem.trim(u8, line["content-length:".len..], " \t");
            return std.fmt.parseInt(usize, value, 10) catch null;
        }
    }
    return null;
}

pub fn isChunkedEncoding(headers: []const u8) bool {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |header| {
        if (std.ascii.startsWithIgnoreCase(header, "transfer-encoding:")) {
            const value = std.mem.trimStart(u8, header["transfer-encoding:".len..], " ");
            var token_iter = std.mem.splitScalar(u8, value, ',');
            while (token_iter.next()) |token| {
                const trimmed = std.mem.trim(u8, token, " ");
                if (trimmed.len == 7 and std.ascii.startsWithIgnoreCase(trimmed, "chunked")) return true;
            }
        }
    }
    return false;
}

pub fn isWebSocketUpgrade(headers: []const u8) bool {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |header| {
        if (std.ascii.startsWithIgnoreCase(header, "upgrade:")) {
            const value = std.mem.trimStart(u8, header["upgrade:".len..], " ");
            if (std.ascii.startsWithIgnoreCase(value, "websocket")) return true;
        }
    }
    return false;
}

pub fn reasonPhrase(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        else => "OK",
    };
}

/// Advance the chunked-decoder one byte. Decoded body bytes are appended to `body`
/// up to its length (`captured` tracks how many landed); excess is dropped but
/// parsing continues and `truncated` is set so the caller can flag the loss.
/// Invalid framing transitions to `.parse_error`; the terminal trailer transitions
/// to `.done`. Callers drive this over their transport and stop on `.done` or
/// `.parse_error`. Prefer `pumpChunked` over driving this by hand.
pub fn chunkedStep(
    byte: u8,
    state: *ChunkState,
    chunk_remaining: *usize,
    size_val: *usize,
    body: []u8,
    captured: *usize,
    truncated: *bool,
) void {
    switch (state.*) {
        .size => {
            if (byte == '\r') {
                state.* = .size_cr;
            } else if (byte == ';') {
                state.* = .size_ext;
            } else {
                const digit = std.fmt.charToDigit(byte, 16) catch {
                    state.* = .parse_error;
                    return;
                };
                // Guard against maliciously long hex strings overflowing usize
                if (size_val.* > std.math.maxInt(usize) / 16) {
                    state.* = .parse_error;
                    return;
                }
                size_val.* = size_val.* * 16 + digit;
            }
        },
        .size_ext => {
            if (byte == '\r') state.* = .size_cr;
        },
        .size_cr => {
            if (byte != '\n') {
                state.* = .parse_error;
                return;
            }
            chunk_remaining.* = size_val.*;
            size_val.* = 0;
            if (chunk_remaining.* == 0) {
                state.* = .trailer_start;
            } else {
                state.* = .data;
            }
        },
        .data => {
            if (captured.* < body.len) {
                body[captured.*] = byte;
                captured.* += 1;
            } else {
                truncated.* = true;
            }
            chunk_remaining.* -= 1;
            if (chunk_remaining.* == 0) {
                state.* = .data_cr;
            }
        },
        .data_cr => {
            if (byte != '\r') {
                state.* = .parse_error;
                return;
            }
            state.* = .data_lf;
        },
        .data_lf => {
            if (byte != '\n') {
                state.* = .parse_error;
                return;
            }
            state.* = .size;
        },
        .trailer_start => {
            if (byte == '\r') {
                state.* = .trailer_end_cr;
            } else {
                state.* = .trailer_line;
            }
        },
        .trailer_line => {
            if (byte == '\r') state.* = .trailer_line_cr;
        },
        .trailer_line_cr => {
            state.* = .trailer_start;
        },
        .trailer_end_cr => {
            state.* = .done;
        },
        .done => {},
        .parse_error => {},
    }
}

/// Resumable chunked decoder: the `chunkedStep` state plus capture bookkeeping, so a
/// caller can decode part of a body (e.g. while deciding whether to hold it), then
/// hand the same decoder to `pumpChunkedResume` to finish. Decoded bytes land in the
/// `capture` slice passed to `feed`; pass the same slice on every call.
pub const ChunkedDecoder = struct {
    state: ChunkState = .size,
    chunk_remaining: usize = 0,
    size_val: usize = 0,
    captured: usize = 0,
    truncated: bool = false,
    /// Decoded payload bytes seen, including those that didn't fit the capture.
    decoded_total: u64 = 0,

    pub fn finished(self: *const ChunkedDecoder) bool {
        return self.state == .done or self.state == .parse_error;
    }

    /// Decode `bytes`; returns how many were consumed. Stops right after the byte
    /// that ends the message (`.done`) or breaks the framing (`.parse_error`), so
    /// bytes after the message (a pipelined request) are left to the caller.
    pub fn feed(self: *ChunkedDecoder, bytes: []const u8, capture: []u8) usize {
        if (self.finished()) return 0;
        for (bytes, 0..) |b, i| {
            if (self.state == .data) self.decoded_total += 1;
            chunkedStep(b, &self.state, &self.chunk_remaining, &self.size_val, capture, &self.captured, &self.truncated);
            if (self.finished()) return i + 1;
        }
        return bytes.len;
    }
};

pub const PumpResult = struct {
    /// Decoded payload bytes landed in `body`.
    captured: usize,
    /// Terminal decoder state: `.done` on a clean trailer, `.parse_error` on bad
    /// framing, or a mid-stream state if the transport ended early.
    state: ChunkState,
    /// At least one decoded byte was dropped because `body` was full.
    truncated: bool,
    /// Bytes read past the end of the message (slice of `initial` or `read_buf`).
    leftover: []const u8 = "",
    /// Decoded size passed `limit`; the read that crossed it was not relayed.
    over_limit: bool = false,
};

/// A sink may expose `isFailed() bool` (e.g. a dead upstream); relays stop reading
/// their source once it reports failure instead of draining it into the void.
fn sinkFailed(sink: anytype) bool {
    return if (@hasDecl(@TypeOf(sink), "isFailed")) sink.isFailed() else false;
}

fn pumpResult(dec: *const ChunkedDecoder, leftover: []const u8, over_limit: bool) PumpResult {
    return .{ .captured = dec.captured, .state = dec.state, .truncated = dec.truncated, .leftover = leftover, .over_limit = over_limit };
}

/// A sink that discards forwarded bytes — used by the capture-only path where the
/// chunked body is decoded into an Entry but not relayed to a client.
pub const NullSink = struct {
    pub fn write(_: NullSink, _: []const u8) void {}
};

/// Decode a chunked body in full from a fresh decoder. See `pumpChunkedResume`;
/// this wrapper owns its read buffer, so it never reports `leftover`.
pub fn pumpChunked(initial: []const u8, src: anytype, sink: anytype, body: []u8) PumpResult {
    var dec = ChunkedDecoder{};
    var read_buf: [16384]u8 = undefined;
    var r = pumpChunkedResume(&dec, initial, src, sink, body, &read_buf, std.math.maxInt(u64));
    r.leftover = "";
    return r;
}

/// Continue decoding a chunked body with `dec`: `initial` holds bytes already read,
/// `src` supplies the rest (`read([]u8) !usize`) into `read_buf`, and `sink`
/// receives the *raw* chunked bytes of this message verbatim (`write([]const u8)
/// void`) while `body` receives the decoded payload. Stops at the end of the
/// message (`leftover` = bytes past it), on invalid framing, when `src` ends, or
/// when the decoded size passes `limit` (`over_limit`; that read is not relayed).
pub fn pumpChunkedResume(dec: *ChunkedDecoder, initial: []const u8, src: anytype, sink: anytype, body: []u8, read_buf: []u8, limit: u64) PumpResult {
    if (dec.finished()) return pumpResult(dec, initial, false);
    if (initial.len > 0) {
        const used = dec.feed(initial, body);
        if (dec.decoded_total > limit) return pumpResult(dec, "", true);
        sink.write(initial[0..used]);
        if (dec.finished()) return pumpResult(dec, initial[used..], false);
    }
    while (!dec.finished() and !sinkFailed(sink)) {
        const n = src.read(read_buf) catch break;
        if (n == 0) break;
        const used = dec.feed(read_buf[0..n], body);
        if (dec.decoded_total > limit) return pumpResult(dec, "", true);
        sink.write(read_buf[0..used]);
        if (dec.finished()) return pumpResult(dec, read_buf[used..n], false);
    }
    return pumpResult(dec, "", false);
}

/// The parsed head of an HTTP response. All slices point into the caller's read
/// buffer, so it must outlive the ResponseHead.
pub const ResponseHead = struct {
    /// Parsed status code, or 0 if the status line was malformed.
    status: u16,
    /// The status line including its trailing CRLF (ready to relay verbatim).
    status_line: []const u8,
    /// The header block between the status line and the terminating CRLFCRLF.
    headers: []const u8,
    /// Body bytes that arrived in the same reads as the head.
    initial_body: []const u8,
};

/// Responses that never carry a body regardless of their framing headers
/// (RFC 9110 6.4.1): any response to HEAD, and 1xx, 204 and 304.
pub fn responseHasBody(method: []const u8, status: u16) bool {
    if (std.mem.eql(u8, method, "HEAD")) return false;
    return !((status >= 100 and status < 200) or status == 204 or status == 304);
}

fn parseStatus(status_line: []const u8) u16 {
    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next(); // skip HTTP version
    const status_str = parts.next() orelse return 0;
    return std.fmt.parseInt(u16, status_str, 10) catch 0;
}

/// Read from `src` (`read([]u8) !usize`) into `buf` until the end of the response
/// head (CRLFCRLF), then parse the status line and slice out the header block and
/// any leftover body bytes. Interim 1xx heads (100 Continue, 103 Early Hints) are
/// skipped; 101 is final (protocol switch). Returns null if the connection yielded
/// nothing or no complete head fit in `buf`. The returned slices point into `buf`.
pub fn readResponseHead(src: anytype, buf: []u8) ?ResponseHead {
    var total: usize = 0;
    while (true) {
        var headers_end: ?usize = std.mem.indexOf(u8, buf[0..total], "\r\n\r\n");
        while (headers_end == null and total < buf.len) {
            const n = src.read(buf[total..]) catch break;
            if (n == 0) break;
            total += n;
            headers_end = std.mem.indexOf(u8, buf[0..total], "\r\n\r\n");
        }
        if (total == 0) return null;
        const hdr_end = headers_end orelse return null;

        const first_line_end = std.mem.indexOf(u8, buf[0..total], "\r\n") orelse return null;
        const status = parseStatus(buf[0..first_line_end]);
        const body_start = hdr_end + 4;

        if (status >= 100 and status < 200 and status != 101) {
            // Drop the interim head and look for the next one in what's left.
            std.mem.copyForwards(u8, buf[0 .. total - body_start], buf[body_start..total]);
            total -= body_start;
            continue;
        }

        return .{
            .status = status,
            .status_line = buf[0 .. first_line_end + 2],
            // A headerless response (status line immediately followed by CRLFCRLF) has
            // first_line_end == hdr_end — yield an empty header block, not a bad slice.
            .headers = if (first_line_end + 2 <= hdr_end) buf[first_line_end + 2 .. hdr_end] else buf[0..0],
            .initial_body = if (body_start < total) buf[body_start..total] else buf[0..0],
        };
    }
}

pub const BodyResult = struct {
    /// Captured payload bytes landed in `body`.
    captured: usize,
    /// At least one byte was dropped because `body` filled.
    truncated: bool,
    /// Body bytes relayed in total.
    total: u64 = 0,
    /// `initial` bytes past `content_length` (a pipelined request), not relayed.
    leftover: []const u8 = "",
};

/// Copy `chunk` into `body` starting at `captured`, advancing it, and set
/// `truncated` if any byte of `chunk` did not fit.
fn captureInto(chunk: []const u8, body: []u8, captured: *usize, truncated: *bool) void {
    const space = body.len - captured.*;
    const n = @min(chunk.len, space);
    if (n > 0) {
        @memcpy(body[captured.*..][0..n], chunk[0..n]);
        captured.* += n;
    }
    if (chunk.len > space) truncated.* = true;
}

/// Relay a non-chunked body from `src` (`read([]u8) !usize`) to `sink`
/// (`write([]const u8) void`) while capturing up to `body.len` bytes. `initial` is
/// the slice already read past the headers. With a `content_length` the relay
/// stops exactly there: reads never ask for more, and surplus `initial` bytes come
/// back as `leftover`. Null means read until `src` closes. Pass `NullSink{}` to
/// capture without forwarding.
pub fn streamBody(initial: []const u8, src: anytype, sink: anytype, content_length: ?usize, body: []u8) BodyResult {
    var captured: usize = 0;
    var truncated = false;

    const first_len = if (content_length) |cl| @min(initial.len, cl) else initial.len;
    const first = initial[0..first_len];
    if (first.len > 0) {
        sink.write(first);
        captureInto(first, body, &captured, &truncated);
    }

    var read_total: usize = first.len;
    var read_buf: [16384]u8 = undefined;
    while (!sinkFailed(sink)) {
        var want: usize = read_buf.len;
        if (content_length) |cl| {
            if (read_total >= cl) break;
            want = @min(want, cl - read_total);
        }
        const n = src.read(read_buf[0..want]) catch break;
        if (n == 0) break;
        sink.write(read_buf[0..n]);
        captureInto(read_buf[0..n], body, &captured, &truncated);
        read_total += n;
    }

    return .{ .captured = captured, .truncated = truncated, .total = read_total, .leftover = initial[first_len..] };
}

/// A header-forwarding policy: which header lines to drop, and whether to rewrite
/// the Set-Cookie `Domain=` attribute to the proxy domain.
pub const ForwardPolicy = struct {
    /// Lowercase header-name prefixes (including the trailing colon) to drop.
    skip: []const []const u8 = &.{},
    /// Rewrite the Domain= attribute of Set-Cookie headers to `domain`.
    rewrite_set_cookie: bool = false,
};

fn matchesAnyPrefix(header: []const u8, prefixes: []const []const u8) bool {
    for (prefixes) |p| {
        if (std.ascii.startsWithIgnoreCase(header, p)) return true;
    }
    return false;
}

/// Forward CRLF-separated header lines to `sink` (`write([]const u8) void`),
/// dropping any whose name matches a `policy.skip` prefix and, when
/// `policy.rewrite_set_cookie`, rewriting Set-Cookie `Domain=` to `domain`. Each
/// surviving header is written followed by CRLF. The caller owns the start line,
/// any appended headers (Connection, Content-Length), and the terminating CRLF.
pub fn forwardHeaders(headers: []const u8, sink: anytype, policy: ForwardPolicy, domain: []const u8) void {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |header| {
        if (header.len == 0) continue;
        if (matchesAnyPrefix(header, policy.skip)) continue;
        if (policy.rewrite_set_cookie and std.ascii.startsWithIgnoreCase(header, "set-cookie:")) {
            writeCookieWithDomain(sink, header, domain);
            sink.write("\r\n");
            continue;
        }
        sink.write(header);
        sink.write("\r\n");
    }
}

/// Write a Set-Cookie `header` to `sink`, replacing its `Domain=` attribute value
/// with `.<domain>`. The search for `Domain=` begins after the first `;` so a
/// `domain=` substring inside the cookie value is never matched. If no `Domain=`
/// attribute is present the header is written unchanged. No trailing CRLF.
pub fn writeCookieWithDomain(sink: anytype, header: []const u8, domain: []const u8) void {
    const attr_start = if (std.mem.indexOfScalar(u8, header, ';')) |pos| pos else header.len;
    var i: usize = attr_start;
    while (i + 7 <= header.len) : (i += 1) {
        if (std.ascii.startsWithIgnoreCase(header[i..], "domain=")) {
            sink.write(header[0..i]);
            sink.write("Domain=.");
            sink.write(domain);
            // Skip past the original domain value (until ; or end of header).
            var j = i + 7;
            if (j < header.len and header[j] == '.') j += 1; // skip leading dot
            while (j < header.len and header[j] != ';') : (j += 1) {}
            sink.write(header[j..]);
            return;
        }
    }
    sink.write(header);
}

// --- Unit Tests ---

const testing = std.testing;

/// Path zlodev answers itself on :443 and :80. Namespaced so an app's own
/// `/health` route still reaches the dev server.
pub const health_path = "/.zlodev/health";

pub fn isHealthCheck(path: []const u8) bool {
    return std.mem.eql(u8, path, health_path);
}

test "getContentLength present" {
    try testing.expectEqual(@as(?usize, 42), getContentLength("Content-Length: 42\r\nHost: dev.lo\r\n"));
    try testing.expectEqual(@as(?usize, 0), getContentLength("Content-Length: 0\r\n"));
    try testing.expectEqual(@as(?usize, 12345), getContentLength("Host: dev.lo\r\nContent-Length: 12345\r\n"));
}

test "getContentLength case insensitive" {
    try testing.expectEqual(@as(?usize, 100), getContentLength("content-length: 100\r\n"));
    try testing.expectEqual(@as(?usize, 200), getContentLength("CONTENT-LENGTH: 200\r\n"));
}

test "getContentLength missing" {
    try testing.expect(getContentLength("Host: dev.lo\r\nAccept: */*\r\n") == null);
    try testing.expect(getContentLength("") == null);
}

test "getContentLength invalid value" {
    try testing.expect(getContentLength("Content-Length: abc\r\n") == null);
    try testing.expect(getContentLength("Content-Length: \r\n") == null);
}

test "isWebSocketUpgrade true" {
    try testing.expect(isWebSocketUpgrade("Upgrade: websocket\r\nConnection: Upgrade\r\n"));
    try testing.expect(isWebSocketUpgrade("Host: dev.lo\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n"));
    try testing.expect(isWebSocketUpgrade("upgrade: websocket\r\n"));
    try testing.expect(isWebSocketUpgrade("UPGRADE: WEBSOCKET\r\n"));
}

test "isWebSocketUpgrade false" {
    try testing.expect(!isWebSocketUpgrade("Host: dev.lo\r\nAccept: */*\r\n"));
    try testing.expect(!isWebSocketUpgrade("Upgrade: h2c\r\n"));
    try testing.expect(!isWebSocketUpgrade(""));
}

test "getConnectionHeader close" {
    try testing.expectEqual(ConnectionHeader.close, getConnectionHeader("Connection: close\r\nHost: dev.lo\r\n"));
    try testing.expectEqual(ConnectionHeader.close, getConnectionHeader("Host: dev.lo\r\nConnection: close\r\n"));
    try testing.expectEqual(ConnectionHeader.close, getConnectionHeader("connection: close\r\n"));
    try testing.expectEqual(ConnectionHeader.close, getConnectionHeader("CONNECTION: CLOSE\r\n"));
}

test "getConnectionHeader keep-alive" {
    try testing.expectEqual(ConnectionHeader.keep_alive, getConnectionHeader("Connection: keep-alive\r\n"));
    try testing.expectEqual(ConnectionHeader.keep_alive, getConnectionHeader("connection: Keep-Alive\r\n"));
}

test "getConnectionHeader none" {
    try testing.expectEqual(ConnectionHeader.none, getConnectionHeader("Host: dev.lo\r\nAccept: */*\r\n"));
    try testing.expectEqual(ConnectionHeader.none, getConnectionHeader(""));
}

test "getConnectionHeader upgrade ignored" {
    try testing.expectEqual(ConnectionHeader.none, getConnectionHeader("Connection: Upgrade\r\n"));
}

test "reasonPhrase common codes" {
    try testing.expectEqualStrings("OK", reasonPhrase(200));
    try testing.expectEqualStrings("Not Found", reasonPhrase(404));
    try testing.expectEqualStrings("Internal Server Error", reasonPhrase(500));
    try testing.expectEqualStrings("Bad Gateway", reasonPhrase(502));
    try testing.expectEqualStrings("Unauthorized", reasonPhrase(401));
    try testing.expectEqualStrings("Moved Permanently", reasonPhrase(301));
}

test "reasonPhrase unknown code falls back to OK" {
    try testing.expectEqualStrings("OK", reasonPhrase(999));
    try testing.expectEqualStrings("OK", reasonPhrase(0));
}

test "isChunkedEncoding true" {
    try testing.expect(isChunkedEncoding("Transfer-Encoding: chunked\r\n"));
    try testing.expect(isChunkedEncoding("transfer-encoding: chunked\r\n"));
    try testing.expect(isChunkedEncoding("Host: dev.lo\r\nTransfer-Encoding: chunked\r\n"));
}

test "isChunkedEncoding false" {
    try testing.expect(!isChunkedEncoding("Content-Length: 42\r\n"));
    try testing.expect(!isChunkedEncoding("Transfer-Encoding: gzip\r\n"));
    try testing.expect(!isChunkedEncoding(""));
}

test "getHeaderValue found" {
    try testing.expectEqualStrings("dev.lo", getHeaderValue("Host: dev.lo\r\nAccept: */*\r\n", "host:").?);
    try testing.expectEqualStrings("*/*", getHeaderValue("Host: dev.lo\r\nAccept: */*\r\n", "accept:").?);
}

test "getHeaderValue not found" {
    try testing.expect(getHeaderValue("Host: dev.lo\r\n", "content-type:") == null);
    try testing.expect(getHeaderValue("", "host:") == null);
}

test "getHeaderValue trims whitespace" {
    try testing.expectEqualStrings("dev.lo", getHeaderValue("Host:   dev.lo  \r\n", "host:").?);
}

/// Drive chunkedStep over a whole buffer; returns final state + bytes captured.
fn decodeAll(input: []const u8, body: []u8) struct { state: ChunkState, captured: usize, truncated: bool } {
    var state: ChunkState = .size;
    var chunk_remaining: usize = 0;
    var size_val: usize = 0;
    var captured: usize = 0;
    var truncated = false;
    for (input) |b| {
        chunkedStep(b, &state, &chunk_remaining, &size_val, body, &captured, &truncated);
        if (state == .done or state == .parse_error) break;
    }
    return .{ .state = state, .captured = captured, .truncated = truncated };
}

/// Reader adapter over a fixed slice — feeds bytes to pumpChunked in one or more reads.
const SliceReader = struct {
    data: []const u8,
    pos: usize = 0,
    fn read(self: *SliceReader, buf: []u8) !usize {
        const n = @min(buf.len, self.data.len - self.pos);
        @memcpy(buf[0..n], self.data[self.pos..][0..n]);
        self.pos += n;
        return n;
    }
};

/// Sink adapter that records the raw bytes forwarded, into a caller-owned buffer.
const CaptureSink = struct {
    buf: []u8,
    len: *usize,
    fn write(self: CaptureSink, bytes: []const u8) void {
        const n = @min(bytes.len, self.buf.len - self.len.*);
        @memcpy(self.buf[self.len.*..][0..n], bytes[0..n]);
        self.len.* += n;
    }
};

test "chunkedStep decodes a multi-chunk body" {
    var body: [64]u8 = undefined;
    const r = decodeAll("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", &body);
    try testing.expectEqual(ChunkState.done, r.state);
    try testing.expectEqualStrings("Wikipedia", body[0..r.captured]);
}

test "chunkedStep honors chunk extensions" {
    var body: [64]u8 = undefined;
    const r = decodeAll("4;name=value\r\nWiki\r\n0\r\n\r\n", &body);
    try testing.expectEqual(ChunkState.done, r.state);
    try testing.expectEqualStrings("Wiki", body[0..r.captured]);
}

test "chunkedStep flags invalid hex size" {
    var body: [64]u8 = undefined;
    const r = decodeAll("zz\r\n", &body);
    try testing.expectEqual(ChunkState.parse_error, r.state);
}

test "chunkedStep flags missing LF after size CR" {
    var body: [64]u8 = undefined;
    const r = decodeAll("4\rXbad", &body);
    try testing.expectEqual(ChunkState.parse_error, r.state);
}

test "chunkedStep stops capturing at body capacity but keeps parsing" {
    var body: [2]u8 = undefined; // smaller than the 4-byte chunk
    const r = decodeAll("4\r\nWiki\r\n0\r\n\r\n", &body);
    try testing.expectEqual(ChunkState.done, r.state);
    try testing.expectEqual(@as(usize, 2), r.captured);
    try testing.expect(r.truncated);
    try testing.expectEqualStrings("Wi", body[0..r.captured]);
}

test "pumpChunked forwards raw framing and captures decoded payload" {
    var reader = SliceReader{ .data = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n" };
    var fwd: [64]u8 = undefined;
    var fwd_len: usize = 0;
    var body: [64]u8 = undefined;

    const r = pumpChunked("", &reader, CaptureSink{ .buf = &fwd, .len = &fwd_len }, &body);

    try testing.expectEqual(ChunkState.done, r.state);
    try testing.expect(!r.truncated);
    try testing.expectEqualStrings("Wikipedia", body[0..r.captured]);
    // Sink received the raw chunked stream verbatim, not the decoded body.
    try testing.expectEqualStrings("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", fwd[0..fwd_len]);
}

test "pumpChunked decodes a prefix slice plus streamed remainder" {
    const whole = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    var reader = SliceReader{ .data = whole[6..] }; // stream everything after "4\r\nWik"
    var fwd: [64]u8 = undefined;
    var fwd_len: usize = 0;
    var body: [64]u8 = undefined;

    const r = pumpChunked(whole[0..6], &reader, CaptureSink{ .buf = &fwd, .len = &fwd_len }, &body);

    try testing.expectEqual(ChunkState.done, r.state);
    try testing.expectEqualStrings("Wikipedia", body[0..r.captured]);
    try testing.expectEqualStrings(whole, fwd[0..fwd_len]);
}

test "pumpChunked flags truncation when body buffer is too small" {
    var reader = SliceReader{ .data = "9\r\nWikipedia\r\n0\r\n\r\n" };
    var body: [4]u8 = undefined; // smaller than the 9-byte payload

    const r = pumpChunked("", &reader, NullSink{}, &body);

    try testing.expectEqual(ChunkState.done, r.state);
    try testing.expect(r.truncated);
    try testing.expectEqual(@as(usize, 4), r.captured);
    try testing.expectEqualStrings("Wiki", body[0..r.captured]);
}

test "pumpChunked propagates parse_error on invalid framing" {
    var reader = SliceReader{ .data = "zz\r\n" };
    var body: [64]u8 = undefined;

    const r = pumpChunked("", &reader, NullSink{}, &body);

    try testing.expectEqual(ChunkState.parse_error, r.state);
}

test "pumpChunked with NullSink decodes without forwarding" {
    var reader = SliceReader{ .data = "3\r\nabc\r\n0\r\n\r\n" };
    var body: [64]u8 = undefined;

    const r = pumpChunked("", &reader, NullSink{}, &body);

    try testing.expectEqual(ChunkState.done, r.state);
    try testing.expectEqualStrings("abc", body[0..r.captured]);
}

test "ChunkedDecoder gives the same result for every split point" {
    const whole = "4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\nTrailer: v\r\n\r\n";
    for (0..whole.len + 1) |split| {
        var dec = ChunkedDecoder{};
        var body: [64]u8 = undefined;
        const a = dec.feed(whole[0..split], &body);
        try testing.expectEqual(split, a);
        const b = dec.feed(whole[split..], &body);
        try testing.expectEqual(whole.len - split, b);
        try testing.expectEqual(ChunkState.done, dec.state);
        try testing.expectEqualStrings("Wikipedia", body[0..dec.captured]);
        try testing.expectEqual(@as(u64, 9), dec.decoded_total);
    }
}

test "ChunkedDecoder stops at the end of the message" {
    var dec = ChunkedDecoder{};
    var body: [64]u8 = undefined;
    const input = "3\r\nabc\r\n0\r\n\r\nGET /next HTTP/1.1\r\n";
    const used = dec.feed(input, &body);
    try testing.expectEqual(@as(usize, 13), used);
    try testing.expectEqualStrings("GET /next HTTP/1.1\r\n", input[used..]);
    // A finished decoder consumes nothing more.
    try testing.expectEqual(@as(usize, 0), dec.feed("more", &body));
}

test "ChunkedDecoder reports parse_error and stops consuming" {
    var dec = ChunkedDecoder{};
    var body: [64]u8 = undefined;
    const used = dec.feed("zz\r\nrest", &body);
    try testing.expectEqual(@as(usize, 1), used);
    try testing.expectEqual(ChunkState.parse_error, dec.state);
    try testing.expect(dec.finished());
}

test "ChunkedDecoder counts decoded bytes past the capture" {
    var dec = ChunkedDecoder{};
    var body: [2]u8 = undefined;
    _ = dec.feed("5\r\nhello\r\n0\r\n\r\n", &body);
    try testing.expect(dec.truncated);
    try testing.expectEqual(@as(usize, 2), dec.captured);
    try testing.expectEqual(@as(u64, 5), dec.decoded_total);
}

test "pumpChunkedResume continues a decoder and returns bytes past the end" {
    const whole = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    var dec = ChunkedDecoder{};
    var body: [64]u8 = undefined;
    _ = dec.feed(whole[0..7], &body); // as if a probe already decoded "4\r\nWiki"
    var reader = SliceReader{ .data = whole[7..] ++ "NEXT" };
    var fwd: [64]u8 = undefined;
    var fwd_len: usize = 0;
    var read_buf: [64]u8 = undefined;
    const r = pumpChunkedResume(&dec, "", &reader, CaptureSink{ .buf = &fwd, .len = &fwd_len }, &body, &read_buf, std.math.maxInt(u64));
    try testing.expectEqual(ChunkState.done, r.state);
    try testing.expectEqualStrings("Wikipedia", body[0..r.captured]);
    try testing.expectEqualStrings(whole[7..], fwd[0..fwd_len]);
    try testing.expectEqualStrings("NEXT", r.leftover);
}

test "pumpChunkedResume stops with over_limit once decoded bytes pass the limit" {
    var dec = ChunkedDecoder{};
    var body: [64]u8 = undefined;
    var reader = SliceReader{ .data = "a\r\n0123456789\r\n0\r\n\r\n" };
    var fwd: [64]u8 = undefined;
    var fwd_len: usize = 0;
    var read_buf: [64]u8 = undefined;
    const r = pumpChunkedResume(&dec, "", &reader, CaptureSink{ .buf = &fwd, .len = &fwd_len }, &body, &read_buf, 5);
    try testing.expect(r.over_limit);
    try testing.expectEqual(@as(usize, 0), fwd_len); // nothing past the limit was relayed
}

test "streamBody with content-length leaves surplus initial bytes as leftover" {
    var reader = SliceReader{ .data = "" };
    var fwd: [32]u8 = undefined;
    var fwd_len: usize = 0;
    var body: [32]u8 = undefined;
    const r = streamBody("abcGET /", &reader, CaptureSink{ .buf = &fwd, .len = &fwd_len }, 3, &body);
    try testing.expectEqualStrings("abc", fwd[0..fwd_len]);
    try testing.expectEqualStrings("GET /", r.leftover);
    try testing.expectEqual(@as(u64, 3), r.total);
}

test "streamBody never reads past content-length" {
    var reader = SliceReader{ .data = "helloEXTRA" };
    var fwd: [32]u8 = undefined;
    var fwd_len: usize = 0;
    var body: [32]u8 = undefined;
    const r = streamBody("", &reader, CaptureSink{ .buf = &fwd, .len = &fwd_len }, 5, &body);
    try testing.expectEqualStrings("hello", fwd[0..fwd_len]);
    try testing.expectEqual(@as(usize, 5), reader.pos); // EXTRA still unread
    try testing.expectEqual(@as(u64, 5), r.total);
}

test "reasonPhrase names 431" {
    try testing.expectEqualStrings("Request Header Fields Too Large", reasonPhrase(431));
}

/// Sink whose writes start failing after `ok_writes`, recording the failure.
const FailingSink = struct {
    ok_writes: usize,
    writes: *usize,
    fn write(self: FailingSink, _: []const u8) void {
        self.writes.* += 1;
    }
    pub fn isFailed(self: FailingSink) bool {
        return self.writes.* > self.ok_writes;
    }
};

/// Reader that hands out one byte per read, so a relay takes many iterations.
const OneByteReader = struct {
    data: []const u8,
    pos: usize = 0,
    fn read(self: *OneByteReader, buf: []u8) !usize {
        if (self.pos >= self.data.len or buf.len == 0) return 0;
        buf[0] = self.data[self.pos];
        self.pos += 1;
        return 1;
    }
};

test "streamBody stops reading once the sink has failed" {
    var reader = OneByteReader{ .data = "0123456789" };
    var writes: usize = 0;
    var body: [4]u8 = undefined;
    _ = streamBody("", &reader, FailingSink{ .ok_writes = 0, .writes = &writes }, 10, &body);
    try testing.expectEqual(@as(usize, 1), writes);
    try testing.expectEqual(@as(usize, 1), reader.pos);
}

test "pumpChunkedResume stops reading once the sink has failed" {
    var dec = ChunkedDecoder{};
    var reader = OneByteReader{ .data = "1\r\na\r\n1\r\nb\r\n0\r\n\r\n" };
    var writes: usize = 0;
    var body: [8]u8 = undefined;
    var read_buf: [4]u8 = undefined;
    const r = pumpChunkedResume(&dec, "", &reader, FailingSink{ .ok_writes = 0, .writes = &writes }, &body, &read_buf, std.math.maxInt(u64));
    try testing.expectEqual(@as(usize, 1), writes);
    try testing.expect(r.state != .done);
}

test "streamBody captures and forwards a content-length body" {
    var reader = SliceReader{ .data = "hello" };
    var fwd: [32]u8 = undefined;
    var fwd_len: usize = 0;
    var body: [32]u8 = undefined;

    const r = streamBody("", &reader, CaptureSink{ .buf = &fwd, .len = &fwd_len }, 5, &body);

    try testing.expect(!r.truncated);
    try testing.expectEqualStrings("hello", body[0..r.captured]);
    try testing.expectEqualStrings("hello", fwd[0..fwd_len]);
}

test "streamBody reads until close when content-length is null" {
    var reader = SliceReader{ .data = "world" };
    var body: [32]u8 = undefined;

    const r = streamBody("", &reader, NullSink{}, null, &body);

    try testing.expect(!r.truncated);
    try testing.expectEqualStrings("world", body[0..r.captured]);
}

test "streamBody captures the initial slice before the stream" {
    var reader = SliceReader{ .data = "llo" };
    var fwd: [32]u8 = undefined;
    var fwd_len: usize = 0;
    var body: [32]u8 = undefined;

    const r = streamBody("he", &reader, CaptureSink{ .buf = &fwd, .len = &fwd_len }, 5, &body);

    try testing.expectEqualStrings("hello", body[0..r.captured]);
    try testing.expectEqualStrings("hello", fwd[0..fwd_len]);
}

test "streamBody flags truncation when body buffer fills" {
    var reader = SliceReader{ .data = "hello" };
    var body: [3]u8 = undefined;

    const r = streamBody("", &reader, NullSink{}, 5, &body);

    try testing.expect(r.truncated);
    try testing.expectEqual(@as(usize, 3), r.captured);
    try testing.expectEqualStrings("hel", body[0..r.captured]);
}

test "streamBody stops reading once content-length is satisfied" {
    // Reader would yield more, but the first read already covers content-length.
    var reader = SliceReader{ .data = "abcde" };
    var body: [32]u8 = undefined;

    const r = streamBody("abc", &reader, NullSink{}, 3, &body);

    // initial already met content-length; the stream loop never reads.
    try testing.expectEqual(@as(usize, 0), reader.pos);
    try testing.expectEqualStrings("abc", body[0..r.captured]);
}

/// SliceReader variant that yields at most `chunk` bytes per read, to exercise
/// callers across multiple reads (e.g. a head split over packet boundaries).
const ChunkedReader = struct {
    data: []const u8,
    chunk: usize,
    pos: usize = 0,
    fn read(self: *ChunkedReader, buf: []u8) !usize {
        const avail = self.data.len - self.pos;
        const n = @min(@min(buf.len, self.chunk), avail);
        @memcpy(buf[0..n], self.data[self.pos..][0..n]);
        self.pos += n;
        return n;
    }
};

test "readResponseHead parses status, headers, and leftover body" {
    var reader = SliceReader{ .data = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nServer: x\r\n\r\nhello" };
    var buf: [256]u8 = undefined;

    const head = readResponseHead(&reader, &buf).?;

    try testing.expectEqual(@as(u16, 200), head.status);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n", head.status_line);
    try testing.expectEqualStrings("Content-Length: 5\r\nServer: x", head.headers);
    try testing.expectEqualStrings("hello", head.initial_body);
}

test "readResponseHead reassembles a head split across reads" {
    var reader = ChunkedReader{ .data = "HTTP/1.1 404 Not Found\r\nX: y\r\n\r\n", .chunk = 4 };
    var buf: [256]u8 = undefined;

    const head = readResponseHead(&reader, &buf).?;

    try testing.expectEqual(@as(u16, 404), head.status);
    try testing.expectEqualStrings("X: y", head.headers);
    try testing.expectEqualStrings("", head.initial_body);
}

test "readResponseHead returns null when the connection yields nothing" {
    var reader = SliceReader{ .data = "" };
    var buf: [256]u8 = undefined;
    try testing.expect(readResponseHead(&reader, &buf) == null);
}

test "readResponseHead reports status 0 for a malformed status line" {
    var reader = SliceReader{ .data = "garbage\r\n\r\n" };
    var buf: [256]u8 = undefined;
    const head = readResponseHead(&reader, &buf).?;
    try testing.expectEqual(@as(u16, 0), head.status);
}

test "readResponseHead handles a response with no headers" {
    // Status line immediately followed by the terminating CRLFCRLF — must not
    // produce an invalid header slice (regression: this panicked the proxy thread).
    var reader = SliceReader{ .data = "HTTP/1.1 204 No Content\r\n\r\n" };
    var buf: [256]u8 = undefined;
    const head = readResponseHead(&reader, &buf).?;
    try testing.expectEqual(@as(u16, 204), head.status);
    try testing.expectEqualStrings("", head.headers);
    try testing.expectEqualStrings("", head.initial_body);
}

// End-to-end: a fake upstream drives the real response read+capture path that the
// socket-backed UpstreamConn drives in production — no socket, no TLS.

test "upstream response path captures and forwards a content-length body" {
    var reader = SliceReader{ .data = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" };
    var head_buf: [256]u8 = undefined;
    const head = readResponseHead(&reader, &head_buf).?;

    const cl = getContentLength(head.headers);
    var fwd: [64]u8 = undefined;
    var fwd_len: usize = 0;
    var body: [64]u8 = undefined;
    const r = streamBody(head.initial_body, &reader, CaptureSink{ .buf = &fwd, .len = &fwd_len }, cl, &body);

    try testing.expectEqualStrings("hello", body[0..r.captured]);
    try testing.expectEqualStrings("hello", fwd[0..fwd_len]);
    try testing.expect(!r.truncated);
}

test "upstream response path captures and forwards a chunked body" {
    var reader = SliceReader{ .data = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n" };
    var head_buf: [256]u8 = undefined;
    const head = readResponseHead(&reader, &head_buf).?;

    try testing.expect(isChunkedEncoding(head.headers));
    var fwd: [64]u8 = undefined;
    var fwd_len: usize = 0;
    var body: [64]u8 = undefined;
    const r = pumpChunked(head.initial_body, &reader, CaptureSink{ .buf = &fwd, .len = &fwd_len }, &body);

    try testing.expectEqual(ChunkState.done, r.state);
    try testing.expectEqualStrings("Wiki", body[0..r.captured]);
    try testing.expectEqualStrings("4\r\nWiki\r\n0\r\n\r\n", fwd[0..fwd_len]);
}

/// Run forwardHeaders into a fixed buffer and return the forwarded bytes.
fn forwardInto(out: []u8, headers: []const u8, policy: ForwardPolicy, domain: []const u8) []const u8 {
    var len: usize = 0;
    forwardHeaders(headers, CaptureSink{ .buf = out, .len = &len }, policy, domain);
    return out[0..len];
}

test "forwardHeaders drops skipped headers, keeps the rest" {
    var out: [256]u8 = undefined;
    const got = forwardInto(&out, "Host: dev.lo\r\nCache-Control: no-cache\r\nContent-Length: 5\r\nAccept: */*\r\n", .{ .skip = &.{ "cache-control:", "content-length:" } }, "dev.lo");
    try testing.expectEqualStrings("Host: dev.lo\r\nAccept: */*\r\n", got);
}

test "forwardHeaders skip is case-insensitive" {
    var out: [256]u8 = undefined;
    const got = forwardInto(&out, "CONNECTION: keep-alive\r\nX-Trace: 1\r\n", .{ .skip = &.{"connection:"} }, "dev.lo");
    try testing.expectEqualStrings("X-Trace: 1\r\n", got);
}

test "forwardHeaders leaves Set-Cookie untouched when rewrite off" {
    var out: [256]u8 = undefined;
    const got = forwardInto(&out, "Set-Cookie: id=abc; Domain=staging.example.com; Path=/\r\n", .{ .rewrite_set_cookie = false }, "dev.lo");
    try testing.expectEqualStrings("Set-Cookie: id=abc; Domain=staging.example.com; Path=/\r\n", got);
}

test "forwardHeaders rewrites Set-Cookie Domain when policy set" {
    var out: [256]u8 = undefined;
    const got = forwardInto(&out, "Set-Cookie: id=abc; Domain=staging.example.com; Path=/\r\n", .{ .rewrite_set_cookie = true }, "dev.lo");
    try testing.expectEqualStrings("Set-Cookie: id=abc; Domain=.dev.lo; Path=/\r\n", got);
}

test "writeCookieWithDomain strips a leading dot on the original domain" {
    var out: [256]u8 = undefined;
    var len: usize = 0;
    writeCookieWithDomain(CaptureSink{ .buf = &out, .len = &len }, "Set-Cookie: id=abc; Domain=.staging.example.com; HttpOnly", "dev.lo");
    try testing.expectEqualStrings("Set-Cookie: id=abc; Domain=.dev.lo; HttpOnly", out[0..len]);
}

test "writeCookieWithDomain ignores a domain= substring in the cookie value" {
    var out: [256]u8 = undefined;
    var len: usize = 0;
    writeCookieWithDomain(CaptureSink{ .buf = &out, .len = &len }, "Set-Cookie: redirect=domain=evil; Path=/", "dev.lo");
    // No Domain= attribute after the first ';' — header passes through unchanged.
    try testing.expectEqualStrings("Set-Cookie: redirect=domain=evil; Path=/", out[0..len]);
}

test "writeCookieWithDomain passes through a cookie with no Domain attribute" {
    var out: [256]u8 = undefined;
    var len: usize = 0;
    writeCookieWithDomain(CaptureSink{ .buf = &out, .len = &len }, "Set-Cookie: id=abc; Path=/; HttpOnly", "dev.lo");
    try testing.expectEqualStrings("Set-Cookie: id=abc; Path=/; HttpOnly", out[0..len]);
}

test "isHealthCheck answers only the namespaced path, leaving /health to the app" {
    try testing.expect(isHealthCheck("/.zlodev/health"));
    try testing.expect(!isHealthCheck("/health"));
    try testing.expect(!isHealthCheck("/.zlodev/health/x"));
}

test "responseHasBody is false for HEAD, 1xx, 204 and 304" {
    try testing.expect(!responseHasBody("HEAD", 200));
    try testing.expect(!responseHasBody("GET", 100));
    try testing.expect(!responseHasBody("GET", 103));
    try testing.expect(!responseHasBody("GET", 204));
    try testing.expect(!responseHasBody("GET", 304));
    try testing.expect(responseHasBody("GET", 200));
    try testing.expect(responseHasBody("POST", 201));
    try testing.expect(responseHasBody("GET", 404));
}

test "readResponseHead skips interim 1xx heads" {
    var reader = SliceReader{ .data = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" };
    var buf: [256]u8 = undefined;
    const head = readResponseHead(&reader, &buf).?;
    try testing.expectEqual(@as(u16, 200), head.status);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n", head.status_line);
    try testing.expectEqualStrings("Content-Length: 2", head.headers);
    try testing.expectEqualStrings("ok", head.initial_body);
}

test "readResponseHead skips a 100 Continue that arrives in its own read" {
    var reader = ChunkedReader{ .data = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n", .chunk = 25 };
    var buf: [256]u8 = undefined;
    const head = readResponseHead(&reader, &buf).?;
    try testing.expectEqual(@as(u16, 204), head.status);
}

test "readResponseHead returns 101 Switching Protocols as final" {
    var reader = SliceReader{ .data = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n" };
    var buf: [256]u8 = undefined;
    const head = readResponseHead(&reader, &buf).?;
    try testing.expectEqual(@as(u16, 101), head.status);
}
