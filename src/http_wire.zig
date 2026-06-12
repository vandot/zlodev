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
            const value = std.mem.trimLeft(u8, header["transfer-encoding:".len..], " ");
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
            const value = std.mem.trimLeft(u8, header["upgrade:".len..], " ");
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

pub const PumpResult = struct {
    /// Decoded payload bytes landed in `body`.
    captured: usize,
    /// Terminal decoder state: `.done` on a clean trailer, `.parse_error` on bad
    /// framing, or a mid-stream state if the transport ended early.
    state: ChunkState,
    /// At least one decoded byte was dropped because `body` was full.
    truncated: bool,
};

/// A sink that discards forwarded bytes — used by the capture-only path where the
/// chunked body is decoded into an Entry but not relayed to a client.
pub const NullSink = struct {
    pub fn write(_: NullSink, _: []const u8) void {}
};

/// Decode a chunked transfer-encoded body in full: `initial` is the slice already
/// read past the response headers, `src` supplies the rest (`read([]u8) !usize`),
/// and `sink` receives the *raw* chunked bytes verbatim (`write([]const u8) void`)
/// so a forwarding caller relays valid framing while `body` receives only the
/// decoded payload. Pass `NullSink{}` to decode without forwarding. Stops at the
/// terminal trailer (`.done`) or on invalid framing (`.parse_error`); a short read
/// returns the mid-stream state. Owns its own read buffer.
pub fn pumpChunked(initial: []const u8, src: anytype, sink: anytype, body: []u8) PumpResult {
    var state: ChunkState = .size;
    var chunk_remaining: usize = 0;
    var size_val: usize = 0;
    var captured: usize = 0;
    var truncated = false;

    if (initial.len > 0) {
        sink.write(initial);
        for (initial) |byte| {
            chunkedStep(byte, &state, &chunk_remaining, &size_val, body, &captured, &truncated);
            if (state == .done or state == .parse_error)
                return .{ .captured = captured, .state = state, .truncated = truncated };
        }
    }

    var read_buf: [16384]u8 = undefined;
    while (state != .done and state != .parse_error) {
        const n = src.read(&read_buf) catch break;
        if (n == 0) break;
        sink.write(read_buf[0..n]);
        for (read_buf[0..n]) |byte| {
            chunkedStep(byte, &state, &chunk_remaining, &size_val, body, &captured, &truncated);
            if (state == .done or state == .parse_error)
                return .{ .captured = captured, .state = state, .truncated = truncated };
        }
    }

    return .{ .captured = captured, .state = state, .truncated = truncated };
}

// --- Unit Tests ---

const testing = std.testing;

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
