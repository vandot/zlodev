//! End-to-end check that a share URL works: resolve the tunnel host at a public
//! resolver (never the system one, so the OS can't cache an early NXDOMAIN), then
//! TLS to that address with SNI + hostname verification and `GET /.zlodev/health`.
//!
//! Every wait is sliced (100ms) and checks a caller's `keep_going`, so quitting
//! never waits on a probe; sockets are non-blocking throughout.
const std = @import("std");
const compat = @import("compat.zig");
const http_wire = @import("http_wire.zig");
const proxy = @import("proxy.zig");
const rt = @import("rt.zig");

const ssl_c = @import("ssl_c");

const IpAddress = std.Io.net.IpAddress;

pub const ProbeResult = enum {
    ok,
    /// Neither public resolver answered (UDP/53 blocked?).
    dns_unreachable,
    /// The resolver answered without an A record (not routed yet).
    no_dns,
    connect_failed,
    tls_failed,
    bad_response,
};

/// Short words for the failure reason: `isn't reachable yet after 60s (<hint>)`.
pub fn hint(result: ProbeResult) []const u8 {
    return switch (result) {
        .ok => "",
        .dns_unreachable => "couldn't reach 1.1.1.1",
        .no_dns => "no DNS record yet",
        .connect_failed => "couldn't connect",
        .tls_failed => "TLS check failed",
        .bad_response => "Cloudflare answered with an error",
    };
}

/// Public resolvers for the tunnel host (Cloudflare's own, so they see new
/// trycloudflare names first); the second is asked only if the first is silent.
pub const public_resolvers = [_]IpAddress{
    .{ .ip4 = .{ .bytes = .{ 1, 1, 1, 1 }, .port = 53 } },
    .{ .ip4 = .{ .bytes = .{ 1, 0, 0, 1 }, .port = 53 } },
};
const dns_timeout_ms: u32 = 2000;
/// Hard budget for TCP connect + TLS handshake + response.
const fetch_timeout_ms: u32 = 5000;
/// Longest single wait, so a stop is noticed quickly.
const slice_ms: u32 = 100;

pub const KeepGoing = *const fn () bool;

const dns_header_len = 12;
const dns_type_a: u16 = 1;
const dns_class_in: u16 = 1;

/// Encode a recursive (RD=1) DNS query for the A record of `host` into `buf`.
/// Null if `host` isn't a valid name (empty label, label >63, name >253) or `buf`
/// is too small. One trailing dot is allowed.
pub fn buildAQuery(id: u16, host: []const u8, buf: []u8) ?[]const u8 {
    const name = if (std.mem.endsWith(u8, host, ".")) host[0 .. host.len - 1] else host;
    if (name.len == 0 or name.len > 253) return null;
    // Header + labels (name.len + 2: a length byte per label, the root byte) + type/class.
    const total = dns_header_len + name.len + 2 + 4;
    if (buf.len < total) return null;

    std.mem.writeInt(u16, buf[0..2], id, .big);
    std.mem.writeInt(u16, buf[2..4], 0x0100, .big); // RD
    std.mem.writeInt(u16, buf[4..6], 1, .big); // QDCOUNT
    @memset(buf[6..12], 0);
    var pos: usize = dns_header_len;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return null;
        buf[pos] = @intCast(label.len);
        @memcpy(buf[pos + 1 ..][0..label.len], label);
        pos += 1 + label.len;
    }
    buf[pos] = 0;
    std.mem.writeInt(u16, buf[pos + 1 ..][0..2], dns_type_a, .big);
    std.mem.writeInt(u16, buf[pos + 3 ..][0..2], dns_class_in, .big);
    return buf[0 .. pos + 5];
}

/// Offset just past the name at `pos`. Compression pointers end the name without
/// being followed, so a pointer loop can't spin; every step advances `pos`.
fn skipName(resp: []const u8, start: usize) ?usize {
    var pos = start;
    while (pos < resp.len) {
        const b = resp[pos];
        if (b == 0) return pos + 1;
        switch (b & 0xC0) {
            0xC0 => return if (pos + 2 <= resp.len) pos + 2 else null,
            0x00 => pos += 1 + @as(usize, b),
            else => return null, // reserved label types
        }
    }
    return null;
}

/// First IPv4 address in the answer section of `resp`, a reply to query `id`.
/// CNAMEs (and any other record types) are skipped. Null on a wrong id, a query
/// (QR=0), a truncated reply (TC), a non-zero RCODE, or malformed framing.
pub fn parseAAnswer(resp: []const u8, id: u16) ?[4]u8 {
    if (resp.len < dns_header_len) return null;
    if (std.mem.readInt(u16, resp[0..2], .big) != id) return null;
    const flags = std.mem.readInt(u16, resp[2..4], .big);
    if (flags & 0x8000 == 0) return null; // QR
    if (flags & 0x0200 != 0) return null; // TC
    if (flags & 0x000F != 0) return null; // RCODE
    const qdcount = std.mem.readInt(u16, resp[4..6], .big);
    const ancount = std.mem.readInt(u16, resp[6..8], .big);

    var pos: usize = dns_header_len;
    for (0..qdcount) |_| {
        pos = skipName(resp, pos) orelse return null;
        pos += 4; // QTYPE, QCLASS
        if (pos > resp.len) return null;
    }
    for (0..ancount) |_| {
        pos = skipName(resp, pos) orelse return null;
        if (pos + 10 > resp.len) return null;
        const rtype = std.mem.readInt(u16, resp[pos..][0..2], .big);
        const rclass = std.mem.readInt(u16, resp[pos + 2 ..][0..2], .big);
        const rdlen = std.mem.readInt(u16, resp[pos + 8 ..][0..2], .big);
        pos += 10;
        if (pos + rdlen > resp.len) return null;
        if (rtype == dns_type_a and rclass == dns_class_in) {
            if (rdlen != 4) return null;
            return resp[pos..][0..4].*;
        }
        pos += rdlen;
    }
    return null;
}

pub const Lookup = union(enum) {
    addr: [4]u8,
    /// Answered, but no A record (NXDOMAIN, empty, malformed).
    no_record,
    /// No reply in time (or stopped, or a socket error).
    no_reply,
};

/// Resolve `host`'s A record at each of `servers` in turn, moving on only when
/// one doesn't answer at all.
pub fn resolveAFrom(host: []const u8, servers: []const IpAddress, timeout_ms: u32, keep_going: KeepGoing) Lookup {
    for (servers) |server| {
        if (!keep_going()) return .no_reply;
        const got = resolveAAt(host, server, timeout_ms, keep_going);
        if (got != .no_reply) return got;
    }
    return .no_reply;
}

/// Resolve `host`'s A record at `server` (UDP), waiting up to `timeout_ms`.
/// Datagrams from elsewhere or with another id are ignored; the first reply from
/// `server` with our id decides.
pub fn resolveAAt(host: []const u8, server: IpAddress, timeout_ms: u32, keep_going: KeepGoing) Lookup {
    var query_buf: [512]u8 = undefined;
    var id_bytes: [2]u8 = undefined;
    rt.io().random(&id_bytes);
    const id = std.mem.readInt(u16, &id_bytes, .big);
    const query = buildAQuery(id, host, &query_buf) orelse return .no_record;

    const sock = compat.udpBind(.{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } }) catch return .no_reply;
    defer compat.closeSocket(sock);
    compat.sendTo(sock, server, query) catch return .no_reply;

    const deadline = rt.milliTimestamp() + timeout_ms;
    var resp_buf: [1500]u8 = undefined;
    while (true) {
        if (!waitFd(sock, compat.POLL.IN, deadline, keep_going)) return .no_reply;
        const dg = compat.recvFrom(sock, &resp_buf) catch return .no_reply;
        if (!sameAddress(dg.from, server)) continue;
        if (dg.data.len < 2 or std.mem.readInt(u16, dg.data[0..2], .big) != id) continue;
        return if (parseAAnswer(dg.data, id)) |a| .{ .addr = a } else .no_record;
    }
}

/// Wait for `events` on `sock` until `deadline`, in short slices so a false
/// `keep_going()` ends the wait within `slice_ms`. True when ready.
fn waitFd(sock: compat.socket_t, events: i16, deadline: i64, keep_going: KeepGoing) bool {
    while (keep_going()) {
        const left = remainingMs(deadline) orelse return false;
        var fds = [1]compat.pollfd{.{ .fd = sock, .events = events, .revents = 0 }};
        const n = compat.poll(&fds, @intCast(@min(left, slice_ms))) catch return false;
        if (n > 0) return true;
    }
    return false;
}

fn sameAddress(a: IpAddress, b: IpAddress) bool {
    return switch (a) {
        .ip4 => |x| switch (b) {
            .ip4 => |y| x.port == y.port and std.mem.eql(u8, &x.bytes, &y.bytes),
            .ip6 => false,
        },
        .ip6 => |x| switch (b) {
            .ip4 => false,
            .ip6 => |y| x.port == y.port and std.mem.eql(u8, &x.bytes, &y.bytes),
        },
    };
}

/// Milliseconds left until `deadline`, or null once it has passed.
fn remainingMs(deadline: i64) ?u32 {
    const left = deadline - rt.milliTimestamp();
    return if (left > 0) @intCast(left) else null;
}

/// True when `bytes` hold a complete `200` response whose body is exactly `ok`
/// (by Content-Length, chunked, or read-to-close).
pub fn parseHealthResponse(bytes: []const u8) bool {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return false;
    const head = bytes[0 .. head_end + 2];
    const body = bytes[head_end + 4 ..];
    const line_end = std.mem.indexOf(u8, head, "\r\n").?;
    const status_line = head[0..line_end];
    if (!std.mem.startsWith(u8, status_line, "HTTP/1.") or status_line.len < 12) return false;
    if (status_line[8] != ' ' or !std.mem.eql(u8, status_line[9..12], "200")) return false;
    if (status_line.len > 12 and status_line[12] != ' ') return false;

    const headers = head[line_end + 2 ..];
    if (http_wire.isChunkedEncoding(headers)) {
        var dec: http_wire.ChunkedDecoder = .{};
        var capture: [16]u8 = undefined;
        _ = dec.feed(body, &capture);
        return dec.state == .done and !dec.truncated and std.mem.eql(u8, capture[0..dec.captured], "ok");
    }
    if (http_wire.getContentLength(headers)) |len| {
        return len == 2 and body.len >= 2 and std.mem.eql(u8, body[0..2], "ok");
    }
    return std.mem.eql(u8, body, "ok");
}

/// Probes `https://<host>/.zlodev/health` end to end. Holds the client TLS
/// context (system roots loaded once) for the whole probe loop.
pub const Client = struct {
    /// Null when no context or no trusted roots: every probe is `tls_failed`.
    ctx: ?*ssl_c.SSL_CTX,
    /// Why the last TLS check failed (static text), for the log.
    tls_error: []const u8 = "",

    pub fn init() Client {
        _ = ssl_c.OPENSSL_init_ssl(0, null);
        const ctx = ssl_c.SSL_CTX_new(ssl_c.TLS_client_method()) orelse return .{ .ctx = null, .tls_error = "no TLS context" };
        ssl_c.SSL_CTX_set_verify(ctx, ssl_c.SSL_VERIFY_PEER, null);
        if (!proxy.loadSystemRoots(ctx)) {
            ssl_c.SSL_CTX_free(ctx);
            return .{ .ctx = null, .tls_error = "no trusted roots" };
        }
        return .{ .ctx = ctx };
    }

    pub fn deinit(self: *Client) void {
        if (self.ctx) |c| ssl_c.SSL_CTX_free(c);
        self.ctx = null;
    }

    /// One check: resolve at 1.1.1.1 (then 1.0.0.1 if silent), connect to the A
    /// address, TLS with SNI + hostname verification, expect `200` + `ok`. Bounded
    /// by the DNS timeouts plus a hard 5s for connect/TLS/response, and ends
    /// within ~100ms once `keep_going()` is false.
    pub fn probe(self: *Client, host: []const u8, keep_going: KeepGoing) ProbeResult {
        const addr = switch (resolveAFrom(host, &public_resolvers, dns_timeout_ms, keep_going)) {
            .addr => |a| a,
            .no_record => return .no_dns,
            .no_reply => return .dns_unreachable,
        };
        return self.fetchHealthAt(host, .{ .ip4 = .{ .bytes = addr, .port = 443 } }, keep_going);
    }

    fn fetchHealthAt(self: *Client, host: []const u8, addr: IpAddress, keep_going: KeepGoing) ProbeResult {
        const deadline = rt.milliTimestamp() + fetch_timeout_ms;
        const sock = compat.tcpConnectNonBlocking(addr, fetch_timeout_ms, keep_going) catch return .connect_failed;
        defer compat.closeSocket(sock);

        const ctx = self.ctx orelse return .tls_failed;
        const ssl = self.handshake(ctx, sock, host, deadline, keep_going) orelse return .tls_failed;
        defer ssl_c.SSL_free(ssl);
        defer ssl_c.ERR_clear_error();

        var req_buf: [512]u8 = undefined;
        const req = std.fmt.bufPrint(&req_buf, "GET " ++ http_wire.health_path ++ " HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{host}) catch return .bad_response;
        var sent: usize = 0;
        while (sent < req.len) {
            const r = ssl_c.SSL_write(ssl, req[sent..].ptr, @intCast(req.len - sent));
            if (r > 0) {
                sent += @intCast(r);
                continue;
            }
            const events = wantEvents(ssl, r) orelse return .bad_response;
            if (!waitFd(sock, events, deadline, keep_going)) return .bad_response;
        }

        // Read until close, 4KB, the deadline, or a complete `ok` response.
        var buf: [4096]u8 = undefined;
        var n: usize = 0;
        while (n < buf.len and !parseHealthResponse(buf[0..n])) {
            const r = ssl_c.SSL_read(ssl, buf[n..].ptr, @intCast(buf.len - n));
            if (r > 0) {
                n += @intCast(r);
                continue;
            }
            const events = wantEvents(ssl, r) orelse break; // closed or error
            if (!waitFd(sock, events, deadline, keep_going)) break;
        }
        return if (parseHealthResponse(buf[0..n])) .ok else .bad_response;
    }

    /// Non-blocking client handshake with SNI + hostname verification. Logs
    /// nothing (the probe loop logs outcomes, deduplicated); the verify error, if
    /// any, lands in `tls_error`.
    fn handshake(self: *Client, ctx: *ssl_c.SSL_CTX, sock: compat.socket_t, host: []const u8, deadline: i64, keep_going: KeepGoing) ?*ssl_c.SSL {
        self.tls_error = "";
        var host_buf: [256]u8 = undefined;
        const host_z = std.fmt.bufPrintSentinel(&host_buf, "{s}", .{host}, 0) catch return null;
        const ssl = ssl_c.SSL_new(ctx) orelse return null;
        _ = ssl_c.SSL_set_fd(ssl, compat.socketToFd(sock));
        _ = ssl_c.SSL_set_tlsext_host_name(ssl, host_z.ptr);
        if (ssl_c.SSL_set1_host(ssl, host_z.ptr) != 1) {
            ssl_c.SSL_free(ssl);
            return null;
        }
        while (true) {
            const r = ssl_c.SSL_connect(ssl);
            if (r == 1) return ssl;
            const events = wantEvents(ssl, r) orelse {
                const verify = ssl_c.SSL_get_verify_result(ssl);
                self.tls_error = if (verify != ssl_c.X509_V_OK) std.mem.span(ssl_c.X509_verify_cert_error_string(verify)) else "handshake failed";
                break;
            };
            if (!waitFd(sock, events, deadline, keep_going)) {
                self.tls_error = "handshake timed out";
                break;
            }
        }
        ssl_c.ERR_clear_error();
        ssl_c.SSL_free(ssl);
        return null;
    }
};

/// Poll events a non-blocking SSL call that returned `r` waits for, or null when
/// it failed for good (or the peer closed).
fn wantEvents(ssl: *ssl_c.SSL, r: c_int) ?i16 {
    return switch (ssl_c.SSL_get_error(ssl, r)) {
        ssl_c.SSL_ERROR_WANT_READ => compat.POLL.IN,
        ssl_c.SSL_ERROR_WANT_WRITE => compat.POLL.OUT,
        else => null,
    };
}

// --- Unit Tests ---
// Names start with "share_probe: " so `test-c` can run just these from this root
// (proxy.zig's own tests run from proxy.zig).

const testing = std.testing;

/// `s` repeated `n` times at comptime (Zig 0.17 has no `**`).
fn rep(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
    const T = struct {
        const value: [s.len * n]u8 = blk: {
            @setEvalBranchQuota(10 * s.len * n + 1000);
            var out: [s.len * n]u8 = undefined;
            for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
            break :blk out;
        };
    };
    return &T.value;
}

/// DNS response header + question for `host` (id, flags, counts given).
fn testResponse(buf: []u8, id: u16, flags: u16, ancount: u16, host: []const u8) []u8 {
    const q = buildAQuery(id, host, buf).?;
    std.mem.writeInt(u16, buf[2..4], flags, .big);
    std.mem.writeInt(u16, buf[6..8], ancount, .big);
    return buf[0..q.len];
}

fn appendBytes(buf: []u8, len: *usize, bytes: []const u8) void {
    @memcpy(buf[len.*..][0..bytes.len], bytes);
    len.* += bytes.len;
}

/// Answer record with a pointer to the question name (offset 12).
fn appendRecord(buf: []u8, len: *usize, rtype: u16, rdata: []const u8) void {
    appendBytes(buf, len, &.{ 0xC0, 0x0C });
    var fixed: [10]u8 = undefined;
    std.mem.writeInt(u16, fixed[0..2], rtype, .big);
    std.mem.writeInt(u16, fixed[2..4], 1, .big);
    std.mem.writeInt(u32, fixed[4..8], 300, .big);
    std.mem.writeInt(u16, fixed[8..10], @intCast(rdata.len), .big);
    appendBytes(buf, len, &fixed);
    appendBytes(buf, len, rdata);
}

test "share_probe: buildAQuery encodes labels" {
    var buf: [512]u8 = undefined;
    const q = buildAQuery(0xBEEF, "ab.example.com", &buf).?;
    const expected = [_]u8{
        0xBE, 0xEF, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        2,    'a',  'b',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,
        'c',  'o',  'm',  0,    0x00, 0x01, 0x00, 0x01,
    };
    try testing.expectEqualSlices(u8, &expected, q);
    // A trailing dot is the same name.
    try testing.expectEqualSlices(u8, &expected, buildAQuery(0xBEEF, "ab.example.com.", &buf).?);

    try testing.expect(buildAQuery(1, rep("a", 63) ++ ".com", &buf) != null);
    try testing.expect(buildAQuery(1, rep("a", 64) ++ ".com", &buf) == null);
    const long = rep(rep("a", 49) ++ ".", 5) ++ "abc"; // 253 chars
    try testing.expectEqual(@as(usize, 253), long.len);
    try testing.expect(buildAQuery(1, long, &buf) != null);
    try testing.expect(buildAQuery(1, long ++ "d", &buf) == null);
    try testing.expect(buildAQuery(1, "", &buf) == null);
    try testing.expect(buildAQuery(1, "a..b", &buf) == null);
    var small: [20]u8 = undefined;
    try testing.expect(buildAQuery(1, "ab.example.com", &small) == null);
}

test "share_probe: parseAAnswer returns first A" {
    var buf: [512]u8 = undefined;
    var len = testResponse(&buf, 0x1234, 0x8180, 2, "x.trycloudflare.com").len;
    appendRecord(&buf, &len, 1, &.{ 104, 16, 230, 132 });
    appendRecord(&buf, &len, 1, &.{ 104, 16, 231, 132 });
    try testing.expectEqual([4]u8{ 104, 16, 230, 132 }, parseAAnswer(buf[0..len], 0x1234).?);
}

test "share_probe: parseAAnswer skips CNAME" {
    var buf: [512]u8 = undefined;
    var len = testResponse(&buf, 7, 0x8180, 2, "x.trycloudflare.com").len;
    appendRecord(&buf, &len, 5, &.{ 3, 'f', 'o', 'o', 0xC0, 0x0C });
    appendRecord(&buf, &len, 1, &.{ 1, 2, 3, 4 });
    try testing.expectEqual([4]u8{ 1, 2, 3, 4 }, parseAAnswer(buf[0..len], 7).?);
}

test "share_probe: parseAAnswer rejects bad responses" {
    var buf: [512]u8 = undefined;
    var len = testResponse(&buf, 7, 0x8180, 1, "x.example.com").len;
    appendRecord(&buf, &len, 1, &.{ 1, 2, 3, 4 });
    const good = buf[0..len];
    try testing.expect(parseAAnswer(good, 7) != null);

    try testing.expect(parseAAnswer(good, 8) == null); // wrong id

    var copy: [512]u8 = undefined;
    @memcpy(copy[0..len], good);
    std.mem.writeInt(u16, copy[2..4], 0x0180, .big); // QR=0
    try testing.expect(parseAAnswer(copy[0..len], 7) == null);
    std.mem.writeInt(u16, copy[2..4], 0x8183, .big); // NXDOMAIN
    try testing.expect(parseAAnswer(copy[0..len], 7) == null);

    // Truncated anywhere: never an answer, never out of bounds.
    for (0..len) |cut| try testing.expect(parseAAnswer(good[0..cut], 7) == null);

    // No answers.
    const empty = testResponse(&buf, 9, 0x8180, 0, "x.example.com");
    try testing.expect(parseAAnswer(empty, 9) == null);

    // A record with the wrong rdata length.
    len = testResponse(&buf, 7, 0x8180, 1, "x.example.com").len;
    appendRecord(&buf, &len, 1, &.{ 1, 2, 3 });
    try testing.expect(parseAAnswer(buf[0..len], 7) == null);

    // Compression pointer loops (self and mutual) and reserved label types end the
    // parse instead of spinning.
    for ([_][]const u8{ &.{ 0xC0, 0x0C }, &.{ 0xC0, 0x0E, 0xC0, 0x0C }, &.{ 0x40, 0x00 }, &.{ 0x80, 0x00 } }) |name| {
        var p: [64]u8 = undefined;
        var plen: usize = 0;
        appendBytes(&p, &plen, &.{ 0x00, 0x07, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
        appendBytes(&p, &plen, name);
        appendBytes(&p, &plen, &.{ 0x00, 0x01, 0x00, 0x01 });
        _ = parseAAnswer(p[0..plen], 7); // must return
    }
    // An answer count far beyond the packet is bounded by the packet length.
    len = testResponse(&buf, 7, 0x8180, 0xFFFF, "x.example.com").len;
    appendRecord(&buf, &len, 5, &.{ 0xC0, 0x0C });
    try testing.expect(parseAAnswer(buf[0..len], 7) == null);
}

test "share_probe: parseHealthResponse" {
    try testing.expect(parseHealthResponse("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"));
    try testing.expect(parseHealthResponse("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok"));
    try testing.expect(parseHealthResponse("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"));
    try testing.expect(parseHealthResponse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"));

    try testing.expect(!parseHealthResponse("HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nok"));
    try testing.expect(!parseHealthResponse("HTTP/1.1 530 <none>\r\nContent-Type: text/html\r\nServer: cloudflare\r\n\r\n<!DOCTYPE html><html><title>Cloudflare Tunnel error</title></html>"));
    try testing.expect(!parseHealthResponse("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"));
    try testing.expect(!parseHealthResponse("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\no"));
    try testing.expect(!parseHealthResponse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"));
    try testing.expect(!parseHealthResponse("HTTP/1.1 200 OK\r\n\r\nnot ok"));
    try testing.expect(!parseHealthResponse("HTTP/1.1 2000 OK\r\n\r\nok"));
    try testing.expect(!parseHealthResponse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n"));
    try testing.expect(!parseHealthResponse(""));
}

/// UDP DNS stub on 127.0.0.1: answers one query with `answer`, after first sending
/// a reply with the wrong id (which the client must ignore).
const DnsStub = struct {
    sock: compat.socket_t,
    port: u16,
    answer: [4]u8,

    fn bind() !DnsStub {
        var port: u16 = 20000 + @as(u16, @intCast(@mod(rt.milliTimestamp(), 20000)));
        var tries: usize = 0;
        while (tries < 200) : (tries += 1) {
            const s = compat.udpBind(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } }) catch {
                port = if (port >= 60000) 20000 else port + 1;
                continue;
            };
            return .{ .sock = s, .port = port, .answer = .{ 203, 0, 113, 7 } };
        }
        return error.NoPort;
    }

    fn serve(self: *const DnsStub) void {
        // Bounded wait, so a client that never sends can't hang the test's join.
        var fds = [1]compat.pollfd{.{ .fd = self.sock, .events = compat.POLL.IN, .revents = 0 }};
        if ((compat.poll(&fds, 3000) catch 0) == 0) return;
        var buf: [512]u8 = undefined;
        const dg = compat.recvFrom(self.sock, &buf) catch return;
        var resp: [512]u8 = undefined;
        var len = dg.data.len;
        @memcpy(resp[0..len], dg.data);
        std.mem.writeInt(u16, resp[2..4], 0x8180, .big);
        std.mem.writeInt(u16, resp[6..8], 1, .big);
        appendRecord(&resp, &len, 1, &self.answer);
        const id = std.mem.readInt(u16, resp[0..2], .big);
        std.mem.writeInt(u16, resp[0..2], id +% 1, .big);
        compat.sendTo(self.sock, dg.from, resp[0..len]) catch return;
        std.mem.writeInt(u16, resp[0..2], id, .big);
        compat.sendTo(self.sock, dg.from, resp[0..len]) catch return;
    }
};

test "share_probe: resolveA against a local UDP stub" {
    const stub = try DnsStub.bind();
    defer compat.closeSocket(stub.sock);
    const t = try std.Thread.spawn(.{}, DnsStub.serve, .{&stub});
    const server: IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = stub.port } };
    const got = resolveAAt("words-here.trycloudflare.com", server, 2000, testAlways);
    t.join();
    try testing.expectEqual(Lookup{ .addr = .{ 203, 0, 113, 7 } }, got);
}

test "share_probe: resolveA times out on a silent server" {
    const stub = try DnsStub.bind();
    defer compat.closeSocket(stub.sock);
    const server: IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = stub.port } };
    const start = rt.milliTimestamp();
    try testing.expectEqual(Lookup.no_reply, resolveAAt("x.trycloudflare.com", server, 300, testAlways));
    try testing.expect(rt.milliTimestamp() - start < 2000);
}

fn testAlways() bool {
    return true;
}

const TestStop = struct {
    var deadline: i64 = 0;
    fn running() bool {
        return rt.milliTimestamp() < deadline;
    }
};

test "share_probe: resolve falls back to the second resolver" {
    const silent = try DnsStub.bind();
    defer compat.closeSocket(silent.sock);
    const stub = try DnsStub.bind();
    defer compat.closeSocket(stub.sock);
    const t = try std.Thread.spawn(.{}, DnsStub.serve, .{&stub});
    const servers = [_]IpAddress{
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = silent.port } },
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = stub.port } },
    };
    const got = resolveAFrom("x.trycloudflare.com", &servers, 300, testAlways);
    t.join();
    try testing.expectEqual(Lookup{ .addr = .{ 203, 0, 113, 7 } }, got);
}

test "share_probe: resolve stops soon after keep_going turns false" {
    const stub = try DnsStub.bind();
    defer compat.closeSocket(stub.sock);
    const servers = [_]IpAddress{
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = stub.port } },
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = stub.port } },
    };
    const start = rt.milliTimestamp();
    TestStop.deadline = start + 100;
    try testing.expectEqual(Lookup.no_reply, resolveAFrom("x.trycloudflare.com", &servers, 5000, TestStop.running));
    try testing.expect(rt.milliTimestamp() - start < 500);
}

test "share_probe: hints name the failing step" {
    try testing.expectEqualStrings("couldn't reach 1.1.1.1", hint(.dns_unreachable));
    try testing.expectEqualStrings("no DNS record yet", hint(.no_dns));
    try testing.expectEqualStrings("couldn't connect", hint(.connect_failed));
    try testing.expectEqualStrings("TLS check failed", hint(.tls_failed));
    try testing.expectEqualStrings("Cloudflare answered with an error", hint(.bad_response));
}

/// TCP listener on 127.0.0.1 that accepts and then stays silent.
fn silentListener() !struct { sock: compat.socket_t, port: u16 } {
    var port: u16 = 20000 + @as(u16, @intCast(@mod(rt.milliTimestamp() + 7, 20000)));
    var tries: usize = 0;
    while (tries < 200) : (tries += 1) {
        const s = compat.tcpListen(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } }) catch {
            port = if (port >= 60000) 20000 else port + 1;
            continue;
        };
        return .{ .sock = s, .port = port };
    }
    return error.NoPort;
}

test "share_probe: a silent TLS peer is abandoned soon after stop" {
    var client = Client.init();
    defer client.deinit();
    const l = try silentListener();
    defer compat.closeSocket(l.sock);
    const start = rt.milliTimestamp();
    TestStop.deadline = start + 150;
    const r = client.fetchHealthAt("x.trycloudflare.com", .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = l.port } }, TestStop.running);
    try testing.expectEqual(ProbeResult.tls_failed, r);
    try testing.expect(rt.milliTimestamp() - start < 600);
}

test "share_probe: a silent TLS peer fails at the fetch deadline" {
    var client = Client.init();
    defer client.deinit();
    const l = try silentListener();
    defer compat.closeSocket(l.sock);
    const start = rt.milliTimestamp();
    const r = client.fetchHealthAt("x.trycloudflare.com", .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = l.port } }, testAlways);
    try testing.expectEqual(ProbeResult.tls_failed, r);
    const took = rt.milliTimestamp() - start;
    try testing.expect(took >= fetch_timeout_ms - 100 and took < fetch_timeout_ms + 1000);
}

test "share_probe: nothing listening is connect_failed" {
    var client = Client.init();
    defer client.deinit();
    const l = try silentListener();
    const port = l.port;
    compat.closeSocket(l.sock);
    const r = client.fetchHealthAt("x.trycloudflare.com", .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } }, testAlways);
    try testing.expectEqual(ProbeResult.connect_failed, r);
}
