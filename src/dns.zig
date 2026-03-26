const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const log = @import("log.zig");
const sys = @import("sys.zig");
const compat = @import("compat.zig");
const shutdown = @import("shutdown.zig");

// DNS constants
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const TYPE_NULL: u16 = 10;

const DnsHeader = struct {
    id: u16,
    flags: u16,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
};

const DnsQuestion = struct {
    name_start: usize,
    name_end: usize,
    qtype: u16,
    qclass: u16,
};

fn readU16(data: []const u8, offset: usize) u16 {
    return (@as(u16, data[offset]) << 8) | @as(u16, data[offset + 1]);
}

fn writeU16(buf: []u8, offset: usize, value: u16) void {
    buf[offset] = @intCast(value >> 8);
    buf[offset + 1] = @intCast(value & 0xFF);
}

fn writeU32(buf: []u8, offset: usize, value: u32) void {
    buf[offset] = @intCast((value >> 24) & 0xFF);
    buf[offset + 1] = @intCast((value >> 16) & 0xFF);
    buf[offset + 2] = @intCast((value >> 8) & 0xFF);
    buf[offset + 3] = @intCast(value & 0xFF);
}

fn parseHeader(data: []const u8) DnsHeader {
    return .{
        .id = readU16(data, 0),
        .flags = readU16(data, 2),
        .qd_count = readU16(data, 4),
        .an_count = readU16(data, 6),
        .ns_count = readU16(data, 8),
        .ar_count = readU16(data, 10),
    };
}

fn parseQuestion(data: []const u8) ?DnsQuestion {
    const name_start: usize = 12;
    var pos: usize = 12;
    // Skip QNAME labels
    while (pos < data.len and data[pos] != 0) {
        const label_len = @as(usize, data[pos]);
        pos += 1 + label_len;
        if (pos >= data.len) return null;
    }
    if (pos >= data.len) return null;
    pos += 1; // skip zero terminator
    if (pos + 4 > data.len) return null;
    return .{
        .name_start = name_start,
        .name_end = pos,
        .qtype = readU16(data, pos),
        .qclass = readU16(data, pos + 2),
    };
}

fn decodeName(data: []const u8, name_start: usize, name_end: usize, buf: []u8) []const u8 {
    var pos = name_start;
    var out: usize = 0;
    while (pos < name_end and data[pos] != 0) {
        const label_len = @as(usize, data[pos]);
        pos += 1;
        if (out > 0) {
            buf[out] = '.';
            out += 1;
        }
        if (pos + label_len > data.len or out + label_len > buf.len) break;
        @memcpy(buf[out..][0..label_len], data[pos..][0..label_len]);
        out += label_len;
        pos += label_len;
    }
    return buf[0..out];
}

fn buildResponse(
    request: []const u8,
    question: DnsQuestion,
    header: DnsHeader,
    tld: []const u8,
    buf: []u8,
) usize {
    var name_buf: [256]u8 = undefined;
    const name = decodeName(request, question.name_start, question.name_end, &name_buf);

    // Check if domain ends with our TLD
    // decodeName produces "dev.lo" (no trailing dot), so check for ".lo" or exact "lo"
    var is_valid_domain = false;
    if (name.len > tld.len and name[name.len - tld.len - 1] == '.') {
        is_valid_domain = std.mem.eql(u8, name[name.len - tld.len ..], tld);
    } else if (name.len == tld.len) {
        is_valid_domain = std.mem.eql(u8, name, tld);
    }

    // Copy question section (shared by all response types)
    const question_len = question.name_end - question.name_start + 4; // +4 for QTYPE and QCLASS

    if (!is_valid_domain) {
        // NXDOMAIN response
        log.info("component=dns type={d} domain={s} rcode=NXDOMAIN", .{ question.qtype, name });
        var pos: usize = 0;
        writeU16(buf, pos, header.id);
        pos += 2;
        writeU16(buf, pos, 0x8003); // QR=1, RCODE=3 (NXDOMAIN)
        pos += 2;
        writeU16(buf, pos, 1); // QDCOUNT
        pos += 2;
        writeU16(buf, pos, 0); // ANCOUNT
        pos += 2;
        writeU16(buf, pos, 0); // NSCOUNT
        pos += 2;
        writeU16(buf, pos, 0); // ARCOUNT
        pos += 2;
        @memcpy(buf[pos..][0..question_len], request[question.name_start..][0..question_len]);
        pos += question_len;
        return pos;
    }

    // Determine response record type and data
    var rdata: [16]u8 = undefined;
    var rdlength: u16 = 0;
    var rtype: u16 = undefined;
    const ttl: u32 = 299;

    switch (question.qtype) {
        QTYPE_A => {
            log.info("component=dns type=A domain={s}", .{name});
            rtype = QTYPE_A;
            rdata[0] = 127;
            rdata[1] = 0;
            rdata[2] = 0;
            rdata[3] = 1;
            rdlength = 4;
        },
        QTYPE_AAAA => {
            // Return empty response — proxy only listens on IPv4, so we must
            // not advertise an IPv6 address or browsers will try ::1 first.
            log.info("component=dns type=AAAA domain={s} rcode=NOERROR ancount=0", .{name});
            var pos: usize = 0;
            writeU16(buf, pos, header.id);
            pos += 2;
            writeU16(buf, pos, 0x8000); // QR=1, RCODE=0
            pos += 2;
            writeU16(buf, pos, 1); // QDCOUNT
            pos += 2;
            writeU16(buf, pos, 0); // ANCOUNT
            pos += 2;
            writeU16(buf, pos, 0); // NSCOUNT
            pos += 2;
            writeU16(buf, pos, 0); // ARCOUNT
            pos += 2;
            @memcpy(buf[pos..][0..question_len], request[question.name_start..][0..question_len]);
            pos += question_len;
            return pos;
        },
        else => {
            // Return empty response (no answer) for unsupported types
            log.info("component=dns type={d} domain={s} rcode=NOERROR ancount=0", .{ question.qtype, name });
            var pos: usize = 0;
            writeU16(buf, pos, header.id);
            pos += 2;
            writeU16(buf, pos, 0x8000); // QR=1, RCODE=0
            pos += 2;
            writeU16(buf, pos, 1); // QDCOUNT
            pos += 2;
            writeU16(buf, pos, 0); // ANCOUNT
            pos += 2;
            writeU16(buf, pos, 0); // NSCOUNT
            pos += 2;
            writeU16(buf, pos, 0); // ARCOUNT
            pos += 2;
            @memcpy(buf[pos..][0..question_len], request[question.name_start..][0..question_len]);
            pos += question_len;
            return pos;
        },
    }

    // Build successful response with answer
    var pos: usize = 0;

    // Header
    writeU16(buf, pos, header.id);
    pos += 2;
    writeU16(buf, pos, 0x8000); // QR=1, RCODE=0
    pos += 2;
    writeU16(buf, pos, 1); // QDCOUNT
    pos += 2;
    writeU16(buf, pos, 1); // ANCOUNT
    pos += 2;
    writeU16(buf, pos, 0); // NSCOUNT
    pos += 2;
    writeU16(buf, pos, 0); // ARCOUNT
    pos += 2;

    // Question section
    @memcpy(buf[pos..][0..question_len], request[question.name_start..][0..question_len]);
    pos += question_len;

    // Answer: pointer to question name (0xC00C = offset 12)
    buf[pos] = 0xC0;
    buf[pos + 1] = 0x0C;
    pos += 2;

    // TYPE
    writeU16(buf, pos, rtype);
    pos += 2;

    // CLASS
    writeU16(buf, pos, CLASS_IN);
    pos += 2;

    // TTL
    writeU32(buf, pos, ttl);
    pos += 4;

    // RDLENGTH
    writeU16(buf, pos, rdlength);
    pos += 2;

    // RDATA
    @memcpy(buf[pos..][0..rdlength], rdata[0..rdlength]);
    pos += rdlength;

    return pos;
}

pub fn serve(ip: []const u8, port: u16, tld: []const u8) void {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch |e| {
        log.err("component=dns op=socket error={any}", .{e});
        return;
    };
    defer compat.closeSocket(sock);

    const addr = parseAddr(ip, port) catch |e| {
        log.err("component=dns op=addr_parse error={any}", .{e});
        return;
    };
    posix.bind(sock, &addr.any, addr.getOsSockLen()) catch |e| {
        log.err("component=dns op=bind ip={s} port={d} error={any}", .{ ip, port, e });
        if (e == error.AddressInUse) {
            std.debug.print("dns port {d} is already in use\n", .{port});
        }
        return;
    };

    log.info("component=dns op=listening ip={s} port={d}", .{ ip, port });

    var recv_buf: [512]u8 = undefined;
    var resp_buf: [512]u8 = undefined;

    while (shutdown.isRunning()) {
        // Poll with 1-second timeout before recvfrom
        var fds = [1]posix.pollfd{
            .{ .fd = sock, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = posix.poll(&fds, 1000) catch |e| {
            log.err("component=dns op=poll error={any}", .{e});
            continue;
        };
        if (ready == 0) continue; // timeout, re-check shutdown

        var src_addr: posix.sockaddr.in = undefined;
        var src_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        const n = posix.recvfrom(sock, &recv_buf, 0, @ptrCast(&src_addr), &src_addr_len) catch |e| {
            log.err("component=dns op=recvfrom error={any}", .{e});
            continue;
        };

        if (n < 12) continue; // Too small for DNS header

        const data = recv_buf[0..n];
        const header = parseHeader(data);
        if (header.qd_count == 0) continue;

        const question = parseQuestion(data) orelse continue;
        const resp_len = buildResponse(data, question, header, tld, &resp_buf);
        if (resp_len == 0) continue;

        _ = posix.sendto(sock, resp_buf[0..resp_len], 0, @ptrCast(&src_addr), src_addr_len) catch |e| {
            log.err("component=dns op=sendto error={any}", .{e});
            continue;
        };
    }
}

fn parseAddr(ip: []const u8, port: u16) !std.net.Address {
    return try std.net.Address.parseIp4(ip, port);
}

pub fn systemProbe() struct { ip: []const u8, port: u16 } {
    switch (builtin.os.tag) {
        .linux => {
            // RFC7600 dummy address
            return .{ .ip = "192.0.0.8", .port = 5354 };
        },
        .windows => {
            return .{ .ip = "127.0.0.1", .port = 53 };
        },
        else => {
            // macOS
            return .{ .ip = "127.0.0.1", .port = 5354 };
        },
    }
}

pub fn install(allocator: std.mem.Allocator, ip: []const u8, port: u16, tld: []const u8) !void {
    switch (builtin.os.tag) {
        .macos => {
            // Create /etc/resolver directory if needed (requires sudo)
            try sys.sudoCmd(allocator, &.{ "sudo", "mkdir", "-p", "/etc/resolver" });
            const text = try std.fmt.allocPrint(allocator, "nameserver {s}\nport {d}\n", .{ ip, port });
            defer allocator.free(text);
            const tmp_path = try sys.writeTmpFile(allocator, "dns_resolver", text);
            defer allocator.free(tmp_path);
            const dest = try std.fmt.allocPrint(allocator, "/etc/resolver/{s}", .{tld});
            defer allocator.free(dest);
            try sys.sudoCmd(allocator, &.{ "sudo", "mv", tmp_path, dest });
        },
        .linux => {
            const network_text = if (port == 53)
                try std.fmt.allocPrint(allocator, "[Match]\nName=zlodev0\n[Network]\nAddress={s}/32\nDomains=~{s}\nDNS={s}\n", .{ ip, tld, ip })
            else
                try std.fmt.allocPrint(allocator, "[Match]\nName=zlodev0\n[Network]\nAddress={s}/32\nDomains=~{s}\nDNS={s}:{d}\n", .{ ip, tld, ip, port });
            defer allocator.free(network_text);
            const tmp_network = try sys.writeTmpFile(allocator, "dns_network", network_text);
            defer allocator.free(tmp_network);
            try sys.sudoCmd(allocator, &.{ "sudo", "install", "-m", "644", tmp_network, "/etc/systemd/network/zlodev0.network" });

            const netdev_text = "[NetDev]\nName=zlodev0\nKind=dummy\n";
            const tmp_netdev = try sys.writeTmpFile(allocator, "dns_netdev", netdev_text);
            defer allocator.free(tmp_netdev);
            try sys.sudoCmd(allocator, &.{ "sudo", "install", "-m", "644", tmp_netdev, "/etc/systemd/network/zlodev0.netdev" });
            // Best-effort: services may not be running
            sys.sudoCmd(allocator, &.{ "sudo", "systemctl", "restart", "systemd-networkd.service" }) catch {};
            sys.sudoCmd(allocator, &.{ "sudo", "systemctl", "restart", "systemd-resolved.service" }) catch {};
        },
        .windows => {
            const ps_cmd = try std.fmt.allocPrint(allocator, "Add-DnsClientNrptRule -Namespace '.{s}' -NameServers '{s}'", .{ tld, ip });
            defer allocator.free(ps_cmd);
            try sys.sudoCmd(allocator, &.{ "Powershell.exe", "-Command", ps_cmd });
        },
        else => {},
    }
}

pub fn uninstall(allocator: std.mem.Allocator, tld: []const u8) !void {
    switch (builtin.os.tag) {
        .macos => {
            const path = try std.fmt.allocPrint(allocator, "/etc/resolver/{s}", .{tld});
            defer allocator.free(path);
            try sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", path });
        },
        .linux => {
            try sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", "/etc/systemd/network/zlodev0.network" });
            try sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", "/etc/systemd/network/zlodev0.netdev" });
            // Only delete interface if it exists
            if (std.fs.accessAbsolute("/sys/class/net/zlodev0", .{})) |_| {
                sys.sudoCmd(allocator, &.{ "sudo", "networkctl", "delete", "zlodev0" }) catch {};
            } else |_| {}
            sys.sudoCmd(allocator, &.{ "sudo", "systemctl", "restart", "systemd-networkd.service" }) catch {};
            sys.sudoCmd(allocator, &.{ "sudo", "systemctl", "restart", "systemd-resolved.service" }) catch {};
        },
        .windows => {
            const ps_cmd = try std.fmt.allocPrint(allocator, "Get-DnsClientNrptRule | Where {{ $_.Namespace -eq '.{s}' }} | Remove-DnsClientNrptRule -Force", .{tld});
            defer allocator.free(ps_cmd);
            try sys.sudoCmd(allocator, &.{ "Powershell.exe", "-Command", ps_cmd });
        },
        else => {},
    }
}


// --- Unit Tests ---

const testing = std.testing;

// Helper: build a DNS query packet for a given domain name and qtype
fn buildTestQuery(name: []const u8, qtype: u16) [512]u8 {
    var buf: [512]u8 = @splat(0);
    // Header: ID=0x1234, flags=0x0100 (RD), QDCOUNT=1
    buf[0] = 0x12;
    buf[1] = 0x34;
    buf[2] = 0x01;
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x01;
    // ANCOUNT, NSCOUNT, ARCOUNT = 0

    // Encode QNAME starting at offset 12
    var pos: usize = 12;
    var iter = std.mem.splitScalar(u8, name, '.');
    while (iter.next()) |label| {
        buf[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(buf[pos..][0..label.len], label);
        pos += label.len;
    }
    buf[pos] = 0; // root terminator
    pos += 1;

    // QTYPE
    writeU16(&buf, pos, qtype);
    pos += 2;
    // QCLASS = IN (1)
    writeU16(&buf, pos, CLASS_IN);

    return buf;
}

fn testQueryLen(name: []const u8) usize {
    // 12 (header) + encoded name length + 1 (root) + 4 (qtype+qclass)
    var len: usize = 12;
    var iter = std.mem.splitScalar(u8, name, '.');
    while (iter.next()) |label| {
        len += 1 + label.len;
    }
    len += 1 + 4; // root terminator + qtype + qclass
    return len;
}

test "parseHeader" {
    const data = buildTestQuery("dev.lo", QTYPE_A);
    const header = parseHeader(&data);
    try testing.expectEqual(@as(u16, 0x1234), header.id);
    try testing.expectEqual(@as(u16, 0x0100), header.flags);
    try testing.expectEqual(@as(u16, 1), header.qd_count);
    try testing.expectEqual(@as(u16, 0), header.an_count);
    try testing.expectEqual(@as(u16, 0), header.ns_count);
    try testing.expectEqual(@as(u16, 0), header.ar_count);
}

test "parseQuestion" {
    const data = buildTestQuery("dev.lo", QTYPE_A);
    const question = parseQuestion(&data) orelse {
        return error.TestUnexpectedResult;
    };
    try testing.expectEqual(@as(u16, QTYPE_A), question.qtype);
    try testing.expectEqual(@as(u16, CLASS_IN), question.qclass);
    try testing.expectEqual(@as(usize, 12), question.name_start);
}

test "parseQuestion AAAA" {
    const data = buildTestQuery("test.lo", QTYPE_AAAA);
    const question = parseQuestion(&data) orelse {
        return error.TestUnexpectedResult;
    };
    try testing.expectEqual(@as(u16, QTYPE_AAAA), question.qtype);
    try testing.expectEqual(@as(u16, CLASS_IN), question.qclass);
}

test "parseQuestion too small" {
    const data = [_]u8{ 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0 }; // < 12 bytes
    // parseQuestion requires at least 12 bytes for header
    // With only 11 bytes, behavior depends on implementation
    // The function should handle this gracefully
    const result = parseQuestion(&data);
    _ = result; // Just verify it doesn't crash
}

test "decodeName simple" {
    const data = buildTestQuery("dev.lo", QTYPE_A);
    const question = parseQuestion(&data).?;
    var name_buf: [256]u8 = undefined;
    const name = decodeName(&data, question.name_start, question.name_end, &name_buf);
    try testing.expectEqualStrings("dev.lo", name);
}

test "decodeName multi-label" {
    const data = buildTestQuery("app.dev.lo", QTYPE_A);
    const question = parseQuestion(&data).?;
    var name_buf: [256]u8 = undefined;
    const name = decodeName(&data, question.name_start, question.name_end, &name_buf);
    try testing.expectEqualStrings("app.dev.lo", name);
}

test "decodeName single label" {
    const data = buildTestQuery("lo", QTYPE_A);
    const question = parseQuestion(&data).?;
    var name_buf: [256]u8 = undefined;
    const name = decodeName(&data, question.name_start, question.name_end, &name_buf);
    try testing.expectEqualStrings("lo", name);
}

test "buildResponse A record for matching domain" {
    const data = buildTestQuery("dev.lo", QTYPE_A);
    const header = parseHeader(&data);
    const question = parseQuestion(&data).?;
    var resp_buf: [512]u8 = undefined;
    const resp_len = buildResponse(&data, question, header, "lo", &resp_buf);
    try testing.expect(resp_len > 0);

    // Check response header
    const resp_header = parseHeader(&resp_buf);
    try testing.expectEqual(@as(u16, 0x1234), resp_header.id);
    try testing.expectEqual(@as(u16, 0x8000), resp_header.flags); // QR=1, RCODE=0
    try testing.expectEqual(@as(u16, 1), resp_header.qd_count);
    try testing.expectEqual(@as(u16, 1), resp_header.an_count);

    // Check answer contains 127.0.0.1
    // Answer RDATA is at the end: last 4 bytes should be 127.0.0.1
    try testing.expectEqual(@as(u8, 127), resp_buf[resp_len - 4]);
    try testing.expectEqual(@as(u8, 0), resp_buf[resp_len - 3]);
    try testing.expectEqual(@as(u8, 0), resp_buf[resp_len - 2]);
    try testing.expectEqual(@as(u8, 1), resp_buf[resp_len - 1]);
}

test "buildResponse AAAA record for matching domain returns empty" {
    const data = buildTestQuery("dev.lo", QTYPE_AAAA);
    const header = parseHeader(&data);
    const question = parseQuestion(&data).?;
    var resp_buf: [512]u8 = undefined;
    const resp_len = buildResponse(&data, question, header, "lo", &resp_buf);
    try testing.expect(resp_len > 0);

    const resp_header = parseHeader(&resp_buf);
    // AAAA returns empty response (no answer) to force IPv4
    try testing.expectEqual(@as(u16, 0), resp_header.an_count);
}

test "buildResponse NXDOMAIN for non-matching domain" {
    const data = buildTestQuery("example.com", QTYPE_A);
    const header = parseHeader(&data);
    const question = parseQuestion(&data).?;
    var resp_buf: [512]u8 = undefined;
    const resp_len = buildResponse(&data, question, header, "lo", &resp_buf);
    try testing.expect(resp_len > 0);

    const resp_header = parseHeader(&resp_buf);
    try testing.expectEqual(@as(u16, 0x1234), resp_header.id);
    try testing.expectEqual(@as(u16, 0x8003), resp_header.flags); // QR=1, RCODE=3 (NXDOMAIN)
    try testing.expectEqual(@as(u16, 0), resp_header.an_count);
}

test "buildResponse unsupported type for matching domain" {
    const data = buildTestQuery("dev.lo", TYPE_NULL);
    const header = parseHeader(&data);
    const question = parseQuestion(&data).?;
    var resp_buf: [512]u8 = undefined;
    const resp_len = buildResponse(&data, question, header, "lo", &resp_buf);
    try testing.expect(resp_len > 0);

    const resp_header = parseHeader(&resp_buf);
    try testing.expectEqual(@as(u16, 0x8000), resp_header.flags); // NOERROR
    try testing.expectEqual(@as(u16, 0), resp_header.an_count); // no answer
}

test "buildResponse subdomain matches TLD" {
    const data = buildTestQuery("app.dev.lo", QTYPE_A);
    const header = parseHeader(&data);
    const question = parseQuestion(&data).?;
    var resp_buf: [512]u8 = undefined;
    const resp_len = buildResponse(&data, question, header, "lo", &resp_buf);
    try testing.expect(resp_len > 0);

    const resp_header = parseHeader(&resp_buf);
    try testing.expectEqual(@as(u16, 0x8000), resp_header.flags); // NOERROR, not NXDOMAIN
    try testing.expectEqual(@as(u16, 1), resp_header.an_count);
}

test "buildResponse exact TLD matches" {
    const data = buildTestQuery("lo", QTYPE_A);
    const header = parseHeader(&data);
    const question = parseQuestion(&data).?;
    var resp_buf: [512]u8 = undefined;
    const resp_len = buildResponse(&data, question, header, "lo", &resp_buf);
    try testing.expect(resp_len > 0);

    const resp_header = parseHeader(&resp_buf);
    try testing.expectEqual(@as(u16, 0x8000), resp_header.flags); // NOERROR
    try testing.expectEqual(@as(u16, 1), resp_header.an_count);
}

test "readU16 and writeU16 roundtrip" {
    var buf: [2]u8 = undefined;
    writeU16(&buf, 0, 0xABCD);
    try testing.expectEqual(@as(u16, 0xABCD), readU16(&buf, 0));
    writeU16(&buf, 0, 0);
    try testing.expectEqual(@as(u16, 0), readU16(&buf, 0));
    writeU16(&buf, 0, 0xFFFF);
    try testing.expectEqual(@as(u16, 0xFFFF), readU16(&buf, 0));
}

test "writeU32" {
    var buf: [4]u8 = undefined;
    writeU32(&buf, 0, 0x12345678);
    try testing.expectEqual(@as(u8, 0x12), buf[0]);
    try testing.expectEqual(@as(u8, 0x34), buf[1]);
    try testing.expectEqual(@as(u8, 0x56), buf[2]);
    try testing.expectEqual(@as(u8, 0x78), buf[3]);
}
