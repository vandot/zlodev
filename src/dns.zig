const std = @import("std");
const rt = @import("rt.zig");
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
        if (label_len >= 0xC0) return null; // compression pointer — not supported
        if (label_len > 63) return null; // RFC 1035: labels must be <= 63 bytes
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
        if (label_len >= 0xC0) break; // compression pointer — stop decoding
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

    // Guard: worst case response is 12 (header) + question_len + 16 (A record answer)
    if (12 + question_len + 16 > buf.len) return 0;

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
            writeU16(buf, pos, 0x8400); // QR=1, AA=1, RCODE=0
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
            writeU16(buf, pos, 0x8400); // QR=1, AA=1, RCODE=0
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
    writeU16(buf, pos, 0x8400); // QR=1, AA=1, RCODE=0
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

/// Create and bind the DNS UDP socket. Separate from `serve` so startup can
/// fail before the TUI opens when the port is taken.
pub fn bind(ip: []const u8, port: u16) !compat.socket_t {
    const addr = parseAddr(ip, port) catch |e| {
        log.err("component=dns op=addr_parse error={any}", .{e});
        return e;
    };
    return compat.udpBindFreebind(addr) catch |e| {
        log.err("component=dns op=bind ip={s} port={d} error={any}", .{ ip, port, e });
        return e;
    };
}

/// Answer queries on a socket from `bind` until shutdown. Takes ownership of `sock`.
pub fn serve(sock: compat.socket_t, ip: []const u8, port: u16, tld: []const u8) void {
    defer compat.closeSocket(sock);

    log.info("component=dns op=listening ip={s} port={d}", .{ ip, port });

    var recv_buf: [512]u8 = undefined;
    var resp_buf: [512]u8 = undefined;

    while (shutdown.isRunning()) {
        // Poll with 1-second timeout before receive
        var fds = [1]compat.pollfd{
            .{ .fd = sock, .events = compat.POLL.IN, .revents = 0 },
        };
        const ready = compat.poll(&fds, 1000) catch |e| {
            log.err("component=dns op=poll error={any}", .{e});
            continue;
        };
        if (ready == 0) continue; // timeout, re-check shutdown

        const msg = compat.recvFrom(sock, &recv_buf) catch |e| {
            log.err("component=dns op=recvfrom error={any}", .{e});
            continue;
        };

        if (msg.data.len < 12) continue; // Too small for DNS header

        const data = msg.data;
        const header = parseHeader(data);
        if (header.qd_count == 0) continue;

        const question = parseQuestion(data) orelse continue;
        const resp_len = buildResponse(data, question, header, tld, &resp_buf);
        if (resp_len == 0) continue;

        compat.sendTo(sock, msg.from, resp_buf[0..resp_len]) catch |e| {
            log.err("component=dns op=sendto error={any}", .{e});
            continue;
        };
    }
}

fn parseAddr(ip: []const u8, port: u16) !std.Io.net.IpAddress {
    return try std.Io.net.IpAddress.parseIp4(ip, port);
}

/// Linux DNS install needs systemd as PID 1 and systemd-resolved active.
/// Inputs are raw `ps -o comm 1` / `systemctl is-active` output.
pub fn systemdResolvedReady(pid1_comm: []const u8, resolved_state: []const u8) bool {
    const ws = "\n\r ";
    return std.mem.eql(u8, std.mem.trim(u8, pid1_comm, ws), "systemd") and
        std.mem.eql(u8, std.mem.trim(u8, resolved_state, ws), "active");
}

/// Address of the zlodev0 link on Linux: the link's own address, its DNS
/// server, and what zlodev listens on (port 53: NetworkManager can't set a
/// DNS port). RFC 7600 dummy address.
pub const linux_dns_ip = "192.0.0.8";

/// NetworkManager connection that owns zlodev0 on NetworkManager systems.
pub const nm_connection = "zlodev";

pub const LinuxBackend = enum { networkd, network_manager };

/// Pick who creates zlodev0. networkd wins when both run, so systems set up
/// by earlier versions keep their files. Inputs are raw `systemctl
/// is-active` output ("" when the command failed).
pub fn chooseLinuxBackend(networkd_state: []const u8, nm_state: []const u8) ?LinuxBackend {
    const ws = "\n\r ";
    if (std.mem.eql(u8, std.mem.trim(u8, networkd_state, ws), "active")) return .networkd;
    if (std.mem.eql(u8, std.mem.trim(u8, nm_state, ws), "active")) return .network_manager;
    return null;
}

/// zlodev0.network for networkd. The address makes resolved use the link's
/// DNS settings (a link without one stays `degraded`, scope none).
pub fn networkdNetworkText(allocator: std.mem.Allocator, ip: []const u8, tld: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "[Match]\nName=zlodev0\n[Network]\nAddress={s}/32\nDomains=~{s}\nDNS={s}\n", .{ ip, tld, ip });
}

/// `sudo nmcli connection add ...` argv for the zlodev0 dummy connection.
/// `argv` borrows `ip`; `addr` and `search` are owned, freed by `deinit`.
pub const NmcliAdd = struct {
    addr: []u8,
    search: []u8,
    argv: [24][]const u8,

    pub fn deinit(self: *const NmcliAdd, allocator: std.mem.Allocator) void {
        allocator.free(self.addr);
        allocator.free(self.search);
    }
};

pub fn nmcliAddArgs(allocator: std.mem.Allocator, ip: []const u8, tld: []const u8) !NmcliAdd {
    const addr = try std.fmt.allocPrint(allocator, "{s}/32", .{ip});
    errdefer allocator.free(addr);
    const search = try std.fmt.allocPrint(allocator, "~{s}", .{tld});
    return .{ .addr = addr, .search = search, .argv = .{
        "sudo",           "nmcli",    "connection",             "add",
        "type",           "dummy",    "con-name",               nm_connection,
        "ifname",         "zlodev0",  "ipv4.method",            "manual",
        "ipv4.addresses", addr,       "ipv4.never-default",     "yes",
        "ipv4.dns",       ip,         "ipv4.dns-search",        search,
        "ipv6.method",    "disabled", "connection.autoconnect", "yes",
    } };
}

/// zlodev 0.6.0 and earlier pointed resolved at port 5354.
pub fn isLegacyNetworkd(contents: []const u8) bool {
    return std.mem.indexOf(u8, contents, ":5354") != null;
}

/// Start-time warning for Linux DNS setup. `network_file` is the contents of
/// /etc/systemd/network/zlodev0.network (null if absent); `link_exists` is
/// whether /sys/class/net/zlodev0 exists (both backends create it).
pub fn linuxDnsWarning(network_file: ?[]const u8, link_exists: bool) ?[]const u8 {
    if (network_file) |c| if (isLegacyNetworkd(c))
        return "warning: DNS config is from an older zlodev, run 'zlodev install --dns' again\n";
    if (!link_exists) return "warning: DNS resolver not installed, run 'zlodev install --dns' first\n";
    return null;
}

pub fn systemProbe() struct { ip: []const u8, port: u16 } {
    switch (builtin.os.tag) {
        .linux => {
            return .{ .ip = linux_dns_ip, .port = 53 };
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

/// Load zlodev0 .netdev/.network changes. `networkctl reload` leaves other
/// interfaces alone; a restart reconfigures every link networkd manages, which
/// can drop the machine's real connection. Restart only where reload is missing
/// (systemd < 244).
fn reloadNetworkd(allocator: std.mem.Allocator) !void {
    sys.sudoCmd(allocator, &.{ "sudo", "networkctl", "reload" }) catch {
        try sys.sudoCmd(allocator, &.{ "sudo", "systemctl", "restart", "systemd-networkd.service" });
    };
}

const networkd_network_path = "/etc/systemd/network/zlodev0.network";
const networkd_netdev_path = "/etc/systemd/network/zlodev0.netdev";

fn pathExists(path: []const u8) bool {
    std.Io.Dir.accessAbsolute(rt.io(), path, .{}) catch return false;
    return true;
}

fn detectLinuxBackend(allocator: std.mem.Allocator) ?LinuxBackend {
    const nd = sys.runCmdOutput(allocator, &.{ "systemctl", "is-active", "systemd-networkd.service" });
    defer if (nd) |s| allocator.free(s);
    const nm = sys.runCmdOutput(allocator, &.{ "systemctl", "is-active", "NetworkManager.service" });
    defer if (nm) |s| allocator.free(s);
    return chooseLinuxBackend(nd orelse "", nm orelse "");
}

fn nmConnectionExists() bool {
    return sys.runUserCmd(&.{ "nmcli", "-g", "connection.id", "connection", "show", "id", nm_connection }) == .ok;
}

fn installNetworkd(allocator: std.mem.Allocator, ip: []const u8, tld: []const u8) !void {
    const network_text = try networkdNetworkText(allocator, ip, tld);
    defer allocator.free(network_text);
    const tmp_network = try sys.writeTmpFile(allocator, "dns_network", network_text);
    defer allocator.free(tmp_network);
    defer sys.removeTmpFile(tmp_network);
    try sys.sudoCmd(allocator, &.{ "sudo", "install", "-m", "644", tmp_network, networkd_network_path });

    const netdev_text = "[NetDev]\nName=zlodev0\nKind=dummy\n";
    const tmp_netdev = try sys.writeTmpFile(allocator, "dns_netdev", netdev_text);
    defer allocator.free(tmp_netdev);
    defer sys.removeTmpFile(tmp_netdev);
    try sys.sudoCmd(allocator, &.{ "sudo", "install", "-m", "644", tmp_netdev, networkd_netdev_path });
    const link_existed = pathExists("/sys/class/net/zlodev0");
    // networkd creates the zlodev0 dummy interface; without it .lo never resolves.
    reloadNetworkd(allocator) catch |e| {
        std.debug.print("could not reload systemd-networkd (needed for the zlodev0 interface); is it installed and not masked?\n", .{});
        return e;
    };
    // Reinstall: reload alone leaves an existing link on the old .network (systemd < 249).
    if (link_existed) sys.sudoCmd(allocator, &.{ "sudo", "networkctl", "reconfigure", "zlodev0" }) catch {};
}

fn installNetworkManager(allocator: std.mem.Allocator, ip: []const u8, tld: []const u8) !void {
    // Reinstall: replace the connection so it gets the current settings.
    if (nmConnectionExists()) {
        try sys.sudoCmd(allocator, &.{ "sudo", "nmcli", "connection", "delete", nm_connection });
    }
    const add = try nmcliAddArgs(allocator, ip, tld);
    defer add.deinit(allocator);
    sys.sudoCmd(allocator, &add.argv) catch |e| {
        std.debug.print("could not create the zlodev NetworkManager connection\n", .{});
        return e;
    };
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
            defer sys.removeTmpFile(tmp_path);
            const dest = try std.fmt.allocPrint(allocator, "/etc/resolver/{s}", .{tld});
            defer allocator.free(dest);
            try sys.sudoCmd(allocator, &.{ "sudo", "install", "-m", "644", tmp_path, dest });
        },
        .linux => {
            const backend = detectLinuxBackend(allocator) orelse {
                std.debug.print("linux DNS setup needs systemd-networkd or NetworkManager to be running\n", .{});
                std.process.exit(1);
            };
            switch (backend) {
                .networkd => try installNetworkd(allocator, ip, tld),
                .network_manager => try installNetworkManager(allocator, ip, tld),
            }
            sys.sudoCmd(allocator, &.{ "sudo", "resolvectl", "flush-caches" }) catch {};
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
            if (nmConnectionExists()) {
                sys.sudoCmd(allocator, &.{ "sudo", "nmcli", "connection", "delete", nm_connection }) catch {};
            }
            // Touch networkd only if zlodev configured it: reloadNetworkd falls
            // back to a restart, which would start networkd on a
            // NetworkManager-only system.
            if (pathExists(networkd_network_path) or pathExists(networkd_netdev_path)) {
                try sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", networkd_network_path });
                try sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", networkd_netdev_path });
                if (pathExists("/sys/class/net/zlodev0")) {
                    sys.sudoCmd(allocator, &.{ "sudo", "networkctl", "delete", "zlodev0" }) catch {};
                }
                reloadNetworkd(allocator) catch {};
            }
            sys.sudoCmd(allocator, &.{ "sudo", "resolvectl", "flush-caches" }) catch {};
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
    const result = parseQuestion(&data);
    try testing.expect(result == null);
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
    try testing.expectEqual(@as(u16, 0x8400), resp_header.flags); // QR=1, AA=1, RCODE=0
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
    try testing.expectEqual(@as(u16, 0x8400), resp_header.flags); // QR=1, AA=1, NOERROR
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
    try testing.expectEqual(@as(u16, 0x8400), resp_header.flags); // QR=1, AA=1, NOERROR
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
    try testing.expectEqual(@as(u16, 0x8400), resp_header.flags); // QR=1, AA=1, NOERROR
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

test "parseQuestion rejects compression pointers" {
    // Craft a packet with a compression pointer (0xC0) where a label length should be
    var pkt: [20]u8 = @splat(0);
    // Header (12 bytes)
    pkt[4] = 0; pkt[5] = 1; // QDCOUNT = 1
    // QNAME starting at byte 12: compression pointer instead of label
    pkt[12] = 0xC0; // compression pointer
    pkt[13] = 0x00; // pointer offset
    const result = parseQuestion(&pkt);
    try std.testing.expect(result == null);
}

test "bind reports AddressInUse when the port is taken" {
    const first = try bind("127.0.0.1", 18095);
    defer compat.closeSocket(first);
    try std.testing.expectError(error.AddressInUse, bind("127.0.0.1", 18095));
}

test "systemdResolvedReady accepts systemd with active resolved" {
    try std.testing.expect(systemdResolvedReady("systemd\n", "active\n"));
}

test "systemdResolvedReady rejects inactive resolved" {
    try std.testing.expect(!systemdResolvedReady("systemd", "inactive"));
}

test "systemdResolvedReady rejects a non-systemd init" {
    try std.testing.expect(!systemdResolvedReady("init", "active"));
}

test "chooseLinuxBackend prefers networkd, falls back to NetworkManager" {
    try std.testing.expectEqual(LinuxBackend.networkd, chooseLinuxBackend("active\n", "inactive\n").?);
    try std.testing.expectEqual(LinuxBackend.networkd, chooseLinuxBackend("active\n", "active\n").?);
    try std.testing.expectEqual(LinuxBackend.network_manager, chooseLinuxBackend("inactive\n", " active\r\n").?);
    try std.testing.expectEqual(LinuxBackend.network_manager, chooseLinuxBackend("", "active").?);
    try std.testing.expectEqual(@as(?LinuxBackend, null), chooseLinuxBackend("inactive", "failed"));
    try std.testing.expectEqual(@as(?LinuxBackend, null), chooseLinuxBackend("", ""));
}

test "networkdNetworkText routes the tld to the link's own address on port 53" {
    const text = try networkdNetworkText(std.testing.allocator, "192.0.0.8", "lo");
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings(
        "[Match]\nName=zlodev0\n[Network]\nAddress=192.0.0.8/32\nDomains=~lo\nDNS=192.0.0.8\n",
        text,
    );
}

test "nmcliAddArgs builds the dummy connection command" {
    const add = try nmcliAddArgs(std.testing.allocator, "192.0.0.8", "lo");
    defer add.deinit(std.testing.allocator);
    const want = [_][]const u8{
        "sudo",           "nmcli",        "connection",             "add",
        "type",           "dummy",        "con-name",               "zlodev",
        "ifname",         "zlodev0",      "ipv4.method",            "manual",
        "ipv4.addresses", "192.0.0.8/32", "ipv4.never-default",     "yes",
        "ipv4.dns",       "192.0.0.8",    "ipv4.dns-search",        "~lo",
        "ipv6.method",    "disabled",     "connection.autoconnect", "yes",
    };
    try std.testing.expectEqual(want.len, add.argv.len);
    for (want, add.argv) |w, got| try std.testing.expectEqualStrings(w, got);
}

test "isLegacyNetworkd detects the 0.6.0 port-5354 config" {
    try std.testing.expect(isLegacyNetworkd("[Match]\nName=zlodev0\n[Network]\nAddress=192.0.0.8/32\nDomains=~lo\nDNS=192.0.0.8:5354\n"));
    try std.testing.expect(!isLegacyNetworkd("[Match]\nName=zlodev0\n[Network]\nAddress=192.0.0.8/32\nDomains=~lo\nDNS=192.0.0.8\n"));
    try std.testing.expect(!isLegacyNetworkd(""));
}

test "linuxDnsWarning: legacy config, missing link, or nothing" {
    const legacy = "DNS=192.0.0.8:5354\n";
    try std.testing.expectEqualStrings(
        "warning: DNS config is from an older zlodev, run 'zlodev install --dns' again\n",
        linuxDnsWarning(legacy, true).?,
    );
    try std.testing.expectEqualStrings(
        "warning: DNS config is from an older zlodev, run 'zlodev install --dns' again\n",
        linuxDnsWarning(legacy, false).?,
    );
    try std.testing.expectEqualStrings(
        "warning: DNS resolver not installed, run 'zlodev install --dns' first\n",
        linuxDnsWarning(null, false).?,
    );
    try std.testing.expectEqual(@as(?[]const u8, null), linuxDnsWarning(null, true));
    try std.testing.expectEqual(@as(?[]const u8, null), linuxDnsWarning("DNS=192.0.0.8\n", true));
}

test "systemProbe on Linux is the zlodev0 address on port 53" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const p = systemProbe();
    try std.testing.expectEqualStrings("192.0.0.8", p.ip);
    try std.testing.expectEqual(@as(u16, 53), p.port);
}
