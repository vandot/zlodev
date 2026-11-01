const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const win32 = @import("win32.zig");

pub const socket_t = posix.socket_t;

/// Close a raw socket (not a std.net.Stream).
/// On Windows uses closesocket, on POSIX uses close.
pub fn closeSocket(sock: socket_t) void {
    if (builtin.os.tag == .windows) {
        _ = win32.closesocket(sock);
    } else {
        _ = posix.system.close(sock);
    }
}

/// Convert a socket handle to the int type that SSL_set_fd expects.
/// On POSIX, socket_t is already int. On Windows, SOCKET is a UINT_PTR (64-bit)
/// but SSL_set_fd takes c_int. We truncate to c_int because BoringSSL internally
/// stores and retrieves the value via the same truncated path (SSL_get_fd returns
/// the same c_int). The actual Windows socket handle is preserved as long as we
/// round-trip through fdToSocket.
pub fn socketToFd(sock: socket_t) c_int {
    if (builtin.os.tag == .windows) {
        // Truncate the pointer to c_int — this matches what Winsock's internal
        // fd-to-socket mapping expects for small handle values.
        return @truncate(@as(isize, @bitCast(@intFromPtr(sock))));
    } else {
        return sock;
    }
}

/// Convert an fd from SSL_get_fd back to a socket_t for use with poll/closesocket.
pub fn fdToSocket(fd: c_int) socket_t {
    if (builtin.os.tag == .windows) {
        // Sign-extend back to the original pointer-sized SOCKET value.
        const wide: usize = @bitCast(@as(isize, fd));
        return @ptrFromInt(wide);
    } else {
        return fd;
    }
}

/// poll() over sockets. Zig 0.17's std.posix.poll no longer covers Windows,
/// so use WSAPoll there (what 0.15's posix.poll called).
pub const pollfd = if (builtin.os.tag == .windows) win32.WSAPOLLFD else posix.pollfd;
pub const POLL = if (builtin.os.tag == .windows) win32.POLL else posix.POLL;

pub fn poll(fds: []pollfd, timeout_ms: i32) !usize {
    if (builtin.os.tag == .windows) {
        const rc = win32.WSAPoll(fds.ptr, @intCast(fds.len), timeout_ms);
        if (rc == win32.SOCKET_ERROR) return error.Unexpected;
        return @intCast(rc);
    }
    return posix.poll(fds, timeout_ms);
}

/// Initialize Winsock. Must be called before any socket operations on Windows.
/// No-op on other platforms.
pub fn initNetworking() void {
    if (builtin.os.tag == .windows) {
        var wsa_data: win32.WSADATA = undefined;
        _ = win32.WSAStartup(0x0202, &wsa_data);
    }
}

/// Get a temporary directory path.
pub fn getTmpDir() []const u8 {
    if (builtin.os.tag == .windows) {
        return getenv("TEMP") orelse getenv("TMP") orelse "C:\\Windows\\Temp";
    }
    return "/tmp";
}

/// Cross-platform socket stream. On Windows, Zig's std.net.Stream uses ReadFile/
/// WriteFile which don't work with Winsock sockets. This wrapper uses recv/send
/// on Windows and read/write on POSIX.
pub const SocketStream = struct {
    handle: socket_t,

    pub fn read(self: SocketStream, buf: []u8) !usize {
        if (builtin.os.tag == .windows) {
            const rc = win32.recv(self.handle, buf.ptr, @intCast(buf.len), 0);
            if (rc == win32.SOCKET_ERROR) return error.Unexpected;
            return @intCast(rc);
        }
        return posix.read(self.handle, buf);
    }

    pub fn writeAll(self: SocketStream, data: []const u8) !void {
        if (builtin.os.tag == .windows) {
            var written: usize = 0;
            while (written < data.len) {
                const rc = win32.send(self.handle, data[written..].ptr, @intCast(data.len - written), 0);
                if (rc == win32.SOCKET_ERROR) return error.Unexpected;
                written += @intCast(rc);
            }
        } else {
            var written: usize = 0;
            while (written < data.len) {
                const rc = posix.system.write(self.handle, data[written..].ptr, data.len - written);
                switch (posix.errno(rc)) {
                    .SUCCESS => written += @intCast(rc),
                    .INTR => continue,
                    else => return error.Unexpected,
                }
            }
        }
    }

    pub fn close(self: SocketStream) void {
        closeSocket(self.handle);
    }
};

// --- Sockets ---
//
// Zig 0.17's std.Io.net opens raw AFD handles on Windows, which Winsock calls
// (recv/send/WSAPoll/setsockopt) and BoringSSL's socket BIO reject. So zlodev
// creates its own sockets: Winsock on Windows, the BSD socket API elsewhere
// (libc or Linux syscalls via std.posix.system). Addresses use
// std.Io.net.IpAddress for parsing and formatting only.

pub const SocketError = error{
    AddressInUse,
    AccessDenied,
    ConnectionRefused,
    ConnectionResetByPeer,
    NetworkUnreachable,
    TimedOut,
    UnknownHostName,
    Unexpected,
};

const SockAddr = struct {
    storage: std.c.sockaddr.storage = undefined,
    len: u32 = 0,

    fn from(ip: Ip) SockAddr {
        var sa: SockAddr = .{};
        switch (ip) {
            .ip4 => |a| {
                const in: std.c.sockaddr.in = .{
                    .port = std.mem.nativeToBig(u16, a.port),
                    .addr = @bitCast(a.bytes),
                };
                @memcpy(std.mem.asBytes(&sa.storage)[0..@sizeOf(@TypeOf(in))], std.mem.asBytes(&in));
                sa.len = @sizeOf(@TypeOf(in));
            },
            .ip6 => |a| {
                const in6: std.c.sockaddr.in6 = .{
                    .port = std.mem.nativeToBig(u16, a.port),
                    .flowinfo = a.flow,
                    .addr = a.bytes,
                    .scope_id = 0,
                };
                @memcpy(std.mem.asBytes(&sa.storage)[0..@sizeOf(@TypeOf(in6))], std.mem.asBytes(&in6));
                sa.len = @sizeOf(@TypeOf(in6));
            },
        }
        return sa;
    }

    fn toIp(self: *const SockAddr) Ip {
        return fromRaw(@ptrCast(&self.storage));
    }

    fn fromRaw(raw: *const std.c.sockaddr) Ip {
        if (raw.family == std.c.AF.INET6) {
            const in6: *const std.c.sockaddr.in6 = @ptrCast(@alignCast(raw));
            return .{ .ip6 = .{ .port = std.mem.bigToNative(u16, in6.port), .bytes = in6.addr, .flow = in6.flowinfo } };
        }
        const in: *const std.c.sockaddr.in = @ptrCast(@alignCast(raw));
        return .{ .ip4 = .{ .port = std.mem.bigToNative(u16, in.port), .bytes = @bitCast(in.addr) } };
    }
};

fn family(ip: Ip) u32 {
    return switch (ip) {
        .ip4 => std.c.AF.INET,
        .ip6 => std.c.AF.INET6,
    };
}

fn lastError() SocketError {
    if (builtin.os.tag == .windows) {
        return switch (win32.WSAGetLastError()) {
            10048 => error.AddressInUse, // WSAEADDRINUSE
            10013 => error.AccessDenied, // WSAEACCES
            10061 => error.ConnectionRefused, // WSAECONNREFUSED
            10054 => error.ConnectionResetByPeer, // WSAECONNRESET
            10051, 10065 => error.NetworkUnreachable, // WSAENETUNREACH, WSAEHOSTUNREACH
            10060 => error.TimedOut, // WSAETIMEDOUT
            else => error.Unexpected,
        };
    }
    unreachable;
}

fn posixError(e: posix.E) SocketError {
    return switch (e) {
        .ADDRINUSE => error.AddressInUse,
        .ACCES, .PERM => error.AccessDenied,
        .CONNREFUSED => error.ConnectionRefused,
        .CONNRESET => error.ConnectionResetByPeer,
        .NETUNREACH, .HOSTUNREACH => error.NetworkUnreachable,
        .TIMEDOUT => error.TimedOut,
        else => error.Unexpected,
    };
}

var winsock_started: std.atomic.Value(bool) = .init(false);

fn openSocket(fam: u32, kind: u32) SocketError!socket_t {
    if (builtin.os.tag == .windows) {
        // Start Winsock on first use (tests and helpers may not go through main);
        // WSAStartup is reference-counted, so a racing second call is harmless.
        if (!winsock_started.swap(true, .acq_rel)) initNetworking();
        const s = win32.WSASocketW(@intCast(fam), @intCast(kind), 0, null, 0, win32.WSA_FLAG_OVERLAPPED | win32.WSA_FLAG_NO_HANDLE_INHERIT);
        if (@intFromPtr(s) == win32.INVALID_SOCKET) return lastError();
        return s;
    }
    // Close-on-exec so the --command dev server doesn't inherit our sockets.
    const flags: u32 = if (builtin.os.tag == .linux) posix.SOCK.CLOEXEC else 0;
    const rc = posix.system.socket(fam, kind | flags, 0);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => |e| return posixError(e),
    }
    const fd: socket_t = @intCast(rc);
    if (flags == 0) setCloexec(fd);
    return fd;
}

fn setCloexec(fd: socket_t) void {
    if (builtin.os.tag == .windows) return;
    _ = posix.system.fcntl(fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC));
}

fn setReuse(sock: socket_t) void {
    const one: c_int = 1;
    if (builtin.os.tag == .windows) {
        _ = win32.setsockopt(sock, 0xffff, 0x0004, std.mem.asBytes(&one), @sizeOf(c_int)); // SOL_SOCKET, SO_REUSEADDR
        return;
    }
    // Same options std.net used in 0.15 for reuse_address.
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
    if (@hasDecl(posix.SO, "REUSEPORT")) {
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&one)) catch {};
    }
}

fn bindTo(sock: socket_t, sa: *const SockAddr) SocketError!void {
    if (builtin.os.tag == .windows) {
        if (win32.bind(sock, &sa.storage, @intCast(sa.len)) != 0) return lastError();
        return;
    }
    switch (posix.errno(posix.system.bind(sock, @ptrCast(&sa.storage), sa.len))) {
        .SUCCESS => {},
        else => |e| return posixError(e),
    }
}

/// Bind a UDP socket.
pub fn udpBind(ip: Ip) SocketError!socket_t {
    const sock = try openSocket(family(ip), posix.SOCK.DGRAM);
    errdefer closeSocket(sock);
    try bindTo(sock, &.from(ip));
    return sock;
}

/// Bind and listen on a TCP socket with address reuse (as zlodev always has).
pub fn tcpListen(ip: Ip) SocketError!socket_t {
    return listenTcp(ip, true);
}

fn listenTcp(ip: Ip, reuse: bool) SocketError!socket_t {
    const sock = try openSocket(family(ip), posix.SOCK.STREAM);
    errdefer closeSocket(sock);
    if (reuse) setReuse(sock);
    try bindTo(sock, &.from(ip));
    if (builtin.os.tag == .windows) {
        if (win32.listen(sock, 128) != 0) return lastError();
    } else switch (posix.errno(posix.system.listen(sock, 128))) {
        .SUCCESS => {},
        else => |e| return posixError(e),
    }
    return sock;
}

pub const Accepted = struct { sock: socket_t, addr: Ip };

/// Accept one connection (blocking).
pub fn accept(listener: socket_t) SocketError!Accepted {
    var sa: SockAddr = .{};
    if (builtin.os.tag == .windows) {
        var len: c_int = @sizeOf(std.c.sockaddr.storage);
        const s = win32.accept(listener, &sa.storage, &len);
        if (@intFromPtr(s) == win32.INVALID_SOCKET) return lastError();
        return .{ .sock = s, .addr = sa.toIp() };
    }
    while (true) {
        var len: posix.socklen_t = @sizeOf(std.c.sockaddr.storage);
        const rc = posix.system.accept(listener, @ptrCast(&sa.storage), &len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const fd: socket_t = @intCast(rc);
                setCloexec(fd);
                return .{ .sock = fd, .addr = sa.toIp() };
            },
            .INTR, .CONNABORTED => continue,
            else => |e| return posixError(e),
        }
    }
}

fn connectTo(sock: socket_t, sa: *const SockAddr) SocketError!void {
    if (builtin.os.tag == .windows) {
        if (win32.connect(sock, &sa.storage, @intCast(sa.len)) != 0) return lastError();
        return;
    }
    while (true) {
        switch (posix.errno(posix.system.connect(sock, @ptrCast(&sa.storage), sa.len))) {
            .SUCCESS => return,
            .INTR => continue,
            else => |e| return posixError(e),
        }
    }
}

/// Open a TCP connection to an IP address (blocking).
pub fn tcpConnect(ip: Ip) SocketError!socket_t {
    const sock = try openSocket(family(ip), posix.SOCK.STREAM);
    errdefer closeSocket(sock);
    try connectTo(sock, &.from(ip));
    return sock;
}

/// Resolve `host` and connect to the first address that accepts (blocking).
/// Needs libc on POSIX (getaddrinfo); only the proxy, which links libc, uses it.
pub fn tcpConnectHost(host: []const u8, port: u16) SocketError!socket_t {
    var host_buf: [256]u8 = undefined;
    if (host.len >= host_buf.len) return error.UnknownHostName;
    @memcpy(host_buf[0..host.len], host);
    host_buf[host.len] = 0;
    const host_z: [*:0]const u8 = @ptrCast(&host_buf);

    const Ai = if (builtin.os.tag == .windows) win32.ADDRINFOA else std.c.addrinfo;
    var hints = std.mem.zeroes(Ai);
    hints.socktype = posix.SOCK.STREAM;
    var res: ?*Ai = null;
    const rc = if (builtin.os.tag == .windows)
        win32.getaddrinfo(host_z, null, &hints, &res)
    else
        @intFromEnum(std.c.getaddrinfo(host_z, null, &hints, &res));
    if (rc != 0) return error.UnknownHostName;
    const list = res orelse return error.UnknownHostName;
    defer if (builtin.os.tag == .windows) win32.freeaddrinfo(list) else std.c.freeaddrinfo(list);

    var last_err: SocketError = error.UnknownHostName;
    var it: ?*Ai = list;
    while (it) |ai| : (it = ai.next) {
        const raw = ai.addr orelse continue;
        if (raw.family != std.c.AF.INET and raw.family != std.c.AF.INET6) continue;
        var ip = SockAddr.fromRaw(raw);
        switch (ip) {
            .ip4 => |*a| a.port = port,
            .ip6 => |*a| a.port = port,
        }
        return tcpConnect(ip) catch |e| {
            last_err = e;
            continue;
        };
    }
    return last_err;
}

pub const Datagram = struct { data: []u8, from: Ip };

/// Receive one datagram into `buf` (blocking).
pub fn recvFrom(sock: socket_t, buf: []u8) SocketError!Datagram {
    var sa: SockAddr = .{};
    if (builtin.os.tag == .windows) {
        var len: c_int = @sizeOf(std.c.sockaddr.storage);
        const rc = win32.recvfrom(sock, buf.ptr, @intCast(buf.len), 0, &sa.storage, &len);
        if (rc == win32.SOCKET_ERROR) return lastError();
        return .{ .data = buf[0..@intCast(rc)], .from = sa.toIp() };
    }
    while (true) {
        var len: posix.socklen_t = @sizeOf(std.c.sockaddr.storage);
        const rc = posix.system.recvfrom(sock, buf.ptr, buf.len, 0, @ptrCast(&sa.storage), &len);
        switch (posix.errno(rc)) {
            .SUCCESS => return .{ .data = buf[0..@intCast(rc)], .from = sa.toIp() },
            .INTR => continue,
            else => |e| return posixError(e),
        }
    }
}

/// Send one datagram to `to`.
pub fn sendTo(sock: socket_t, to: Ip, data: []const u8) SocketError!void {
    const sa: SockAddr = .from(to);
    if (builtin.os.tag == .windows) {
        if (win32.sendto(sock, data.ptr, @intCast(data.len), 0, &sa.storage, @intCast(sa.len)) == win32.SOCKET_ERROR) return lastError();
        return;
    }
    while (true) {
        const rc = posix.system.sendto(sock, data.ptr, data.len, 0, @ptrCast(&sa.storage), sa.len);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => |e| return posixError(e),
        }
    }
}

/// Get an environment variable via the C runtime (we always link libc).
pub fn getenv(comptime name: [:0]const u8) ?[]const u8 {
    const result = std.c.getenv(name) orelse return null;
    return std.mem.sliceTo(result, 0);
}

const Ip = std.Io.net.IpAddress;

test "udpBind, sendTo, poll and recvFrom round-trip a datagram" {
    const addr = try Ip.parseIp4("127.0.0.1", 53536);
    const sock = try udpBind(addr);
    defer closeSocket(sock);

    var fds = [1]pollfd{.{ .fd = sock, .events = POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 0), try poll(&fds, 0));

    try sendTo(sock, addr, "ping");
    fds[0].revents = 0;
    try std.testing.expectEqual(@as(usize, 1), try poll(&fds, 1000));
    try std.testing.expect(fds[0].revents & POLL.IN != 0);

    var buf: [16]u8 = undefined;
    const msg = try recvFrom(sock, &buf);
    try std.testing.expectEqualStrings("ping", msg.data);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, msg.from.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 53536), msg.from.ip4.port);
}

test "udpBind reports AddressInUse when the port is taken" {
    const addr = try Ip.parseIp4("127.0.0.1", 53537);
    const first = try udpBind(addr);
    defer closeSocket(first);
    try std.testing.expectError(error.AddressInUse, udpBind(addr));
}

test "tcpListen reports AddressInUse when another process holds the port" {
    // The other process binds without address reuse; zlodev's listen uses it.
    const addr = try Ip.parseIp4("127.0.0.1", 18081);
    const other = try listenTcp(addr, false);
    defer closeSocket(other);
    try std.testing.expectError(error.AddressInUse, tcpListen(addr));
}

test "tcpConnect and accept exchange bytes and report the peer address" {
    const addr = try Ip.parseIp4("127.0.0.1", 18082);
    const listener = try tcpListen(addr);
    defer closeSocket(listener);

    const client = try tcpConnect(addr);
    defer closeSocket(client);
    const conn = try accept(listener);
    defer closeSocket(conn.sock);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, conn.addr.ip4.bytes);

    try (SocketStream{ .handle = client }).writeAll("hello");
    var buf: [8]u8 = undefined;
    const n = try (SocketStream{ .handle = conn.sock }).read(&buf);
    try std.testing.expectEqualStrings("hello", buf[0..n]);
}

test "tcpConnect reports ConnectionRefused when nothing listens" {
    const addr = try Ip.parseIp4("127.0.0.1", 18083);
    try std.testing.expectError(error.ConnectionRefused, tcpConnect(addr));
}

test "sockets are close-on-exec so the dev server doesn't inherit them" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const sock = try tcpListen(try Ip.parseIp4("127.0.0.1", 18084));
    defer closeSocket(sock);
    const fd_flags = posix.system.fcntl(sock, posix.F.GETFD, @as(usize, 0));
    try std.testing.expect(fd_flags & posix.FD_CLOEXEC != 0);
}
