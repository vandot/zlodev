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
        _ = std.c.close(sock);
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
                const rc = std.c.write(self.handle, data[written..].ptr, data.len - written);
                if (rc < 0) return error.Unexpected;
                written += @intCast(rc);
            }
        }
    }

    pub fn close(self: SocketStream) void {
        closeSocket(self.handle);
    }
};

/// Get an environment variable via the C runtime (we always link libc).
pub fn getenv(comptime name: [:0]const u8) ?[]const u8 {
    const result = std.c.getenv(name) orelse return null;
    return std.mem.sliceTo(result, 0);
}

test "poll reports a readable UDP socket and times out on an idle one" {
    const io = @import("rt.zig").io();
    const addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 53536);
    const sock = try addr.bind(io, .{ .mode = .dgram });
    defer sock.close(io);

    var fds = [1]pollfd{.{ .fd = sock.handle, .events = POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 0), try poll(&fds, 0));

    try sock.send(io, &addr, "ping");
    fds[0].revents = 0;
    try std.testing.expectEqual(@as(usize, 1), try poll(&fds, 1000));
    try std.testing.expect(fds[0].revents & POLL.IN != 0);
}
