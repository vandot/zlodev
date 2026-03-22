const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const socket_t = posix.socket_t;

/// Close a raw socket (not a std.net.Stream).
/// On Windows uses closesocket, on POSIX uses close.
pub fn closeSocket(sock: socket_t) void {
    if (builtin.os.tag == .windows) {
        std.os.windows.closesocket(sock) catch {};
    } else {
        posix.close(sock);
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

/// Initialize Winsock. Must be called before any socket operations on Windows.
/// No-op on other platforms.
pub fn initNetworking() void {
    if (builtin.os.tag == .windows) {
        var wsa_data: std.os.windows.ws2_32.WSADATA = undefined;
        _ = std.os.windows.ws2_32.WSAStartup(0x0202, &wsa_data);
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
/// on Windows and delegates to the standard Stream on POSIX.
pub const SocketStream = struct {
    handle: socket_t,

    pub fn read(self: SocketStream, buf: []u8) !usize {
        if (builtin.os.tag == .windows) {
            const ws2 = std.os.windows.ws2_32;
            const rc = ws2.recv(self.handle, @ptrCast(buf.ptr), @intCast(buf.len), 0);
            if (rc == ws2.SOCKET_ERROR) return error.Unexpected;
            return @intCast(rc);
        }
        return posix.read(self.handle, buf);
    }

    pub fn writeAll(self: SocketStream, data: []const u8) !void {
        if (builtin.os.tag == .windows) {
            const ws2 = std.os.windows.ws2_32;
            var written: usize = 0;
            while (written < data.len) {
                const rc = ws2.send(self.handle, @ptrCast(data[written..].ptr), @intCast(data.len - written), 0);
                if (rc == ws2.SOCKET_ERROR) return error.Unexpected;
                written += @intCast(rc);
            }
        } else {
            const stream = std.net.Stream{ .handle = self.handle };
            return stream.writeAll(data);
        }
    }

    pub fn close(self: SocketStream) void {
        closeSocket(self.handle);
    }
};

/// Get an environment variable, cross-platform.
/// On Windows, uses C runtime getenv via libc. On POSIX, uses posix.getenv.
pub fn getenv(comptime name: [:0]const u8) ?[]const u8 {
    if (builtin.os.tag == .windows) {
        const result = std.c.getenv(name);
        if (result) |ptr| {
            return std.mem.sliceTo(ptr, 0);
        }
        return null;
    }
    return posix.getenv(name);
}
