const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const binary_path = switch (builtin.os.tag) {
    .windows => "zig-out\\bin\\zlodev.exe",
    else => "zig-out/bin/zlodev",
};

fn runCmd(argv: []const []const u8) !std.process.Child.Term {
    var child = std.process.Child.init(argv, testing.allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    try child.spawn();
    return child.wait();
}

fn runCmdExpectSuccess(argv: []const []const u8) !void {
    const term = try runCmd(argv);
    try testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, term);
}

fn fileExists(path: []const u8) bool {
    if (std.fs.path.isAbsolute(path)) {
        std.fs.accessAbsolute(path, .{}) catch return false;
    } else {
        std.fs.cwd().access(path, .{}) catch return false;
    }
    return true;
}

fn getCertDir(buf: []u8, domain: []const u8) ![]const u8 {
    switch (builtin.os.tag) {
        .macos => {
            const home = std.posix.getenv("HOME") orelse return error.NoHomeDir;
            return std.fmt.bufPrint(buf, "{s}/Library/Application Support/zlodev/{s}", .{ home, domain });
        },
        .windows => {
            const local = std.posix.getenv("LocalAppData") orelse return error.NoLocalAppData;
            return std.fmt.bufPrint(buf, "{s}/zlodev/{s}", .{ local, domain });
        },
        else => {
            if (std.posix.getenv("XDG_DATA_HOME")) |xdg| {
                return std.fmt.bufPrint(buf, "{s}/zlodev/{s}", .{ xdg, domain });
            }
            const home = std.posix.getenv("HOME") orelse return error.NoHomeDir;
            return std.fmt.bufPrint(buf, "{s}/.local/share/zlodev/{s}", .{ home, domain });
        },
    }
}

fn getHostname(buf: *[std.posix.HOST_NAME_MAX]u8) []const u8 {
    const hostname = std.posix.gethostname(buf) catch return "unknown";
    // Strip .local suffix if present (macOS reports FQDN)
    if (std.mem.endsWith(u8, hostname, ".local")) {
        return hostname[0 .. hostname.len - 6];
    }
    return hostname;
}

fn verifyCertFiles(domain: []const u8) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const cert_dir = try getCertDir(&buf, domain);

    var ca_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ca_path = try std.fmt.bufPrint(&ca_buf, "{s}/zlodevCA.pem", .{cert_dir});
    try testing.expect(fileExists(ca_path));

    var cert_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cert_path = try std.fmt.bufPrint(&cert_buf, "{s}/zlodev.crt", .{cert_dir});
    try testing.expect(fileExists(cert_path));

    var key_buf: [std.fs.max_path_bytes]u8 = undefined;
    const key_path = try std.fmt.bufPrint(&key_buf, "{s}/zlodev.key", .{cert_dir});
    try testing.expect(fileExists(key_path));

    var der_buf: [std.fs.max_path_bytes]u8 = undefined;
    const der_path = try std.fmt.bufPrint(&der_buf, "{s}/zlodevCA.der", .{cert_dir});
    try testing.expect(fileExists(der_path));
}

fn verifyCertDirRemoved(domain: []const u8) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const cert_dir = try getCertDir(&buf, domain);
    try testing.expect(!fileExists(cert_dir));
}

// --- Default mode (dev.lo) ---

test "install and verify" {
    try testing.expect(fileExists(binary_path));

    try runCmdExpectSuccess(&.{ binary_path, "install" });
    try verifyCertFiles("dev.lo");

    switch (builtin.os.tag) {
        .macos => {
            try testing.expect(fileExists("/etc/resolver/lo"));
            try runCmdExpectSuccess(&.{ "security", "find-certificate", "-c", "dev.lo CA", "/Library/Keychains/System.keychain" });
        },
        .linux => {
            try testing.expect(fileExists("/etc/systemd/network/zlodev0.network"));
            try testing.expect(fileExists("/etc/systemd/network/zlodev0.netdev"));
            const found = fileExists("/usr/local/share/ca-certificates/zlodevCA.crt") or
                fileExists("/etc/pki/ca-trust/source/anchors/zlodevCA.pem") or
                fileExists("/etc/ca-certificates/trust-source/anchors/zlodevCA.crt") or
                fileExists("/usr/share/pki/trust/anchors/zlodevCA.pem");
            try testing.expect(found);
        },
        .windows => {
            try runCmdExpectSuccess(&.{ "Powershell.exe", "-Command", "if (!(Get-DnsClientNrptRule | Where { $_.Namespace -eq '.lo' })) { exit 1 }" });
            try runCmdExpectSuccess(&.{ "Powershell.exe", "-Command", "if (!(Get-ChildItem Cert:\\LocalMachine\\Root | Where { $_.Subject -match 'zlodev' })) { exit 1 }" });
        },
        else => {},
    }
}

test "install -f succeeds when already installed" {
    try runCmdExpectSuccess(&.{ binary_path, "install", "-f" });
    try verifyCertFiles("dev.lo");
}

test "uninstall and verify" {
    try runCmdExpectSuccess(&.{ binary_path, "uninstall" });
    try verifyCertDirRemoved("dev.lo");

    switch (builtin.os.tag) {
        .macos => {
            try testing.expect(!fileExists("/etc/resolver/lo"));
            const term = try runCmd(&.{ "security", "find-certificate", "-c", "dev.lo CA", "/Library/Keychains/System.keychain" });
            try testing.expect(!std.meta.eql(term, std.process.Child.Term{ .Exited = 0 }));
        },
        .linux => {
            try testing.expect(!fileExists("/etc/systemd/network/zlodev0.network"));
            try testing.expect(!fileExists("/etc/systemd/network/zlodev0.netdev"));
            const found = fileExists("/usr/local/share/ca-certificates/zlodevCA.crt") or
                fileExists("/etc/pki/ca-trust/source/anchors/zlodevCA.pem") or
                fileExists("/etc/ca-certificates/trust-source/anchors/zlodevCA.crt") or
                fileExists("/usr/share/pki/trust/anchors/zlodevCA.pem");
            try testing.expect(!found);
        },
        .windows => {
            try runCmdExpectSuccess(&.{ "Powershell.exe", "-Command", "if (Get-DnsClientNrptRule | Where { $_.Namespace -eq '.lo' }) { exit 1 }" });
            try runCmdExpectSuccess(&.{ "Powershell.exe", "-Command", "if (Get-ChildItem Cert:\\LocalMachine\\Root | Where { $_.Subject -match 'zlodev' }) { exit 1 }" });
        },
        else => {},
    }
}

// --- Local mode (hostname.local) ---

test "install --local and verify" {
    var hostname_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const hostname = getHostname(&hostname_buf);
    var domain_buf: [512]u8 = undefined;
    const domain = try std.fmt.bufPrint(&domain_buf, "{s}.local", .{hostname});
    var cn_buf: [512]u8 = undefined;
    const cn = try std.fmt.bufPrint(&cn_buf, "{s} CA", .{domain});

    try runCmdExpectSuccess(&.{ binary_path, "install", "-l" });
    try verifyCertFiles(domain);

    // Local mode: no DNS installed (mDNS handles it)
    switch (builtin.os.tag) {
        .macos => {
            try runCmdExpectSuccess(&.{ "security", "find-certificate", "-c", cn, "/Library/Keychains/System.keychain" });
        },
        .linux => {
            const found = fileExists("/usr/local/share/ca-certificates/zlodevCA.crt") or
                fileExists("/etc/pki/ca-trust/source/anchors/zlodevCA.pem") or
                fileExists("/etc/ca-certificates/trust-source/anchors/zlodevCA.crt") or
                fileExists("/usr/share/pki/trust/anchors/zlodevCA.pem");
            try testing.expect(found);
        },
        .windows => {
            try runCmdExpectSuccess(&.{ "Powershell.exe", "-Command", "if (!(Get-ChildItem Cert:\\LocalMachine\\Root | Where { $_.Subject -match 'zlodev' })) { exit 1 }" });
        },
        else => {},
    }
}

test "install --local -f succeeds when already installed" {
    var hostname_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const hostname = getHostname(&hostname_buf);
    var domain_buf: [512]u8 = undefined;
    const domain = try std.fmt.bufPrint(&domain_buf, "{s}.local", .{hostname});

    try runCmdExpectSuccess(&.{ binary_path, "install", "-l", "-f" });
    try verifyCertFiles(domain);
}

test "uninstall --local and verify" {
    var hostname_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const hostname = getHostname(&hostname_buf);
    var domain_buf: [512]u8 = undefined;
    const domain = try std.fmt.bufPrint(&domain_buf, "{s}.local", .{hostname});
    var cn_buf: [512]u8 = undefined;
    const cn = try std.fmt.bufPrint(&cn_buf, "{s} CA", .{domain});

    try runCmdExpectSuccess(&.{ binary_path, "uninstall", "-l" });
    try verifyCertDirRemoved(domain);

    switch (builtin.os.tag) {
        .macos => {
            const term = try runCmd(&.{ "security", "find-certificate", "-c", cn, "/Library/Keychains/System.keychain" });
            try testing.expect(!std.meta.eql(term, std.process.Child.Term{ .Exited = 0 }));
        },
        .linux => {
            const found = fileExists("/usr/local/share/ca-certificates/zlodevCA.crt") or
                fileExists("/etc/pki/ca-trust/source/anchors/zlodevCA.pem") or
                fileExists("/etc/ca-certificates/trust-source/anchors/zlodevCA.crt") or
                fileExists("/usr/share/pki/trust/anchors/zlodevCA.pem");
            try testing.expect(!found);
        },
        .windows => {
            try runCmdExpectSuccess(&.{ "Powershell.exe", "-Command", "if (Get-ChildItem Cert:\\LocalMachine\\Root | Where { $_.Subject -match 'zlodev' }) { exit 1 }" });
        },
        else => {},
    }
}
