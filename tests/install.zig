const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const binary_path = switch (builtin.os.tag) {
    .windows => "zig-out\\bin\\zlodev.exe",
    else => "zig-out/bin/zlodev",
};

const hostname_max = if (builtin.os.tag == .windows) 256 else std.posix.HOST_NAME_MAX;

fn runCmd(argv: []const []const u8) !std.process.Child.Term {
    var child = try std.process.spawn(testing.io, .{ .argv = argv, .stdin = .ignore });
    return child.wait(testing.io);
}

fn runCmdExpectSuccess(argv: []const []const u8) !void {
    const term = try runCmd(argv);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

fn fileExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(testing.io, path, .{}) catch return false;
    return true;
}

fn getEnvOwned(name: []const u8) ?[]const u8 {
    return testing.environ.getAlloc(testing.allocator, name) catch return null;
}

fn getCertDir(buf: []u8, domain: []const u8) ![]const u8 {
    switch (builtin.os.tag) {
        .macos => {
            const home = getEnvOwned("HOME") orelse return error.NoHomeDir;
            defer testing.allocator.free(home);
            return std.fmt.bufPrint(buf, "{s}/Library/Application Support/zlodev/{s}", .{ home, domain });
        },
        .windows => {
            const local = getEnvOwned("LocalAppData") orelse return error.NoLocalAppData;
            defer testing.allocator.free(local);
            return std.fmt.bufPrint(buf, "{s}/zlodev/{s}", .{ local, domain });
        },
        else => {
            if (getEnvOwned("XDG_DATA_HOME")) |xdg| {
                defer testing.allocator.free(xdg);
                return std.fmt.bufPrint(buf, "{s}/zlodev/{s}", .{ xdg, domain });
            }
            const home = getEnvOwned("HOME") orelse return error.NoHomeDir;
            defer testing.allocator.free(home);
            return std.fmt.bufPrint(buf, "{s}/.local/share/zlodev/{s}", .{ home, domain });
        },
    }
}

fn getHostname(buf: *[hostname_max]u8) []const u8 {
    if (builtin.os.tag == .windows) {
        const name = getEnvOwned("COMPUTERNAME") orelse return "localhost";
        defer testing.allocator.free(name);
        const len = @min(name.len, buf.len);
        @memcpy(buf[0..len], name[0..len]);
        return buf[0..len];
    }
    const hostname = std.posix.gethostname(buf) catch return "unknown";
    if (std.mem.endsWith(u8, hostname, ".local")) {
        return hostname[0 .. hostname.len - 6];
    }
    return hostname;
}

fn verifyCertFiles(domain: []const u8) !void {
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const cert_dir = try getCertDir(&buf, domain);

    var ca_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const ca_path = try std.fmt.bufPrint(&ca_buf, "{s}/zlodevCA.pem", .{cert_dir});
    try testing.expect(fileExists(ca_path));

    var cert_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const cert_path = try std.fmt.bufPrint(&cert_buf, "{s}/zlodev.crt", .{cert_dir});
    try testing.expect(fileExists(cert_path));

    var key_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const key_path = try std.fmt.bufPrint(&key_buf, "{s}/zlodev.key", .{cert_dir});
    try testing.expect(fileExists(key_path));

    var der_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const der_path = try std.fmt.bufPrint(&der_buf, "{s}/zlodevCA.der", .{cert_dir});
    try testing.expect(fileExists(der_path));
}

fn verifyCertDirRemoved(domain: []const u8) !void {
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const cert_dir = try getCertDir(&buf, domain);
    try testing.expect(!fileExists(cert_dir));
}

const linux_anchor_dirs = [_]struct { dir: []const u8, ext: []const u8 }{
    .{ .dir = "/etc/pki/ca-trust/source/anchors", .ext = "pem" },
    .{ .dir = "/usr/local/share/ca-certificates", .ext = "crt" },
    .{ .dir = "/etc/ca-certificates/trust-source/anchors", .ext = "crt" },
    .{ .dir = "/usr/share/pki/trust/anchors", .ext = "pem" },
};

/// True when the per-domain system trust anchor exists in any distro's anchor dir.
fn anchorExists(domain: []const u8) bool {
    for (linux_anchor_dirs) |a| {
        var buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}/zlodevCA-{s}.{s}", .{ a.dir, domain, a.ext }) catch continue;
        if (fileExists(path)) return true;
    }
    return false;
}

const fake_firefox_profile = ".mozilla/firefox/zlodevtest.default";

fn homePath(buf: []u8, rel: []const u8) ![]const u8 {
    const home = getEnvOwned("HOME") orelse return error.NoHomeDir;
    defer testing.allocator.free(home);
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ home, rel });
}

/// True when `certutil -L` finds the domain's CA in the NSS database at `rel` under $HOME.
fn nssHas(rel: []const u8, domain: []const u8) bool {
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = homePath(&dir_buf, rel) catch return false;
    var arg_buf: [std.Io.Dir.max_path_bytes + 4]u8 = undefined;
    const db_arg = std.fmt.bufPrint(&arg_buf, "sql:{s}", .{dir}) catch return false;
    var nick_buf: [512]u8 = undefined;
    const nick = std.fmt.bufPrint(&nick_buf, "zlodev {s} CA", .{domain}) catch return false;
    const term = runCmd(&.{ "certutil", "-L", "-d", db_arg, "-n", nick }) catch return false;
    return std.meta.eql(term, std.process.Child.Term{ .exited = 0 });
}

/// A Firefox profile with an empty NSS database, so install has one to find.
fn createFakeFirefoxProfile() !void {
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = try homePath(&dir_buf, fake_firefox_profile);
    var db_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (fileExists(try std.fmt.bufPrint(&db_buf, "{s}/cert9.db", .{dir}))) return;
    try std.Io.Dir.cwd().createDirPath(testing.io, dir);
    var arg_buf: [std.Io.Dir.max_path_bytes + 4]u8 = undefined;
    try runCmdExpectSuccess(&.{ "certutil", "-N", "--empty-password", "-d", try std.fmt.bufPrint(&arg_buf, "sql:{s}", .{dir}) });
}

// --- Default mode (dev.lo) ---

test "install and verify" {
    try testing.expect(fileExists(binary_path));

    if (builtin.os.tag == .linux) try createFakeFirefoxProfile();
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
            try testing.expect(anchorExists("dev.lo"));
            try testing.expect(nssHas(".pki/nssdb", "dev.lo"));
            try testing.expect(nssHas(fake_firefox_profile, "dev.lo"));
        },
        .windows => {
            try runCmdExpectSuccess(&.{ "Powershell.exe", "-Command", "if (!(Get-DnsClientNrptRule | Where { $_.Namespace -eq '.lo' })) { exit 1 }" });
            try runCmdExpectSuccess(&.{ "certutil", "-verifystore", "Root", "dev.lo CA" });
        },
        else => {},
    }
}

test "install -f succeeds when already installed" {
    try runCmdExpectSuccess(&.{ binary_path, "install", "-f" });
    try verifyCertFiles("dev.lo");
    if (builtin.os.tag == .linux) {
        try testing.expect(anchorExists("dev.lo"));
        try testing.expect(nssHas(".pki/nssdb", "dev.lo"));
    }
}

test "uninstall and verify" {
    try runCmdExpectSuccess(&.{ binary_path, "uninstall" });
    try verifyCertDirRemoved("dev.lo");

    switch (builtin.os.tag) {
        .macos => {
            try testing.expect(!fileExists("/etc/resolver/lo"));
            const term = try runCmd(&.{ "security", "find-certificate", "-c", "dev.lo CA", "/Library/Keychains/System.keychain" });
            try testing.expect(!std.meta.eql(term, std.process.Child.Term{ .exited = 0 }));
        },
        .linux => {
            try testing.expect(!fileExists("/etc/systemd/network/zlodev0.network"));
            try testing.expect(!fileExists("/etc/systemd/network/zlodev0.netdev"));
            try testing.expect(!anchorExists("dev.lo"));
            try testing.expect(!nssHas(".pki/nssdb", "dev.lo"));
            try testing.expect(!nssHas(fake_firefox_profile, "dev.lo"));
        },
        .windows => {
            try runCmdExpectSuccess(&.{ "Powershell.exe", "-Command", "if (Get-DnsClientNrptRule | Where { $_.Namespace -eq '.lo' }) { exit 1 }" });
            // certutil -verifystore should fail when cert is removed
            const term_w = try runCmd(&.{ "certutil", "-verifystore", "Root", "dev.lo CA" });
            try testing.expect(!std.meta.eql(term_w, std.process.Child.Term{ .exited = 0 }));
        },
        else => {},
    }
}

// --- Local mode (hostname.local) ---

test "install --local and verify" {
    // On Linux, systemd-resolved may have died during the previous uninstall test.
    // Reset failed state, reload networkd first (resolved depends on it), then restart resolved.
    // Reload, not restart: restarting networkd reconfigures the runner's real interface.
    if (builtin.os.tag == .linux) {
        _ = runCmd(&.{ "sudo", "systemctl", "reset-failed", "systemd-resolved.service" }) catch {};
        _ = runCmd(&.{ "sudo", "systemctl", "reset-failed", "systemd-networkd.service" }) catch {};
        _ = runCmd(&.{ "sudo", "networkctl", "reload" }) catch {};
        _ = runCmd(&.{ "sudo", "systemctl", "restart", "systemd-resolved.service" }) catch {};
        testing.io.sleep(.fromSeconds(2), .awake) catch {};
    }
    var hostname_buf: [hostname_max]u8 = undefined;
    const hostname = getHostname(&hostname_buf);
    var domain_buf: [512]u8 = undefined;
    const domain = try std.fmt.bufPrint(&domain_buf, "{s}.local", .{hostname});
    var cn_buf: [512]u8 = undefined;
    const cn_full = try std.fmt.bufPrint(&cn_buf, "{s} CA", .{domain});
    const cn = if (cn_full.len > 64) cn_full[0..64] else cn_full;

    try runCmdExpectSuccess(&.{ binary_path, "install", "-l" });
    try verifyCertFiles(domain);

    switch (builtin.os.tag) {
        .macos => {
            try runCmdExpectSuccess(&.{ "security", "find-certificate", "-c", cn, "/Library/Keychains/System.keychain" });
        },
        .linux => {
            try testing.expect(anchorExists(domain));
            try testing.expect(nssHas(".pki/nssdb", domain));
        },
        .windows => {
            try runCmdExpectSuccess(&.{ "certutil", "-verifystore", "Root", cn });
        },
        else => {},
    }
}

test "install --local -f succeeds when already installed" {
    var hostname_buf: [hostname_max]u8 = undefined;
    const hostname = getHostname(&hostname_buf);
    var domain_buf: [512]u8 = undefined;
    const domain = try std.fmt.bufPrint(&domain_buf, "{s}.local", .{hostname});

    try runCmdExpectSuccess(&.{ binary_path, "install", "-l", "-f" });
    try verifyCertFiles(domain);
}

test "uninstall --local and verify" {
    var hostname_buf: [hostname_max]u8 = undefined;
    const hostname = getHostname(&hostname_buf);
    var domain_buf: [512]u8 = undefined;
    const domain = try std.fmt.bufPrint(&domain_buf, "{s}.local", .{hostname});
    var cn_buf: [512]u8 = undefined;
    const cn_full = try std.fmt.bufPrint(&cn_buf, "{s} CA", .{domain});
    const cn = if (cn_full.len > 64) cn_full[0..64] else cn_full;

    try runCmdExpectSuccess(&.{ binary_path, "uninstall", "-l" });
    try verifyCertDirRemoved(domain);

    switch (builtin.os.tag) {
        .macos => {
            const term = try runCmd(&.{ "security", "find-certificate", "-c", cn, "/Library/Keychains/System.keychain" });
            try testing.expect(!std.meta.eql(term, std.process.Child.Term{ .exited = 0 }));
        },
        .linux => {
            try testing.expect(!anchorExists(domain));
            try testing.expect(!nssHas(".pki/nssdb", domain));
        },
        .windows => {
            const term_wl = try runCmd(&.{ "certutil", "-verifystore", "Root", cn });
            try testing.expect(!std.meta.eql(term_wl, std.process.Child.Term{ .exited = 0 }));
        },
        else => {},
    }
}
