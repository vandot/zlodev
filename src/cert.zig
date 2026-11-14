const std = @import("std");
const sep = std.fs.path.sep_str;
const builtin = @import("builtin");
const log = @import("log.zig");
const sys = @import("sys.zig");
const compat = @import("compat.zig");
const rt = @import("rt.zig");

const c = @import("cert_c");

pub fn getBasePath(buf: []u8) ![]const u8 {
    switch (builtin.os.tag) {
        .macos => {
            const home = compat.getenv("HOME") orelse return error.NoHomeDir;
            return std.fmt.bufPrint(buf, "{s}" ++ sep ++ "Library/Application Support/zlodev", .{home});
        },
        .windows => {
            const local_env = compat.getenv("LocalAppData") orelse return error.NoLocalAppData;
            return std.fmt.bufPrint(buf, "{s}" ++ sep ++ "zlodev", .{local_env});
        },
        else => {
            // Linux
            const xdg = compat.getenv("XDG_DATA_HOME");
            if (xdg) |data_home| {
                return std.fmt.bufPrint(buf, "{s}" ++ sep ++ "zlodev", .{data_home});
            }
            const home = compat.getenv("HOME") orelse return error.NoHomeDir;
            return std.fmt.bufPrint(buf, "{s}" ++ sep ++ ".local/share/zlodev", .{home});
        },
    }
}

pub fn getCertPath(buf: []u8, domain: []const u8) ![]const u8 {
    var base_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const base = try getBasePath(&base_buf);
    return std.fmt.bufPrint(buf, "{s}" ++ sep ++ "{s}", .{ base, domain });
}

pub fn getCert(cert_buf: []u8, key_buf: []u8, domain: []const u8) !struct { cert: []const u8, key: []const u8 } {
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = try getCertPath(&path_buf, domain);
    const cert_path = try std.fmt.bufPrint(cert_buf, "{s}" ++ sep ++ "zlodev.crt", .{dir});
    const key = try std.fmt.bufPrint(key_buf, "{s}" ++ sep ++ "zlodev.key", .{dir});

    // Check if files exist
    std.Io.Dir.accessAbsolute(rt.io(), cert_path, .{}) catch return error.CertNotFound;
    std.Io.Dir.accessAbsolute(rt.io(), key, .{}) catch return error.KeyNotFound;

    return .{ .cert = cert_path, .key = key };
}

pub fn caExists(domain: []const u8) bool {
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = getCertPath(&path_buf, domain) catch return false;
    var ca_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const ca_path = std.fmt.bufPrint(&ca_buf, "{s}" ++ sep ++ "zlodevCA.pem", .{dir}) catch return false;
    std.Io.Dir.accessAbsolute(rt.io(), ca_path, .{}) catch return false;
    return true;
}

pub fn getCaPath(buf: []u8, domain: []const u8) ![]const u8 {
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = try getCertPath(&path_buf, domain);
    return std.fmt.bufPrint(buf, "{s}" ++ sep ++ "zlodevCA.pem", .{dir});
}

pub fn getCaDerPath(buf: []u8, domain: []const u8) ![]const u8 {
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = try getCertPath(&path_buf, domain);
    return std.fmt.bufPrint(buf, "{s}" ++ sep ++ "zlodevCA.der", .{dir});
}

// --- OpenSSL C API helpers ---

fn generateRsaKey() !*c.EVP_PKEY {
    const ctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse return error.KeyGenFailed;
    defer c.EVP_PKEY_CTX_free(ctx);

    if (c.EVP_PKEY_keygen_init(ctx) != 1) return error.KeyGenFailed;

    if (c.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) != 1)
        return error.KeyGenFailed;

    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_keygen(ctx, &pkey) != 1) return error.KeyGenFailed;

    return pkey orelse error.KeyGenFailed;
}

/// Write a private key readable only by the owner. The PEM is built in memory so
/// the file is created 0600 rather than with the umask's 0644, and an existing
/// key from an older install is tightened before the new key is written into it.
fn writePemKey(path: [:0]const u8, pkey: *c.EVP_PKEY) !void {
    const bio = c.BIO_new(c.BIO_s_mem()) orelse return error.FileWriteFailed;
    defer _ = c.BIO_free(bio);
    if (c.PEM_write_bio_PrivateKey(bio, pkey, null, null, 0, null, null) != 1)
        return error.FileWriteFailed;
    var pem_ptr: [*c]const u8 = undefined;
    var pem_len: usize = 0;
    if (c.BIO_mem_contents(bio, &pem_ptr, &pem_len) != 1) return error.FileWriteFailed;

    const io = rt.io();
    const owner_only: std.Io.File.Permissions = if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);
    const file = std.Io.Dir.cwd().createFile(io, path, .{ .permissions = owner_only }) catch return error.FileWriteFailed;
    defer file.close(io);
    if (builtin.os.tag != .windows) file.setPermissions(io, owner_only) catch return error.FileWriteFailed;
    file.writeStreamingAll(io, pem_ptr[0..pem_len]) catch return error.FileWriteFailed;
}

fn writePemCert(path: [:0]const u8, x509: *c.X509) !void {
    const bio = c.BIO_new_file(path.ptr, "w") orelse return error.FileWriteFailed;
    defer _ = c.BIO_free(bio);
    if (c.PEM_write_bio_X509(bio, x509) != 1)
        return error.FileWriteFailed;
}

fn writeDerCert(path: [:0]const u8, x509: *c.X509) !void {
    const bio = c.BIO_new_file(path.ptr, "w") orelse return error.FileWriteFailed;
    defer _ = c.BIO_free(bio);
    if (c.i2d_X509_bio(bio, x509) != 1)
        return error.FileWriteFailed;
}

fn addExtension(cert_x509: *c.X509, issuer: ?*c.X509, nid: c_int, value: [:0]const u8) !void {
    var ctx: c.X509V3_CTX = undefined;
    c.X509V3_set_ctx(&ctx, issuer orelse cert_x509, cert_x509, null, null, 0);
    ctx.db = null;

    const ext = c.X509V3_EXT_nconf_nid(null, &ctx, nid, value.ptr) orelse return error.ExtensionFailed;
    defer c.X509_EXTENSION_free(ext);
    if (c.X509_add_ext(cert_x509, ext, -1) != 1) return error.ExtensionFailed;
}

fn allocPrintZ(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) ![:0]u8 {
    const s = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(s);
    return try allocator.dupeSentinel(u8, s, 0);
}

fn setNameEntry(name: *c.X509_NAME, nid: c_int, value: []const u8) !void {
    if (c.X509_NAME_add_entry_by_NID(name, nid, c.MBSTRING_ASC, value.ptr, @intCast(value.len), -1, 0) != 1)
        return error.CertCreateFailed;
}

const day_s: i64 = 24 * 60 * 60;
const ca_days: i64 = 3650;
const leaf_days: i64 = 398;

const CertKey = struct {
    cert: *c.X509,
    key: *c.EVP_PKEY,

    fn deinit(self: CertKey) void {
        c.X509_free(self.cert);
        c.EVP_PKEY_free(self.key);
    }
};

fn setValidity(x509: *c.X509, not_before: i64, not_after: i64) !void {
    if (c.ASN1_TIME_set_posix(c.X509_getm_notBefore(x509), not_before) == null) return error.CertCreateFailed;
    if (c.ASN1_TIME_set_posix(c.X509_getm_notAfter(x509), not_after) == null) return error.CertCreateFailed;
}

fn setRandomSerial(x509: *c.X509) !void {
    const serial_bn = c.BN_new() orelse return error.CertCreateFailed;
    defer c.BN_free(serial_bn);
    if (c.BN_rand(serial_bn, 64, 0, 0) != 1) return error.CertCreateFailed;
    if (c.BN_to_ASN1_INTEGER(serial_bn, c.X509_get_serialNumber(x509)) == null) return error.CertCreateFailed;
}

fn notAfter(x509: *c.X509) !i64 {
    var t: i64 = 0;
    if (c.ASN1_TIME_to_posix(c.X509_get0_notAfter(x509), &t) != 1) return error.CertReadFailed;
    return t;
}

fn readPemCert(path: [:0]const u8) ?*c.X509 {
    const bio = c.BIO_new_file(path.ptr, "r") orelse return null;
    defer _ = c.BIO_free(bio);
    return c.PEM_read_bio_X509(bio, null, null, null);
}

fn readPemKey(path: [:0]const u8) ?*c.EVP_PKEY {
    const bio = c.BIO_new_file(path.ptr, "r") orelse return null;
    defer _ = c.BIO_free(bio);
    return c.PEM_read_bio_PrivateKey(bio, null, null, null);
}

fn buildCA(allocator: std.mem.Allocator, domain: []const u8, not_before: i64, not_after: i64) !CertKey {
    const ca_key = try generateRsaKey();
    errdefer c.EVP_PKEY_free(ca_key);
    const ca_cert = c.X509_new() orelse return error.CertCreateFailed;
    errdefer c.X509_free(ca_cert);

    if (c.X509_set_version(ca_cert, 2) != 1) return error.CertCreateFailed;
    try setRandomSerial(ca_cert);
    try setValidity(ca_cert, not_before, not_after);

    const name = c.X509_get_subject_name(ca_cert) orelse return error.CertCreateFailed;
    try setNameEntry(name, c.NID_countryName, "LO");
    try setNameEntry(name, c.NID_stateOrProvinceName, "Dev");
    try setNameEntry(name, c.NID_localityName, "Local");
    try setNameEntry(name, c.NID_organizationName, "zlodev");
    try setNameEntry(name, c.NID_organizationalUnitName, "CA");

    // CN = "{domain} CA" (truncated to 64 bytes — X.509 CN limit)
    const cn = try allocPrintZ(allocator, "{s} CA", .{domain});
    defer allocator.free(cn);
    const cn_truncated = if (cn.len > 64) cn[0..64] else @as([]const u8, cn);
    try setNameEntry(name, c.NID_commonName, cn_truncated);

    // Self-signed: issuer = subject
    if (c.X509_set_issuer_name(ca_cert, name) != 1) return error.CertCreateFailed;
    if (c.X509_set_pubkey(ca_cert, ca_key) != 1) return error.CertCreateFailed;

    try addExtension(ca_cert, null, c.NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
    try addExtension(ca_cert, null, c.NID_key_usage, "critical,keyCertSign");
    try addExtension(ca_cert, null, c.NID_subject_key_identifier, "hash");

    if (c.X509_sign(ca_cert, ca_key, c.EVP_sha256()) == 0) return error.SignFailed;
    return .{ .cert = ca_cert, .key = ca_key };
}

fn writeCA(allocator: std.mem.Allocator, cert_dir: []const u8, ca: CertKey) !void {
    const ca_pem_path = try allocPrintZ(allocator, "{s}" ++ sep ++ "zlodevCA.pem", .{cert_dir});
    defer allocator.free(ca_pem_path);
    const ca_key_path = try allocPrintZ(allocator, "{s}" ++ sep ++ "zlodevCA.key", .{cert_dir});
    defer allocator.free(ca_key_path);
    const ca_der_path = try allocPrintZ(allocator, "{s}" ++ sep ++ "zlodevCA.der", .{cert_dir});
    defer allocator.free(ca_der_path);

    try writePemCert(ca_pem_path, ca.cert);
    try writePemKey(ca_key_path, ca.key);
    try writeDerCert(ca_der_path, ca.cert);
}

fn buildCert(allocator: std.mem.Allocator, cn: []const u8, san: [:0]const u8, ca: CertKey, not_before: i64, not_after: i64) !CertKey {
    const key = try generateRsaKey();
    errdefer c.EVP_PKEY_free(key);
    const cert_x509 = c.X509_new() orelse return error.CertCreateFailed;
    errdefer c.X509_free(cert_x509);

    if (c.X509_set_version(cert_x509, 2) != 1) return error.CertCreateFailed;
    try setRandomSerial(cert_x509);
    try setValidity(cert_x509, not_before, not_after);

    const name = c.X509_get_subject_name(cert_x509) orelse return error.CertCreateFailed;
    try setNameEntry(name, c.NID_countryName, "LO");
    try setNameEntry(name, c.NID_stateOrProvinceName, "Dev");
    try setNameEntry(name, c.NID_localityName, "Local");
    try setNameEntry(name, c.NID_organizationName, "Dev");
    try setNameEntry(name, c.NID_organizationalUnitName, "Local");

    const cn_z = try allocPrintZ(allocator, "{s}", .{cn});
    defer allocator.free(cn_z);
    const cn_z_truncated = if (cn_z.len > 64) cn_z[0..64] else @as([]const u8, cn_z);
    try setNameEntry(name, c.NID_commonName, cn_z_truncated);

    const ca_subject = c.X509_get_subject_name(ca.cert) orelse return error.CertCreateFailed;
    if (c.X509_set_issuer_name(cert_x509, ca_subject) != 1) return error.CertCreateFailed;
    if (c.X509_set_pubkey(cert_x509, key) != 1) return error.CertCreateFailed;

    try addExtension(cert_x509, ca.cert, c.NID_authority_key_identifier, "keyid:always");
    try addExtension(cert_x509, ca.cert, c.NID_basic_constraints, "critical,CA:FALSE");
    try addExtension(cert_x509, ca.cert, c.NID_key_usage, "critical,digitalSignature,keyEncipherment");
    try addExtension(cert_x509, ca.cert, c.NID_ext_key_usage, "serverAuth");
    try addExtension(cert_x509, ca.cert, c.NID_subject_alt_name, san);

    if (c.X509_sign(cert_x509, ca.key, c.EVP_sha256()) == 0) return error.SignFailed;
    return .{ .cert = cert_x509, .key = key };
}

fn buildLeaf(allocator: std.mem.Allocator, domain: []const u8, ca: CertKey, not_before: i64, not_after: i64) !CertKey {
    const san = try allocPrintZ(allocator, "DNS:*.{s},DNS:{s}", .{ domain, domain });
    defer allocator.free(san);
    return buildCert(allocator, domain, san, ca, not_before, not_after);
}

/// Write the leaf next to the old one, then rename over it, so a failed write never
/// leaves a half-written cert. Key goes first: a crash between the renames leaves a
/// mismatched pair, which ensureLeafIn detects and renews on the next start.
fn writeLeaf(allocator: std.mem.Allocator, cert_dir: []const u8, leaf: CertKey) !void {
    const crt_path = try allocPrintZ(allocator, "{s}" ++ sep ++ "zlodev.crt", .{cert_dir});
    defer allocator.free(crt_path);
    const key_path = try allocPrintZ(allocator, "{s}" ++ sep ++ "zlodev.key", .{cert_dir});
    defer allocator.free(key_path);
    const crt_tmp = try allocPrintZ(allocator, "{s}" ++ sep ++ "zlodev.crt.tmp", .{cert_dir});
    defer allocator.free(crt_tmp);
    const key_tmp = try allocPrintZ(allocator, "{s}" ++ sep ++ "zlodev.key.tmp", .{cert_dir});
    defer allocator.free(key_tmp);

    const io = rt.io();
    const cwd = std.Io.Dir.cwd();
    errdefer cwd.deleteFile(io, crt_tmp) catch {};
    errdefer cwd.deleteFile(io, key_tmp) catch {};

    try writePemKey(key_tmp, leaf.key);
    try writePemCert(crt_tmp, leaf.cert);
    cwd.rename(key_tmp, cwd, key_path, io) catch return error.FileWriteFailed;
    cwd.rename(crt_tmp, cwd, crt_path, io) catch return error.FileWriteFailed;
}

/// Create the cert dir (and parents) and restrict it to the owner, including a
/// dir left 0755 by an older install. Windows relies on the user-profile ACL.
fn makePrivateDir(path: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(rt.io(), path);
    if (builtin.os.tag != .windows) try cwd.setFilePermissions(rt.io(), path, .fromMode(0o700), .{});
}

pub fn installCA(allocator: std.mem.Allocator, domain: []const u8) !void {
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const cert_dir = try getCertPath(&path_buf, domain);

    makePrivateDir(cert_dir) catch return error.CertCreateFailed;

    const now = rt.timestamp();
    const ca = try buildCA(allocator, domain, now, now + ca_days * day_s);
    defer ca.deinit();
    try writeCA(allocator, cert_dir, ca);

    const leaf = try buildLeaf(allocator, domain, ca, now, now + leaf_days * day_s);
    defer leaf.deinit();
    try writeLeaf(allocator, cert_dir, leaf);

    // Install CA to system trust store
    const ca_path = try std.fmt.allocPrint(allocator, "{s}" ++ sep ++ "zlodevCA.pem", .{cert_dir});
    defer allocator.free(ca_path);

    switch (builtin.os.tag) {
        .macos => {
            std.debug.print("installing CA and generating certificate, please provide sudo password and login to keychain when asked\n", .{});
            try sys.sudoCmd(allocator, &.{ "sudo", "security", "add-trusted-cert", "-d", "-k", "/Library/Keychains/System.keychain", ca_path });
        },
        .linux => {
            std.debug.print("installing CA and generating certificate, please provide sudo password when asked\n", .{});
            if (sys.dirExists("/etc/pki/ca-trust/source/anchors")) {
                try sys.sudoCmd(allocator, &.{ "sudo", "cp", ca_path, "/etc/pki/ca-trust/source/anchors/zlodevCA.pem" });
                try sys.sudoCmd(allocator, &.{ "sudo", "update-ca-trust", "extract" });
            } else if (sys.dirExists("/usr/local/share/ca-certificates")) {
                try sys.sudoCmd(allocator, &.{ "sudo", "cp", ca_path, "/usr/local/share/ca-certificates/zlodevCA.crt" });
                try sys.sudoCmd(allocator, &.{ "sudo", "update-ca-certificates" });
            } else if (sys.dirExists("/etc/ca-certificates/trust-source/anchors")) {
                try sys.sudoCmd(allocator, &.{ "sudo", "cp", ca_path, "/etc/ca-certificates/trust-source/anchors/zlodevCA.crt" });
                try sys.sudoCmd(allocator, &.{ "sudo", "trust", "extract-compat" });
            } else if (sys.dirExists("/usr/share/pki/trust/anchors")) {
                try sys.sudoCmd(allocator, &.{ "sudo", "cp", ca_path, "/usr/share/pki/trust/anchors/zlodevCA.pem" });
                try sys.sudoCmd(allocator, &.{ "sudo", "update-ca-certificates" });
            }
        },
        .windows => {
            std.debug.print("installing CA and generating certificate\n", .{});
            try sys.sudoCmd(allocator, &.{ "certutil", "-addstore", "Root", ca_path });
            // Also add CA to Git's OpenSSL CA bundle so tools like Git's curl can verify certs
            appendToGitCaBundle(allocator, ca_path);
        },
        else => {},
    }

    std.debug.print("CA added as trusted root and certificate generated\n", .{});
    std.debug.print("certificate is located at {s}" ++ sep ++ "zlodev.crt\n", .{cert_dir});
    std.debug.print("key is located at {s}" ++ sep ++ "zlodev.key\n", .{cert_dir});
}

pub fn uninstallCA(allocator: std.mem.Allocator, domain: []const u8) !void {
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const cert_dir = try getCertPath(&path_buf, domain);

    if (!caExists(domain)) {
        std.debug.print("no certificates found for {s}\n", .{domain});
        return;
    }

    switch (builtin.os.tag) {
        .macos => {
            std.debug.print("uninstalling and removing CA, please provide sudo password and login to keychain when asked\n", .{});
            removeFromKeychain(allocator, cert_dir);
        },
        .linux => {
            std.debug.print("uninstalling and removing CA, please provide sudo password when asked\n", .{});
            if (sys.dirExists("/etc/pki/ca-trust/source/anchors")) {
                try sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", "/etc/pki/ca-trust/source/anchors/zlodevCA.pem" });
                try sys.sudoCmd(allocator, &.{ "sudo", "update-ca-trust", "extract" });
            } else if (sys.dirExists("/usr/local/share/ca-certificates")) {
                try sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", "/usr/local/share/ca-certificates/zlodevCA.crt" });
                try sys.sudoCmd(allocator, &.{ "sudo", "update-ca-certificates" });
            } else if (sys.dirExists("/etc/ca-certificates/trust-source/anchors")) {
                try sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", "/etc/ca-certificates/trust-source/anchors/zlodevCA.crt" });
                try sys.sudoCmd(allocator, &.{ "sudo", "trust", "extract-compat" });
            } else if (sys.dirExists("/usr/share/pki/trust/anchors")) {
                try sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", "/usr/share/pki/trust/anchors/zlodevCA.pem" });
                try sys.sudoCmd(allocator, &.{ "sudo", "update-ca-certificates" });
            }
        },
        .windows => {
            std.debug.print("uninstalling and removing CA\n", .{});
            const cn = std.fmt.allocPrint(allocator, "{s} CA", .{domain}) catch {
                std.debug.print("failed to allocate CN string\n", .{});
                return;
            };
            defer allocator.free(cn);
            sys.sudoCmd(allocator, &.{ "certutil", "-delstore", "Root", cn }) catch {
                std.debug.print("failed to remove certificate from store\n", .{});
            };
            removeFromGitCaBundle(allocator);
        },
        else => {},
    }

    // Remove cert directory
    std.Io.Dir.cwd().deleteTree(rt.io(), cert_dir) catch {};
    std.debug.print("CA removed from trusted roots and certificates deleted for {s}\n", .{domain});
}

fn removeFromKeychain(allocator: std.mem.Allocator, cert_dir: []const u8) void {
    var ca_path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const ca_path = std.fmt.bufPrint(&ca_path_buf, "{s}" ++ sep ++ "zlodevCA.pem", .{cert_dir}) catch {
        std.debug.print("CA file path could not be determined, skipping keychain removal\n", .{});
        return;
    };
    const sha1 = getFingerprint(ca_path) catch {
        std.debug.print("CA file not found, skipping keychain removal\n", .{});
        return;
    };
    sys.sudoCmd(allocator, &.{ "sudo", "security", "delete-certificate", "-Z", &sha1 }) catch {
        std.debug.print("failed to remove certificate from keychain\n", .{});
    };
}

const ca_bundle_marker_begin = "\n# BEGIN zlodev CA\n";
const ca_bundle_marker_end = "# END zlodev CA\n";

/// Append the zlodev CA PEM to Git's OpenSSL CA bundle so tools using
/// OpenSSL (e.g. Git's bundled curl) can verify zlodev certificates.
fn appendToGitCaBundle(allocator: std.mem.Allocator, ca_pem_path: []const u8) void {
    const bundle_path = getGitCaBundlePath(allocator) orelse return;
    defer allocator.free(bundle_path);

    // Read CA PEM content
    const ca_content = std.Io.Dir.cwd().readFileAlloc(rt.io(), ca_pem_path, allocator, .limited(8192)) catch {
        std.debug.print("warning: could not read CA file for Git bundle\n", .{});
        return;
    };
    defer allocator.free(ca_content);

    // Check if already present
    const bundle_content = std.Io.Dir.cwd().readFileAlloc(rt.io(), bundle_path, allocator, .limited(4 * 1024 * 1024)) catch {
        std.debug.print("warning: could not read Git CA bundle\n", .{});
        return;
    };
    defer allocator.free(bundle_content);
    if (std.mem.indexOf(u8, bundle_content, "# BEGIN zlodev CA") != null) return;

    // Build new content in memory
    var new_content: std.ArrayListUnmanaged(u8) = .empty;
    defer new_content.deinit(allocator);
    new_content.appendSlice(allocator, bundle_content) catch return;
    new_content.appendSlice(allocator, ca_bundle_marker_begin) catch return;
    new_content.appendSlice(allocator, ca_content) catch return;
    new_content.appendSlice(allocator, ca_bundle_marker_end) catch return;

    // Write atomically via temp file + rename
    const tmp_path = std.fmt.allocPrint(allocator, "{s}.zlodev_tmp", .{bundle_path}) catch return;
    defer allocator.free(tmp_path);

    const tmp_file = std.Io.Dir.createFileAbsolute(rt.io(), tmp_path, .{}) catch return;
    tmp_file.writeStreamingAll(rt.io(), new_content.items) catch {
        tmp_file.close(rt.io());
        std.Io.Dir.deleteFileAbsolute(rt.io(), tmp_path) catch {};
        return;
    };
    tmp_file.close(rt.io());

    std.Io.Dir.renameAbsolute(tmp_path, bundle_path, rt.io()) catch {
        std.Io.Dir.deleteFileAbsolute(rt.io(), tmp_path) catch {};
        return;
    };

    std.debug.print("CA also added to Git CA bundle at {s}\n", .{bundle_path});
}

/// Remove the zlodev CA from Git's OpenSSL CA bundle.
fn removeFromGitCaBundle(allocator: std.mem.Allocator) void {
    const bundle_path = getGitCaBundlePath(allocator) orelse return;
    defer allocator.free(bundle_path);

    const content = std.Io.Dir.cwd().readFileAlloc(rt.io(), bundle_path, allocator, .limited(4 * 1024 * 1024)) catch return;
    defer allocator.free(content);

    const begin = std.mem.indexOf(u8, content, ca_bundle_marker_begin) orelse return;
    const after_begin = begin + ca_bundle_marker_begin.len;
    const end_marker = std.mem.indexOfPos(u8, content, after_begin, ca_bundle_marker_end) orelse return;
    const end = end_marker + ca_bundle_marker_end.len;

    // Write to a temporary file, then rename atomically
    const tmp_path = std.fmt.allocPrint(allocator, "{s}.zlodev_tmp", .{bundle_path}) catch return;
    defer allocator.free(tmp_path);

    const tmp_file = std.Io.Dir.createFileAbsolute(rt.io(), tmp_path, .{}) catch return;
    tmp_file.writeStreamingAll(rt.io(), content[0..begin]) catch {
        tmp_file.close(rt.io());
        std.Io.Dir.deleteFileAbsolute(rt.io(), tmp_path) catch {};
        return;
    };
    tmp_file.writeStreamingAll(rt.io(), content[end..]) catch {
        tmp_file.close(rt.io());
        std.Io.Dir.deleteFileAbsolute(rt.io(), tmp_path) catch {};
        return;
    };
    tmp_file.close(rt.io());

    std.Io.Dir.renameAbsolute(tmp_path, bundle_path, rt.io()) catch {
        std.Io.Dir.deleteFileAbsolute(rt.io(), tmp_path) catch {};
        return;
    };
    std.debug.print("CA removed from Git CA bundle\n", .{});
}

/// Find the Git CA bundle path. Tries `git config` first, then common install paths.
fn getGitCaBundlePath(allocator: std.mem.Allocator) ?[]const u8 {
    // Try git config
    const configs = [_][]const []const u8{
        &.{ "git", "config", "--system", "http.sslCAInfo" },
        &.{ "git", "config", "--global", "http.sslCAInfo" },
    };
    for (configs) |argv| {
        if (sys.runCmdOutput(allocator, argv)) |output| {
            const trimmed = std.mem.trim(u8, output, " \t\r\n");
            if (trimmed.len > 0) {
                const result = allocator.dupe(u8, trimmed) catch {
                    allocator.free(output);
                    continue;
                };
                allocator.free(output);
                return result;
            }
            allocator.free(output);
        }
    }
    // Fallback: check common Git for Windows CA bundle locations
    const fallback_paths = [_][]const u8{
        "C:\\Program Files\\Git\\mingw64\\etc\\ssl\\certs\\ca-bundle.crt",
        "C:\\Program Files (x86)\\Git\\mingw64\\etc\\ssl\\certs\\ca-bundle.crt",
    };
    for (fallback_paths) |path| {
        std.Io.Dir.accessAbsolute(rt.io(), path, .{}) catch continue;
        return allocator.dupe(u8, path) catch return null;
    }
    return null;
}

fn getFingerprint(ca_path: []const u8) ![40]u8 {
    // Null-terminate the path for C API
    var path_z_buf: [std.Io.Dir.max_path_bytes + 1]u8 = undefined;
    const path_z = std.mem.printSentinel(&path_z_buf, "{s}", .{ca_path}, 0) catch return error.CertReadFailed;

    const bio = c.BIO_new_file(path_z.ptr, "r") orelse return error.CertReadFailed;
    defer _ = c.BIO_free(bio);

    const x509 = c.PEM_read_bio_X509(bio, null, null, null) orelse return error.CertReadFailed;
    defer c.X509_free(x509);

    var md: [c.EVP_MAX_MD_SIZE]u8 = undefined;
    var md_len: c_uint = 0;
    if (c.X509_digest(x509, c.EVP_sha1(), &md, &md_len) != 1) return error.DigestFailed;

    // Format as uppercase hex (SHA-1 = 20 bytes = 40 hex chars)
    var hex: [40]u8 = undefined;
    const hex_chars = "0123456789ABCDEF";
    for (0..@as(usize, md_len)) |i| {
        hex[i * 2] = hex_chars[md[i] >> 4];
        hex[i * 2 + 1] = hex_chars[md[i] & 0x0F];
    }
    return hex;
}


fn testKey() !*c.EVP_PKEY {
    return generateRsaKey();
}

fn tmpPathZ(buf: []u8, tmp: *const std.testing.TmpDir, name: []const u8) ![:0]const u8 {
    return std.fmt.bufPrintSentinel(buf, ".zig-cache" ++ sep ++ "tmp" ++ sep ++ "{s}" ++ sep ++ "{s}", .{ &tmp.sub_path, name }, 0);
}

fn modeOf(dir: std.Io.Dir, sub_path: []const u8) !std.posix.mode_t {
    const st = try dir.statFile(rt.io(), sub_path, .{});
    return st.permissions.toMode() & 0o777;
}

test "writePemKey creates a key file only the owner can read" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const key = try testKey();
    defer c.EVP_PKEY_free(key);
    var buf: [256]u8 = undefined;
    try writePemKey(try tmpPathZ(&buf, &tmp, "k.key"), key);
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(tmp.dir, "k.key"));
}

test "writePemKey tightens an existing world-readable key file" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Keys written by older versions are 0644; O_CREAT's mode won't touch them.
    const old = try tmp.dir.createFile(rt.io(), "k.key", .{ .permissions = .fromMode(0o644) });
    old.close(rt.io());
    const key = try testKey();
    defer c.EVP_PKEY_free(key);
    var buf: [256]u8 = undefined;
    try writePemKey(try tmpPathZ(&buf, &tmp, "k.key"), key);
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(tmp.dir, "k.key"));
    const contents = try tmp.dir.readFileAlloc(rt.io(), "k.key", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(contents);
    try std.testing.expect(std.mem.startsWith(u8, contents, "-----BEGIN PRIVATE KEY-----"));
}

test "makePrivateDir creates the cert dir and tightens an existing one to 0700" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [256]u8 = undefined;
    try makePrivateDir(try tmpPathZ(&buf, &tmp, "a" ++ sep ++ "b"));
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o700), try modeOf(tmp.dir, "a" ++ sep ++ "b"));

    try tmp.dir.createDir(rt.io(), "open", .fromMode(0o755));
    try makePrivateDir(try tmpPathZ(&buf, &tmp, "open"));
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o700), try modeOf(tmp.dir, "open"));
}

fn tmpDirPath(buf: []u8, tmp: *const std.testing.TmpDir) ![]const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache" ++ sep ++ "tmp" ++ sep ++ "{s}", .{&tmp.sub_path});
}

test "buildLeaf uses the requested validity and the CA as issuer" {
    const now: i64 = 1794614400; // 2026-11-14
    const ca = try buildCA(std.testing.allocator, "dev.lo", now, now + ca_days * day_s);
    defer ca.deinit();
    const leaf = try buildLeaf(std.testing.allocator, "dev.lo", ca, now, now + 10 * day_s);
    defer leaf.deinit();
    try std.testing.expectEqual(now + 10 * day_s, try notAfter(leaf.cert));
    try std.testing.expectEqual(@as(c_int, 0), c.X509_NAME_cmp(c.X509_get_issuer_name(leaf.cert), c.X509_get_subject_name(ca.cert)));
    try std.testing.expectEqual(@as(c_int, 1), c.X509_verify(leaf.cert, ca.key));
}

test "writeLeaf replaces both files and leaves no tmp files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    // Old files from a previous leaf, plus a stale world-readable tmp key from a crashed run.
    for ([_][]const u8{ "zlodev.crt", "zlodev.key", "zlodev.key.tmp" }) |name| {
        const f = try tmp.dir.createFile(rt.io(), name, .{ .permissions = .fromMode(0o644) });
        f.close(rt.io());
    }
    const now: i64 = 1794614400;
    const ca = try buildCA(std.testing.allocator, "dev.lo", now, now + ca_days * day_s);
    defer ca.deinit();
    const leaf = try buildLeaf(std.testing.allocator, "dev.lo", ca, now, now + leaf_days * day_s);
    defer leaf.deinit();
    try writeLeaf(std.testing.allocator, dir, leaf);

    var buf: [256]u8 = undefined;
    const crt = readPemCert(try tmpPathZ(&buf, &tmp, "zlodev.crt")) orelse return error.TestUnexpectedResult;
    defer c.X509_free(crt);
    const key = readPemKey(try tmpPathZ(&buf, &tmp, "zlodev.key")) orelse return error.TestUnexpectedResult;
    defer c.EVP_PKEY_free(key);
    try std.testing.expectEqual(@as(c_int, 1), c.X509_check_private_key(crt, key));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(rt.io(), "zlodev.crt.tmp", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(rt.io(), "zlodev.key.tmp", .{}));
    if (builtin.os.tag != .windows)
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(tmp.dir, "zlodev.key"));
}
