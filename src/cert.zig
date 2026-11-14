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
    // Limit the CA to the zlodev domain, so a leaked CA key can't mint certs for other sites or IPs.
    const nc = try allocPrintZ(allocator, "critical,permitted;DNS:{s},excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0", .{domain});
    defer allocator.free(nc);
    try addExtension(ca_cert, null, c.NID_name_constraints, nc);

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

const renew_before_s: i64 = 30 * day_s;

/// True when the leaf has under 30 days left (or already expired).
pub fn needsRenewal(not_after: i64, now: i64) bool {
    return not_after - now < renew_before_s;
}

fn formatDate(buf: *[10]u8, posix: i64) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(posix, 0)) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ yd.year, md.month.numeric(), @as(u8, md.day_index) + 1 }) catch unreachable;
}

/// Restrict the cert dir and key files written world-readable by older versions.
/// Missing files are skipped; failures only warn, start goes on.
fn tightenPrivateFiles(cert_dir: []const u8) void {
    if (builtin.os.tag == .windows) return;
    tightenPath(cert_dir, 0o700);
    for ([_][]const u8{ "zlodev.key", "zlodevCA.key" }) |name| {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}" ++ sep ++ "{s}", .{ cert_dir, name }) catch continue;
        tightenPath(path, 0o600);
    }
}

fn tightenPath(path: []const u8, mode: std.posix.mode_t) void {
    const cwd = std.Io.Dir.cwd();
    const st = cwd.statFile(rt.io(), path, .{}) catch return;
    if (st.permissions.toMode() & 0o077 == 0) return;
    cwd.setFilePermissions(rt.io(), path, .fromMode(mode), .{}) catch |e| {
        std.debug.print("warning: could not restrict {s}: {s}\n", .{ path, @errorName(e) });
    };
}

const Renewal = union(enum) {
    /// Leaf has 30+ days left and matches its key.
    current,
    /// New leaf written; payload is its notAfter.
    renewed: i64,
    /// Renewal failed but the old leaf hasn't expired yet.
    kept: struct { err: anyerror, not_after: i64 },
};

/// notAfter of the leaf at crt/key, or null if either is unreadable or they don't match.
fn leafNotAfter(crt_path: [:0]const u8, key_path: [:0]const u8) ?i64 {
    const crt = readPemCert(crt_path) orelse return null;
    defer c.X509_free(crt);
    const key = readPemKey(key_path) orelse return null;
    defer c.EVP_PKEY_free(key);
    if (c.X509_check_private_key(crt, key) != 1) return null;
    return notAfter(crt) catch null;
}

fn renewLeaf(allocator: std.mem.Allocator, domain: []const u8, cert_dir: []const u8, ca_cert: *c.X509, now: i64) !i64 {
    const ca_key_path = try allocPrintZ(allocator, "{s}" ++ sep ++ "zlodevCA.key", .{cert_dir});
    defer allocator.free(ca_key_path);
    const ca_key = readPemKey(ca_key_path) orelse return error.CaKeyNotFound;
    defer c.EVP_PKEY_free(ca_key);
    const ca: CertKey = .{ .cert = ca_cert, .key = ca_key };

    const ca_not_after = try notAfter(ca.cert);
    if (ca_not_after <= now) return error.CaExpired;
    const not_after = @min(now + leaf_days * day_s, ca_not_after);
    const leaf = try buildLeaf(allocator, domain, ca, now, not_after);
    defer leaf.deinit();
    try writeLeaf(allocator, cert_dir, leaf);
    return not_after;
}

fn ensureLeafIn(allocator: std.mem.Allocator, domain: []const u8, cert_dir: []const u8, now: i64) !Renewal {
    tightenPrivateFiles(cert_dir);

    // The proxy loads the CA cert as a chain cert, so without it start can't serve at all.
    const ca_pem = try allocPrintZ(allocator, "{s}" ++ sep ++ "zlodevCA.pem", .{cert_dir});
    defer allocator.free(ca_pem);
    const ca_cert = readPemCert(ca_pem) orelse return error.CaNotFound;
    defer c.X509_free(ca_cert);

    const crt_path = try allocPrintZ(allocator, "{s}" ++ sep ++ "zlodev.crt", .{cert_dir});
    defer allocator.free(crt_path);
    const key_path = try allocPrintZ(allocator, "{s}" ++ sep ++ "zlodev.key", .{cert_dir});
    defer allocator.free(key_path);

    if (leafNotAfter(crt_path, key_path)) |na| if (!needsRenewal(na, now)) return .current;

    const not_after = renewLeaf(allocator, domain, cert_dir, ca_cert, now) catch |e| {
        // Re-read: a failed writeLeaf may have replaced the key but not the cert.
        if (leafNotAfter(crt_path, key_path)) |na| if (na > now) return .{ .kept = .{ .err = e, .not_after = na } };
        return e;
    };
    return .{ .renewed = not_after };
}

pub const cert_warning_len = 128;

/// One-line warning for a leaf that couldn't be renewed, shown in the TUI header.
fn keptWarning(buf: *[cert_warning_len]u8, err: anyerror, not_after: i64) []const u8 {
    var date_buf: [10]u8 = undefined;
    return std.fmt.bufPrint(buf, "renewal failed ({s}), expires {s} - run zlodev install -f", .{ @errorName(err), formatDate(&date_buf, not_after) }) catch buf[0..];
}

/// Re-sign the leaf with the kept CA key when it has under 30 days left. No sudo:
/// the CA and trust store are untouched. Errors mean there is no usable leaf.
/// Returns a warning (in `warning_buf`) when renewal failed but the old leaf still works.
pub fn ensureLeaf(allocator: std.mem.Allocator, domain: []const u8, warning_buf: *[cert_warning_len]u8) !?[]const u8 {
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const cert_dir = try getCertPath(&path_buf, domain);
    switch (try ensureLeafIn(allocator, domain, cert_dir, rt.timestamp())) {
        .current => return null,
        .renewed => |na| {
            var date_buf: [10]u8 = undefined;
            const date = formatDate(&date_buf, na);
            log.info("component=cert op=renew domain={s} not_after={s}", .{ domain, date });
            std.debug.print("renewed certificate for {s}, valid until {s}\n", .{ domain, date });
            return null;
        },
        .kept => |k| {
            log.err("component=cert op=renew domain={s} error={s}", .{ domain, @errorName(k.err) });
            const warning = keptWarning(warning_buf, k.err, k.not_after);
            std.debug.print("warning: {s}: {s}\n", .{ domain, warning });
            return warning;
        },
    }
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

test "needsRenewal renews under 30 days left, including expired" {
    const now: i64 = 1794614400;
    try std.testing.expect(!needsRenewal(now + 200 * day_s, now));
    try std.testing.expect(!needsRenewal(now + 30 * day_s, now));
    try std.testing.expect(needsRenewal(now + 29 * day_s, now));
    try std.testing.expect(needsRenewal(now - day_s, now));
}

test "formatDate prints UTC YYYY-MM-DD" {
    var buf: [10]u8 = undefined;
    try std.testing.expectEqualStrings("1970-01-01", formatDate(&buf, 0));
    try std.testing.expectEqualStrings("2026-11-14", formatDate(&buf, 1794614400));
}

/// Writes a CA and a leaf into `dir` with the given expiry times.
fn writeFixture(dir: []const u8, now: i64, ca_not_after: i64, leaf_not_after: i64) !void {
    const ca = try buildCA(std.testing.allocator, "dev.lo", now - 400 * day_s, ca_not_after);
    defer ca.deinit();
    try writeCA(std.testing.allocator, dir, ca);
    const leaf = try buildLeaf(std.testing.allocator, "dev.lo", ca, now - 388 * day_s, leaf_not_after);
    defer leaf.deinit();
    try writeLeaf(std.testing.allocator, dir, leaf);
}

fn readFixtureFile(tmp: *const std.testing.TmpDir, name: []const u8) ![]u8 {
    return tmp.dir.readFileAlloc(rt.io(), name, std.testing.allocator, .unlimited);
}

test "ensureLeafIn renews a leaf with 10 days left" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    const now: i64 = 1794614400;
    try writeFixture(dir, now, now + 3000 * day_s, now + 10 * day_s);
    const old_key = try readFixtureFile(&tmp, "zlodev.key");
    defer std.testing.allocator.free(old_key);

    const r = try ensureLeafIn(std.testing.allocator, "dev.lo", dir, now);
    try std.testing.expectEqual(now + leaf_days * day_s, r.renewed);

    var buf: [256]u8 = undefined;
    const crt = readPemCert(try tmpPathZ(&buf, &tmp, "zlodev.crt")) orelse return error.TestUnexpectedResult;
    defer c.X509_free(crt);
    const ca_key = readPemKey(try tmpPathZ(&buf, &tmp, "zlodevCA.key")) orelse return error.TestUnexpectedResult;
    defer c.EVP_PKEY_free(ca_key);
    try std.testing.expectEqual(@as(c_int, 1), c.X509_verify(crt, ca_key));
    try std.testing.expectEqual(now + leaf_days * day_s, try notAfter(crt));
    const new_key = try readFixtureFile(&tmp, "zlodev.key");
    defer std.testing.allocator.free(new_key);
    try std.testing.expect(!std.mem.eql(u8, old_key, new_key));
    if (builtin.os.tag != .windows)
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(tmp.dir, "zlodev.key"));
}

test "ensureLeafIn leaves a leaf with 200 days left untouched" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    const now: i64 = 1794614400;
    try writeFixture(dir, now, now + 3000 * day_s, now + 200 * day_s);
    const before = try readFixtureFile(&tmp, "zlodev.crt");
    defer std.testing.allocator.free(before);

    try std.testing.expectEqual(Renewal.current, try ensureLeafIn(std.testing.allocator, "dev.lo", dir, now));
    const after = try readFixtureFile(&tmp, "zlodev.crt");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "ensureLeafIn clamps the renewed leaf to the CA's expiry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    const now: i64 = 1794614400;
    try writeFixture(dir, now, now + 100 * day_s, now + 10 * day_s);
    const r = try ensureLeafIn(std.testing.allocator, "dev.lo", dir, now);
    try std.testing.expectEqual(now + 100 * day_s, r.renewed);
}

test "ensureLeafIn renews again when the CA itself has under 30 days left" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    const now: i64 = 1794614400;
    try writeFixture(dir, now, now + 20 * day_s, now + 10 * day_s);
    try std.testing.expectEqual(now + 20 * day_s, (try ensureLeafIn(std.testing.allocator, "dev.lo", dir, now)).renewed);
    // Clamped leaf still has under 30 days, so the next start renews again and succeeds.
    try std.testing.expectEqual(now + 20 * day_s, (try ensureLeafIn(std.testing.allocator, "dev.lo", dir, now + 60)).renewed);
}

test "ensureLeafIn renews a leaf whose key does not match" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    const now: i64 = 1794614400;
    try writeFixture(dir, now, now + 3000 * day_s, now + 200 * day_s);
    // Simulate a crash between the key rename and the cert rename.
    const other = try testKey();
    defer c.EVP_PKEY_free(other);
    var buf: [256]u8 = undefined;
    try writePemKey(try tmpPathZ(&buf, &tmp, "zlodev.key"), other);

    _ = (try ensureLeafIn(std.testing.allocator, "dev.lo", dir, now)).renewed;
    const crt = readPemCert(try tmpPathZ(&buf, &tmp, "zlodev.crt")) orelse return error.TestUnexpectedResult;
    defer c.X509_free(crt);
    const key = readPemKey(try tmpPathZ(&buf, &tmp, "zlodev.key")) orelse return error.TestUnexpectedResult;
    defer c.EVP_PKEY_free(key);
    try std.testing.expectEqual(@as(c_int, 1), c.X509_check_private_key(crt, key));
}

test "ensureLeafIn fails with CaExpired and leaves the leaf untouched" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    const now: i64 = 1794614400;
    try writeFixture(dir, now, now - day_s, now - day_s);
    const before = try readFixtureFile(&tmp, "zlodev.crt");
    defer std.testing.allocator.free(before);
    try std.testing.expectError(error.CaExpired, ensureLeafIn(std.testing.allocator, "dev.lo", dir, now));
    const after = try readFixtureFile(&tmp, "zlodev.crt");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "ensureLeafIn keeps a still-valid leaf when the CA key is missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    const now: i64 = 1794614400;
    try writeFixture(dir, now, now + 3000 * day_s, now + 10 * day_s);
    try tmp.dir.deleteFile(rt.io(), "zlodevCA.key");
    const r = try ensureLeafIn(std.testing.allocator, "dev.lo", dir, now);
    try std.testing.expectEqual(error.CaKeyNotFound, r.kept.err);
    try std.testing.expectEqual(now + 10 * day_s, r.kept.not_after);
}

test "ensureLeafIn fails when the leaf is expired and the CA is missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    const now: i64 = 1794614400;
    try writeFixture(dir, now, now + 3000 * day_s, now - day_s);
    try tmp.dir.deleteFile(rt.io(), "zlodevCA.pem");
    try std.testing.expectError(error.CaNotFound, ensureLeafIn(std.testing.allocator, "dev.lo", dir, now));
}

test "ensureLeafIn fails with CaKeyNotFound when the leaf is expired and the CA key is missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    const now: i64 = 1794614400;
    try writeFixture(dir, now, now + 3000 * day_s, now - day_s);
    try tmp.dir.deleteFile(rt.io(), "zlodevCA.key");
    try std.testing.expectError(error.CaKeyNotFound, ensureLeafIn(std.testing.allocator, "dev.lo", dir, now));
}

test "ensureLeafIn fails when the CA cert is missing, even with a current leaf" {
    // The proxy loads zlodevCA.pem as a chain cert, so start can't serve without it.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    const now: i64 = 1794614400;
    try writeFixture(dir, now, now + 3000 * day_s, now + 200 * day_s);
    try tmp.dir.deleteFile(rt.io(), "zlodevCA.pem");
    try std.testing.expectError(error.CaNotFound, ensureLeafIn(std.testing.allocator, "dev.lo", dir, now));
}

test "ensureLeafIn tightens key files and the dir left open by older versions" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [256]u8 = undefined;
    const dir = try tmpDirPath(&dir_buf, &tmp);
    const now: i64 = 1794614400;
    try writeFixture(dir, now, now + 3000 * day_s, now + 200 * day_s);
    try tmp.dir.setFilePermissions(rt.io(), "zlodev.key", .fromMode(0o644), .{});
    try tmp.dir.setFilePermissions(rt.io(), "zlodevCA.key", .fromMode(0o644), .{});
    try std.testing.expectEqual(Renewal.current, try ensureLeafIn(std.testing.allocator, "dev.lo", dir, now));
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(tmp.dir, "zlodev.key"));
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(tmp.dir, "zlodevCA.key"));
    const st = try std.Io.Dir.cwd().statFile(rt.io(), dir, .{});
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o700), st.permissions.toMode() & 0o777);
}

/// X509_V_* result of verifying `leaf` with `ca` as the only trust anchor (0 = OK).
fn verifyError(ca: *c.X509, leaf: *c.X509) !c_int {
    const store = c.X509_STORE_new() orelse return error.OutOfMemory;
    defer c.X509_STORE_free(store);
    if (c.X509_STORE_add_cert(store, ca) != 1) return error.CertReadFailed;
    const ctx = c.X509_STORE_CTX_new() orelse return error.OutOfMemory;
    defer c.X509_STORE_CTX_free(ctx);
    if (c.X509_STORE_CTX_init(ctx, store, leaf, null) != 1) return error.CertReadFailed;
    _ = c.X509_verify_cert(ctx);
    return c.X509_STORE_CTX_get_error(ctx);
}

test "CA name constraint allows dev.lo and *.dev.lo" {
    const now = rt.timestamp();
    const ca = try buildCA(std.testing.allocator, "dev.lo", now - day_s, now + ca_days * day_s);
    defer ca.deinit();
    const leaf = try buildLeaf(std.testing.allocator, "dev.lo", ca, now - day_s, now + leaf_days * day_s);
    defer leaf.deinit();
    try std.testing.expectEqual(@as(c_int, c.X509_V_OK), try verifyError(ca.cert, leaf.cert));
}

test "CA name constraint rejects other domains" {
    const now = rt.timestamp();
    const ca = try buildCA(std.testing.allocator, "dev.lo", now - day_s, now + ca_days * day_s);
    defer ca.deinit();
    const leaf = try buildLeaf(std.testing.allocator, "evil.com", ca, now - day_s, now + leaf_days * day_s);
    defer leaf.deinit();
    try std.testing.expectEqual(@as(c_int, c.X509_V_ERR_PERMITTED_VIOLATION), try verifyError(ca.cert, leaf.cert));
}

test "CA name constraint rejects IP address certificates" {
    const now = rt.timestamp();
    const ca = try buildCA(std.testing.allocator, "dev.lo", now - day_s, now + ca_days * day_s);
    defer ca.deinit();
    const leaf = try buildCert(std.testing.allocator, "x.dev.lo", "IP:127.0.0.1", ca, now - day_s, now + leaf_days * day_s);
    defer leaf.deinit();
    // BoringSSL doesn't evaluate IP subtrees and rejects with UNSUPPORTED_CONSTRAINT_TYPE;
    // other verifiers report EXCLUDED_VIOLATION. Either way the leaf is refused.
    const err = try verifyError(ca.cert, leaf.cert);
    try std.testing.expect(err == c.X509_V_ERR_EXCLUDED_VIOLATION or err == c.X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE);
}

test "CA name constraint follows the -l domain" {
    const now = rt.timestamp();
    const ca = try buildCA(std.testing.allocator, "mybox.local", now - day_s, now + ca_days * day_s);
    defer ca.deinit();
    const ok = try buildLeaf(std.testing.allocator, "mybox.local", ca, now - day_s, now + leaf_days * day_s);
    defer ok.deinit();
    try std.testing.expectEqual(@as(c_int, c.X509_V_OK), try verifyError(ca.cert, ok.cert));
    const bad = try buildLeaf(std.testing.allocator, "dev.lo", ca, now - day_s, now + leaf_days * day_s);
    defer bad.deinit();
    try std.testing.expectEqual(@as(c_int, c.X509_V_ERR_PERMITTED_VIOLATION), try verifyError(ca.cert, bad.cert));
}

test "keptWarning names the error, expiry date and fix" {
    var buf: [cert_warning_len]u8 = undefined;
    try std.testing.expectEqualStrings(
        "renewal failed (CaKeyNotFound), expires 2026-11-14 - run zlodev install -f",
        keptWarning(&buf, error.CaKeyNotFound, 1794614400),
    );
}
