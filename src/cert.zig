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

const AnchorStore = struct { dir: []const u8, ext: []const u8, refresh: []const []const u8 };

/// System trust-anchor dirs, first existing one wins: Fedora/RHEL, Debian/Ubuntu, Arch, openSUSE.
const linux_anchor_stores = [_]AnchorStore{
    .{ .dir = "/etc/pki/ca-trust/source/anchors", .ext = "pem", .refresh = &.{ "sudo", "update-ca-trust", "extract" } },
    .{ .dir = "/usr/local/share/ca-certificates", .ext = "crt", .refresh = &.{ "sudo", "update-ca-certificates" } },
    .{ .dir = "/etc/ca-certificates/trust-source/anchors", .ext = "crt", .refresh = &.{ "sudo", "trust", "extract-compat" } },
    .{ .dir = "/usr/share/pki/trust/anchors", .ext = "pem", .refresh = &.{ "sudo", "update-ca-certificates" } },
};

fn linuxAnchorStore() ?AnchorStore {
    for (linux_anchor_stores) |store| {
        if (sys.dirExists(store.dir)) return store;
    }
    return null;
}

fn anchorPath(buf: []u8, store: AnchorStore, domain: []const u8) ![]const u8 {
    var name_buf: [256]u8 = undefined;
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ store.dir, try anchorFileName(&name_buf, domain, store.ext) });
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
            if (linuxAnchorStore()) |store| {
                var anchor_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
                try sys.sudoCmd(allocator, &.{ "sudo", "cp", ca_path, try anchorPath(&anchor_buf, store, domain) });
                try sys.sudoCmd(allocator, store.refresh);
            }
            addToNss(allocator, domain, ca_path);
        },
        .windows => {
            std.debug.print("installing CA and generating certificate\n", .{});
            try sys.sudoCmd(allocator, &.{ "certutil", "-addstore", "Root", ca_path });
            // Also add CA to Git's OpenSSL CA bundle so tools like Git's curl can verify certs
            appendToGitCaBundle(allocator, domain, ca_path);
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
    var ca_path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const ca_path = try std.fmt.bufPrint(&ca_path_buf, "{s}" ++ sep ++ "zlodevCA.pem", .{cert_dir});

    switch (builtin.os.tag) {
        .macos => {
            std.debug.print("uninstalling and removing CA, please provide sudo password and login to keychain when asked\n", .{});
            removeFromKeychain(allocator, cert_dir);
        },
        .linux => {
            std.debug.print("uninstalling and removing CA, please provide sudo password when asked\n", .{});
            if (linuxAnchorStore()) |store| {
                var anchor_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
                try sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", try anchorPath(&anchor_buf, store, domain) });
                // Older versions used one file for every domain: remove it only if it holds this CA.
                var legacy_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
                const legacy = try std.fmt.bufPrint(&legacy_buf, "{s}/zlodevCA.{s}", .{ store.dir, store.ext });
                if (sameFileContents(allocator, legacy, ca_path)) try sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", legacy });
                try sys.sudoCmd(allocator, store.refresh);
            }
            removeFromNss(allocator, domain);
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
            removeFromGitCaBundle(allocator, domain, ca_path);
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

// Markers written by versions before per-domain blocks; only read for cleanup.
const legacy_bundle_begin = "\n# BEGIN zlodev CA\n";
const legacy_bundle_end = "# END zlodev CA\n";

const BundleBlock = struct { start: usize, stop: usize, body: []const u8 };

fn findBlock(content: []const u8, begin: []const u8, end: []const u8) ?BundleBlock {
    const start = std.mem.indexOf(u8, content, begin) orelse return null;
    const body_start = start + begin.len;
    const end_at = std.mem.indexOfPos(u8, content, body_start, end) orelse return null;
    return .{ .start = start, .stop = end_at + end.len, .body = content[body_start..end_at] };
}

/// `content` with a block for `domain` appended; null when that domain already has one.
pub fn bundleWithCa(allocator: std.mem.Allocator, content: []const u8, domain: []const u8, pem: []const u8) !?[]u8 {
    var begin_buf: [320]u8 = undefined;
    var end_buf: [320]u8 = undefined;
    const begin = try std.fmt.bufPrint(&begin_buf, "\n# BEGIN zlodev CA {s}\n", .{domain});
    const end = try std.fmt.bufPrint(&end_buf, "# END zlodev CA {s}\n", .{domain});
    if (std.mem.indexOf(u8, content, begin) != null) return null;
    return try std.mem.concat(allocator, u8, &.{ content, begin, pem, end });
}

/// `content` without `domain`'s block, and without an older unnamed block when it
/// holds this CA's PEM (so the other domain's CA survives). Null when nothing changed.
pub fn bundleWithoutCa(allocator: std.mem.Allocator, content: []const u8, domain: []const u8, pem: []const u8) !?[]u8 {
    var begin_buf: [320]u8 = undefined;
    var end_buf: [320]u8 = undefined;
    const begin = try std.fmt.bufPrint(&begin_buf, "\n# BEGIN zlodev CA {s}\n", .{domain});
    const end = try std.fmt.bufPrint(&end_buf, "# END zlodev CA {s}\n", .{domain});
    var owned: ?[]u8 = null;
    errdefer if (owned) |o| allocator.free(o);
    var current = content;
    if (findBlock(current, begin, end)) |b| {
        owned = try std.mem.concat(allocator, u8, &.{ current[0..b.start], current[b.stop..] });
        current = owned.?;
    }
    if (findBlock(current, legacy_bundle_begin, legacy_bundle_end)) |b| {
        if (std.mem.eql(u8, b.body, pem)) {
            const next = try std.mem.concat(allocator, u8, &.{ current[0..b.start], current[b.stop..] });
            if (owned) |o| allocator.free(o);
            owned = next;
        }
    }
    return owned;
}

fn writeFileAtomic(allocator: std.mem.Allocator, path: []const u8, bytes: []const u8) !void {
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.zlodev_tmp", .{path});
    defer allocator.free(tmp_path);
    const tmp_file = try std.Io.Dir.createFileAbsolute(rt.io(), tmp_path, .{});
    tmp_file.writeStreamingAll(rt.io(), bytes) catch |e| {
        tmp_file.close(rt.io());
        std.Io.Dir.deleteFileAbsolute(rt.io(), tmp_path) catch {};
        return e;
    };
    tmp_file.close(rt.io());
    std.Io.Dir.renameAbsolute(tmp_path, path, rt.io()) catch |e| {
        std.Io.Dir.deleteFileAbsolute(rt.io(), tmp_path) catch {};
        return e;
    };
}

/// Append the domain's CA to Git's OpenSSL CA bundle so tools using OpenSSL
/// (e.g. Git's bundled curl) can verify zlodev certificates.
fn appendToGitCaBundle(allocator: std.mem.Allocator, domain: []const u8, ca_pem_path: []const u8) void {
    const bundle_path = getGitCaBundlePath(allocator) orelse return;
    defer allocator.free(bundle_path);
    const ca_content = std.Io.Dir.cwd().readFileAlloc(rt.io(), ca_pem_path, allocator, .limited(8192)) catch {
        std.debug.print("warning: could not read CA file for Git bundle\n", .{});
        return;
    };
    defer allocator.free(ca_content);
    const bundle_content = std.Io.Dir.cwd().readFileAlloc(rt.io(), bundle_path, allocator, .limited(4 * 1024 * 1024)) catch {
        std.debug.print("warning: could not read Git CA bundle\n", .{});
        return;
    };
    defer allocator.free(bundle_content);
    const new_content = (bundleWithCa(allocator, bundle_content, domain, ca_content) catch return) orelse return;
    defer allocator.free(new_content);
    writeFileAtomic(allocator, bundle_path, new_content) catch return;
    std.debug.print("CA also added to Git CA bundle at {s}\n", .{bundle_path});
}

/// Remove the domain's CA from Git's OpenSSL CA bundle.
fn removeFromGitCaBundle(allocator: std.mem.Allocator, domain: []const u8, ca_pem_path: []const u8) void {
    const bundle_path = getGitCaBundlePath(allocator) orelse return;
    defer allocator.free(bundle_path);
    // Without the PEM only the named block can go; a legacy block never matches "".
    const pem = std.Io.Dir.cwd().readFileAlloc(rt.io(), ca_pem_path, allocator, .limited(8192)) catch
        allocator.dupe(u8, "") catch return;
    defer allocator.free(pem);
    const content = std.Io.Dir.cwd().readFileAlloc(rt.io(), bundle_path, allocator, .limited(4 * 1024 * 1024)) catch return;
    defer allocator.free(content);
    const new_content = (bundleWithoutCa(allocator, content, domain, pem) catch return) orelse return;
    defer allocator.free(new_content);
    writeFileAtomic(allocator, bundle_path, new_content) catch return;
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

/// Trust-anchor file name for `domain`, so `install` and `install -l` don't share one file.
pub fn anchorFileName(buf: []u8, domain: []const u8, ext: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "zlodevCA-{s}.{s}", .{ domain, ext });
}

/// Nickname of the CA in browsers' NSS databases.
pub fn nssNickname(buf: []u8, domain: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "zlodev {s} CA", .{domain});
}

pub const NssKind = enum { chromium, snap, firefox };
pub const NssDb = struct { path: []u8, kind: NssKind };

/// NSS databases browsers read on Linux, which ignore the system CA bundle.
/// `[0]` is always `<home>/.pki/nssdb` (deb/rpm Chrome, Chromium, Brave, Edge,
/// Vivaldi, Opera), even when missing; the rest exist: snap apps' own
/// `.pki/nssdb` and Firefox profiles (dirs holding cert9.db), including newer
/// Firefox's XDG location (`config_home` = `$XDG_CONFIG_HOME`, else `<home>/.config`).
pub fn nssDatabases(allocator: std.mem.Allocator, home: []const u8, config_home: ?[]const u8) ![]NssDb {
    var list: std.ArrayListUnmanaged(NssDb) = .empty;
    errdefer {
        for (list.items) |db| allocator.free(db.path);
        list.deinit(allocator);
    }
    try appendDb(allocator, &list, try std.fmt.allocPrint(allocator, "{s}" ++ sep ++ ".pki" ++ sep ++ "nssdb", .{home}), .chromium);

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    try appendExistingDbs(allocator, &list, try std.fmt.bufPrint(&root_buf, "{s}" ++ sep ++ "snap", .{home}), "current" ++ sep ++ ".pki" ++ sep ++ "nssdb", .snap);
    try appendExistingDbs(allocator, &list, try std.fmt.bufPrint(&root_buf, "{s}" ++ sep ++ ".mozilla" ++ sep ++ "firefox", .{home}), "", .firefox);
    const xdg_firefox = if (config_home) |dir|
        try std.fmt.bufPrint(&root_buf, "{s}" ++ sep ++ "mozilla" ++ sep ++ "firefox", .{dir})
    else
        try std.fmt.bufPrint(&root_buf, "{s}" ++ sep ++ ".config" ++ sep ++ "mozilla" ++ sep ++ "firefox", .{home});
    try appendExistingDbs(allocator, &list, xdg_firefox, "", .firefox);
    try appendExistingDbs(allocator, &list, try std.fmt.bufPrint(&root_buf, "{s}" ++ sep ++ "snap" ++ sep ++ "firefox" ++ sep ++ "common" ++ sep ++ ".mozilla" ++ sep ++ "firefox", .{home}), "", .firefox);
    return list.toOwnedSlice(allocator);
}

pub fn freeNssDatabases(allocator: std.mem.Allocator, dbs: []NssDb) void {
    for (dbs) |db| allocator.free(db.path);
    allocator.free(dbs);
}

fn appendDb(allocator: std.mem.Allocator, list: *std.ArrayListUnmanaged(NssDb), path: []u8, kind: NssKind) !void {
    errdefer allocator.free(path);
    try list.append(allocator, .{ .path = path, .kind = kind });
}

/// Appends `<root>/<subdir>/<suffix>` for each subdir of `root` whose NSS
/// database exists. A missing `root` adds nothing.
fn appendExistingDbs(allocator: std.mem.Allocator, list: *std.ArrayListUnmanaged(NssDb), root: []const u8, suffix: []const u8, kind: NssKind) !void {
    var dir = std.Io.Dir.cwd().openDir(rt.io(), root, .{ .iterate = true }) catch return;
    defer dir.close(rt.io());
    var it = dir.iterate();
    while (it.next(rt.io()) catch null) |entry| {
        if (entry.kind != .directory) continue;
        const path = if (suffix.len == 0)
            try std.fmt.allocPrint(allocator, "{s}" ++ sep ++ "{s}", .{ root, entry.name })
        else
            try std.fmt.allocPrint(allocator, "{s}" ++ sep ++ "{s}" ++ sep ++ "{s}", .{ root, entry.name, suffix });
        if (!nssDbExists(allocator, path)) {
            allocator.free(path);
            continue;
        }
        try appendDb(allocator, list, path, kind);
    }
}

fn nssDbExists(allocator: std.mem.Allocator, db_dir: []const u8) bool {
    const path = std.fmt.allocPrint(allocator, "{s}" ++ sep ++ "cert9.db", .{db_dir}) catch return false;
    defer allocator.free(path);
    std.Io.Dir.cwd().access(rt.io(), path, .{}) catch return false;
    return true;
}

const certutil_missing_fmt = "warning: certutil not found, so Chrome and Firefox won't trust {s}. Install libnss3-tools (Debian/Ubuntu), nss-tools (Fedora) or nss (Arch), then run 'zlodev install -f'\n";

/// Add the CA to the NSS databases Chromium-based browsers and Firefox read on
/// Linux. Runs as the user, not sudo; failures only warn.
fn addToNss(allocator: std.mem.Allocator, domain: []const u8, ca_path: []const u8) void {
    const home = compat.getenv("HOME") orelse return;
    const dbs = nssDatabases(allocator, home, compat.getenv("XDG_CONFIG_HOME")) catch return;
    defer freeNssDatabases(allocator, dbs);
    var nick_buf: [256]u8 = undefined;
    const nick = nssNickname(&nick_buf, domain) catch return;
    for (dbs) |db| {
        var arg_buf: [std.Io.Dir.max_path_bytes + 4]u8 = undefined;
        const db_arg = std.fmt.bufPrint(&arg_buf, "sql:{s}", .{db.path}) catch continue;
        if (!nssDbExists(allocator, db.path)) {
            // Only ~/.pki/nssdb is listed while missing: create it so a browser started later trusts the CA.
            makePrivateDir(db.path) catch {
                std.debug.print("warning: could not add CA to {s}\n", .{db.path});
                continue;
            };
            switch (sys.runUserCmd(&.{ "certutil", "-N", "--empty-password", "-d", db_arg })) {
                .ok => {},
                .missing => {
                    std.debug.print(certutil_missing_fmt, .{domain});
                    return;
                },
                .failed => {
                    std.debug.print("warning: could not add CA to {s}\n", .{db.path});
                    continue;
                },
            }
        }
        // Clear an entry left by an earlier CA under the same nickname (install -f).
        if (sys.runUserCmd(&.{ "certutil", "-D", "-d", db_arg, "-n", nick }) == .missing) {
            std.debug.print(certutil_missing_fmt, .{domain});
            return;
        }
        switch (sys.runUserCmd(&.{ "certutil", "-A", "-d", db_arg, "-t", "C,,", "-n", nick, "-i", ca_path })) {
            .ok => switch (db.kind) {
                .chromium => std.debug.print("CA added to Chromium-based browsers ({s})\n", .{db.path}),
                .snap => std.debug.print("CA added to {s}\n", .{db.path}),
                .firefox => std.debug.print("CA added to Firefox profile {s}; restart Firefox if it is running\n", .{std.fs.path.basename(db.path)}),
            },
            .missing => {
                std.debug.print(certutil_missing_fmt, .{domain});
                return;
            },
            .failed => std.debug.print("warning: could not add CA to {s}\n", .{db.path}),
        }
    }
}

/// Remove the CA from every NSS database that exists. Never creates one.
fn removeFromNss(allocator: std.mem.Allocator, domain: []const u8) void {
    const home = compat.getenv("HOME") orelse return;
    const dbs = nssDatabases(allocator, home, compat.getenv("XDG_CONFIG_HOME")) catch return;
    defer freeNssDatabases(allocator, dbs);
    var nick_buf: [256]u8 = undefined;
    const nick = nssNickname(&nick_buf, domain) catch return;
    for (dbs) |db| {
        if (!nssDbExists(allocator, db.path)) continue;
        var arg_buf: [std.Io.Dir.max_path_bytes + 4]u8 = undefined;
        const db_arg = std.fmt.bufPrint(&arg_buf, "sql:{s}", .{db.path}) catch continue;
        switch (sys.runUserCmd(&.{ "certutil", "-D", "-d", db_arg, "-n", nick })) {
            .ok => std.debug.print("CA removed from {s}\n", .{db.path}),
            .missing => return,
            .failed => {}, // no entry for this domain
        }
    }
}

/// True when both files exist and hold the same bytes.
fn sameFileContents(allocator: std.mem.Allocator, a: []const u8, b: []const u8) bool {
    const cwd = std.Io.Dir.cwd();
    const x = cwd.readFileAlloc(rt.io(), a, allocator, .limited(64 * 1024)) catch return false;
    defer allocator.free(x);
    const y = cwd.readFileAlloc(rt.io(), b, allocator, .limited(64 * 1024)) catch return false;
    defer allocator.free(y);
    return std.mem.eql(u8, x, y);
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
        const open: std.Io.File.Permissions = if (builtin.os.tag == .windows) .default_file else .fromMode(0o644);
        const f = try tmp.dir.createFile(rt.io(), name, .{ .permissions = open });
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

test "anchorFileName and nssNickname carry the domain" {
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("zlodevCA-dev.lo.crt", try anchorFileName(&buf, "dev.lo", "crt"));
    try std.testing.expectEqualStrings("zlodevCA-myhost.local.pem", try anchorFileName(&buf, "myhost.local", "pem"));
    try std.testing.expectEqualStrings("zlodev dev.lo CA", try nssNickname(&buf, "dev.lo"));
}

test "anchorFileName and nssNickname fit a 63-character host" {
    const domain = "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh" ++ ".local"; // 63 chars
    var buf: [256]u8 = undefined;
    try std.testing.expectEqual(@as(usize, "zlodevCA-".len + domain.len + ".crt".len), (try anchorFileName(&buf, domain, "crt")).len);
    try std.testing.expectEqual(@as(usize, "zlodev ".len + domain.len + " CA".len), (try nssNickname(&buf, domain)).len);
}

test "sameFileContents compares bytes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(rt.io(), .{ .sub_path = "a.pem", .data = "PEM-A\n" });
    try tmp.dir.writeFile(rt.io(), .{ .sub_path = "a2.pem", .data = "PEM-A\n" });
    try tmp.dir.writeFile(rt.io(), .{ .sub_path = "b.pem", .data = "PEM-B\n" });
    var a: [256]u8 = undefined;
    var a2: [256]u8 = undefined;
    var b: [256]u8 = undefined;
    var missing: [256]u8 = undefined;
    const pa = try tmpPathZ(&a, &tmp, "a.pem");
    try std.testing.expect(sameFileContents(std.testing.allocator, pa, try tmpPathZ(&a2, &tmp, "a2.pem")));
    try std.testing.expect(!sameFileContents(std.testing.allocator, pa, try tmpPathZ(&b, &tmp, "b.pem")));
    try std.testing.expect(!sameFileContents(std.testing.allocator, pa, try tmpPathZ(&missing, &tmp, "none.pem")));
}

test "runUserCmd reports a missing binary" {
    try std.testing.expectEqual(sys.RunResult.missing, sys.runUserCmd(&.{"zlodev-no-such-binary-7f3a"}));
}

test "runUserCmd reports success and failure" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try std.testing.expectEqual(sys.RunResult.ok, sys.runUserCmd(&.{"true"}));
    try std.testing.expectEqual(sys.RunResult.failed, sys.runUserCmd(&.{"false"}));
}

fn touchFile(dir: std.Io.Dir, path: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent| try dir.createDirPath(rt.io(), parent);
    const f = try dir.createFile(rt.io(), path, .{});
    f.close(rt.io());
}

fn hasDb(dbs: []const NssDb, suffix: []const u8, kind: NssKind) bool {
    for (dbs) |db| {
        if (db.kind == kind and std.mem.endsWith(u8, db.path, suffix)) return true;
    }
    return false;
}

test "nssDatabases lists ~/.pki/nssdb first even when it is missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(rt.io(), "home");
    var buf: [256]u8 = undefined;
    const dbs = try nssDatabases(std.testing.allocator, try tmpPathZ(&buf, &tmp, "home"), null);
    defer freeNssDatabases(std.testing.allocator, dbs);
    try std.testing.expectEqual(@as(usize, 1), dbs.len);
    try std.testing.expectEqual(NssKind.chromium, dbs[0].kind);
    try std.testing.expect(std.mem.endsWith(u8, dbs[0].path, "home" ++ sep ++ ".pki" ++ sep ++ "nssdb"));
}

test "nssDatabases finds snap databases and Firefox profiles that exist" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const h = "home" ++ sep;
    const snap_db = sep ++ "current" ++ sep ++ ".pki" ++ sep ++ "nssdb";
    try touchFile(tmp.dir, h ++ "snap" ++ sep ++ "brave" ++ snap_db ++ sep ++ "cert9.db");
    try touchFile(tmp.dir, h ++ "snap" ++ sep ++ "chromium" ++ snap_db ++ sep ++ "cert9.db");
    try tmp.dir.createDirPath(rt.io(), h ++ "snap" ++ sep ++ "spotify" ++ sep ++ "current");
    const ff = h ++ ".mozilla" ++ sep ++ "firefox" ++ sep;
    try touchFile(tmp.dir, ff ++ "abc.default-release" ++ sep ++ "cert9.db");
    try touchFile(tmp.dir, ff ++ "My Profile" ++ sep ++ "cert9.db");
    try tmp.dir.createDirPath(rt.io(), ff ++ "Crash Reports");
    try touchFile(tmp.dir, h ++ "snap" ++ sep ++ "firefox" ++ sep ++ "common" ++ sep ++ ".mozilla" ++ sep ++ "firefox" ++ sep ++ "xyz.default" ++ sep ++ "cert9.db");
    try touchFile(tmp.dir, h ++ ".var" ++ sep ++ "app" ++ sep ++ "com.brave.Browser" ++ sep ++ ".pki" ++ sep ++ "nssdb" ++ sep ++ "cert9.db");

    var buf: [256]u8 = undefined;
    const dbs = try nssDatabases(std.testing.allocator, try tmpPathZ(&buf, &tmp, "home"), null);
    defer freeNssDatabases(std.testing.allocator, dbs);

    try std.testing.expectEqual(@as(usize, 6), dbs.len);
    try std.testing.expectEqual(NssKind.chromium, dbs[0].kind);
    try std.testing.expect(hasDb(dbs, "brave" ++ snap_db, .snap));
    try std.testing.expect(hasDb(dbs, "chromium" ++ snap_db, .snap));
    try std.testing.expect(hasDb(dbs, "abc.default-release", .firefox));
    try std.testing.expect(hasDb(dbs, "My Profile", .firefox));
    try std.testing.expect(hasDb(dbs, "xyz.default", .firefox));
    for (dbs) |db| try std.testing.expect(std.mem.indexOf(u8, db.path, ".var") == null);
}

const test_pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
const other_pem = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";

const dev_block = "\n# BEGIN zlodev CA dev.lo\n" ++ test_pem ++ "# END zlodev CA dev.lo\n";
const host_block = "\n# BEGIN zlodev CA host.local\n" ++ other_pem ++ "# END zlodev CA host.local\n";

const legacy_test_bundle = "roots\n\n# BEGIN zlodev CA\n" ++ test_pem ++ "# END zlodev CA\n";

test "bundleWithCa appends a block named for the domain" {
    const out = (try bundleWithCa(std.testing.allocator, "roots\n", "dev.lo", test_pem)).?;
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("roots\n" ++ dev_block, out);
}

test "bundleWithCa skips a domain already present and adds a second domain" {
    const first = "roots\n" ++ dev_block;
    try std.testing.expect((try bundleWithCa(std.testing.allocator, first, "dev.lo", test_pem)) == null);
    const out = (try bundleWithCa(std.testing.allocator, first, "host.local", other_pem)).?;
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings(first ++ host_block, out);
}

test "bundleWithoutCa removes only the named domain" {
    const both = "roots\n" ++ dev_block ++ host_block;
    const out = (try bundleWithoutCa(std.testing.allocator, both, "host.local", other_pem)).?;
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("roots\n" ++ dev_block, out);
}

test "bundleWithoutCa removes a legacy block holding this CA" {
    const out = (try bundleWithoutCa(std.testing.allocator, legacy_test_bundle, "dev.lo", test_pem)).?;
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("roots\n", out);
}

test "bundleWithoutCa keeps a legacy block holding another CA" {
    try std.testing.expect((try bundleWithoutCa(std.testing.allocator, legacy_test_bundle, "host.local", other_pem)) == null);
}

test "bundleWithoutCa returns null when the domain has no block" {
    try std.testing.expect((try bundleWithoutCa(std.testing.allocator, "roots\n", "dev.lo", test_pem)) == null);
}

test "nssDatabases finds Firefox profiles in the XDG config dir" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try touchFile(tmp.dir, "home" ++ sep ++ ".config" ++ sep ++ "mozilla" ++ sep ++ "firefox" ++ sep ++ "p1.default" ++ sep ++ "cert9.db");
    try touchFile(tmp.dir, "xdg" ++ sep ++ "mozilla" ++ sep ++ "firefox" ++ sep ++ "p2.default" ++ sep ++ "cert9.db");
    var home_buf: [256]u8 = undefined;
    var xdg_buf: [256]u8 = undefined;
    const home = try tmpPathZ(&home_buf, &tmp, "home");

    const default_dbs = try nssDatabases(std.testing.allocator, home, null);
    defer freeNssDatabases(std.testing.allocator, default_dbs);
    try std.testing.expect(hasDb(default_dbs, "p1.default", .firefox));

    const xdg_dbs = try nssDatabases(std.testing.allocator, home, try tmpPathZ(&xdg_buf, &tmp, "xdg"));
    defer freeNssDatabases(std.testing.allocator, xdg_dbs);
    try std.testing.expect(hasDb(xdg_dbs, "p2.default", .firefox));
    try std.testing.expect(!hasDb(xdg_dbs, "p1.default", .firefox));
}
