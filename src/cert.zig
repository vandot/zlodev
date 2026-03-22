const std = @import("std");
const builtin = @import("builtin");
const log = @import("log.zig");
const sys = @import("sys.zig");
const compat = @import("compat.zig");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/x509v3.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bn.h");
    @cInclude("openssl/rsa.h");
});

pub fn getBasePath(buf: []u8) ![]const u8 {
    switch (builtin.os.tag) {
        .macos => {
            const home = compat.getenv("HOME") orelse return error.NoHomeDir;
            return std.fmt.bufPrint(buf, "{s}/Library/Application Support/zlodev", .{home});
        },
        .windows => {
            const local_env = compat.getenv("LocalAppData") orelse return error.NoLocalAppData;
            return std.fmt.bufPrint(buf, "{s}/zlodev", .{local_env});
        },
        else => {
            // Linux
            const xdg = compat.getenv("XDG_DATA_HOME");
            if (xdg) |data_home| {
                return std.fmt.bufPrint(buf, "{s}/zlodev", .{data_home});
            }
            const home = compat.getenv("HOME") orelse return error.NoHomeDir;
            return std.fmt.bufPrint(buf, "{s}/.local/share/zlodev", .{home});
        },
    }
}

pub fn getCertPath(buf: []u8, domain: []const u8) ![]const u8 {
    var base_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try getBasePath(&base_buf);
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ base, domain });
}

pub fn getCert(cert_buf: []u8, key_buf: []u8, domain: []const u8) !struct { cert: []const u8, key: []const u8 } {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try getCertPath(&path_buf, domain);
    const cert_path = try std.fmt.bufPrint(cert_buf, "{s}/zlodev.crt", .{dir});
    const key = try std.fmt.bufPrint(key_buf, "{s}/zlodev.key", .{dir});

    // Check if files exist
    std.fs.accessAbsolute(cert_path, .{}) catch return error.CertNotFound;
    std.fs.accessAbsolute(key, .{}) catch return error.KeyNotFound;

    return .{ .cert = cert_path, .key = key };
}

pub fn caExists(domain: []const u8) bool {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = getCertPath(&path_buf, domain) catch return false;
    var ca_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ca_path = std.fmt.bufPrint(&ca_buf, "{s}/zlodevCA.pem", .{dir}) catch return false;
    std.fs.accessAbsolute(ca_path, .{}) catch return false;
    return true;
}

pub fn getCaPath(buf: []u8, domain: []const u8) ![]const u8 {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try getCertPath(&path_buf, domain);
    return std.fmt.bufPrint(buf, "{s}/zlodevCA.pem", .{dir});
}

pub fn getCaDerPath(buf: []u8, domain: []const u8) ![]const u8 {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try getCertPath(&path_buf, domain);
    return std.fmt.bufPrint(buf, "{s}/zlodevCA.der", .{dir});
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

fn writePemKey(path: [:0]const u8, pkey: *c.EVP_PKEY) !void {
    const bio = c.BIO_new_file(path.ptr, "w") orelse return error.FileWriteFailed;
    defer _ = c.BIO_free(bio);
    if (c.PEM_write_bio_PrivateKey(bio, pkey, null, null, 0, null, null) != 1)
        return error.FileWriteFailed;
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
    return try allocator.dupeZ(u8, s);
}

fn setNameEntry(name: *c.X509_NAME, nid: c_int, value: []const u8) !void {
    if (c.X509_NAME_add_entry_by_NID(name, nid, c.MBSTRING_ASC, value.ptr, @intCast(value.len), -1, 0) != 1)
        return error.CertCreateFailed;
}

fn generateCA(allocator: std.mem.Allocator, domain: []const u8, cert_dir: []const u8) !struct { cert_x509: *c.X509, key: *c.EVP_PKEY } {
    // Generate CA key
    const ca_key = try generateRsaKey();
    errdefer c.EVP_PKEY_free(ca_key);

    // Create certificate
    const ca_cert = c.X509_new() orelse return error.CertCreateFailed;
    errdefer c.X509_free(ca_cert);

    // Version 3
    if (c.X509_set_version(ca_cert, 2) != 1) return error.CertCreateFailed;

    // Random serial number
    const serial_bn = c.BN_new() orelse return error.CertCreateFailed;
    defer c.BN_free(serial_bn);
    if (c.BN_rand(serial_bn, 64, 0, 0) != 1) return error.CertCreateFailed;
    const serial_asn1 = c.X509_get_serialNumber(ca_cert);
    if (c.BN_to_ASN1_INTEGER(serial_bn, serial_asn1) == null) return error.CertCreateFailed;

    // Validity: now to +3650 days
    const not_before = c.X509_get_notBefore(ca_cert);
    _ = c.X509_gmtime_adj(not_before, 0);
    const not_after = c.X509_get_notAfter(ca_cert);
    _ = c.X509_gmtime_adj(not_after, 3650 * 24 * 60 * 60);

    // Subject name
    const name = c.X509_get_subject_name(ca_cert) orelse return error.CertCreateFailed;
    try setNameEntry(name, c.NID_countryName, "LO");
    try setNameEntry(name, c.NID_stateOrProvinceName, "Dev");
    try setNameEntry(name, c.NID_localityName, "Local");
    try setNameEntry(name, c.NID_organizationName, "zlodev");
    try setNameEntry(name, c.NID_organizationalUnitName, "CA");

    // CN = "{domain} CA"
    const cn = try allocPrintZ(allocator, "{s} CA", .{domain});
    defer allocator.free(cn);
    try setNameEntry(name, c.NID_commonName, cn);

    // Self-signed: issuer = subject
    if (c.X509_set_issuer_name(ca_cert, name) != 1) return error.CertCreateFailed;

    // Set public key
    if (c.X509_set_pubkey(ca_cert, ca_key) != 1) return error.CertCreateFailed;

    // Extensions
    try addExtension(ca_cert, null, c.NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
    try addExtension(ca_cert, null, c.NID_key_usage, "critical,keyCertSign");
    try addExtension(ca_cert, null, c.NID_subject_key_identifier, "hash");

    // Sign
    if (c.X509_sign(ca_cert, ca_key, c.EVP_sha256()) == 0) return error.SignFailed;

    // Write files directly to cert_dir
    const ca_pem_path = try allocPrintZ(allocator, "{s}/zlodevCA.pem", .{cert_dir});
    defer allocator.free(ca_pem_path);
    const ca_key_path = try allocPrintZ(allocator, "{s}/zlodevCA.key", .{cert_dir});
    defer allocator.free(ca_key_path);
    const ca_der_path = try allocPrintZ(allocator, "{s}/zlodevCA.der", .{cert_dir});
    defer allocator.free(ca_der_path);

    try writePemCert(ca_pem_path, ca_cert);
    try writePemKey(ca_key_path, ca_key);
    try writeDerCert(ca_der_path, ca_cert);

    return .{ .cert_x509 = ca_cert, .key = ca_key };
}

fn generateDomainCert(allocator: std.mem.Allocator, domain: []const u8, ca_cert: *c.X509, ca_key: *c.EVP_PKEY, cert_dir: []const u8) !void {
    // Generate domain key
    const domain_key = try generateRsaKey();
    defer c.EVP_PKEY_free(domain_key);

    // Create certificate
    const domain_cert = c.X509_new() orelse return error.CertCreateFailed;
    defer c.X509_free(domain_cert);

    // Version 3
    if (c.X509_set_version(domain_cert, 2) != 1) return error.CertCreateFailed;

    // Random serial
    const serial_bn = c.BN_new() orelse return error.CertCreateFailed;
    defer c.BN_free(serial_bn);
    if (c.BN_rand(serial_bn, 64, 0, 0) != 1) return error.CertCreateFailed;
    const serial_asn1 = c.X509_get_serialNumber(domain_cert);
    if (c.BN_to_ASN1_INTEGER(serial_bn, serial_asn1) == null) return error.CertCreateFailed;

    // Validity: now to +398 days
    const not_before = c.X509_get_notBefore(domain_cert);
    _ = c.X509_gmtime_adj(not_before, 0);
    const not_after = c.X509_get_notAfter(domain_cert);
    _ = c.X509_gmtime_adj(not_after, 398 * 24 * 60 * 60);

    // Subject name
    const name = c.X509_get_subject_name(domain_cert) orelse return error.CertCreateFailed;
    try setNameEntry(name, c.NID_countryName, "LO");
    try setNameEntry(name, c.NID_stateOrProvinceName, "Dev");
    try setNameEntry(name, c.NID_localityName, "Local");
    try setNameEntry(name, c.NID_organizationName, "Dev");
    try setNameEntry(name, c.NID_organizationalUnitName, "Local");

    const cn_z = try allocPrintZ(allocator, "{s}", .{domain});
    defer allocator.free(cn_z);
    try setNameEntry(name, c.NID_commonName, cn_z);

    // Issuer = CA subject
    const ca_subject = c.X509_get_subject_name(ca_cert) orelse return error.CertCreateFailed;
    if (c.X509_set_issuer_name(domain_cert, ca_subject) != 1) return error.CertCreateFailed;

    // Set public key
    if (c.X509_set_pubkey(domain_cert, domain_key) != 1) return error.CertCreateFailed;

    // Extensions
    try addExtension(domain_cert, ca_cert, c.NID_authority_key_identifier, "keyid:always");
    try addExtension(domain_cert, ca_cert, c.NID_basic_constraints, "critical,CA:FALSE");
    try addExtension(domain_cert, ca_cert, c.NID_key_usage, "critical,digitalSignature,keyEncipherment");
    try addExtension(domain_cert, ca_cert, c.NID_ext_key_usage, "serverAuth");

    // SAN
    const san = try allocPrintZ(allocator, "DNS:*.{s},DNS:{s}", .{ domain, domain });
    defer allocator.free(san);
    try addExtension(domain_cert, ca_cert, c.NID_subject_alt_name, san);

    // Sign with CA key
    if (c.X509_sign(domain_cert, ca_key, c.EVP_sha256()) == 0) return error.SignFailed;

    // Write files
    const cert_path = try allocPrintZ(allocator, "{s}/zlodev.crt", .{cert_dir});
    defer allocator.free(cert_path);
    const key_path = try allocPrintZ(allocator, "{s}/zlodev.key", .{cert_dir});
    defer allocator.free(key_path);

    try writePemCert(cert_path, domain_cert);
    try writePemKey(key_path, domain_key);
}

pub fn installCA(allocator: std.mem.Allocator, domain: []const u8) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cert_dir = try getCertPath(&path_buf, domain);

    // Create directories
    var base_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base_dir = try getBasePath(&base_buf);
    std.fs.makeDirAbsolute(base_dir) catch {};
    std.fs.makeDirAbsolute(cert_dir) catch {};

    // Generate CA certificate and key
    const ca = try generateCA(allocator, domain, cert_dir);
    defer c.X509_free(ca.cert_x509);
    defer c.EVP_PKEY_free(ca.key);

    // Generate domain certificate signed by CA
    try generateDomainCert(allocator, domain, ca.cert_x509, ca.key, cert_dir);

    // Install CA to system trust store
    const ca_path = try std.fmt.allocPrint(allocator, "{s}/zlodevCA.pem", .{cert_dir});
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
            const ps_cmd = try std.fmt.allocPrint(allocator, "Import-Certificate -FilePath '{s}' -CertStoreLocation Cert:\\LocalMachine\\Root", .{ca_path});
            defer allocator.free(ps_cmd);
            try sys.sudoCmd(allocator, &.{ "Powershell.exe", "-Command", ps_cmd });
        },
        else => {},
    }

    std.debug.print("CA added as trusted root and certificate generated\n", .{});
    std.debug.print("certificate is located at {s}/zlodev.crt\n", .{cert_dir});
    std.debug.print("key is located at {s}/zlodev.key\n", .{cert_dir});
}

pub fn uninstallCA(allocator: std.mem.Allocator, domain: []const u8) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
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
            try sys.sudoCmd(allocator, &.{ "Powershell.exe", "-Command", "Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object {$_.Subject -match 'zlodev'} | Remove-Item" });
        },
        else => {},
    }

    // Remove cert directory
    std.fs.deleteTreeAbsolute(cert_dir) catch {};
    std.debug.print("CA removed from trusted roots and certificates deleted for {s}\n", .{domain});
}

fn removeFromKeychain(allocator: std.mem.Allocator, cert_dir: []const u8) void {
    var ca_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ca_path = std.fmt.bufPrint(&ca_path_buf, "{s}/zlodevCA.pem", .{cert_dir}) catch {
        std.debug.print("CA file path could not be determined, skipping keychain removal\n", .{});
        return;
    };
    const sha1 = getFingerprint(ca_path) catch {
        std.debug.print("CA file not found, skipping keychain removal\n", .{});
        return;
    };
    sys.sudoCmd(allocator, &.{ "sudo", "security", "delete-certificate", "-t", "-Z", &sha1 }) catch {
        std.debug.print("failed to remove certificate from keychain\n", .{});
    };
}

fn getFingerprint(ca_path: []const u8) ![40]u8 {
    // Null-terminate the path for C API
    var path_z_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&path_z_buf, "{s}", .{ca_path}) catch return error.CertReadFailed;

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

