const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const version = b.option([]const u8, "version", "Version string") orelse "dev";
    const max_entries = b.option(u32, "max-entries", "Max request entries in ring buffer [default 500]") orelse 500;

    const options = b.addOptions();
    options.addOption([]const u8, "version", version);
    options.addOption(u32, "max_entries", max_entries);

    const boringssl = b.dependency("boringssl", .{});

    // Build BoringSSL crypto and ssl static libraries
    const crypto_lib = buildCrypto(b, boringssl, target, optimize);
    const ssl_lib = buildSSL(b, boringssl, target, optimize);

    const exe = b.addExecutable(.{
        .name = "zlodev",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    exe.root_module.addOptions("build_options", options);

    const vaxis = b.dependency("vaxis", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("vaxis", vaxis.module("vaxis"));

    // Link BoringSSL
    exe.root_module.linkLibrary(crypto_lib);
    exe.root_module.linkLibrary(ssl_lib);
    exe.root_module.addIncludePath(boringssl.path("include"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run zlodev");
    run_step.dependOn(&run_cmd.step);
}

const common_flags = &[_][]const u8{
    "-DOPENSSL_NO_ASM",
    "-DBORINGSSL_IMPLEMENTATION",
    "-DOPENSSL_SMALL",
};

fn buildCrypto(
    b: *std.Build,
    boringssl: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    mod.addIncludePath(boringssl.path("include"));
    mod.addIncludePath(boringssl.path("crypto"));

    // Crypto C sources (from crypto/CMakeLists.txt)
    mod.addCSourceFiles(.{
        .root = boringssl.path("crypto"),
        .files = crypto_sources,
        .flags = common_flags,
    });

    // FIPS module amalgamation (bcm.c #includes all fipsmodule/*.c files)
    mod.addCSourceFiles(.{
        .root = boringssl.path("crypto/fipsmodule"),
        .files = &.{ "bcm.c", "fips_shared_support.c" },
        .flags = common_flags,
    });

    // Pre-generated err_data.c (from BoringSSL's Go script, pinned to dependency version)
    mod.addCSourceFile(.{
        .file = b.path("src/boringssl_err_data.c"),
        .flags = common_flags,
    });

    return b.addLibrary(.{
        .name = "crypto",
        .root_module = mod,
    });
}

fn buildSSL(
    b: *std.Build,
    boringssl: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });

    mod.addIncludePath(boringssl.path("include"));

    // SSL C++ sources (from ssl/CMakeLists.txt)
    mod.addCSourceFiles(.{
        .root = boringssl.path("ssl"),
        .files = ssl_sources,
        .flags = common_flags,
    });

    return b.addLibrary(.{
        .name = "ssl",
        .root_module = mod,
    });
}

const crypto_sources: []const []const u8 = &.{
    "asn1/a_bitstr.c",
    "asn1/a_bool.c",
    "asn1/a_d2i_fp.c",
    "asn1/a_dup.c",
    "asn1/a_gentm.c",
    "asn1/a_i2d_fp.c",
    "asn1/a_int.c",
    "asn1/a_mbstr.c",
    "asn1/a_object.c",
    "asn1/a_octet.c",
    "asn1/a_strex.c",
    "asn1/a_strnid.c",
    "asn1/a_time.c",
    "asn1/a_type.c",
    "asn1/a_utctm.c",
    "asn1/asn1_lib.c",
    "asn1/asn1_par.c",
    "asn1/asn_pack.c",
    "asn1/f_int.c",
    "asn1/f_string.c",
    "asn1/tasn_dec.c",
    "asn1/tasn_enc.c",
    "asn1/tasn_fre.c",
    "asn1/tasn_new.c",
    "asn1/tasn_typ.c",
    "asn1/tasn_utl.c",
    "asn1/posix_time.c",
    "base64/base64.c",
    "bio/bio.c",
    "bio/bio_mem.c",
    "bio/connect.c",
    "bio/errno.c",
    "bio/fd.c",
    "bio/file.c",
    "bio/hexdump.c",
    "bio/pair.c",
    "bio/printf.c",
    "bio/socket.c",
    "bio/socket_helper.c",
    "blake2/blake2.c",
    "bn_extra/bn_asn1.c",
    "bn_extra/convert.c",
    "buf/buf.c",
    "bytestring/asn1_compat.c",
    "bytestring/ber.c",
    "bytestring/cbb.c",
    "bytestring/cbs.c",
    "bytestring/unicode.c",
    "chacha/chacha.c",
    "cipher_extra/cipher_extra.c",
    "cipher_extra/derive_key.c",
    "cipher_extra/e_aesctrhmac.c",
    "cipher_extra/e_aesgcmsiv.c",
    "cipher_extra/e_chacha20poly1305.c",
    "cipher_extra/e_des.c",
    "cipher_extra/e_null.c",
    "cipher_extra/e_rc2.c",
    "cipher_extra/e_rc4.c",
    "cipher_extra/e_tls.c",
    "cipher_extra/tls_cbc.c",
    "conf/conf.c",
    "cpu_aarch64_apple.c",
    "cpu_aarch64_openbsd.c",
    "cpu_aarch64_fuchsia.c",
    "cpu_aarch64_linux.c",
    "cpu_aarch64_sysreg.c",
    "cpu_aarch64_win.c",
    "cpu_arm_freebsd.c",
    "cpu_arm_linux.c",
    "cpu_arm.c",
    "cpu_intel.c",
    "crypto.c",
    "curve25519/curve25519.c",
    "curve25519/curve25519_64_adx.c",
    "curve25519/spake25519.c",
    "des/des.c",
    "dh_extra/params.c",
    "dh_extra/dh_asn1.c",
    "digest_extra/digest_extra.c",
    "dsa/dsa.c",
    "dsa/dsa_asn1.c",
    "ecdh_extra/ecdh_extra.c",
    "ecdsa_extra/ecdsa_asn1.c",
    "ec_extra/ec_asn1.c",
    "ec_extra/ec_derive.c",
    "ec_extra/hash_to_curve.c",
    "err/err.c",
    "engine/engine.c",
    "evp/evp.c",
    "evp/evp_asn1.c",
    "evp/evp_ctx.c",
    "evp/p_dsa_asn1.c",
    "evp/p_ec.c",
    "evp/p_ec_asn1.c",
    "evp/p_ed25519.c",
    "evp/p_ed25519_asn1.c",
    "evp/p_hkdf.c",
    "evp/p_rsa.c",
    "evp/p_rsa_asn1.c",
    "evp/p_x25519.c",
    "evp/p_x25519_asn1.c",
    "evp/pbkdf.c",
    "evp/print.c",
    "evp/scrypt.c",
    "evp/sign.c",
    "ex_data.c",
    "hpke/hpke.c",
    "hrss/hrss.c",
    "kyber/keccak.c",
    "kyber/kyber.c",
    "lhash/lhash.c",
    "mem.c",
    "obj/obj.c",
    "obj/obj_xref.c",
    "pem/pem_all.c",
    "pem/pem_info.c",
    "pem/pem_lib.c",
    "pem/pem_oth.c",
    "pem/pem_pk8.c",
    "pem/pem_pkey.c",
    "pem/pem_x509.c",
    "pem/pem_xaux.c",
    "pkcs7/pkcs7.c",
    "pkcs7/pkcs7_x509.c",
    "pkcs8/pkcs8.c",
    "pkcs8/pkcs8_x509.c",
    "pkcs8/p5_pbev2.c",
    "poly1305/poly1305.c",
    "poly1305/poly1305_arm.c",
    "poly1305/poly1305_vec.c",
    "pool/pool.c",
    "rand_extra/deterministic.c",
    "rand_extra/forkunsafe.c",
    "rand_extra/getentropy.c",
    "rand_extra/ios.c",
    "rand_extra/passive.c",
    "rand_extra/rand_extra.c",
    "rand_extra/trusty.c",
    "rand_extra/windows.c",
    "rc4/rc4.c",
    "refcount.c",
    "rsa_extra/rsa_asn1.c",
    "rsa_extra/rsa_crypt.c",
    "rsa_extra/rsa_print.c",
    "stack/stack.c",
    "siphash/siphash.c",
    "thread.c",
    "thread_none.c",
    "thread_pthread.c",
    "thread_win.c",
    "trust_token/pmbtoken.c",
    "trust_token/trust_token.c",
    "trust_token/voprf.c",
    "x509/a_digest.c",
    "x509/a_sign.c",
    "x509/a_verify.c",
    "x509/algorithm.c",
    "x509/asn1_gen.c",
    "x509/by_dir.c",
    "x509/by_file.c",
    "x509/i2d_pr.c",
    "x509/name_print.c",
    "x509/policy.c",
    "x509/rsa_pss.c",
    "x509/t_crl.c",
    "x509/t_req.c",
    "x509/t_x509.c",
    "x509/t_x509a.c",
    "x509/x509.c",
    "x509/x509_att.c",
    "x509/x509_cmp.c",
    "x509/x509_d2.c",
    "x509/x509_def.c",
    "x509/x509_ext.c",
    "x509/x509_lu.c",
    "x509/x509_obj.c",
    "x509/x509_req.c",
    "x509/x509_set.c",
    "x509/x509_trs.c",
    "x509/x509_txt.c",
    "x509/x509_v3.c",
    "x509/x509_vfy.c",
    "x509/x509_vpm.c",
    "x509/x509cset.c",
    "x509/x509name.c",
    "x509/x509rset.c",
    "x509/x509spki.c",
    "x509/x_algor.c",
    "x509/x_all.c",
    "x509/x_attrib.c",
    "x509/x_crl.c",
    "x509/x_exten.c",
    "x509/x_info.c",
    "x509/x_name.c",
    "x509/x_pkey.c",
    "x509/x_pubkey.c",
    "x509/x_req.c",
    "x509/x_sig.c",
    "x509/x_spki.c",
    "x509/x_val.c",
    "x509/x_x509.c",
    "x509/x_x509a.c",
    "x509v3/v3_akey.c",
    "x509v3/v3_akeya.c",
    "x509v3/v3_alt.c",
    "x509v3/v3_bcons.c",
    "x509v3/v3_bitst.c",
    "x509v3/v3_conf.c",
    "x509v3/v3_cpols.c",
    "x509v3/v3_crld.c",
    "x509v3/v3_enum.c",
    "x509v3/v3_extku.c",
    "x509v3/v3_genn.c",
    "x509v3/v3_ia5.c",
    "x509v3/v3_info.c",
    "x509v3/v3_int.c",
    "x509v3/v3_lib.c",
    "x509v3/v3_ncons.c",
    "x509v3/v3_ocsp.c",
    "x509v3/v3_pcons.c",
    "x509v3/v3_pmaps.c",
    "x509v3/v3_prn.c",
    "x509v3/v3_purp.c",
    "x509v3/v3_skey.c",
    "x509v3/v3_utl.c",
};

const ssl_sources: []const []const u8 = &.{
    "bio_ssl.cc",
    "d1_both.cc",
    "d1_lib.cc",
    "d1_pkt.cc",
    "d1_srtp.cc",
    "dtls_method.cc",
    "dtls_record.cc",
    "encrypted_client_hello.cc",
    "extensions.cc",
    "handoff.cc",
    "handshake.cc",
    "handshake_client.cc",
    "handshake_server.cc",
    "s3_both.cc",
    "s3_lib.cc",
    "s3_pkt.cc",
    "ssl_aead_ctx.cc",
    "ssl_asn1.cc",
    "ssl_buffer.cc",
    "ssl_cert.cc",
    "ssl_cipher.cc",
    "ssl_file.cc",
    "ssl_key_share.cc",
    "ssl_lib.cc",
    "ssl_privkey.cc",
    "ssl_session.cc",
    "ssl_stat.cc",
    "ssl_transcript.cc",
    "ssl_versions.cc",
    "ssl_x509.cc",
    "t1_enc.cc",
    "tls_method.cc",
    "tls_record.cc",
    "tls13_both.cc",
    "tls13_client.cc",
    "tls13_enc.cc",
    "tls13_server.cc",
};
