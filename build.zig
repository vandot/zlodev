const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const version = b.option([]const u8, "version", "Version string") orelse "dev";
    const max_entries = b.option(u32, "max-entries", "Max request entries in ring buffer [default 500]") orelse 500;

    // OpenSSL path overrides
    const openssl_include = b.option([]const u8, "openssl-include", "OpenSSL include path override");
    const openssl_lib = b.option([]const u8, "openssl-lib", "OpenSSL library path override");

    const options = b.addOptions();
    options.addOption([]const u8, "version", version);
    options.addOption(u32, "max_entries", max_entries);

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

    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");

    // Windows: link Winsock2 for networking
    if (target.result.os.tag == .windows) {
        exe.linkSystemLibrary("ws2_32");
    }

    // Apply explicit overrides if provided
    if (openssl_include) |inc| {
        exe.addIncludePath(.{ .cwd_relative = inc });
    }
    if (openssl_lib) |lib| {
        exe.addLibraryPath(.{ .cwd_relative = lib });
    }

    // Auto-discover OpenSSL paths when no explicit override is given.
    // linkSystemLibrary already tries pkg-config; these are fallbacks
    // for when pkg-config is unavailable or doesn't know about OpenSSL.
    if (openssl_include == null and openssl_lib == null) {
        discoverOpenSSL(exe, target.result.os.tag);
    }

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run zlodev");
    run_step.dependOn(&run_cmd.step);
}

fn discoverOpenSSL(exe: *std.Build.Step.Compile, os: std.Target.Os.Tag) void {
    switch (os) {
        .macos => {
            // Homebrew (Apple Silicon, Intel) and MacPorts
            const search_paths = [_]struct { inc: []const u8, lib: []const u8 }{
                .{ .inc = "/opt/homebrew/opt/openssl@3/include", .lib = "/opt/homebrew/opt/openssl@3/lib" },
                .{ .inc = "/usr/local/opt/openssl@3/include", .lib = "/usr/local/opt/openssl@3/lib" },
                .{ .inc = "/opt/local/libexec/openssl3/include", .lib = "/opt/local/libexec/openssl3/lib" },
            };
            for (search_paths) |p| {
                if (std.fs.accessAbsolute(p.lib, .{})) |_| {
                    exe.addIncludePath(.{ .cwd_relative = p.inc });
                    exe.addLibraryPath(.{ .cwd_relative = p.lib });
                    return;
                } else |_| {}
            }
        },
        .linux => {
            // Standard distro paths (Debian/Ubuntu, Fedora/RHEL, Alpine, Arch)
            const search_paths = [_]struct { inc: []const u8, lib: []const u8 }{
                .{ .inc = "/usr/include/openssl", .lib = "/usr/lib/x86_64-linux-gnu" },
                .{ .inc = "/usr/include/openssl", .lib = "/usr/lib/aarch64-linux-gnu" },
                .{ .inc = "/usr/include/openssl", .lib = "/usr/lib64" },
                .{ .inc = "/usr/include/openssl", .lib = "/usr/lib" },
            };
            for (search_paths) |p| {
                if (std.fs.accessAbsolute(p.lib, .{})) |_| {
                    exe.addIncludePath(.{ .cwd_relative = p.inc });
                    exe.addLibraryPath(.{ .cwd_relative = p.lib });
                    return;
                } else |_| {}
            }
        },
        .windows => {
            // vcpkg, Chocolatey, Strawberry Perl, and MSYS2
            const search_paths = [_]struct { inc: []const u8, lib: []const u8 }{
                .{ .inc = "C:\\vcpkg\\installed\\x64-windows\\include", .lib = "C:\\vcpkg\\installed\\x64-windows\\lib" },
                .{ .inc = "C:\\Program Files\\OpenSSL-Win64\\include", .lib = "C:\\Program Files\\OpenSSL-Win64\\lib" },
                .{ .inc = "C:\\Program Files\\OpenSSL\\include", .lib = "C:\\Program Files\\OpenSSL\\lib" },
                .{ .inc = "C:\\Strawberry\\c\\include", .lib = "C:\\Strawberry\\c\\lib" },
                .{ .inc = "C:\\msys64\\mingw64\\include", .lib = "C:\\msys64\\mingw64\\lib" },
            };
            for (search_paths) |p| {
                if (std.fs.accessAbsolute(p.lib, .{})) |_| {
                    exe.addIncludePath(.{ .cwd_relative = p.inc });
                    exe.addLibraryPath(.{ .cwd_relative = p.lib });
                    return;
                } else |_| {}
            }
        },
        else => {},
    }
}
