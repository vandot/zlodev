const std = @import("std");
const builtin = @import("builtin");
const dns = @import("dns.zig");
const cert = @import("cert.zig");
const proxy = @import("proxy.zig");
const http_server = @import("http_server.zig");
const log = @import("log.zig");
const sys = @import("sys.zig");
const tui = @import("tui.zig");
const shutdown = @import("shutdown.zig");
const intercept = @import("intercept.zig");
const subprocess = @import("subprocess.zig");
const cli = @import("cli.zig");
const build_options = @import("build_options");

const version = build_options.version;

const Command = enum {
    none,
    install,
    start,
    uninstall,
};

pub const panic = tui.panic;

const compat = @import("compat.zig");
const rt = @import("rt.zig");
const tunnel = @import("tunnel.zig");
const share = @import("share.zig");

pub fn main(init: std.process.Init) !void {
    compat.initNetworking();

    // One Threaded Io for the whole process. Worker counts are capped by the
    // proxy (64) and HTTP (8) atomic counters, not here: a global limit would
    // also count io.async work (e.g. HostName.connect) and could refuse
    // connections on many-core machines. Worker stacks match the old pool.
    var threaded: std.Io.Threaded = .init(init.gpa, .{
        .stack_size = if (builtin.cpu.arch == .x86_64) 4 * 1024 * 1024 else 1024 * 1024,
        .concurrent_limit = .unlimited,
        .environ = init.minimal.environ,
        .argv0 = .init(init.minimal.args),
    });
    defer threaded.deinit();
    rt.setIo(threaded.io());
    rt.env_map = init.environ_map;

    const allocator = init.gpa;

    var command: Command = .none;
    var local = false;
    var force = false;
    var port_set = false;
    var target_port: u16 = 3000;
    var bind_addr: []const u8 = "0.0.0.0";
    var bind_set = false;
    // Set when -b/--bind or a config `bind=` chose the address; otherwise the
    // default 0.0.0.0 (needed for sudo-less :80/:443 on macOS) serves loopback only.
    var bind_explicit = false;
    var no_tui: bool = false;
    var no_tui_set = false;
    var insecure_upstream = false;
    var share_on = false;
    var dns_only: bool = false;
    var cert_only: bool = false;
    var max_body: usize = proxy.default_max_request_body;
    var max_body_set = false;
    var timeout_s: u32 = proxy.default_upstream_timeout_s;
    var timeout_set = false;
    var routes: [proxy.max_routes]proxy.Route = undefined;
    var route_count: usize = 0;
    defer for (routes[0..route_count]) |route| {
        allocator.free(route.pattern);
        if (route.hostname) |h| allocator.free(h);
    };
    var config_path: ?[]const u8 = null;
    var command_str: ?[]const u8 = null;
    var command_set = false;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.skip(); // skip program name

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "install")) {
            command = .install;
        } else if (std.mem.eql(u8, arg, "start")) {
            command = .start;
        } else if (std.mem.eql(u8, arg, "uninstall")) {
            command = .uninstall;
        } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--local")) {
            local = true;
        } else if (takeFlag(arg, "-p", "--port", &args)) |val| {
            target_port = std.fmt.parseInt(u16, val, 10) catch {
                std.debug.print("invalid port value: {s}\n", .{val});
                std.process.exit(1);
            };
            port_set = true;
        } else if (takeFlag(arg, "-b", "--bind", &args)) |val| {
            bind_addr = val;
            bind_set = true;
            bind_explicit = true;
        } else if (takeFlag(arg, null, "--max-body", &args)) |val| {
            max_body = cli.parseSize(val) orelse {
                std.debug.print("invalid max-body value: {s}\n", .{val});
                std.process.exit(1);
            };
            max_body_set = true;
        } else if (takeFlag(arg, null, "--timeout", &args)) |val| {
            timeout_s = proxy.parseTimeoutSeconds(val) orelse {
                std.debug.print("invalid timeout value: {s}\n", .{val});
                std.process.exit(1);
            };
            timeout_set = true;
        } else if (takeFlag(arg, null, "--route", &args)) |val| {
            addRoute(allocator, &routes, &route_count, val);
        } else if (takeFlag(arg, "-c", "--config", &args)) |val| {
            config_path = val;
        } else if (std.mem.eql(u8, arg, "--no-tui")) {
            no_tui = true;
            no_tui_set = true;
        } else if (std.mem.eql(u8, arg, "--insecure-upstream")) {
            insecure_upstream = true;
        } else if (std.mem.eql(u8, arg, "--share")) {
            share_on = true;
        } else if (std.mem.eql(u8, arg, "--dns")) {
            dns_only = true;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            cert_only = true;
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
            force = true;
        } else if (takeFlag(arg, null, "--command", &args)) |val| {
            command_str = val;
            command_set = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            std.debug.print("zlodev-{s}\n", .{version});
            return;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printHelp();
            return;
        } else {
            std.debug.print("unknown argument: {s}\n", .{arg});
            printHelp();
            std.process.exit(1);
        }
    }

    // Read config file for start command — config values are defaults, CLI args override
    if (command == .start) {
        const cfg_path = config_path orelse ".zlodev";
        if (readConfigFile(allocator, cfg_path, &routes, &route_count)) |cfg| {
            if (!port_set) if (cfg.port) |p| {
                target_port = p;
                port_set = true;
            };
            if (!bind_set) {
                if (cfg.bind) |b| {
                    bind_addr = b;
                    bind_explicit = true;
                }
            } else {
                // CLI override used — free config bind if allocated
                if (cfg.bind) |b| {
                    allocator.free(b);
                }
            }
            if (!no_tui_set and cfg.no_tui) no_tui = true;
            if (cfg.insecure_upstream) insecure_upstream = true;
            if (cfg.share) share_on = true;
            if (!max_body_set) if (cfg.max_body) |mb| {
                max_body = mb;
            };
            if (!timeout_set) if (cfg.timeout) |t| {
                timeout_s = t;
            };
            if (cfg.local) local = true;
            if (cfg.dns) dns_only = true;
            if (cfg.intercept_pattern) |pat| intercept.enableWithPattern(pat);
            if (!command_set) if (cfg.command) |c| {
                command_str = c;
            };
        } else |_| {
            if (config_path != null) {
                std.debug.print("config file not found: {s}\n", .{cfg_path});
                std.process.exit(1);
            }
        }
    }

    // When using --dns with start, no other options apply
    if (command == .start and dns_only) {
        if (share_on) {
            std.debug.print("--share cannot be combined with --dns\n", .{});
            std.process.exit(1);
        }
        if (port_set or bind_set or no_tui_set or max_body_set or timeout_set or route_count > 0 or insecure_upstream) {
            std.debug.print("--dns cannot be combined with other start options\n", .{});
            std.process.exit(1);
        }
    }

    // Validate command option
    if (command_str) |cmd| {
        const trimmed = std.mem.trim(u8, cmd, " \t");
        if (trimmed.len == 0) {
            std.debug.print("--command value cannot be empty\n", .{});
            std.process.exit(1);
        }
        if (cmd.len > subprocess.max_command_len) {
            std.debug.print("--command is longer than {d} bytes\n", .{subprocess.max_command_len});
            std.process.exit(1);
        }
        if (dns_only) {
            std.debug.print("--command cannot be combined with --dns\n", .{});
            std.process.exit(1);
        }
        if (no_tui) {
            std.debug.print("--command cannot be combined with --no-tui\n", .{});
            std.process.exit(1);
        }
    }

    const tld: []const u8 = if (local) "local" else "lo";

    // In local mode, use hostname.local for mDNS access from other devices
    var domain_allocated = false;
    var full_domain: []const u8 = "dev.lo";
    if (local) {
        var hostname_buf: [hostname_max]u8 = undefined;
        const hostname = getHostname(&hostname_buf);
        full_domain = try std.fmt.allocPrint(allocator, "{s}.local", .{hostname});
        domain_allocated = true;
    }
    defer if (domain_allocated) allocator.free(full_domain);

    // Subdomain routes are not allowed in local mode
    if (local) {
        for (routes[0..route_count]) |route| {
            if (route.kind == .subdomain) {
                std.debug.print("subdomain routes are not supported in local mode (-l): {s}\n", .{route.pattern});
                std.process.exit(1);
            }
        }
    }

    // Auto-detect port if not explicitly set
    if (!port_set) {
        target_port = detectPort();
    }

    switch (command) {
        .install => {
            if (dns_only and cert_only) {
                std.debug.print("--dns and --cert are mutually exclusive\n", .{});
                std.process.exit(1);
            }
            if (dns_only) {
                try doInstallDns(allocator, tld);
            } else if (cert_only) {
                try doInstallCert(allocator, full_domain, force);
            } else {
                try doInstall(allocator, full_domain, local, tld, force);
            }
        },
        .start => {
            if (dns_only) {
                try doStartDns(tld);
            } else {
                try doStart(allocator, full_domain, local, tld, target_port, bind_addr, !local and !bind_explicit, no_tui, max_body, routes[0..route_count], command_str, insecure_upstream, timeout_s, share_on);
            }
        },
        .uninstall => {
            if (dns_only and cert_only) {
                std.debug.print("--dns and --cert are mutually exclusive\n", .{});
                std.process.exit(1);
            }
            if (dns_only) {
                try doUninstallDns(allocator, tld);
            } else if (cert_only) {
                try doUninstallCert(allocator, full_domain);
            } else {
                try doUninstall(allocator, full_domain, local, tld);
            }
        },
        .none => {
            printHelp();
        },
    }
}

fn doInstall(allocator: std.mem.Allocator, full_domain: []const u8, local: bool, tld: []const u8, force: bool) !void {
    // Refuse before touching anything, so -f doesn't remove a working install first.
    if (builtin.os.tag == .linux) {
        try requireSystemdResolved(allocator);
        if (!local) requireLinuxBackend(allocator);
    }

    // Check if certificates already exist
    if (cert.caExists(full_domain)) {
        if (!force) {
            std.debug.print("certificates already installed, use -f/--force to overwrite\n", .{});
            std.process.exit(1);
        }
        // Force: uninstall existing first
        doUninstall(allocator, full_domain, local, tld) catch |e| {
            std.debug.print("warning: failed to uninstall existing certificates: {any}\n", .{e});
        };
    }

    switch (builtin.os.tag) {
        .macos => {
            // Validate LocalHostName == HostName
            const local_result = try runCmdOutput(allocator, &.{ "scutil", "--get", "LocalHostName" });
            defer allocator.free(local_result);
            const host_result = try runCmdOutput(allocator, &.{ "scutil", "--get", "HostName" });
            defer allocator.free(host_result);
            const local_name = std.mem.trim(u8, local_result, "\n\r ");
            const host_name = std.mem.trim(u8, host_result, "\n\r ");
            if (!std.mem.eql(u8, local_name, host_name)) {
                std.debug.print("LocalHostName and HostName must be the same, checkout README.md\n", .{});
                std.process.exit(1);
            }
        },
        .linux => {
            // Check avahi for mDNS config
            const avahi_result = try runCmdOutput(allocator, &.{ "systemctl", "is-active", "avahi-daemon.service" });
            defer allocator.free(avahi_result);
            const avahi = std.mem.trim(u8, avahi_result, "\n\r ");

            if (!std.mem.eql(u8, avahi, "active")) {
                // Configure systemd-resolved for mDNS
                const resolved_conf = "[Resolve]\nMulticastDNS=yes\nLLMNR=no";
                const tmp_conf = try sys.writeTmpFile(allocator, "resolved_conf", resolved_conf);
                defer allocator.free(tmp_conf);
                defer sys.removeTmpFile(tmp_conf);
                try sys.sudoCmd(allocator, &.{ "sudo", "mkdir", "-p", "/etc/systemd/resolved.conf.d" });
                try sys.sudoCmd(allocator, &.{ "sudo", "install", "-m", "644", tmp_conf, "/etc/systemd/resolved.conf.d/zlodev.conf" });
                sys.sudoCmd(allocator, &.{ "sudo", "systemctl", "restart", "systemd-resolved.service" }) catch {};
            }
        },
        else => {},
    }

    // Install CA certificate
    try cert.installCA(allocator, full_domain);

    // Install DNS (not needed in .local mode — mDNS handles resolution)
    if (!local) {
        const probe = dns.systemProbe();
        try dns.install(allocator, probe.ip, probe.port, tld);
    }
}

fn doInstallDns(allocator: std.mem.Allocator, tld: []const u8) !void {
    if (builtin.os.tag == .linux) {
        try requireSystemdResolved(allocator);
        requireLinuxBackend(allocator);
    }
    const probe = dns.systemProbe();
    try dns.install(allocator, probe.ip, probe.port, tld);
}

/// Linux DNS setup needs networkd or NetworkManager to create zlodev0; refuse
/// before anything is installed (the CA would otherwise be left trusted).
fn requireLinuxBackend(allocator: std.mem.Allocator) void {
    if (dns.detectLinuxBackend(allocator) == null) {
        std.debug.print("linux DNS setup needs systemd-networkd or NetworkManager to be running\n", .{});
        std.process.exit(1);
    }
}

/// Linux DNS setup goes through systemd-resolved; refuse early otherwise
/// rather than writing config nothing reads.
fn requireSystemdResolved(allocator: std.mem.Allocator) !void {
    const systemd_result = try runCmdOutput(allocator, &.{ "ps", "--no-headers", "-o", "comm", "1" });
    defer allocator.free(systemd_result);
    const resolved_result = try runCmdOutput(allocator, &.{ "systemctl", "is-active", "systemd-resolved.service" });
    defer allocator.free(resolved_result);
    if (!dns.systemdResolvedReady(systemd_result, resolved_result)) {
        std.debug.print("linux initialization is supported only for systemd using systemd-resolved\n", .{});
        std.process.exit(1);
    }
}

fn doInstallCert(allocator: std.mem.Allocator, full_domain: []const u8, force: bool) !void {
    if (cert.caExists(full_domain)) {
        if (!force) {
            std.debug.print("certificates already installed, use -f/--force to overwrite\n", .{});
            std.process.exit(1);
        }
        cert.uninstallCA(allocator, full_domain) catch |e| {
            std.debug.print("warning: failed to uninstall existing certificates: {any}\n", .{e});
        };
    }
    try cert.installCA(allocator, full_domain);
}

/// Linux: why .lo may not resolve (DNS set up by an older zlodev or not at
/// all), or null. Printed at start; the TUI also shows it, since its alt screen
/// hides stderr.
fn linuxDnsSetupWarning() ?[]const u8 {
    if (builtin.os.tag != .linux) return null;
    const allocator = std.heap.page_allocator;
    const contents: ?[]u8 = std.Io.Dir.cwd().readFileAlloc(rt.io(), "/etc/systemd/network/zlodev0.network", allocator, .limited(4096)) catch null;
    defer if (contents) |c| allocator.free(c);
    const link_exists = if (std.Io.Dir.accessAbsolute(rt.io(), "/sys/class/net/zlodev0", .{})) |_| true else |_| false;
    const msg = dns.linuxDnsWarning(contents, link_exists) orelse return null;
    std.debug.print("warning: {s}\n", .{msg});
    return msg;
}

fn doStartDns(tld: []const u8) !void {
    // Warn if DNS resolver is not installed
    switch (builtin.os.tag) {
        .macos => {
            var path_buf: [256]u8 = undefined;
            const resolver_path = std.fmt.bufPrint(&path_buf, "/etc/resolver/{s}", .{tld}) catch "";
            std.Io.Dir.accessAbsolute(rt.io(), resolver_path, .{}) catch {
                std.debug.print("warning: DNS resolver not installed, run 'zlodev install --dns' first\n", .{});
            };
        },
        .linux => _ = linuxDnsSetupWarning(),
        .windows => {
            std.debug.print("note: ensure DNS is installed ('zlodev install --dns') and run in an elevated terminal\n", .{});
        },
        else => {},
    }
    const probe = dns.systemProbe();
    const dns_sock = dns.bind(probe.ip, probe.port) catch |e| exitBindError("DNS", probe.ip, probe.port, e);
    log.info("component=dns op=listening ip={s} port={d} tld={s}", .{ probe.ip, probe.port, tld });
    dns.serve(dns_sock, probe.ip, probe.port, tld);
}

/// Print why a listener could not be bound and exit. Called before the TUI
/// opens, so the message stays visible instead of being hidden by the alt screen.
fn exitBindError(service: []const u8, ip: []const u8, port: u16, e: anyerror) noreturn {
    switch (e) {
        error.AddressInUse => std.debug.print(
            "cannot start: {s} port {s}:{d} is already in use by another process\n",
            .{ service, ip, port },
        ),
        error.AddressNotAvailable => {
            const hint: []const u8 = if (builtin.os.tag == .linux and std.mem.eql(u8, service, "DNS"))
                "the zlodev0 interface is missing, run 'zlodev install --dns'"
            else
                "no network interface has this address";
            std.debug.print("cannot start: {s} address {s}:{d} is not available ({s})\n", .{ service, ip, port, hint });
        },
        error.AccessDenied, error.PermissionDenied => {
            const hint: []const u8 = switch (builtin.os.tag) {
                .windows => "run in an elevated terminal",
                .linux => "run: sudo setcap cap_net_bind_service=+eip $(which zlodev)",
                else => "check that no firewall or security policy blocks it",
            };
            std.debug.print("cannot start: permission denied binding {s} port {s}:{d} ({s})\n", .{ service, ip, port, hint });
        },
        else => std.debug.print("cannot start: failed to bind {s} port {s}:{d}: {any}\n", .{ service, ip, port, e }),
    }
    std.process.exit(1);
}

fn doStart(
    allocator: std.mem.Allocator,
    full_domain: []const u8,
    local: bool,
    tld: []const u8,
    target_port: u16,
    bind_addr: []const u8,
    loopback_only: bool,
    no_tui: bool,
    max_request_body: usize,
    routes: []const proxy.Route,
    command: ?[]const u8,
    insecure_upstream: bool,
    upstream_timeout_s: u32,
    share_on: bool,
) !void {
    var cf_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var cloudflared_path: []const u8 = "";
    if (share_on) {
        cloudflared_path = tunnel.preflight(&cf_buf) catch |e| {
            switch (e) {
                error.CloudflaredNotFound => std.debug.print("--share needs cloudflared, which was not found on PATH. Install: {s}\n", .{tunnel.installHint()}),
                error.CloudflaredConfigPresent => {
                    const home = if (rt.env_map) |env| (env.get(if (builtin.os.tag == .windows) "USERPROFILE" else "HOME") orelse "") else "";
                    var cfg_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
                    const cfg = tunnel.findConfigFile(home, &cfg_buf) orelse "its config file";
                    std.debug.print("--share runs a Cloudflare quick tunnel, which cloudflared refuses while {s} exists. Move it aside and retry.\n", .{cfg});
                },
            }
            std.process.exit(1);
        };
    }
    // Check if another instance is already running
    if (isPortListening(bind_addr, 443)) {
        std.debug.print("port 443 is already in use — is another zlodev instance running?\n", .{});
        std.process.exit(1);
    }
    if (isPortListening(bind_addr, 80)) {
        std.debug.print("port 80 is already in use — is another zlodev instance running?\n", .{});
        std.process.exit(1);
    }

    // Renew the leaf from the kept CA when it's close to expiry (no sudo needed).
    var cert_warning_buf: [cert.cert_warning_len]u8 = undefined;
    const cert_warning = cert.ensureLeaf(allocator, full_domain, &cert_warning_buf) catch |e| {
        switch (e) {
            error.CaExpired => std.debug.print("CA expired, run 'zlodev install -f'\n", .{}),
            error.CaNotFound => std.debug.print("certificates not found, run 'zlodev install' first\n", .{}),
            error.CaKeyNotFound => std.debug.print("CA key missing or unreadable, run 'zlodev install -f'\n", .{}),
            else => std.debug.print("certificate renewal failed ({s}), run 'zlodev install -f'\n", .{@errorName(e)}),
        }
        std.process.exit(1);
    };

    // Get certificate paths
    var cert_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var key_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const certs = cert.getCert(&cert_buf, &key_buf, full_domain) catch {
        std.debug.print("certificates not found, run 'zlodev install' first\n", .{});
        std.process.exit(1);
    };

    // Get CA paths for HTTP server and proxy
    var ca_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const ca_path = cert.getCaPath(&ca_buf, full_domain) catch {
        std.debug.print("CA certificate not found, run 'zlodev install' first\n", .{});
        std.process.exit(1);
    };
    var ca_der_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const ca_der_path = cert.getCaDerPath(&ca_der_buf, full_domain) catch {
        std.debug.print("CA DER certificate not found, run 'zlodev install' first\n", .{});
        std.process.exit(1);
    };

    // We need null-terminated paths for OpenSSL
    const cert_path_z = try allocator.dupeSentinel(u8, certs.cert, 0);
    defer allocator.free(cert_path_z);
    const key_path_z = try allocator.dupeSentinel(u8, certs.key, 0);
    defer allocator.free(key_path_z);
    const ca_path_z = try allocator.dupeSentinel(u8, ca_path, 0);
    defer allocator.free(ca_path_z);

    // Make owned copies for threads (freed after TUI exits, process is terminating)
    const domain_owned = try allocator.dupe(u8, full_domain);
    defer allocator.free(domain_owned);
    const ca_pem_owned = try allocator.dupe(u8, ca_path);
    defer allocator.free(ca_pem_owned);
    const ca_der_owned = try allocator.dupe(u8, ca_der_path);
    defer allocator.free(ca_der_owned);
    const tld_owned = try allocator.dupe(u8, tld);
    defer allocator.free(tld_owned);
    const bind_owned = try allocator.dupe(u8, bind_addr);
    defer allocator.free(bind_owned);

    const dns_warning: ?[]const u8 = if (local) null else linuxDnsSetupWarning();

    // Bind every listener before the TUI takes over the terminal, so a port
    // conflict is reported on the normal screen and zlodev exits instead of
    // running half-started.
    const probe = dns.systemProbe();
    const dns_sock: ?compat.socket_t = if (local) null else dns.bind(probe.ip, probe.port) catch |e|
        exitBindError("DNS", probe.ip, probe.port, e);
    const http_listener = http_server.listen(bind_owned) catch |e| exitBindError("HTTP", bind_owned, 80, e);
    const https_listener = proxy.listen(bind_owned) catch |e| exitBindError("HTTPS", bind_owned, 443, e);

    // Install signal handlers before spawning anything
    shutdown.installSignalHandlers();

    // Mute logging before spawning threads when TUI is active,
    // so server startup messages go to log file instead of stderr
    // (otherwise they leak through when the TUI alt screen is restored on exit).
    if (!no_tui) {
        log.initLogFile();
        log.mute();
    }

    // Start DNS server (not needed in .local mode — mDNS handles resolution)
    var dns_thread: ?std.Thread = null;
    if (dns_sock) |sock| {
        dns_thread = try std.Thread.spawn(.{}, struct {
            fn run(s: compat.socket_t, ip: []const u8, port: u16, t: []const u8) void {
                dns.serve(s, ip, port, t);
            }
        }.run, .{ sock, probe.ip, probe.port, tld_owned });
    }

    // Start HTTP server
    const http_thread = try std.Thread.spawn(.{}, struct {
        fn run(l: compat.socket_t, addr: []const u8, lo_only: bool, d: []const u8, ca_pem: []const u8, ca_der: []const u8) void {
            http_server.serve(l, addr, lo_only, d, ca_pem, ca_der);
        }
    }.run, .{ http_listener, bind_owned, loopback_only, domain_owned, ca_pem_owned, ca_der_owned });

    // Start HTTPS proxy on its own thread
    const config = proxy.ProxyConfig{
        .target_host = "127.0.0.1",
        .target_port = target_port,
        .listen_addr = bind_owned,
        .loopback_only = loopback_only,
        .cert_path = cert_path_z,
        .key_path = key_path_z,
        .ca_path = ca_path_z,
        .server_ident = "zlodev",
        .max_request_body = max_request_body,
        .routes = routes,
        .domain = domain_owned,
        .insecure_upstream = insecure_upstream,
        .upstream_timeout_s = upstream_timeout_s,
    };
    if (insecure_upstream) {
        std.debug.print("warning: --insecure-upstream: certificates of external routes are not verified\n", .{});
        log.err("component=main op=start insecure_upstream=true", .{});
    }
    const proxy_thread = try std.Thread.spawn(.{}, struct {
        fn run(cfg: *const proxy.ProxyConfig, l: compat.socket_t) void {
            proxy.start(cfg, l) catch |e| {
                log.err("component=proxy op=start error={any}", .{e});
            };
        }
    }.run, .{ &config, https_listener });

    // Start subprocess if command is configured
    if (command) |cmd| {
        subprocess.start(allocator, cmd) catch |e| {
            log.err("component=subprocess op=start error={any}", .{e});
        };
    }

    var tunnel_started = false;
    defer if (tunnel_started) tunnel.stop();
    if (share_on) {
        std.debug.print("warning: --share makes your dev server reachable by anyone with the URL\n", .{});
        for (routes) |route| {
            if (route.hostname) |h| {
                if (route.kind == .path) {
                    std.debug.print("  public visitors can reach: {s} -> {s}:{d}\n", .{ route.pattern, h, route.port });
                }
            }
        }
        var target_buf: [128]u8 = undefined;
        if (tunnel.start(cloudflared_path, tunnel.targetAddr(bind_owned, &target_buf))) |_| {
            tunnel_started = true;
        } else |e| {
            log.err("component=tunnel op=start error={any}", .{e});
            if (!no_tui) std.debug.print("cloudflared failed to start: {s}\n", .{@errorName(e)});
            var rbuf: [96]u8 = undefined;
            share.fail(std.fmt.bufPrint(&rbuf, "cloudflared failed to start: {s}", .{@errorName(e)}) catch "cloudflared failed to start");
        }
    }

    if (no_tui) {
        log.info("component=main op=running domain={s} target=127.0.0.1:{d} routes={d}", .{ full_domain, target_port, routes.len });
        for (routes) |route| {
            const kind_str: []const u8 = if (route.kind == .subdomain) "subdomain" else "path";
            log.info("component=main route kind={s} pattern={s} port={d}", .{ kind_str, route.pattern, route.port });
        }
        var last_status: share.Status = .off;
        while (shutdown.isRunning()) {
            rt.sleepMs(100);
            if (share_on) {
                share.checkTimeout(rt.milliTimestamp());
                const snap = share.snapshot();
                if (snap.status != last_status) {
                    last_status = snap.status;
                    switch (snap.status) {
                        .ready => {
                            var out_buf: [share.max_host_len + 32]u8 = undefined;
                            if (std.fmt.bufPrint(&out_buf, "share: https://{s}\n", .{snap.getHost()})) |line| {
                                std.Io.File.stdout().writeStreamingAll(rt.io(), line) catch {};
                            } else |_| {}
                        },
                        .failed, .exited => std.debug.print("share: {s}\n", .{snap.getReason()}),
                        .verifying => {},
                        else => {},
                    }
                }
            }
        }
    } else {
        // Run TUI on main thread (blocks until user quits)
        tui.run(allocator, full_domain, target_port, routes, command != null, cert_warning, dns_warning, version) catch |e| {
            log.unmute();
            log.err("component=tui op=start error={any}", .{e});
        };
        log.unmute();
        log.deinitLogFile();
    }

    // Signal all server loops to stop and wait for them
    shutdown.requestShutdown();
    if (share_on) tunnel.stop();
    if (command != null) subprocess.stop();
    proxy_thread.join();
    http_thread.join();
    if (dns_thread) |dt| dt.join();
}

fn doUninstallDns(allocator: std.mem.Allocator, tld: []const u8) !void {
    try dns.uninstall(allocator, tld);
}

fn doUninstallCert(allocator: std.mem.Allocator, full_domain: []const u8) !void {
    try cert.uninstallCA(allocator, full_domain);
}

fn doUninstall(allocator: std.mem.Allocator, full_domain: []const u8, local: bool, tld: []const u8) !void {
    if (!local) {
        try dns.uninstall(allocator, tld);
    }

    switch (builtin.os.tag) {
        .linux => {
            if (local) {
                const avahi_result = try runCmdOutput(allocator, &.{ "systemctl", "is-active", "avahi-daemon.service" });
                defer allocator.free(avahi_result);
                const avahi = std.mem.trim(u8, avahi_result, "\n\r ");

                if (!std.mem.eql(u8, avahi, "active")) {
                    sys.sudoCmd(allocator, &.{ "sudo", "rm", "-f", "/etc/systemd/resolved.conf.d/zlodev.conf" }) catch {};
                    sys.sudoCmd(allocator, &.{ "sudo", "systemctl", "restart", "systemd-resolved.service" }) catch {};
                }
            }
        },
        else => {},
    }

    try cert.uninstallCA(allocator, full_domain);
}

fn printHelp() void {
    std.debug.print(
        \\zlodev-{s}
        \\  Run local reverse proxy server with SSL termination
        \\  and custom DNS resolver.
        \\
        \\Commands:
        \\  install              install certificates and DNS
        \\  install --cert       install certificates only
        \\  install --dns        install DNS only
        \\  uninstall            uninstall certificates and DNS
        \\  uninstall --cert     uninstall certificates only
        \\  uninstall --dns      uninstall DNS only
        \\  start                start service (proxy + DNS + TUI)
        \\  start --dns          start DNS server only (log mode)
        \\
        \\Options:
        \\  -p=PORT, --port=PORT       target port [auto-detect or 3000]
        \\  -b=ADDR, --bind=ADDR       listen address [default 0.0.0.0, local clients only]
        \\  --route=PATTERN=TARGET     route by subdomain or path (repeatable)
        \\  -c=PATH, --config=PATH     config file path [default .zlodev]
        \\  --max-body=SIZE            max request body size [default 10M]
        \\  --timeout=SECONDS          upstream connect/response timeout [default 30, 0 = none]
        \\  --command=CMD              run CMD as subprocess (stopped on exit)
        \\  --no-tui                   disable TUI, log to stderr
        \\  --insecure-upstream        don't verify external route certificates
        \\  --share                    public URL via Cloudflare quick tunnel (needs cloudflared)
        \\                             (URL changes each run; no SSE; anyone with the URL can reach your app)
        \\  -l, --local                use .local domain (mDNS)
        \\  --dns                      DNS only (install/uninstall/start)
        \\  --cert                     certificates only (install/uninstall)
        \\  -f, --force                force reinstall
        \\  -h, --help                 show help
        \\  -v, --version              show version
        \\
        \\Config file (.zlodev):
        \\  Place a .zlodev file in your project directory, one option per line:
        \\    port=3000
        \\    bind=127.0.0.1
        \\    route=api=3001
        \\    route=/api=3000
        \\    intercept=POST /api
        \\    command=npm run dev
        \\    no-tui
        \\    insecure-upstream
        \\    share
        \\    timeout=60
        \\  CLI arguments override config file values.
        \\
        \\Routes:
        \\  --route=api=3001              subdomain: api.dev.lo -> localhost:3001
        \\  --route=/api=3001             path:      dev.lo/api/* -> localhost:3001
        \\  --route=api=example.com       external:  api.dev.lo -> example.com:443
        \\  --route=api=example.com:8080  external:  api.dev.lo -> example.com:8080
        \\  Subdomain routes are not allowed in local mode (-l).
        \\  Priority: subdomain > longest path > default port
        \\
        \\SIZE accepts suffixes: K (KB), M (MB), G (GB). Example: --max-body=50M
        \\Value options also accept a space: --port 3000
        \\
    , .{version});
}

/// Value of a value flag, from `--flag=value` or the next argument; exits 1 when
/// the flag ends the command line.
fn takeFlag(arg: []const u8, short: ?[]const u8, long: []const u8, args: anytype) ?[]const u8 {
    return switch (cli.matchFlag(arg, short, long)) {
        .none => null,
        .value => |v| v,
        .needs_next => args.next() orelse {
            std.debug.print("missing value for {s}\n", .{long});
            std.process.exit(1);
        },
    };
}

fn detectPort() u16 {
    // 1. Check .env for PORT=
    if (readEnvPort()) |port| return port;

    // 2. Detect framework by config file
    const checks = [_]struct { file: []const u8, port: u16 }{
        // JS/TS frameworks
        .{ .file = "next.config.js", .port = 3000 },
        .{ .file = "next.config.mjs", .port = 3000 },
        .{ .file = "next.config.ts", .port = 3000 },
        .{ .file = "nuxt.config.js", .port = 3000 },
        .{ .file = "nuxt.config.ts", .port = 3000 },
        .{ .file = "remix.config.js", .port = 3000 },
        .{ .file = "astro.config.mjs", .port = 4321 },
        .{ .file = "astro.config.ts", .port = 4321 },
        .{ .file = "vite.config.js", .port = 5173 },
        .{ .file = "vite.config.ts", .port = 5173 },
        .{ .file = "svelte.config.js", .port = 5173 },
        .{ .file = "angular.json", .port = 4200 },
        .{ .file = "vue.config.js", .port = 8080 },
        // Python
        .{ .file = "manage.py", .port = 8000 },
        // Ruby
        .{ .file = "config.ru", .port = 3000 },
        .{ .file = "Gemfile", .port = 3000 },
        // Go
        .{ .file = "go.mod", .port = 8080 },
        // Rust
        .{ .file = "Cargo.toml", .port = 8080 },
        // PHP
        .{ .file = "artisan", .port = 8000 },
        .{ .file = "composer.json", .port = 8000 },
        // Elixir
        .{ .file = "mix.exs", .port = 4000 },
    };

    const cwd = std.Io.Dir.cwd();
    for (checks) |check| {
        if (cwd.access(rt.io(), check.file, .{})) |_| {
            return check.port;
        } else |_| {}
    }

    return 3000;
}

fn readEnvPort() ?u16 {
    var buf: [4096]u8 = undefined;
    const content = std.Io.Dir.cwd().readFile(rt.io(), ".env", &buf) catch return null;

    var iter = std.mem.splitScalar(u8, content, '\n');
    while (iter.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (std.mem.startsWith(u8, trimmed, "PORT=")) {
            const val = std.mem.trim(u8, trimmed["PORT=".len..], " \t\"'");
            return std.fmt.parseInt(u16, val, 10) catch null;
        }
    }
    return null;
}

const hostname_max = if (builtin.os.tag == .windows) 256 else std.posix.HOST_NAME_MAX;

fn getHostname(buf: *[hostname_max]u8) []const u8 {
    if (builtin.os.tag == .windows) {
        const name = compat.getenv("COMPUTERNAME") orelse return "localhost";
        const len = @min(name.len, buf.len);
        @memcpy(buf[0..len], name[0..len]);
        return buf[0..len];
    }
    return std.posix.gethostname(buf) catch "localhost";
}

fn isPortListening(bind_addr: []const u8, port: u16) bool {
    const addr = std.Io.net.IpAddress.parse(bind_addr, port) catch return false;
    const sock = compat.tcpConnect(addr) catch return false;
    compat.closeSocket(sock);
    return true;
}

fn addRoute(allocator: std.mem.Allocator, routes: *[proxy.max_routes]proxy.Route, route_count: *usize, val: []const u8) void {
    if (route_count.* >= proxy.max_routes) {
        std.debug.print("too many routes (max {d})\n", .{proxy.max_routes});
        std.process.exit(1);
    }
    if (std.mem.lastIndexOfScalar(u8, val, '=')) |eq| {
        const pattern = val[0..eq];
        const target = val[eq + 1 ..];
        if (pattern.len == 0) {
            std.debug.print("empty route pattern in: {s}\n", .{val});
            std.process.exit(1);
        }
        if (target.len == 0) {
            std.debug.print("empty route target in: {s}\n", .{val});
            std.process.exit(1);
        }

        // Try parsing as a plain port number (local route)
        if (std.fmt.parseInt(u16, target, 10)) |rport| {
            routes[route_count.*] = .{
                .kind = if (pattern[0] == '/') .path else .subdomain,
                .pattern = allocator.dupe(u8, pattern) catch oom(),
                .port = rport,
            };
        } else |_| {
            // External host — parse host:port or host (default 443)
            var hostname: []const u8 = target;
            var rport: u16 = 443;
            if (std.mem.lastIndexOfScalar(u8, target, ':')) |colon| {
                rport = std.fmt.parseInt(u16, target[colon + 1 ..], 10) catch {
                    std.debug.print("invalid route port in: {s}\n", .{target});
                    std.process.exit(1);
                };
                hostname = target[0..colon];
            }
            if (hostname.len == 0) {
                std.debug.print("empty hostname in route: {s}\n", .{val});
                std.process.exit(1);
            }
            routes[route_count.*] = .{
                .kind = if (pattern[0] == '/') .path else .subdomain,
                .pattern = allocator.dupe(u8, pattern) catch oom(),
                .port = rport,
                .hostname = allocator.dupe(u8, hostname) catch oom(),
            };
        }
        route_count.* += 1;
    } else {
        std.debug.print("invalid route format, expected PATTERN=PORT or PATTERN=HOST:PORT: {s}\n", .{val});
        std.process.exit(1);
    }
}

fn oom() noreturn {
    std.debug.print("out of memory\n", .{});
    std.process.exit(1);
}

const ConfigResult = struct {
    port: ?u16 = null,
    bind: ?[]const u8 = null,
    no_tui: bool = false,
    insecure_upstream: bool = false,
    share: bool = false,
    max_body: ?usize = null,
    timeout: ?u32 = null,
    local: bool = false,
    dns: bool = false,
    intercept_pattern: ?[]const u8 = null,
    command: ?[]const u8 = null,
};

fn readConfigFile(
    allocator: std.mem.Allocator,
    path: []const u8,
    routes: *[proxy.max_routes]proxy.Route,
    route_count: *usize,
) !ConfigResult {
    // Dir.cwd().readFile accepts absolute paths too.
    var buf: [8192]u8 = undefined;
    const content = try std.Io.Dir.cwd().readFile(rt.io(), path, &buf);

    var result = ConfigResult{};

    var iter = std.mem.splitScalar(u8, content, '\n');
    while (iter.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        if (lineValue(line, "port") orelse lineValue(line, "p")) |val| {
            result.port = std.fmt.parseInt(u16, val, 10) catch {
                std.debug.print("config: invalid port value: {s}\n", .{val});
                std.process.exit(1);
            };
        } else if (lineValue(line, "bind") orelse lineValue(line, "b")) |val| {
            result.bind = allocator.dupe(u8, val) catch null;
        } else if (lineValue(line, "max-body")) |val| {
            result.max_body = cli.parseSize(val) orelse {
                std.debug.print("config: invalid max-body value: {s}\n", .{val});
                std.process.exit(1);
            };
        } else if (lineValue(line, "timeout")) |val| {
            result.timeout = proxy.parseTimeoutSeconds(val) orelse {
                std.debug.print("config: invalid timeout value: {s}\n", .{val});
                std.process.exit(1);
            };
        } else if (lineValue(line, "route")) |val| {
            addRoute(allocator, routes, route_count, val);
        } else if (std.mem.eql(u8, line, "no-tui")) {
            result.no_tui = true;
        } else if (std.mem.eql(u8, line, "insecure-upstream")) {
            result.insecure_upstream = true;
        } else if (std.mem.eql(u8, line, "share")) {
            result.share = true;
        } else if (std.mem.eql(u8, line, "local") or std.mem.eql(u8, line, "l")) {
            result.local = true;
        } else if (std.mem.eql(u8, line, "dns")) {
            result.dns = true;
        } else if (lineValue(line, "intercept")) |val| {
            result.intercept_pattern = allocator.dupe(u8, val) catch null;
        } else if (lineValue(line, "command")) |val| {
            if (result.command != null) {
                std.debug.print("config: duplicate command option\n", .{});
                std.process.exit(1);
            }
            const trimmed = std.mem.trim(u8, val, " \t");
            if (trimmed.len == 0) {
                std.debug.print("config: empty command value\n", .{});
                std.process.exit(1);
            }
            result.command = allocator.dupe(u8, trimmed) catch null;
        } else {
            std.debug.print("config: unknown option: {s}\n", .{line});
            std.process.exit(1);
        }
    }

    return result;
}

fn lineValue(line: []const u8, key: []const u8) ?[]const u8 {
    if (line.len > key.len and line[key.len] == '=' and std.mem.eql(u8, line[0..key.len], key)) {
        return std.mem.trim(u8, line[key.len + 1 ..], " \t");
    }
    return null;
}

fn runCmdOutput(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    const res = try std.process.run(allocator, rt.io(), .{ .argv = argv });
    allocator.free(res.stderr);
    return res.stdout;
}

