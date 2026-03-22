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

pub fn main() !void {
    compat.initNetworking();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var command: Command = .none;
    var local = false;
    var force = false;
    var port_set = false;
    var target_port: u16 = 3000;
    var bind_addr: []const u8 = "0.0.0.0";
    var no_tui: bool = false;
    var dns_only: bool = false;
    var cert_only: bool = false;
    var max_body: usize = proxy.default_max_request_body;
    var routes: [proxy.max_routes]proxy.Route = undefined;
    var route_count: usize = 0;

    var args = if (builtin.os.tag == .windows)
        try std.process.argsWithAllocator(std.heap.page_allocator)
    else
        std.process.args();
    defer if (builtin.os.tag == .windows) args.deinit();
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
        } else if (flagValue(arg, "-p", "--port")) |val| {
            target_port = std.fmt.parseInt(u16, val, 10) catch {
                std.debug.print("invalid port value: {s}\n", .{val});
                std.process.exit(1);
            };
            port_set = true;
        } else if (flagValue(arg, "-b", "--bind")) |val| {
            bind_addr = val;
        } else if (flagValue(arg, null, "--max-body")) |val| {
            max_body = parseSize(val) orelse {
                std.debug.print("invalid max-body value: {s}\n", .{val});
                std.process.exit(1);
            };
        } else if (flagValue(arg, null, "--route")) |val| {
            if (route_count >= proxy.max_routes) {
                std.debug.print("too many routes (max {d})\n", .{proxy.max_routes});
                std.process.exit(1);
            }
            // Parse PATTERN=PORT — pattern is everything up to last '='
            if (std.mem.lastIndexOfScalar(u8, val, '=')) |eq| {
                const pattern = val[0..eq];
                const port_str = val[eq + 1 ..];
                const rport = std.fmt.parseInt(u16, port_str, 10) catch {
                    std.debug.print("invalid route port: {s}\n", .{port_str});
                    std.process.exit(1);
                };
                if (pattern.len == 0) {
                    std.debug.print("empty route pattern in: {s}\n", .{val});
                    std.process.exit(1);
                }
                routes[route_count] = .{
                    .kind = if (pattern[0] == '/') .path else .subdomain,
                    .pattern = allocator.dupe(u8, pattern) catch {
                        std.debug.print("out of memory\n", .{});
                        std.process.exit(1);
                    },
                    .port = rport,
                };
                route_count += 1;
            } else {
                std.debug.print("invalid route format, expected PATTERN=PORT: {s}\n", .{val});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--no-tui")) {
            no_tui = true;
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--dns")) {
            dns_only = true;
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--cert")) {
            cert_only = true;
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
            force = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            std.debug.print("zlodev-{s}\n", .{version});
            return;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printHelp();
            return;
        } else {
            std.debug.print("unknown argument: {s}\n", .{arg});
            printHelp();
            return;
        }
    }

    defer for (routes[0..route_count]) |route| {
        allocator.free(route.pattern);
    };

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

    // Auto-detect port if not explicitly set
    if (!port_set) {
        target_port = detectPort();
    }

    switch (command) {
        .install => {
            if (dns_only and cert_only) {
                std.debug.print("-d and -c are mutually exclusive\n", .{});
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
                try doStart(allocator, full_domain, local, tld, target_port, bind_addr, no_tui, max_body, routes[0..route_count]);
            }
        },
        .uninstall => {
            if (dns_only and cert_only) {
                std.debug.print("-d and -c are mutually exclusive\n", .{});
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
            // Check systemd and systemd-resolved
            const systemd_result = try runCmdOutput(allocator, &.{ "ps", "--no-headers", "-o", "comm", "1" });
            defer allocator.free(systemd_result);
            const resolved_result = try runCmdOutput(allocator, &.{ "systemctl", "is-active", "systemd-resolved.service" });
            defer allocator.free(resolved_result);
            const systemd = std.mem.trim(u8, systemd_result, "\n\r ");
            const resolved = std.mem.trim(u8, resolved_result, "\n\r ");

            if (!std.mem.eql(u8, systemd, "systemd") or !std.mem.eql(u8, resolved, "active")) {
                std.debug.print("linux initialization is supported only for systemd using systemd-resolved\n", .{});
                std.process.exit(1);
            }

            // Check avahi for mDNS config
            const avahi_result = try runCmdOutput(allocator, &.{ "systemctl", "is-active", "avahi-daemon.service" });
            defer allocator.free(avahi_result);
            const avahi = std.mem.trim(u8, avahi_result, "\n\r ");

            if (!std.mem.eql(u8, avahi, "active")) {
                // Configure systemd-resolved for mDNS
                const resolved_conf = "[Resolve]\nMulticastDNS=yes\nLLMNR=no";
                const tmp_file = try std.fs.cwd().createFile("/tmp/zlodev_resolved.conf", .{});
                try tmp_file.writeAll(resolved_conf);
                tmp_file.close();
                try sys.sudoCmd(allocator, &.{ "sudo", "install", "-m", "644", "/tmp/zlodev_resolved.conf", "/etc/systemd/resolved.conf.d/zlodev.conf" });
                std.fs.cwd().deleteFile("/tmp/zlodev_resolved.conf") catch {};
                try sys.sudoCmd(allocator, &.{ "sudo", "systemctl", "restart", "systemd-resolved.service" });
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
    const probe = dns.systemProbe();
    try dns.install(allocator, probe.ip, probe.port, tld);
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

fn doStartDns(tld: []const u8) !void {
    // Warn if DNS resolver is not installed
    switch (builtin.os.tag) {
        .macos => {
            var path_buf: [256]u8 = undefined;
            const resolver_path = std.fmt.bufPrint(&path_buf, "/etc/resolver/{s}", .{tld}) catch "";
            std.fs.accessAbsolute(resolver_path, .{}) catch {
                std.debug.print("warning: DNS resolver not installed, run 'zlodev install -d' first\n", .{});
            };
        },
        .linux => {
            std.fs.accessAbsolute("/etc/systemd/network/zlodev0.network", .{}) catch {
                std.debug.print("warning: DNS resolver not installed, run 'zlodev install -d' first\n", .{});
            };
        },
        .windows => {
            std.debug.print("note: ensure DNS is installed ('zlodev install -d') and run in an elevated terminal\n", .{});
        },
        else => {},
    }
    const probe = dns.systemProbe();
    log.info("component=dns op=listening ip={s} port={d} tld={s}", .{ probe.ip, probe.port, tld });
    dns.serve(probe.ip, probe.port, tld);
}

fn doStart(
    allocator: std.mem.Allocator,
    full_domain: []const u8,
    local: bool,
    tld: []const u8,
    target_port: u16,
    bind_addr: []const u8,
    no_tui: bool,
    max_request_body: usize,
    routes: []const proxy.Route,
) !void {
    // Check if another instance is already running
    if (isPortListening(bind_addr, 443)) {
        std.debug.print("port 443 is already in use — is another zlodev instance running?\n", .{});
        std.process.exit(1);
    }
    if (isPortListening(bind_addr, 80)) {
        std.debug.print("port 80 is already in use — is another zlodev instance running?\n", .{});
        std.process.exit(1);
    }

    // Get certificate paths
    var cert_buf: [std.fs.max_path_bytes]u8 = undefined;
    var key_buf: [std.fs.max_path_bytes]u8 = undefined;
    const certs = cert.getCert(&cert_buf, &key_buf, full_domain) catch {
        std.debug.print("certificates not found, run 'zlodev install' first\n", .{});
        std.process.exit(1);
    };

    // Get CA paths for HTTP server and proxy
    var ca_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ca_path = cert.getCaPath(&ca_buf, full_domain) catch {
        std.debug.print("CA certificate not found, run 'zlodev install' first\n", .{});
        std.process.exit(1);
    };
    var ca_der_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ca_der_path = cert.getCaDerPath(&ca_der_buf, full_domain) catch {
        std.debug.print("CA DER certificate not found, run 'zlodev install' first\n", .{});
        std.process.exit(1);
    };

    // We need null-terminated paths for OpenSSL
    const cert_path_z = try allocator.dupeZ(u8, certs.cert);
    defer allocator.free(cert_path_z);
    const key_path_z = try allocator.dupeZ(u8, certs.key);
    defer allocator.free(key_path_z);
    const ca_path_z = try allocator.dupeZ(u8, ca_path);
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
    if (!local) {
        const probe = dns.systemProbe();
        dns_thread = try std.Thread.spawn(.{}, struct {
            fn run(ip: []const u8, port: u16, t: []const u8) void {
                dns.serve(ip, port, t);
            }
        }.run, .{ probe.ip, probe.port, tld_owned });
    }

    // Start HTTP server
    const http_thread = try std.Thread.spawn(.{}, struct {
        fn run(addr: []const u8, d: []const u8, ca_pem: []const u8, ca_der: []const u8) void {
            http_server.serve(addr, d, ca_pem, ca_der);
        }
    }.run, .{ bind_owned, domain_owned, ca_pem_owned, ca_der_owned });

    // Start HTTPS proxy on its own thread
    const config = proxy.ProxyConfig{
        .target_host = "127.0.0.1",
        .target_port = target_port,
        .listen_addr = bind_owned,
        .cert_path = cert_path_z,
        .key_path = key_path_z,
        .ca_path = ca_path_z,
        .server_ident = "zlodev",
        .max_request_body = max_request_body,
        .routes = routes,
        .domain = domain_owned,
    };
    const proxy_thread = try std.Thread.spawn(.{}, struct {
        fn run(cfg: *const proxy.ProxyConfig) void {
            proxy.start(cfg) catch |e| {
                log.err("component=proxy op=start error={any}", .{e});
            };
        }
    }.run, .{&config});

    if (no_tui) {
        log.info("component=main op=running domain={s} target=127.0.0.1:{d} routes={d}", .{ full_domain, target_port, routes.len });
        for (routes) |route| {
            const kind_str: []const u8 = if (route.kind == .subdomain) "subdomain" else "path";
            log.info("component=main route kind={s} pattern={s} port={d}", .{ kind_str, route.pattern, route.port });
        }
        while (shutdown.isRunning()) {
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
    } else {
        // Run TUI on main thread (blocks until user quits)
        tui.run(allocator, full_domain, target_port, routes) catch |e| {
            log.unmute();
            log.err("component=tui op=start error={any}", .{e});
        };
        log.unmute();
        log.deinitLogFile();
    }

    // Signal all server loops to stop and wait for them
    shutdown.requestShutdown();
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
                    try sys.sudoCmd(allocator, &.{ "sudo", "rm", "/etc/systemd/resolved.conf.d/zlodev.conf" });
                    try sys.sudoCmd(allocator, &.{ "sudo", "systemctl", "restart", "systemd-resolved.service" });
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
        \\  install -c           install certificates only
        \\  install -d           install DNS only
        \\  uninstall            uninstall certificates and DNS
        \\  uninstall -c         uninstall certificates only
        \\  uninstall -d         uninstall DNS only
        \\  start                start service (proxy + DNS + TUI)
        \\  start -d             start DNS server only (log mode)
        \\
        \\Options:
        \\  -p=PORT, --port=PORT       target port [auto-detect or 3000]
        \\  -b=ADDR, --bind=ADDR       listen address [default 0.0.0.0]
        \\  --route=PATTERN=PORT       route by subdomain or path (repeatable)
        \\  --max-body=SIZE            max request body size [default 10M]
        \\  --no-tui                   disable TUI, log to stderr
        \\  -l, --local                use .local domain (mDNS)
        \\  -f, --force                force reinstall
        \\  -h, --help                 show help
        \\  -v, --version              show version
        \\
        \\Routes:
        \\  --route=api=3001           subdomain: api.dev.lo -> :3001
        \\  --route=/api=3001          path:      dev.lo/api/* -> :3001
        \\  Priority: subdomain > longest path > default port
        \\
        \\SIZE accepts suffixes: K (KB), M (MB), G (GB). Example: --max-body=50M
        \\
    , .{version});
}

/// Extract value from --flag=VALUE or -f=VALUE style arguments.
/// Returns the value after '=' if the arg matches, null otherwise.
fn flagValue(arg: []const u8, short: ?[]const u8, long: []const u8) ?[]const u8 {
    if (short) |s| {
        const prefix = s;
        if (arg.len > prefix.len and arg[prefix.len] == '=' and std.mem.startsWith(u8, arg, prefix)) {
            return arg[prefix.len + 1 ..];
        }
    }
    if (arg.len > long.len and arg[long.len] == '=' and std.mem.startsWith(u8, arg, long)) {
        return arg[long.len + 1 ..];
    }
    return null;
}

/// Parse a size string with optional suffix: K, M, G. Returns bytes.
fn parseSize(val: []const u8) ?usize {
    if (val.len == 0) return null;
    const last = val[val.len - 1];
    if (last == 'K' or last == 'k') {
        const n = std.fmt.parseInt(usize, val[0 .. val.len - 1], 10) catch return null;
        return n * 1024;
    } else if (last == 'M' or last == 'm') {
        const n = std.fmt.parseInt(usize, val[0 .. val.len - 1], 10) catch return null;
        return n * 1024 * 1024;
    } else if (last == 'G' or last == 'g') {
        const n = std.fmt.parseInt(usize, val[0 .. val.len - 1], 10) catch return null;
        return n * 1024 * 1024 * 1024;
    }
    return std.fmt.parseInt(usize, val, 10) catch null;
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

    const cwd = std.fs.cwd();
    for (checks) |check| {
        if (cwd.access(check.file, .{})) |_| {
            return check.port;
        } else |_| {}
    }

    return 3000;
}

fn readEnvPort() ?u16 {
    const cwd = std.fs.cwd();
    const file = cwd.openFile(".env", .{}) catch return null;
    defer file.close();

    var buf: [4096]u8 = undefined;
    const n = file.readAll(&buf) catch return null;
    const content = buf[0..n];

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
    const addr = std.net.Address.parseIp(bind_addr, port) catch return false;
    const sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch return false;
    defer compat.closeSocket(sock);
    std.posix.connect(sock, &addr.any, addr.getOsSockLen()) catch return false;
    return true;
}

fn runCmdOutput(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    const stdout_file = child.stdout.?;
    var read_buf: [4096]u8 = undefined;
    var result = std.ArrayListUnmanaged(u8){};
    defer result.deinit(allocator);
    while (true) {
        const n = try stdout_file.read(&read_buf);
        if (n == 0) break;
        try result.appendSlice(allocator, read_buf[0..n]);
    }
    _ = try child.wait();
    return try result.toOwnedSlice(allocator);
}

