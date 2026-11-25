const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const log = @import("log.zig");
const requests = @import("requests.zig");
const intercept = @import("intercept.zig");
const hold = @import("hold.zig");
const http_wire = @import("http_wire.zig");
const shutdown = @import("shutdown.zig");
const compat = @import("compat.zig");
const rt = @import("rt.zig");
const share = @import("share.zig");
const win32 = @import("win32.zig");

const ssl_c = @import("ssl_c");

pub const default_max_request_body: usize = 10 * 1024 * 1024; // 10MB
pub const default_upstream_timeout_s: u32 = 30;

/// `--timeout` / `timeout=` value: whole seconds, 0 (no limit) to one day.
pub fn parseTimeoutSeconds(val: []const u8) ?u32 {
    const n = std.fmt.parseInt(u32, val, 10) catch return null;
    return if (n <= 86400) n else null;
}

pub const Route = struct {
    kind: enum { subdomain, path },
    pattern: []const u8,
    port: u16,
    hostname: ?[]const u8 = null, // null = localhost, set = external host
};

pub const max_routes = 16;

pub const ProxyConfig = struct {
    target_host: []const u8,
    target_port: u16,
    listen_addr: []const u8,
    /// Drop clients that aren't on this machine (default mode, no explicit bind).
    loopback_only: bool = false,
    cert_path: [:0]const u8,
    key_path: [:0]const u8,
    ca_path: [:0]const u8,
    server_ident: []const u8,
    max_request_body: usize = default_max_request_body,
    routes: []const Route = &.{},
    domain: []const u8 = "dev.lo",
    /// Skip certificate verification for external routes (`--insecure-upstream`).
    insecure_upstream: bool = false,
    /// Upstream connect + response-head deadline in seconds (`--timeout`); 0 = none.
    upstream_timeout_s: u32 = default_upstream_timeout_s,
};

var conn_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

fn nextConnId() u64 {
    return conn_counter.fetchAdd(1, .monotonic) + 1;
}

const RouteResult = struct {
    port: u16,
    index: u8, // 0xff = no route match
    hostname: ?[]const u8 = null, // null = localhost
};

/// Resolve the upstream port for a request based on configured routes.
/// Priority: 1) subdomain match on Host header, 2) longest path prefix, 3) default port.
fn resolveRoute(config: *const ProxyConfig, host: []const u8, uri: []const u8) RouteResult {
    // 1. Check subdomain routes: match "api" against Host "api.dev.lo"
    var best_path_len: usize = 0;
    var best_path_port: ?u16 = null;
    var best_path_idx: u8 = 0xff;
    var best_path_hostname: ?[]const u8 = null;

    for (config.routes, 0..) |route, i| {
        switch (route.kind) {
            .subdomain => {
                // Host header may include port (e.g. "api.dev.lo:443")
                const host_name = if (std.mem.indexOfScalar(u8, host, ':')) |colon| host[0..colon] else host;
                // Check if host starts with "pattern." and the rest matches the domain
                if (host_name.len > route.pattern.len + 1 + config.domain.len) {
                    // Too long, skip
                } else if (host_name.len == route.pattern.len + 1 + config.domain.len and
                    std.mem.startsWith(u8, host_name, route.pattern) and
                    host_name[route.pattern.len] == '.' and
                    std.mem.eql(u8, host_name[route.pattern.len + 1 ..], config.domain))
                {
                    return .{ .port = route.port, .index = @intCast(i), .hostname = route.hostname };
                }
            },
            .path => {
                // Longest prefix match
                if (std.mem.startsWith(u8, uri, route.pattern) and route.pattern.len > best_path_len) {
                    // Ensure we match at a boundary: exact match, or next char is '/' or '?'
                    if (uri.len == route.pattern.len or
                        uri[route.pattern.len] == '/' or
                        uri[route.pattern.len] == '?' or
                        route.pattern[route.pattern.len - 1] == '/')
                    {
                        best_path_len = route.pattern.len;
                        best_path_port = route.port;
                        best_path_idx = @intCast(i);
                        best_path_hostname = route.hostname;
                    }
                }
            },
        }
    }

    // 2. Return longest path match if found
    if (best_path_port) |port| return .{ .port = port, .index = best_path_idx, .hostname = best_path_hostname };

    // 3. Default
    return .{ .port = config.target_port, .index = 0xff };
}

/// Upstream connection abstraction — wraps either a plain socket (local) or TLS (external).
const UpstreamConn = struct {
    sock: compat.SocketStream,
    /// TLS upstreams (external routes) run non-blocking after the handshake: poll
    /// readiness can come from records that hold no data (TLS 1.3 session tickets),
    /// and a blocking SSL_read would then wait past any deadline or shutdown.
    ssl_conn: ?*ssl_c.SSL = null,
    /// How long a TLS write may wait for the socket (`--timeout`; 0 = no limit).
    write_timeout_ms: u32 = 0,

    fn writeAll(self: UpstreamConn, data: []const u8) !void {
        if (self.ssl_conn) |s| {
            var sent: usize = 0;
            while (sent < data.len) {
                const n = ssl_c.SSL_write(s, @ptrCast(data[sent..].ptr), @intCast(data.len - sent));
                if (n <= 0) {
                    const events: i16 = switch (ssl_c.SSL_get_error(s, n)) {
                        ssl_c.SSL_ERROR_WANT_WRITE => compat.POLL.OUT,
                        ssl_c.SSL_ERROR_WANT_READ => compat.POLL.IN,
                        else => return error.SslWrite,
                    };
                    var fds = [1]compat.pollfd{.{ .fd = self.sock.handle, .events = events, .revents = 0 }};
                    const wait_ms = if (self.write_timeout_ms == 0) std.math.maxInt(u32) else self.write_timeout_ms;
                    if (compat.pollWhileRunning(&fds, wait_ms, shutdown.isRunning) != .ready) return error.SslWrite;
                    continue;
                }
                sent += @intCast(n);
            }
        } else {
            try self.sock.writeAll(data);
        }
    }

    /// `error.WouldBlock` (TLS only): nothing to read yet; poll and try again.
    pub fn read(self: UpstreamConn, buf: []u8) !usize {
        if (self.ssl_conn) |s| {
            const n = ssl_c.SSL_read(s, @ptrCast(buf.ptr), @intCast(buf.len));
            if (n <= 0) return switch (ssl_c.SSL_get_error(s, n)) {
                ssl_c.SSL_ERROR_WANT_READ, ssl_c.SSL_ERROR_WANT_WRITE => error.WouldBlock,
                ssl_c.SSL_ERROR_ZERO_RETURN => 0,
                else => error.SslRead,
            };
            return @intCast(n);
        } else {
            return self.sock.read(buf);
        }
    }

    fn close(self: UpstreamConn) void {
        if (self.ssl_conn) |s| {
            _ = ssl_c.SSL_shutdown(s);
            ssl_c.SSL_free(s);
        }
        self.sock.close();
    }
};

/// Reads the upstream through poll, so a deadline can end the wait (`error.Timeout`)
/// and shutdown is noticed within a second. `deadline_ms` 0 = wait until data,
/// close or shutdown. TLS bytes BoringSSL already decrypted are read without polling.
const UpstreamReader = struct {
    conn: UpstreamConn,
    deadline_ms: i64 = 0,

    pub fn read(self: UpstreamReader, buf: []u8) !usize {
        while (true) {
            const pending = if (self.conn.ssl_conn) |s| ssl_c.SSL_pending(s) > 0 else false;
            if (!pending) {
                var fds = [1]compat.pollfd{.{ .fd = self.conn.sock.handle, .events = compat.POLL.IN, .revents = 0 }};
                const wait_ms: u32 = if (self.deadline_ms == 0) std.math.maxInt(u32) else blk: {
                    const left = self.deadline_ms - rt.milliTimestamp();
                    break :blk if (left > 0) @intCast(left) else 0;
                };
                switch (compat.pollWhileRunning(&fds, wait_ms, shutdown.isRunning)) {
                    .ready => {},
                    .timeout => return error.Timeout,
                    .stopped, .failed => return error.Closed,
                }
            }
            // A TLS record with no application data (session ticket) or half a
            // record: nothing to hand back yet, so wait again within the deadline.
            return self.conn.read(buf) catch |e| {
                if (e == error.WouldBlock) continue;
                return e;
            };
        }
    }
};

/// Absolute deadline `timeout_s` from now; 0 = none.
fn deadlineAfter(timeout_s: u32) i64 {
    return if (timeout_s == 0) 0 else rt.milliTimestamp() + @as(i64, timeout_s) * 1000;
}

/// Root bundles tried after BoringSSL's defaults (`/etc/ssl/cert.pem`, `/etc/ssl/certs`,
/// `SSL_CERT_FILE`/`SSL_CERT_DIR`). The first that loads wins.
const root_bundles = [_][:0]const u8{
    "/etc/ssl/cert.pem", // macOS, Alpine, Arch
    "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt", // Fedora, RHEL
    "/etc/ssl/ca-bundle.pem", // openSUSE
};

/// Load the OS trust store into `ctx` for verifying external upstreams. BoringSSL
/// built from source doesn't know the platform stores, so macOS and Linux load a
/// PEM bundle and Windows copies the system ROOT store. False if nothing loaded.
fn loadSystemRoots(ctx: *ssl_c.SSL_CTX) bool {
    defer ssl_c.ERR_clear_error();
    if (builtin.os.tag == .windows) return loadWindowsRoots(ctx) > 0;
    _ = ssl_c.SSL_CTX_set_default_verify_paths(ctx);
    if (compat.getenv("SSL_CERT_FILE") != null or compat.getenv("SSL_CERT_DIR") != null) return true;
    for (root_bundles) |path| {
        if (ssl_c.SSL_CTX_load_verify_locations(ctx, path.ptr, null) == 1) return true;
    }
    return false;
}

fn loadWindowsRoots(ctx: *ssl_c.SSL_CTX) usize {
    const store = ssl_c.SSL_CTX_get_cert_store(ctx);
    const sys_store = win32.CertOpenSystemStoreW(0, std.unicode.utf8ToUtf16LeStringLiteral("ROOT")) orelse return 0;
    defer _ = win32.CertCloseStore(sys_store, 0);
    var added: usize = 0;
    // CertEnumCertificatesInStore frees the previous context on each call.
    var prev: ?*const win32.CERT_CONTEXT = null;
    while (win32.CertEnumCertificatesInStore(sys_store, prev)) |cc| : (prev = cc) {
        var der: [*c]const u8 = cc.pbCertEncoded;
        const x509 = ssl_c.d2i_X509(null, &der, @intCast(cc.cbCertEncoded)) orelse continue;
        defer ssl_c.X509_free(x509);
        if (ssl_c.X509_STORE_add_cert(store, x509) == 1) added += 1;
    }
    return added;
}

/// Create a TLS client context for connecting to external upstreams. Verifies the
/// upstream's certificate against the OS trust store unless `insecure`
/// (`--insecure-upstream`).
fn createClientSslCtx(insecure: bool) ?*ssl_c.SSL_CTX {
    const ctx = ssl_c.SSL_CTX_new(ssl_c.TLS_client_method()) orelse return null;
    if (insecure) {
        ssl_c.SSL_CTX_set_verify(ctx, ssl_c.SSL_VERIFY_NONE, null);
    } else {
        ssl_c.SSL_CTX_set_verify(ctx, ssl_c.SSL_VERIFY_PEER, null);
        if (!loadSystemRoots(ctx)) {
            log.err("component=proxy op=client_ssl error=no_trusted_roots hint=set SSL_CERT_FILE or use --insecure-upstream", .{});
        }
    }
    _ = ssl_c.SSL_CTX_set_mode(ctx, ssl_c.SSL_MODE_AUTO_RETRY);
    return ctx;
}

/// TLS-wrap a connected upstream socket: SNI plus verification against `host`
/// (DNS name or IP literal). A rejected certificate is `UpstreamCertUntrusted`, so
/// the client gets a 502 that names the fix.
fn upstreamHandshake(cctx: *ssl_c.SSL_CTX, sock: compat.socket_t, host: []const u8, conn_id: u64) !*ssl_c.SSL {
    const us = ssl_c.SSL_new(cctx) orelse {
        log.err("component=proxy conn={d} op=upstream_ssl_new error=alloc_failed", .{conn_id});
        return error.UpstreamUnavailable;
    };
    errdefer ssl_c.SSL_free(us);
    _ = ssl_c.SSL_set_fd(us, compat.socketToFd(sock));

    var host_buf: [256]u8 = undefined;
    const host_z = std.fmt.bufPrintSentinel(&host_buf, "{s}", .{host}, 0) catch return error.UpstreamUnavailable;
    const is_ip = if (std.Io.net.IpAddress.parse(host, 0)) |_| true else |_| false;
    if (is_ip) {
        // SNI must not carry an IP literal; match the cert's IP SAN instead.
        if (ssl_c.X509_VERIFY_PARAM_set1_ip_asc(ssl_c.SSL_get0_param(us), host_z.ptr) != 1) return error.UpstreamUnavailable;
    } else {
        _ = ssl_c.SSL_set_tlsext_host_name(us, host_z.ptr);
        if (ssl_c.SSL_set1_host(us, host_z.ptr) != 1) return error.UpstreamUnavailable;
    }

    if (ssl_c.SSL_connect(us) != 1) {
        const verify = ssl_c.SSL_get_verify_result(us);
        ssl_c.ERR_clear_error();
        if (verify != ssl_c.X509_V_OK) {
            log.err("component=proxy conn={d} op=upstream_tls_verify host={s} error=\"{s}\"", .{ conn_id, host, std.mem.span(ssl_c.X509_verify_cert_error_string(verify)) });
            return error.UpstreamCertUntrusted;
        }
        log.err("component=proxy conn={d} op=upstream_tls_handshake host={s} error=failed", .{ conn_id, host });
        return error.UpstreamUnavailable;
    }
    return us;
}

/// Bind the HTTPS listener on port 443. Separate from `start` so startup can
/// fail before the TUI opens when the port is taken.
pub fn listen(listen_addr: []const u8) !compat.socket_t {
    const address = try std.Io.net.IpAddress.parse(listen_addr, 443);
    return compat.tcpListen(address) catch |e| {
        log.err("component=proxy op=bind port=443 error={any}", .{e});
        return e;
    };
}

/// Run the proxy on a listener from `listen`. Takes ownership of `listener`.
pub fn start(config: *const ProxyConfig, listener: compat.socket_t) !void {
    defer compat.closeSocket(listener);

    _ = ssl_c.OPENSSL_init_ssl(0, null);

    const ctx = ssl_c.SSL_CTX_new(ssl_c.TLS_server_method()) orelse {
        log.err("component=proxy op=ssl_init error=context_create_failed", .{});
        return error.SslInit;
    };
    defer ssl_c.SSL_CTX_free(ctx);

    if (ssl_c.SSL_CTX_use_certificate_file(ctx, config.cert_path.ptr, ssl_c.SSL_FILETYPE_PEM) != 1) {
        log.err("component=proxy op=ssl_cert path={s} error=load_failed", .{config.cert_path});
        return error.SslCert;
    }

    // Load CA as extra chain cert so clients can verify the full chain
    if (ssl_c.SSL_CTX_load_verify_locations(ctx, config.ca_path.ptr, null) != 1) {
        log.err("component=proxy op=ssl_ca path={s} error=load_failed", .{config.ca_path});
        return error.SslCa;
    }
    // Add CA to the chain sent during TLS handshake
    _ = ssl_c.SSL_CTX_set_mode(ctx, ssl_c.SSL_MODE_AUTO_RETRY);
    {
        const bio = ssl_c.BIO_new_file(config.ca_path.ptr, "r") orelse {
            log.err("component=proxy op=ssl_ca path={s} error=bio_open_failed", .{config.ca_path});
            return error.SslCa;
        };
        defer _ = ssl_c.BIO_free(bio);
        const ca_cert = ssl_c.PEM_read_bio_X509(bio, null, null, null) orelse {
            log.err("component=proxy op=ssl_ca path={s} error=parse_failed", .{config.ca_path});
            return error.SslCa;
        };
        // SSL_CTX_add_extra_chain_cert takes ownership, do not free ca_cert
        if (ssl_c.SSL_CTX_add_extra_chain_cert(ctx, ca_cert) != 1) {
            log.err("component=proxy op=ssl_ca error=chain_add_failed", .{});
            ssl_c.X509_free(ca_cert);
            return error.SslCa;
        }
    }

    if (ssl_c.SSL_CTX_use_PrivateKey_file(ctx, config.key_path.ptr, ssl_c.SSL_FILETYPE_PEM) != 1) {
        log.err("component=proxy op=ssl_key path={s} error=load_failed", .{config.key_path});
        return error.SslKey;
    }

    // Create client TLS context for external upstream connections (if any routes have hostnames)
    var has_external = false;
    for (config.routes) |route| {
        if (route.hostname != null) {
            has_external = true;
            break;
        }
    }
    const client_ctx: ?*ssl_c.SSL_CTX = if (has_external) createClientSslCtx(config.insecure_upstream) else null;
    defer if (client_ctx) |c| ssl_c.SSL_CTX_free(c);

    log.info("component=proxy op=listening ip={s} port=443 target={s}:{d}", .{ config.listen_addr, config.target_host, config.target_port });

    var group: std.Io.Group = .init;

    var consecutive_failures: u32 = 0;
    while (shutdown.isRunning()) {
        // Poll with 1-second timeout before accept
        var fds = [1]compat.pollfd{
            .{ .fd = listener, .events = compat.POLL.IN, .revents = 0 },
        };
        const ready = compat.poll(&fds, 1000) catch |e| {
            log.err("component=proxy op=poll error={any}", .{e});
            continue;
        };
        if (ready == 0) continue; // timeout, re-check shutdown

        const conn = compat.accept(listener) catch |e| {
            log.err("component=proxy op=accept error={any}", .{e});
            consecutive_failures += 1;
            const backoff_ms: u64 = @min(5000, @as(u64, 100) << @intCast(@min(consecutive_failures, 6)));
            rt.sleepMs(backoff_ms);
            continue;
        };
        consecutive_failures = 0;
        if (config.loopback_only and !compat.isLoopback(conn.addr)) {
            var addr_buf: [46]u8 = undefined;
            log.info("component=proxy op=reject_remote client={s}", .{formatAddress(conn.addr, &addr_buf)});
            compat.closeSocket(conn.sock);
            continue;
        }

        const ssl = ssl_c.SSL_new(ctx) orelse {
            log.err("component=proxy op=ssl_new error=alloc_failed", .{});
            compat.closeSocket(conn.sock);
            continue;
        };

        _ = ssl_c.SSL_set_fd(ssl, compat.socketToFd(conn.sock));

        const conn_id = nextConnId();
        // All workers busy: hold this connection until one frees up (further
        // clients wait in the listen backlog), like the old queued thread pool.
        if (!rt.acquireWorkerSlot(&proxy_workers, max_proxy_workers, shutdown.isRunning)) {
            // Shutdown began while waiting for a slot — not a spawn failure.
            discardConnection(ssl, conn.sock);
            break;
        }
        rt.spawnWorker(rt.io(), &group, handleConnection, .{
            ssl,
            conn.sock,
            conn.addr,
            config,
            conn_id,
            client_ctx,
        }, rejectConnectionAndRelease, .{ ssl, conn.sock, conn_id });
    }

    // Release intercept holds and wait (bounded) for workers. Group.cancel
    // awaits every task, so only call it once they've all finished; on a
    // timeout return anyway and let process exit reap the stragglers.
    if (drainWorkers(shutdown_drain_ms)) {
        group.cancel(rt.io());
    } else {
        log.err("component=proxy op=shutdown workers={d} error=DrainTimeout", .{proxy_workers.load(.acquire)});
    }
}

var proxy_workers: std.atomic.Value(u32) = .init(0);
const max_proxy_workers = 64;
/// How long shutdown waits for proxy workers before exiting anyway.
const shutdown_drain_ms = 5000;

/// After the accept loop stops: wake workers parked on intercept holds and
/// wait for every proxy worker to exit. dropAll runs on each pass because a
/// worker mid-request can begin a hold after the first one. Returns false if
/// workers are still running at the deadline (e.g. stuck on a slow upstream).
fn drainWorkers(timeout_ms: u32) bool {
    const deadline = rt.milliTimestamp() + timeout_ms;
    while (proxy_workers.load(.acquire) > 0) {
        if (rt.milliTimestamp() >= deadline) return false;
        intercept.dropAll();
        rt.sleepMs(20);
    }
    return true;
}

fn discardConnection(ssl: *ssl_c.SSL, client_sock: compat.socket_t) void {
    ssl_c.SSL_free(ssl);
    compat.closeSocket(client_sock);
}

fn rejectConnection(ssl: *ssl_c.SSL, client_sock: compat.socket_t, conn_id: u64) void {
    log.err("component=proxy op=pool_spawn conn={d} error=ConcurrencyUnavailable", .{conn_id});
    discardConnection(ssl, client_sock);
}

fn rejectConnectionAndRelease(ssl: *ssl_c.SSL, client_sock: compat.socket_t, conn_id: u64) void {
    _ = proxy_workers.fetchSub(1, .acq_rel);
    rejectConnection(ssl, client_sock, conn_id);
}

const UpstreamError = error{ DnsFailed, ConnectRefused, ConnectFailed, ConnectTimeout, TlsFailed, UpstreamCertUntrusted };

fn connectError(e: compat.SocketError) UpstreamError {
    return switch (e) {
        error.UnknownHostName => error.DnsFailed,
        error.ConnectionRefused => error.ConnectRefused,
        error.TimedOut => error.ConnectTimeout,
        else => error.ConnectFailed,
    };
}

/// Resolve, connect (within `--timeout`), and for external routes TLS-handshake an
/// upstream connection. Each failure is logged and returned as its own error so the
/// caller can tell the client why. Sets send/recv timeouts on the socket.
fn connectUpstream(
    is_external: bool,
    upstream_host: []const u8,
    upstream_port: u16,
    config: *const ProxyConfig,
    client_ctx: ?*ssl_c.SSL_CTX,
    conn_id: u64,
) UpstreamError!UpstreamConn {
    const timeout_ms = config.upstream_timeout_s * 1000;
    // Resolve + connect — DNS for external, IP parse for local
    const upstream_sock: compat.socket_t = blk: {
        if (is_external) {
            break :blk compat.tcpConnectHost(upstream_host, upstream_port, timeout_ms) catch |e| {
                switch (e) {
                    error.UnknownHostName => log.err(
                        "component=proxy conn={d} op=dns_resolve host={s} error={any}",
                        .{ conn_id, upstream_host, e },
                    ),
                    else => log.err(
                        "component=proxy conn={d} op=upstream_connect host={s} error={any}",
                        .{ conn_id, upstream_host, e },
                    ),
                }
                return connectError(e);
            };
        } else {
            const addr = std.Io.net.IpAddress.parse(config.target_host, upstream_port) catch {
                return error.ConnectFailed;
            };
            break :blk compat.tcpConnectTimeout(addr, timeout_ms) catch |e| {
                log.err("component=proxy conn={d} op=upstream_connect host={s} error={any}", .{ conn_id, upstream_host, e });
                return connectError(e);
            };
        }
    };

    // Before the TLS handshake: an upstream that accepts TCP but never answers
    // the handshake must not pin this worker forever.
    setSocketTimeout(upstream_sock, .recv, config.upstream_timeout_s);
    setSocketTimeout(upstream_sock, .send, config.upstream_timeout_s);

    // Wrap in TLS for external upstreams; plain socket for local
    var upstream_ssl_obj: ?*ssl_c.SSL = null;
    if (is_external) {
        const cctx = client_ctx orelse {
            // client_ctx is null — SSL_CTX allocation failed at startup
            log.err("component=proxy conn={d} op=external_tls error=no_client_ctx", .{conn_id});
            compat.closeSocket(upstream_sock);
            return error.TlsFailed;
        };
        const us = upstreamHandshake(cctx, upstream_sock, upstream_host, conn_id) catch |e| {
            compat.closeSocket(upstream_sock);
            return if (e == error.UpstreamCertUntrusted) error.UpstreamCertUntrusted else error.TlsFailed;
        };
        upstream_ssl_obj = us;
        // See UpstreamConn: from here on TLS reads and writes never block.
        compat.setBlocking(upstream_sock, false) catch {
            ssl_c.SSL_free(us);
            compat.closeSocket(upstream_sock);
            return error.TlsFailed;
        };
    }

    return UpstreamConn{ .sock = .{ .handle = upstream_sock }, .ssl_conn = upstream_ssl_obj, .write_timeout_ms = timeout_ms };
}

fn handleConnection(
    ssl: *ssl_c.SSL,
    client_sock: compat.socket_t,
    client_addr: std.Io.net.IpAddress,
    config: *const ProxyConfig,
    conn_id: u64,
    client_ctx: ?*ssl_c.SSL_CTX,
) void {
    defer _ = proxy_workers.fetchSub(1, .acq_rel);
    defer {
        _ = ssl_c.SSL_shutdown(ssl);
        ssl_c.SSL_free(ssl);
        compat.closeSocket(client_sock);
    }

    if (!acceptTls(ssl, client_sock, handshake_timeout_s)) return;

    // Set receive timeout on client socket
    setSocketTimeout(client_sock, .recv, 30);

    // Keep-alive loop: process multiple requests on the same TLS connection.
    // Bytes read past the end of one request (pipelining) start the next one.
    var carry_buf: [16384]u8 = undefined;
    var carry_len: usize = 0;
    var request_count: u32 = 0;
    while (request_count < 100) : (request_count += 1) {
        // Read request headers
        var req_buf: [16384]u8 = undefined;
        @memcpy(req_buf[0..carry_len], carry_buf[0..carry_len]);
        var total: usize = carry_len;
        carry_len = 0;
        var headers_end: ?usize = std.mem.indexOf(u8, req_buf[0..total], "\r\n\r\n");
        // Same budget as the SO_RCVTIMEO set below: 30s first request, 15s keep-alive.
        const idle_timeout_ms: u32 = if (request_count == 0) 30_000 else 15_000;

        while (headers_end == null and total < req_buf.len) {
            // Idle keep-alive connections park here; wake each second so
            // Ctrl+C doesn't wait out the receive timeout. BoringSSL may
            // already hold decrypted bytes the socket poll can't see.
            if (ssl_c.SSL_pending(ssl) == 0) {
                var fds = [1]compat.pollfd{.{ .fd = client_sock, .events = compat.POLL.IN, .revents = 0 }};
                if (compat.pollWhileRunning(&fds, idle_timeout_ms, shutdown.isRunning) != .ready) return;
            }
            const n = ssl_c.SSL_read(ssl, @ptrCast(req_buf[total..].ptr), @intCast(req_buf.len - total));
            if (n <= 0) break;
            total += @as(usize, @intCast(n));
            headers_end = std.mem.indexOf(u8, req_buf[0..total], "\r\n\r\n");
        }

        if (headers_end == null) {
            if (total == req_buf.len) {
                var big = requests.Entry{ .timestamp = rt.milliTimestamp() };
                fillRequestLine(&big, req_buf[0..total]);
                failRequest(ssl, &big, null, 431, "request head over 16KB");
                discardPendingInput(ssl, client_sock);
            }
            return; // client closed, or a head that doesn't fit
        }

        const hdr_end = headers_end.?;
        const start_time = rt.milliTimestamp();

        // Parse request line
        const first_line_end = std.mem.indexOf(u8, req_buf[0..total], "\r\n") orelse return;
        const request_line = req_buf[0..first_line_end];

        var parts = std.mem.splitScalar(u8, request_line, ' ');
        const method = parts.next() orelse return;
        const uri = parts.next() orelse return;
        const version = parts.next() orelse "HTTP/1.0";
        var addr_buf: [46]u8 = undefined;
        log.info("component=proxy conn={d} method={s} uri={s} client={s}", .{ conn_id, method, uri, formatAddress(client_addr, &addr_buf) });

        // Health check — return immediately, bypass everything
        if (http_wire.isHealthCheck(uri)) {
            const health_response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            sslWriteAll(ssl, health_response);
            return;
        }

        // Determine keep-alive based on HTTP version and Connection header
        const is_http11 = std.mem.eql(u8, version, "HTTP/1.1");
        const req_hdr_section = req_buf[first_line_end + 2 .. hdr_end];
        const client_conn = http_wire.getConnectionHeader(req_hdr_section);
        const keep_alive = if (client_conn == .close) false else if (client_conn == .keep_alive) true else is_http11;

        // Extract Host header for route resolution
        const host = http_wire.getHeaderValue(req_hdr_section, "host:") orelse "";
        const route_result = resolveRoute(config, host, uri);
        // Arrived through the share tunnel: the app sees its local domain, the
        // public host goes in X-Forwarded-Host, and responses are rewritten back.
        const shared = share.isPublicHost(host);
        const real_ip = if (shared) shareRealIp(client_addr, req_hdr_section) else "";
        const public_host: ?[]const u8 = if (shared) share.publicHost() else null;
        const upstream_port = route_result.port;

        // Capture for display only: what goes upstream comes from req_buf, which
        // stays intact for the whole request (bodies are read into body_buf).
        var entry = requests.Entry{ .timestamp = start_time, .route_index = route_result.index };
        entry.method_len = @intCast(@min(method.len, entry.method.len));
        @memcpy(entry.method[0..entry.method_len], method[0..entry.method_len]);
        entry.path_len = @intCast(@min(uri.len, entry.path.len));
        @memcpy(entry.path[0..entry.path_len], uri[0..entry.path_len]);
        entry.path_truncated = uri.len > entry.path.len;
        const rh_len = @min(req_hdr_section.len, requests.max_header_len);
        @memcpy(entry.req_headers[0..rh_len], req_hdr_section[0..rh_len]);
        entry.req_headers_len = @intCast(rh_len);
        entry.req_headers_truncated = req_hdr_section.len > requests.max_header_len;
        entry.shared = shared;

        // Check for WebSocket upgrade
        if (http_wire.isWebSocketUpgrade(req_hdr_section)) {
            var ws_ip_buf: [64]u8 = undefined;
            const ws_target: WsTarget = .{
                .is_external = route_result.hostname != null,
                .host = route_result.hostname orelse config.target_host,
                .port = upstream_port,
            };
            handleWebSocket(ssl, req_buf[0..total], config, ws_target, .{
                .is_external = ws_target.is_external,
                .upstream_host = ws_target.host,
                .client_host = host,
                .client_ip = formatAddress(client_addr, &ws_ip_buf),
                .client_xff = http_wire.getHeaderValue(req_hdr_section, "x-forwarded-for:") orelse "",
                .domain = config.domain,
                .shared = shared,
                .real_ip = real_ip,
            }, client_ctx, conn_id, &entry);
            return;
        }

        // Body framing. Chunked wins over Content-Length (RFC 9112 6.3).
        const req_chunked = http_wire.isChunkedEncoding(req_hdr_section);
        const content_length: usize = if (req_chunked) 0 else http_wire.getContentLength(req_hdr_section) orelse 0;
        if (content_length > config.max_request_body) {
            log.err("component=proxy conn={d} op=body_read bytes={d} max={d} error=body_too_large", .{ conn_id, content_length, config.max_request_body });
            entry.req_body_truncated = true;
            var rb: [64]u8 = undefined;
            failRequest(ssl, &entry, null, 413, std.fmt.bufPrint(&rb, "body over --max-body ({d} bytes)", .{content_length}) catch "body over --max-body");
            discardPendingInput(ssl, client_sock);
            return;
        }
        const buffered = req_buf[hdr_end + 4 .. total];
        var body_buf: [16384]u8 = undefined;
        // Bytes past this request's body, handed to the next iteration.
        var leftover: []const u8 = "";

        // Intercept: hold only a request whose capture is complete, so the TUI edits
        // exactly what will be sent. Anything bigger passes through unheld.
        var was_intercepted = false;
        var intercept_backing_idx: usize = 0;
        var dec = http_wire.ChunkedDecoder{};
        var probe: ?Probe = null;
        var probe_buf: ?[]u8 = null;
        defer if (probe_buf) |b| std.heap.page_allocator.free(b);
        // Body read in full for a hold (complete capture): forwarded from the entry.
        var body_read = false;
        if (intercept.shouldInterceptRequest(method, uri)) hold: {
            const head_fits = method.len <= entry.method.len and !entry.path_truncated and !entry.req_headers_truncated;
            var fits = head_fits and content_length <= requests.max_body_len;
            if (fits and req_chunked) {
                const raw = std.heap.page_allocator.alloc(u8, probe_cap) catch break :hold;
                probe_buf = raw;
                const p = probeChunked(&dec, buffered, SslSource{ .ssl = ssl }, &entry.req_body, raw);
                probe = p;
                switch (p.outcome) {
                    .parse_error => {
                        entry.req_body_truncated = true;
                        failRequest(ssl, &entry, null, 400, "bad chunked encoding");
                        discardPendingInput(ssl, client_sock);
                        return;
                    },
                    .ended, .timed_out => return, // client gone mid-body
                    .too_large => fits = false,
                    .complete => {
                        entry.req_body_len = @intCast(dec.captured);
                        entry.req_body_total = dec.decoded_total;
                        leftover = p.leftover;
                        body_read = true;
                    },
                }
            } else if (fits) {
                const fit = http_wire.streamBody(buffered, SslSource{ .ssl = ssl }, http_wire.NullSink{}, content_length, &entry.req_body);
                if (fit.total < content_length) return; // client gone mid-body
                entry.req_body_len = @intCast(fit.captured);
                entry.req_body_total = fit.total;
                leftover = fit.leftover;
                body_read = true;
            }
            if (!fits) {
                entry.too_large_to_intercept = true;
                break :hold;
            }
            entry.state = .intercepted;
            if (hold.begin(&entry, false, start_time)) |h| {
                was_intercepted = true;
                intercept_backing_idx = h.index();
                switch (h.awaitDecision()) {
                    .drop => {
                        h.drop();
                        sslSendError(ssl, 502, "Dropped by intercept");
                        return;
                    },
                    else => h.accept(), // continue to upstream
                }
            } else {
                // Ring full of pins, or all intercept slots busy — begin restored the
                // ring entry to normal; the body is already read, so forward the
                // capture (complete by construction) as a held request would be.
                entry.state = .normal;
                was_intercepted = false;
            }
        }

        const held: ?usize = if (was_intercepted) intercept_backing_idx else null;

        // Ensure intercepted entries are unpinned on any early exit after this point.
        // Normal completion paths call finishEntry/finishResponseIntercept explicitly,
        // which set status/duration before unpinning — so this defer only fires for
        // error exits where the entry would otherwise be pinned forever.
        defer if (was_intercepted) {
            const dur = rt.milliTimestamp() - start_time;
            requests.finishIfDangling(intercept_backing_idx, 502, if (dur > 0) @intCast(dur) else 0);
        };

        // Connect to upstream (per-request — dev servers may not support keep-alive)
        const is_external = route_result.hostname != null;
        const upstream_host = route_result.hostname orelse config.target_host;

        const upstream = connectUpstream(is_external, upstream_host, upstream_port, config, client_ctx, conn_id) catch |e| {
            var rb: [192]u8 = undefined;
            const r = connectReason(&rb, e, upstream_host, upstream_port, config.upstream_timeout_s);
            failRequest(ssl, &entry, held, r.status, r.reason);
            return;
        };
        defer upstream.close();

        // Forward the (possibly TUI-edited) request. The TUI edits a held entry only
        // while the proxy is blocked in hold.awaitDecision(); once that returns the edit
        // is done, so we snapshot the held entry off the lock rather than read it live.
        var fwd_snapshot: ?*requests.Entry = null;
        defer if (fwd_snapshot) |s| std.heap.page_allocator.destroy(s);
        const fwd_entry: *const requests.Entry = if (was_intercepted) blk: {
            const s = std.heap.page_allocator.create(requests.Entry) catch {
                failRequest(ssl, &entry, held, 502, "out of memory");
                return;
            };
            fwd_snapshot = s;
            requests.snapshotByBackingIndex(intercept_backing_idx, s);
            break :blk s;
        } else &entry;

        var ip_buf: [64]u8 = undefined;
        const fwd_ctx: RequestForward = .{
            .is_external = is_external,
            .upstream_host = upstream_host,
            .client_host = host,
            .client_ip = formatAddress(client_addr, &ip_buf),
            .client_xff = http_wire.getHeaderValue(req_hdr_section, "x-forwarded-for:") orelse "",
            .domain = config.domain,
            .shared = shared,
            .real_ip = real_ip,
        };
        var upstream_failed = false;
        const up_sink = UpstreamSink{ .upstream = upstream, .failed = &upstream_failed };
        if (was_intercepted) {
            forwardRequest(up_sink, fwd_entry, fwd_ctx);
        } else if (body_read) {
            forwardRequest(up_sink, &entry, fwd_ctx); // hold skipped; capture is complete
        } else {
            forwardRequestHead(up_sink, method, uri, req_hdr_section, req_chunked, fwd_ctx);
            if (req_chunked) {
                // A probe that overflowed already read part of the body: relay it,
                // then let the same decoder finish from the client stream.
                var initial: []const u8 = buffered;
                if (probe) |pb| {
                    up_sink.write(pb.raw);
                    initial = pb.leftover;
                }
                const pr = http_wire.pumpChunkedResume(&dec, initial, SslSource{ .ssl = ssl }, up_sink, &entry.req_body, &body_buf, config.max_request_body);
                entry.req_body_len = @intCast(pr.captured);
                entry.req_body_total = dec.decoded_total;
                entry.req_body_truncated = pr.truncated;
                if (pr.over_limit) {
                    log.err("component=proxy conn={d} op=body_read max={d} error=body_too_large", .{ conn_id, config.max_request_body });
                    entry.req_body_truncated = true;
                    var rb: [64]u8 = undefined;
                    failRequest(ssl, &entry, null, 413, std.fmt.bufPrint(&rb, "body over --max-body ({d} bytes)", .{dec.decoded_total}) catch "body over --max-body");
                    discardPendingInput(ssl, client_sock);
                    return;
                }
                if (pr.state != .done and !upstream_failed) {
                    if (pr.state == .parse_error) {
                        entry.req_body_truncated = true;
                        failRequest(ssl, &entry, null, 400, "bad chunked encoding");
                        discardPendingInput(ssl, client_sock);
                    }
                    return; // bad framing, or client gone mid-body
                }
                leftover = pr.leftover;
            } else {
                const br = http_wire.streamBody(buffered, SslSource{ .ssl = ssl }, up_sink, content_length, &entry.req_body);
                entry.req_body_len = @intCast(br.captured);
                entry.req_body_total = br.total;
                entry.req_body_truncated = br.truncated;
                if (br.total < content_length and !upstream_failed) return; // client gone mid-body
                leftover = br.leftover;
            }
        }
        if (upstream_failed) {
            // Upstream stopped taking the request (closed, or a 30s send timeout):
            // don't drain the rest of the upload into it.
            log.err("component=proxy conn={d} op=upstream_write error=write_failed", .{conn_id});
            failRequest(ssl, &entry, held, 502, "upstream stopped reading the request");
            discardPendingInput(ssl, client_sock);
            return;
        }
        @memcpy(carry_buf[0..leftover.len], leftover);
        carry_len = leftover.len;

        // Read and parse the upstream response head
        var resp_buf: [16384]u8 = undefined;
        const head_src = UpstreamReader{ .conn = upstream, .deadline_ms = deadlineAfter(config.upstream_timeout_s) };
        const head = switch (http_wire.readResponseHeadResult(head_src, &resp_buf)) {
            .head => |h| h,
            .closed => {
                failRequest(ssl, &entry, held, 502, "upstream closed before responding");
                return;
            },
            .too_large => {
                failRequest(ssl, &entry, held, 502, "response head over 16KB");
                return;
            },
            .timeout => {
                var rb: [48]u8 = undefined;
                failRequest(ssl, &entry, held, 504, std.fmt.bufPrint(&rb, "no response within {d}s", .{config.upstream_timeout_s}) catch "no response in time");
                return;
            },
        };
        entry.status = head.status;

        // Capture response headers
        const resp_headers_section = head.headers;
        const rsh_len = @min(resp_headers_section.len, requests.max_header_len);
        @memcpy(entry.resp_headers[0..rsh_len], resp_headers_section[0..rsh_len]);
        entry.resp_headers_len = @intCast(rsh_len);
        entry.resp_headers_truncated = resp_headers_section.len > requests.max_header_len;

        // HEAD, 1xx, 204 and 304 never carry a body, whatever their framing headers
        // say; reading one would wait for bytes that never come.
        const has_body = http_wire.responseHasBody(method, head.status);

        // Determine if we must close after this response
        const is_chunked = has_body and http_wire.isChunkedEncoding(resp_headers_section);
        const resp_content_length: ?usize = if (has_body) http_wire.getContentLength(resp_headers_section) else 0;
        const upstream_conn = http_wire.getConnectionHeader(resp_headers_section);
        const response_has_defined_length = is_chunked or resp_content_length != null;
        const must_close = !keep_alive or upstream_conn == .close or !response_has_defined_length;

        const relay_ctx: RelayCtx = .{
            .is_external = is_external,
            .domain = config.domain,
            .must_close = must_close,
            .is_chunked = is_chunked,
            .content_length = resp_content_length,
            .has_body = has_body,
            .public_host = public_host,
        };
        var resp_dec = http_wire.ChunkedDecoder{};
        var prefetched: []const u8 = "";
        var resp_probe_buf: ?[]u8 = null;
        defer if (resp_probe_buf) |b| std.heap.page_allocator.free(b);

        if (intercept.shouldInterceptResponse(method, uri)) resp_hold: {
            // Hold only a response whose capture is complete; else relay it unheld.
            var fits = !entry.resp_headers_truncated;
            // The probe gives up at --timeout; what it read so far is relayed unheld.
            const probe_src = UpstreamReader{ .conn = upstream, .deadline_ms = deadlineAfter(config.upstream_timeout_s) };
            if (fits and has_body) {
                if (is_chunked or resp_content_length == null) {
                    const raw = std.heap.page_allocator.alloc(u8, probe_cap) catch break :resp_hold;
                    resp_probe_buf = raw;
                    if (is_chunked) {
                        const p = probeChunked(&resp_dec, head.initial_body, probe_src, &entry.resp_body, raw);
                        if (p.outcome == .complete) {
                            entry.resp_body_len = @intCast(resp_dec.captured);
                            entry.resp_body_total = resp_dec.decoded_total;
                        } else if (p.outcome == .too_large or p.outcome == .timed_out) {
                            fits = false;
                            prefetched = p.raw;
                        } else return; // bad framing or upstream gone before the end
                    } else {
                        const p = probeUntilClose(head.initial_body, probe_src, raw[0 .. requests.max_body_len + 1]);
                        if (p.complete) {
                            @memcpy(entry.resp_body[0..p.raw.len], p.raw);
                            entry.resp_body_len = @intCast(p.raw.len);
                            entry.resp_body_total = p.raw.len;
                        } else {
                            fits = false;
                            prefetched = p.raw;
                        }
                    }
                } else if (resp_content_length.? <= requests.max_body_len) {
                    const br = http_wire.streamBody(head.initial_body, probe_src, http_wire.NullSink{}, resp_content_length, &entry.resp_body);
                    entry.resp_body_len = @intCast(br.captured);
                    entry.resp_body_total = br.total;
                    if (br.total < resp_content_length.?) {
                        // Timed out (or closed) short: the bytes read sit in the capture.
                        fits = false;
                        prefetched = entry.resp_body[0..br.captured];
                    }
                } else {
                    fits = false;
                }
            }
            if (!fits) {
                entry.too_large_to_intercept = true;
                break :resp_hold;
            }

            // Record when upstream response was fully received
            const resp_received_time = rt.milliTimestamp();
            const upstream_dur = resp_received_time - start_time;
            const req_dur: u64 = if (upstream_dur > 0) @intCast(upstream_dur) else 0;

            // Push or finish the request entry with upstream round-trip time
            if (was_intercepted) {
                requests.finishEntry(intercept_backing_idx, entry.status, req_dur, entry.resp_headers[0..entry.resp_headers_len], entry.resp_body[0..entry.resp_body_len]);
            } else {
                // Push request entry (copies into ring buffer, so we can reuse entry for response)
                entry.duration_ms = req_dur;
                requests.push(entry);
            }

            // Reuse entry for response intercept — use resp_received_time as timestamp
            entry.state = .intercepted;
            entry.resp_intercepted = true;
            entry.timestamp = resp_received_time;
            if (hold.begin(&entry, true, resp_received_time)) |h| {
                switch (h.awaitDecision()) {
                    .drop => {
                        h.drop();
                        sslSendError(ssl, 502, "Dropped by intercept");
                        return;
                    },
                    else => {
                        // Accept — forward the (possibly TUI-edited) response, read off the lock.
                        h.accept();
                        const resp_snap = std.heap.page_allocator.create(requests.Entry) catch {
                            requests.finishResponseIntercept(h.index(), 0);
                            sslSendError(ssl, 502, "Out of memory");
                            return;
                        };
                        defer std.heap.page_allocator.destroy(resp_snap);
                        requests.snapshotByBackingIndex(h.index(), resp_snap);
                        forwardResponseFromEntry(ssl, resp_snap, is_external, config.domain, must_close, has_body, public_host);

                        // Duration = hold time only
                        const hold_elapsed = rt.milliTimestamp() - resp_received_time;
                        requests.finishResponseIntercept(h.index(), if (hold_elapsed > 0) @intCast(hold_elapsed) else 0);

                        if (must_close) return;
                        setSocketTimeout(client_sock, .recv, 15);
                        continue;
                    },
                }
            } else {
                // Ring full of pins, or all slots busy — begin restored any pushed
                // entry to a normal capture; forward the buffered response untouched.
                entry.state = .normal;
                entry.resp_intercepted = false;
            }

            // Fell through: intercept skipped, forward buffered response normally.
            forwardResponseFromEntry(ssl, &entry, is_external, config.domain, must_close, has_body, public_host);

            if (must_close) return;
            setSocketTimeout(client_sock, .recv, 15);
            continue;
        }

        relayResponse(ssl, head, UpstreamReader{ .conn = upstream }, &entry, relay_ctx, &resp_dec, prefetched);

        const elapsed = rt.milliTimestamp() - start_time;
        entry.duration_ms = if (elapsed > 0) @intCast(elapsed) else 0;

        if (was_intercepted) {
            requests.finishEntry(
                intercept_backing_idx,
                entry.status,
                entry.duration_ms,
                entry.resp_headers[0..entry.resp_headers_len],
                entry.resp_body[0..entry.resp_body_len],
            );
        } else {
            requests.push(entry);
        }

        if (must_close) return;

        // Shorter idle timeout for subsequent requests on this connection
        setSocketTimeout(client_sock, .recv, 15);
    }
}

/// The visitor's address for X-Real-IP on a shared request: `CF-Connecting-IP`,
/// trusted only from a loopback peer (cloudflared runs locally) and only when it is
/// a bare IPv4/IPv6 literal. Empty means use the peer address.
fn shareRealIp(peer: std.Io.net.IpAddress, headers: []const u8) []const u8 {
    if (!compat.isLoopback(peer)) return "";
    const v = http_wire.getHeaderValue(headers, "cf-connecting-ip:") orelse return "";
    if (v.len == 0) return "";
    for (v) |c| {
        if (!std.ascii.isHex(c) and c != '.' and c != ':') return "";
    }
    _ = std.Io.net.IpAddress.parse(v, 0) catch return "";
    return v;
}

/// Everything forwardRequest needs beyond the entry itself: routing target and the
/// client identity to stamp into X-Forwarded-* / X-Real-IP headers.
const RequestForward = struct {
    is_external: bool,
    upstream_host: []const u8,
    client_host: []const u8, // original Host header, preserved as X-Forwarded-Host
    client_ip: []const u8,
    client_xff: []const u8 = "", // client's own X-Forwarded-For, extended with client_ip
    domain: []const u8,
    /// Arrived through the share tunnel: a local upstream gets `Host: <domain>`.
    shared: bool = false,
    /// X-Real-IP override (a validated CF-Connecting-IP); empty uses client_ip.
    real_ip: []const u8 = "",
};

/// Headers zlodev writes itself (client copies dropped so they aren't doubled or
/// spoofed), plus Accept-Encoding so upstreams answer uncompressed and the TUI
/// shows readable bodies.
const proxy_owned_headers = [_][]const u8{ "cache-control:", "accept-encoding:", "x-forwarded-host:", "x-forwarded-for:", "x-forwarded-proto:", "x-real-ip:" };

/// The proxy's own headers after the forwarded block: the Host rewrite (external
/// upstream host, or the local domain for shared requests), X-Forwarded-Host
/// (original Host), X-Forwarded-For, X-Real-IP, X-Forwarded-Proto,
/// Accept-Encoding: identity, no-cache.
fn writeProxyHeaders(sink: anytype, ctx: RequestForward) void {
    if (ctx.is_external) {
        sink.write("Host: ");
        sink.write(ctx.upstream_host);
        sink.write("\r\n");
    } else if (ctx.shared) {
        sink.write("Host: ");
        sink.write(ctx.domain);
        sink.write("\r\n");
    }
    if (ctx.client_host.len > 0) {
        sink.write("X-Forwarded-Host: ");
        sink.write(ctx.client_host);
        sink.write("\r\n");
    }
    sink.write("X-Forwarded-For: ");
    if (ctx.client_xff.len > 0) {
        sink.write(ctx.client_xff);
        sink.write(", ");
    }
    sink.write(ctx.client_ip);
    sink.write("\r\n");
    sink.write("X-Real-IP: ");
    sink.write(if (ctx.real_ip.len > 0) ctx.real_ip else ctx.client_ip);
    sink.write("\r\n");
    sink.write("X-Forwarded-Proto: https\r\n");
    // Explicit: a request without Accept-Encoding accepts any coding (RFC 9110 12.5.3).
    sink.write("Accept-Encoding: identity\r\n");
    sink.write("Cache-Control: no-cache\r\n");
    sink.write("Pragma: no-cache\r\n");
}

/// Emit the client's request head as received — original method, URI and full
/// header block — with the proxy's header policy, ending with the blank line. The
/// body follows as sent, so framing headers stay; only `Content-Length` is dropped
/// when the body is chunked (chunked wins, RFC 9112 6.3).
fn forwardRequestHead(sink: anytype, method: []const u8, uri: []const u8, headers: []const u8, chunked: bool, ctx: RequestForward) void {
    sink.write(method);
    sink.write(" ");
    sink.write(uri);
    sink.write(" HTTP/1.1\r\n");
    var skip_buf: [proxy_owned_headers.len + 2][]const u8 = undefined;
    @memcpy(skip_buf[0..proxy_owned_headers.len], &proxy_owned_headers);
    var n: usize = proxy_owned_headers.len;
    if (chunked) {
        skip_buf[n] = "content-length:";
        n += 1;
    }
    if (ctx.is_external or ctx.shared) {
        skip_buf[n] = "host:";
        n += 1;
    }
    http_wire.forwardHeaders(headers, sink, .{ .skip = skip_buf[0..n] }, ctx.domain);
    writeProxyHeaders(sink, ctx);
    sink.write("\r\n");
}

/// Emit a held (possibly TUI-edited) request entry to `sink` (`write([]const u8)
/// void`): request line, forwarded request headers, the proxy's own headers, a
/// recomputed Content-Length, and the body. Used only for held requests, whose
/// capture is complete by construction; a chunked original goes out de-chunked.
fn forwardRequest(sink: anytype, e: *const requests.Entry, ctx: RequestForward) void {
    sink.write(e.getMethod());
    sink.write(" ");
    sink.write(e.getPath());
    sink.write(" HTTP/1.1\r\n");
    const headers = e.getReqHeaders();
    if (headers.len > 0) {
        const framing = [_][]const u8{ "content-length:", "transfer-encoding:" };
        var skip_buf: [proxy_owned_headers.len + framing.len + 1][]const u8 = undefined;
        @memcpy(skip_buf[0..proxy_owned_headers.len], &proxy_owned_headers);
        @memcpy(skip_buf[proxy_owned_headers.len..][0..framing.len], &framing);
        var n: usize = proxy_owned_headers.len + framing.len;
        if (ctx.is_external or ctx.shared) {
            skip_buf[n] = "host:";
            n += 1;
        }
        http_wire.forwardHeaders(headers, sink, .{ .skip = skip_buf[0..n] }, ctx.domain);
    }
    writeProxyHeaders(sink, ctx);
    const body = e.getReqBody();
    var cl_buf: [64]u8 = undefined;
    const cl_hdr = std.fmt.bufPrint(&cl_buf, "Content-Length: {d}\r\n", .{body.len}) catch "";
    sink.write(cl_hdr);
    sink.write("\r\n");
    if (body.len > 0) sink.write(body);
}

/// Forward a buffered response from an entry to the client.
/// Used after response intercept (accept) to send the (possibly edited) response.
/// `has_body` false (HEAD, 1xx, 204, 304): the upstream's Content-Length is kept
/// as-is (for HEAD it describes the GET body) and no body is sent.
fn forwardResponseFromEntry(ssl: *ssl_c.SSL, e: *const requests.Entry, is_external: bool, domain: []const u8, must_close: bool, has_body: bool, public_host: ?[]const u8) void {
    // Build and send status line
    var status_buf: [64]u8 = undefined;
    const status_line = std.fmt.bufPrint(&status_buf, "HTTP/1.1 {d} {s}\r\n", .{ e.status, http_wire.reasonPhrase(e.status) }) catch return;
    sslWriteAll(ssl, status_line);

    // Forward response headers. Connection, Content-Length, and Transfer-Encoding
    // are dropped — Content-Length is recomputed below and Connection appended.
    http_wire.forwardHeaders(e.getRespHeaders(), SslSink{ .ssl = ssl }, .{
        .skip = if (has_body) &.{ "connection:", "content-length:", "transfer-encoding:" } else &.{"connection:"},
        .rewrite_set_cookie = is_external,
        .public_host = public_host,
    }, domain);

    // Set Content-Length to match actual body (may have been edited)
    const body = if (has_body) e.getRespBody() else e.getRespBody()[0..0];
    if (has_body) {
        var cl_buf: [64]u8 = undefined;
        const cl_hdr = std.fmt.bufPrint(&cl_buf, "Content-Length: {d}\r\n", .{body.len}) catch "";
        sslWriteAll(ssl, cl_hdr);
    }

    if (must_close) {
        sslWriteAll(ssl, "Connection: close\r\n");
    } else {
        sslWriteAll(ssl, "Connection: keep-alive\r\n");
    }
    sslWriteAll(ssl, "\r\n");

    // Send body
    if (body.len > 0) {
        sslWriteAll(ssl, body);
    }
}

const RelayCtx = struct {
    is_external: bool,
    domain: []const u8,
    must_close: bool,
    is_chunked: bool,
    content_length: ?usize,
    has_body: bool,
    /// Shared request: Location and Set-Cookie Domain rewritten for the public host.
    public_host: ?[]const u8 = null,
};

/// Stream an upstream response to the client as received: status line, headers
/// (Connection replaced, Set-Cookie Domain rewritten for external routes), then the
/// body, capturing up to max_body_len into `entry`. `prefetched` holds body bytes an
/// intercept probe already read (relayed first); for chunked bodies `dec` carries
/// the probe's decoder state, else it is fresh.
fn relayResponse(ssl: *ssl_c.SSL, head: http_wire.ResponseHead, upstream: UpstreamReader, entry: *requests.Entry, ctx: RelayCtx, dec: *http_wire.ChunkedDecoder, prefetched: []const u8) void {
    const sink = SslSink{ .ssl = ssl };
    sslWriteAll(ssl, head.status_line);
    http_wire.forwardHeaders(head.headers, sink, .{
        .skip = &.{"connection:"},
        .rewrite_set_cookie = ctx.is_external,
        .public_host = ctx.public_host,
    }, ctx.domain);
    sslWriteAll(ssl, if (ctx.must_close) "Connection: close\r\n" else "Connection: keep-alive\r\n");
    sslWriteAll(ssl, "\r\n");
    if (!ctx.has_body) return;

    var read_buf: [16384]u8 = undefined;
    if (ctx.is_chunked) {
        var initial = head.initial_body;
        if (prefetched.len > 0) {
            sink.write(prefetched);
            initial = "";
        }
        const pr = http_wire.pumpChunkedResume(dec, initial, upstream, sink, &entry.resp_body, &read_buf, std.math.maxInt(u64));
        entry.resp_body_len = @intCast(pr.captured);
        entry.resp_body_truncated = pr.truncated;
        entry.resp_body_total = dec.decoded_total;
    } else if (prefetched.len > 0 and ctx.content_length != null) {
        // Content-Length body whose intercept fit read timed out: its first bytes
        // are already in the capture; relay them, then stream the rest.
        sink.write(prefetched);
        const br = http_wire.streamBody("", upstream, sink, ctx.content_length.? - prefetched.len, entry.resp_body[prefetched.len..]);
        entry.resp_body_len = @intCast(prefetched.len + br.captured);
        entry.resp_body_truncated = br.truncated;
        entry.resp_body_total = prefetched.len + br.total;
    } else if (prefetched.len > 0) {
        // Read-to-close body the probe outgrew: relay it, capture its head, stream the rest.
        sink.write(prefetched);
        const cap = @min(prefetched.len, entry.resp_body.len);
        @memcpy(entry.resp_body[0..cap], prefetched[0..cap]);
        const br = http_wire.streamBody("", upstream, sink, null, entry.resp_body[0..0]);
        entry.resp_body_len = @intCast(cap);
        entry.resp_body_truncated = true;
        entry.resp_body_total = prefetched.len + br.total;
    } else {
        const br = http_wire.streamBody(head.initial_body, upstream, sink, ctx.content_length, &entry.resp_body);
        entry.resp_body_len = @intCast(br.captured);
        entry.resp_body_truncated = br.truncated;
        entry.resp_body_total = br.total;
    }
}

/// Read a read-to-close body into `raw` (starting with `initial`) until `src`
/// closes or `raw` fills; `complete` means it closed first.
fn probeUntilClose(initial: []const u8, src: anytype, raw: []u8) struct { complete: bool, raw: []const u8 } {
    @memcpy(raw[0..initial.len], initial);
    var len: usize = initial.len;
    while (len < raw.len) {
        // A timeout is not the end of the body: report it as not complete.
        const n = src.read(raw[len..]) catch |e| {
            if (http_wire.isTimeout(e)) return .{ .complete = false, .raw = raw[0..len] };
            return .{ .complete = true, .raw = raw[0..len] };
        };
        if (n == 0) return .{ .complete = true, .raw = raw[0..len] };
        len += n;
    }
    return .{ .complete = false, .raw = raw[0..len] };
}

/// Forwarding sink for `http_wire` over the client TLS connection — relays bytes
/// to the browser (chunked body, response headers). Write failures are swallowed,
/// matching `sslWriteAll`; the caller's next write detects the dead connection.
const SslSink = struct {
    ssl: *ssl_c.SSL,
    pub fn write(self: SslSink, bytes: []const u8) void {
        sslWriteAll(self.ssl, bytes);
    }
};

/// Forwarding sink for request bytes over the upstream connection.
const UpstreamSink = struct {
    upstream: UpstreamConn,
    /// Set on the first failed write; later writes are skipped and body relays
    /// (`http_wire.streamBody`/`pumpChunkedResume`) stop reading the client.
    failed: ?*bool = null,
    pub fn write(self: UpstreamSink, bytes: []const u8) void {
        if (self.isFailed()) return;
        self.upstream.writeAll(bytes) catch {
            if (self.failed) |f| f.* = true;
        };
    }
    pub fn isFailed(self: UpstreamSink) bool {
        return if (self.failed) |f| f.* else false;
    }
};

/// Read side of the client TLS session for `http_wire` (`read([]u8) !usize`).
/// 0 = client closed; errors (timeout, reset) end the read too.
const SslSource = struct {
    ssl: *ssl_c.SSL,
    pub fn read(self: SslSource, buf: []u8) !usize {
        const n = ssl_c.SSL_read(self.ssl, @ptrCast(buf.ptr), @intCast(buf.len));
        if (n < 0) return error.SslRead;
        return @intCast(n);
    }
};

/// Read and discard what the client already sent (bounded), so closing right after
/// an early error response doesn't reset the connection and lose that response.
fn discardPendingInput(ssl: *ssl_c.SSL, sock: compat.socket_t) void {
    var scratch: [16384]u8 = undefined;
    var budget: usize = 1024 * 1024;
    while (budget > 0) {
        if (ssl_c.SSL_pending(ssl) == 0) {
            var fds = [1]compat.pollfd{.{ .fd = sock, .events = compat.POLL.IN, .revents = 0 }};
            if (compat.pollWhileRunning(&fds, 100, shutdown.isRunning) != .ready) return;
        }
        const n = ssl_c.SSL_read(ssl, @ptrCast(&scratch), scratch.len);
        if (n <= 0) return;
        budget -|= @intCast(n);
    }
}

/// Most raw bytes a probe buffers while deciding whether a chunked or read-to-close
/// body fits the capture. Framing can outweigh the payload (tiny chunks); a body
/// whose framing fills this is treated as too large to hold.
const probe_cap = 4 * requests.max_body_len;

const Probe = struct {
    outcome: enum { complete, too_large, parse_error, ended, timed_out },
    /// The message bytes read so far, framing included — relayed first if not held.
    raw: []const u8,
    /// Bytes read past the end of the message (a pipelined request).
    leftover: []const u8,
};

/// Read a chunked body into `raw` (starting with `initial`) while `dec` decodes it
/// into `capture`, until the message ends, the capture overflows, `raw` fills, or
/// `src` ends. `initial.len` must be <= `raw.len`.
fn probeChunked(dec: *http_wire.ChunkedDecoder, initial: []const u8, src: anytype, capture: []u8, raw: []u8) Probe {
    @memcpy(raw[0..initial.len], initial);
    var len: usize = initial.len;
    var scan: usize = 0;
    while (true) {
        scan += dec.feed(raw[scan..len], capture);
        if (dec.state == .parse_error) return .{ .outcome = .parse_error, .raw = raw[0..scan], .leftover = "" };
        if (dec.state == .done) return .{ .outcome = if (dec.truncated) .too_large else .complete, .raw = raw[0..scan], .leftover = raw[scan..len] };
        if (dec.truncated or len == raw.len) return .{ .outcome = .too_large, .raw = raw[0..scan], .leftover = "" };
        const n = src.read(raw[len..]) catch |e| {
            if (http_wire.isTimeout(e)) return .{ .outcome = .timed_out, .raw = raw[0..scan], .leftover = "" };
            return .{ .outcome = .ended, .raw = raw[0..scan], .leftover = "" };
        };
        if (n == 0) return .{ .outcome = .ended, .raw = raw[0..scan], .leftover = "" };
        len += n;
    }
}

/// Emit a captured request for replay: request line, stored headers with
/// Content-Length, Transfer-Encoding and Connection replaced, and the stored body.
fn writeReplayRequest(sink: anytype, source: *const requests.Entry) void {
    sink.write(source.getMethod());
    sink.write(" ");
    sink.write(source.getPath());
    sink.write(" HTTP/1.1\r\n");
    const req_hdrs = source.getReqHeaders();
    const body = source.getReqBody();
    if (req_hdrs.len > 0) {
        var hdr_iter = std.mem.splitSequence(u8, req_hdrs, "\r\n");
        while (hdr_iter.next()) |header| {
            if (header.len == 0) continue;
            if (std.ascii.startsWithIgnoreCase(header, "content-length:")) continue;
            if (std.ascii.startsWithIgnoreCase(header, "connection:")) continue;
            // The stored body is de-chunked; sending it under its original
            // Transfer-Encoding would make the proxy parse it as chunk framing.
            if (std.ascii.startsWithIgnoreCase(header, "transfer-encoding:")) continue;
            sink.write(header);
            sink.write("\r\n");
        }
    }
    var cl_buf: [64]u8 = undefined;
    const cl_hdr = std.fmt.bufPrint(&cl_buf, "Content-Length: {d}\r\n", .{body.len}) catch return;
    sink.write(cl_hdr);
    sink.write("Connection: close\r\n");
    sink.write("\r\n");
    if (body.len > 0) sink.write(body);
}

/// Replay a stored request through the proxy's own TLS endpoint.
/// Connects to 127.0.0.1:443 over TLS so the request goes through the full
/// proxy path (TLS termination → upstream → response). The proxy's handleConnection
/// naturally creates the log entry.
pub fn replay(source: *const requests.Entry) void {
    defer std.heap.page_allocator.destroy(source);

    // Create TLS client context (skip cert verification — it's our own self-signed cert)
    const ctx = ssl_c.SSL_CTX_new(ssl_c.TLS_client_method()) orelse {
        log.err("component=proxy op=replay_ssl_init error=context_create_failed", .{});
        return;
    };
    defer ssl_c.SSL_CTX_free(ctx);
    ssl_c.SSL_CTX_set_verify(ctx, ssl_c.SSL_VERIFY_NONE, null);

    // Connect TCP to the proxy's own HTTPS endpoint
    const proxy_addr = std.Io.net.IpAddress.parse("127.0.0.1", 443) catch |e| {
        log.err("component=proxy op=replay_connect error={any}", .{e});
        return;
    };
    const sock = compat.tcpConnect(proxy_addr) catch |e| {
        log.err("component=proxy op=replay_connect error={any}", .{e});
        return;
    };

    // Set up TLS — SSL_set_fd uses BIO_NOCLOSE, so we must close sock ourselves.
    const ssl = ssl_c.SSL_new(ctx) orelse {
        log.err("component=proxy op=replay_ssl_new error=alloc_failed", .{});
        compat.closeSocket(sock);
        return;
    };
    _ = ssl_c.SSL_set_fd(ssl, compat.socketToFd(sock));
    defer {
        _ = ssl_c.SSL_shutdown(ssl);
        ssl_c.SSL_free(ssl);
        compat.closeSocket(sock);
    }

    if (ssl_c.SSL_connect(ssl) != 1) {
        log.err("component=proxy op=replay_ssl_connect error=handshake_failed", .{});
        return;
    }

    writeReplayRequest(SslSink{ .ssl = ssl }, source);

    // Read and discard the response — the proxy's handleConnection already
    // captures it and pushes the entry to the request log.
    var resp_buf: [16384]u8 = undefined;
    while (true) {
        const n = ssl_c.SSL_read(ssl, @ptrCast(&resp_buf), @intCast(resp_buf.len));
        if (n <= 0) break;
    }
}

fn sslWriteAll(ssl: *ssl_c.SSL, data: []const u8) void {
    var written: usize = 0;
    while (written < data.len) {
        const n = ssl_c.SSL_write(ssl, @ptrCast(data[written..].ptr), @intCast(data.len - written));
        if (n <= 0) return;
        written += @as(usize, @intCast(n));
    }
}

fn sslSendError(ssl: *ssl_c.SSL, status: u16, message: []const u8) void {
    var buf: [512]u8 = undefined;
    const response = std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        status, message, message.len, message,
    }) catch return;
    sslWriteAll(ssl, response);
}

/// Error response whose status line uses the standard phrase and whose body is
/// `reason`, so the browser shows what went wrong.
fn sslSendReason(ssl: *ssl_c.SSL, status: u16, reason: []const u8) void {
    var buf: [512]u8 = undefined;
    const response = std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        status, http_wire.reasonPhrase(status), reason.len, reason,
    }) catch return;
    sslWriteAll(ssl, response);
}

/// zlodev answered this request itself: tell the client, then record the entry
/// with `status` and `reason`, finishing the held ring entry if it was intercepted.
fn failRequest(ssl: *ssl_c.SSL, entry: *requests.Entry, held: ?usize, status: u16, reason: []const u8) void {
    log.err("component=proxy op=fail_request method={s} uri={s} status={d} reason=\"{s}\"", .{ entry.getMethod(), entry.getPath(), status, reason });
    sslSendReason(ssl, status, reason);
    const elapsed = rt.milliTimestamp() - entry.timestamp;
    const dur: u64 = if (elapsed > 0) @intCast(elapsed) else 0;
    if (held) |idx| {
        requests.finishFailed(idx, status, dur, reason);
        return;
    }
    entry.status = status;
    entry.duration_ms = dur;
    entry.setError(reason);
    requests.push(entry.*);
}

const FailReason = struct { status: u16, reason: []const u8 };

fn connectReason(buf: []u8, e: UpstreamError, host: []const u8, port: u16, timeout_s: u32) FailReason {
    return switch (e) {
        error.ConnectRefused => .{ .status = 502, .reason = std.fmt.bufPrint(buf, "connection refused {s}:{d}", .{ host, port }) catch "connection refused" },
        error.ConnectFailed => .{ .status = 502, .reason = std.fmt.bufPrint(buf, "connect failed {s}:{d}", .{ host, port }) catch "connect failed" },
        error.DnsFailed => .{ .status = 502, .reason = std.fmt.bufPrint(buf, "DNS lookup failed {s}", .{host}) catch "DNS lookup failed" },
        error.ConnectTimeout => .{ .status = 504, .reason = std.fmt.bufPrint(buf, "connect timed out after {d}s {s}:{d}", .{ timeout_s, host, port }) catch "connect timed out" },
        error.TlsFailed => .{ .status = 502, .reason = std.fmt.bufPrint(buf, "TLS handshake failed {s}", .{host}) catch "TLS handshake failed" },
        error.UpstreamCertUntrusted => .{ .status = 502, .reason = std.fmt.bufPrint(buf, "upstream certificate not trusted {s} (use --insecure-upstream to skip verification)", .{host}) catch "upstream certificate not trusted" },
    };
}

/// Fill method, path and the headers that fit from a head too big to parse whole.
/// No request line in the bytes: method and path are "?".
fn fillRequestLine(entry: *requests.Entry, head: []const u8) void {
    const line_end = std.mem.indexOf(u8, head, "\r\n");
    var method: []const u8 = "?";
    var path: []const u8 = "?";
    if (line_end) |le| {
        var parts = std.mem.splitScalar(u8, head[0..le], ' ');
        method = parts.next() orelse "?";
        path = parts.next() orelse "?";
    }
    entry.method_len = @intCast(@min(method.len, entry.method.len));
    @memcpy(entry.method[0..entry.method_len], method[0..entry.method_len]);
    entry.path_len = @intCast(@min(path.len, entry.path.len));
    @memcpy(entry.path[0..entry.path_len], path[0..entry.path_len]);
    entry.path_truncated = path.len > entry.path.len or line_end == null;
    const rest = if (line_end) |le| head[le + 2 ..] else "";
    const n = @min(rest.len, requests.max_header_len);
    @memcpy(entry.req_headers[0..n], rest[0..n]);
    entry.req_headers_len = @intCast(n);
    entry.req_headers_truncated = true;
}

const WsTarget = struct { is_external: bool, host: []const u8, port: u16 };

fn handleWebSocket(
    ssl: *ssl_c.SSL,
    raw_request: []const u8,
    config: *const ProxyConfig,
    target: WsTarget,
    fwd: RequestForward,
    client_ctx: ?*ssl_c.SSL_CTX,
    conn_id: u64,
    entry: *requests.Entry,
) void {
    log.info("component=proxy op=websocket_upgrade uri={s}", .{entry.getPath()});

    // Same connect path as plain requests: external routes get TLS + verification.
    const upstream = connectUpstream(target.is_external, target.host, target.port, config, client_ctx, conn_id) catch |e| {
        var rb: [192]u8 = undefined;
        const r = connectReason(&rb, e, target.host, target.port, config.upstream_timeout_s);
        failRequest(ssl, entry, null, r.status, r.reason);
        return;
    };
    defer upstream.close();

    // Forward the upgrade head with the same header policy as plain requests:
    // X-Real-IP, X-Forwarded-Proto, and on external routes Host rewritten (original
    // kept as X-Forwarded-Host). Origin is untouched.
    const first_end = std.mem.indexOf(u8, raw_request, "\r\n") orelse return;
    const hdr_end = std.mem.indexOf(u8, raw_request, "\r\n\r\n") orelse return;
    var line_parts = std.mem.splitScalar(u8, raw_request[0..first_end], ' ');
    const method = line_parts.next() orelse return;
    const uri = line_parts.next() orelse return;
    const headers = if (first_end + 2 <= hdr_end) raw_request[first_end + 2 .. hdr_end] else raw_request[0..0];
    var upstream_failed = false;
    const sink = UpstreamSink{ .upstream = upstream, .failed = &upstream_failed };
    forwardRequestHead(sink, method, uri, headers, false, fwd);
    sink.write(raw_request[hdr_end + 4 ..]);
    if (upstream_failed) return;

    // Read upstream response (expect 101 Switching Protocols) within --timeout
    const head_src = UpstreamReader{ .conn = upstream, .deadline_ms = deadlineAfter(config.upstream_timeout_s) };
    var resp_buf: [4096]u8 = undefined;
    var resp_total: usize = 0;
    var timed_out = false;
    while (resp_total < resp_buf.len) {
        const n = head_src.read(resp_buf[resp_total..]) catch |e| {
            timed_out = http_wire.isTimeout(e);
            break;
        };
        if (n == 0) break;
        resp_total += n;
        if (std.mem.indexOf(u8, resp_buf[0..resp_total], "\r\n\r\n") != null) break;
    }
    if (resp_total == 0) {
        if (timed_out) {
            var rb: [48]u8 = undefined;
            failRequest(ssl, entry, null, 504, std.fmt.bufPrint(&rb, "no response within {d}s", .{config.upstream_timeout_s}) catch "no response in time");
        } else failRequest(ssl, entry, null, 502, "upstream closed before responding");
        return;
    }

    // Forward response to client
    sslWriteAll(ssl, resp_buf[0..resp_total]);

    // Log as a WS entry (pinned so it won't be overwritten during long-lived connection)
    entry.status = 101;
    const elapsed = rt.milliTimestamp() - entry.timestamp;
    entry.duration_ms = if (elapsed > 0) @intCast(elapsed) else 0;
    // Store response headers
    if (std.mem.indexOf(u8, resp_buf[0..resp_total], "\r\n")) |resp_line_end| {
        if (std.mem.indexOf(u8, resp_buf[0..resp_total], "\r\n\r\n")) |resp_hdr_end| {
            const resp_hdrs = resp_buf[resp_line_end + 2 .. resp_hdr_end];
            const rh_len = @min(resp_hdrs.len, requests.max_header_len);
            @memcpy(entry.resp_headers[0..rh_len], resp_hdrs[0..rh_len]);
            entry.resp_headers_len = @intCast(rh_len);
        }
    }
    const ws_backing_idx = requests.pushAndPin(entry.*) orelse {
        // All slots pinned, push without pinning
        requests.push(entry.*);
        return;
    };

    relayWebSocket(ssl, upstream);
    requests.unpin(ws_backing_idx);
}

/// Bidirectional pipe between the TLS client and the upstream socket until
/// either side closes, 30s pass with no traffic, or shutdown starts.
fn relayWebSocket(ssl: *ssl_c.SSL, upstream: UpstreamConn) void {
    const raw_fd = ssl_c.SSL_get_fd(ssl);
    if (raw_fd < 0) return;
    const client_fd = compat.fdToSocket(raw_fd);

    var pipe_buf: [8192]u8 = undefined;
    while (true) {
        var fds = [2]compat.pollfd{
            .{ .fd = client_fd, .events = compat.POLL.IN, .revents = 0 },
            .{ .fd = upstream.sock.handle, .events = compat.POLL.IN, .revents = 0 },
        };
        // No idle timeout: HMR sockets sit quiet for minutes, and dropping one makes
        // clients like Vite reload the page. The pipe ends when either side closes;
        // shutdown still closes it within 1s.
        if (compat.pollWhileRunning(&fds, std.math.maxInt(u32), shutdown.isRunning) != .ready) break;

        // Client -> upstream
        if (fds[0].revents & compat.POLL.IN != 0) {
            // A TLS record (up to 16 KB) can outsize pipe_buf; drain what BoringSSL
            // already decrypted, since poll() only sees the socket.
            const ok = while (true) {
                const n = ssl_c.SSL_read(ssl, @ptrCast(&pipe_buf), @intCast(pipe_buf.len));
                if (n <= 0) break false;
                upstream.writeAll(pipe_buf[0..@intCast(n)]) catch break false;
                if (ssl_c.SSL_pending(ssl) == 0) break true;
            };
            if (!ok) break;
        }
        if (fds[0].revents & (compat.POLL.HUP | compat.POLL.ERR) != 0) break;

        // Upstream -> client
        if (fds[1].revents & compat.POLL.IN != 0) {
            // Same drain for a TLS upstream (external route).
            const ok = while (true) {
                const n = upstream.read(&pipe_buf) catch |e| {
                    if (e == error.WouldBlock) break true; // TLS record with no data yet
                    break false;
                };
                if (n == 0) break false;
                sslWriteAll(ssl, pipe_buf[0..n]);
                const pending = if (upstream.ssl_conn) |us| ssl_c.SSL_pending(us) else 0;
                if (pending == 0) break true;
            };
            if (!ok) break;
        }
        if (fds[1].revents & (compat.POLL.HUP | compat.POLL.ERR) != 0) break;
    }
}

/// Budget for a client to start and complete the TLS handshake. Without it a
/// TCP client that never sends a ClientHello pins a worker forever.
const handshake_timeout_s = 10;

/// Wait (shutdown-aware) for the ClientHello, then handshake with a per-read
/// receive timeout so a stalled client can't block SSL_accept either.
fn acceptTls(ssl: *ssl_c.SSL, client_sock: compat.socket_t, timeout_s: u32) bool {
    setSocketTimeout(client_sock, .recv, timeout_s);
    var fds = [1]compat.pollfd{.{ .fd = client_sock, .events = compat.POLL.IN, .revents = 0 }};
    if (compat.pollWhileRunning(&fds, timeout_s * 1000, shutdown.isRunning) != .ready) return false;
    return ssl_c.SSL_accept(ssl) == 1;
}

const SO_TIMEOUT = enum { recv, send };

fn setSocketTimeout(fd: posix.socket_t, which: SO_TIMEOUT, seconds: u32) void {
    if (builtin.os.tag == .windows) {
        // Windows SO_RCVTIMEO/SO_SNDTIMEO takes DWORD milliseconds
        const opt: i32 = switch (which) {
            .recv => 0x1006, // SO_RCVTIMEO
            .send => 0x1005, // SO_SNDTIMEO
        };
        const ms: u32 = seconds * 1000;
        const bytes = std.mem.toBytes(ms);
        _ = win32.setsockopt(fd, 0xffff, opt, &bytes, @sizeOf(@TypeOf(ms))); // 0xffff = SOL_SOCKET
    } else {
        const opt: u32 = switch (which) {
            .recv => ssl_c.SO_RCVTIMEO,
            .send => ssl_c.SO_SNDTIMEO,
        };
        const tv = ssl_c.struct_timeval{ .tv_sec = @intCast(seconds), .tv_usec = 0 };
        _ = ssl_c.setsockopt(fd, ssl_c.SOL_SOCKET, @intCast(opt), &tv, @sizeOf(@TypeOf(tv)));
    }
}

fn formatAddress(addr: std.Io.net.IpAddress, buf: []u8) []const u8 {
    // Format IP only, without port
    return switch (addr) {
        .ip4 => |a| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3] }) catch "0.0.0.0",
        .ip6 => |a| std.fmt.bufPrint(buf, "{f}", .{a}) catch "0.0.0.0",
    };
}

// --- Unit Tests ---

const testing = std.testing;

test "formatAddress IPv4" {
    const addr = std.Io.net.IpAddress.parseIp4("192.168.1.42", 8080) catch unreachable;
    var buf: [64]u8 = undefined;
    const result = formatAddress(addr, &buf);
    try testing.expectEqualStrings("192.168.1.42", result);
}

test "formatAddress loopback" {
    const addr = std.Io.net.IpAddress.parseIp4("127.0.0.1", 443) catch unreachable;
    var buf: [64]u8 = undefined;
    const result = formatAddress(addr, &buf);
    try testing.expectEqualStrings("127.0.0.1", result);
}

test "resolveRoute subdomain match" {
    const routes = [_]Route{
        .{ .kind = .subdomain, .pattern = "api", .port = 3001 },
    };
    const config = ProxyConfig{
        .target_host = "127.0.0.1",
        .target_port = 3000,
        .listen_addr = "0.0.0.0",
        .cert_path = "",
        .key_path = "",
        .ca_path = "",
        .server_ident = "",
        .routes = &routes,
    };
    const result = resolveRoute(&config, "api.dev.lo", "/test");
    try testing.expectEqual(@as(u16, 3001), result.port);
    try testing.expectEqual(@as(u8, 0), result.index);
    try testing.expect(result.hostname == null);
}

test "resolveRoute subdomain with port in host" {
    const routes = [_]Route{
        .{ .kind = .subdomain, .pattern = "api", .port = 3001 },
    };
    const config = ProxyConfig{
        .target_host = "127.0.0.1",
        .target_port = 3000,
        .listen_addr = "0.0.0.0",
        .cert_path = "",
        .key_path = "",
        .ca_path = "",
        .server_ident = "",
        .routes = &routes,
    };
    const result = resolveRoute(&config, "api.dev.lo:443", "/");
    try testing.expectEqual(@as(u16, 3001), result.port);
}

test "resolveRoute path match longest prefix" {
    const routes = [_]Route{
        .{ .kind = .path, .pattern = "/api", .port = 3001 },
        .{ .kind = .path, .pattern = "/api/v2", .port = 3002 },
    };
    const config = ProxyConfig{
        .target_host = "127.0.0.1",
        .target_port = 3000,
        .listen_addr = "0.0.0.0",
        .cert_path = "",
        .key_path = "",
        .ca_path = "",
        .server_ident = "",
        .routes = &routes,
    };
    const result = resolveRoute(&config, "dev.lo", "/api/v2/users");
    try testing.expectEqual(@as(u16, 3002), result.port);
    try testing.expectEqual(@as(u8, 1), result.index);
}

test "resolveRoute default fallback" {
    const routes = [_]Route{
        .{ .kind = .subdomain, .pattern = "api", .port = 3001 },
    };
    const config = ProxyConfig{
        .target_host = "127.0.0.1",
        .target_port = 3000,
        .listen_addr = "0.0.0.0",
        .cert_path = "",
        .key_path = "",
        .ca_path = "",
        .server_ident = "",
        .routes = &routes,
    };
    const result = resolveRoute(&config, "dev.lo", "/");
    try testing.expectEqual(@as(u16, 3000), result.port);
    try testing.expectEqual(@as(u8, 0xff), result.index);
}

test "resolveRoute external hostname" {
    const routes = [_]Route{
        .{ .kind = .subdomain, .pattern = "api", .port = 443, .hostname = "staging.example.com" },
    };
    const config = ProxyConfig{
        .target_host = "127.0.0.1",
        .target_port = 3000,
        .listen_addr = "0.0.0.0",
        .cert_path = "",
        .key_path = "",
        .ca_path = "",
        .server_ident = "",
        .routes = &routes,
    };
    const result = resolveRoute(&config, "api.dev.lo", "/");
    try testing.expectEqual(@as(u16, 443), result.port);
    try testing.expectEqualStrings("staging.example.com", result.hostname.?);
}

test "resolveRoute no routes" {
    const config = ProxyConfig{
        .target_host = "127.0.0.1",
        .target_port = 8080,
        .listen_addr = "0.0.0.0",
        .cert_path = "",
        .key_path = "",
        .ca_path = "",
        .server_ident = "",
    };
    const result = resolveRoute(&config, "dev.lo", "/anything");
    try testing.expectEqual(@as(u16, 8080), result.port);
    try testing.expectEqual(@as(u8, 0xff), result.index);
}

test "default_max_request_body is 10MB" {
    try testing.expectEqual(@as(usize, 10 * 1024 * 1024), default_max_request_body);
}

test "getContentLength detects values above default_max_request_body" {
    // A Content-Length of 20MB should be parseable (validation is done by caller)
    const cl = http_wire.getContentLength("Content-Length: 20971520\r\n");
    try testing.expect(cl != null);
    try testing.expect(cl.? > default_max_request_body);
}

/// Records bytes written to it, for asserting forwardRequest output without a socket.
const TestSink = struct {
    buf: []u8,
    len: *usize,
    pub fn write(self: TestSink, bytes: []const u8) void {
        const n = @min(bytes.len, self.buf.len - self.len.*);
        @memcpy(self.buf[self.len.*..][0..n], bytes[0..n]);
        self.len.* += n;
    }
};

fn buildEntry(method: []const u8, path: []const u8, headers: []const u8, body: []const u8) requests.Entry {
    var e = requests.Entry{};
    @memcpy(e.method[0..method.len], method);
    e.method_len = @intCast(method.len);
    @memcpy(e.path[0..path.len], path);
    e.path_len = @intCast(path.len);
    @memcpy(e.req_headers[0..headers.len], headers);
    e.req_headers_len = @intCast(headers.len);
    @memcpy(e.req_body[0..body.len], body);
    e.req_body_len = @intCast(body.len);
    return e;
}

test "forwardRequest emits a local request, dropping cache-control and content-length" {
    const e = buildEntry("GET", "/api/x", "Host: dev.lo\r\nCache-Control: max-age=9\r\nContent-Length: 0\r\nAccept: */*\r\n", "");
    var out: [512]u8 = undefined;
    var len: usize = 0;
    forwardRequest(TestSink{ .buf = &out, .len = &len }, &e, .{
        .is_external = false,
        .upstream_host = "127.0.0.1",
        .client_host = "dev.lo",
        .client_ip = "10.0.0.1",
        .domain = "dev.lo",
    });
    try testing.expectEqualStrings(
        "GET /api/x HTTP/1.1\r\n" ++
            "Host: dev.lo\r\nAccept: */*\r\n" ++
            "X-Forwarded-Host: dev.lo\r\nX-Forwarded-For: 10.0.0.1\r\n" ++
            "X-Real-IP: 10.0.0.1\r\nX-Forwarded-Proto: https\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n" ++
            "Content-Length: 0\r\n\r\n",
        out[0..len],
    );
}

test "forwardRequest rewrites Host and adds X-Forwarded-Host for external routes" {
    const e = buildEntry("POST", "/login", "Host: dev.lo\r\nContent-Length: 2\r\n", "hi");
    var out: [512]u8 = undefined;
    var len: usize = 0;
    forwardRequest(TestSink{ .buf = &out, .len = &len }, &e, .{
        .is_external = true,
        .upstream_host = "staging.example.com",
        .client_host = "dev.lo",
        .client_ip = "10.0.0.1",
        .domain = "dev.lo",
    });
    try testing.expectEqualStrings(
        "POST /login HTTP/1.1\r\n" ++
            "Host: staging.example.com\r\nX-Forwarded-Host: dev.lo\r\nX-Forwarded-For: 10.0.0.1\r\n" ++
            "X-Real-IP: 10.0.0.1\r\nX-Forwarded-Proto: https\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n" ++
            "Content-Length: 2\r\n\r\nhi",
        out[0..len],
    );
}

test "forwardRequest appends to the client's X-Forwarded-For and drops client proxy headers" {
    const e = buildEntry("GET", "/x", "Host: dev.lo\r\nX-Forwarded-For: 1.2.3.4\r\nX-Real-IP: 6.6.6.6\r\nX-Forwarded-Proto: http\r\nX-Forwarded-Host: evil\r\nAccept-Encoding: gzip, br\r\n", "");
    var out: [512]u8 = undefined;
    var len: usize = 0;
    forwardRequest(TestSink{ .buf = &out, .len = &len }, &e, .{
        .is_external = false,
        .upstream_host = "127.0.0.1",
        .client_host = "dev.lo",
        .client_ip = "10.0.0.1",
        .client_xff = "1.2.3.4",
        .domain = "dev.lo",
    });
    const got = out[0..len];
    try testing.expect(std.mem.indexOf(u8, got, "X-Forwarded-For: 1.2.3.4, 10.0.0.1\r\n") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "X-Forwarded-For:"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "X-Real-IP:"));
    try testing.expect(std.mem.indexOf(u8, got, "X-Real-IP: 10.0.0.1\r\n") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "X-Forwarded-Proto:"));
    try testing.expect(std.mem.indexOf(u8, got, "X-Forwarded-Host: dev.lo\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "evil") == null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "Accept-Encoding"));
    try testing.expect(std.mem.indexOf(u8, got, "Accept-Encoding: identity\r\n") != null);
}

test "forwardRequest recomputes Content-Length from the body, ignoring the original" {
    // Original header claims length 99; emitted Content-Length must match the body.
    const e = buildEntry("PUT", "/x", "Content-Length: 99\r\n", "abcd");
    var out: [512]u8 = undefined;
    var len: usize = 0;
    forwardRequest(TestSink{ .buf = &out, .len = &len }, &e, .{
        .is_external = false,
        .upstream_host = "127.0.0.1",
        .client_host = "",
        .client_ip = "10.0.0.1",
        .domain = "dev.lo",
    });
    try testing.expect(std.mem.indexOf(u8, out[0..len], "Content-Length: 4\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, out[0..len], "Content-Length: 99") == null);
    try testing.expect(std.mem.endsWith(u8, out[0..len], "\r\n\r\nabcd"));
}

test "replay sends a captured chunked request de-chunked" {
    const e = buildEntry("POST", "/c", "Host: dev.lo\r\nTransfer-Encoding: chunked\r\n", "Wikipedia");
    var out: [512]u8 = undefined;
    var len: usize = 0;
    writeReplayRequest(TestSink{ .buf = &out, .len = &len }, &e);
    try testing.expectEqualStrings(
        "POST /c HTTP/1.1\r\nHost: dev.lo\r\nContent-Length: 9\r\nConnection: close\r\n\r\nWikipedia",
        out[0..len],
    );
}

test "connectUpstream returns DnsFailed for an unresolvable external host" {
    const cfg = ProxyConfig{
        .target_host = "127.0.0.1",
        .target_port = 1,
        .listen_addr = "127.0.0.1",
        .cert_path = "",
        .key_path = "",
        .ca_path = "",
        .server_ident = "test",
        .max_request_body = 0,
        .routes = &.{},
        .domain = "dev.lo",
    };
    try testing.expectError(error.DnsFailed, connectUpstream(true, "nonexistent.invalid", 443, &cfg, null, 1));
}

const DrainTestWorker = struct {
    fn holdUntilDecided(slot: *intercept.PendingEntry, out: *intercept.Decision) void {
        out.* = intercept.awaitAndRelease(slot);
        _ = proxy_workers.fetchSub(1, .acq_rel);
    }
    fn holdLate(out: *intercept.Decision) void {
        rt.sleepMs(100); // begins its hold after drainWorkers' first dropAll()
        const slot = intercept.acquire(9) orelse {
            _ = proxy_workers.fetchSub(1, .acq_rel);
            return;
        };
        holdUntilDecided(slot, out);
    }
};

test "drainWorkers drops held intercepts so their workers finish" {
    proxy_workers.store(1, .release);
    defer proxy_workers.store(0, .release);
    const slot = intercept.acquire(7) orelse return error.NoFreeSlot;
    var decision: intercept.Decision = .pending;
    const t = try std.Thread.spawn(.{}, DrainTestWorker.holdUntilDecided, .{ slot, &decision });
    try testing.expect(drainWorkers(2000));
    t.join();
    try testing.expectEqual(intercept.Decision.drop, decision);
}

test "drainWorkers drops a hold that begins after draining started" {
    proxy_workers.store(1, .release);
    defer proxy_workers.store(0, .release);
    var decision: intercept.Decision = .pending;
    const t = try std.Thread.spawn(.{}, DrainTestWorker.holdLate, .{&decision});
    try testing.expect(drainWorkers(2000));
    t.join();
    try testing.expectEqual(intercept.Decision.drop, decision);
}

test "drainWorkers gives up after the deadline when a worker never finishes" {
    proxy_workers.store(1, .release);
    defer proxy_workers.store(0, .release);
    const start_ms = rt.milliTimestamp();
    try testing.expect(!drainWorkers(100));
    const took = rt.milliTimestamp() - start_ms;
    try testing.expect(took >= 100 and took < 1000);
}

const HandshakeTest = struct {
    listener: compat.socket_t,
    client: compat.socket_t,
    server: compat.socket_t,
    ctx: *ssl_c.SSL_CTX,
    ssl: *ssl_c.SSL,

    fn init(port: u16) !HandshakeTest {
        const addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
        const listener = try compat.tcpListen(addr);
        errdefer compat.closeSocket(listener);
        const client = try compat.tcpConnect(addr);
        errdefer compat.closeSocket(client);
        const conn = try compat.accept(listener);
        errdefer compat.closeSocket(conn.sock);
        const ctx = ssl_c.SSL_CTX_new(ssl_c.TLS_server_method()) orelse return error.SslCtx;
        errdefer ssl_c.SSL_CTX_free(ctx);
        const ssl = ssl_c.SSL_new(ctx) orelse return error.SslNew;
        _ = ssl_c.SSL_set_fd(ssl, compat.socketToFd(conn.sock));
        return .{ .listener = listener, .client = client, .server = conn.sock, .ctx = ctx, .ssl = ssl };
    }

    fn deinit(self: *HandshakeTest) void {
        ssl_c.SSL_free(self.ssl);
        ssl_c.SSL_CTX_free(self.ctx);
        compat.closeSocket(self.server);
        compat.closeSocket(self.client);
        compat.closeSocket(self.listener);
    }
};

test "acceptTls gives up on a client that never sends a ClientHello" {
    var h = try HandshakeTest.init(18090);
    defer h.deinit();
    const start_ms = rt.milliTimestamp();
    try testing.expect(!acceptTls(h.ssl, h.server, 1));
    const took = rt.milliTimestamp() - start_ms;
    try testing.expect(took >= 900 and took < 3000);
}

test "acceptTls fails fast on a client that sends plain HTTP" {
    var h = try HandshakeTest.init(18091);
    defer h.deinit();
    try (compat.SocketStream{ .handle = h.client }).writeAll("GET / HTTP/1.1\r\nHost: dev.lo\r\n\r\n");
    const start_ms = rt.milliTimestamp();
    try testing.expect(!acceptTls(h.ssl, h.server, 10));
    try testing.expect(rt.milliTimestamp() - start_ms < 1000);
}

/// Server context with a throwaway self-signed certificate, for tests that need
/// a real TLS session (clients in these tests don't verify).
fn testServerCtx() !*ssl_c.SSL_CTX {
    const srv = try testServer(null);
    ssl_c.X509_free(srv.cert);
    return srv.ctx;
}

const TestServer = struct { ctx: *ssl_c.SSL_CTX, cert: *ssl_c.X509 };

/// Self-signed RSA server context. With `name`, the cert carries CN and SAN
/// DNS:`name`, so hostname verification can match it. Caller frees both.
fn testServer(name: ?[:0]const u8) !TestServer {
    const kctx = ssl_c.EVP_PKEY_CTX_new_id(ssl_c.EVP_PKEY_RSA, null) orelse return error.KeyGen;
    defer ssl_c.EVP_PKEY_CTX_free(kctx);
    if (ssl_c.EVP_PKEY_keygen_init(kctx) != 1) return error.KeyGen;
    if (ssl_c.EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) != 1) return error.KeyGen;
    var pkey: ?*ssl_c.EVP_PKEY = null;
    if (ssl_c.EVP_PKEY_keygen(kctx, &pkey) != 1) return error.KeyGen;
    defer ssl_c.EVP_PKEY_free(pkey);

    const x509 = ssl_c.X509_new() orelse return error.Cert;
    errdefer ssl_c.X509_free(x509);
    if (ssl_c.X509_set_version(x509, 2) != 1) return error.Cert;
    if (ssl_c.ASN1_INTEGER_set(ssl_c.X509_get_serialNumber(x509), 1) != 1) return error.Cert;
    if (ssl_c.X509_gmtime_adj(ssl_c.X509_getm_notBefore(x509), 0) == null) return error.Cert;
    if (ssl_c.X509_gmtime_adj(ssl_c.X509_getm_notAfter(x509), 3600) == null) return error.Cert;
    if (ssl_c.X509_set_pubkey(x509, pkey) != 1) return error.Cert;
    if (name) |n| {
        const subj = ssl_c.X509_get_subject_name(x509);
        if (ssl_c.X509_NAME_add_entry_by_NID(subj, ssl_c.NID_commonName, ssl_c.MBSTRING_ASC, n.ptr, @intCast(n.len), -1, 0) != 1) return error.Cert;
        if (ssl_c.X509_set_issuer_name(x509, subj) != 1) return error.Cert;
        var san_buf: [300]u8 = undefined;
        const san = std.fmt.bufPrintSentinel(&san_buf, "DNS:{s}", .{n}, 0) catch return error.Cert;
        const ext = ssl_c.X509V3_EXT_nconf_nid(null, null, ssl_c.NID_subject_alt_name, san.ptr) orelse return error.Cert;
        defer ssl_c.X509_EXTENSION_free(ext);
        if (ssl_c.X509_add_ext(x509, ext, -1) != 1) return error.Cert;
    }
    if (ssl_c.X509_sign(x509, pkey, ssl_c.EVP_sha256()) == 0) return error.Cert;

    const ctx = ssl_c.SSL_CTX_new(ssl_c.TLS_server_method()) orelse return error.SslCtx;
    errdefer ssl_c.SSL_CTX_free(ctx);
    if (ssl_c.SSL_CTX_use_certificate(ctx, x509) != 1) return error.Cert;
    if (ssl_c.SSL_CTX_use_PrivateKey(ctx, pkey) != 1) return error.Cert;
    return .{ .ctx = ctx, .cert = x509 };
}

/// A loopback TCP connection: `a` is the connecting end, `b` the accepted end.
const TcpPair = struct {
    listener: compat.socket_t,
    a: compat.socket_t,
    b: compat.socket_t,

    fn init(port: u16) !TcpPair {
        const addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
        const listener = try compat.tcpListen(addr);
        errdefer compat.closeSocket(listener);
        const a = try compat.tcpConnect(addr);
        errdefer compat.closeSocket(a);
        const conn = try compat.accept(listener);
        return .{ .listener = listener, .a = a, .b = conn.sock };
    }

    fn deinit(self: *TcpPair) void {
        compat.closeSocket(self.a);
        compat.closeSocket(self.b);
        compat.closeSocket(self.listener);
    }
};

/// A completed TLS session over loopback: `client` talks to `server`.
const TlsPair = struct {
    tcp: TcpPair,
    server_ctx: *ssl_c.SSL_CTX,
    client_ctx: *ssl_c.SSL_CTX,
    server: *ssl_c.SSL,
    client: *ssl_c.SSL,

    fn init(port: u16) !TlsPair {
        var tcp = try TcpPair.init(port);
        errdefer tcp.deinit();
        const server_ctx = try testServerCtx();
        errdefer ssl_c.SSL_CTX_free(server_ctx);
        const client_ctx = ssl_c.SSL_CTX_new(ssl_c.TLS_client_method()) orelse return error.SslCtx;
        errdefer ssl_c.SSL_CTX_free(client_ctx);
        const server = ssl_c.SSL_new(server_ctx) orelse return error.SslNew;
        errdefer ssl_c.SSL_free(server);
        const client = ssl_c.SSL_new(client_ctx) orelse return error.SslNew;
        errdefer ssl_c.SSL_free(client);
        _ = ssl_c.SSL_set_fd(server, compat.socketToFd(tcp.b));
        _ = ssl_c.SSL_set_fd(client, compat.socketToFd(tcp.a));

        var connect_rc: c_int = 0;
        const t = try std.Thread.spawn(.{}, struct {
            fn run(ssl: *ssl_c.SSL, rc: *c_int) void {
                rc.* = ssl_c.SSL_connect(ssl);
            }
        }.run, .{ client, &connect_rc });
        const accept_rc = ssl_c.SSL_accept(server);
        t.join();
        if (accept_rc != 1 or connect_rc != 1) return error.Handshake;
        return .{ .tcp = tcp, .server_ctx = server_ctx, .client_ctx = client_ctx, .server = server, .client = client };
    }

    fn deinit(self: *TlsPair) void {
        ssl_c.SSL_free(self.client);
        ssl_c.SSL_free(self.server);
        ssl_c.SSL_CTX_free(self.client_ctx);
        ssl_c.SSL_CTX_free(self.server_ctx);
        self.tcp.deinit();
    }
};

test "relayWebSocket forwards a client write larger than its read buffer at once" {
    var tls = try TlsPair.init(18092);
    defer tls.deinit();
    var up = try TcpPair.init(18093);
    defer up.deinit();

    const relay = try std.Thread.spawn(.{}, relayWebSocket, .{ tls.server, UpstreamConn{ .sock = .{ .handle = up.b } } });
    defer relay.join();
    // close_notify makes the relay's SSL_read return 0, so the deferred join returns.
    defer _ = ssl_c.SSL_shutdown(tls.client);

    // One 12,000-byte write is one TLS record: more than the relay's 8 KB read,
    // so the remainder sits inside BoringSSL where poll() can't see it.
    var payload: [12_000]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);
    try testing.expectEqual(@as(c_int, payload.len), ssl_c.SSL_write(tls.client, &payload, payload.len));

    setSocketTimeout(up.a, .recv, 2);
    var got: [12_000]u8 = undefined;
    var total: usize = 0;
    const upstream = compat.SocketStream{ .handle = up.a };
    while (total < got.len) {
        const n = upstream.read(got[total..]) catch break;
        if (n == 0) break;
        total += n;
    }
    try testing.expectEqual(payload.len, total);
    try testing.expectEqualSlices(u8, &payload, &got);
}

/// Fake dev server for proxy tests: answers each accepted connection's request with
/// `bodiless` when it starts with HEAD or `If-None-Match` (then holds the socket
/// open, like Node's keep-alive), otherwise with a 2-byte "ok" body.
const FakeUpstream = struct {
    listener: compat.socket_t,
    bodiless: []const u8,
    held: [4]compat.socket_t = undefined,
    held_len: usize = 0,
    thread: std.Thread = undefined,

    var running: std.atomic.Value(bool) = .init(true);
    fn isRunning() bool {
        return running.load(.acquire);
    }

    fn start(self: *FakeUpstream, port: u16) !void {
        running.store(true, .release);
        self.listener = try compat.tcpListen(try std.Io.net.IpAddress.parseIp4("127.0.0.1", port));
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
    }

    fn serve(self: *FakeUpstream) void {
        while (true) {
            var fds = [1]compat.pollfd{.{ .fd = self.listener, .events = compat.POLL.IN, .revents = 0 }};
            switch (compat.pollWhileRunning(&fds, 100, isRunning)) {
                .ready => {},
                .timeout => continue,
                else => return,
            }
            const conn = compat.accept(self.listener) catch return;
            const s = compat.SocketStream{ .handle = conn.sock };
            var buf: [4096]u8 = undefined;
            var total: usize = 0;
            while (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") == null and total < buf.len) {
                const n = s.read(buf[total..]) catch break;
                if (n == 0) break;
                total += n;
            }
            const req = buf[0..total];
            if (std.mem.startsWith(u8, req, "HEAD") or std.mem.indexOf(u8, req, "If-None-Match") != null) {
                s.writeAll(self.bodiless) catch {};
                if (self.held_len < self.held.len) {
                    self.held[self.held_len] = conn.sock;
                    self.held_len += 1;
                    continue;
                }
            } else {
                s.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch {};
            }
            compat.closeSocket(conn.sock);
        }
    }

    fn stop(self: *FakeUpstream) void {
        running.store(false, .release);
        self.thread.join();
        for (self.held[0..self.held_len]) |s| compat.closeSocket(s);
        compat.closeSocket(self.listener);
    }
};

/// Fake upstream that reads one whole request per connection (Content-Length or
/// chunked framing), keeps its exact bytes, and answers with `response`.
const RecordingUpstream = struct {
    listener: compat.socket_t = undefined,
    response: []const u8 = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    /// False: hang up right after the request head, without reading the body or answering.
    read_body: bool = true,
    /// Wait this long after reading the request before answering (sliced, ends on stop).
    delay_ms: u32 = 0,
    /// Written `gap_ms` after `response`: a stream that goes quiet, then continues.
    response2: []const u8 = "",
    gap_ms: u32 = 0,
    buf: []u8 = &.{},
    len: std.atomic.Value(usize) = .init(0),
    thread: std.Thread = undefined,

    var running: std.atomic.Value(bool) = .init(true);
    fn isRunning() bool {
        return running.load(.acquire);
    }

    fn start(self: *RecordingUpstream, port: u16) !void {
        running.store(true, .release);
        self.buf = try std.heap.page_allocator.alloc(u8, 2 * 1024 * 1024);
        self.listener = try compat.tcpListen(try std.Io.net.IpAddress.parseIp4("127.0.0.1", port));
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
    }

    fn serve(self: *RecordingUpstream) void {
        while (true) {
            var fds = [1]compat.pollfd{.{ .fd = self.listener, .events = compat.POLL.IN, .revents = 0 }};
            switch (compat.pollWhileRunning(&fds, 100, isRunning)) {
                .ready => {},
                .timeout => continue,
                else => return,
            }
            const conn = compat.accept(self.listener) catch return;
            const s = compat.SocketStream{ .handle = conn.sock };
            if (!self.read_body) {
                var head: [16384]u8 = undefined;
                _ = s.read(&head) catch {};
                compat.closeSocket(conn.sock);
                continue;
            }
            self.len.store(readRequest(s, self.buf), .release);
            sleepWhileRunning(self.delay_ms, isRunning);
            s.writeAll(self.response) catch {};
            if (self.response2.len > 0) {
                sleepWhileRunning(self.gap_ms, isRunning);
                s.writeAll(self.response2) catch {};
            }
            compat.closeSocket(conn.sock);
        }
    }

    fn sleepWhileRunning(ms: u32, running_fn: *const fn () bool) void {
        var left = ms;
        while (left > 0 and running_fn()) {
            const step = @min(left, 50);
            rt.sleepMs(step);
            left -= step;
        }
    }

    /// Read one request: the head, then its Content-Length or chunked body.
    fn readRequest(s: compat.SocketStream, buf: []u8) usize {
        var total: usize = 0;
        var hdr_end: ?usize = null;
        while (hdr_end == null and total < buf.len) {
            const n = s.read(buf[total..]) catch return total;
            if (n == 0) return total;
            total += n;
            hdr_end = std.mem.indexOf(u8, buf[0..total], "\r\n\r\n");
        }
        const body_start = (hdr_end orelse return total) + 4;
        const head = buf[0..body_start];
        if (http_wire.isChunkedEncoding(head)) {
            var dec = http_wire.ChunkedDecoder{};
            var scan = body_start;
            while (true) {
                scan += dec.feed(buf[scan..total], &.{});
                if (dec.finished() or total == buf.len) return total;
                const n = s.read(buf[total..]) catch return total;
                if (n == 0) return total;
                total += n;
            }
        }
        const cl = http_wire.getContentLength(head) orelse 0;
        while (total < body_start + cl and total < buf.len) {
            const n = s.read(buf[total..]) catch return total;
            if (n == 0) return total;
            total += n;
        }
        return total;
    }

    fn received(self: *RecordingUpstream) []const u8 {
        return self.buf[0..self.len.load(.acquire)];
    }

    fn stop(self: *RecordingUpstream) void {
        running.store(false, .release);
        self.thread.join();
        compat.closeSocket(self.listener);
        std.heap.page_allocator.free(self.buf);
    }
};

/// Comptime `s` repeated `n` times (Zig 0.17 dropped the `**` operator).
fn rep(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
    const T = struct {
        const value: [s.len * n]u8 = blk: {
            @setEvalBranchQuota(10 * s.len * n + 1000);
            var out: [s.len * n]u8 = undefined;
            for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
            break :blk out;
        };
    };
    return &T.value;
}

/// Empty the shared entry ring so the next request's entry is found by count
/// (a full ring stops counting). Returns the count to pass to waitNewestEntry.
fn freshRing() usize {
    requests.clearAll();
    return requests.getCount();
}

/// Wait for the proxy to record a new entry (it pushes after relaying the
/// response) and copy the newest into `dest`.
fn waitNewestEntry(prev_count: usize, dest: *requests.Entry) !void {
    const deadline = rt.milliTimestamp() + 2000;
    while (requests.getCount() <= prev_count) {
        if (rt.milliTimestamp() > deadline) return error.NoEntry;
        rt.sleepMs(10);
    }
    if (!requests.copyEntry(requests.getCount() - 1, dest)) return error.NoEntry;
}

/// Runs `handleConnection` against a fake upstream and returns the client's TLS
/// session, so a test can send requests through the real proxy path.
const ProxyHarness = struct {
    tcp: TcpPair,
    server_ctx: *ssl_c.SSL_CTX,
    client_ctx: *ssl_c.SSL_CTX,
    client: *ssl_c.SSL,
    config: ProxyConfig,
    thread: std.Thread,

    fn start(self: *ProxyHarness, port: u16, upstream_port: u16) !void {
        return self.startWith(port, upstream_port, &.{}, null);
    }

    const HarnessOpts = struct {
        routes: []const Route = &.{},
        client_ctx: ?*ssl_c.SSL_CTX = null,
        max_request_body: usize = default_max_request_body,
        upstream_timeout_s: u32 = default_upstream_timeout_s,
    };

    fn startWith(self: *ProxyHarness, port: u16, upstream_port: u16, routes: []const Route, client_ctx: ?*ssl_c.SSL_CTX) !void {
        return self.startOpts(port, upstream_port, .{ .routes = routes, .client_ctx = client_ctx });
    }

    fn startOpts(self: *ProxyHarness, port: u16, upstream_port: u16, opts: HarnessOpts) !void {
        self.tcp = try TcpPair.init(port);
        self.server_ctx = try testServerCtx();
        self.client_ctx = ssl_c.SSL_CTX_new(ssl_c.TLS_client_method()) orelse return error.SslCtx;
        const server = ssl_c.SSL_new(self.server_ctx) orelse return error.SslNew;
        _ = ssl_c.SSL_set_fd(server, compat.socketToFd(self.tcp.b));
        self.client = ssl_c.SSL_new(self.client_ctx) orelse return error.SslNew;
        _ = ssl_c.SSL_set_fd(self.client, compat.socketToFd(self.tcp.a));
        self.config = .{
            .target_host = "127.0.0.1",
            .target_port = upstream_port,
            .listen_addr = "127.0.0.1",
            .cert_path = "",
            .key_path = "",
            .ca_path = "",
            .server_ident = "test",
            .routes = opts.routes,
            .max_request_body = opts.max_request_body,
            .upstream_timeout_s = opts.upstream_timeout_s,
        };
        _ = proxy_workers.fetchAdd(1, .acq_rel);
        const client_addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        // handleConnection owns the server SSL and the server-side socket from here.
        self.thread = try std.Thread.spawn(.{}, handleConnection, .{ server, self.tcp.b, client_addr, &self.config, @as(u64, 1), opts.client_ctx });
        if (ssl_c.SSL_connect(self.client) != 1) return error.Handshake;
        // Generous: tests with a 2s upstream pause must not trip it on a loaded CI runner.
        setSocketTimeout(self.tcp.a, .recv, 10);
    }

    /// Send `request` and read until the response ends with `want_suffix`.
    fn roundTrip(self: *ProxyHarness, request: []const u8, want_suffix: []const u8, out: []u8) ![]const u8 {
        if (ssl_c.SSL_write(self.client, request.ptr, @intCast(request.len)) <= 0) return error.WriteFailed;
        var total: usize = 0;
        while (total < out.len) {
            const n = ssl_c.SSL_read(self.client, out[total..].ptr, @intCast(out.len - total));
            if (n <= 0) return error.ReadFailed;
            total += @intCast(n);
            if (std.mem.indexOf(u8, out[0..total], "\r\n\r\n") != null and std.mem.endsWith(u8, out[0..total], want_suffix)) return out[0..total];
        }
        return error.ResponseTooLarge;
    }

    /// Read until `n` complete responses with the last ending in `want_suffix`.
    fn readResponses(self: *ProxyHarness, n: usize, want_suffix: []const u8, out: []u8) ![]const u8 {
        var total: usize = 0;
        while (total < out.len) {
            const r = ssl_c.SSL_read(self.client, out[total..].ptr, @intCast(out.len - total));
            if (r <= 0) return error.ReadFailed;
            total += @intCast(r);
            if (std.mem.count(u8, out[0..total], "HTTP/1.1 ") >= n and std.mem.endsWith(u8, out[0..total], want_suffix)) return out[0..total];
        }
        return error.ResponseTooLarge;
    }

    fn stop(self: *ProxyHarness) void {
        _ = ssl_c.SSL_shutdown(self.client);
        compat.closeSocket(self.tcp.a);
        self.thread.join();
        ssl_c.SSL_free(self.client);
        ssl_c.SSL_CTX_free(self.client_ctx);
        ssl_c.SSL_CTX_free(self.server_ctx);
        compat.closeSocket(self.tcp.listener);
    }
};

test "HEAD response with Content-Length doesn't stall the next request on the connection" {
    var up = FakeUpstream{ .listener = undefined, .bodiless = "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n" };
    try up.start(18095);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18094, 18095);
    defer px.stop();

    var buf: [4096]u8 = undefined;
    const head = try px.roundTrip("HEAD / HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "\r\n\r\n", &buf);
    try testing.expect(std.mem.indexOf(u8, head, "Content-Length: 1234") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Connection: keep-alive") != null);

    const t0 = rt.milliTimestamp();
    const get = try px.roundTrip("GET / HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "ok", &buf);
    try testing.expect(std.mem.startsWith(u8, get, "HTTP/1.1 200"));
    try testing.expect(rt.milliTimestamp() - t0 < 1000);
}

test "304 without Content-Length is answered at once and keeps the connection" {
    var up = FakeUpstream{ .listener = undefined, .bodiless = "HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\n\r\n" };
    try up.start(18097);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18096, 18097);
    defer px.stop();

    var buf: [4096]u8 = undefined;
    const t0 = rt.milliTimestamp();
    const resp = try px.roundTrip("GET /a.js HTTP/1.1\r\nHost: dev.lo\r\nIf-None-Match: \"x\"\r\n\r\n", "\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 304"));
    try testing.expect(std.mem.indexOf(u8, resp, "Connection: keep-alive") != null);
    const get = try px.roundTrip("GET / HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "ok", &buf);
    try testing.expect(std.mem.startsWith(u8, get, "HTTP/1.1 200"));
    try testing.expect(rt.milliTimestamp() - t0 < 1000);
}

/// Handshake `client_ctx` against `server` over a loopback pair, through the same
/// upstreamHandshake that connectUpstream uses for external routes.
fn handshakeUpstream(port: u16, server: TestServer, client_ctx: *ssl_c.SSL_CTX, host: []const u8) !void {
    var tcp = try TcpPair.init(port);
    defer tcp.deinit();
    const srv = ssl_c.SSL_new(server.ctx) orelse return error.SslNew;
    defer ssl_c.SSL_free(srv);
    _ = ssl_c.SSL_set_fd(srv, compat.socketToFd(tcp.b));
    const t = try std.Thread.spawn(.{}, struct {
        fn run(s: *ssl_c.SSL) void {
            _ = ssl_c.SSL_accept(s);
        }
    }.run, .{srv});
    defer t.join();
    // A client that rejects the cert sends a fatal alert, which ends SSL_accept.
    const us = try upstreamHandshake(client_ctx, tcp.a, host, 1);
    ssl_c.SSL_free(us);
}

test "upstream TLS rejects a certificate no trusted root vouches for" {
    const srv = try testServer("localhost");
    defer ssl_c.SSL_CTX_free(srv.ctx);
    defer ssl_c.X509_free(srv.cert);
    const cctx = createClientSslCtx(false) orelse return error.SslCtx;
    defer ssl_c.SSL_CTX_free(cctx);
    try testing.expectError(error.UpstreamCertUntrusted, handshakeUpstream(18098, srv, cctx, "localhost"));
}

test "insecure upstream accepts any certificate" {
    const srv = try testServer("totally-wrong.example");
    defer ssl_c.SSL_CTX_free(srv.ctx);
    defer ssl_c.X509_free(srv.cert);
    const cctx = createClientSslCtx(true) orelse return error.SslCtx;
    defer ssl_c.SSL_CTX_free(cctx);
    try handshakeUpstream(18099, srv, cctx, "localhost");
}

test "upstream TLS accepts a trusted certificate for the route's host" {
    const srv = try testServer("localhost");
    defer ssl_c.SSL_CTX_free(srv.ctx);
    defer ssl_c.X509_free(srv.cert);
    const cctx = createClientSslCtx(false) orelse return error.SslCtx;
    defer ssl_c.SSL_CTX_free(cctx);
    try testing.expectEqual(@as(c_int, 1), ssl_c.X509_STORE_add_cert(ssl_c.SSL_CTX_get_cert_store(cctx), srv.cert));
    try handshakeUpstream(18100, srv, cctx, "localhost");
}

test "upstream TLS rejects a trusted certificate issued for another host" {
    const srv = try testServer("localhost");
    defer ssl_c.SSL_CTX_free(srv.ctx);
    defer ssl_c.X509_free(srv.cert);
    const cctx = createClientSslCtx(false) orelse return error.SslCtx;
    defer ssl_c.SSL_CTX_free(cctx);
    try testing.expectEqual(@as(c_int, 1), ssl_c.X509_STORE_add_cert(ssl_c.SSL_CTX_get_cert_store(cctx), srv.cert));
    try testing.expectError(error.UpstreamCertUntrusted, handshakeUpstream(18101, srv, cctx, "staging.example.com"));
}

test "loadSystemRoots finds the OS trust store" {
    const ctx = ssl_c.SSL_CTX_new(ssl_c.TLS_client_method()) orelse return error.SslCtx;
    defer ssl_c.SSL_CTX_free(ctx);
    try testing.expect(loadSystemRoots(ctx));
}

test "relayWebSocket forwards an upstream TLS write larger than its read buffer at once" {
    var tls = try TlsPair.init(18102);
    defer tls.deinit();
    // zlodev is the TLS client of an external upstream: up.client is its side.
    var up = try TlsPair.init(18103);
    defer up.deinit();

    const relay = try std.Thread.spawn(.{}, relayWebSocket, .{ tls.server, UpstreamConn{ .sock = .{ .handle = up.tcp.a }, .ssl_conn = up.client } });
    defer relay.join();
    defer _ = ssl_c.SSL_shutdown(tls.client);

    // One record bigger than the relay's 8 KB read: the rest sits inside BoringSSL.
    var payload: [12_000]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i *% 7);
    try testing.expectEqual(@as(c_int, payload.len), ssl_c.SSL_write(up.server, &payload, payload.len));

    setSocketTimeout(tls.tcp.a, .recv, 2);
    var got: [12_000]u8 = undefined;
    var total: usize = 0;
    while (total < got.len) {
        const n = ssl_c.SSL_read(tls.client, got[total..].ptr, @intCast(got.len - total));
        if (n <= 0) break;
        total += @intCast(n);
    }
    try testing.expectEqual(payload.len, total);
    try testing.expectEqualSlices(u8, &payload, &got);
}

/// TLS WebSocket server for external-route tests: records the upgrade request head,
/// answers 101, then echoes one read back.
const FakeWsUpstream = struct {
    listener: compat.socket_t = undefined,
    srv: TestServer = undefined,
    thread: std.Thread = undefined,
    head: [2048]u8 = undefined,
    head_len: usize = 0,

    fn start(self: *FakeWsUpstream, port: u16) !void {
        self.srv = try testServer("localhost");
        self.listener = try compat.tcpListen(try std.Io.net.IpAddress.parseIp4("127.0.0.1", port));
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
    }

    fn serve(self: *FakeWsUpstream) void {
        var fds = [1]compat.pollfd{.{ .fd = self.listener, .events = compat.POLL.IN, .revents = 0 }};
        // Generous: on Windows "localhost" tries ::1 first, and a refused loopback
        // connect there takes ~2s before the proxy falls back to 127.0.0.1.
        if (compat.pollWhileRunning(&fds, 15_000, shutdown.isRunning) != .ready) return;
        const conn = compat.accept(self.listener) catch return;
        defer compat.closeSocket(conn.sock);
        setSocketTimeout(conn.sock, .recv, 3);
        const ssl = ssl_c.SSL_new(self.srv.ctx) orelse return;
        defer ssl_c.SSL_free(ssl);
        _ = ssl_c.SSL_set_fd(ssl, compat.socketToFd(conn.sock));
        if (ssl_c.SSL_accept(ssl) != 1) return;
        while (std.mem.indexOf(u8, self.head[0..self.head_len], "\r\n\r\n") == null and self.head_len < self.head.len) {
            const n = ssl_c.SSL_read(ssl, self.head[self.head_len..].ptr, @intCast(self.head.len - self.head_len));
            if (n <= 0) return;
            self.head_len += @intCast(n);
        }
        const resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        _ = ssl_c.SSL_write(ssl, resp, resp.len);
        var buf: [256]u8 = undefined;
        const n = ssl_c.SSL_read(ssl, &buf, buf.len);
        if (n > 0) _ = ssl_c.SSL_write(ssl, &buf, n);
        _ = ssl_c.SSL_read(ssl, &buf, buf.len); // wait for the relay to close
    }

    fn stop(self: *FakeWsUpstream) void {
        self.thread.join();
        compat.closeSocket(self.listener);
        ssl_c.SSL_CTX_free(self.srv.ctx);
        ssl_c.X509_free(self.srv.cert);
    }
};

test "WebSocket upgrade on an external route reaches the upstream over TLS" {
    var up = FakeWsUpstream{};
    try up.start(18105);
    defer up.stop();
    const cctx = createClientSslCtx(false) orelse return error.SslCtx;
    defer ssl_c.SSL_CTX_free(cctx);
    try testing.expectEqual(@as(c_int, 1), ssl_c.X509_STORE_add_cert(ssl_c.SSL_CTX_get_cert_store(cctx), up.srv.cert));

    const routes = [_]Route{.{ .kind = .path, .pattern = "/ws", .port = 18105, .hostname = "localhost" }};
    var px: ProxyHarness = undefined;
    try px.startWith(18104, 1, &routes, cctx);
    defer px.stop();

    var buf: [1024]u8 = undefined;
    const resp = try px.roundTrip("GET /ws HTTP/1.1\r\nHost: dev.lo\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://dev.lo\r\n\r\n", "\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 101"));

    const frame = "frame-bytes";
    try testing.expect(ssl_c.SSL_write(px.client, frame, frame.len) == frame.len);
    var total: usize = 0;
    while (total < frame.len) {
        const n = ssl_c.SSL_read(px.client, buf[total..].ptr, @intCast(buf.len - total));
        if (n <= 0) break;
        total += @intCast(n);
    }
    try testing.expectEqualStrings(frame, buf[0..total]);

    const head = up.head[0..up.head_len];
    try testing.expect(std.mem.indexOf(u8, head, "\r\nHost: localhost\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "\r\nX-Forwarded-Host: dev.lo\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "\r\nOrigin: https://dev.lo\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "\r\nX-Real-IP: 127.0.0.1\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "\r\nX-Forwarded-Proto: https\r\n") != null);
}

test "WebSocket upgrade on a local route gets X-Real-IP and X-Forwarded-Proto" {
    var up = RecordingUpstream{ .response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" };
    try up.start(18367);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18366, 18367);
    defer px.stop();

    var buf: [1024]u8 = undefined;
    const resp = try px.roundTrip("GET /hmr HTTP/1.1\r\nHost: dev.lo\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", "\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 101"));

    const got = up.received();
    try testing.expect(std.mem.startsWith(u8, got, "GET /hmr HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, got, "\r\nHost: dev.lo\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nUpgrade: websocket\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nConnection: Upgrade\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nX-Real-IP: 127.0.0.1\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nX-Forwarded-Proto: https\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nX-Forwarded-Host: dev.lo\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\n"));
}

test "upstream gets no Accept-Encoding and the forwarding headers on a local route" {
    var up = RecordingUpstream{};
    try up.start(18373);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18372, 18373);
    defer px.stop();
    var buf: [4096]u8 = undefined;
    _ = try px.roundTrip("GET /a HTTP/1.1\r\nHost: dev.lo\r\nAccept-Encoding: gzip, deflate, br\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n", "ok", &buf);
    const got = up.received();
    try testing.expect(std.mem.indexOf(u8, got, "\r\nAccept-Encoding: identity\r\n") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "Accept-Encoding"));
    try testing.expect(std.mem.indexOf(u8, got, "gzip") == null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nX-Forwarded-Host: dev.lo\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nX-Forwarded-For: 9.9.9.9, 127.0.0.1\r\n") != null);
}

test "response head over 16KB answers 502 with the reason" {
    var up = RecordingUpstream{ .response = "HTTP/1.1 200 OK\r\nX-Big: " ++ rep("a", 17000) ++ "\r\n\r\nok" };
    try up.start(18371);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18370, 18371);
    defer px.stop();
    const before = freshRing();
    var buf: [4096]u8 = undefined;
    const resp = try px.roundTrip("GET /big HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "response head over 16KB", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 502"));
    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);
    try waitNewestEntry(before, e);
    try testing.expectEqualStrings("response head over 16KB", e.getError());
}

test "chunked upload arriving in two writes is relayed whole and the next request still answers" {
    var up = RecordingUpstream{};
    try up.start(18369);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18368, 18369);
    defer px.stop();

    // 5,000 bytes as 5 chunks of 1,000 (0x3e8), split mid-chunk across two writes.
    const chunk = "3e8\r\n" ++ rep("x", 1000) ++ "\r\n";
    const body = chunk ++ chunk ++ chunk ++ chunk ++ chunk ++ "0\r\n\r\n";
    const head = "POST /upload HTTP/1.1\r\nHost: dev.lo\r\nTransfer-Encoding: chunked\r\n\r\n";
    const split = 2500;
    const before = freshRing();
    const first = head ++ body[0..split];
    if (ssl_c.SSL_write(px.client, first.ptr, first.len) <= 0) return error.WriteFailed;
    rt.sleepMs(200);
    const rest = body[split..] ++ "GET /next HTTP/1.1\r\nHost: dev.lo\r\n\r\n";
    if (ssl_c.SSL_write(px.client, rest.ptr, rest.len) <= 0) return error.WriteFailed;
    var buf: [4096]u8 = undefined;
    _ = try px.readResponses(2, "ok", &buf);
    try testing.expect(std.mem.startsWith(u8, up.received(), "GET /next "));

    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);
    const deadline = rt.milliTimestamp() + 2000;
    while (requests.getCount() < before + 2) {
        if (rt.milliTimestamp() > deadline) return error.NoEntry;
        rt.sleepMs(10);
    }
    try testing.expect(requests.copyEntry(before, e));
    try testing.expectEqualStrings("/upload", e.getPath());
    try testing.expectEqual(@as(u64, 5000), e.req_body_total);
}

test "long headers, URLs and methods reach upstream intact" {
    var up = RecordingUpstream{};
    try up.start(18301);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18300, 18301);
    defer px.stop();

    const cookie = rep("a", 3000);
    const path = "/" ++ rep("p", 900);
    const before = freshRing();
    var buf: [4096]u8 = undefined;
    _ = try px.roundTrip("PROPFIND " ++ path ++ " HTTP/1.1\r\nHost: dev.lo\r\nCookie: " ++ cookie ++ "\r\n\r\n", "ok", &buf);

    const got = up.received();
    try testing.expect(std.mem.startsWith(u8, got, "PROPFIND " ++ path ++ " HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, got, "Cookie: " ++ cookie ++ "\r\n") != null);

    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);
    try waitNewestEntry(before, e);
    try testing.expectEqualStrings("PROPFIND", e.getMethod());
    try testing.expect(e.path_truncated);
    try testing.expect(e.req_headers_truncated);
}

test "request bodies over the capture size are forwarded whole" {
    var up = RecordingUpstream{};
    try up.start(18303);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18302, 18303);
    defer px.stop();

    const body = try testing.allocator.alloc(u8, 1024 * 1024);
    defer testing.allocator.free(body);
    for (body, 0..) |*b, i| b.* = @intCast('a' + i % 26);
    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);
    var buf: [4096]u8 = undefined;

    for ([_]usize{ 40 * 1024, 1024 * 1024 }) |size| {
        const head = try std.fmt.allocPrint(testing.allocator, "POST /up HTTP/1.1\r\nHost: dev.lo\r\nContent-Length: {d}\r\n\r\n", .{size});
        defer testing.allocator.free(head);
        const req = try std.mem.concat(testing.allocator, u8, &.{ head, body[0..size] });
        defer testing.allocator.free(req);
        const before = freshRing();
        _ = try px.roundTrip(req, "ok", &buf);

        const got = up.received();
        const got_body = got[(std.mem.indexOf(u8, got, "\r\n\r\n") orelse return error.NoHead) + 4 ..];
        try testing.expectEqualSlices(u8, body[0..size], got_body);
        const cl_line = try std.fmt.allocPrint(testing.allocator, "Content-Length: {d}\r\n", .{size});
        defer testing.allocator.free(cl_line);
        try testing.expect(std.mem.indexOf(u8, got, cl_line) != null);

        try waitNewestEntry(before, e);
        try testing.expectEqual(@as(u32, requests.max_body_len), e.req_body_len);
        try testing.expect(e.req_body_truncated);
        try testing.expectEqual(@as(u64, size), e.req_body_total);
    }
}

test "Content-Length over --max-body gets 413" {
    var up = RecordingUpstream{};
    try up.start(18305);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.startOpts(18304, 18305, .{ .max_request_body = 1000 });
    defer px.stop();
    var buf: [4096]u8 = undefined;
    const resp = try px.roundTrip("POST / HTTP/1.1\r\nHost: dev.lo\r\nContent-Length: 2000\r\n\r\n" ++ rep("x", 2000), "(2000 bytes)", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 413"));
}

test "chunked body over --max-body gets 413" {
    var up = RecordingUpstream{};
    try up.start(18307);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.startOpts(18306, 18307, .{ .max_request_body = 1000 });
    defer px.stop();
    var buf: [4096]u8 = undefined;
    const resp = try px.roundTrip("POST / HTTP/1.1\r\nHost: dev.lo\r\nTransfer-Encoding: chunked\r\n\r\n7d0\r\n" ++ rep("y", 2000) ++ "\r\n0\r\n\r\n", "bytes)", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 413"));
}

test "request head over 16 KB gets 431" {
    var up = RecordingUpstream{};
    try up.start(18309);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18308, 18309);
    defer px.stop();
    var buf: [4096]u8 = undefined;
    const resp = try px.roundTrip("GET / HTTP/1.1\r\nHost: dev.lo\r\nX-Big: " ++ rep("b", 17000) ++ "\r\n\r\n", "request head over 16KB", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 431"));
}

test "malformed chunked request body gets 400" {
    var up = RecordingUpstream{};
    try up.start(18311);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18310, 18311);
    defer px.stop();
    var buf: [4096]u8 = undefined;
    const resp = try px.roundTrip("POST / HTTP/1.1\r\nHost: dev.lo\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", "bad chunked encoding", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 400"));
}

test "chunked request body is relayed with its framing and without Content-Length" {
    var up = RecordingUpstream{};
    try up.start(18313);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18312, 18313);
    defer px.stop();

    const chunked = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    const before = freshRing();
    var buf: [4096]u8 = undefined;
    _ = try px.roundTrip("POST /c HTTP/1.1\r\nHost: dev.lo\r\nTransfer-Encoding: chunked\r\nContent-Length: 99\r\n\r\n" ++ chunked, "ok", &buf);

    const got = up.received();
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\n" ++ chunked));
    try testing.expect(std.mem.indexOf(u8, got, "Transfer-Encoding: chunked\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "Content-Length") == null);

    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);
    try waitNewestEntry(before, e);
    try testing.expectEqualStrings("Wikipedia", e.getReqBody());
    try testing.expectEqual(@as(u64, 9), e.req_body_total);
}

test "pipelined requests after Content-Length and chunked bodies are both answered" {
    var up = RecordingUpstream{};
    try up.start(18315);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18314, 18315);
    defer px.stop();
    var buf: [4096]u8 = undefined;

    const two = "POST /a HTTP/1.1\r\nHost: dev.lo\r\nContent-Length: 3\r\n\r\nabc" ++
        "GET /b HTTP/1.1\r\nHost: dev.lo\r\n\r\n";
    if (ssl_c.SSL_write(px.client, two.ptr, two.len) <= 0) return error.WriteFailed;
    _ = try px.readResponses(2, "ok", &buf);
    try testing.expect(std.mem.startsWith(u8, up.received(), "GET /b "));

    const chunked_two = "POST /c HTTP/1.1\r\nHost: dev.lo\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n" ++
        "GET /d HTTP/1.1\r\nHost: dev.lo\r\n\r\n";
    if (ssl_c.SSL_write(px.client, chunked_two.ptr, chunked_two.len) <= 0) return error.WriteFailed;
    _ = try px.readResponses(2, "ok", &buf);
    try testing.expect(std.mem.startsWith(u8, up.received(), "GET /d "));
}

/// Accepts every intercept hold as it appears, so held requests don't stall tests.
const AutoAccept = struct {
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,

    fn start(self: *AutoAccept) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }
    fn run(self: *AutoAccept) void {
        while (!self.done.load(.acquire)) {
            if (intercept.getPendingCount() > 0) intercept.acceptAll();
            rt.sleepMs(5);
        }
    }
    fn stop(self: *AutoAccept) void {
        self.done.store(true, .release);
        self.thread.join();
    }
};

test "intercept passes oversized requests through unheld" {
    var up = RecordingUpstream{};
    try up.start(18321);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18320, 18321);
    defer px.stop();
    intercept.enableWithPattern("req:");
    defer intercept.toggle();
    var acc = AutoAccept{};
    try acc.start();
    defer acc.stop();

    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);
    var buf: [4096]u8 = undefined;

    // Content-Length body over 32 KB
    const big = rep("z", (100 * 1024));
    var before = freshRing();
    _ = try px.roundTrip("POST /big HTTP/1.1\r\nHost: dev.lo\r\nContent-Length: 102400\r\n\r\n" ++ big, "ok", &buf);
    try testing.expect(std.mem.endsWith(u8, up.received(), "\r\n\r\n" ++ big));
    try waitNewestEntry(before, e);
    try testing.expect(e.too_large_to_intercept);
    try testing.expectEqual(requests.EntryState.normal, e.state);

    // Chunked body over 32 KB, in 16 KB chunks
    const chunk = comptime "4000\r\n" ++ rep("c", 16384) ++ "\r\n";
    const framed = rep(chunk, 4) ++ "0\r\n\r\n";
    before = freshRing();
    _ = try px.roundTrip("POST /bigc HTTP/1.1\r\nHost: dev.lo\r\nTransfer-Encoding: chunked\r\n\r\n" ++ framed, "ok", &buf);
    try testing.expect(std.mem.endsWith(u8, up.received(), "\r\n\r\n" ++ framed));
    try waitNewestEntry(before, e);
    try testing.expect(e.too_large_to_intercept);
    try testing.expectEqual(@as(u64, 4 * 16384), e.req_body_total);

    // Tiny chunks: framing fills the probe buffer before the capture does
    const tiny = rep("1\r\nq\r\n", 30000) ++ "0\r\n\r\n";
    before = freshRing();
    _ = try px.roundTrip("POST /tiny HTTP/1.1\r\nHost: dev.lo\r\nTransfer-Encoding: chunked\r\n\r\n" ++ tiny, "ok", &buf);
    try testing.expect(std.mem.endsWith(u8, up.received(), "\r\n\r\n" ++ tiny));
    try waitNewestEntry(before, e);
    try testing.expect(e.too_large_to_intercept);

    // Long URL: the path can't be edited faithfully
    before = freshRing();
    _ = try px.roundTrip("GET /" ++ rep("u", 900) ++ " HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "ok", &buf);
    try testing.expect(std.mem.startsWith(u8, up.received(), "GET /" ++ rep("u", 900) ++ " "));
    try waitNewestEntry(before, e);
    try testing.expect(e.too_large_to_intercept);
}

test "intercept holds a small chunked request and forwards it de-chunked" {
    var up = RecordingUpstream{};
    try up.start(18323);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18322, 18323);
    defer px.stop();
    intercept.enableWithPattern("req:");
    defer intercept.toggle();
    var acc = AutoAccept{};
    try acc.start();
    defer acc.stop();

    var buf: [4096]u8 = undefined;
    const two = "POST /c HTTP/1.1\r\nHost: dev.lo\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n" ++
        "GET /next HTTP/1.1\r\nHost: dev.lo\r\n\r\n";
    if (ssl_c.SSL_write(px.client, two.ptr, two.len) <= 0) return error.WriteFailed;
    _ = try px.readResponses(2, "ok", &buf);
    // The held POST was forwarded first, de-chunked; the pipelined GET came after.
    try testing.expect(std.mem.startsWith(u8, up.received(), "GET /next "));
}

test "held chunked request reaches upstream with Content-Length and no Transfer-Encoding" {
    var up = RecordingUpstream{};
    try up.start(18325);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18324, 18325);
    defer px.stop();
    intercept.enableWithPattern("req:");
    defer intercept.toggle();
    var acc = AutoAccept{};
    try acc.start();
    defer acc.stop();

    var buf: [4096]u8 = undefined;
    const before = freshRing();
    _ = try px.roundTrip("POST /c HTTP/1.1\r\nHost: dev.lo\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", "ok", &buf);
    const got = up.received();
    try testing.expect(std.mem.endsWith(u8, got, "Content-Length: 9\r\n\r\nWikipedia"));
    try testing.expect(std.mem.indexOf(u8, got, "Transfer-Encoding") == null);
    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);
    try waitNewestEntry(before, e);
    try testing.expect(!e.too_large_to_intercept);
}

test "response intercept relays oversized responses intact and unheld" {
    const body = comptime rep("r", (100 * 1024 - 3)) ++ "END";
    const chunk = comptime "4000\r\n" ++ rep("k", 16384) ++ "\r\n";
    const framed = comptime rep(chunk, 4) ++ "0\r\n\r\n";
    const cases = [_]struct { response: []const u8, want: []const u8 }{
        .{ .response = "HTTP/1.1 200 OK\r\nContent-Length: 102400\r\n\r\n" ++ body, .want = body },
        .{ .response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++ framed, .want = framed },
        .{ .response = "HTTP/1.1 200 OK\r\n\r\n" ++ body, .want = body }, // read to close
    };
    intercept.enableWithPattern("resp:");
    defer intercept.toggle();
    var acc = AutoAccept{};
    try acc.start();
    defer acc.stop();
    const out = try testing.allocator.alloc(u8, 256 * 1024);
    defer testing.allocator.free(out);
    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);

    for (cases, 0..) |c, i| {
        var up = RecordingUpstream{ .response = c.response };
        try up.start(@intCast(18331 + 2 * i));
        defer up.stop();
        var px: ProxyHarness = undefined;
        try px.start(@intCast(18330 + 2 * i), @intCast(18331 + 2 * i));
        defer px.stop();
        const before = freshRing();
        const resp = try px.roundTrip("GET /big HTTP/1.1\r\nHost: dev.lo\r\n\r\n", c.want[c.want.len - 5 ..], out);
        try testing.expect(std.mem.endsWith(u8, resp, c.want));
        const got_body = resp[(std.mem.indexOf(u8, resp, "\r\n\r\n") orelse return error.NoHead) + 4 ..];
        try testing.expectEqualSlices(u8, c.want, got_body);
        try waitNewestEntry(before, e);
        try testing.expect(e.too_large_to_intercept);
        try testing.expect(e.resp_body_truncated);
    }
}

test "response intercept holds small chunked and read-to-close responses, sent with Content-Length" {
    const cases = [_][]const u8{
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\n\r\nWikipedia",
    };
    intercept.enableWithPattern("resp:");
    defer intercept.toggle();
    var acc = AutoAccept{};
    try acc.start();
    defer acc.stop();
    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);
    var buf: [4096]u8 = undefined;

    for (cases, 0..) |response, i| {
        var up = RecordingUpstream{ .response = response };
        try up.start(@intCast(18337 + 2 * i));
        defer up.stop();
        var px: ProxyHarness = undefined;
        try px.start(@intCast(18336 + 2 * i), @intCast(18337 + 2 * i));
        defer px.stop();
        const before = freshRing();
        const resp = try px.roundTrip("GET /small HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "Wikipedia", &buf);
        try testing.expect(std.mem.indexOf(u8, resp, "Content-Length: 9\r\n") != null);
        try testing.expect(std.mem.indexOf(u8, resp, "Transfer-Encoding") == null);
        try waitNewestEntry(before, e);
        try testing.expect(e.resp_intercepted);
        try testing.expect(!e.too_large_to_intercept);
    }
}

test "upstream that hangs up mid-upload gets the client a 502 at once" {
    var up = RecordingUpstream{ .read_body = false };
    try up.start(18317);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18316, 18317);
    defer px.stop();

    const body = try testing.allocator.alloc(u8, 1024 * 1024);
    defer testing.allocator.free(body);
    @memset(body, 'u');
    const req = try std.mem.concat(testing.allocator, u8, &.{ "POST /up HTTP/1.1\r\nHost: dev.lo\r\nContent-Length: 1048576\r\n\r\n", body });
    defer testing.allocator.free(req);
    var buf: [4096]u8 = undefined;
    const resp = try px.roundTrip(req, "upstream stopped reading the request", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 502"));
}

test "parseTimeoutSeconds accepts whole seconds up to a day" {
    try testing.expectEqual(@as(?u32, 30), parseTimeoutSeconds("30"));
    try testing.expectEqual(@as(?u32, 0), parseTimeoutSeconds("0"));
    try testing.expectEqual(@as(?u32, 86400), parseTimeoutSeconds("86400"));
    try testing.expectEqual(@as(?u32, null), parseTimeoutSeconds("86401"));
    try testing.expectEqual(@as(?u32, null), parseTimeoutSeconds("30s"));
    try testing.expectEqual(@as(?u32, null), parseTimeoutSeconds(""));
    try testing.expectEqual(@as(?u32, null), parseTimeoutSeconds("-1"));
}

test "connect refused answers 502 and records the reason" {
    const before = freshRing();
    var px: ProxyHarness = undefined;
    try px.start(18340, 18341); // nothing listens on 18341
    defer px.stop();
    var buf: [1024]u8 = undefined;
    const resp = try px.roundTrip("GET /x HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "127.0.0.1:18341", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 502 Bad Gateway"));
    var e: requests.Entry = undefined;
    try waitNewestEntry(before, &e);
    try testing.expectEqual(@as(u16, 502), e.status);
    try testing.expectEqualStrings("connection refused 127.0.0.1:18341", e.getError());
    try testing.expectEqualStrings("/x", e.getPath());
}

test "413 over --max-body is recorded" {
    const before = freshRing();
    var up = RecordingUpstream{};
    try up.start(18343);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.startOpts(18342, 18343, .{ .max_request_body = 10 });
    defer px.stop();
    var buf: [1024]u8 = undefined;
    _ = try px.roundTrip("POST /up HTTP/1.1\r\nHost: dev.lo\r\nContent-Length: 20\r\n\r\n01234567890123456789", "(20 bytes)", &buf);
    var e: requests.Entry = undefined;
    try waitNewestEntry(before, &e);
    try testing.expectEqual(@as(u16, 413), e.status);
    try testing.expectEqualStrings("body over --max-body (20 bytes)", e.getError());
    try testing.expect(e.requestTruncated());
}

test "chunked body over --max-body is recorded" {
    const before = freshRing();
    var up = RecordingUpstream{};
    try up.start(18345);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.startOpts(18344, 18345, .{ .max_request_body = 10 });
    defer px.stop();
    var buf: [1024]u8 = undefined;
    _ = try px.roundTrip("POST /c HTTP/1.1\r\nHost: dev.lo\r\nTransfer-Encoding: chunked\r\n\r\n14\r\n01234567890123456789\r\n0\r\n\r\n", "bytes)", &buf);
    var e: requests.Entry = undefined;
    try waitNewestEntry(before, &e);
    try testing.expectEqual(@as(u16, 413), e.status);
    try testing.expect(std.mem.startsWith(u8, e.getError(), "body over --max-body"));
}

test "bad chunked framing is recorded as 400" {
    const before = freshRing();
    var up = RecordingUpstream{};
    try up.start(18347);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18346, 18347);
    defer px.stop();
    var buf: [1024]u8 = undefined;
    _ = try px.roundTrip("POST /c HTTP/1.1\r\nHost: dev.lo\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", "bad chunked encoding", &buf);
    var e: requests.Entry = undefined;
    try waitNewestEntry(before, &e);
    try testing.expectEqual(@as(u16, 400), e.status);
    try testing.expectEqualStrings("bad chunked encoding", e.getError());
    try testing.expect(e.requestTruncated());
}

test "431 head over 16KB is recorded with its request line" {
    const before = freshRing();
    var px: ProxyHarness = undefined;
    try px.start(18348, 18349);
    defer px.stop();
    const req = "GET /big HTTP/1.1\r\nX: " ++ rep("a", 17000) ++ "\r\n\r\n";
    var buf: [1024]u8 = undefined;
    _ = try px.roundTrip(req, "request head over 16KB", &buf);
    var e: requests.Entry = undefined;
    try waitNewestEntry(before, &e);
    try testing.expectEqual(@as(u16, 431), e.status);
    try testing.expectEqualStrings("GET", e.getMethod());
    try testing.expectEqualStrings("/big", e.getPath());
    try testing.expect(e.req_headers_truncated);
}

test "held request whose upstream is down finishes with the reason" {
    const before = freshRing();
    intercept.enableWithPattern("req:/held");
    defer intercept.toggle();
    var acc = AutoAccept{};
    try acc.start();
    defer acc.stop();
    var px: ProxyHarness = undefined;
    try px.start(18350, 18351); // nothing on 18351
    defer px.stop();
    var buf: [1024]u8 = undefined;
    _ = try px.roundTrip("GET /held HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "127.0.0.1:18351", &buf);
    // The connection closes after the error response.
    var one: [1]u8 = undefined;
    try testing.expect(ssl_c.SSL_read(px.client, &one, 1) <= 0);
    var e: requests.Entry = undefined;
    try waitNewestEntry(before, &e);
    try testing.expectEqual(@as(u16, 502), e.status);
    try testing.expect(!e.pinned);
    try testing.expectEqualStrings("connection refused 127.0.0.1:18351", e.getError());
}

test "no response head within --timeout answers 504" {
    const before = freshRing();
    var up = RecordingUpstream{ .delay_ms = 3000 };
    try up.start(18353);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.startOpts(18352, 18353, .{ .upstream_timeout_s = 1 });
    defer px.stop();
    var buf: [1024]u8 = undefined;
    const t0 = rt.milliTimestamp();
    const resp = try px.roundTrip("GET /slow HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "no response within 1s", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 504 Gateway Timeout"));
    try testing.expect(rt.milliTimestamp() - t0 < 2500);
    var e: requests.Entry = undefined;
    try waitNewestEntry(before, &e);
    try testing.expectEqual(@as(u16, 504), e.status);
    try testing.expectEqualStrings("no response within 1s", e.getError());
}

test "upstream that closes without a head answers 502" {
    const before = freshRing();
    var up = RecordingUpstream{ .response = "" };
    try up.start(18355);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18354, 18355);
    defer px.stop();
    var buf: [1024]u8 = undefined;
    _ = try px.roundTrip("GET / HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "upstream closed before responding", &buf);
    var e: requests.Entry = undefined;
    try waitNewestEntry(before, &e);
    try testing.expectEqual(@as(u16, 502), e.status);
}

test "a stream quiet for longer than --timeout after its head is relayed whole" {
    var up = RecordingUpstream{
        .response = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: a\n\n",
        .response2 = "data: b\n\n",
        .gap_ms = 2000,
    };
    try up.start(18357);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.startOpts(18356, 18357, .{ .upstream_timeout_s = 1 });
    defer px.stop();
    var buf: [1024]u8 = undefined;
    const resp = try px.roundTrip("GET /events HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "data: b\n\n", &buf);
    try testing.expect(std.mem.indexOf(u8, resp, "data: a\n\ndata: b\n\n") != null);
}

test "response intercept probe that hits --timeout relays unheld" {
    const before = freshRing();
    intercept.enableWithPattern("resp:/probe");
    defer intercept.toggle();
    var acc = AutoAccept{};
    try acc.start();
    defer acc.stop();
    var up = RecordingUpstream{
        .response = "HTTP/1.1 200 OK\r\n\r\nfirst-",
        .response2 = "second",
        .gap_ms = 2000,
    };
    try up.start(18359);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.startOpts(18358, 18359, .{ .upstream_timeout_s = 1 });
    defer px.stop();
    var buf: [1024]u8 = undefined;
    const resp = try px.roundTrip("GET /probe HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "first-second", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200"));
    var e: requests.Entry = undefined;
    try waitNewestEntry(before, &e);
    try testing.expect(e.too_large_to_intercept);
}

/// TLS upstream for an external route: handshakes, reads one request head, waits
/// `delay_ms` (sliced, ends on stop), then answers with `response`.
const SlowTlsUpstream = struct {
    listener: compat.socket_t = undefined,
    srv: TestServer = undefined,
    thread: std.Thread = undefined,
    delay_ms: u32 = 0,
    response: []const u8 = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    /// Before the delay, send only a TLS record header: the proxy's socket polls
    /// readable, but no complete record (and no data) arrives.
    partial_record: bool = false,

    var running: std.atomic.Value(bool) = .init(true);
    fn isRunning() bool {
        return running.load(.acquire);
    }

    fn start(self: *SlowTlsUpstream, port: u16) !void {
        running.store(true, .release);
        self.srv = try testServer("localhost");
        self.listener = try compat.tcpListen(try std.Io.net.IpAddress.parseIp4("127.0.0.1", port));
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
    }

    fn serve(self: *SlowTlsUpstream) void {
        var fds = [1]compat.pollfd{.{ .fd = self.listener, .events = compat.POLL.IN, .revents = 0 }};
        if (compat.pollWhileRunning(&fds, 15_000, isRunning) != .ready) return;
        const conn = compat.accept(self.listener) catch return;
        defer compat.closeSocket(conn.sock);
        setSocketTimeout(conn.sock, .recv, 5);
        const ssl = ssl_c.SSL_new(self.srv.ctx) orelse return;
        defer ssl_c.SSL_free(ssl);
        _ = ssl_c.SSL_set_fd(ssl, compat.socketToFd(conn.sock));
        if (ssl_c.SSL_accept(ssl) != 1) return;
        var head: [4096]u8 = undefined;
        var len: usize = 0;
        while (std.mem.indexOf(u8, head[0..len], "\r\n\r\n") == null and len < head.len) {
            const n = ssl_c.SSL_read(ssl, head[len..].ptr, @intCast(head.len - len));
            if (n <= 0) return;
            len += @intCast(n);
        }
        if (self.partial_record) {
            const s = compat.SocketStream{ .handle = conn.sock };
            s.writeAll("\x17\x03\x03\x00\x40") catch return; // application_data, 64 bytes promised
            RecordingUpstream.sleepWhileRunning(self.delay_ms, isRunning);
            return;
        }
        RecordingUpstream.sleepWhileRunning(self.delay_ms, isRunning);
        _ = ssl_c.SSL_write(ssl, self.response.ptr, @intCast(self.response.len));
        _ = ssl_c.SSL_shutdown(ssl);
    }

    fn stop(self: *SlowTlsUpstream) void {
        running.store(false, .release);
        self.thread.join();
        compat.closeSocket(self.listener);
        ssl_c.SSL_CTX_free(self.srv.ctx);
        ssl_c.X509_free(self.srv.cert);
    }
};

test "external TLS route answers 504 when no response head comes within --timeout" {
    const before = freshRing();
    var up = SlowTlsUpstream{ .delay_ms = 3000, .partial_record = true };
    try up.start(18361);
    defer up.stop();
    const cctx = createClientSslCtx(true) orelse return error.SslCtx;
    defer ssl_c.SSL_CTX_free(cctx);
    const routes = [_]Route{.{ .kind = .path, .pattern = "/ext", .port = 18361, .hostname = "127.0.0.1" }};
    var px: ProxyHarness = undefined;
    try px.startOpts(18360, 1, .{ .routes = &routes, .client_ctx = cctx, .upstream_timeout_s = 1 });
    defer px.stop();
    var buf: [1024]u8 = undefined;
    const t0 = rt.milliTimestamp();
    const resp = try px.roundTrip("GET /ext HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "no response within 1s", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 504"));
    try testing.expect(rt.milliTimestamp() - t0 < 2500);
    var e: requests.Entry = undefined;
    try waitNewestEntry(before, &e);
    try testing.expectEqual(@as(u16, 504), e.status);
}

test "external TLS route relays a response slower than one socket read" {
    var up = SlowTlsUpstream{ .delay_ms = 1500 };
    try up.start(18363);
    defer up.stop();
    const cctx = createClientSslCtx(true) orelse return error.SslCtx;
    defer ssl_c.SSL_CTX_free(cctx);
    const routes = [_]Route{.{ .kind = .path, .pattern = "/ext", .port = 18363, .hostname = "127.0.0.1" }};
    var px: ProxyHarness = undefined;
    try px.startOpts(18362, 1, .{ .routes = &routes, .client_ctx = cctx, .upstream_timeout_s = 10 });
    defer px.stop();
    var buf: [1024]u8 = undefined;
    const resp = try px.roundTrip("GET /ext HTTP/1.1\r\nHost: dev.lo\r\n\r\n", "ok", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200"));
}

test "WebSocket upgrade with no response within --timeout answers 504" {
    const before = freshRing();
    var up = RecordingUpstream{ .delay_ms = 3000 };
    try up.start(18365);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.startOpts(18364, 18365, .{ .upstream_timeout_s = 1 });
    defer px.stop();
    var buf: [1024]u8 = undefined;
    const resp = try px.roundTrip("GET /ws HTTP/1.1\r\nHost: dev.lo\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", "no response within 1s", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 504"));
    var e: requests.Entry = undefined;
    try waitNewestEntry(before, &e);
    try testing.expectEqual(@as(u16, 504), e.status);
}

fn startShareForTest() void {
    share.resetForTest();
    share.begin(0);
    _ = share.publishHost("x.trycloudflare.com");
}

test "forwardRequest writes the local Host for shared requests" {
    const e = buildEntry("GET", "/a", "Host: x.trycloudflare.com\r\nAccept: */*\r\n", "");
    var out: [512]u8 = undefined;
    var len: usize = 0;
    forwardRequest(TestSink{ .buf = &out, .len = &len }, &e, .{
        .is_external = false,
        .upstream_host = "127.0.0.1",
        .client_host = "x.trycloudflare.com",
        .client_ip = "127.0.0.1",
        .domain = "dev.lo",
        .shared = true,
        .real_ip = "203.0.113.7",
    });
    try testing.expectEqualStrings(
        "GET /a HTTP/1.1\r\n" ++
            "Accept: */*\r\n" ++
            "Host: dev.lo\r\nX-Forwarded-Host: x.trycloudflare.com\r\nX-Forwarded-For: 127.0.0.1\r\n" ++
            "X-Real-IP: 203.0.113.7\r\nX-Forwarded-Proto: https\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n" ++
            "Content-Length: 0\r\n\r\n",
        out[0..len],
    );
}

test "shared request goes upstream as the local domain with the public host forwarded" {
    startShareForTest();
    defer share.resetForTest();
    var up = RecordingUpstream{};
    try up.start(18901);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18900, 18901);
    defer px.stop();
    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);
    const before = freshRing();
    var buf: [4096]u8 = undefined;
    _ = try px.roundTrip("GET /s HTTP/1.1\r\nHost: x.trycloudflare.com\r\nCF-Connecting-IP: 203.0.113.7\r\nX-Forwarded-For: 203.0.113.7\r\n\r\n", "ok", &buf);
    const got = up.received();
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "\r\nHost: dev.lo\r\n"));
    try testing.expect(std.mem.indexOf(u8, got, "\r\nHost: x.trycloudflare.com\r\n") == null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nX-Forwarded-Host: x.trycloudflare.com\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nX-Real-IP: 203.0.113.7\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nX-Forwarded-For: 203.0.113.7, 127.0.0.1\r\n") != null);
    try waitNewestEntry(before, e);
    try testing.expect(e.shared);
}

test "non-shared request unchanged while share ready" {
    share.resetForTest();
    defer share.resetForTest();
    const req = "GET /n HTTP/1.1\r\nHost: dev.lo\r\nAccept: */*\r\n\r\n";
    var off_bytes: [2048]u8 = undefined;
    var off_len: usize = 0;
    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);
    var buf: [4096]u8 = undefined;
    {
        var up = RecordingUpstream{};
        try up.start(18903);
        defer up.stop();
        var px: ProxyHarness = undefined;
        try px.start(18902, 18903);
        defer px.stop();
        _ = try px.roundTrip(req, "ok", &buf);
        const got = up.received();
        @memcpy(off_bytes[0..got.len], got);
        off_len = got.len;
    }
    startShareForTest();
    {
        var up = RecordingUpstream{};
        try up.start(18905);
        defer up.stop();
        var px: ProxyHarness = undefined;
        try px.start(18904, 18905);
        defer px.stop();
        const before = freshRing();
        _ = try px.roundTrip(req, "ok", &buf);
        try testing.expectEqualStrings(off_bytes[0..off_len], up.received());
        try waitNewestEntry(before, e);
        try testing.expect(!e.shared);
    }
}

test "bad CF-Connecting-IP falls back to the peer" {
    startShareForTest();
    defer share.resetForTest();
    var up = RecordingUpstream{};
    try up.start(18907);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18906, 18907);
    defer px.stop();
    var buf: [4096]u8 = undefined;
    _ = try px.roundTrip("GET /b HTTP/1.1\r\nHost: x.trycloudflare.com\r\nCF-Connecting-IP: nope\r\n\r\n", "ok", &buf);
    try testing.expect(std.mem.indexOf(u8, up.received(), "\r\nX-Real-IP: 127.0.0.1\r\n") != null);
    _ = try px.roundTrip("GET /b HTTP/1.1\r\nHost: x.trycloudflare.com\r\nCF-Connecting-IP: 1.2.3.4, 5.6.7.8\r\n\r\n", "ok", &buf);
    try testing.expect(std.mem.indexOf(u8, up.received(), "\r\nX-Real-IP: 127.0.0.1\r\n") != null);
    _ = try px.roundTrip("GET /b HTTP/1.1\r\nHost: x.trycloudflare.com\r\nCF-Connecting-IP: 2001:db8::1\r\n\r\n", "ok", &buf);
    try testing.expect(std.mem.indexOf(u8, up.received(), "\r\nX-Real-IP: 2001:db8::1\r\n") != null);
}

const share_redirect_response = "HTTP/1.1 302 Found\r\nLocation: https://dev.lo/home\r\nSet-Cookie: s=1; Domain=dev.lo; Path=/\r\nContent-Length: 2\r\n\r\nok";

test "shared response rewrites Location and drops local cookie Domain" {
    startShareForTest();
    defer share.resetForTest();
    var up = RecordingUpstream{ .response = share_redirect_response };
    try up.start(18909);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18908, 18909);
    defer px.stop();
    var buf: [4096]u8 = undefined;
    const resp = try px.roundTrip("GET / HTTP/1.1\r\nHost: x.trycloudflare.com\r\n\r\n", "ok", &buf);
    try testing.expect(std.mem.indexOf(u8, resp, "\r\nLocation: https://x.trycloudflare.com/home\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "\r\nSet-Cookie: s=1; Path=/\r\n") != null);
}

test "held shared response is rewritten too" {
    startShareForTest();
    defer share.resetForTest();
    intercept.enableWithPattern("resp:");
    defer intercept.toggle();
    var acc = AutoAccept{};
    try acc.start();
    defer acc.stop();
    var up = RecordingUpstream{ .response = share_redirect_response };
    try up.start(18911);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18910, 18911);
    defer px.stop();
    const e = try testing.allocator.create(requests.Entry);
    defer testing.allocator.destroy(e);
    const before = freshRing();
    var buf: [4096]u8 = undefined;
    const resp = try px.roundTrip("GET / HTTP/1.1\r\nHost: x.trycloudflare.com\r\n\r\n", "ok", &buf);
    try testing.expect(std.mem.indexOf(u8, resp, "\r\nLocation: https://x.trycloudflare.com/home\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "\r\nSet-Cookie: s=1; Path=/\r\n") != null);
    try waitNewestEntry(before, e);
    try testing.expect(e.resp_intercepted);
}

test "held shared request goes upstream as the local domain" {
    startShareForTest();
    defer share.resetForTest();
    intercept.enableWithPattern("req:");
    defer intercept.toggle();
    var acc = AutoAccept{};
    try acc.start();
    defer acc.stop();
    var up = RecordingUpstream{};
    try up.start(18913);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18912, 18913);
    defer px.stop();
    var buf: [4096]u8 = undefined;
    _ = try px.roundTrip("GET /h HTTP/1.1\r\nHost: x.trycloudflare.com\r\n\r\n", "ok", &buf);
    const got = up.received();
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "\r\nHost: dev.lo\r\n"));
    try testing.expect(std.mem.indexOf(u8, got, "\r\nHost: x.trycloudflare.com\r\n") == null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nX-Forwarded-Host: x.trycloudflare.com\r\n") != null);
}

test "shared WebSocket upgrade gets Host of the local domain" {
    startShareForTest();
    defer share.resetForTest();
    var up = RecordingUpstream{ .response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" };
    try up.start(18915);
    defer up.stop();
    var px: ProxyHarness = undefined;
    try px.start(18914, 18915);
    defer px.stop();
    var buf: [1024]u8 = undefined;
    const resp = try px.roundTrip("GET /hmr HTTP/1.1\r\nHost: x.trycloudflare.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", "\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 101"));
    const got = up.received();
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "\r\nHost: dev.lo\r\n"));
    try testing.expect(std.mem.indexOf(u8, got, "\r\nHost: x.trycloudflare.com\r\n") == null);
    try testing.expect(std.mem.indexOf(u8, got, "\r\nX-Forwarded-Host: x.trycloudflare.com\r\n") != null);
}
