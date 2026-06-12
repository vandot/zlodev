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

const ssl_c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    if (builtin.os.tag == .windows) {
        @cInclude("winsock2.h");
    } else {
        @cInclude("sys/socket.h");
    }
});

pub const default_max_request_body: usize = 10 * 1024 * 1024; // 10MB

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
    cert_path: [:0]const u8,
    key_path: [:0]const u8,
    ca_path: [:0]const u8,
    server_ident: []const u8,
    max_request_body: usize = default_max_request_body,
    routes: []const Route = &.{},
    domain: []const u8 = "dev.lo",
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
    ssl_conn: ?*ssl_c.SSL = null,

    fn writeAll(self: UpstreamConn, data: []const u8) !void {
        if (self.ssl_conn) |s| {
            var sent: usize = 0;
            while (sent < data.len) {
                const n = ssl_c.SSL_write(s, @ptrCast(data[sent..].ptr), @intCast(data.len - sent));
                if (n <= 0) return error.SslWrite;
                sent += @intCast(n);
            }
        } else {
            try self.sock.writeAll(data);
        }
    }

    pub fn read(self: UpstreamConn, buf: []u8) !usize {
        if (self.ssl_conn) |s| {
            const n = ssl_c.SSL_read(s, @ptrCast(buf.ptr), @intCast(buf.len));
            if (n <= 0) return error.SslRead;
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

/// Create a TLS client context for connecting to external upstreams.
fn createClientSslCtx() ?*ssl_c.SSL_CTX {
    const ctx = ssl_c.SSL_CTX_new(ssl_c.TLS_client_method()) orelse return null;
    // Use system CA certificates for verifying upstream servers
    if (ssl_c.SSL_CTX_set_default_verify_paths(ctx) != 1) {
        log.err("component=proxy op=client_ssl error=set_verify_paths_failed", .{});
    }
    _ = ssl_c.SSL_CTX_set_mode(ctx, ssl_c.SSL_MODE_AUTO_RETRY);
    return ctx;
}

pub fn start(config: *const ProxyConfig) !void {
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
    const client_ctx: ?*ssl_c.SSL_CTX = if (has_external) createClientSslCtx() else null;
    defer if (client_ctx) |c| ssl_c.SSL_CTX_free(c);

    const address = try std.net.Address.parseIp(config.listen_addr, 443);
    var server = address.listen(.{ .reuse_address = true }) catch |e| {
        log.err("component=proxy op=bind port=443 error={any}", .{e});
        if (e == error.AddressInUse) {
            std.debug.print("port 443 is already in use\n", .{});
        }
        return e;
    };
    defer server.deinit();

    log.info("component=proxy op=listening ip={s} port=443 target={s}:{d}", .{ config.listen_addr, config.target_host, config.target_port });

    var pool: std.Thread.Pool = undefined;
    pool.init(.{ .allocator = std.heap.page_allocator, .n_jobs = 64, .stack_size = if (builtin.cpu.arch == .x86_64) 4 * 1024 * 1024 else 1024 * 1024 }) catch |e| {
        log.err("component=proxy op=pool_init error={any}", .{e});
        return e;
    };
    defer pool.deinit();

    var consecutive_failures: u32 = 0;
    while (shutdown.isRunning()) {
        // Poll with 1-second timeout before accept
        var fds = [1]posix.pollfd{
            .{ .fd = server.stream.handle, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = posix.poll(&fds, 1000) catch |e| {
            log.err("component=proxy op=poll error={any}", .{e});
            continue;
        };
        if (ready == 0) continue; // timeout, re-check shutdown

        const conn = server.accept() catch |e| {
            log.err("component=proxy op=accept error={any}", .{e});
            consecutive_failures += 1;
            const backoff_ms: u64 = @min(5000, @as(u64, 100) << @intCast(@min(consecutive_failures, 6)));
            std.Thread.sleep(backoff_ms * std.time.ns_per_ms);
            continue;
        };
        consecutive_failures = 0;

        const ssl = ssl_c.SSL_new(ctx) orelse {
            log.err("component=proxy op=ssl_new error=alloc_failed", .{});
            conn.stream.close();
            continue;
        };

        _ = ssl_c.SSL_set_fd(ssl, compat.socketToFd(conn.stream.handle));

        const conn_id = nextConnId();
        pool.spawn(handleConnection, .{
            ssl,
            conn.stream,
            conn.address,
            config,
            conn_id,
            client_ctx,
        }) catch |e| {
            log.err("component=proxy op=pool_spawn conn={d} error={any}", .{ conn_id, e });
            ssl_c.SSL_free(ssl);
            conn.stream.close();
        };
    }
}

/// Resolve, connect, and (for external routes) TLS-handshake an upstream connection.
/// On any failure the specific cause is logged and `error.UpstreamUnavailable` is
/// returned; the caller maps that to a single 502. Owns the resolved AddressList for
/// its own lifetime and sets send/recv timeouts on the socket before returning.
fn connectUpstream(
    is_external: bool,
    upstream_host: []const u8,
    upstream_port: u16,
    config: *const ProxyConfig,
    client_ctx: ?*ssl_c.SSL_CTX,
    conn_id: u64,
) !UpstreamConn {
    // Resolve upstream address — DNS for external, IP parse for local
    var addr_list: ?*std.net.AddressList = null;
    defer if (addr_list) |al| al.deinit();

    const upstream_addr: std.net.Address = blk: {
        if (is_external) {
            const al = std.net.getAddressList(std.heap.page_allocator, upstream_host, upstream_port) catch {
                log.err("component=proxy conn={d} op=dns_resolve host={s} error=failed", .{ conn_id, upstream_host });
                return error.UpstreamUnavailable;
            };
            addr_list = al;
            if (al.addrs.len == 0) {
                log.err("component=proxy conn={d} op=dns_resolve host={s} error=no_addresses", .{ conn_id, upstream_host });
                return error.UpstreamUnavailable;
            }
            break :blk al.addrs[0];
        } else {
            break :blk std.net.Address.parseIp(config.target_host, upstream_port) catch {
                return error.UpstreamUnavailable;
            };
        }
    };

    const upstream_sock = posix.socket(upstream_addr.any.family, posix.SOCK.STREAM, 0) catch |e| {
        log.err("component=proxy conn={d} op=upstream_socket error={any}", .{ conn_id, e });
        return error.UpstreamUnavailable;
    };
    posix.connect(upstream_sock, &upstream_addr.any, upstream_addr.getOsSockLen()) catch |e| {
        log.err("component=proxy conn={d} op=upstream_connect host={s} error={any}", .{ conn_id, upstream_host, e });
        compat.closeSocket(upstream_sock);
        return error.UpstreamUnavailable;
    };

    // Wrap in TLS for external upstreams; plain socket for local
    var upstream_ssl_obj: ?*ssl_c.SSL = null;
    if (is_external) {
        const cctx = client_ctx orelse {
            // client_ctx is null — SSL_CTX allocation failed at startup
            log.err("component=proxy conn={d} op=external_tls error=no_client_ctx", .{conn_id});
            compat.closeSocket(upstream_sock);
            return error.UpstreamUnavailable;
        };
        const us = ssl_c.SSL_new(cctx) orelse {
            log.err("component=proxy conn={d} op=upstream_ssl_new error=alloc_failed", .{conn_id});
            compat.closeSocket(upstream_sock);
            return error.UpstreamUnavailable;
        };
        _ = ssl_c.SSL_set_fd(us, compat.socketToFd(upstream_sock));
        // Set SNI hostname
        var sni_buf: [256]u8 = undefined;
        if (upstream_host.len < sni_buf.len) {
            @memcpy(sni_buf[0..upstream_host.len], upstream_host);
            sni_buf[upstream_host.len] = 0;
            _ = ssl_c.SSL_set_tlsext_host_name(us, &sni_buf);
        }
        if (ssl_c.SSL_connect(us) != 1) {
            log.err("component=proxy conn={d} op=upstream_tls_handshake host={s} error=failed", .{ conn_id, upstream_host });
            ssl_c.SSL_free(us);
            compat.closeSocket(upstream_sock);
            return error.UpstreamUnavailable;
        }
        upstream_ssl_obj = us;
    }

    const upstream = UpstreamConn{ .sock = .{ .handle = upstream_sock }, .ssl_conn = upstream_ssl_obj };
    setSocketTimeout(upstream_sock, .recv, 30);
    setSocketTimeout(upstream_sock, .send, 30);
    return upstream;
}

fn handleConnection(
    ssl: *ssl_c.SSL,
    stream: std.net.Stream,
    client_addr: std.net.Address,
    config: *const ProxyConfig,
    conn_id: u64,
    client_ctx: ?*ssl_c.SSL_CTX,
) void {
    defer {
        _ = ssl_c.SSL_shutdown(ssl);
        ssl_c.SSL_free(ssl);
        stream.close();
    }

    if (ssl_c.SSL_accept(ssl) != 1) {
        return;
    }

    // Set receive timeout on client socket
    setSocketTimeout(stream.handle, .recv, 30);

    // Keep-alive loop: process multiple requests on the same TLS connection
    var request_count: u32 = 0;
    while (request_count < 100) : (request_count += 1) {
        // Read request headers
        var req_buf: [16384]u8 = undefined;
        var total: usize = 0;
        var headers_end: ?usize = null;

        while (total < req_buf.len) {
            const n = ssl_c.SSL_read(ssl, @ptrCast(req_buf[total..].ptr), @intCast(req_buf.len - total));
            if (n <= 0) break;
            total += @as(usize, @intCast(n));
            if (std.mem.indexOf(u8, req_buf[0..total], "\r\n\r\n")) |pos| {
                headers_end = pos;
                break;
            }
        }

        if (total == 0 or headers_end == null) return; // client closed or bad data

        const hdr_end = headers_end.?;
        const start_time = std.time.milliTimestamp();

        // Parse request line
        const first_line_end = std.mem.indexOf(u8, req_buf[0..total], "\r\n") orelse return;
        const request_line = req_buf[0..first_line_end];

        var parts = std.mem.splitScalar(u8, request_line, ' ');
        var method = parts.next() orelse return;
        var uri = parts.next() orelse return;
        const version = parts.next() orelse "HTTP/1.0";
        var addr_buf: [46]u8 = undefined;
        log.info("component=proxy conn={d} method={s} uri={s} client={s}", .{ conn_id, method, uri, formatAddress(client_addr, &addr_buf) });

        // Health check — return immediately, bypass everything
        if (std.mem.eql(u8, uri, "/health")) {
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
        var host = http_wire.getHeaderValue(req_hdr_section, "host:") orelse "";
        const route_result = resolveRoute(config, host, uri);
        const upstream_port = route_result.port;

        // Prepare request log entry
        var entry = requests.Entry{ .timestamp = start_time, .route_index = route_result.index };
        const m_len = @min(method.len, entry.method.len);
        @memcpy(entry.method[0..m_len], method[0..m_len]);
        entry.method_len = @intCast(m_len);
        const p_len = @min(uri.len, entry.path.len);
        @memcpy(entry.path[0..p_len], uri[0..p_len]);
        entry.path_len = @intCast(p_len);

        // Capture request headers
        const rh_len = @min(req_hdr_section.len, requests.max_header_len);
        @memcpy(entry.req_headers[0..rh_len], req_hdr_section[0..rh_len]);
        entry.req_headers_len = @intCast(rh_len);

        // Re-derive from entry to avoid use-after-free when body read overwrites req_buf
        method = entry.method[0..m_len];
        uri = entry.path[0..p_len];
        host = http_wire.getHeaderValue(entry.req_headers[0..rh_len], "host:") orelse "";

        // Check for WebSocket upgrade
        if (http_wire.isWebSocketUpgrade(req_hdr_section)) {
            handleWebSocket(ssl, req_buf[0..total], config, upstream_port, &entry);
            return;
        }

        // Get Content-Length for body
        const content_length = http_wire.getContentLength(req_buf[0 .. hdr_end + 4]) orelse 0;

        // Reject absurdly large bodies
        if (content_length > config.max_request_body) {
            log.err("component=proxy conn={d} op=body_read bytes={d} max={d} error=body_too_large", .{ conn_id, content_length, config.max_request_body });
            sslSendError(ssl, 413, "Request Entity Too Large");
            return;
        }

        const body_start = hdr_end + 4;
        var body_received = if (total > body_start) total - body_start else 0;

        // Read full request body directly into entry (available for editing/intercept)
        var body_stored: usize = 0;
        if (body_received > 0) {
            const cap = @min(body_received, requests.max_body_len);
            @memcpy(entry.req_body[0..cap], req_buf[body_start .. body_start + cap]);
            body_stored = cap;
        }
        if (body_received < content_length) {
            var remaining = content_length - body_received;
            while (remaining > 0) {
                const n = ssl_c.SSL_read(ssl, @ptrCast(&req_buf), @intCast(@min(remaining, req_buf.len)));
                if (n <= 0) break;
                const read_bytes: usize = @as(usize, @intCast(n));
                const space = requests.max_body_len -| body_stored;
                const cap = @min(read_bytes, space);
                if (cap > 0) {
                    @memcpy(entry.req_body[body_stored .. body_stored + cap], req_buf[0..cap]);
                    body_stored += cap;
                }
                body_received += read_bytes;
                remaining -= read_bytes;
            }
        }
        entry.req_body_len = @intCast(body_stored);
        if (content_length > requests.max_body_len) {
            entry.req_body_truncated = true;
        }

        // Intercept check
        var was_intercepted = false;
        var intercept_backing_idx: usize = 0;
        if (intercept.shouldInterceptRequest(method, uri)) {
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
                // ring entry to normal; continue as an un-intercepted request.
                entry.state = .normal;
            }
        }

        // Ensure intercepted entries are unpinned on any early exit after this point.
        // Normal completion paths call finishEntry/finishResponseIntercept explicitly,
        // which set status/duration before unpinning — so this defer only fires for
        // error exits where the entry would otherwise be pinned forever.
        defer if (was_intercepted) {
            const dur = std.time.milliTimestamp() - start_time;
            requests.finishIfDangling(intercept_backing_idx, 502, if (dur > 0) @intCast(dur) else 0);
        };

        // Connect to upstream (per-request — dev servers may not support keep-alive)
        const is_external = route_result.hostname != null;
        const upstream_host = route_result.hostname orelse config.target_host;

        const upstream = connectUpstream(is_external, upstream_host, upstream_port, config, client_ctx, conn_id) catch {
            const dur = std.time.milliTimestamp() - start_time;
            if (was_intercepted) {
                requests.finishEntry(intercept_backing_idx, 502, if (dur > 0) @intCast(dur) else 0, "", "");
            }
            sslSendError(ssl, 502, "Bad Gateway");
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
                requests.finishEntry(intercept_backing_idx, 502, 0, "", "");
                sslSendError(ssl, 502, "Bad Gateway");
                return;
            };
            fwd_snapshot = s;
            requests.snapshotByBackingIndex(intercept_backing_idx, s);
            break :blk s;
        } else &entry;

        // A truncated request body can't be forwarded with a correct Content-Length —
        // reject before emitting anything to upstream.
        if (fwd_entry.req_body_truncated) {
            sslSendError(ssl, 413, "Request body too large for proxy buffer");
            return;
        }

        var ip_buf: [64]u8 = undefined;
        forwardRequest(UpstreamSink{ .upstream = upstream }, fwd_entry, .{
            .is_external = is_external,
            .upstream_host = upstream_host,
            .client_host = host,
            .client_ip = formatAddress(client_addr, &ip_buf),
            .domain = config.domain,
        });

        // Read upstream response
        var resp_buf: [16384]u8 = undefined;
        var resp_total: usize = 0;
        var resp_headers_end: ?usize = null;

        while (resp_total < resp_buf.len) {
            const n = upstream.read(resp_buf[resp_total..]) catch break;
            if (n == 0) break;
            resp_total += n;
            if (std.mem.indexOf(u8, resp_buf[0..resp_total], "\r\n\r\n")) |pos| {
                resp_headers_end = pos;
                break;
            }
        }

        if (resp_total == 0 or resp_headers_end == null) return;
        const resp_hdr_end = resp_headers_end.?;

        // Extract status line
        const resp_first_line_end = std.mem.indexOf(u8, resp_buf[0..resp_total], "\r\n") orelse return;

        // Extract status code (e.g. "HTTP/1.1 200 OK" -> 200)
        const resp_line = resp_buf[0..resp_first_line_end];
        var resp_parts = std.mem.splitScalar(u8, resp_line, ' ');
        _ = resp_parts.next(); // skip HTTP version
        if (resp_parts.next()) |status_str| {
            entry.status = std.fmt.parseInt(u16, status_str, 10) catch 0;
        }

        // Capture response headers
        const resp_headers_section = resp_buf[resp_first_line_end + 2 .. resp_hdr_end];
        const rsh_len = @min(resp_headers_section.len, requests.max_header_len);
        @memcpy(entry.resp_headers[0..rsh_len], resp_headers_section[0..rsh_len]);
        entry.resp_headers_len = @intCast(rsh_len);

        // Determine if we must close after this response
        const is_chunked = http_wire.isChunkedEncoding(resp_headers_section);
        const resp_content_length = http_wire.getContentLength(resp_buf[0 .. resp_hdr_end + 4]);
        const upstream_conn = http_wire.getConnectionHeader(resp_headers_section);
        const response_has_defined_length = is_chunked or resp_content_length != null;
        const must_close = !keep_alive or upstream_conn == .close or !response_has_defined_length;

        const resp_body_start = resp_hdr_end + 4;
        const initial_body = if (resp_body_start < resp_total) resp_buf[resp_body_start..resp_total] else resp_buf[0..0];

        // Check if we should intercept the response
        const intercept_resp = intercept.shouldInterceptResponse(method, uri);

        if (intercept_resp) {
            // Buffer entire response body into entry before forwarding
            var resp_body_captured: usize = 0;

            if (is_chunked) {
                const pr = http_wire.pumpChunked(initial_body, upstream, http_wire.NullSink{}, &entry.resp_body);
                resp_body_captured = pr.captured;
                if (pr.truncated) entry.resp_body_truncated = true;
            } else {
                const br = http_wire.streamBody(initial_body, upstream, http_wire.NullSink{}, resp_content_length, &entry.resp_body);
                resp_body_captured = br.captured;
                if (br.truncated) entry.resp_body_truncated = true;
            }
            entry.resp_body_len = @intCast(resp_body_captured);

            // Record when upstream response was fully received
            const resp_received_time = std.time.milliTimestamp();
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
                        forwardResponseFromEntry(ssl, resp_snap, is_external, config.domain, must_close);

                        // Duration = hold time only
                        const hold_elapsed = std.time.milliTimestamp() - resp_received_time;
                        requests.finishResponseIntercept(h.index(), if (hold_elapsed > 0) @intCast(hold_elapsed) else 0);

                        if (must_close) return;
                        setSocketTimeout(stream.handle, .recv, 15);
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
            forwardResponseFromEntry(ssl, &entry, is_external, config.domain, must_close);

            if (must_close) return;
            setSocketTimeout(stream.handle, .recv, 15);
            continue;
        }

        // Normal path: stream response to client as we read it
        // Forward response status line
        sslWriteAll(ssl, resp_buf[0 .. resp_first_line_end + 2]);

        // Forward response headers, dropping Connection (our decision is appended
        // below). For external routes, rewrite Set-Cookie Domain to proxy domain.
        http_wire.forwardHeaders(resp_headers_section, SslSink{ .ssl = ssl }, .{
            .skip = &.{"connection:"},
            .rewrite_set_cookie = is_external,
        }, config.domain);
        if (must_close) {
            sslWriteAll(ssl, "Connection: close\r\n");
        } else {
            sslWriteAll(ssl, "Connection: keep-alive\r\n");
        }
        sslWriteAll(ssl, "\r\n");

        var resp_body_captured: usize = 0;

        // Stream response body from upstream
        if (is_chunked) {
            // Chunked: forward raw bytes to client, decode chunks for capture
            const pr = http_wire.pumpChunked(initial_body, upstream, SslSink{ .ssl = ssl }, &entry.resp_body);
            resp_body_captured = pr.captured;
            if (pr.truncated) entry.resp_body_truncated = true;
        } else {
            // Stream raw bytes to client while decoding into the entry.
            const br = http_wire.streamBody(initial_body, upstream, SslSink{ .ssl = ssl }, resp_content_length, &entry.resp_body);
            resp_body_captured = br.captured;
            if (br.truncated) entry.resp_body_truncated = true;
        }
        entry.resp_body_len = @intCast(resp_body_captured);

        const elapsed = std.time.milliTimestamp() - start_time;
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
        setSocketTimeout(stream.handle, .recv, 15);
    }
}

/// Everything forwardRequest needs beyond the entry itself: routing target and the
/// client identity to stamp into X-Forwarded-* / X-Real-IP headers.
const RequestForward = struct {
    is_external: bool,
    upstream_host: []const u8,
    client_host: []const u8, // original Host header, preserved as X-Forwarded-Host
    client_ip: []const u8,
    domain: []const u8,
};

/// Emit a (possibly TUI-edited) request entry to `sink` (`write([]const u8) void`):
/// request line, forwarded request headers, the external Host rewrite, the proxy's
/// own X-* headers, a recomputed Content-Length, and the body. The caller must
/// reject a truncated request body before calling — the emitted Content-Length
/// assumes the captured body is complete.
fn forwardRequest(sink: anytype, e: *const requests.Entry, ctx: RequestForward) void {
    // Request line (entry data may have been edited)
    sink.write(e.getMethod());
    sink.write(" ");
    sink.write(e.getPath());
    sink.write(" HTTP/1.1\r\n");

    // Forwarded request headers. For external routes, drop Host here — it is
    // re-set to the upstream hostname just below.
    const headers = e.getReqHeaders();
    if (headers.len > 0) {
        const skip: []const []const u8 = if (ctx.is_external)
            &.{ "cache-control:", "content-length:", "host:" }
        else
            &.{ "cache-control:", "content-length:" };
        http_wire.forwardHeaders(headers, sink, .{ .skip = skip }, ctx.domain);
    }

    // For external routes, set Host to upstream and preserve original as X-Forwarded-Host
    if (ctx.is_external) {
        sink.write("Host: ");
        sink.write(ctx.upstream_host);
        sink.write("\r\n");
        if (ctx.client_host.len > 0) {
            sink.write("X-Forwarded-Host: ");
            sink.write(ctx.client_host);
            sink.write("\r\n");
        }
    }

    // Proxy headers
    sink.write("X-Real-IP: ");
    sink.write(ctx.client_ip);
    sink.write("\r\n");
    sink.write("X-Forwarded-Proto: https\r\n");
    sink.write("Cache-Control: no-cache\r\n");
    sink.write("Pragma: no-cache\r\n");

    // Recomputed Content-Length for the (possibly edited) body, then the body
    const body = e.getReqBody();
    var cl_buf: [64]u8 = undefined;
    const cl_hdr = std.fmt.bufPrint(&cl_buf, "Content-Length: {d}\r\n", .{body.len}) catch "";
    sink.write(cl_hdr);
    sink.write("\r\n");
    if (body.len > 0) sink.write(body);
}

/// Forward a buffered response from an entry to the client.
/// Used after response intercept (accept) to send the (possibly edited) response.
fn forwardResponseFromEntry(ssl: *ssl_c.SSL, e: *const requests.Entry, is_external: bool, domain: []const u8, must_close: bool) void {
    // Build and send status line
    var status_buf: [64]u8 = undefined;
    const status_line = std.fmt.bufPrint(&status_buf, "HTTP/1.1 {d} {s}\r\n", .{ e.status, http_wire.reasonPhrase(e.status) }) catch return;
    sslWriteAll(ssl, status_line);

    // Forward response headers. Connection, Content-Length, and Transfer-Encoding
    // are dropped — Content-Length is recomputed below and Connection appended.
    http_wire.forwardHeaders(e.getRespHeaders(), SslSink{ .ssl = ssl }, .{
        .skip = &.{ "connection:", "content-length:", "transfer-encoding:" },
        .rewrite_set_cookie = is_external,
    }, domain);

    // Set Content-Length to match actual body (may have been edited)
    const body = e.getRespBody();
    var cl_buf: [64]u8 = undefined;
    const cl_hdr = std.fmt.bufPrint(&cl_buf, "Content-Length: {d}\r\n", .{body.len}) catch "";
    sslWriteAll(ssl, cl_hdr);

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

/// Forwarding sink for `http_wire` over the client TLS connection — relays bytes
/// to the browser (chunked body, response headers). Write failures are swallowed,
/// matching `sslWriteAll`; the caller's next write detects the dead connection.
const SslSink = struct {
    ssl: *ssl_c.SSL,
    pub fn write(self: SslSink, bytes: []const u8) void {
        sslWriteAll(self.ssl, bytes);
    }
};

/// Forwarding sink for `http_wire.forwardHeaders` over the upstream connection.
/// Write failures are swallowed; the request line/body writes that follow the
/// header loop detect the dead connection and abort.
const UpstreamSink = struct {
    upstream: UpstreamConn,
    pub fn write(self: UpstreamSink, bytes: []const u8) void {
        self.upstream.writeAll(bytes) catch {};
    }
};

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
    const proxy_addr = std.net.Address.parseIp("127.0.0.1", 443) catch |e| {
        log.err("component=proxy op=replay_connect error={any}", .{e});
        return;
    };
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |e| {
        log.err("component=proxy op=replay_socket error={any}", .{e});
        return;
    };
    posix.connect(sock, &proxy_addr.any, proxy_addr.getOsSockLen()) catch |e| {
        log.err("component=proxy op=replay_connect error={any}", .{e});
        compat.closeSocket(sock);
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

    // Send request line
    sslWriteAll(ssl, source.getMethod());
    sslWriteAll(ssl, " ");
    sslWriteAll(ssl, source.getPath());
    sslWriteAll(ssl, " HTTP/1.1\r\n");

    // Send stored headers, replacing Content-Length and Connection
    const req_hdrs = source.getReqHeaders();
    const body = source.getReqBody();
    if (req_hdrs.len > 0) {
        var hdr_iter = std.mem.splitSequence(u8, req_hdrs, "\r\n");
        while (hdr_iter.next()) |header| {
            if (header.len == 0) continue;
            if (std.ascii.startsWithIgnoreCase(header, "content-length:")) continue;
            if (std.ascii.startsWithIgnoreCase(header, "connection:")) continue;
            sslWriteAll(ssl, header);
            sslWriteAll(ssl, "\r\n");
        }
    }
    var cl_buf: [64]u8 = undefined;
    const cl_hdr = std.fmt.bufPrint(&cl_buf, "Content-Length: {d}\r\n", .{body.len}) catch return;
    sslWriteAll(ssl, cl_hdr);
    sslWriteAll(ssl, "Connection: close\r\n");
    sslWriteAll(ssl, "\r\n");

    // Send stored body
    if (body.len > 0) {
        sslWriteAll(ssl, body);
    }

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

fn handleWebSocket(
    ssl: *ssl_c.SSL,
    raw_request: []const u8,
    config: *const ProxyConfig,
    upstream_port: u16,
    entry: *requests.Entry,
) void {
    log.info("component=proxy op=websocket_upgrade uri={s}", .{entry.getPath()});

    // Connect to upstream (use resolved route port, not default)
    const upstream_addr = std.net.Address.parseIp(config.target_host, upstream_port) catch |e| {
        log.err("component=proxy op=websocket_connect error={any}", .{e});
        return;
    };
    const upstream_sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |e| {
        log.err("component=proxy op=websocket_socket error={any}", .{e});
        return;
    };
    posix.connect(upstream_sock, &upstream_addr.any, upstream_addr.getOsSockLen()) catch |e| {
        log.err("component=proxy op=websocket_connect error={any}", .{e});
        compat.closeSocket(upstream_sock);
        sslSendError(ssl, 502, "Bad Gateway");
        return;
    };
    const upstream = compat.SocketStream{ .handle = upstream_sock };
    defer upstream.close();

    // Forward the original request as-is to upstream
    upstream.writeAll(raw_request) catch return;

    // Read upstream response (expect 101 Switching Protocols)
    var resp_buf: [4096]u8 = undefined;
    var resp_total: usize = 0;
    while (resp_total < resp_buf.len) {
        const n = upstream.read(resp_buf[resp_total..]) catch break;
        if (n == 0) break;
        resp_total += n;
        if (std.mem.indexOf(u8, resp_buf[0..resp_total], "\r\n\r\n") != null) break;
    }
    if (resp_total == 0) return;

    // Forward response to client
    sslWriteAll(ssl, resp_buf[0..resp_total]);

    // Log as a WS entry (pinned so it won't be overwritten during long-lived connection)
    entry.status = 101;
    const elapsed = std.time.milliTimestamp() - entry.timestamp;
    entry.duration_ms = if (elapsed > 0) @intCast(elapsed) else 0;
    // Store response headers
    if (std.mem.indexOf(u8, resp_buf[0..resp_total], "\r\n")) |first_end| {
        if (std.mem.indexOf(u8, resp_buf[0..resp_total], "\r\n\r\n")) |hdr_end| {
            const resp_hdrs = resp_buf[first_end + 2 .. hdr_end];
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

    // Bidirectional pipe: SSL client <-> upstream socket
    // Use poll to wait for data on either side
    const raw_fd = ssl_c.SSL_get_fd(ssl);
    if (raw_fd < 0) return;
    const client_fd = compat.fdToSocket(raw_fd);

    var pipe_buf: [8192]u8 = undefined;
    while (true) {
        var fds = [2]posix.pollfd{
            .{ .fd = client_fd, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = upstream_sock, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = posix.poll(&fds, 30000) catch break; // 30s timeout
        if (ready == 0) break; // timeout

        // Client -> upstream
        if (fds[0].revents & posix.POLL.IN != 0) {
            const n = ssl_c.SSL_read(ssl, @ptrCast(&pipe_buf), @intCast(pipe_buf.len));
            if (n <= 0) break;
            upstream.writeAll(pipe_buf[0..@intCast(n)]) catch break;
        }
        if (fds[0].revents & (posix.POLL.HUP | posix.POLL.ERR) != 0) break;

        // Upstream -> client
        if (fds[1].revents & posix.POLL.IN != 0) {
            const n = upstream.read(&pipe_buf) catch break;
            if (n == 0) break;
            sslWriteAll(ssl, pipe_buf[0..n]);
        }
        if (fds[1].revents & (posix.POLL.HUP | posix.POLL.ERR) != 0) break;
    }
    requests.unpin(ws_backing_idx);
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
        _ = std.os.windows.ws2_32.setsockopt(fd, std.os.windows.ws2_32.SOL.SOCKET, opt, @ptrCast(&bytes), @sizeOf(@TypeOf(ms)));
    } else {
        const opt: u32 = switch (which) {
            .recv => ssl_c.SO_RCVTIMEO,
            .send => ssl_c.SO_SNDTIMEO,
        };
        const tv = ssl_c.struct_timeval{ .tv_sec = @intCast(seconds), .tv_usec = 0 };
        _ = ssl_c.setsockopt(fd, ssl_c.SOL_SOCKET, @intCast(opt), &tv, @sizeOf(@TypeOf(tv)));
    }
}

fn formatAddress(addr: std.net.Address, buf: []u8) []const u8 {
    // Format IP only, without port
    return switch (addr.any.family) {
        posix.AF.INET => blk: {
            const bytes: [4]u8 = @bitCast(addr.in.sa.addr);
            break :blk std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
                bytes[0], bytes[1], bytes[2], bytes[3],
            }) catch "0.0.0.0";
        },
        else => std.fmt.bufPrint(buf, "{any}", .{addr}) catch "0.0.0.0",
    };
}

// --- Unit Tests ---

const testing = std.testing;

test "formatAddress IPv4" {
    const addr = std.net.Address.parseIp4("192.168.1.42", 8080) catch unreachable;
    var buf: [64]u8 = undefined;
    const result = formatAddress(addr, &buf);
    try testing.expectEqualStrings("192.168.1.42", result);
}

test "formatAddress loopback" {
    const addr = std.net.Address.parseIp4("127.0.0.1", 443) catch unreachable;
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
            "X-Real-IP: 10.0.0.1\r\nX-Forwarded-Proto: https\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n" ++
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
            "Host: staging.example.com\r\nX-Forwarded-Host: dev.lo\r\n" ++
            "X-Real-IP: 10.0.0.1\r\nX-Forwarded-Proto: https\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n" ++
            "Content-Length: 2\r\n\r\nhi",
        out[0..len],
    );
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
