const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const log = @import("log.zig");
const requests = @import("requests.zig");
const intercept = @import("intercept.zig");
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

    fn read(self: UpstreamConn, buf: []u8) !usize {
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
        const client_conn = getConnectionHeader(req_hdr_section);
        const keep_alive = if (client_conn == .close) false else if (client_conn == .keep_alive) true else is_http11;

        // Extract Host header for route resolution
        var host = getHeaderValue(req_hdr_section, "host:") orelse "";
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
        host = getHeaderValue(entry.req_headers[0..rh_len], "host:") orelse "";

        // Check for WebSocket upgrade
        if (isWebSocketUpgrade(req_hdr_section)) {
            handleWebSocket(ssl, req_buf[0..total], config, upstream_port, &entry);
            return;
        }

        // Get Content-Length for body
        const content_length = getContentLength(req_buf[0 .. hdr_end + 4]) orelse 0;

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
            const maybe_idx = requests.pushAndPin(entry);
            if (maybe_idx == null) {
                // All slots pinned — skip intercept, continue normally
                entry.state = .normal;
            } else {
                intercept_backing_idx = maybe_idx.?;
                was_intercepted = true;

                const slot = intercept.acquire();
                if (slot == null) {
                    // All intercept slots full — unpin and continue normally
                    requests.unpin(intercept_backing_idx);
                    requests.getByBackingIndex(intercept_backing_idx).state = .normal;
                    was_intercepted = false;
                } else {
                    const s = slot.?;
                    s.backing_index = intercept_backing_idx;
                    s.event.wait();
                    const decision = intercept.getDecision(s);
                    s.event.reset();
                    intercept.release(s);

                    if (decision == .drop) {
                        const drop_elapsed = std.time.milliTimestamp() - start_time;
                        {
                            requests.lock();
                            defer requests.unlock();
                            const drop_entry = requests.getByBackingIndex(intercept_backing_idx);
                            drop_entry.state = .dropped;
                            drop_entry.duration_ms = if (drop_elapsed > 0) @intCast(drop_elapsed) else 0;
                        }
                        requests.unpin(intercept_backing_idx);
                        sslSendError(ssl, 502, "Dropped by intercept");
                        return;
                    }

                    // Accept — update state and continue to upstream
                    {
                        requests.lock();
                        defer requests.unlock();
                        requests.getByBackingIndex(intercept_backing_idx).state = .accepted;
                    }
                }
            }
        }

        // Ensure intercepted entries are unpinned on any early exit after this point.
        // Normal completion paths call finishEntry/finishResponseIntercept explicitly,
        // which set status/duration before unpinning — so this defer only fires for
        // error exits where the entry would otherwise be pinned forever.
        defer if (was_intercepted) {
            const e = requests.getByBackingIndex(intercept_backing_idx);
            if (e.pinned and !e.starred and e.state == .accepted) {
                const dur = std.time.milliTimestamp() - start_time;
                requests.finishEntry(intercept_backing_idx, 502, if (dur > 0) @intCast(dur) else 0, "", "");
            }
        };

        // Connect to upstream (per-request — dev servers may not support keep-alive)
        const is_external = route_result.hostname != null;
        const upstream_host = route_result.hostname orelse config.target_host;

        // Resolve upstream address — DNS for external, IP parse for local
        var addr_list: ?*std.net.AddressList = null;
        defer if (addr_list) |al| al.deinit();

        const upstream_addr: std.net.Address = blk: {
            if (is_external) {
                const al = std.net.getAddressList(std.heap.page_allocator, upstream_host, upstream_port) catch {
                    log.err("component=proxy conn={d} op=dns_resolve host={s} error=failed", .{ conn_id, upstream_host });
                    if (was_intercepted) {
                        requests.finishEntry(intercept_backing_idx, 502, 0, "", "");
                    }
                    sslSendError(ssl, 502, "Bad Gateway");
                    return;
                };
                addr_list = al;
                if (al.addrs.len == 0) {
                    log.err("component=proxy conn={d} op=dns_resolve host={s} error=no_addresses", .{ conn_id, upstream_host });
                    if (was_intercepted) {
                        requests.finishEntry(intercept_backing_idx, 502, 0, "", "");
                    }
                    sslSendError(ssl, 502, "Bad Gateway");
                    return;
                }
                break :blk al.addrs[0];
            } else {
                break :blk std.net.Address.parseIp(config.target_host, upstream_port) catch {
                    if (was_intercepted) {
                        requests.finishEntry(intercept_backing_idx, 502, 0, "", "");
                    }
                    sslSendError(ssl, 502, "Bad Gateway");
                    return;
                };
            }
        };
        const upstream_sock = posix.socket(upstream_addr.any.family, posix.SOCK.STREAM, 0) catch |e| {
            log.err("component=proxy conn={d} op=upstream_socket error={any}", .{ conn_id, e });
            if (was_intercepted) {
                const dur = std.time.milliTimestamp() - start_time;
                requests.finishEntry(intercept_backing_idx, 502, if (dur > 0) @intCast(dur) else 0, "", "");
            }
            sslSendError(ssl, 502, "Bad Gateway");
            return;
        };
        posix.connect(upstream_sock, &upstream_addr.any, upstream_addr.getOsSockLen()) catch |e| {
            log.err("component=proxy conn={d} op=upstream_connect host={s} error={any}", .{ conn_id, upstream_host, e });
            compat.closeSocket(upstream_sock);
            if (was_intercepted) {
                const dur = std.time.milliTimestamp() - start_time;
                requests.finishEntry(intercept_backing_idx, 502, if (dur > 0) @intCast(dur) else 0, "", "");
            }
            sslSendError(ssl, 502, "Bad Gateway");
            return;
        };

        // Wrap in UpstreamConn — TLS for external, plain socket for local
        var upstream_ssl_obj: ?*ssl_c.SSL = null;
        if (is_external) {
            if (client_ctx) |cctx| {
                const us = ssl_c.SSL_new(cctx) orelse {
                    log.err("component=proxy conn={d} op=upstream_ssl_new error=alloc_failed", .{conn_id});
                    compat.closeSocket(upstream_sock);
                    if (was_intercepted) {
                        requests.finishEntry(intercept_backing_idx, 502, 0, "", "");
                    }
                    sslSendError(ssl, 502, "Bad Gateway");
                    return;
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
                    if (was_intercepted) {
                        requests.finishEntry(intercept_backing_idx, 502, 0, "", "");
                    }
                    sslSendError(ssl, 502, "Bad Gateway");
                    return;
                }
                upstream_ssl_obj = us;
            }
        }
        const upstream = UpstreamConn{ .sock = .{ .handle = upstream_sock }, .ssl_conn = upstream_ssl_obj };
        defer upstream.close();

        // Set timeouts on upstream socket
        setSocketTimeout(upstream_sock, .recv, 30);
        setSocketTimeout(upstream_sock, .send, 30);

        // If intercepted and edited, re-read the (possibly modified) entry data
        // Safe: TUI edits intercepted entries only while waiting on intercept.acquire().
        // By the time the intercept event fires (s.event.wait() returned), the TUI is done editing.
        const fwd_entry = if (was_intercepted) requests.getByBackingIndex(intercept_backing_idx) else &entry;

        // Forward request line (use entry data which may have been edited)
        upstream.writeAll(fwd_entry.getMethod()) catch return;
        upstream.writeAll(" ") catch return;
        upstream.writeAll(fwd_entry.getPath()) catch return;
        upstream.writeAll(" HTTP/1.1\r\n") catch return;

        // Forward headers from entry (may have been edited)
        const fwd_headers = fwd_entry.getReqHeaders();
        if (fwd_headers.len > 0) {
            var header_iter = std.mem.splitSequence(u8, fwd_headers, "\r\n");
            while (header_iter.next()) |header| {
                if (header.len == 0) continue;
                if (startsWithIgnoreCase(header, "cache-control:")) continue;
                if (startsWithIgnoreCase(header, "content-length:")) continue;
                // For external routes, replace Host header with upstream hostname
                if (is_external and startsWithIgnoreCase(header, "host:")) continue;
                upstream.writeAll(header) catch return;
                upstream.writeAll("\r\n") catch return;
            }
        }

        // For external routes, set Host to upstream and preserve original as X-Forwarded-Host
        if (is_external) {
            upstream.writeAll("Host: ") catch return;
            upstream.writeAll(upstream_host) catch return;
            upstream.writeAll("\r\n") catch return;
            if (host.len > 0) {
                upstream.writeAll("X-Forwarded-Host: ") catch return;
                upstream.writeAll(host) catch return;
                upstream.writeAll("\r\n") catch return;
            }
        }

        // Add proxy headers
        var ip_buf: [64]u8 = undefined;
        const client_ip = formatAddress(client_addr, &ip_buf);
        upstream.writeAll("X-Real-IP: ") catch return;
        upstream.writeAll(client_ip) catch return;
        upstream.writeAll("\r\n") catch return;
        upstream.writeAll("X-Forwarded-Proto: https\r\n") catch return;
        upstream.writeAll("Cache-Control: no-cache\r\n") catch return;
        upstream.writeAll("Pragma: no-cache\r\n") catch return;

        // Add correct Content-Length for the (possibly edited) body
        const fwd_body = fwd_entry.getReqBody();

        // If body was truncated, we can't forward it correctly — reject
        if (fwd_entry.req_body_truncated) {
            sslSendError(ssl, 413, "Request body too large for proxy buffer");
            return;
        }

        {
            var cl_buf: [64]u8 = undefined;
            const cl_hdr = std.fmt.bufPrint(&cl_buf, "Content-Length: {d}\r\n", .{fwd_body.len}) catch "";
            upstream.writeAll(cl_hdr) catch return;
        }
        upstream.writeAll("\r\n") catch return;

        // Forward request body from entry
        if (fwd_body.len > 0) {
            upstream.writeAll(fwd_body) catch return;
        }

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
        const is_chunked = isChunkedEncoding(resp_headers_section);
        const resp_content_length = getContentLength(resp_buf[0 .. resp_hdr_end + 4]);
        const upstream_conn = getConnectionHeader(resp_headers_section);
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
                resp_body_captured = bufferChunkedBody(upstream, initial_body, &entry.resp_body, &resp_buf);
                if (resp_body_captured >= requests.max_body_len) {
                    entry.resp_body_truncated = true;
                }
            } else {
                if (initial_body.len > 0) {
                    const cap = @min(initial_body.len, requests.max_body_len);
                    @memcpy(entry.resp_body[0..cap], initial_body[0..cap]);
                    resp_body_captured = cap;
                }
                if (resp_content_length) |cl| {
                    var body_read: usize = initial_body.len;
                    while (body_read < cl) {
                        const n = upstream.read(&resp_buf) catch break;
                        if (n == 0) break;
                        const space = requests.max_body_len -| resp_body_captured;
                        const cap = @min(n, space);
                        if (cap > 0) {
                            @memcpy(entry.resp_body[resp_body_captured .. resp_body_captured + cap], resp_buf[0..cap]);
                            resp_body_captured += cap;
                        }
                        body_read += n;
                    }
                    if (cl > requests.max_body_len) {
                        entry.resp_body_truncated = true;
                    }
                } else {
                    while (true) {
                        const n = upstream.read(&resp_buf) catch break;
                        if (n == 0) break;
                        const space = requests.max_body_len -| resp_body_captured;
                        const cap = @min(n, space);
                        if (cap > 0) {
                            @memcpy(entry.resp_body[resp_body_captured .. resp_body_captured + cap], resp_buf[0..cap]);
                            resp_body_captured += cap;
                        }
                    }
                    if (resp_body_captured >= requests.max_body_len) {
                        entry.resp_body_truncated = true;
                    }
                }
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
            var resp_intercept_idx: usize = 0;
            const maybe_resp_idx = requests.pushAndPin(entry);
            if (maybe_resp_idx == null) {
                // All slots pinned — skip intercept, forward normally
                entry.state = .normal;
                entry.resp_intercepted = false;
            } else {
                resp_intercept_idx = maybe_resp_idx.?;
                const slot = intercept.acquire();
                if (slot == null) {
                    // All intercept slots full — unpin and forward normally
                    requests.unpin(resp_intercept_idx);
                    requests.getByBackingIndex(resp_intercept_idx).state = .normal;
                    requests.getByBackingIndex(resp_intercept_idx).resp_intercepted = false;
                } else {
                    const s = slot.?;
                    s.backing_index = resp_intercept_idx;
                    s.event.wait();
                    const decision = intercept.getDecision(s);
                    s.event.reset();
                    intercept.release(s);

                    if (decision == .drop) {
                        const drop_entry = requests.getByBackingIndex(resp_intercept_idx);
                        drop_entry.state = .dropped;
                        const drop_elapsed = std.time.milliTimestamp() - resp_received_time;
                        drop_entry.duration_ms = if (drop_elapsed > 0) @intCast(drop_elapsed) else 0;
                        requests.unpin(resp_intercept_idx);
                        sslSendError(ssl, 502, "Dropped by intercept");
                        return;
                    }

                    // Accept — read back the (possibly edited) entry for forwarding
                    const resp_entry = requests.getByBackingIndex(resp_intercept_idx);
                    resp_entry.state = .accepted;

                    // Forward the (possibly edited) response to client
                    forwardResponseFromEntry(ssl, resp_entry, is_external, config.domain, must_close);

                    // Duration = hold time only
                    const hold_elapsed = std.time.milliTimestamp() - resp_received_time;
                    const hold_dur: u64 = if (hold_elapsed > 0) @intCast(hold_elapsed) else 0;
                    requests.finishResponseIntercept(resp_intercept_idx, hold_dur);

                    if (must_close) return;
                    setSocketTimeout(stream.handle, .recv, 15);
                    continue;
                }
            }

            // Fell through: intercept skipped, forward buffered response normally
            // Request entry was already pushed/finished above
            forwardResponseFromEntry(ssl, &entry, is_external, config.domain, must_close);

            if (maybe_resp_idx != null) {
                // Response entry was pushed but intercept was skipped — clean up
                {
                    requests.lock();
                    defer requests.unlock();
                    const e = requests.getByBackingIndex(resp_intercept_idx);
                    e.state = .normal;
                    e.resp_intercepted = false;
                    e.duration_ms = req_dur;
                }
                requests.unpin(resp_intercept_idx);
            }

            if (must_close) return;
            setSocketTimeout(stream.handle, .recv, 15);
            continue;
        }

        // Normal path: stream response to client as we read it
        // Forward response status line
        sslWriteAll(ssl, resp_buf[0 .. resp_first_line_end + 2]);

        // Forward response headers, replacing Connection header with our decision
        // For external routes, rewrite Set-Cookie Domain to proxy domain
        var resp_header_iter = std.mem.splitSequence(u8, resp_headers_section, "\r\n");
        while (resp_header_iter.next()) |header| {
            if (header.len == 0) continue;
            if (startsWithIgnoreCase(header, "connection:")) continue;
            if (is_external and startsWithIgnoreCase(header, "set-cookie:")) {
                rewriteCookieDomain(ssl, header, config.domain);
                sslWriteAll(ssl, "\r\n");
                continue;
            }
            sslWriteAll(ssl, header);
            sslWriteAll(ssl, "\r\n");
        }
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
            resp_body_captured = forwardChunkedBody(ssl, upstream, initial_body, &entry.resp_body, &resp_buf);
            if (resp_body_captured >= requests.max_body_len) {
                entry.resp_body_truncated = true;
            }
        } else {
            // Forward initial body bytes
            if (initial_body.len > 0) {
                sslWriteAll(ssl, initial_body);
                const cap = @min(initial_body.len, requests.max_body_len);
                @memcpy(entry.resp_body[0..cap], initial_body[0..cap]);
                resp_body_captured = cap;
            }

            if (resp_content_length) |cl| {
                var body_sent: usize = initial_body.len;
                while (body_sent < cl) {
                    const n = upstream.read(&resp_buf) catch break;
                    if (n == 0) break;
                    sslWriteAll(ssl, resp_buf[0..n]);
                    const space = requests.max_body_len -| resp_body_captured;
                    const cap = @min(n, space);
                    if (cap > 0) {
                        @memcpy(entry.resp_body[resp_body_captured .. resp_body_captured + cap], resp_buf[0..cap]);
                        resp_body_captured += cap;
                    }
                    body_sent += n;
                }
                if (cl > requests.max_body_len) {
                    entry.resp_body_truncated = true;
                }
            } else {
                // No content-length: read until upstream closes
                while (true) {
                    const n = upstream.read(&resp_buf) catch break;
                    if (n == 0) break;
                    sslWriteAll(ssl, resp_buf[0..n]);
                    const space = requests.max_body_len -| resp_body_captured;
                    const cap = @min(n, space);
                    if (cap > 0) {
                        @memcpy(entry.resp_body[resp_body_captured .. resp_body_captured + cap], resp_buf[0..cap]);
                        resp_body_captured += cap;
                    }
                }
                if (resp_body_captured >= requests.max_body_len) {
                    entry.resp_body_truncated = true;
                }
            }
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

/// Forward a buffered response from an entry to the client.
/// Used after response intercept (accept) to send the (possibly edited) response.
fn forwardResponseFromEntry(ssl: *ssl_c.SSL, e: *const requests.Entry, is_external: bool, domain: []const u8, must_close: bool) void {
    // Build and send status line
    var status_buf: [64]u8 = undefined;
    const status_line = std.fmt.bufPrint(&status_buf, "HTTP/1.1 {d} {s}\r\n", .{ e.status, reasonPhrase(e.status) }) catch return;
    sslWriteAll(ssl, status_line);

    // Forward response headers
    const resp_hdrs = e.getRespHeaders();
    if (resp_hdrs.len > 0) {
        var header_iter = std.mem.splitSequence(u8, resp_hdrs, "\r\n");
        while (header_iter.next()) |header| {
            if (header.len == 0) continue;
            if (startsWithIgnoreCase(header, "connection:")) continue;
            if (startsWithIgnoreCase(header, "content-length:")) continue;
            if (startsWithIgnoreCase(header, "transfer-encoding:")) continue;
            if (is_external and startsWithIgnoreCase(header, "set-cookie:")) {
                rewriteCookieDomain(ssl, header, domain);
                sslWriteAll(ssl, "\r\n");
                continue;
            }
            sslWriteAll(ssl, header);
            sslWriteAll(ssl, "\r\n");
        }
    }

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

/// Buffer chunked response body from upstream into entry without forwarding to client.
/// Returns total bytes captured into the body buffer.
fn bufferChunkedBody(upstream: UpstreamConn, initial: []const u8, body: *[requests.max_body_len]u8, read_buf: *[16384]u8) usize {
    var captured: usize = 0;
    var state: ChunkState = .size;
    var chunk_remaining: usize = 0;
    var size_val: usize = 0;

    if (initial.len > 0) {
        for (initial) |byte| {
            chunkedStep(byte, &state, &chunk_remaining, &size_val, body, &captured);
            if (state == .done or state == .parse_error) return captured;
        }
    }

    while (state != .done and state != .parse_error) {
        const n = upstream.read(read_buf) catch break;
        if (n == 0) break;
        for (read_buf.*[0..n]) |byte| {
            chunkedStep(byte, &state, &chunk_remaining, &size_val, body, &captured);
            if (state == .done or state == .parse_error) return captured;
        }
    }

    return captured;
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
            if (startsWithIgnoreCase(header, "content-length:")) continue;
            if (startsWithIgnoreCase(header, "connection:")) continue;
            sslWriteAll(ssl, header);
            sslWriteAll(ssl, "\r\n");
        }
    }
    if (body.len > 0) {
        var cl_buf: [64]u8 = undefined;
        const cl_hdr = std.fmt.bufPrint(&cl_buf, "Content-Length: {d}\r\n", .{body.len}) catch return;
        sslWriteAll(ssl, cl_hdr);
    }
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

fn reasonPhrase(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        else => "OK",
    };
}

fn sslSendError(ssl: *ssl_c.SSL, status: u16, message: []const u8) void {
    var buf: [512]u8 = undefined;
    const response = std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        status, message, message.len, message,
    }) catch return;
    sslWriteAll(ssl, response);
}

/// Rewrite Domain= attribute in a Set-Cookie header to the proxy domain.
/// Writes the full header (without trailing \r\n) to the SSL connection.
fn rewriteCookieDomain(ssl: *ssl_c.SSL, header: []const u8, domain: []const u8) void {
    // Find "Domain=" (case-insensitive) in the cookie attributes (after first ;)
    // Skip the cookie value to avoid matching "domain=" inside it
    const attr_start = if (std.mem.indexOfScalar(u8, header, ';')) |pos| pos else header.len;
    var i: usize = attr_start;
    while (i + 7 <= header.len) : (i += 1) {
        if (startsWithIgnoreCase(header[i..], "domain=")) {
            // Found Domain= at position i
            // Write everything before "Domain="
            sslWriteAll(ssl, header[0..i]);
            // Write "Domain=.<proxy_domain>"
            sslWriteAll(ssl, "Domain=.");
            sslWriteAll(ssl, domain);
            // Skip past the original domain value (until ; or end of header)
            var j = i + 7;
            if (j < header.len and header[j] == '.') j += 1; // skip leading dot
            while (j < header.len and header[j] != ';') : (j += 1) {}
            // Write the rest of the header
            sslWriteAll(ssl, header[j..]);
            return;
        }
    }
    // No Domain= found, forward as-is
    sslWriteAll(ssl, header);
}

const ConnectionHeader = enum { keep_alive, close, none };

fn getHeaderValue(headers: []const u8, comptime name: []const u8) ?[]const u8 {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |line| {
        if (startsWithIgnoreCase(line, name)) {
            return std.mem.trim(u8, line[name.len..], " \t");
        }
    }
    return null;
}

fn getConnectionHeader(headers: []const u8) ConnectionHeader {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |line| {
        if (startsWithIgnoreCase(line, "connection:")) {
            const value = std.mem.trim(u8, line["connection:".len..], " \t");
            if (startsWithIgnoreCase(value, "close")) return .close;
            if (startsWithIgnoreCase(value, "keep-alive")) return .keep_alive;
        }
    }
    return .none;
}

fn getContentLength(headers: []const u8) ?usize {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |line| {
        if (startsWithIgnoreCase(line, "content-length:")) {
            const value = std.mem.trim(u8, line["content-length:".len..], " \t");
            return std.fmt.parseInt(usize, value, 10) catch null;
        }
    }
    return null;
}

fn startsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    for (haystack[0..needle.len], needle) |h, n| {
        if (std.ascii.toLower(h) != std.ascii.toLower(n)) return false;
    }
    return true;
}

fn isChunkedEncoding(headers: []const u8) bool {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |header| {
        if (startsWithIgnoreCase(header, "transfer-encoding:")) {
            const value = std.mem.trimLeft(u8, header["transfer-encoding:".len..], " ");
            var token_iter = std.mem.splitScalar(u8, value, ',');
            while (token_iter.next()) |token| {
                const trimmed = std.mem.trim(u8, token, " ");
                if (trimmed.len == 7 and startsWithIgnoreCase(trimmed, "chunked")) return true;
            }
        }
    }
    return false;
}

const ChunkState = enum { size, size_ext, size_cr, data, data_cr, data_lf, trailer_start, trailer_line, trailer_line_cr, trailer_end_cr, done, parse_error };

fn forwardChunkedBody(
    ssl: *ssl_c.SSL,
    upstream: UpstreamConn,
    initial: []const u8,
    resp_body: *[requests.max_body_len]u8,
    read_buf: *[16384]u8,
) usize {
    var captured: usize = 0;
    var state: ChunkState = .size;
    var chunk_remaining: usize = 0;
    var size_val: usize = 0;

    if (initial.len > 0) {
        sslWriteAll(ssl, initial);
        for (initial) |byte| {
            chunkedStep(byte, &state, &chunk_remaining, &size_val, resp_body, &captured);
            if (state == .done or state == .parse_error) return captured;
        }
    }

    while (state != .done and state != .parse_error) {
        const n = upstream.read(read_buf) catch break;
        if (n == 0) break;
        sslWriteAll(ssl, read_buf.*[0..n]);
        for (read_buf.*[0..n]) |byte| {
            chunkedStep(byte, &state, &chunk_remaining, &size_val, resp_body, &captured);
            if (state == .done or state == .parse_error) return captured;
        }
    }

    return captured;
}

fn chunkedStep(
    byte: u8,
    state: *ChunkState,
    chunk_remaining: *usize,
    size_val: *usize,
    resp_body: *[requests.max_body_len]u8,
    captured: *usize,
) void {
    switch (state.*) {
        .size => {
            if (byte == '\r') {
                state.* = .size_cr;
            } else if (byte == ';') {
                state.* = .size_ext;
            } else {
                const digit = std.fmt.charToDigit(byte, 16) catch {
                    state.* = .parse_error;
                    return;
                };
                // Guard against maliciously long hex strings overflowing usize
                if (size_val.* > std.math.maxInt(usize) / 16) {
                    state.* = .parse_error;
                    return;
                }
                size_val.* = size_val.* * 16 + digit;
            }
        },
        .size_ext => {
            if (byte == '\r') state.* = .size_cr;
        },
        .size_cr => {
            chunk_remaining.* = size_val.*;
            size_val.* = 0;
            if (chunk_remaining.* == 0) {
                state.* = .trailer_start;
            } else {
                state.* = .data;
            }
        },
        .data => {
            if (captured.* < resp_body.len) {
                resp_body[captured.*] = byte;
                captured.* += 1;
            }
            chunk_remaining.* -= 1;
            if (chunk_remaining.* == 0) {
                state.* = .data_cr;
            }
        },
        .data_cr => {
            state.* = .data_lf;
        },
        .data_lf => {
            state.* = .size;
        },
        .trailer_start => {
            if (byte == '\r') {
                state.* = .trailer_end_cr;
            } else {
                state.* = .trailer_line;
            }
        },
        .trailer_line => {
            if (byte == '\r') state.* = .trailer_line_cr;
        },
        .trailer_line_cr => {
            state.* = .trailer_start;
        },
        .trailer_end_cr => {
            state.* = .done;
        },
        .done => {},
        .parse_error => {},
    }
}

fn isWebSocketUpgrade(headers: []const u8) bool {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |header| {
        if (startsWithIgnoreCase(header, "upgrade:")) {
            const value = std.mem.trimLeft(u8, header["upgrade:".len..], " ");
            if (startsWithIgnoreCase(value, "websocket")) return true;
        }
    }
    return false;
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

test "startsWithIgnoreCase exact match" {
    try testing.expect(startsWithIgnoreCase("Content-Type:", "content-type:"));
    try testing.expect(startsWithIgnoreCase("content-type:", "content-type:"));
    try testing.expect(startsWithIgnoreCase("CONTENT-TYPE:", "content-type:"));
}

test "startsWithIgnoreCase prefix match" {
    try testing.expect(startsWithIgnoreCase("Content-Type: text/html", "content-type:"));
    try testing.expect(startsWithIgnoreCase("Host: dev.lo", "host:"));
}

test "startsWithIgnoreCase no match" {
    try testing.expect(!startsWithIgnoreCase("Accept: */*", "content-type:"));
    try testing.expect(!startsWithIgnoreCase("X-Real-IP: 1.2.3.4", "content-length:"));
}

test "startsWithIgnoreCase haystack shorter than needle" {
    try testing.expect(!startsWithIgnoreCase("Hi", "content-type:"));
    try testing.expect(!startsWithIgnoreCase("", "a"));
}

test "startsWithIgnoreCase empty needle" {
    try testing.expect(startsWithIgnoreCase("anything", ""));
    try testing.expect(startsWithIgnoreCase("", ""));
}

test "getContentLength present" {
    try testing.expectEqual(@as(?usize, 42), getContentLength("Content-Length: 42\r\nHost: dev.lo\r\n"));
    try testing.expectEqual(@as(?usize, 0), getContentLength("Content-Length: 0\r\n"));
    try testing.expectEqual(@as(?usize, 12345), getContentLength("Host: dev.lo\r\nContent-Length: 12345\r\n"));
}

test "getContentLength case insensitive" {
    try testing.expectEqual(@as(?usize, 100), getContentLength("content-length: 100\r\n"));
    try testing.expectEqual(@as(?usize, 200), getContentLength("CONTENT-LENGTH: 200\r\n"));
}

test "getContentLength missing" {
    try testing.expect(getContentLength("Host: dev.lo\r\nAccept: */*\r\n") == null);
    try testing.expect(getContentLength("") == null);
}

test "getContentLength invalid value" {
    try testing.expect(getContentLength("Content-Length: abc\r\n") == null);
    try testing.expect(getContentLength("Content-Length: \r\n") == null);
}

test "isWebSocketUpgrade true" {
    try testing.expect(isWebSocketUpgrade("Upgrade: websocket\r\nConnection: Upgrade\r\n"));
    try testing.expect(isWebSocketUpgrade("Host: dev.lo\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n"));
    try testing.expect(isWebSocketUpgrade("upgrade: websocket\r\n"));
    try testing.expect(isWebSocketUpgrade("UPGRADE: WEBSOCKET\r\n"));
}

test "isWebSocketUpgrade false" {
    try testing.expect(!isWebSocketUpgrade("Host: dev.lo\r\nAccept: */*\r\n"));
    try testing.expect(!isWebSocketUpgrade("Upgrade: h2c\r\n"));
    try testing.expect(!isWebSocketUpgrade(""));
}

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

test "getConnectionHeader close" {
    try testing.expectEqual(ConnectionHeader.close, getConnectionHeader("Connection: close\r\nHost: dev.lo\r\n"));
    try testing.expectEqual(ConnectionHeader.close, getConnectionHeader("Host: dev.lo\r\nConnection: close\r\n"));
    try testing.expectEqual(ConnectionHeader.close, getConnectionHeader("connection: close\r\n"));
    try testing.expectEqual(ConnectionHeader.close, getConnectionHeader("CONNECTION: CLOSE\r\n"));
}

test "getConnectionHeader keep-alive" {
    try testing.expectEqual(ConnectionHeader.keep_alive, getConnectionHeader("Connection: keep-alive\r\n"));
    try testing.expectEqual(ConnectionHeader.keep_alive, getConnectionHeader("connection: Keep-Alive\r\n"));
}

test "getConnectionHeader none" {
    try testing.expectEqual(ConnectionHeader.none, getConnectionHeader("Host: dev.lo\r\nAccept: */*\r\n"));
    try testing.expectEqual(ConnectionHeader.none, getConnectionHeader(""));
}

test "getConnectionHeader upgrade ignored" {
    // "Upgrade" doesn't match "close" or "keep-alive", so returns .none-like behavior
    // but the header IS present — it just has an unrecognized value
    try testing.expectEqual(ConnectionHeader.none, getConnectionHeader("Connection: Upgrade\r\n"));
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

test "reasonPhrase common codes" {
    try testing.expectEqualStrings("OK", reasonPhrase(200));
    try testing.expectEqualStrings("Not Found", reasonPhrase(404));
    try testing.expectEqualStrings("Internal Server Error", reasonPhrase(500));
    try testing.expectEqualStrings("Bad Gateway", reasonPhrase(502));
    try testing.expectEqualStrings("Unauthorized", reasonPhrase(401));
    try testing.expectEqualStrings("Moved Permanently", reasonPhrase(301));
}

test "reasonPhrase unknown code falls back to OK" {
    try testing.expectEqualStrings("OK", reasonPhrase(999));
    try testing.expectEqualStrings("OK", reasonPhrase(0));
}

test "isChunkedEncoding true" {
    try testing.expect(isChunkedEncoding("Transfer-Encoding: chunked\r\n"));
    try testing.expect(isChunkedEncoding("transfer-encoding: chunked\r\n"));
    try testing.expect(isChunkedEncoding("Host: dev.lo\r\nTransfer-Encoding: chunked\r\n"));
}

test "isChunkedEncoding false" {
    try testing.expect(!isChunkedEncoding("Content-Length: 42\r\n"));
    try testing.expect(!isChunkedEncoding("Transfer-Encoding: gzip\r\n"));
    try testing.expect(!isChunkedEncoding(""));
}

test "getHeaderValue found" {
    try testing.expectEqualStrings("dev.lo", getHeaderValue("Host: dev.lo\r\nAccept: */*\r\n", "host:").?);
    try testing.expectEqualStrings("*/*", getHeaderValue("Host: dev.lo\r\nAccept: */*\r\n", "accept:").?);
}

test "getHeaderValue not found" {
    try testing.expect(getHeaderValue("Host: dev.lo\r\n", "content-type:") == null);
    try testing.expect(getHeaderValue("", "host:") == null);
}

test "getHeaderValue trims whitespace" {
    try testing.expectEqualStrings("dev.lo", getHeaderValue("Host:   dev.lo  \r\n", "host:").?);
}

test "default_max_request_body is 10MB" {
    try testing.expectEqual(@as(usize, 10 * 1024 * 1024), default_max_request_body);
}

test "getContentLength detects values above default_max_request_body" {
    // A Content-Length of 20MB should be parseable (validation is done by caller)
    const cl = getContentLength("Content-Length: 20971520\r\n");
    try testing.expect(cl != null);
    try testing.expect(cl.? > default_max_request_body);
}
