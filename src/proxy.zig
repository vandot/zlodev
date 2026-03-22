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

pub const ProxyConfig = struct {
    target_host: []const u8,
    target_port: u16,
    listen_addr: []const u8,
    cert_path: [:0]const u8,
    key_path: [:0]const u8,
    ca_path: [:0]const u8,
    server_ident: []const u8,
    max_request_body: usize = default_max_request_body,
};

var conn_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

fn nextConnId() u64 {
    return conn_counter.fetchAdd(1, .monotonic) + 1;
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
    pool.init(.{ .allocator = std.heap.page_allocator, .n_jobs = 64, .stack_size = 256 * 1024 }) catch |e| {
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
        const method = parts.next() orelse return;
        const uri = parts.next() orelse return;
        const version = parts.next() orelse "HTTP/1.0";
        var addr_buf: [46]u8 = undefined;
        log.info("component=proxy conn={d} method={s} uri={s} client={s}", .{ conn_id, method, uri, formatAddress(client_addr, &addr_buf) });

        // Determine keep-alive based on HTTP version and Connection header
        const is_http11 = std.mem.eql(u8, version, "HTTP/1.1");
        const req_hdr_section = req_buf[first_line_end + 2 .. hdr_end];
        const client_conn = getConnectionHeader(req_hdr_section);
        const keep_alive = if (client_conn == .close) false else if (client_conn == .keep_alive) true else is_http11;

        // Prepare request log entry
        var entry = requests.Entry{ .timestamp = start_time };
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

        // Check for WebSocket upgrade
        if (isWebSocketUpgrade(req_hdr_section)) {
            handleWebSocket(ssl, req_buf[0..total], config, &entry);
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
        if (intercept.isEnabled()) {
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
                        const drop_entry = requests.getByBackingIndex(intercept_backing_idx);
                        drop_entry.state = .dropped;
                        const drop_elapsed = std.time.milliTimestamp() - start_time;
                        drop_entry.duration_ms = if (drop_elapsed > 0) @intCast(drop_elapsed) else 0;
                        requests.unpin(intercept_backing_idx);
                        sslSendError(ssl, 502, "Dropped by intercept");
                        if (keep_alive) continue else return;
                    }

                    // Accept — update state and continue to upstream
                    requests.getByBackingIndex(intercept_backing_idx).state = .accepted;
                }
            }
        }

        // Connect to upstream (per-request — dev servers may not support keep-alive)
        const upstream_addr = std.net.Address.parseIp(config.target_host, config.target_port) catch {
            if (was_intercepted) {
                requests.finishEntry(intercept_backing_idx, 502, 0, "", "");
            }
            sslSendError(ssl, 502, "Bad Gateway");
            if (keep_alive) continue else return;
        };
        const upstream_sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |e| {
            log.err("component=proxy conn={d} op=upstream_socket error={any}", .{ conn_id, e });
            if (was_intercepted) {
                const dur = std.time.milliTimestamp() - start_time;
                requests.finishEntry(intercept_backing_idx, 502, if (dur > 0) @intCast(dur) else 0, "", "");
            }
            sslSendError(ssl, 502, "Bad Gateway");
            if (keep_alive) continue else return;
        };
        posix.connect(upstream_sock, &upstream_addr.any, upstream_addr.getOsSockLen()) catch |e| {
            log.err("component=proxy conn={d} op=upstream_connect error={any}", .{ conn_id, e });
            compat.closeSocket(upstream_sock);
            if (was_intercepted) {
                const dur = std.time.milliTimestamp() - start_time;
                requests.finishEntry(intercept_backing_idx, 502, if (dur > 0) @intCast(dur) else 0, "", "");
            }
            sslSendError(ssl, 502, "Bad Gateway");
            if (keep_alive) continue else return;
        };
        const upstream = compat.SocketStream{ .handle = upstream_sock };
        defer upstream.close();

        // Set timeouts on upstream socket
        setSocketTimeout(upstream_sock, .recv, 30);
        setSocketTimeout(upstream_sock, .send, 30);

        // If intercepted and edited, re-read the (possibly modified) entry data
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
                upstream.writeAll(header) catch return;
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
        if (fwd_body.len > 0) {
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

        // Forward response status line
        sslWriteAll(ssl, resp_buf[0 .. resp_first_line_end + 2]);

        // Forward response headers, replacing Connection header with our decision
        var resp_header_iter = std.mem.splitSequence(u8, resp_headers_section, "\r\n");
        while (resp_header_iter.next()) |header| {
            if (header.len == 0) continue;
            if (startsWithIgnoreCase(header, "connection:")) continue;
            sslWriteAll(ssl, header);
            sslWriteAll(ssl, "\r\n");
        }
        if (must_close) {
            sslWriteAll(ssl, "Connection: close\r\n");
        } else {
            sslWriteAll(ssl, "Connection: keep-alive\r\n");
        }
        sslWriteAll(ssl, "\r\n");

        // Forward response body already received
        const resp_body_start = resp_hdr_end + 4;
        var resp_body_captured: usize = 0;
        const initial_body = if (resp_body_start < resp_total) resp_buf[resp_body_start..resp_total] else resp_buf[0..0];

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

fn sslSendError(ssl: *ssl_c.SSL, status: u16, message: []const u8) void {
    var buf: [512]u8 = undefined;
    const response = std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        status, message, message.len, message,
    }) catch return;
    sslWriteAll(ssl, response);
}

const ConnectionHeader = enum { keep_alive, close, none };

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
            if (startsWithIgnoreCase(value, "chunked")) return true;
        }
    }
    return false;
}

const ChunkState = enum { size, size_ext, size_cr, data, data_cr, data_lf, trailer_start, trailer_line, trailer_line_cr, trailer_end_cr, done };

fn forwardChunkedBody(
    ssl: *ssl_c.SSL,
    upstream: compat.SocketStream,
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
            if (state == .done) return captured;
        }
    }

    while (state != .done) {
        const n = upstream.read(read_buf) catch break;
        if (n == 0) break;
        sslWriteAll(ssl, read_buf.*[0..n]);
        for (read_buf.*[0..n]) |byte| {
            chunkedStep(byte, &state, &chunk_remaining, &size_val, resp_body, &captured);
            if (state == .done) return captured;
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
                const digit = std.fmt.charToDigit(byte, 16) catch return;
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
    entry: *requests.Entry,
) void {
    log.info("component=proxy op=websocket_upgrade uri={s}", .{entry.getPath()});

    // Connect to upstream
    const upstream_addr = std.net.Address.parseIp(config.target_host, config.target_port) catch |e| {
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

test "default_max_request_body is 10MB" {
    try testing.expectEqual(@as(usize, 10 * 1024 * 1024), default_max_request_body);
}

test "getContentLength detects values above default_max_request_body" {
    // A Content-Length of 20MB should be parseable (validation is done by caller)
    const cl = getContentLength("Content-Length: 20971520\r\n");
    try testing.expect(cl != null);
    try testing.expect(cl.? > default_max_request_body);
}
