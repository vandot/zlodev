const std = @import("std");
const posix = std.posix;
const log = @import("log.zig");
const shutdown = @import("shutdown.zig");
const compat = @import("compat.zig");

pub fn serve(bind_addr: []const u8, domain: []const u8, ca_pem_path: []const u8, ca_der_path: []const u8) void {
    const address = std.net.Address.parseIp(bind_addr, 80) catch |e| {
        log.err("component=http op=addr_parse error={any}", .{e});
        return;
    };
    var server = address.listen(.{ .reuse_address = true }) catch |e| {
        log.err("component=http op=bind port=80 error={any}", .{e});
        if (e == error.AddressInUse) {
            std.debug.print("port 80 is already in use\n", .{});
        }
        return;
    };
    defer server.deinit();

    var pool: std.Thread.Pool = undefined;
    pool.init(.{ .allocator = std.heap.page_allocator, .n_jobs = 8 }) catch |e| {
        log.err("component=http op=pool_init error={any}", .{e});
        return;
    };
    defer pool.deinit();

    log.info("component=http op=listening ip={s} port=80 host={s}", .{ bind_addr, domain });

    var consecutive_failures: u32 = 0;
    while (shutdown.isRunning()) {
        // Poll with 1-second timeout before accept
        var fds = [1]posix.pollfd{
            .{ .fd = server.stream.handle, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = posix.poll(&fds, 1000) catch |e| {
            log.err("component=http op=poll error={any}", .{e});
            continue;
        };
        if (ready == 0) continue; // timeout, re-check shutdown

        const conn = server.accept() catch |e| {
            log.err("component=http op=accept error={any}", .{e});
            consecutive_failures += 1;
            const backoff_ms: u64 = @min(5000, @as(u64, 100) << @intCast(@min(consecutive_failures, 6)));
            std.Thread.sleep(backoff_ms * std.time.ns_per_ms);
            continue;
        };
        consecutive_failures = 0;

        const stream = compat.SocketStream{ .handle = conn.stream.handle };
        pool.spawn(handleRequest, .{ stream, domain, ca_pem_path, ca_der_path }) catch |e| {
            log.err("component=http op=pool_spawn error={any}", .{e});
            stream.close();
        };
    }
}

const Platform = enum { ios, android, desktop };

fn detectPlatform(headers: []const u8) Platform {
    // Scan User-Agent header
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |line| {
        if (startsWithIgnoreCase(line, "user-agent:")) {
            const ua = line["user-agent:".len..];
            if (std.mem.indexOf(u8, ua, "iPhone") != null or
                std.mem.indexOf(u8, ua, "iPad") != null or
                std.mem.indexOf(u8, ua, "iPod") != null)
                return .ios;
            if (std.mem.indexOf(u8, ua, "Android") != null)
                return .android;
            return .desktop;
        }
    }
    return .desktop;
}

fn startsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    for (haystack[0..needle.len], needle) |h, n| {
        if (std.ascii.toLower(h) != std.ascii.toLower(n)) return false;
    }
    return true;
}

fn handleRequest(stream: compat.SocketStream, domain: []const u8, ca_pem_path: []const u8, ca_der_path: []const u8) void {
    defer stream.close();

    // Read request
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = stream.read(buf[total..]) catch |e| {
            // On Windows, connection reset/aborted by client surfaces as
            // error.Unexpected — treat it like a closed connection.
            if (e == error.Unexpected or e == error.ConnectionResetByPeer) return;
            log.err("component=http op=read error={any}", .{e});
            return;
        };
        if (n == 0) return;
        total += n;
        if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) break;
    }
    if (total == 0) return;

    // Parse request line to get path
    const first_line_end = std.mem.indexOf(u8, buf[0..total], "\r\n") orelse return;
    const request_line = buf[0..first_line_end];

    // Extract method and path
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return;
    const path = parts.next() orelse return;

    log.info("component=http method={s} uri={s}", .{ method, path });

    if (std.mem.eql(u8, path, "/ca")) {
        const platform = detectPlatform(buf[0..total]);
        serveCaPage(stream, domain, platform);
    } else if (std.mem.eql(u8, path, "/ca.cer")) {
        serveFile(stream, ca_der_path, "application/x-x509-ca-cert", "zlodevCA.cer") catch {
            serveFile(stream, ca_pem_path, "application/x-pem-file", "zlodevCA.pem") catch {
                sendError(stream, "500 Internal Server Error");
            };
        };
    } else if (std.mem.eql(u8, path, "/ca.pem")) {
        serveFile(stream, ca_pem_path, "application/x-pem-file", "zlodevCA.pem") catch {
            sendError(stream, "500 Internal Server Error");
        };
    } else if (std.mem.eql(u8, path, "/health")) {
        const health_response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        stream.writeAll(health_response) catch return;
    } else {
        // Reject paths with CRLF to prevent header injection
        for (path) |ch| {
            if (ch == '\r' or ch == '\n') {
                const bad_response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Request";
                stream.writeAll(bad_response) catch return;
                return;
            }
        }
        // Redirect to HTTPS
        var resp_buf: [1024]u8 = undefined;
        const response = std.fmt.bufPrint(&resp_buf,
            "HTTP/1.1 302 Found\r\n" ++
                "Content-Type: text/plain; charset=utf-8\r\n" ++
                "Location: https://{s}{s}\r\n" ++
                "Content-Length: 0\r\n" ++
                "\r\n", .{ domain, path }) catch return;
        stream.writeAll(response) catch return;
    }
}

fn serveCaPage(stream: compat.SocketStream, domain: []const u8, platform: Platform) void {
    const page = caPage(domain, platform);
    var header_buf: [256]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/html; charset=utf-8\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Cache-Control: no-cache\r\n" ++
            "\r\n", .{page.len}) catch return;
    stream.writeAll(header) catch return;
    stream.writeAll(page) catch return;
}

fn caPage(domain: []const u8, platform: Platform) []const u8 {
    _ = domain;
    return switch (platform) {
        .ios => ca_page_ios,
        .android => ca_page_android,
        .desktop => ca_page_desktop,
    };
}

const ca_page_style =
    \\<!DOCTYPE html>
    \\<html lang="en"><head><meta charset="utf-8">
    \\<meta name="viewport" content="width=device-width, initial-scale=1">
    \\<title>zlodev - Install CA Certificate</title>
    \\<style>
    \\*{box-sizing:border-box;margin:0;padding:0}
    \\body{font-family:-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    \\background:#0f1117;color:#e1e4e8;min-height:100vh;display:flex;justify-content:center;padding:2rem 1rem}
    \\.wrap{max-width:540px;width:100%}
    \\h1{font-size:1.5rem;margin-bottom:.25rem;color:#fff}
    \\.sub{color:#8b949e;margin-bottom:2rem;font-size:.95rem}
    \\.badge{display:inline-block;background:#1f6feb33;color:#58a6ff;padding:.15rem .6rem;
    \\border-radius:1rem;font-size:.8rem;margin-bottom:1.5rem;border:1px solid #1f6feb55}
    \\.card{background:#161b22;border:1px solid #30363d;border-radius:.75rem;padding:1.5rem;margin-bottom:1.25rem}
    \\.card h2{font-size:1.05rem;margin-bottom:1rem;color:#fff}
    \\.step{display:flex;gap:.75rem;margin-bottom:1rem}
    \\.step:last-child{margin-bottom:0}
    \\.num{flex-shrink:0;width:1.6rem;height:1.6rem;background:#1f6feb;color:#fff;
    \\border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.8rem;font-weight:600;margin-top:.1rem}
    \\.step p{font-size:.9rem;line-height:1.5}
    \\.step code{background:#1f6feb22;color:#58a6ff;padding:.1rem .35rem;border-radius:.25rem;font-size:.8rem}
    \\.btn{display:block;width:100%;padding:.85rem;background:#1f6feb;color:#fff;border:none;
    \\border-radius:.5rem;font-size:1rem;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;margin-top:1.5rem}
    \\.btn:hover{background:#388bfd}
    \\.btn-alt{background:transparent;border:1px solid #30363d;color:#8b949e;font-size:.85rem;margin-top:.75rem}
    \\.btn-alt:hover{border-color:#58a6ff;color:#58a6ff}
    \\.note{color:#8b949e;font-size:.8rem;margin-top:1rem;line-height:1.5}
    \\</style></head><body><div class="wrap">
    \\<h1>zlodev</h1>
    \\<p class="sub">Local development CA certificate</p>
    \\
;

const ca_page_ios = ca_page_style ++
    \\<span class="badge">iOS</span>
    \\<div class="card"><h2>Install Certificate Profile</h2>
    \\<div class="step"><div class="num">1</div>
    \\<p>Tap the download button below. Safari will show <strong>"This website is trying to download a configuration profile"</strong> &mdash; tap <strong>Allow</strong>.</p></div>
    \\<div class="step"><div class="num">2</div>
    \\<p>Open <strong>Settings</strong> &rarr; <strong>General</strong> &rarr; <strong>VPN &amp; Device Management</strong>. Tap the <strong>zlodev</strong> profile and tap <strong>Install</strong>.</p></div>
    \\<div class="step"><div class="num">3</div>
    \\<p>Go to <strong>Settings</strong> &rarr; <strong>General</strong> &rarr; <strong>About</strong> &rarr; <strong>Certificate Trust Settings</strong>. Enable full trust for the <strong>zlodev</strong> root certificate.</p></div>
    \\</div>
    \\<a class="btn" href="/ca.cer">Download Certificate</a>
    \\<a class="btn btn-alt" href="/ca.pem">Download PEM format</a>
    \\<p class="note">The certificate is only valid for local development domains. It is unique to your machine and was generated locally.</p>
    \\</div></body></html>
;

const ca_page_android = ca_page_style ++
    \\<span class="badge">Android</span>
    \\<div class="card"><h2>Install CA Certificate</h2>
    \\<div class="step"><div class="num">1</div>
    \\<p>Tap the download button below to save the certificate file.</p></div>
    \\<div class="step"><div class="num">2</div>
    \\<p>Open <strong>Settings</strong> &rarr; <strong>Security</strong> (or <strong>Biometrics &amp; Security</strong>) &rarr; <strong>Encryption &amp; Credentials</strong> &rarr; <strong>Install a certificate</strong> &rarr; <strong>CA certificate</strong>.</p></div>
    \\<div class="step"><div class="num">3</div>
    \\<p>Tap <strong>Install anyway</strong> when warned, then select the downloaded <code>zlodevCA.cer</code> file.</p></div>
    \\<div class="step"><div class="num">4</div>
    \\<p>Verify installation: go to <strong>Encryption &amp; Credentials</strong> &rarr; <strong>Trusted credentials</strong> &rarr; <strong>User</strong> tab. You should see the zlodev certificate.</p></div>
    \\</div>
    \\<a class="btn" href="/ca.cer">Download Certificate</a>
    \\<a class="btn btn-alt" href="/ca.pem">Download PEM format</a>
    \\<p class="note">On some Android versions the path may differ. Look for "Install certificates" or "Credential storage" in Settings search. The certificate is only valid for local development domains.</p>
    \\</div></body></html>
;

const ca_page_desktop = ca_page_style ++
    \\<span class="badge">Desktop</span>
    \\<div class="card"><h2>Certificate Already Trusted</h2>
    \\<div class="step"><div class="num">&#10003;</div>
    \\<p>The CA certificate was added to your system trust store during <code>zlodev install</code>. Your desktop browser should already trust it.</p></div>
    \\</div>
    \\<div class="card"><h2>Installing on a Mobile Device?</h2>
    \\<div class="step"><div class="num">1</div>
    \\<p>Make sure your phone is on the same network as this machine.</p></div>
    \\<div class="step"><div class="num">2</div>
    \\<p>Open this page on your phone's browser. The page will show platform-specific instructions.</p></div>
    \\</div>
    \\<a class="btn" href="/ca.cer">Download Certificate (DER)</a>
    \\<a class="btn btn-alt" href="/ca.pem">Download Certificate (PEM)</a>
    \\<p class="note">The certificate is unique to your machine and was generated locally. It is only valid for local development domains.</p>
    \\</div></body></html>
;

fn serveFile(stream: compat.SocketStream, file_path: []const u8, content_type: []const u8, filename: []const u8) !void {
    const file = try std.fs.openFileAbsolute(file_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(std.heap.page_allocator, 1024 * 1024);
    defer std.heap.page_allocator.free(content);

    var resp_buf: [512]u8 = undefined;
    const header = try std.fmt.bufPrint(&resp_buf,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Disposition: attachment; filename=\"{s}\"\r\n" ++
            "Content-Length: {d}\r\n" ++
            "\r\n", .{ content_type, filename, content.len });

    try stream.writeAll(header);
    try stream.writeAll(content);
}

fn sendError(stream: compat.SocketStream, status: []const u8) void {
    var buf: [256]u8 = undefined;
    const response = std.fmt.bufPrint(&buf,
        "HTTP/1.1 {s}\r\nContent-Length: 0\r\n\r\n", .{status}) catch return;
    stream.writeAll(response) catch {};
}
