# Medium Bug Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 8 medium severity bugs identified in the 2026-03-28 code audit.

**Architecture:** Independent bug fixes across proxy, tui, http_server, dns, cert, and main modules. Each fix is self-contained.

**Tech Stack:** Zig 0.15.1, BoringSSL

---

## File Map

| File | Changes |
|------|---------|
| `src/proxy.zig` | Fix #8 (body truncation forwarded silently), Fix #9 (sslSendError + keep-alive) |
| `src/tui.zig` | Fix #10 (replayEntry torn read), Fix #11 (applyToEntry torn write) |
| `src/http_server.zig` | Fix #13 (header injection via CRLF in path) |
| `src/dns.zig` | Fix #14 (DNS compression pointer validation) |
| `src/cert.zig` | Fix #15 (X509_gmtime_adj return check) |
| `src/main.zig` | Fix #16 (wrong flag names in error messages) |
| `src/requests.zig` | Add `copyEntry` and `withLockedEntry` helpers for TUI fixes |

---

### Task 1: Fix error messages referencing wrong flags (main.zig)

**Files:** `src/main.zig:177,197`

- [ ] **Step 1:** Change both occurrences of `"-d and -c are mutually exclusive"` to `"--dns and --cert are mutually exclusive"` at lines 177 and 197.
- [ ] **Step 2:** Run `zig build` to verify.

---

### Task 2: Fix `X509_gmtime_adj` return value unchecked (cert.zig)

**Files:** `src/cert.zig:160,162,228,230`

- [ ] **Step 1:** Change all four `_ = c.X509_gmtime_adj(...)` calls to check for null and return error:

```zig
// Before (4 instances):
_ = c.X509_gmtime_adj(not_before, 0);
_ = c.X509_gmtime_adj(not_after, N);

// After:
if (c.X509_gmtime_adj(not_before, 0) == null) return error.CertCreateFailed;
if (c.X509_gmtime_adj(not_after, N) == null) return error.CertCreateFailed;
```

- [ ] **Step 2:** Run `zig build` to verify.

---

### Task 3: Fix HTTP response header injection (http_server.zig)

**Files:** `src/http_server.zig:134-143`

**Root cause:** Raw request path is interpolated into `Location` header. CRLF bytes in path allow header injection.

- [ ] **Step 1:** Before building the redirect response, check if `path` contains `\r` or `\n`. If it does, return a 400 error instead of redirecting:

```zig
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
    ...
```

- [ ] **Step 2:** Run `zig build` to verify.

---

### Task 4: Fix DNS label length not validated for compression pointers (dns.zig)

**Files:** `src/dns.zig:62-64,82`

**Root cause:** DNS compression pointers use the two high bits (bytes >= 0xC0). The code treats them as label lengths, causing out-of-bounds reads.

- [ ] **Step 1:** In `parseQuestion` (line 62-64), add a check for compression pointer bytes:

```zig
while (pos < data.len and data[pos] != 0) {
    const label_len = @as(usize, data[pos]);
    if (label_len >= 0xC0) return null; // compression pointer — not supported, reject
    pos += 1 + label_len;
    if (pos >= data.len) return null;
}
```

- [ ] **Step 2:** In `decodeName` (line 82), add the same check:

```zig
while (pos < name_end and data[pos] != 0) {
    const label_len = @as(usize, data[pos]);
    if (label_len >= 0xC0) break; // compression pointer — stop decoding
    pos += 1;
    ...
```

- [ ] **Step 3:** Add a test for compression pointer handling:

```zig
test "parseQuestion rejects compression pointers" {
    // Craft a packet with a compression pointer (0xC0) where a label length should be
    var pkt: [20]u8 = .{0} ** 20;
    // Header (12 bytes)
    pkt[4] = 0; pkt[5] = 1; // QDCOUNT = 1
    // QNAME starting at byte 12: compression pointer instead of label
    pkt[12] = 0xC0; // compression pointer
    pkt[13] = 0x00; // pointer offset
    const result = parseQuestion(&pkt);
    try std.testing.expect(result == null);
}
```

- [ ] **Step 4:** Run `zig test src/dns.zig` to verify.

---

### Task 5: Fix `sslSendError` + keep-alive protocol violation (proxy.zig)

**Files:** `src/proxy.zig` — multiple `sslSendError` + `if (keep_alive) continue` sites

**Root cause:** `sslSendError` sends `Connection: close` but the keep-alive loop continues if `keep_alive` is true.

- [ ] **Step 1:** After every `sslSendError` call that is followed by `if (keep_alive) continue else return;`, change to just `return;`. The response told the client the connection is closed, so we must close it.

Find all patterns like:
```zig
sslSendError(ssl, NNN, "...");
if (keep_alive) continue else return;
```
And replace with:
```zig
sslSendError(ssl, NNN, "...");
return;
```

These occur at approximately: lines 447, 484, 493, 502, 513, 523, 537, 555, 771 (verify exact locations).

- [ ] **Step 2:** Run `zig build` and `zig test src/proxy.zig` to verify.

---

### Task 6: Fix request body truncation forwarded silently (proxy.zig)

**Files:** `src/proxy.zig:408-411,613-619`

**Root cause:** Bodies > 32KB are truncated in the entry but the truncated size is used for Content-Length. The upstream gets a body shorter than declared.

**Fix:** When the body is truncated, use the original `content_length` for the Content-Length header and forward the full body by re-reading from the stored entry plus continuing to forward remaining bytes from the SSL connection. However, this is complex because the full body was already consumed from SSL. A simpler approach: when `req_body_truncated` is true, use the original `content_length` for the upstream Content-Length and forward the truncated body followed by signaling the truncation. Actually — the simplest correct fix is to reject requests with truncated bodies when they'd be forwarded incorrectly, OR to forward the original content_length and note the mismatch.

The most practical fix: store the original content_length in the entry, and use it (not fwd_body.len) for the Content-Length header when forwarding. The body is already fully read from the client into `req_buf` and consumed; we just don't have it all stored. Since the body was read and discarded beyond 32KB, the upstream will get an incomplete body with the correct declared length and timeout. A better approach:

**Correct fix:** Forward the original `content_length` and stream the body directly from the SSL connection to upstream instead of going through the entry. But for intercepted requests the body must go through the entry. For non-intercepted requests with truncated bodies, we should forward the correct Content-Length. Since we already consumed the body from SSL, the actual body data in the entry is only 32KB. We need to track the original content length.

**Simplest safe fix:** When the body is truncated (`entry.req_body_truncated`), send the full `content_length` as Content-Length and send what we have. The upstream will hang waiting for more data and eventually timeout. This is still wrong.

**Actually correct fix:** The body IS fully read from SSL (lines 392-406 consume all `content_length` bytes from the wire). But only 32KB is stored. The rest is discarded. So we genuinely don't have the full body. The right fix is: when truncated, return 413 to the client instead of silently forwarding a broken request. This matches the existing 413 for bodies > max_request_body.

- [ ] **Step 1:** After line 411 (`entry.req_body_truncated = true`), add early rejection for non-intercepted truncated bodies. But we don't know if it'll be intercepted yet at that point. Move the check to the forwarding section.

After the `fwd_body` assignment (line 614), add:
```zig
        // If body was truncated, we can't forward it correctly — reject
        if (fwd_entry.req_body_truncated) {
            if (was_intercepted) {
                const dur = std.time.milliTimestamp() - start_time;
                requests.finishEntry(intercept_backing_idx, 413, if (dur > 0) @intCast(dur) else 0, "", "");
            }
            sslSendError(ssl, 413, "Request body too large for proxy buffer");
            return;
        }
```

- [ ] **Step 2:** Run `zig build` and `zig test src/proxy.zig` to verify.

---

### Task 7: Fix TUI torn read in `replayEntry` (tui.zig)

**Files:** `src/tui.zig:1607-1611`, `src/requests.zig`

**Root cause:** `getOne` returns a pointer to the backing entry. After `getOne` returns, the mutex is released. The 69KB copy at line 1611 (`copy.* = entry.*`) happens without the mutex held.

**Fix:** Add a `copyEntry` function to `requests.zig` that does the copy under the mutex, then use it in `replayEntry`.

- [ ] **Step 1:** Add to `src/requests.zig`:

```zig
/// Copy an entry by logical index into caller-provided storage, under the mutex.
/// Returns true if the entry was found and copied, false otherwise.
pub fn copyEntry(logical: usize, dest: *Entry) bool {
    mutex.lock();
    defer mutex.unlock();
    ensureInit();
    if (count == 0) return false;
    const ring_start = if (count >= max_entries) write_pos else 0;
    var seen: usize = 0;
    for (0..count) |i| {
        const idx = (ring_start + i) % max_entries;
        if (entries_backing[idx].state == .deleted) continue;
        if (seen == logical) {
            dest.* = entries_backing[idx];
            return true;
        }
        seen += 1;
    }
    return false;
}
```

- [ ] **Step 2:** In `src/tui.zig`, modify `replayEntry`:

```zig
fn replayEntry(logical: usize) void {
    const copy = std.heap.page_allocator.create(requests.Entry) catch return;
    if (!requests.copyEntry(logical, copy)) {
        std.heap.page_allocator.destroy(copy);
        return;
    }
    if (copy.state == .intercepted or copy.resp_intercepted) {
        std.heap.page_allocator.destroy(copy);
        return;
    }
    const thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, proxy.replay, .{
        copy,
    }) catch {
        std.heap.page_allocator.destroy(copy);
        return;
    };
    thread.detach();
}
```

- [ ] **Step 3:** Run `zig build` and `zig test src/requests.zig` to verify.

---

### Task 8: Fix TUI torn write in `applyToEntry` (tui.zig)

**Files:** `src/tui.zig:235-266`, `src/requests.zig`

**Root cause:** `applyToEntry` calls `getByBackingIndex` which does NOT hold the mutex, then writes to the entry directly.

**Fix:** Add a `withLockedEntry` function to `requests.zig` that provides locked access to an entry by backing index, or simpler — add a `lock`/`unlock` pair that the TUI can bracket around its writes. Since `applyToEntry` only runs on intercepted (pinned) entries, the entry won't be overwritten, but the proxy thread could be reading it simultaneously.

- [ ] **Step 1:** Add lock/unlock helpers to `src/requests.zig`:

```zig
/// Lock the entries mutex. Must be paired with unlock().
/// Use for external code that needs to modify entries in-place.
pub fn lock() void {
    mutex.lock();
}

/// Unlock the entries mutex.
pub fn unlock() void {
    mutex.unlock();
}
```

- [ ] **Step 2:** In `src/tui.zig`, wrap `applyToEntry` body with lock/unlock:

```zig
fn applyToEntry(self: *const EditState, alloc: std.mem.Allocator) void {
    requests.lock();
    defer requests.unlock();
    const entry = requests.getByBackingIndex(self.backing_idx);
    // ... rest unchanged
}
```

- [ ] **Step 3:** Run `zig build` to verify.

---

## Execution Order

1. Task 1 (main.zig — string fix)
2. Task 2 (cert.zig — null checks)
3. Task 3 (http_server.zig — CRLF rejection)
4. Task 4 (dns.zig — compression pointer + test)
5. Task 5 (proxy.zig — sslSendError return)
6. Task 6 (proxy.zig — body truncation rejection)
7. Task 7 (requests.zig + tui.zig — copyEntry for replay)
8. Task 8 (requests.zig + tui.zig — lock/unlock for apply)

## Verification

```bash
zig build
zig test src/proxy.zig
zig test src/requests.zig
zig test src/intercept.zig
zig test src/dns.zig
zig test src/har.zig
```
