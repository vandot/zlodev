# Critical/High Bug Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 7 critical/high severity bugs identified in the 2026-03-28 code audit.

**Architecture:** These are independent bug fixes across proxy, requests, sys, cert, and main modules. Each fix is self-contained and can be committed separately. Order is by severity and dependency — issues sharing the same file are grouped.

**Tech Stack:** Zig 0.15.1, BoringSSL

---

## File Map

| File | Changes |
|------|---------|
| `src/proxy.zig` | Fix #1 (use-after-free: copy method/uri/host before body read), Fix #4 (unpin intercepted entries on upstream write errors) |
| `src/requests.zig` | Fix #2 (clearAll deadlock), Fix #3 (clearAll data race), Fix #12-related (unpin respects starred) |
| `src/main.zig` | Fix #5 (dangling pointer from readConfigFile) |
| `src/sys.zig` | Fix #6 (runCmdOutput toOwnedSlice) |
| `src/cert.zig` | Fix #7 (atomic write in removeFromGitCaBundle) |

---

### Task 1: Fix `runCmdOutput` returning `result.items` instead of `toOwnedSlice()` (sys.zig)

**Severity:** HIGH — memory corruption on free (GPA panic in debug, UB in release)

**Files:**
- Modify: `src/sys.zig:53`

**Root cause:** `ArrayListUnmanaged.items` is a slice with `.len` = number of appended bytes, but the actual allocation has `capacity` bytes. When the caller frees the returned slice, `allocator.free()` uses `.len` which doesn't match the allocated size.

- [ ] **Step 1: Fix `runCmdOutput` to use `toOwnedSlice`**

In `src/sys.zig`, replace line 53:
```zig
// Before:
return result.items;

// After:
return result.toOwnedSlice(allocator) catch {
    result.deinit(allocator);
    return null;
};
```

- [ ] **Step 2: Verify the fix compiles**

Run: `zig build`
Expected: Clean build, no errors.

- [ ] **Step 3: Commit**

```bash
git add src/sys.zig
git commit -m "fix: use toOwnedSlice in runCmdOutput to prevent size mismatch on free"
```

---

### Task 2: Fix dangling pointer from `readConfigFile` returning `bind` into stack buffer (main.zig)

**Severity:** HIGH — `bind_addr` points to freed stack memory after `readConfigFile` returns

**Files:**
- Modify: `src/main.zig:738-789`

**Root cause:** `readConfigFile` parses a stack-local `buf: [8192]u8`. The returned `ConfigResult.bind` and `intercept_pattern` are slices into this buffer. After the function returns, the buffer is gone. `intercept_pattern` is safe because `enableWithPattern` copies it immediately (line 129). But `bind_addr = b` (line 121) stores the dangling slice for later use.

- [ ] **Step 1: Change `readConfigFile` to accept an allocator and dupe string values**

In `src/main.zig`, modify the `ConfigResult` struct and `readConfigFile` function. The function already receives an `allocator` parameter. Dupe `bind` and `intercept_pattern` values so they outlive the stack buffer:

```zig
// In readConfigFile, change the bind assignment (around line 767):
// Before:
result.bind = val;

// After:
result.bind = allocator.dupe(u8, val) catch null;
```

```zig
// Same for intercept_pattern (around line 782):
// Before:
result.intercept_pattern = val;

// After:
result.intercept_pattern = allocator.dupe(u8, val) catch null;
```

Note: These allocations are intentionally never freed — they live for the lifetime of the process (config is read once at startup). The `intercept_pattern` dupe is belt-and-suspenders since `enableWithPattern` copies it, but it makes the API safe regardless of how the result is consumed.

- [ ] **Step 2: Verify the fix compiles**

Run: `zig build`
Expected: Clean build, no errors.

- [ ] **Step 3: Commit**

```bash
git add src/main.zig
git commit -m "fix: dupe config strings to prevent dangling pointer from stack buffer"
```

---

### Task 3: Fix use-after-free of `method`/`uri`/`host` after body read in proxy (proxy.zig)

**Severity:** CRITICAL — slices into `req_buf` go stale when body read overwrites the buffer

**Files:**
- Modify: `src/proxy.zig:318-411,579,656`

**Root cause:** `method`, `uri`, and `host` (lines 323, 324, 343) are slices into `req_buf`. When the request has a body, the body read loop at line 390 does `SSL_read(ssl, @ptrCast(&req_buf), ...)` which overwrites `req_buf`. After that, `method`/`uri`/`host` point to body data. They're used at:
- Line 411: `intercept.shouldInterceptRequest(method, uri)`
- Line 656: `intercept.shouldInterceptResponse(method, uri)`
- Lines 579-581: `X-Forwarded-Host: host`

The data IS already copied into `entry` (lines 349-354 for method/uri, line 357-359 for headers containing host). The fix is to re-derive these slices from the entry's fixed buffers after the copy, before the body read.

- [ ] **Step 1: Re-derive `method`, `uri`, and `host` from entry after copying**

In `src/proxy.zig`, after the entry fields are populated (after line 359), reassign the local variables to point at the entry's owned copies:

Since `method`, `uri`, and `host` are currently `const`, we need to change the original declarations to `var`. Replace:
```zig
// Lines 323-324, change from:
const method = parts.next() orelse return;
const uri = parts.next() orelse return;
```
to:
```zig
var method = parts.next() orelse return;
var uri = parts.next() orelse return;
```

And line 343, change from:
```zig
const host = getHeaderValue(req_hdr_section, "host:") orelse "";
```
to:
```zig
var host = getHeaderValue(req_hdr_section, "host:") orelse "";
```

Then after line 359 (after `entry.req_headers_len = @intCast(rh_len);`), add reassignments to point at the entry's owned copies:
```zig
// Re-derive from entry to avoid use-after-free when body read overwrites req_buf
method = entry.method[0..m_len];
uri = entry.path[0..p_len];
host = getHeaderValue(entry.req_headers[0..rh_len], "host:") orelse "";
```

Note: `host` is used at line 344 for route resolution (before body read — safe) and at lines 579-581 for X-Forwarded-Host (after body read — unsafe without this fix). The reassignment makes both uses safe.

- [ ] **Step 2: Verify the fix compiles**

Run: `zig build`
Expected: Clean build.

- [ ] **Step 3: Run proxy tests**

Run: `zig test src/proxy.zig`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/proxy.zig
git commit -m "fix: prevent use-after-free of method/uri/host after body read overwrites req_buf"
```

---

### Task 4: Fix intercepted entries pinned forever on upstream write errors (proxy.zig)

**Severity:** HIGH — `catch return` paths after upstream connect don't call `finishEntry` when `was_intercepted`

**Files:**
- Modify: `src/proxy.zig:554-607,625-629`

**Root cause:** After the upstream connection is established (line 543), multiple `catch return` paths exit the function without unpinning the intercepted entry:
- Lines 554-557: forwarding request line (`upstream.writeAll(...) catch return`)
- Lines 569-570: forwarding headers
- Lines 576-583: forwarding external host/X-Forwarded-Host
- Lines 589-594: forwarding proxy headers
- Lines 598-607: forwarding body
- Line 625: `if (resp_total == 0 or resp_headers_end == null) return`
- Line 629: `const resp_first_line_end = ... orelse return`

The earlier error paths (DNS resolve, connect, TLS handshake at lines 461-539) already handle this correctly by checking `if (was_intercepted)` and calling `finishEntry`.

**Fix approach:** Rather than adding `if (was_intercepted) finishEntry(...)` before every `catch return`, use a `defer` block right after the intercept decision block. This ensures cleanup on ANY exit path.

- [ ] **Step 1: Add a defer block for intercept cleanup**

After the intercept decision block (after line 449, the closing `}` of `if (intercept.shouldInterceptRequest(...))`), add a defer that handles cleanup for all subsequent exit paths:

```zig
// After line 449 (after the intercept block closes):
// Ensure intercepted entries are unpinned on any early exit after this point.
// Normal completion paths call finishEntry/finishResponseIntercept explicitly,
// which set status/duration before unpinning — so this defer only fires for
// error exits where the entry would otherwise be pinned forever.
defer if (was_intercepted) {
    const e = requests.getByBackingIndex(intercept_backing_idx);
    if (e.pinned and !e.starred and e.state == .accepted) {
        // Only clean up if still pinned and in accepted state (meaning finishEntry wasn't called yet)
        const dur = std.time.milliTimestamp() - start_time;
        requests.finishEntry(intercept_backing_idx, 502, if (dur > 0) @intCast(dur) else 0, "", "");
    }
};
```

Now remove the existing `if (was_intercepted)` checks in the upstream error paths (lines 463-464, 473-474, 481-482, 491-493, 501-503, 516-518, 534-535) since the defer handles them. Actually — keep those existing checks as they set specific status codes and are within the same scope. The defer acts as a safety net for paths that were missed. The existing explicit calls set status 502 and unpin via `finishEntry` which also sets `pinned = false`, so the defer's `e.pinned` check will correctly skip them.

Wait — `finishEntry` sets `pinned = false` (if not starred), so after `finishEntry` is called, `e.pinned` will be false, and the defer won't double-call. This is correct.

- [ ] **Step 2: Verify the fix compiles**

Run: `zig build`
Expected: Clean build.

- [ ] **Step 3: Run proxy tests**

Run: `zig test src/proxy.zig`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/proxy.zig
git commit -m "fix: defer unpin of intercepted entries to prevent permanent pin on upstream errors"
```

---

### Task 5: Fix `unpin()` not checking `starred` flag (requests.zig)

**Severity:** MEDIUM (listed as medium in audit, but prerequisite for clearAll fixes)

**Files:**
- Modify: `src/requests.zig:164-169`

**Root cause:** `unpin()` unconditionally clears the `pinned` flag. If an entry is starred, unpinning removes its ring buffer overflow protection. `finishEntry` (line 151) and `finishResponseIntercept` (line 161) already check `starred` correctly, but `unpin()` (used in the drop path at line 440 of proxy.zig) does not.

- [ ] **Step 1: Add starred check to `unpin()`**

In `src/requests.zig`, modify `unpin`:
```zig
// Before:
pub fn unpin(idx: usize) void {
    mutex.lock();
    defer mutex.unlock();
    entries_backing[idx].pinned = false;
}

// After:
pub fn unpin(idx: usize) void {
    mutex.lock();
    defer mutex.unlock();
    if (!entries_backing[idx].starred) entries_backing[idx].pinned = false;
}
```

- [ ] **Step 2: Add a test for `unpin` on starred entries**

In `src/requests.zig`, add a test at the end of the file:

```zig
test "unpin preserves pinned flag on starred entries" {
    // Push and pin an entry
    var e = Entry{ .timestamp = 1 };
    const idx = pushAndPin(e).?;

    // Star the entry
    toggleStar(idx);
    const entry = getByBackingIndex(idx);
    try std.testing.expect(entry.starred);
    try std.testing.expect(entry.pinned);

    // Unpin should NOT clear pinned because it's starred
    unpin(idx);
    try std.testing.expect(entry.pinned);

    // Unstar, then unpin should clear pinned
    toggleStar(idx);
    try std.testing.expect(!entry.pinned);
}
```

- [ ] **Step 3: Run requests tests**

Run: `zig test src/requests.zig`
Expected: All tests pass, including the new test.

- [ ] **Step 4: Commit**

```bash
git add src/requests.zig
git commit -m "fix: unpin() now preserves pinned flag on starred entries"
```

---

### Task 6: Fix `clearAll()` deadlock and data race (requests.zig)

**Severity:** CRITICAL — proxy threads blocked on `event.wait()` hang forever; data race on entry state

**Files:**
- Modify: `src/requests.zig:194-207`
- Modify: `src/intercept.zig` (need to expose a way to wake/release all pending intercept slots)

**Root cause (deadlock):** `clearAll()` sets `pinned=false` and resets entry state. But proxy threads that called `pushAndPin()` are blocked on `slot.event.wait()` in `proxy.zig:430`. With the entry unpinned and state changed, the proxy thread will never be woken because nobody signals the event. The intercept slots remain consumed forever.

**Root cause (data race):** After `clearAll()` sets `pinned=false`, `push()` can overwrite the entry slot. A proxy thread that got the backing index via `pushAndPin()` still holds that index — when it wakes (if it ever does), it reads a completely different entry.

**Fix:** `clearAll()` must signal all active intercept slots with a `drop` decision before clearing entries. This wakes the proxy threads, which will see the drop decision, skip forwarding, and release naturally. The entries can then be safely cleared after all pending intercepts are resolved.

- [ ] **Step 1: Add `dropAll()` to intercept.zig**

Add a function in `src/intercept.zig` that sets all active slots to `drop` and signals their events:

```zig
/// Drop all pending intercepts — sets decision to drop and signals all active slots.
/// Used by clearAll() to wake blocked proxy threads before clearing entries.
pub fn dropAll() void {
    mutex.lock();
    defer mutex.unlock();
    for (&slots) |*s| {
        if (s.active) {
            s.decision.store(@intFromEnum(Decision.drop), .release);
            s.event.set();
        }
    }
}

/// Return the number of currently active intercept slots.
pub fn getPendingCount() usize {
    mutex.lock();
    defer mutex.unlock();
    var n: usize = 0;
    for (&slots) |*s| {
        if (s.active) n += 1;
    }
    return n;
}
```

- [ ] **Step 2: Update `clearAll()` in requests.zig to call `dropAll()` and spin-wait**

In `src/requests.zig`, add the intercept import and modify `clearAll`:

```zig
const intercept = @import("intercept.zig");

// ...

pub fn clearAll() void {
    // First, drop all pending intercepts to wake blocked proxy threads.
    // They will see the drop decision, unpin their entries, and exit.
    intercept.dropAll();

    // Spin-wait for proxy threads to process drops and release their slots (up to 100ms).
    var wait_iters: usize = 0;
    while (intercept.getPendingCount() > 0 and wait_iters < 100) : (wait_iters += 1) {
        std.time.sleep(1 * std.time.ns_per_ms);
    }

    mutex.lock();
    defer mutex.unlock();
    for (0..max_entries) |i| {
        entries_backing[i].state = .deleted;
        entries_backing[i].pinned = false;
        entries_backing[i].starred = false;
        entries_backing[i].resp_intercepted = false;
    }
    count = 0;
    live_count = 0;
    write_pos = 0;
}
```

Note: The spin-wait is deterministic — it waits until all intercept slots are released, with a 100ms timeout as a safety bound. The mutex lock after the wait serializes with any concurrent `finishEntry` calls.

- [ ] **Step 3: Add tests for `dropAll` and `getPendingCount`**

In `src/intercept.zig`, add tests at the end of the file:

```zig
test "dropAll signals all active slots" {
    // Acquire a slot
    const s = acquire().?;
    try std.testing.expect(s.active);
    try std.testing.expectEqual(@as(usize, 1), getPendingCount());

    // dropAll should set drop decision and signal
    dropAll();
    try std.testing.expectEqual(@as(u8, @intFromEnum(Decision.drop)), s.decision.load(.acquire));

    // Clean up
    s.event.wait();
    s.event.reset();
    release(s);
    try std.testing.expectEqual(@as(usize, 0), getPendingCount());
}
```

- [ ] **Step 4: Verify the fix compiles**

Run: `zig build`
Expected: Clean build.

- [ ] **Step 5: Run intercept and requests tests**

Run: `zig test src/intercept.zig && zig test src/requests.zig`
Expected: All tests pass, including the new tests.

- [ ] **Step 6: Commit**

```bash
git add src/intercept.zig src/requests.zig
git commit -m "fix: clearAll drops pending intercepts to prevent deadlock and data race"
```

---

### Task 7: Fix `removeFromGitCaBundle` truncating file before writing (cert.zig)

**Severity:** HIGH — if writeAll fails, the entire Git CA bundle is destroyed

**Files:**
- Modify: `src/cert.zig:432-451`

**Root cause:** `std.fs.createFileAbsolute(bundle_path, .{})` truncates the file to zero length immediately. The subsequent `writeAll` calls write the content without the zlodev CA section. If either `writeAll` fails partway through, the file is left truncated/partial, destroying the Git CA bundle.

**Fix:** Write to a temporary file first, then atomically rename over the original.

- [ ] **Step 1: Use atomic write pattern**

In `src/cert.zig`, modify `removeFromGitCaBundle`:

```zig
fn removeFromGitCaBundle(allocator: std.mem.Allocator) void {
    const bundle_path = getGitCaBundlePath(allocator) orelse return;
    defer allocator.free(bundle_path);

    const content = std.fs.cwd().readFileAlloc(allocator, bundle_path, 4 * 1024 * 1024) catch return;
    defer allocator.free(content);

    const begin = std.mem.indexOf(u8, content, ca_bundle_marker_begin) orelse return;
    const after_begin = begin + ca_bundle_marker_begin.len;
    const end_marker = std.mem.indexOfPos(u8, content, after_begin, ca_bundle_marker_end) orelse return;
    const end = end_marker + ca_bundle_marker_end.len;

    // Write to a temporary file, then rename atomically
    const tmp_path = std.fmt.allocPrint(allocator, "{s}.zlodev_tmp", .{bundle_path}) catch return;
    defer allocator.free(tmp_path);

    const tmp_file = std.fs.createFileAbsolute(tmp_path, .{}) catch return;
    tmp_file.writeAll(content[0..begin]) catch {
        tmp_file.close();
        std.fs.deleteFileAbsolute(tmp_path) catch {};
        return;
    };
    tmp_file.writeAll(content[end..]) catch {
        tmp_file.close();
        std.fs.deleteFileAbsolute(tmp_path) catch {};
        return;
    };
    tmp_file.close();

    std.fs.renameAbsolute(tmp_path, bundle_path) catch {
        std.fs.deleteFileAbsolute(tmp_path) catch {};
        return;
    };
    std.debug.print("CA removed from Git CA bundle\n", .{});
}
```

- [ ] **Step 2: Verify the fix compiles**

Run: `zig build`
Expected: Clean build.

- [ ] **Step 3: Commit**

```bash
git add src/cert.zig
git commit -m "fix: use atomic write pattern in removeFromGitCaBundle to prevent data loss"
```

---

## Execution Order

Tasks are independent and can be executed in any order. Recommended order (simplest/safest first):

1. **Task 1** (sys.zig — one-line fix)
2. **Task 2** (main.zig — two-line fix)
3. **Task 5** (requests.zig — one-line fix, prerequisite knowledge for Task 6)
4. **Task 7** (cert.zig — isolated, self-contained)
5. **Task 6** (requests.zig + intercept.zig — most complex, touches concurrency)
6. **Task 3** (proxy.zig — variable reassignment, moderate complexity)
7. **Task 4** (proxy.zig — defer block, builds on understanding from Task 3)

## Verification

After all tasks are complete:
```bash
zig build
zig test src/proxy.zig
zig test src/requests.zig
zig test src/intercept.zig
zig test src/dns.zig
zig test src/har.zig
```
