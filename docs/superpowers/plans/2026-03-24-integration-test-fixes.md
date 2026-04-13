# Integration Test Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get install/uninstall integration tests passing on all 3 CI platforms (Linux, macOS, Windows) by fixing test assertions and gating unstable `--local` tests.

**Architecture:** Two changes to `tests/install.zig` only — gate `--local` tests behind an env var, fix Windows cert verification name.

**Tech Stack:** Zig 0.15.1, GitHub Actions CI

**Spec:** `docs/superpowers/specs/2026-03-24-integration-test-fixes-design.md`

---

### Task 1: Gate `--local` tests behind `ZLODEV_TEST_LOCAL` env var

**Files:**
- Modify: `tests/install.zig:171,200,210`

- [ ] **Step 1: Add env var gate to "install --local and verify" test**

At the top of the test body (line 172, before `var hostname_buf`), add:

```zig
test "install --local and verify" {
    if (getEnvOwned("ZLODEV_TEST_LOCAL")) |val| {
        testing.allocator.free(val);
    } else return;

    var hostname_buf: [hostname_max]u8 = undefined;
    // ... rest unchanged
```

- [ ] **Step 2: Add env var gate to "install --local -f succeeds when already installed" test**

At the top of the test body (line 201, before `var hostname_buf`), add:

```zig
test "install --local -f succeeds when already installed" {
    if (getEnvOwned("ZLODEV_TEST_LOCAL")) |val| {
        testing.allocator.free(val);
    } else return;

    var hostname_buf: [hostname_max]u8 = undefined;
    // ... rest unchanged
```

- [ ] **Step 3: Add env var gate to "uninstall --local and verify" test**

At the top of the test body (line 211, before `var hostname_buf`), add:

```zig
test "uninstall --local and verify" {
    if (getEnvOwned("ZLODEV_TEST_LOCAL")) |val| {
        testing.allocator.free(val);
    } else return;

    var hostname_buf: [hostname_max]u8 = undefined;
    // ... rest unchanged
```

- [ ] **Step 4: Run tests locally to verify gating works**

Run: `zig test tests/install.zig 2>&1`
Expected: Only 3 tests run (the dev.lo tests). The 3 `--local` tests should show as "3 passed" with the local ones returning early (they count as passed, not skipped — Zig has no skip mechanism).

Run: `ZLODEV_TEST_LOCAL=1 zig test tests/install.zig 2>&1`
Expected: All 6 tests run (requires sudo for install).

### Task 2: Fix Windows `certutil -verifystore` name in dev.lo tests

**Files:**
- Modify: `tests/install.zig:129,162`

- [ ] **Step 1: Fix cert verification in "install and verify" test**

On line 129, change:

```zig
            try runCmdExpectSuccess(&.{ "certutil", "-verifystore", "Root", "zlodev" });
```

to:

```zig
            try runCmdExpectSuccess(&.{ "certutil", "-verifystore", "Root", "dev.lo CA" });
```

- [ ] **Step 2: Fix cert verification in "uninstall and verify" test**

On line 162, change:

```zig
            const term_w = try runCmd(&.{ "certutil", "-verifystore", "Root", "zlodev" });
```

to:

```zig
            const term_w = try runCmd(&.{ "certutil", "-verifystore", "Root", "dev.lo CA" });
```

- [ ] **Step 3: Run tests locally to verify no regressions**

Run: `zig test tests/install.zig 2>&1`
Expected: 6 passed (3 dev.lo tests run, 3 --local tests return early). No compilation errors.

### Task 3: Commit and push

- [ ] **Step 1: Commit changes**

```bash
git add tests/install.zig
git commit -m "fix integration tests: gate --local behind env var, fix Windows certutil name"
```

- [ ] **Step 2: Push and verify CI**

```bash
git push
```

Expected: All 3 CI jobs (Linux, macOS, Windows) pass.
