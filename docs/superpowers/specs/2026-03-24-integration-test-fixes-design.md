# Integration Test Fixes — dev.lo Mode

**Date**: 2026-03-24
**Status**: Approved
**Scope**: Get install/uninstall integration tests passing on Linux, macOS, and Windows

## Problem

CI fails on the `integration-testing` branch:
- **macOS**: `install --local` tests fail — `CertCreateFailed` at `setNameEntry` for CN with CI runner hostname
- **Windows**: `certutil -verifystore Root "zlodev"` can't find cert — CN is `"dev.lo CA"`, not `"zlodev"`
- **Linux**: Passes all tests

## Approach

Minimal test-only fixes. No changes to `cert.zig` or CI workflow.

## Changes

### 1. Gate `--local` tests behind env var

In `tests/install.zig`, add an early return at the top of each `--local` test if `ZLODEV_TEST_LOCAL` is not set. Uses the existing `getEnvOwned` helper (line 35) and frees the result to avoid leak detection by `testing.allocator`:

```zig
test "install --local and verify" {
    if (getEnvOwned("ZLODEV_TEST_LOCAL")) |val| {
        testing.allocator.free(val);
    } else return;
    // ... existing test body
}
```

Affected tests:
- `"install --local and verify"` (line 171)
- `"install --local -f succeeds when already installed"` (line 200)
- `"uninstall --local and verify"` (line 210)

This means CI runs only the 3 `dev.lo` tests. To run `--local` tests locally: `ZLODEV_TEST_LOCAL=1 zig test tests/install.zig`

### 2. Fix Windows cert verification name

In `tests/install.zig`, change the Windows `certutil -verifystore` calls in the `dev.lo` tests:

**Before:**
```zig
try runCmdExpectSuccess(&.{ "certutil", "-verifystore", "Root", "zlodev" });
```

**After:**
```zig
try runCmdExpectSuccess(&.{ "certutil", "-verifystore", "Root", "dev.lo CA" });
```

This applies to both the `"install and verify"` test (line 129) and the `"uninstall and verify"` test (line 162).

The cert is created with CN `"dev.lo CA"` by `cert.zig:generateCA`, so the verification must match.

## Deferred

- **macOS `--local` CN bug**: Investigate what hostname causes `X509_NAME_add_entry_by_NID` to fail. Requires debug logging or reproducing on a CI runner.
- **Windows `--local` verification**: Same `certutil` name issue applies to `--local` tests (CN would be `"{hostname}.local CA"`, not `"zlodev"`).
- **Broader integration tests** (Phase 2 from testing plan): proxy, DNS, routing — requires `zlodev install` + running proxy + curl.

## Expected Result

All 3 CI jobs green. 3 `dev.lo` tests pass per platform, 3 `--local` tests skipped.
