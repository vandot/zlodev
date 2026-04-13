# Command Runner and Logs Pane

## Summary

Add a `command=` option (CLI and config) that launches a user-specified dev-server command when `zlodev start` runs, captures its stdout and stderr into a bounded ring buffer, and exposes them through a new logs pane in the TUI. The pane occupies the bottom 40% of the body area, is toggled with `l`, and shares the TUI with the existing requests pane — focus moves between the two with `Tab`. Autoscroll is per-pane, `j`/`k`/`g`/`G` respect focus, and every other existing key continues to operate on requests regardless of focus.

The feature is purely additive: users who don't set `command` see no visual or behavioral change.

## Goals

- Let a developer launch their dev server alongside zlodev in a single command and watch its output without leaving the TUI.
- Keep the implementation small, predictable, and consistent with existing patterns in `requests.zig`, `tui.zig`, and `main.zig`.
- Fail loud on spawn or runtime errors — never silently swallow a failed child — while keeping the TUI itself up so the user can diagnose.
- Guarantee child cleanup on zlodev exit, including for processes that spawn subchildren (`npm run dev` → `node`).

## Non-Goals

- Multiple commands, tabbed logs, or any form of process orchestration — a single child, period.
- PTY allocation, ANSI color rendering, or any form of rich terminal emulation. ANSI escapes are stripped on ingest.
- Auto-restart on crash. The user presses `R` when ready.
- Log search, log export, "copy log line", or a dedicated "clear logs" key.
- Configurable split ratio, log line count, or max line length.
- TUI test harness — TUI-level changes are verified manually.

## User-facing Behavior

### Starting a command

Either from the config file:

```
command=npm run dev
```

or from the CLI:

```sh
zlodev start -p 3001 --command="npm run dev"
```

The value is passed through a shell (`sh -c "..."` on Unix, `cmd /c "..."` on Windows), so env vars, pipes, `&&`, and quoting all work exactly as in an interactive shell. CLI flag takes precedence over config, matching every other option.

`--command` uses the `arg=value` form only, consistent with all other zlodev flags. There is no short form and no space-separated variant. The flag has no positional requirement — the user may quote long values in their shell, e.g. `--command="PORT=3001 npm run dev"`.

When the user runs `zlodev start` with `command` set:

1. The proxy, DNS, and HTTP servers spawn as today.
2. `subprocess.start()` is called, which spawns the shell child.
3. The TUI comes up with the logs pane **already visible**, so the user immediately sees their dev server booting.

If `subprocess.start()` fails (e.g. the shell binary is missing), a synthetic `[zlodev] failed to start: <error>` line is injected into the log ring buffer and the TUI still launches — the user sees the error inside the logs pane and can quit cleanly.

### Invalid combinations

Rejected at argument validation with a clear error, exit code 1:

- `--command` with `--dns` (dns-only mode has no TUI and no proxy).
- `--command` with `--no-tui` (no pane to display the output).

An empty or whitespace-only `command=` value is a config parse error at startup.

### TUI layout

With `command` configured and the child running, the body area splits:

```
┌─ zlodev header (routes, counts, etc.) ──────────────────────┐
│                                                             │
│  ┌────────────────────────────────────────────────────── ┐  │  <- requests pane border
│  │  GET   /api/users                          200  12ms  │  │     (focused = bright)
│  │  POST  /api/login                          200   8ms  │  │
│  │  ...                                                  │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌── logs (autoscroll) ───────────────────────────────── ┐  │  <- logs pane border
│  │  vite v5.0.0 ready in 342 ms                          │  │     (unfocused = dim)
│  │  ➜  Local:   http://localhost:3001/                   │  │
│  │  ...                                                  │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
└─ footer: l:logs  tab:focus  R:restart  ...                  ┘
```

- Split ratio: 60% requests pane / 40% logs pane, measured in rows of the body area.
- Borders are **only** drawn when the split is active. In single-pane mode (logs hidden, or no command configured), the layout is visually identical to the current TUI — no regression for users who don't use the feature.
- Focus indicator: the focused pane's border is drawn in a bright color (`rgb 0x5fafff`); the unfocused pane's border is dim (`rgb 0x4a4a4a`).
- The logs pane border label shows `─── logs (autoscroll) ───` when that pane's autoscroll is on, `─── logs ───` when off. This lets the user see autoscroll state without consulting the header.
- `.detail` view (`Enter` on a request) and `.edit` view remain **fullscreen** — they temporarily hide header, footer, and both panes. Returning to `.list` restores the previous split and focus state.

### Keybindings

Global (unaffected by focus):

| Key | Action |
|-----|--------|
| `l` | Toggle logs pane visibility. No-op if no command is configured. |
| `Tab` | Switch focus between requests and logs. No-op if logs are hidden. |
| `R` | Restart the child process. Unix: `SIGTERM` to the process group → 3 s grace → `SIGKILL` → respawn. Windows: close the job handle (atomic kill, no graceful signal) → respawn. Windows restart is therefore always abrupt in v1; a graceful path is explicitly not attempted. |

Focus-dependent (only these four respect focus):

| Key | `focus == .requests` | `focus == .logs` |
|-----|----------------------|------------------|
| `j` | `cursor += 1`; sets `req_autoscroll = false` | `logs_scroll += 1`; sets `logs_autoscroll = false` |
| `k` | `cursor -= 1`; sets `req_autoscroll = false` | `logs_scroll -= 1`; sets `logs_autoscroll = false` |
| `g` | Jump to top of requests | Jump to top of log buffer |
| `G` | Jump to bottom of requests | Jump to bottom of log buffer |

`s` (autoscroll toggle) acts on the **focused** pane's autoscroll flag. When logs are hidden, focus is always `.requests`, so `s` behaves exactly as today for existing users.

Every other existing key — `/`, `Enter`, `i`, `a`, `A`, `C`, `d`, `c`, `E`, `*`, `q`, `?` — operates on the requests pane regardless of focus. The mental model: "logs are a read-only tail; everything else is request-focused."

`C` (clear all) clears only the requests ring. There is no dedicated "clear logs" key in v1.

The footer gains `l: logs  tab: focus  R: restart` when a command is configured. The `?` help overlay gains a "Logs pane" section listing the focus-dependent bindings.

## Components

### New file: `src/subprocess.zig`

Encapsulates the child process, its pipes, the reader threads, and the log ring buffer. Surface:

```zig
pub const max_log_lines: usize = 5000;
pub const max_line_len: usize = 4096;

pub const LogSource = enum(u1) { stdout, stderr };

pub const LogLine = struct {
    bytes: [max_line_len]u8,
    len: u16,
    source: LogSource,
    synthetic: bool, // true for [zlodev] lines
    seq: u64,
};

pub fn start(allocator: std.mem.Allocator, command: []const u8) !void;
pub fn restart() void;
pub fn stop() void;
pub fn isRunning() bool;
pub fn getLineCount() usize;
pub fn copyRange(dest: []LogLine, start: usize, n: usize) usize;
pub fn clearAll() void;
```

**Spawning** — `sh -c "<command>"` on Unix; `cmd /c "<command>"` on Windows.

**Process-group cleanup** — Unix: the child is launched with `setsid()` so it becomes its own process group leader; kill uses `killpg(pgid, SIGTERM)` with a 3-second grace period, then `killpg(pgid, SIGKILL)`. Windows: the child is placed in a job object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so closing the job handle atomically terminates the whole tree with no graceful signal.

**Reader threads** — two threads, one per pipe (`stdout`, `stderr`). Each reads chunks with a 1-second poll timeout that also checks `shutdown.isRunning()`, same pattern as the proxy and HTTP server loops. Each chunk is run through an ANSI escape state machine that drops:

- CSI sequences: `ESC[` followed by parameter/intermediate bytes and a final byte in `@–~` (covers SGR `m`, erase `K`/`J`, cursor movement, `?25l`/`?25h` show/hide cursor, etc.).
- OSC sequences: `ESC]...BEL` and `ESC]...ESC\` (terminal title updates — Vite and npm emit these and they would otherwise render as garbage).
- Bare `ESC` followed by a non-bracket byte (two-byte sequences like `ESC c`).

Everything else passes through unchanged. After stripping, bytes are split on `\n`. Lines longer than `max_line_len` are hard-split — the tail becomes the next line, no truncation, no data loss. CRLF is handled by stripping trailing `\r`.

**Ring buffer** — fixed-size array of `LogLine` heap-allocated at `start()` time via `page_allocator.create` and freed in `stop()`. ~20 MB (5000 × 4112 bytes). Users who never set `command=` pay zero memory cost for this feature — important because `requests.zig`'s ring is module-level BSS, and putting another 20 MB in BSS would inflate the baseline RSS for everyone. `requests.zig` is referenced here only as a pattern for the mutex + ring layout, *not* for the allocation strategy. Protected by a single mutex; `copyRange` takes the mutex, copies the requested window, returns count. Eviction is unconditional (no pinning — unlike `requests.zig`).

**Exit handling** — a watcher thread (or whichever reader sees EOF first) calls `waitpid` / `WaitForSingleObject` on the child, captures the exit code, and injects a synthetic line `[zlodev] exited (code N)` via the same append path. A `synthetic: true` flag lets the TUI render these in yellow/bold. `start` failures inject `[zlodev] failed to start: <error>` before returning.

**Structured logging** — `subprocess.zig` uses `log.zig` for internal events (`component=subprocess op=start command=<truncated>`, `op=exit code=N`, `op=reader_error`). These are muted in TUI mode along with the rest of stderr, per the existing pattern in `doStart`.

### Changes to `src/main.zig`

- `ConfigResult` gains `command: ?[]const u8 = null`.
- `readConfigFile` parses `command=<value>`. Duplicate `command=` lines are a config parse error. Empty or whitespace-only values are a parse error.
- CLI argument loop parses `--command=<value>` via the existing `flagValue` helper. No short form.
- Argument validation: `--command` + `--dns` and `--command` + `--no-tui` are both errors with clear messages, same style as the existing `--dns cannot be combined` check.
- `doStart` gains a final `command: ?[]const u8` parameter.
- In `doStart`: after the proxy / DNS / HTTP servers are spawned but **before** `tui.run()`, if `command != null` call `subprocess.start(allocator, command)`. A failure from `subprocess.start` is *not* fatal — the error is already in the log ring at that point, so the TUI still launches.
- At the end of `doStart`, before deferred proxy shutdown, call `subprocess.stop()` so children die first and the proxy drain is clean.

### Changes to `src/tui.zig`

New state in `run()`:

```zig
var logs_visible: bool = has_command;
var focus: enum { requests, logs } = .requests;
var logs_scroll: usize = 0;
var req_autoscroll: bool = true;   // replaces existing `autoscroll`
var logs_autoscroll: bool = true;
```

The existing `autoscroll` variable is renamed and split. `drawHeader` continues to receive a single "autoscroll" bool for its status indicator, but it now receives `req_autoscroll` — the header still reflects the requests pane's state, matching what existing users expect.

New function `drawLogs(win, logs_autoscroll, focus)`:

- Copies a window of lines from `subprocess.copyRange` into a local stack buffer each frame.
- If `logs_autoscroll`: show the last `N` lines where `N = pane_height - 1` (minus border).
- Otherwise: show `N` lines starting at `logs_scroll` from the top.
- Lines are truncated at pane width (no wrapping — matches detail view behavior).
- stdout lines render with default fg; stderr lines render with dim red fg; synthetic `[zlodev]` lines render with yellow fg and bold.

New helper `drawBorder(win, rect, label, focused)` draws a single-row horizontal border with an optional centered label. Used for both pane borders.

Layout computation in `run()`'s draw loop: when `logs_visible` and `view == .list`, the body area is split into `req_h = @max(1, body_h * 60 / 100)` and `logs_h = body_h - req_h - 2` (two rows for borders). When `logs_visible == false`, the draw loop is unchanged.

Key routing: focus-dependent keys (`j`/`k`/`g`/`G`) check `focus` before dispatching. All other keys retain their current behavior. `l`, `Tab`, `R`, and `s` are handled at the top of the list-view key switch.

### Changes to build / test

- `build.zig` gains `src/subprocess.zig` in the module list (tests are run per-file, so this is just for compilation).
- `CLAUDE.md` gains a line in the architecture table for `subprocess.zig`, and a brief note about the new key design decisions in the "Key design decisions" section.
- `README.md` gains a short section on the `command=` option and the logs pane keybindings. (Not strictly required by this spec but natural for discoverability.)

## Data Flow

```
config / CLI ──┐
               ▼
           main.zig: doStart
               │
               ├── spawns proxy / DNS / HTTP threads (as today)
               │
               ├── subprocess.start(command)
               │       │
               │       ├── fork+setsid+exec (Unix) / CreateProcess+job (Windows)
               │       ├── allocates log ring (20 MB)
               │       └── spawns reader threads (stdout, stderr)
               │              │
               │              └── loop: read → strip ANSI → split lines → append under mutex
               │
               └── tui.run()
                       │
                       └── draw loop (every 50 ms):
                             ├── drawHeader
                             ├── if logs_visible && view == .list:
                             │     ├── drawBorder(req, focused=focus==.requests)
                             │     ├── drawRequests(req_pane)
                             │     ├── drawBorder(logs, focused=focus==.logs, label)
                             │     └── drawLogs(logs_pane)
                             │         └── subprocess.copyRange(window)
                             ├── else: drawRequests full-body (as today)
                             └── drawFooter
```

On shutdown (`q`, Ctrl-C, SIGTERM):

```
shutdown.requestShutdown()
    │
    ├── tui.run() exits its loop and returns
    │
    └── main.zig: doStart defers run
            │
            ├── subprocess.stop()
            │       ├── killpg(SIGTERM) / close job handle
            │       ├── wait up to 3 s
            │       ├── killpg(SIGKILL) if still alive
            │       └── join reader threads
            │
            └── proxy / DNS / HTTP drain as today
```

## Error Handling and Edge Cases

| Situation | Behavior |
|-----------|----------|
| `fork` / `CreateProcess` fails | `[zlodev] failed to start: <errno>` injected into log ring; header flash; TUI launches; no retry. |
| Shell resolves binary to nothing (`sh: nmp: command not found`) | sh prints to stderr → reader captures it → appears as red line. Followed by `[zlodev] exited (code 127)`. |
| Child crashes or exits voluntarily | `[zlodev] exited (code N)` injected; no auto-restart; `R` restarts. |
| Pipe read returns 0 (child closed pipe) | Reader thread exits cleanly; the surviving thread or the watcher handles `waitpid`. |
| Pipe read returns error | Logged once via `log.zig`, reader thread exits. |
| Config has `command=` but empty value | Config parse error at startup (`process.exit(1)`). |
| `--command=""` | Same error. |
| Duplicate `command=` in config | Config parse error. |
| Log line exactly `max_line_len` with no newline | Flushed as a complete line; next bytes continue into the following entry. |
| Line longer than `max_line_len` | Hard-split at the boundary. |
| Line contains CRLF | Trailing `\r` stripped before append. |
| Ring overflow | Oldest lines evicted unconditionally (no pinning). |
| Ctrl-C while child is in an uninterruptible syscall | `SIGKILL` sent after 3 s grace; if the child is stuck in uninterruptible I/O, nothing can kill it — same as any other Unix tool. |
| Windows: Ctrl-C | Job object is closed, kernel terminates the whole tree atomically — no 3 s wait needed. |
| TUI requests to scroll past the end of the ring | Clamped to valid range (same pattern as requests-pane scroll clamping). |
| `l` pressed with no command configured | No-op (logs pane cannot open). |
| `Tab` pressed with logs hidden | No-op. |
| `R` pressed with no command configured | No-op. |
| Terminal resize | Layout recomputed next frame; scroll offsets clamped to new pane height. |

## Testing Strategy

### Unit tests in `src/subprocess.zig`

1. **ANSI-strip state machine** — given a byte sequence containing `ESC[31m`, `ESC[0m`, `ESC[2K`, `ESC[?25l`, the output is the same bytes with those sequences removed. Bare `ESC` followed by a non-bracket char is also dropped.
2. **Line splitter** — handles `\n`, `\r\n`, lone `\r` (treated as part of the same line), no trailing newline (line is held in the pending buffer until the next chunk or flush), and lines longer than `max_line_len` (hard-split at boundary).
3. **Ring overflow** — writing `max_log_lines + 100` lines leaves the oldest 100 evicted. `copyRange(0, max_log_lines)` returns the most recent `max_log_lines` in order. `seq` numbers are monotonic.
4. **Synthetic line injection** — a call to the internal `injectSynthetic` helper adds a line with `synthetic: true` and the correct content. `[zlodev] failed to start: ...` and `[zlodev] exited (code N)` appear through this path.

### Config parse test in `src/main.zig`

A lightweight test of `readConfigFile` that verifies `command=npm run dev` populates `ConfigResult.command` correctly, and that empty / duplicate `command=` values produce the expected error. If `main.zig` has no existing test pattern, add an inline `test "..."` block at the bottom of the file.

### Manual / integration

These are verified by running `zlodev start --command="..."` and observing the TUI:

- `--command="sh -c 'while true; do echo tick; sleep 1; done'"` — lines appear at ~1 Hz, logs pane visible on launch, autoscroll works, `j` disables autoscroll and lets you scroll up, `G` jumps to bottom and re-engages autoscroll, `s` toggles the focused pane's autoscroll.
- `--command="sh -c 'echo hi; exit 7'"` — one line `hi`, one line `[zlodev] exited (code 7)`, `R` respawns the child.
- `--command="nonexistent-binary-xyz"` — synthetic failure line appears; TUI is usable.
- `--command="npm run dev"` in a real Vite project — dev server boots, requests proxy through, logs show compilation output, restart with `R` works cleanly, quit with `q` kills the dev server (verify no orphan `node` processes).
- `--command` + `--dns` → error.
- `--command` + `--no-tui` → error.
- Tab focus indicator: bright border on focused pane, dim on unfocused. Pressing `l` hides the logs pane; pressing `l` again restores it with prior focus and scroll state.
- Entering detail view (`Enter`) hides both panes; escaping returns to the split view in its previous state.
- Terminal resize while logs are visible — layout recomputes, nothing crashes, scroll offsets clamp sensibly.

TUI-level automated testing is out of scope for v1 (no existing test harness in the codebase).

## Memory Budget

| Component | Size |
|-----------|------|
| `subprocess` log ring (5000 × 4112 bytes) | ~20 MB |
| Reader thread stacks (2 × 64 KB default) | ~128 KB |
| TUI state additions (flags + scroll offset) | negligible |
| **Total new static** | **~20 MB** |

This brings zlodev's baseline RSS from ~35 MB (requests ring ~35 MB plus overhead) to ~55 MB when a command is configured. Acceptable for a dev tool; still an order of magnitude less than a browser tab.

## Open Questions

None remaining — all clarifying questions have been resolved in the brainstorming session. This spec is ready for implementation planning.
