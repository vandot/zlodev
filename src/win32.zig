//! Win32 bindings zlodev uses that Zig 0.17's std no longer exposes.
//! Only reference these from `if (builtin.os.tag == .windows)` branches so
//! they are never analyzed for other targets.
const std = @import("std");
const windows = std.os.windows;

pub const BOOL = windows.BOOL;
pub const DWORD = windows.DWORD;
pub const HANDLE = windows.HANDLE;
pub const TRUE: BOOL = .TRUE;
pub const STD_INPUT_HANDLE: DWORD = @bitCast(@as(i32, -10));

pub const HandlerRoutine = *const fn (DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetConsoleCtrlHandler(handler: ?HandlerRoutine, add: BOOL) callconv(.winapi) BOOL;
pub extern "kernel32" fn TerminateProcess(process: HANDLE, exit_code: u32) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetStdHandle(n: DWORD) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn FlushConsoleInputBuffer(h: HANDLE) callconv(.winapi) BOOL;

// std.os.windows.ws2_32 no longer declares SOCKET; posix.socket_t is fd_t (HANDLE) on Windows.
pub const SOCKET = std.posix.socket_t;
pub const SOCKET_ERROR: c_int = -1;
pub const WSADATA = extern struct {
    wVersion: u16,
    wHighVersion: u16,
    iMaxSockets: u16,
    iMaxUdpDg: u16,
    lpVendorInfo: ?[*]u8,
    szDescription: [257]u8,
    szSystemStatus: [129]u8,
};
pub extern "ws2_32" fn WSAStartup(version: u16, data: *WSADATA) callconv(.winapi) c_int;
pub extern "ws2_32" fn recv(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
pub extern "ws2_32" fn send(s: SOCKET, buf: [*]const u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
pub extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;
pub extern "ws2_32" fn setsockopt(s: SOCKET, level: c_int, optname: c_int, optval: [*]const u8, optlen: c_int) callconv(.winapi) c_int;

// Job objects: `--command` puts cmd.exe in a kill-on-close job so stop/restart
// (and zlodev exiting) take the whole tree down, e.g. node under cmd.exe.
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
const JobObjectExtendedLimitInformation: c_int = 9;

const BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: i64 = 0,
    PerJobUserTimeLimit: i64 = 0,
    LimitFlags: u32 = 0,
    MinimumWorkingSetSize: usize = 0,
    MaximumWorkingSetSize: usize = 0,
    ActiveProcessLimit: u32 = 0,
    Affinity: usize = 0,
    PriorityClass: u32 = 0,
    SchedulingClass: u32 = 0,
};
const IO_COUNTERS = extern struct {
    ReadOperationCount: u64 = 0,
    WriteOperationCount: u64 = 0,
    OtherOperationCount: u64 = 0,
    ReadTransferCount: u64 = 0,
    WriteTransferCount: u64 = 0,
    OtherTransferCount: u64 = 0,
};
const EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: BASIC_LIMIT_INFORMATION = .{},
    IoInfo: IO_COUNTERS = .{},
    ProcessMemoryLimit: usize = 0,
    JobMemoryLimit: usize = 0,
    PeakProcessMemoryUsed: usize = 0,
    PeakJobMemoryUsed: usize = 0,
};

extern "kernel32" fn CreateJobObjectW(attrs: ?*anyopaque, name: ?[*:0]const u16) callconv(.winapi) ?HANDLE;
extern "kernel32" fn SetInformationJobObject(job: HANDLE, class: c_int, info: *const anyopaque, len: u32) callconv(.winapi) BOOL;
extern "kernel32" fn AssignProcessToJobObject(job: HANDLE, process: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn TerminateJobObject(job: HANDLE, exit_code: u32) callconv(.winapi) BOOL;

/// Put `process` into a new job that kills all its processes when closed
/// (including when zlodev exits). Returns null if any step fails.
pub fn assignToKillJob(process: HANDLE) ?HANDLE {
    const job = CreateJobObjectW(null, null) orelse return null;
    var info = EXTENDED_LIMIT_INFORMATION{};
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, @sizeOf(EXTENDED_LIMIT_INFORMATION)) == .FALSE or
        AssignProcessToJobObject(job, process) == .FALSE)
    {
        windows.CloseHandle(job);
        return null;
    }
    return job;
}
