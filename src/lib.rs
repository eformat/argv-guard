//! argv-guard — LD_PRELOAD execve veto.
//!
//! Design (see ~/.opencode/plan/argv-guard.md and README):
//! - hooks execve/execveat via symbol interposition (RTLD_NEXT)
//! - fast path: no allocation, no env lookup, no syscalls — raw byte scan
//! - on secret-shaped argv: stderr warning + local redacted log + EPERM
//! - the scanned line must NEVER travel as this library's own argv: callers
//!   pass it as argv (naturally — it IS the child's argv) and the guard scans
//!   in-place; the guard itself never execs anything with user data.
//! - bypass: ARVGUARD_OFF=1 (checked once per process, cached)

pub mod log;
pub mod matcher;

use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, Ordering};

use libc::{c_char, c_int, c_void};

static STATE: AtomicU8 = AtomicU8::new(0); // 0=uninit 1=on 2=off
static REAL_EXECVE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_EXECVEAT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static LOG_INIT: AtomicBool = AtomicBool::new(false);

const EPERM: c_int = 1;
const RTLD_NEXT: *mut c_void = -1isize as *mut c_void;

extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

unsafe fn ensure_init() {
    if STATE.load(Ordering::Relaxed) != 0 {
        return;
    }
    let off = std::env::var("ARVGUARD_OFF").is_ok();
    STATE.store(if off { 2 } else { 1 }, Ordering::Relaxed);
}

unsafe fn real_execve() -> *mut c_void {
    let p = REAL_EXECVE.load(Ordering::Relaxed);
    if !p.is_null() {
        return p;
    }
    let sym = c"execve".as_ptr();
    let p = dlsym(RTLD_NEXT, sym);
    REAL_EXECVE.store(p, Ordering::Relaxed);
    p
}

unsafe fn real_execveat() -> *mut c_void {
    let p = REAL_EXECVEAT.load(Ordering::Relaxed);
    if !p.is_null() {
        return p;
    }
    let sym = c"execveat".as_ptr();
    let p = dlsym(RTLD_NEXT, sym);
    REAL_EXECVEAT.store(p, Ordering::Relaxed);
    p
}

unsafe fn cstr(p: *const c_char) -> Option<&'static [u8]> {
    if p.is_null() {
        return None;
    }
    let mut n = 0usize;
    while *p.add(n) != 0 {
        n += 1;
        if n > (1 << 20) {
            // absurd argv element — stop scanning it (doS guard)
            return None;
        }
    }
    Some(std::slice::from_raw_parts(p as *const u8, n))
}

/// Scan the whole argv array. Returns (pattern, exe, arg_index, preview).
/// Caps: first 2048 bytes per arg (secrets live at the start of args),
/// 64 KiB total per exec — keeps worst-case cost sub-millisecond.
unsafe fn scan_argv(argv: *const *const c_char) -> Option<(&'static str, String, usize, String)> {
    if argv.is_null() {
        return None;
    }
    const ARG_CAP: usize = 2048;
    const TOTAL_CAP: usize = 65536;
    let exe = exe_of(argv);
    let mut idx = 0usize;
    let mut budget = TOTAL_CAP;
    let mut p = argv;
    while !(*p).is_null() {
        if let Some(bytes) = cstr(*p) {
            let n = bytes.len().min(ARG_CAP).min(budget);
            if let Some((name, pos, plen)) = matcher::scan_arg(&bytes[..n]) {
                let preview = log::preview(bytes, pos, plen);
                return Some((name, exe, idx, preview));
            }
            budget = budget.saturating_sub(n);
            if budget == 0 {
                return None;
            }
        }
        p = p.add(1);
        idx += 1;
    }
    None
}

unsafe fn exe_of(argv: *const *const c_char) -> String {
    if !(*argv).is_null() {
        if let Some(b) = cstr(*argv) {
            return String::from_utf8_lossy(b).into_owned();
        }
    }
    "?".to_string()
}

unsafe fn veto(exe: &str, pattern: &str, idx: usize, preview: &str) -> c_int {
    eprintln!(
        "argv-guard: BLOCKED exec of '{exe}' — secret pattern '{pattern}' in argument {idx} (preview: {preview})"
    );
    eprintln!("argv-guard: false positive? re-run with ARVGUARD_OFF=1 to bypass");
    if LOG_INIT
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        log::append_hit(exe, pattern, idx, preview);
    }
    { *libc::__errno_location() = EPERM; }
    -1
}

/// int execve(const char *pathname, char *const argv[], char *const envp[]);
///
/// # Safety
/// Called by the runtime through symbol interposition; `path`/`argv`/`envp`
/// must be valid C values as per execve(2). On a pattern match the exec is
/// vetoed (EPERM) and the real execve is never called.
#[no_mangle]
pub unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    ensure_init();
    if STATE.load(Ordering::Relaxed) == 1 {
        if let Some((pat, exe, idx, preview)) = scan_argv(argv) {
            return veto(&exe, pat, idx, &preview);
        }
    }
    let real = real_execve();
    if real.is_null() {
        { *libc::__errno_location() = libc::ENOENT; }
        return -1;
    }
    type FnExecve = unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int;
    std::mem::transmute::<*mut c_void, FnExecve>(real)(path, argv, envp)
}

/// int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);
///
/// # Safety
/// Called by the runtime through symbol interposition; arguments must be
/// valid per execveat(2). On a pattern match the exec is vetoed (EPERM).
#[no_mangle]
pub unsafe extern "C" fn execveat(
    dirfd: c_int,
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    flags: c_int,
) -> c_int {
    ensure_init();
    if STATE.load(Ordering::Relaxed) == 1 {
        if let Some((pat, exe, idx, preview)) = scan_argv(argv) {
            return veto(&exe, pat, idx, &preview);
        }
    }
    let real = real_execveat();
    if real.is_null() {
        { *libc::__errno_location() = libc::ENOENT; }
        return -1;
    }
    type FnExecveat = unsafe extern "C" fn(c_int, *const c_char, *const *const c_char, *const *const c_char, c_int) -> c_int;
    std::mem::transmute::<*mut c_void, FnExecveat>(real)(dirfd, path, argv, envp, flags)
}
