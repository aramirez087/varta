//! Process start-time reader (Linux only) — the PID *generation* token.
//!
//! A numeric PID is not a stable process identity: the kernel recycles it
//! once the holding process dies. Field 22 (`starttime`) of
//! `/proc/<pid>/stat` — the process start time in clock ticks since boot —
//! disambiguates PID generations: two processes that happen to share a PID
//! value cannot share a start time, because the first holds the PID until it
//! exits. The observer pins this token alongside the PID-namespace inode
//! (see [`super::ns_inode`]) so a recycled PID is treated as a fresh agent
//! rather than inheriting the dead process's nonce baseline, origin, and
//! silence timer (which would otherwise false-stall the new process and
//! misdirect recovery against it).
//!
//! macOS and the BSDs return `None`: they expose no `/proc` and, for Varta's
//! pathname datagram socket, fall back to [`super::BeatOrigin::SocketModeOnly`]
//! — which already refuses recovery, bounding the recycle exposure there to
//! monitoring accuracy. The reader uses only inline `extern "C"` FFI to
//! satisfy the workspace's zero-registry-dependency constraint, and reads into
//! fixed stack buffers (no allocation).

#[cfg(target_os = "linux")]
extern "C" {
    fn open(path: *const core::ffi::c_char, oflag: core::ffi::c_int) -> core::ffi::c_int;
    // `buf: *mut u8` matches the existing `read` declaration in
    // `nonblock_fd.rs`; a `*mut c_void` here trips `clashing_extern_declarations`
    // (CI runs clippy with `-D warnings`).
    fn read(fd: core::ffi::c_int, buf: *mut u8, count: usize) -> isize;
    fn close(fd: core::ffi::c_int) -> core::ffi::c_int;
}

// Linux `O_RDONLY` is 0; `O_CLOEXEC` is `0o2000000`. `O_CLOEXEC` keeps the
// descriptor from leaking into a recovery child if a fork ever interleaved
// (it does not today — the read/close is synchronous within `record`), and is
// free hygiene.
#[cfg(target_os = "linux")]
const O_RDONLY: core::ffi::c_int = 0;
#[cfg(target_os = "linux")]
const O_CLOEXEC: core::ffi::c_int = 0o2_000_000;

/// Read the start-time generation token for `pid` from `/proc/<pid>/stat`.
///
/// Returns `Some(starttime_ticks)` on success, or `None` if the platform is
/// not Linux, the file is unreadable (peer died, permission denied, `/proc`
/// not mounted), or field 22 cannot be parsed. A `None` result is treated by
/// the tracker as "generation unknown" — first-wins, never a recycle signal —
/// mirroring the namespace-inode reader's lenient `None` handling.
///
/// Zero allocations — a 32-byte stack buffer for the path and a 512-byte stack
/// buffer for the file contents (field 22 lands well within 512 bytes because
/// the kernel caps `comm` at 16 bytes).
#[cfg(target_os = "linux")]
pub(crate) fn read_pid_start_time(pid: u32) -> Option<u64> {
    let mut path = [0u8; 32];
    write_proc_pid_stat(&mut path, pid)?;
    // SAFETY: `path` is NUL-terminated by `write_proc_pid_stat`. `O_RDONLY`
    // takes no mode argument, so the non-variadic declaration is ABI-correct.
    let fd = unsafe {
        open(
            path.as_ptr() as *const core::ffi::c_char,
            O_RDONLY | O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 512];
    // SAFETY: `buf` is a valid mutable slice of `buf.len()` bytes; `read`
    // writes at most `count` bytes and returns the number written.
    let n = unsafe { read(fd, buf.as_mut_ptr(), buf.len()) };
    // SAFETY: `fd` was returned by `open` above and is not used after close.
    unsafe {
        close(fd);
    }
    if n <= 0 {
        return None;
    }
    parse_starttime(&buf[..n as usize])
}

/// Parse field 22 (`starttime`) out of the contents of `/proc/<pid>/stat`.
///
/// The `comm` field (field 2) is wrapped in parentheses and may itself contain
/// spaces and `)` characters, so the parse anchors on the **last** `)` in the
/// buffer; everything after it is whitespace-delimited fields beginning at
/// field 3 (`state`). `starttime` is field 22 — the 20th token after the final
/// `)` (0-based index 19).
#[cfg(target_os = "linux")]
fn parse_starttime(stat: &[u8]) -> Option<u64> {
    let close = stat.iter().rposition(|&b| b == b')')?;
    let rest = stat.get(close + 1..)?;
    let token = rest
        .split(|&b| b == b' ' || b == b'\t' || b == b'\n')
        .filter(|s| !s.is_empty())
        .nth(19)?;
    if token.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &c in token {
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(acc)
}

/// Format `/proc/<pid>/stat\0` into `out` without allocation. Returns the
/// number of bytes written including the NUL terminator, or `None` if the
/// buffer is too small (statically impossible for u32 PIDs given the 32-byte
/// buffer, but defensive).
#[cfg(target_os = "linux")]
fn write_proc_pid_stat(out: &mut [u8; 32], pid: u32) -> Option<usize> {
    let prefix = b"/proc/";
    let suffix = b"/stat\0";
    let mut i = 0;
    for &b in prefix {
        *out.get_mut(i)? = b;
        i += 1;
    }
    let mut digit_buf = [0u8; 10];
    let mut n = pid;
    let mut len = 0usize;
    if n == 0 {
        digit_buf[0] = b'0';
        len = 1;
    } else {
        while n > 0 {
            digit_buf[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
    }
    for k in 0..len {
        *out.get_mut(i)? = digit_buf[len - 1 - k];
        i += 1;
    }
    for &b in suffix {
        *out.get_mut(i)? = b;
        i += 1;
    }
    Some(i)
}

/// Non-Linux stub: `/proc/<pid>/stat` does not exist. PID recycling on these
/// platforms is bounded to monitoring accuracy because UDS falls back to
/// `SocketModeOnly` (recovery refused) and all UDP is `NetworkUnverified`.
#[cfg(not(target_os = "linux"))]
#[inline]
pub(crate) fn read_pid_start_time(_pid: u32) -> Option<u64> {
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // A real-looking /proc/<pid>/stat line. starttime (field 22) is the 20th
    // token after the final ')': here `8462` for a normal comm.
    #[test]
    fn parse_starttime_normal_comm() {
        let line =
            b"1234 (bash) S 1 1234 1234 34816 1234 4194304 1 0 0 0 0 0 0 0 20 0 1 0 8462 0 0 ...";
        assert_eq!(parse_starttime(line), Some(8462));
    }

    // comm containing spaces AND a literal ')' — the adversarial case the
    // last-')' anchor exists for. The fields after the real closing paren are
    // identical, so starttime must still resolve to 8462.
    #[test]
    fn parse_starttime_comm_with_spaces_and_paren() {
        let line =
            b"1234 (weird )name foo) S 1 1234 1234 34816 1234 4194304 1 0 0 0 0 0 0 0 20 0 1 0 8462 0 0";
        assert_eq!(parse_starttime(line), Some(8462));
    }

    #[test]
    fn parse_starttime_rejects_no_paren() {
        assert_eq!(parse_starttime(b"1234 bash S 1 1 1 1 1 1"), None);
    }

    #[test]
    fn parse_starttime_rejects_truncated() {
        // Fewer than 20 tokens after ')': cannot resolve field 22.
        assert_eq!(parse_starttime(b"1234 (bash) S 1 1234 1234"), None);
    }

    #[test]
    fn parse_starttime_rejects_non_numeric_field() {
        let line = b"1234 (bash) S 1 1234 1234 34816 1234 4194304 1 0 0 0 0 0 0 0 20 0 1 0 xx 0";
        assert_eq!(parse_starttime(line), None);
    }

    #[test]
    fn write_proc_pid_stat_formats_correctly() {
        let mut buf = [0u8; 32];
        let n = write_proc_pid_stat(&mut buf, 12345).expect("fits");
        assert_eq!(&buf[..n], b"/proc/12345/stat\0");
    }

    #[test]
    #[cfg(not(miri))]
    fn reads_own_start_time() {
        // /proc/self resolves to the running test process; its starttime is
        // always readable and non-zero on Linux with /proc mounted.
        let st = read_pid_start_time(std::process::id());
        assert!(st.is_some(), "must resolve own start time");
        assert!(
            st.unwrap() > 0,
            "starttime ticks are non-zero for a live process"
        );
    }
}
