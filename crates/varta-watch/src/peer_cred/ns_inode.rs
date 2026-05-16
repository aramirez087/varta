//! PID-namespace inode reader (Linux only).
//!
//! PID namespaces are a Linux kernel concept (`pid_namespaces(7)`). The inode
//! number of `/proc/<pid>/ns/pid` uniquely identifies the namespace a process
//! belongs to. The observer reads its own inode once at startup and compares
//! the peer's inode on every kernel-attested datagram to detect cross-namespace
//! senders. macOS and the BSDs return `None` from these helpers — namespaces
//! don't exist as a concept there, so the gate short-circuits to "match".

use std::sync::OnceLock;

#[cfg(target_os = "linux")]
extern "C" {
    fn readlink(
        path: *const core::ffi::c_char,
        buf: *mut core::ffi::c_char,
        bufsiz: usize,
    ) -> isize;
}

/// Read the PID-namespace inode for `pid` via `readlink("/proc/<pid>/ns/pid")`.
///
/// Returns `Some(inode)` if the symlink resolves to the canonical `pid:[N]`
/// form. Returns `None` if the platform is not Linux, the symlink is
/// unreadable (peer died, permission denied via `ptrace_may_access`, `/proc`
/// not mounted), or the target string is malformed.
///
/// Zero allocations — uses two stack buffers (32 bytes for the path, 64 bytes
/// for the readlink target).
#[cfg(target_os = "linux")]
pub(crate) fn read_pid_namespace_inode(pid: u32) -> Option<u64> {
    let mut path = [0u8; 32];
    write_proc_pid_ns_pid(&mut path, pid)?;
    let mut link_buf = [0u8; 64];
    // SAFETY: `path` is NUL-terminated by `write_proc_pid_ns_pid`. `link_buf`
    // is a fixed-size stack buffer of known length. `readlink` does not write
    // a NUL terminator (we read only the returned length bytes).
    let ret = unsafe {
        readlink(
            path.as_ptr() as *const core::ffi::c_char,
            link_buf.as_mut_ptr() as *mut core::ffi::c_char,
            link_buf.len(),
        )
    };
    if ret <= 0 {
        return None;
    }
    parse_ns_inode(&link_buf[..ret as usize])
}

/// Format `/proc/<pid>/ns/pid\0` into `out` without allocation. Returns the
/// number of bytes written including the NUL terminator on success, or `None`
/// if the buffer is too small (statically impossible for u32 PIDs given the
/// 32-byte buffer, but defensive).
#[cfg(target_os = "linux")]
fn write_proc_pid_ns_pid(out: &mut [u8; 32], pid: u32) -> Option<usize> {
    let prefix = b"/proc/";
    let suffix = b"/ns/pid\0";
    let mut i = 0;
    for &b in prefix {
        if i >= out.len() {
            return None;
        }
        out[i] = b;
        i += 1;
    }
    // u32 decimal is at most 10 digits.
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
        if i >= out.len() {
            return None;
        }
        out[i] = digit_buf[len - 1 - k];
        i += 1;
    }
    for &b in suffix {
        if i >= out.len() {
            return None;
        }
        out[i] = b;
        i += 1;
    }
    Some(i)
}

/// Parse the inode out of a `pid:[NNNNN]` readlink target.
#[cfg(target_os = "linux")]
fn parse_ns_inode(bytes: &[u8]) -> Option<u64> {
    let prefix = b"pid:[";
    if bytes.len() < prefix.len() + 2 || &bytes[..prefix.len()] != prefix {
        return None;
    }
    let after = &bytes[prefix.len()..];
    let close = after.iter().position(|&b| b == b']')?;
    let digits = &after[..close];
    if digits.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &c in digits {
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(acc)
}

/// Non-Linux stub: PID namespaces are a Linux kernel concept.
#[cfg(not(target_os = "linux"))]
#[inline]
pub(crate) fn read_pid_namespace_inode(_pid: u32) -> Option<u64> {
    None
}

/// Cached observer PID-namespace inode. Linux processes cannot change PID
/// namespaces after `unshare`, so caching at first call is safe for the
/// observer's lifetime. On non-Linux platforms returns `None`.
pub(crate) fn observer_pid_namespace_inode() -> Option<u64> {
    static NS: OnceLock<Option<u64>> = OnceLock::new();
    *NS.get_or_init(|| {
        #[cfg(target_os = "linux")]
        {
            read_pid_namespace_inode(std::process::id())
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    })
}

#[cfg(all(test, target_os = "linux"))]
mod ns_tests {
    use super::*;

    #[test]
    fn parse_ns_inode_known_format() {
        assert_eq!(parse_ns_inode(b"pid:[4026531836]"), Some(4026531836));
        assert_eq!(parse_ns_inode(b"pid:[1]"), Some(1));
    }

    #[test]
    fn parse_ns_inode_rejects_malformed() {
        assert_eq!(parse_ns_inode(b"xxx"), None);
        assert_eq!(parse_ns_inode(b"pid:[]"), None);
        assert_eq!(parse_ns_inode(b"pid:[abc]"), None);
        assert_eq!(parse_ns_inode(b"pid:[42"), None); // missing close bracket
        assert_eq!(parse_ns_inode(b"net:[42]"), None); // wrong namespace prefix
    }

    #[test]
    fn write_proc_pid_ns_pid_formats_correctly() {
        let mut buf = [0u8; 32];
        let n = write_proc_pid_ns_pid(&mut buf, 12345).expect("fits");
        // Expect "/proc/12345/ns/pid\0" — 18 chars + NUL = 19 bytes.
        assert_eq!(n, 19);
        assert_eq!(&buf[..n], b"/proc/12345/ns/pid\0");
    }

    #[test]
    #[cfg(not(miri))]
    fn observer_can_read_its_own_namespace_inode() {
        // /proc/self/ns/pid is always readable for the running process on
        // Linux with /proc mounted. CI runners satisfy both.
        let inode = observer_pid_namespace_inode();
        assert!(
            inode.is_some(),
            "observer must resolve its own PID-ns inode"
        );
    }
}
