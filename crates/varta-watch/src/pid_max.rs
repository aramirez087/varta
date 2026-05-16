//! Linux `/proc/sys/kernel/pid_max` reader for observer-side PID range gating.
//!
//! Frames decoded by [`varta_vlp::Frame::decode`] reject `pid ∈ {0, 1}` as
//! [`varta_vlp::DecodeError::BadPid`] — those are wire-format invariants
//! enforced by VLP. The observer additionally rejects frames whose `pid`
//! exceeds the kernel's configured maximum (`/proc/sys/kernel/pid_max`),
//! since any pid above that ceiling cannot map to a live process on this
//! host. This is a policy check, not a wire-format check, so it lives on
//! the observer side (varta-vlp is `#![no_std]` and has no filesystem
//! access).
//!
//! Read once at observer startup; cheap to query on the hot path (`u32`
//! comparison).

#[cfg(target_os = "linux")]
const LINUX_DEFAULT_PID_MAX: u32 = 4_194_304;

/// Read `/proc/sys/kernel/pid_max` on Linux; return a permissive ceiling on
/// other platforms.
///
/// On Linux, parses the first decimal integer in `/proc/sys/kernel/pid_max`.
/// On any failure — file missing (chroot, container without `/proc`),
/// permission denied, malformed contents, or value > [`u32::MAX`] — falls
/// back to [`LINUX_DEFAULT_PID_MAX`] (4 194 304, the modern kernel default).
/// Returning a permissive default rather than refusing to start preserves
/// availability for air-gapped or minimal-`/proc` deployments.
///
/// On macOS, FreeBSD, and other non-Linux targets, returns [`u32::MAX`]:
/// those platforms expose the analogous limit via sysctl, which is out of
/// scope for this gate (the observer only does cross-namespace `/proc`
/// reads on Linux today).
#[cfg(target_os = "linux")]
pub fn read_pid_max() -> u32 {
    use std::io::Read;

    let mut buf = [0u8; 16];
    let n = match std::fs::File::open("/proc/sys/kernel/pid_max").and_then(|mut f| f.read(&mut buf))
    {
        Ok(n) => n,
        Err(_) => return LINUX_DEFAULT_PID_MAX,
    };
    let slice = &buf[..n];
    let trimmed = match std::str::from_utf8(slice) {
        Ok(s) => s.trim(),
        Err(_) => return LINUX_DEFAULT_PID_MAX,
    };
    match trimmed.parse::<u64>() {
        Ok(v) if v > 0 && v <= u32::MAX as u64 => v as u32,
        _ => LINUX_DEFAULT_PID_MAX,
    }
}

/// Non-Linux fallback: `u32::MAX` (the gate is effectively disabled).
#[cfg(not(target_os = "linux"))]
pub fn read_pid_max() -> u32 {
    u32::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_pid_max_returns_positive_value() {
        let v = read_pid_max();
        assert!(
            v >= 2,
            "pid_max must be at least 2 (covers pid 0/1 reserved): {v}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_pid_max_does_not_exceed_modern_default_on_typical_hosts() {
        let v = read_pid_max();
        assert!(
            v <= LINUX_DEFAULT_PID_MAX,
            "pid_max must not exceed the modern kernel default on typical hosts: \
             got {v}, expected ≤ {LINUX_DEFAULT_PID_MAX}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_returns_permissive_u32_max() {
        assert_eq!(read_pid_max(), u32::MAX);
    }
}
