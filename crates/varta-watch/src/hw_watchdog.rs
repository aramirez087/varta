//! Hardware watchdog driver for `varta-watch`.
//!
//! Opens a watchdog device (typically `/dev/watchdog`) for writing and kicks
//! it once per poll iteration.  If the observer crashes or hangs the device
//! is not kicked, the kernel watchdog timer expires, and the host reboots.
//!
//! On Linux, opening the device also verifies the standard watchdog ioctl API,
//! proves crash-close semantics (`WDIOF_MAGICCLOSE` or sysfs `nowayout=1`), and
//! enforces the documented timeout floor.  A character device that accepts
//! writes but does not answer these watchdog queries is not a watchdog.
//!
//! **Magic close:** on a clean shutdown (SIGTERM/SIGINT followed by graceful
//! exit) [`HwWatchdog::arm_disarm_on_drop`] is called before the value is
//! dropped.  For devices that advertise `WDIOF_MAGICCLOSE`, the `Drop` impl
//! writes the magic byte `'V'`, which tells the kernel to disarm the watchdog
//! instead of rebooting.  If the process crashes without calling
//! `arm_disarm_on_drop`, the file is closed without `'V'` and the watchdog
//! fires.  Linux devices accepted only because sysfs reports `nowayout=1` are
//! intentionally not disarmable; the kernel keeps them armed after any close.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// Minimum hardware-watchdog timeout accepted by `varta-watch`.
///
/// The operator guide derives this from the observer's p99 iteration time,
/// soft iteration budget, and self-watchdog deadline.  Shorter device
/// timeouts can reboot a healthy observer during transient filesystem or
/// scrape pressure.
pub const MIN_HW_WATCHDOG_TIMEOUT_SECS: i32 = 30;

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    )
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchdogTimeoutOp {
    GetTimeout,
    SetTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchdogCloseBehavior {
    MagicClose,
    #[cfg(target_os = "linux")]
    NoWayOut,
}

/// Hardware watchdog driver for `varta-watch`.
///
/// Created via [`HwWatchdog::open`] and kicked once per poll iteration.
/// Uses magic-close semantics when the kernel advertises them: call
/// [`HwWatchdog::arm_disarm_on_drop`] before dropping on a clean shutdown to
/// send the `'V'` byte that disarms the watchdog; omit it on the crash path to
/// allow the kernel to reboot. Linux `nowayout=1` devices are accepted as
/// intentionally non-disarmable.
pub struct HwWatchdog {
    file: File,
    /// Set by `arm_disarm_on_drop` when the observer is shutting down
    /// cleanly.  The `Drop` impl writes `'V'` only when this is true.
    disarm_on_drop: AtomicBool,
    close_behavior: WatchdogCloseBehavior,
}

impl HwWatchdog {
    /// Open `path` for writing.
    ///
    /// The opened descriptor must refer to a character device. This rejects
    /// regular files, FIFOs, and sockets that would accept writes without
    /// providing any watchdog protection.
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be opened or the opened descriptor
    /// is not a character device.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().write(true).open(path)?;
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(e) => return Err(disarm_after_failed_open(file, e)),
        };
        if !metadata.file_type().is_char_device() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{}: hardware watchdog must be a character device",
                    path.display()
                ),
            ));
        }
        let close_behavior = match validate_watchdog_contract(&file) {
            Ok(close_behavior) => close_behavior,
            Err(e) => return Err(disarm_after_failed_open(file, e)),
        };
        if let Err(e) = enforce_timeout_floor(&file) {
            return Err(disarm_after_failed_open(file, e));
        }
        Ok(Self {
            file,
            disarm_on_drop: AtomicBool::new(false),
            close_behavior,
        })
    }

    /// Write one byte to the device, resetting the hardware timer.
    ///
    /// Errors are intentionally ignored — a single missed kick is tolerable;
    /// persistent failures will cause the watchdog to fire naturally.
    pub fn kick(&mut self) {
        let _ = self.file.write_all(&[0u8]);
    }

    /// Signal that the next `Drop` should disarm the watchdog via magic close
    /// when the kernel supports that close mode.
    ///
    /// Call this immediately before the observer exits cleanly (after the
    /// `SHUTDOWN` latch is observed to be true and the poll loop has exited).
    /// Do NOT call on the crash path — omitting the call keeps the watchdog
    /// armed so the kernel will reboot.  On Linux `nowayout=1` devices, clean
    /// disarm is impossible by kernel policy; this flag is intentionally
    /// ignored by `Drop`.
    pub fn arm_disarm_on_drop(&self) {
        self.disarm_on_drop.store(true, Ordering::Release);
    }
}

impl Drop for HwWatchdog {
    fn drop(&mut self) {
        if self.disarm_on_drop.load(Ordering::Acquire)
            && self.close_behavior == WatchdogCloseBehavior::MagicClose
        {
            // Write the POSIX magic-close byte to disarm the watchdog.
            let _ = self.file.write_all(b"V");
        }
        // Whether or not we wrote 'V', the file is closed here. If 'V' was not
        // written on a crash path, or if the Linux device is nowayout, the
        // kernel watchdog timer is still running and will trigger a reboot.
    }
}

fn disarm_after_failed_open(mut file: File, err: std::io::Error) -> std::io::Error {
    // Opening a Linux watchdog can arm it. If startup validation rejects the
    // descriptor after open(2), send the magic-close byte before returning the
    // error so a clean startup failure can disarm magic-close devices. Kernel
    // nowayout devices cannot be disarmed by userspace.
    let _ = file.write_all(b"V");
    err
}

#[cfg(target_os = "linux")]
fn validate_watchdog_contract(file: &File) -> std::io::Result<WatchdogCloseBehavior> {
    linux_watchdog::validate_contract(file)
}

#[cfg(not(target_os = "linux"))]
fn validate_watchdog_contract(_file: &File) -> std::io::Result<WatchdogCloseBehavior> {
    Ok(WatchdogCloseBehavior::MagicClose)
}

#[cfg(target_os = "linux")]
fn enforce_timeout_floor(file: &File) -> std::io::Result<()> {
    linux_watchdog::enforce_timeout_floor(file)
}

#[cfg(not(target_os = "linux"))]
fn enforce_timeout_floor(_file: &File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    )
))]
fn enforce_timeout_floor_with<F>(mut ioctl: F) -> std::io::Result<()>
where
    F: FnMut(WatchdogTimeoutOp, &mut i32) -> std::io::Result<()>,
{
    let mut timeout = 0;
    ioctl(WatchdogTimeoutOp::GetTimeout, &mut timeout)
        .map_err(|e| std::io::Error::new(e.kind(), format!("WDIOC_GETTIMEOUT failed: {e}")))?;

    if timeout >= MIN_HW_WATCHDOG_TIMEOUT_SECS {
        return Ok(());
    }

    let observed = timeout;
    timeout = MIN_HW_WATCHDOG_TIMEOUT_SECS;
    ioctl(WatchdogTimeoutOp::SetTimeout, &mut timeout).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "watchdog timeout {observed}s is below required \
                 {MIN_HW_WATCHDOG_TIMEOUT_SECS}s and WDIOC_SETTIMEOUT failed: {e}"
            ),
        )
    })?;

    if timeout < MIN_HW_WATCHDOG_TIMEOUT_SECS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "watchdog timeout {timeout}s is below required \
                 {MIN_HW_WATCHDOG_TIMEOUT_SECS}s after requesting \
                 {MIN_HW_WATCHDOG_TIMEOUT_SECS}s"
            ),
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
mod linux_watchdog {
    use std::fs::File;
    use std::io;

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    use super::{enforce_timeout_floor_with, WatchdogTimeoutOp};
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    use std::os::raw::{c_int, c_ulong};
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    use std::os::unix::fs::MetadataExt;
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    use std::os::unix::io::AsRawFd;

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct WatchdogInfo {
        options: u32,
        firmware_version: u32,
        identity: [u8; 32],
    }

    // Linux watchdog UAPI:
    //   include/uapi/linux/watchdog.h:
    //     WDIOC_GETSUPPORT = _IOR('W', 0, struct watchdog_info)
    //     WDIOC_SETTIMEOUT = _IOWR('W', 6, int)
    //     WDIOC_GETTIMEOUT = _IOR('W', 7, int)
    //     WDIOF_MAGICCLOSE = 0x0100
    //   include/uapi/asm-generic/ioctl.h:
    //     _IOC_NRBITS=8, _IOC_TYPEBITS=8, _IOC_SIZEBITS=14,
    //     _IOC_DIRBITS=2, _IOC_READ=2, _IOC_WRITE=1.
    //
    // The default supported Linux arches for varta-watch use this
    // asm-generic ioctl encoding.  Do not let a different arch inherit these
    // constants silently; ioctl encodings are a known per-arch footgun.
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    mod raw {
        use std::os::raw::{c_int, c_ulong};

        const IOC_NRBITS: c_ulong = 8;
        const IOC_TYPEBITS: c_ulong = 8;
        const IOC_SIZEBITS: c_ulong = 14;

        const IOC_NRSHIFT: c_ulong = 0;
        const IOC_TYPESHIFT: c_ulong = IOC_NRSHIFT + IOC_NRBITS;
        const IOC_SIZESHIFT: c_ulong = IOC_TYPESHIFT + IOC_TYPEBITS;
        const IOC_DIRSHIFT: c_ulong = IOC_SIZESHIFT + IOC_SIZEBITS;

        const IOC_WRITE: c_ulong = 1;
        const IOC_READ: c_ulong = 2;
        const WATCHDOG_IOCTL_BASE: c_ulong = b'W' as c_ulong;
        pub const WDIOF_MAGICCLOSE: u32 = 0x0100;

        const fn ioc(dir: c_ulong, ty: c_ulong, nr: c_ulong, size: c_ulong) -> c_ulong {
            (dir << IOC_DIRSHIFT)
                | (ty << IOC_TYPESHIFT)
                | (nr << IOC_NRSHIFT)
                | (size << IOC_SIZESHIFT)
        }

        pub const WDIOC_GETSUPPORT: c_ulong = ioc(
            IOC_READ,
            WATCHDOG_IOCTL_BASE,
            0,
            core::mem::size_of::<super::WatchdogInfo>() as c_ulong,
        );
        pub const WDIOC_SETTIMEOUT: c_ulong = ioc(
            IOC_READ | IOC_WRITE,
            WATCHDOG_IOCTL_BASE,
            6,
            core::mem::size_of::<c_int>() as c_ulong,
        );
        pub const WDIOC_GETTIMEOUT: c_ulong = ioc(
            IOC_READ,
            WATCHDOG_IOCTL_BASE,
            7,
            core::mem::size_of::<c_int>() as c_ulong,
        );

        const _: () = assert!(WDIOC_GETSUPPORT == 0x8028_5700);
        const _: () = assert!(WDIOC_SETTIMEOUT == 0xC004_5706);
        const _: () = assert!(WDIOC_GETTIMEOUT == 0x8004_5707);
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    extern "C" {
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    pub fn validate_contract(file: &File) -> io::Result<super::WatchdogCloseBehavior> {
        let fd = file.as_raw_fd();
        let info = query_support(fd)?;
        close_behavior_for_file(file, info.options)
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    pub fn validate_contract(_file: &File) -> io::Result<super::WatchdogCloseBehavior> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            concat!(
                "Linux watchdog ioctl constants are not verified for this architecture; ",
                "--hw-watchdog is disabled on this target until the ioctl ABI is pinned"
            ),
        ))
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    pub fn enforce_timeout_floor(file: &File) -> io::Result<()> {
        let fd = file.as_raw_fd();
        enforce_timeout_floor_with(|op, timeout| raw_ioctl(fd, op, timeout))
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    pub fn enforce_timeout_floor(_file: &File) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            concat!(
                "Linux watchdog ioctl constants are not verified for this architecture; ",
                "--hw-watchdog is disabled on this target until the ioctl ABI is pinned"
            ),
        ))
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    fn raw_ioctl(fd: c_int, op: WatchdogTimeoutOp, timeout: &mut i32) -> io::Result<()> {
        let request = match op {
            WatchdogTimeoutOp::GetTimeout => raw::WDIOC_GETTIMEOUT,
            WatchdogTimeoutOp::SetTimeout => raw::WDIOC_SETTIMEOUT,
        };
        // SAFETY: `fd` is an open file descriptor owned by `HwWatchdog`, the
        // request constants are the Linux watchdog UAPI values for the active
        // architecture, and `timeout` points to a valid writable `int` slot for
        // the duration of the call.
        let ret = unsafe { ioctl(fd, request, timeout as *mut i32) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    fn query_support(fd: c_int) -> io::Result<WatchdogInfo> {
        let mut info = WatchdogInfo::default();
        // SAFETY: `fd` is an open file descriptor owned by `HwWatchdog`, the
        // request constant is the Linux watchdog UAPI value for the active
        // architecture, and `info` points to a valid writable
        // `struct watchdog_info` slot for the duration of the call.
        let ret = unsafe { ioctl(fd, raw::WDIOC_GETSUPPORT, &mut info as *mut WatchdogInfo) };
        if ret == 0 {
            Ok(info)
        } else {
            let e = io::Error::last_os_error();
            Err(io::Error::new(
                e.kind(),
                format!("WDIOC_GETSUPPORT failed: {e}"),
            ))
        }
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    fn close_behavior_for_file(
        file: &File,
        options: u32,
    ) -> io::Result<super::WatchdogCloseBehavior> {
        if options & raw::WDIOF_MAGICCLOSE != 0 {
            return Ok(super::WatchdogCloseBehavior::MagicClose);
        }
        validate_close_behavior(options, read_nowayout_for_file(file)?)
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    fn validate_close_behavior(
        options: u32,
        nowayout: Option<bool>,
    ) -> io::Result<super::WatchdogCloseBehavior> {
        if options & raw::WDIOF_MAGICCLOSE != 0 {
            Ok(super::WatchdogCloseBehavior::MagicClose)
        } else if nowayout == Some(true) {
            Ok(super::WatchdogCloseBehavior::NoWayOut)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "watchdog device does not advertise WDIOF_MAGICCLOSE and \
                 sysfs nowayout is not enabled; crash-close may disarm it",
            ))
        }
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    fn read_nowayout_for_file(file: &File) -> io::Result<Option<bool>> {
        let metadata = file.metadata()?;
        let (major, minor) = linux_dev_major_minor(metadata.rdev());
        read_sysfs_nowayout_for_dev(major, minor)
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    fn read_sysfs_nowayout_for_dev(major: u64, minor: u64) -> io::Result<Option<bool>> {
        let entries = match std::fs::read_dir("/sys/class/watchdog") {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        for entry in entries {
            let entry = entry?;
            let dir = entry.path();
            let dev = match std::fs::read_to_string(dir.join("dev")) {
                Ok(dev) => dev,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            if parse_sysfs_dev(&dev) != Some((major, minor)) {
                continue;
            }

            let nowayout = match std::fs::read_to_string(dir.join("nowayout")) {
                Ok(nowayout) => nowayout,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            };
            return Ok(parse_sysfs_bool(&nowayout));
        }

        Ok(None)
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    fn linux_dev_major_minor(dev: u64) -> (u64, u64) {
        let major = ((dev >> 8) & 0x0fff) | ((dev >> 32) & !0x0fff);
        let minor = (dev & 0x00ff) | ((dev >> 12) & !0x00ff);
        (major, minor)
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    fn parse_sysfs_dev(s: &str) -> Option<(u64, u64)> {
        let (major, minor) = s.trim().split_once(':')?;
        Some((major.parse().ok()?, minor.parse().ok()?))
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    fn parse_sysfs_bool(s: &str) -> Option<bool> {
        match s.trim() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        }
    }

    #[cfg(all(
        test,
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ))]
    pub(super) mod test_api {
        pub(crate) const WDIOF_MAGICCLOSE: u32 = super::raw::WDIOF_MAGICCLOSE;

        pub(crate) fn validate_close_behavior(
            options: u32,
            nowayout: Option<bool>,
        ) -> std::io::Result<super::super::WatchdogCloseBehavior> {
            super::validate_close_behavior(options, nowayout)
        }

        pub(crate) fn parse_sysfs_dev(s: &str) -> Option<(u64, u64)> {
            super::parse_sysfs_dev(s)
        }

        pub(crate) fn parse_sysfs_bool(s: &str) -> Option<bool> {
            super::parse_sysfs_bool(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io;

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("varta-hw-wdt-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn file_backed_watchdog(path: &Path) -> HwWatchdog {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open test sink");
        HwWatchdog {
            file,
            disarm_on_drop: AtomicBool::new(false),
            close_behavior: WatchdogCloseBehavior::MagicClose,
        }
    }

    #[test]
    fn open_rejects_regular_file() {
        let path = tmp_path("regular");
        std::fs::write(&path, b"").unwrap();

        let err = HwWatchdog::open(&path)
            .err()
            .expect("regular file must not be accepted as a watchdog");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn open_accepts_character_device() {
        let watchdog = HwWatchdog::open(Path::new("/dev/null"))
            .expect("/dev/null is a portable character-device test fixture");
        drop(watchdog);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_open_rejects_character_device_without_watchdog_ioctl() {
        let err = HwWatchdog::open(Path::new("/dev/null"))
            .err()
            .expect("/dev/null is not a Linux watchdog device");

        assert!(
            err.to_string().contains("WDIOC_GETSUPPORT failed"),
            "unexpected error: {err}"
        );
    }

    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ))]
    #[test]
    fn close_contract_accepts_magic_close_capability() {
        let behavior = linux_watchdog::test_api::validate_close_behavior(
            linux_watchdog::test_api::WDIOF_MAGICCLOSE,
            None,
        )
        .expect("WDIOF_MAGICCLOSE proves crash-close semantics");

        assert_eq!(behavior, WatchdogCloseBehavior::MagicClose);
    }

    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ))]
    #[test]
    fn close_contract_accepts_nowayout_without_magic_close() {
        let behavior = linux_watchdog::test_api::validate_close_behavior(0, Some(true))
            .expect("nowayout devices remain armed after close");

        assert_eq!(behavior, WatchdogCloseBehavior::NoWayOut);
    }

    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ))]
    #[test]
    fn close_contract_rejects_unproven_close_semantics() {
        let err = linux_watchdog::test_api::validate_close_behavior(0, Some(false))
            .expect_err("non-nowayout devices without magic close can disarm on crash-close");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("WDIOF_MAGICCLOSE"),
            "unexpected error: {err}"
        );
    }

    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ))]
    #[test]
    fn close_contract_rejects_missing_nowayout_status_without_magic_close() {
        let err = linux_watchdog::test_api::validate_close_behavior(0, None)
            .expect_err("missing sysfs status cannot prove crash-close semantics");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("nowayout"),
            "unexpected error: {err}"
        );
    }

    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ))]
    #[test]
    fn parses_sysfs_watchdog_dev_and_bool_files() {
        assert_eq!(
            linux_watchdog::test_api::parse_sysfs_dev("10:130\n"),
            Some((10, 130))
        );
        assert_eq!(linux_watchdog::test_api::parse_sysfs_dev("bad\n"), None);
        assert_eq!(
            linux_watchdog::test_api::parse_sysfs_bool("0\n"),
            Some(false)
        );
        assert_eq!(
            linux_watchdog::test_api::parse_sysfs_bool("1\n"),
            Some(true)
        );
        assert_eq!(linux_watchdog::test_api::parse_sysfs_bool("2\n"), None);
    }

    #[test]
    fn timeout_at_floor_does_not_set_timeout() {
        let calls = RefCell::new(Vec::new());

        enforce_timeout_floor_with(|op, timeout| {
            calls.borrow_mut().push(op);
            match op {
                WatchdogTimeoutOp::GetTimeout => {
                    *timeout = MIN_HW_WATCHDOG_TIMEOUT_SECS;
                    Ok(())
                }
                WatchdogTimeoutOp::SetTimeout => panic!("set should not be called"),
            }
        })
        .expect("timeout at the floor is acceptable");

        assert_eq!(calls.into_inner(), [WatchdogTimeoutOp::GetTimeout]);
    }

    #[test]
    fn timeout_below_floor_is_raised() {
        let calls = RefCell::new(Vec::new());

        enforce_timeout_floor_with(|op, timeout| {
            calls.borrow_mut().push((op, *timeout));
            match op {
                WatchdogTimeoutOp::GetTimeout => {
                    *timeout = 5;
                    Ok(())
                }
                WatchdogTimeoutOp::SetTimeout => {
                    assert_eq!(*timeout, MIN_HW_WATCHDOG_TIMEOUT_SECS);
                    *timeout = MIN_HW_WATCHDOG_TIMEOUT_SECS;
                    Ok(())
                }
            }
        })
        .expect("settable short timeout should be raised");

        assert_eq!(
            calls.into_inner(),
            [
                (WatchdogTimeoutOp::GetTimeout, 0),
                (WatchdogTimeoutOp::SetTimeout, MIN_HW_WATCHDOG_TIMEOUT_SECS)
            ]
        );
    }

    #[test]
    fn timeout_still_below_floor_after_set_is_rejected() {
        let err = enforce_timeout_floor_with(|op, timeout| {
            match op {
                WatchdogTimeoutOp::GetTimeout => {
                    *timeout = 5;
                }
                WatchdogTimeoutOp::SetTimeout => {
                    *timeout = 8;
                }
            }
            Ok(())
        })
        .expect_err("kernel-clamped timeout below floor must fail closed");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string()
                .contains("below required 30s after requesting 30s"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn get_timeout_failure_rejects_device() {
        let err = enforce_timeout_floor_with(|op, _timeout| {
            assert_eq!(op, WatchdogTimeoutOp::GetTimeout);
            Err(io::Error::new(io::ErrorKind::Other, "not a watchdog"))
        })
        .expect_err("GETTIMEOUT failure must reject the device");

        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(
            err.to_string().contains("WDIOC_GETTIMEOUT failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn failed_post_open_validation_writes_magic_close() {
        let path = tmp_path("failed-open-magic");
        std::fs::write(&path, b"").unwrap();
        let file = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open test sink");

        let err = disarm_after_failed_open(file, io::Error::new(io::ErrorKind::Other, "reject"));

        assert_eq!(err.kind(), io::ErrorKind::Other);
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(
            contents.last().copied(),
            Some(b'V'),
            "post-open startup rejection must best-effort magic-close"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn kick_writes_byte_to_device() {
        let path = tmp_path("kick");
        std::fs::write(&path, b"").unwrap();
        let mut w = file_backed_watchdog(&path);
        w.kick();
        drop(w); // disarm_on_drop = false → no 'V' written
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, &[0u8], "kick must write NUL byte");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn magic_close_writes_v_on_clean_shutdown() {
        let path = tmp_path("magic");
        std::fs::write(&path, b"").unwrap();
        let mut w = file_backed_watchdog(&path);
        w.kick();
        w.arm_disarm_on_drop(); // clean shutdown
        drop(w); // Drop writes 'V'
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(
            contents.last().copied(),
            Some(b'V'),
            "clean shutdown must write magic-close byte V"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn no_magic_close_without_arm() {
        let path = tmp_path("nomagic");
        std::fs::write(&path, b"").unwrap();
        let mut w = file_backed_watchdog(&path);
        w.kick();
        // do NOT call arm_disarm_on_drop
        drop(w);
        let contents = std::fs::read(&path).unwrap();
        assert_ne!(
            contents.last().copied(),
            Some(b'V'),
            "crash path must not write magic-close byte"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nowayout_close_behavior_never_writes_magic_close() {
        let path = tmp_path("nowayout");
        std::fs::write(&path, b"").unwrap();
        let file = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open test sink");
        let w = HwWatchdog {
            file,
            disarm_on_drop: AtomicBool::new(false),
            close_behavior: WatchdogCloseBehavior::NoWayOut,
        };

        w.arm_disarm_on_drop();
        drop(w);

        let contents = std::fs::read(&path).unwrap();
        assert!(
            contents.is_empty(),
            "nowayout devices cannot be disarmed by magic close"
        );
        let _ = std::fs::remove_file(&path);
    }
}
