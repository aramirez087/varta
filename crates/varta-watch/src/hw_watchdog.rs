//! Hardware watchdog driver for `varta-watch`.
//!
//! Opens a watchdog device (typically `/dev/watchdog`) for writing and kicks
//! it once per poll iteration.  If the observer crashes or hangs the device
//! is not kicked, the kernel watchdog timer expires, and the host reboots.
//!
//! **Magic close:** on a clean shutdown (SIGTERM/SIGINT followed by graceful
//! exit) [`HwWatchdog::arm_disarm_on_drop`] is called before the value is
//! dropped.  The `Drop` impl writes the magic byte `'V'` (the POSIX "magic
//! close" sequence) which tells the kernel to disarm the watchdog instead of
//! rebooting.  If the process crashes without calling `arm_disarm_on_drop`,
//! the file is closed without `'V'` and the watchdog fires.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// Hardware watchdog driver for `varta-watch`.
///
/// Created via [`HwWatchdog::open`] and kicked once per poll iteration.
/// Uses magic-close semantics: call [`HwWatchdog::arm_disarm_on_drop`]
/// before dropping on a clean shutdown to send the `'V'` byte that
/// disarms the watchdog; omit it on the crash path to allow the kernel
/// to reboot.
pub struct HwWatchdog {
    file: File,
    /// Set by `arm_disarm_on_drop` when the observer is shutting down
    /// cleanly.  The `Drop` impl writes `'V'` only when this is true.
    disarm_on_drop: AtomicBool,
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
        if !file.metadata()?.file_type().is_char_device() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{}: hardware watchdog must be a character device",
                    path.display()
                ),
            ));
        }
        Ok(Self {
            file,
            disarm_on_drop: AtomicBool::new(false),
        })
    }

    /// Write one byte to the device, resetting the hardware timer.
    ///
    /// Errors are intentionally ignored — a single missed kick is tolerable;
    /// persistent failures will cause the watchdog to fire naturally.
    pub fn kick(&mut self) {
        let _ = self.file.write_all(&[0u8]);
    }

    /// Signal that the next `Drop` should disarm the watchdog via magic close.
    ///
    /// Call this immediately before the observer exits cleanly (after the
    /// `SHUTDOWN` latch is observed to be true and the poll loop has exited).
    /// Do NOT call on the crash path — omitting the call keeps the watchdog
    /// armed so the kernel will reboot.
    pub fn arm_disarm_on_drop(&self) {
        self.disarm_on_drop.store(true, Ordering::Release);
    }
}

impl Drop for HwWatchdog {
    fn drop(&mut self) {
        if self.disarm_on_drop.load(Ordering::Acquire) {
            // Write the POSIX magic-close byte to disarm the watchdog.
            let _ = self.file.write_all(b"V");
        }
        // Whether or not we wrote 'V', the file is closed here.  If 'V' was
        // not written, the kernel watchdog timer is still running and will
        // trigger a reboot — which is the correct behaviour on a crash path.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn open_accepts_character_device() {
        let watchdog = HwWatchdog::open(Path::new("/dev/null"))
            .expect("/dev/null is a portable character-device test fixture");
        drop(watchdog);
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
}
