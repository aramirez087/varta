//! systemd `sd_notify` integration for `varta-watch`.
//!
//! Sends `READY=1`, `WATCHDOG=1`, and `STOPPING=1` messages to the systemd
//! service manager via `$NOTIFY_SOCKET` when present. All failures are
//! non-fatal — the observer continues running whether or not the manager
//! receives the messages.
//!
//! Supports both path-based sockets and Linux abstract-namespace sockets
//! (`$NOTIFY_SOCKET` starting with `@`).  Abstract-namespace handling
//! requires a raw `connect(2)` syscall because `std::os::unix::net` cannot
//! represent a `sun_path` with a leading NUL byte portably; the call is
//! wrapped in a tightly-scoped `unsafe` block with a safety justification.

use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant};

/// systemd `sd_notify` client for `varta-watch`.
///
/// Created via [`SdNotify::from_env`] and used to signal readiness,
/// watchdog liveness, and shutdown intent to the service manager.
///
/// `WATCHDOG=1` emission is intentionally split out into a separate
/// [`WatchdogNotifier`] that lives on the self-watchdog thread (see H5 in
/// `docs/architecture/observer-liveness.md`).  Use [`SdNotify::take_watchdog_notifier`]
/// to extract the watchdog half before spawning the thread; the original
/// `SdNotify` retains `READY` / `STOPPING` capability on the main thread.
pub struct SdNotify {
    sock: Option<UnixDatagram>,
    /// Half of WATCHDOG_USEC — notify at this cadence.  Taken by
    /// `take_watchdog_notifier`; if `None`, `watchdog_tick` is a no-op.
    watchdog_interval: Option<Duration>,
    last_notify: Instant,
}

/// WATCHDOG=1 emitter owned by the self-watchdog thread.
///
/// Holds an independent `dup(2)`-ed copy of the notify socket so the main
/// thread can keep `SdNotify` for lifecycle events without sharing a `Mutex`.
/// `tick()` is rate-limited by the original `$WATCHDOG_USEC / 2` half-interval.
pub struct WatchdogNotifier {
    sock: UnixDatagram,
    interval: Duration,
    last_notify: Instant,
}

impl SdNotify {
    /// Initialise from the process environment.
    ///
    /// Reads `$NOTIFY_SOCKET` (path or `@`-prefixed abstract name) and
    /// `$WATCHDOG_USEC`. Returns a no-op instance when the variable is unset
    /// or the socket cannot be opened.
    pub fn from_env() -> Self {
        let sock = std::env::var("NOTIFY_SOCKET").ok().and_then(|addr| {
            open_notify_socket(&addr)
                .map_err(|e| {
                    crate::varta_warn!("sd_notify: could not open {addr:?}: {e}");
                })
                .ok()
        });

        let watchdog_interval = std::env::var("WATCHDOG_USEC")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&us| us > 0)
            .map(|us| Duration::from_micros(us / 2));

        Self {
            sock,
            watchdog_interval,
            last_notify: Instant::now(),
        }
    }

    /// Send `READY=1\n` to the service manager.
    pub fn ready(&mut self) {
        self.send(b"READY=1\n");
    }

    /// Send `WATCHDOG=1\n` if the watchdog half-interval has elapsed since the
    /// last notification. No-op when `$WATCHDOG_USEC` is unset OR when
    /// `take_watchdog_notifier` has already handed off the emission to the
    /// self-watchdog thread (the canonical configuration — keeping this
    /// method behavior allows tests and callers that have not yet been
    /// migrated to compile without change).
    pub fn watchdog_tick(&mut self) {
        if let Some(interval) = self.watchdog_interval {
            if self.last_notify.elapsed() >= interval {
                self.send(b"WATCHDOG=1\n");
                self.last_notify = Instant::now();
            }
        }
    }

    /// Send `STOPPING=1\n` to the service manager.
    pub fn stopping(&mut self) {
        self.send(b"STOPPING=1\n");
    }

    /// Hand `WATCHDOG=1` emission off to the self-watchdog thread.
    ///
    /// Returns `None` when `$NOTIFY_SOCKET` is unset, `$WATCHDOG_USEC` is
    /// unset / zero, or the socket cannot be `dup(2)`-ed.  The returned
    /// [`WatchdogNotifier`] owns an independent file descriptor; after the
    /// call, `self.watchdog_tick()` becomes a no-op so the two halves can
    /// never double-emit.
    ///
    /// H5: with this split, the watchdog thread is the sole source of
    /// `WATCHDOG=1` notifications.  If the thread dies, `WATCHDOG=1` stops
    /// arriving and systemd's `WatchdogSec=` fires — closing the silent
    /// watchdog-thread-death gap that existed when emission lived on the
    /// main loop.
    pub fn take_watchdog_notifier(&mut self) -> Option<WatchdogNotifier> {
        let interval = self.watchdog_interval.take()?;
        let sock = self.sock.as_ref()?.try_clone().ok()?;
        Some(WatchdogNotifier {
            sock,
            interval,
            last_notify: self.last_notify,
        })
    }

    /// Returns `Some(half_interval)` when `$WATCHDOG_USEC` was configured at
    /// startup and not yet taken via `take_watchdog_notifier`.  Used by the
    /// daemon entry to auto-enable the self-watchdog thread when systemd
    /// is supervising us but the operator did not pass `--self-watchdog-secs`.
    pub fn watchdog_half_interval(&self) -> Option<Duration> {
        self.watchdog_interval
    }

    fn send(&self, msg: &[u8]) {
        if let Some(ref sock) = self.sock {
            let _ = sock.send(msg);
        }
    }
}

impl WatchdogNotifier {
    /// Send `WATCHDOG=1\n` if the half-interval has elapsed since the last
    /// send.  Failures are silently dropped — same contract as
    /// `SdNotify::send`.
    pub fn tick(&mut self) {
        if self.last_notify.elapsed() >= self.interval {
            let _ = self.sock.send(b"WATCHDOG=1\n");
            self.last_notify = Instant::now();
        }
    }

    /// Half of `$WATCHDOG_USEC` — the cadence at which `tick` will actually
    /// emit.  Exposed so the watchdog thread can pick a sleep period
    /// proportional to the cadence (`half_interval / 2`, clamped) instead
    /// of a fixed 500 ms that would miss tight `WatchdogSec` settings.
    pub fn half_interval(&self) -> Duration {
        self.interval
    }
}

/// Open an unbound `UnixDatagram` and connect it to `addr`.
///
/// If `addr` starts with `@` it is treated as a Linux abstract-namespace
/// socket: a `sockaddr_un` is built with `sun_path[0] = 0` followed by the
/// remaining bytes, then `connect(2)` is called via FFI.  This is the only
/// way to reach an abstract socket from safe Rust on stable.
fn open_notify_socket(addr: &str) -> std::io::Result<UnixDatagram> {
    let sock = UnixDatagram::unbound()?;
    if let Some(name) = addr.strip_prefix('@') {
        // SAFETY: we call connect(2) with a well-formed sockaddr_un that we
        // build here.  The socket fd is valid (just created above), the
        // address buffer is on the stack and fully initialised before the
        // call, and the length is computed precisely from the struct size.
        // The only `unsafe` operation is the FFI call itself.
        connect_abstract(&sock, name)?;
    } else {
        sock.connect(addr)?;
    }
    Ok(sock)
}

#[cfg(unix)]
fn connect_abstract(sock: &UnixDatagram, name: &str) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    // Abstract socket path: sun_path[0] = '\0', followed by the name bytes.
    // The kernel identifies the socket by the full byte sequence including the
    // leading NUL.
    let name_bytes = name.as_bytes();
    // PATH_MAX for sun_path is 108 bytes on Linux.
    if name_bytes.len() >= 108 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET abstract name too long",
        ));
    }

    // Construct sockaddr_un manually. The struct has two fields on Linux:
    //   sa_family_t sun_family  (u16, AF_UNIX = 1)
    //   char        sun_path[108]
    // Total size = 110 bytes.  We zero-initialise then write the fields.
    let mut addr_buf = [0u8; 110];
    // sun_family = AF_UNIX = 1, little-endian
    addr_buf[0] = 1;
    addr_buf[1] = 0;
    // sun_path[0] = 0 (abstract marker), then name bytes
    addr_buf[2] = 0;
    addr_buf[3..3 + name_bytes.len()].copy_from_slice(name_bytes);
    // addrlen = offsetof(sun_path) + 1 (NUL) + name length
    let addrlen = (2u32 + 1 + name_bytes.len() as u32) as libc_socklen_t;

    extern "C" {
        fn connect(
            sockfd: std::ffi::c_int,
            addr: *const std::ffi::c_void,
            addrlen: libc_socklen_t,
        ) -> std::ffi::c_int;
    }

    // SAFETY: `sock` fd is valid and open; `addr_buf` is fully initialised
    // above; `addrlen` is the exact byte count we populated.
    let rc = unsafe {
        connect(
            sock.as_raw_fd(),
            addr_buf.as_ptr() as *const std::ffi::c_void,
            addrlen,
        )
    };
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn connect_abstract(_sock: &UnixDatagram, _name: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "abstract sockets are only available on Linux",
    ))
}

// `socklen_t` is `u32` on Linux/macOS.
#[allow(non_camel_case_types)]
type libc_socklen_t = u32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_op_when_env_unset() {
        // Temporarily unset NOTIFY_SOCKET so this test is hermetic.
        let prev = std::env::var("NOTIFY_SOCKET").ok();
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        let mut n = SdNotify::from_env();
        // None of these should panic.
        n.ready();
        n.watchdog_tick();
        n.stopping();
        assert!(n.sock.is_none());
        if let Some(v) = prev {
            unsafe { std::env::set_var("NOTIFY_SOCKET", v) };
        }
    }

    #[test]
    fn watchdog_tick_does_not_send_before_interval() {
        let mut n = SdNotify {
            sock: None,
            watchdog_interval: Some(Duration::from_secs(60)),
            last_notify: Instant::now(),
        };
        // Should not send (interval not elapsed) — confirmed by no panic on None sock.
        n.watchdog_tick();
    }

    /// `take_watchdog_notifier` must zero the original's interval so a
    /// stale `watchdog_tick` call cannot double-emit alongside the
    /// background thread.  Returning `None` here is also the correct
    /// behavior on the second call.
    #[test]
    fn take_watchdog_notifier_disarms_main_thread_emission() {
        let mut n = SdNotify {
            sock: None,
            watchdog_interval: Some(Duration::from_micros(100)),
            last_notify: Instant::now(),
        };
        // First take returns `None` because `sock` is None — but the
        // interval is consumed regardless (no point handing out a
        // notifier whose socket is absent; the daemon would auto-skip
        // the watchdog thread in that case).
        let taken = n.take_watchdog_notifier();
        assert!(taken.is_none());
        assert!(
            n.watchdog_half_interval().is_none(),
            "take_watchdog_notifier must consume the interval even when sock is absent",
        );
        // Subsequent watchdog_tick must be a no-op.
        n.watchdog_tick();
    }

    /// With a live socket the notifier comes back populated and ticks fire
    /// onto the dup-ed fd; the original SdNotify retains lifecycle channels
    /// (READY / STOPPING) but no longer emits WATCHDOG=1 itself.
    #[test]
    fn take_watchdog_notifier_clones_socket_and_emits_independently() {
        use std::os::unix::net::UnixDatagram;
        use std::time::Duration;

        // Build a socketpair: listener side stays here, sender side goes
        // into SdNotify.  No filesystem entry — keeps the test hermetic
        // across parallel runs (no umask interaction; cerebrum 2026-05-13).
        let (listener, sender) =
            UnixDatagram::pair().expect("socketpair for hermetic notify test");
        listener
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set read timeout");

        let mut n = SdNotify {
            sock: Some(sender),
            watchdog_interval: Some(Duration::from_micros(0)),
            last_notify: Instant::now() - Duration::from_secs(1),
        };

        let mut wdt = n
            .take_watchdog_notifier()
            .expect("take_watchdog_notifier when sock + interval are set");

        // The original is disarmed.
        assert!(n.watchdog_half_interval().is_none());

        // Send READY=1 through the original SdNotify (still has its own fd).
        n.ready();
        let mut buf = [0u8; 64];
        let nread = listener.recv(&mut buf).expect("recv READY=1 from main fd");
        assert_eq!(&buf[..nread], b"READY=1\n");

        // Tick on the watchdog notifier sends WATCHDOG=1 through the dup-ed fd.
        wdt.tick();
        let nread = listener.recv(&mut buf).expect("recv WATCHDOG=1 from dup fd");
        assert_eq!(&buf[..nread], b"WATCHDOG=1\n");

        // STOPPING=1 from the original SdNotify still works.
        n.stopping();
        let nread = listener.recv(&mut buf).expect("recv STOPPING=1 from main fd");
        assert_eq!(&buf[..nread], b"STOPPING=1\n");
    }
}
