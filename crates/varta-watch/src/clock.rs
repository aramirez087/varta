//! Configurable monotonic clock for stall-threshold accounting.
//!
//! The observer's stall detector decides "this PID has been silent for too
//! long" by subtracting a recorded `last_beat_ns` from a "now_ns" derived
//! from a monotonic clock.  Which kernel clock backs that "now_ns" depends
//! on the deployment profile:
//!
//! - **SRE / cloud (default `monotonic`)** — `CLOCK_MONOTONIC`.  Pauses
//!   when the host is suspended (live migration, hypervisor pause,
//!   `systemctl suspend` for maintenance).  This is the right semantic
//!   for fleet observability: a 30-minute host suspend should NOT fire a
//!   stall alert across every agent on that host.
//!
//! - **Medical / embedded (`boottime`, Linux only)** — `CLOCK_BOOTTIME`.
//!   Continues to advance during suspend.  This is the right semantic for
//!   battery-conscious clinical devices (insulin pumps, holter monitors)
//!   that aggressively suspend to sleep: a 4-hour suspend IS a 4-hour
//!   silence and MUST register as a stall on wake-up.  See
//!   `docs/architecture/safety-profiles.md` for the deployment matrix.
//!
//! macOS / BSD have no equivalent of `CLOCK_BOOTTIME` — `CLOCK_UPTIME_RAW`
//! on Darwin *excludes* suspend (opposite semantics).  `boottime` is
//! therefore rejected at startup on every non-Linux target.  Choosing
//! `boottime` on macOS would silently break the medical-device contract;
//! a hard error makes the misconfiguration visible.
//!
//! # Implementation
//!
//! [`Clock`] is a concrete struct, not a trait.  The single-threaded
//! observer poll loop calls [`Clock::now_ns`] once per tick; a vtable
//! indirection would add a per-tick predicted branch with no benefit, and
//! parameterising every downstream type on a `Clock` generic would
//! explode the signature surface.  The internal `match self.source` is
//! one well-predicted branch on each call.
//!
//! Raw `extern "C" clock_gettime(2)` is used rather than the `libc` crate
//! — same pattern as the project's `getrandom` (cerebrum 2026-05-12) and
//! `sigaction` (main.rs:54) FFI sites.  No registry dependency.

use std::io;

/// `CLOCK_MONOTONIC` is NOT a POSIX-mandated numeric constant — values
/// differ across kernels. Source-of-truth per platform:
///
/// - Linux:    `<bits/time.h>` — `CLOCK_MONOTONIC = 1`
/// - macOS/iOS: `<sys/_types/_clock_id.h>` — `_CLOCK_MONOTONIC = 6` (10.12+)
/// - FreeBSD:  `<sys/_clock_id.h>` — `CLOCK_MONOTONIC = 4`
/// - NetBSD/OpenBSD/DragonFly: same as FreeBSD (4)
#[cfg(target_os = "linux")]
const CLOCK_MONOTONIC: i32 = 1;
#[cfg(any(target_os = "macos", target_os = "ios"))]
const CLOCK_MONOTONIC: i32 = 6;
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
const CLOCK_MONOTONIC: i32 = 4;
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
)))]
const CLOCK_MONOTONIC: i32 = 1; // Last-resort default — most kernels follow Linux.

/// Linux: `<bits/time.h>` — `CLOCK_BOOTTIME` (since 2.6.39). Like
/// `CLOCK_MONOTONIC`, but also includes time the system has been
/// suspended. Linux-only — do NOT use on other targets.
#[cfg(target_os = "linux")]
const CLOCK_BOOTTIME: i32 = 7;

/// Kernel clock backing stall-threshold accounting.
///
/// Wire-format and observer semantics are unchanged; only the kernel
/// clock that drives "now_ns" is configurable.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ClockSource {
    /// `CLOCK_MONOTONIC` — pauses on system suspend. SRE default.
    #[default]
    Monotonic,
    /// `CLOCK_BOOTTIME` (Linux only) — advances through suspend.
    /// Medical / embedded deployment.
    Boottime,
}

impl std::fmt::Display for ClockSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClockSource::Monotonic => f.write_str("monotonic"),
            ClockSource::Boottime => f.write_str("boottime"),
        }
    }
}

impl std::str::FromStr for ClockSource {
    type Err = ClockSourceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "monotonic" => Ok(ClockSource::Monotonic),
            "boottime" => Ok(ClockSource::Boottime),
            other => Err(ClockSourceParseError {
                raw: other.to_string(),
            }),
        }
    }
}

/// Parse error surfaced when `--clock-source` is given an unknown value.
#[derive(Debug)]
pub struct ClockSourceParseError {
    /// The raw value the operator supplied.
    pub raw: String,
}

impl std::fmt::Display for ClockSourceParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown clock source {:?}: expected one of `monotonic`, `boottime`",
            self.raw
        )
    }
}

impl std::error::Error for ClockSourceParseError {}

/// Numeric tag used by the self-watchdog `static CLOCK_SOURCE: AtomicU8`
/// in `main.rs` to communicate the chosen source to the background
/// watchdog thread without an `Arc`.
impl ClockSource {
    /// 0 → `Monotonic`, 1 → `Boottime`. Stable across versions.
    pub fn as_u8(self) -> u8 {
        match self {
            ClockSource::Monotonic => 0,
            ClockSource::Boottime => 1,
        }
    }

    /// Inverse of [`Self::as_u8`]; unknown values fall back to `Monotonic`
    /// (defensive — the only writer is `as_u8` on the same enum).
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            1 => ClockSource::Boottime,
            _ => ClockSource::Monotonic,
        }
    }

    /// Kernel `clk_id` argument for `clock_gettime(2)`.
    ///
    /// Returns `None` when the source is unsupported on the current
    /// platform (e.g. `Boottime` on macOS).
    pub fn clk_id(self) -> Option<i32> {
        match self {
            ClockSource::Monotonic => Some(CLOCK_MONOTONIC),
            #[cfg(target_os = "linux")]
            ClockSource::Boottime => Some(CLOCK_BOOTTIME),
            #[cfg(not(target_os = "linux"))]
            ClockSource::Boottime => None,
        }
    }
}

/// Failures surfaced by [`Clock::new`].
#[derive(Debug)]
pub enum ClockError {
    /// The requested `ClockSource` has no kernel equivalent on this
    /// platform.  Currently fires for `Boottime` on every non-Linux
    /// target.
    Unsupported {
        /// The source the operator requested.
        source: ClockSource,
        /// `std::env::consts::OS` at compile time, for the error message.
        platform: &'static str,
    },
    /// `clock_gettime(2)` returned an OS-level error.
    Os(io::Error),
}

impl std::fmt::Display for ClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClockError::Unsupported { source, platform } => write!(
                f,
                "clock source `{source}` is not supported on `{platform}` \
                 (no equivalent of Linux CLOCK_BOOTTIME)"
            ),
            ClockError::Os(e) => write!(f, "clock_gettime: {e}"),
        }
    }
}

impl std::error::Error for ClockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClockError::Unsupported { .. } => None,
            ClockError::Os(e) => Some(e),
        }
    }
}

impl From<ClockError> for io::Error {
    fn from(e: ClockError) -> Self {
        match e {
            ClockError::Os(inner) => inner,
            ClockError::Unsupported { .. } => {
                io::Error::new(io::ErrorKind::Unsupported, e.to_string())
            }
        }
    }
}

// --- Raw clock_gettime FFI ---------------------------------------------------
//
// Per-platform `struct timespec`. POSIX specifies `tv_sec: time_t,
// tv_nsec: long`; `time_t` and `long` widths differ per OS.

#[cfg(target_os = "linux")]
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[repr(C)]
struct Timespec {
    /// `time_t` on Darwin is `__darwin_time_t = long = i64` on 64-bit.
    tv_sec: i64,
    /// `long` on Darwin is i64 on 64-bit (LP64). `<sys/_types/_timespec.h>`
    /// defines `tv_nsec` as `long`, matching `tv_sec` width.
    tv_nsec: i64,
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
)))]
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
}

/// Read the requested kernel clock and return nanoseconds since its
/// epoch as a `u64`.
///
/// The caller is responsible for clamping forward-monotonic over a baseline;
/// this helper just exposes the raw clock value.  Used both by [`Clock`]
/// (observer hot path) and by the self-watchdog thread in `main.rs`.
pub fn clock_gettime_raw(clk_id: i32) -> io::Result<u64> {
    let mut tp = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `tp` is a valid, exclusively-owned `Timespec` and remains in
    // scope for the duration of the call. `clock_gettime` writes to `tp`
    // only on success; the caller has exclusive `&mut` access through the
    // raw pointer here.
    let rc = unsafe { clock_gettime(clk_id, &mut tp as *mut Timespec) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // `tv_sec` and `tv_nsec` are non-negative for any reasonable clock_id.
    // Cast carefully and saturate to u64::MAX on overflow.
    let sec = if tp.tv_sec < 0 {
        0u64
    } else {
        tp.tv_sec as u64
    };
    let nsec = if tp.tv_nsec < 0 {
        0u64
    } else {
        tp.tv_nsec as u64
    };
    let total = sec
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nsec))
        .unwrap_or(u64::MAX);
    Ok(total)
}

/// Monotonic clock anchored to an observer-startup baseline.
///
/// Mirrors the semantics of `Observer::start.elapsed().as_nanos()` so
/// downstream stall arithmetic is unchanged when the operator does not
/// pass `--clock-source`.
pub struct Clock {
    source: ClockSource,
    start_ns: u64,
}

impl Clock {
    /// Build a `Clock` backed by `source`.
    ///
    /// Performs one `clock_gettime(2)` call to anchor `start_ns`. Returns
    /// `ClockError::Unsupported` when `source = Boottime` on a non-Linux
    /// target.
    pub fn new(source: ClockSource) -> Result<Self, ClockError> {
        let clk_id = source.clk_id().ok_or(ClockError::Unsupported {
            source,
            platform: std::env::consts::OS,
        })?;
        let start_ns = clock_gettime_raw(clk_id).map_err(ClockError::Os)?;
        Ok(Self { source, start_ns })
    }

    /// One-call probe: surface `Unsupported` / OS errors at startup
    /// before threading the clock through `Observer`.
    pub fn probe(source: ClockSource) -> Result<(), ClockError> {
        Self::new(source).map(|_| ())
    }

    /// Nanoseconds since this `Clock`'s baseline. Saturates to `u64::MAX`
    /// on a wildly long-running process (>584 years).
    pub fn now_ns(&self) -> u64 {
        let clk_id = match self.source.clk_id() {
            Some(id) => id,
            // Unreachable: `new` rejected the unsupported case.
            None => return 0,
        };
        let raw = clock_gettime_raw(clk_id).unwrap_or(self.start_ns);
        raw.saturating_sub(self.start_ns)
    }

    /// Inspect the configured source (used by tests and by `main.rs` to
    /// publish into the watchdog atomic).
    pub fn source(&self) -> ClockSource {
        self.source
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse_monotonic_and_boottime() {
        assert_eq!(
            ClockSource::from_str("monotonic").unwrap(),
            ClockSource::Monotonic
        );
        assert_eq!(
            ClockSource::from_str("boottime").unwrap(),
            ClockSource::Boottime
        );
    }

    #[test]
    fn parse_unknown_value_errors() {
        let e = ClockSource::from_str("wallclock").unwrap_err();
        assert_eq!(e.raw, "wallclock");
    }

    #[test]
    fn display_round_trip() {
        for src in [ClockSource::Monotonic, ClockSource::Boottime] {
            let s = format!("{src}");
            assert_eq!(ClockSource::from_str(&s).unwrap(), src);
        }
    }

    #[test]
    fn as_u8_from_u8_round_trip() {
        for src in [ClockSource::Monotonic, ClockSource::Boottime] {
            assert_eq!(ClockSource::from_u8(src.as_u8()), src);
        }
    }

    #[test]
    fn monotonic_forward_only() {
        let clk = Clock::new(ClockSource::Monotonic).expect("CLOCK_MONOTONIC must be supported");
        let a = clk.now_ns();
        let b = clk.now_ns();
        assert!(b >= a, "monotonic clock regressed: {a} -> {b}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn boottime_forward_only_on_linux() {
        let clk = Clock::new(ClockSource::Boottime).expect("CLOCK_BOOTTIME must work on Linux");
        let a = clk.now_ns();
        let b = clk.now_ns();
        assert!(b >= a, "boottime clock regressed: {a} -> {b}");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn boottime_rejected_on_unsupported_platform() {
        match Clock::new(ClockSource::Boottime) {
            Err(ClockError::Unsupported { source, .. }) => {
                assert_eq!(source, ClockSource::Boottime);
            }
            Err(other) => panic!("expected Unsupported, got {other:?}"),
            Ok(_) => panic!("expected Boottime to be rejected on non-Linux"),
        }
    }

    #[test]
    fn now_ns_baseline_starts_near_zero() {
        let clk = Clock::new(ClockSource::Monotonic).unwrap();
        let first = clk.now_ns();
        // First call shouldn't be wildly in the future — at most a few
        // milliseconds of slack on cold startup.
        assert!(
            first < 1_000_000_000,
            "first now_ns reading too large: {first}"
        );
    }
}
