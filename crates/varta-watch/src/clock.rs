//! Configurable monotonic clock for stall-threshold accounting.
//!
//! The observer's stall detector decides "this PID has been silent for too
//! long" by subtracting a recorded `last_beat_ns` from a "now_ns" derived
//! from a monotonic clock.  Which kernel clock backs that "now_ns" depends
//! on the deployment profile.
//!
//! # Per-platform semantics
//!
//! `CLOCK_MONOTONIC` is not a POSIX-mandated numeric constant, and its
//! behavior across system suspend / sleep differs by kernel. The shipped
//! clock sources are:
//!
//! - **`monotonic` (default, all platforms)** — `CLOCK_MONOTONIC`.
//!   - Linux (`clk_id = 1`): pauses while the host is suspended.
//!     NTP-slewable.
//!   - FreeBSD / DragonFly (`clk_id = 4`): pauses while the host is
//!     suspended. Linux-compatible semantics.
//!   - NetBSD / OpenBSD (`clk_id = 3`): pauses while the host is
//!     suspended. (clk_id 4 is `CLOCK_THREAD_CPUTIME_ID` on OpenBSD and
//!     unassigned on NetBSD — see the `CLOCK_MONOTONIC` constant below.)
//!   - macOS / iOS (`clk_id = 6`): backed by `mach_absolute_time`. Pauses
//!     during sleep on 10.12 (Sierra) and later — the same observable
//!     semantics as Linux. The underlying tick rate is host-dependent
//!     (≈24 MHz on Apple Silicon, ≈1 GHz on Intel); `clock_gettime`
//!     reports nanoseconds regardless, so downstream stall arithmetic
//!     is unaffected by the hardware difference.
//!
//!   `monotonic` is the right semantic for fleet observability: a
//!   30-minute host suspend should NOT fire a stall alert across every
//!   agent on that host.
//!
//! - **`boottime` (Linux only)** — `CLOCK_BOOTTIME` (`clk_id = 7`).
//!   Continues to advance during suspend.  This is the right semantic for
//!   battery-conscious clinical devices (insulin pumps, holter monitors)
//!   that aggressively suspend to sleep: a 4-hour suspend IS a 4-hour
//!   silence and MUST register as a stall on wake-up. Rejected at startup
//!   on every non-Linux target.
//!
//! - **`monotonic-raw` (macOS / iOS only)** — `CLOCK_MONOTONIC_RAW`
//!   (`clk_id = 4`), backed by `mach_continuous_time`. Continues to
//!   advance during sleep — the Darwin equivalent of Linux's
//!   `CLOCK_BOOTTIME`. This is the right choice for macOS-hosted clinical
//!   devices or any deployment where "wall-clock silence including sleep"
//!   is the stall semantic. Rejected at startup on every non-macOS
//!   target; Linux operators should use `boottime` and BSD operators have
//!   no equivalent. (Note: Linux also defines `CLOCK_MONOTONIC_RAW`, but
//!   there it merely opts out of NTP slewing — it still pauses during
//!   suspend. Exposing it on Linux would invite a name collision with
//!   different semantics, so the variant is structurally macOS-only.)
//!
//! See `book/src/architecture/safety-profiles.md` for the deployment
//! matrix.
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
/// - FreeBSD/DragonFly: `<sys/_clock_id.h>` — `CLOCK_MONOTONIC = 4`
/// - NetBSD `<sys/time.h>` / OpenBSD `<sys/_time.h>` — `CLOCK_MONOTONIC = 3`
///   (clk_id 4 is `CLOCK_THREAD_CPUTIME_ID` on OpenBSD, unassigned on NetBSD)
#[cfg(target_os = "linux")]
const CLOCK_MONOTONIC: i32 = 1;
#[cfg(any(target_os = "macos", target_os = "ios"))]
const CLOCK_MONOTONIC: i32 = 6;
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
const CLOCK_MONOTONIC: i32 = 4;
// NetBSD/OpenBSD number CLOCK_MONOTONIC as 3, NOT 4 like FreeBSD. clk_id 4 is
// `CLOCK_THREAD_CPUTIME_ID` on OpenBSD (per-thread on-CPU time — it advances
// only while the single observer poll thread is actually scheduled, so the
// silence delta `now_ns - last_beat_ns` never reaches `threshold_ns` and
// stalls are silently never detected) and is unassigned on NetBSD (where
// `clock_gettime(4)` returns EINVAL, so the observer fails to start). Using 4
// here is a brick on NetBSD and a silent missed-stall on OpenBSD.
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
const CLOCK_MONOTONIC: i32 = 3;
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

/// Darwin: `<sys/_types/_clock_id.h>` — `_CLOCK_MONOTONIC_RAW = 4` (10.12+),
/// backed by `mach_continuous_time`. Unlike Linux's same-numbered constant
/// (which still pauses during suspend) this advances through sleep — the
/// Darwin equivalent of Linux's `CLOCK_BOOTTIME`. The variant is exposed to
/// operators only on macOS / iOS; using it on any other platform is a hard
/// error at startup.
#[cfg(any(target_os = "macos", target_os = "ios"))]
const CLOCK_MONOTONIC_RAW: i32 = 4;

/// Kernel clock backing stall-threshold accounting.
///
/// Wire-format and observer semantics are unchanged; only the kernel
/// clock that drives "now_ns" is configurable.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ClockSource {
    /// `CLOCK_MONOTONIC` — pauses on system suspend. SRE default,
    /// available on every supported platform.
    #[default]
    Monotonic,
    /// `CLOCK_BOOTTIME` (Linux only) — advances through suspend.
    /// Medical / embedded deployment.
    Boottime,
    /// `CLOCK_MONOTONIC_RAW` (macOS / iOS only) — backed by
    /// `mach_continuous_time`; advances through sleep. Darwin equivalent
    /// of Linux's `Boottime`. Rejected at startup on non-Darwin targets.
    MonotonicRaw,
}

impl std::fmt::Display for ClockSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClockSource::Monotonic => f.write_str("monotonic"),
            ClockSource::Boottime => f.write_str("boottime"),
            ClockSource::MonotonicRaw => f.write_str("monotonic-raw"),
        }
    }
}

impl std::str::FromStr for ClockSource {
    type Err = ClockSourceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "monotonic" => Ok(ClockSource::Monotonic),
            "boottime" => Ok(ClockSource::Boottime),
            "monotonic-raw" | "monotonic_raw" => Ok(ClockSource::MonotonicRaw),
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
            "unknown clock source {:?}: expected one of `monotonic`, `boottime`, `monotonic-raw`",
            self.raw
        )
    }
}

impl std::error::Error for ClockSourceParseError {}

/// Stable numeric (de)serialization for [`ClockSource`] — a compact `u8`
/// encoding suitable for `AtomicU8`/cross-thread publication or persistence
/// without an `Arc`.
impl ClockSource {
    /// 0 → `Monotonic`, 1 → `Boottime`, 2 → `MonotonicRaw`. Stable across
    /// versions; only ever produced by `as_u8` on the same enum.
    pub fn as_u8(self) -> u8 {
        match self {
            ClockSource::Monotonic => 0,
            ClockSource::Boottime => 1,
            ClockSource::MonotonicRaw => 2,
        }
    }

    /// Inverse of [`Self::as_u8`]; unknown values fall back to `Monotonic`
    /// (defensive — the only writer is `as_u8` on the same enum).
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            1 => ClockSource::Boottime,
            2 => ClockSource::MonotonicRaw,
            _ => ClockSource::Monotonic,
        }
    }

    /// Kernel `clk_id` argument for `clock_gettime(2)`.
    ///
    /// Returns `None` when the source is unsupported on the current
    /// platform (e.g. `Boottime` on macOS, `MonotonicRaw` on Linux/BSD).
    pub fn clk_id(self) -> Option<i32> {
        match self {
            ClockSource::Monotonic => Some(CLOCK_MONOTONIC),
            #[cfg(target_os = "linux")]
            ClockSource::Boottime => Some(CLOCK_BOOTTIME),
            #[cfg(not(target_os = "linux"))]
            ClockSource::Boottime => None,
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            ClockSource::MonotonicRaw => Some(CLOCK_MONOTONIC_RAW),
            #[cfg(not(any(target_os = "macos", target_os = "ios")))]
            ClockSource::MonotonicRaw => None,
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
            ClockError::Unsupported { source, platform } => {
                let hint = match source {
                    ClockSource::Boottime => {
                        " (Linux only; on macOS use `monotonic-raw` for advance-through-sleep semantics)"
                    }
                    ClockSource::MonotonicRaw => {
                        " (macOS / iOS only; on Linux use `boottime` for advance-through-sleep semantics)"
                    }
                    ClockSource::Monotonic => "",
                };
                write!(
                    f,
                    "clock source `{source}` is not supported on `{platform}`{hint}"
                )
            }
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
    fn parse_all_clock_source_variants() {
        assert_eq!(
            ClockSource::from_str("monotonic").unwrap(),
            ClockSource::Monotonic
        );
        assert_eq!(
            ClockSource::from_str("boottime").unwrap(),
            ClockSource::Boottime
        );
        assert_eq!(
            ClockSource::from_str("monotonic-raw").unwrap(),
            ClockSource::MonotonicRaw
        );
        // Underscore spelling is accepted as a convenience.
        assert_eq!(
            ClockSource::from_str("monotonic_raw").unwrap(),
            ClockSource::MonotonicRaw
        );
    }

    #[test]
    fn parse_unknown_value_errors() {
        let e = ClockSource::from_str("wallclock").unwrap_err();
        assert_eq!(e.raw, "wallclock");
    }

    #[test]
    fn display_round_trip() {
        for src in [
            ClockSource::Monotonic,
            ClockSource::Boottime,
            ClockSource::MonotonicRaw,
        ] {
            let s = format!("{src}");
            assert_eq!(ClockSource::from_str(&s).unwrap(), src);
        }
    }

    #[test]
    fn as_u8_from_u8_round_trip() {
        for src in [
            ClockSource::Monotonic,
            ClockSource::Boottime,
            ClockSource::MonotonicRaw,
        ] {
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

    /// The numeric `clk_id` backing `Monotonic` is platform-specific and is
    /// NOT caught by `monotonic_forward_only`: a wrong-but-forward clock
    /// (e.g. OpenBSD's `CLOCK_THREAD_CPUTIME_ID = 4`) passes that test while
    /// silently mis-clocking stall detection, and NetBSD's missing clk_id 4
    /// would only fail at `Clock::new`. Pin the integer per platform so the
    /// constant cannot drift back to a wrong value (the regression guard for
    /// the FreeBSD-assumed BSD `clk_id`).
    #[test]
    fn monotonic_clk_id_matches_platform() {
        #[cfg(target_os = "linux")]
        let expected = 1;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let expected = 6;
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        let expected = 4;
        #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
        let expected = 3;
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "openbsd",
        )))]
        let expected = 1; // last-resort default — most kernels follow Linux

        assert_eq!(
            ClockSource::Monotonic.clk_id(),
            Some(expected),
            "Monotonic clk_id drifted from the per-platform CLOCK_MONOTONIC value"
        );
        assert_eq!(CLOCK_MONOTONIC, expected);
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

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn monotonic_raw_forward_only_on_macos() {
        let clk =
            Clock::new(ClockSource::MonotonicRaw).expect("CLOCK_MONOTONIC_RAW must work on macOS");
        let a = clk.now_ns();
        let b = clk.now_ns();
        assert!(b >= a, "monotonic-raw clock regressed: {a} -> {b}");
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn monotonic_raw_rejected_on_non_macos() {
        match Clock::new(ClockSource::MonotonicRaw) {
            Err(ClockError::Unsupported { source, .. }) => {
                assert_eq!(source, ClockSource::MonotonicRaw);
            }
            Err(other) => panic!("expected Unsupported, got {other:?}"),
            Ok(_) => panic!("expected MonotonicRaw to be rejected outside macOS / iOS"),
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
