//! Per-kind cooldown rate limiter for `varta-watch` diagnostic logging.
//!
//! Under a sustained flood of error conditions on the hot poll path
//! (e.g. a broken file-export sink, a wedged heartbeat file, or a noisy
//! `/metrics` serve error), the observer's poll tick would otherwise emit
//! one log message per beat, driving allocator pressure and stderr I/O on
//! the steady-state path.  This module implements a fixed-size token-bucket
//! table that suppresses repeat messages within a 1-second cooldown window
//! and appends a suppression summary on the next allowed emit.
//!
//! # Design
//!
//! * A `[BucketState; LogKind::COUNT]` array is stored behind a global
//!   `Mutex`.  No `HashMap` — the series set is fixed by the enum.
//! * Suppressed counts are cumulative and never reset; each emit that fires
//!   reports and resets only the `queued_drops` accumulated since the
//!   previous emit.
//! * The Prometheus counter `varta_log_suppressed_total{kind=...}` is
//!   derived from the `total_suppressed` field.  The PromExporter drains
//!   counts via [`LogRateLimiter::snapshot_totals`].

use std::sync::Mutex;

/// Categories of hot-path log events that may be rate-limited.
///
/// This enum is also used to index into the exporter's
/// `varta_log_suppressed_total{kind=...}` label set; add new variants at
/// the end (never reorder) and update [`LOG_KIND_LABELS`] in `exporter.rs`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogKind {
    /// `varta_error!("file export error: ...")` — fired every poll tick when
    /// the TSV file-exporter encounters an I/O error.
    FileExportIo = 0,
    /// `varta_warn!("recovery audit IO error: ...")` — fired each tick while
    /// the recovery audit-log sync fails.
    AuditIo = 1,
    /// `varta_error!("/metrics serve error: ...")` — fired per Prometheus
    /// scrape when the serve call fails.
    PromServe = 2,
    /// `varta_error!("heartbeat file write error: ...")` — fired each
    /// heartbeat-file interval on I/O failure.
    HeartbeatIo = 3,
    /// `varta_warn!("audit ring \u{2265} 75% full: drain not keeping up")`
    /// — fired when the audit-record ring crosses the 75% fill
    /// threshold (rising edge only; re-arms on falling back below).
    AuditRingWarn = 4,
    /// `varta_error!("audit ring \u{2265} 95% full: records will drop
    /// soon")` — fired when the audit-record ring crosses the 95% fill
    /// threshold.  One step short of `audit_dropped_total` incrementing.
    AuditRingCritical = 5,
}

impl LogKind {
    /// Total number of `LogKind` variants.  Used to size the bucket array.
    pub const COUNT: usize = 6;

    /// Stable numeric index for array lookups and Prometheus label ordering.
    #[inline]
    pub fn index(self) -> usize {
        self as usize
    }
}

/// Per-kind rate-limit state.
#[derive(Clone, Copy, Default)]
struct BucketState {
    /// Monotonic nanosecond timestamp of the most recent allowed emission.
    /// Zero means "never emitted" (first message of this kind is always
    /// allowed regardless of cooldown).
    last_emit_ns: u64,
    /// Messages suppressed since the last allowed emission.  Reset to zero
    /// after each allowed emission that appends the suppression summary.
    queued_drops: u64,
    /// Cumulative total of suppressed messages for this kind.  Monotonically
    /// non-decreasing; fed into `varta_log_suppressed_total`.
    total_suppressed: u64,
}

/// Global rate-limiter table, one bucket per [`LogKind`].
pub struct LogRateLimiter {
    buckets: [BucketState; LogKind::COUNT],
}

impl LogRateLimiter {
    const COOLDOWN_NS: u64 = 1_000_000_000; // 1 second

    const fn new() -> Self {
        Self {
            buckets: [BucketState {
                last_emit_ns: 0,
                queued_drops: 0,
                total_suppressed: 0,
            }; LogKind::COUNT],
        }
    }

    /// Check whether a message of `kind` should be emitted given the current
    /// monotonic time `now_ns`.
    ///
    /// Returns `Some(queued_drops)` when the message should be emitted —
    /// the caller should append "(suppressed N)" when `queued_drops > 0`.
    /// Returns `None` when the message is within the cooldown window; the
    /// suppression counters are updated internally.
    pub fn should_emit(&mut self, kind: LogKind, now_ns: u64) -> Option<u64> {
        let b = &mut self.buckets[kind.index()];
        if b.last_emit_ns == 0 || now_ns.saturating_sub(b.last_emit_ns) >= Self::COOLDOWN_NS {
            let drops = b.queued_drops;
            b.last_emit_ns = now_ns;
            b.queued_drops = 0;
            Some(drops)
        } else {
            b.queued_drops = b.queued_drops.saturating_add(1);
            b.total_suppressed = b.total_suppressed.saturating_add(1);
            None
        }
    }

    /// Return the cumulative total suppressed count for each kind.
    /// Indexed by [`LogKind::index`].  Used by the Prometheus exporter.
    pub fn snapshot_totals(&self) -> [u64; LogKind::COUNT] {
        let mut out = [0u64; LogKind::COUNT];
        for (i, b) in self.buckets.iter().enumerate() {
            out[i] = b.total_suppressed;
        }
        out
    }
}

/// Global rate-limiter instance.  Locked only on hot-path log calls (which
/// are already I/O-bound when they fire) and on Prometheus scrapes.
pub static LOG_RATE_LIMITER: Mutex<LogRateLimiter> = Mutex::new(LogRateLimiter::new());

/// Return the current wall-clock time in nanoseconds for rate-limit checks.
/// Uses `UNIX_EPOCH.elapsed()` — monotonicity is not strictly required; the
/// 1-second cooldown granularity tolerates occasional clock jitter.
#[inline]
pub fn rl_now_ns() -> u64 {
    std::time::UNIX_EPOCH
        .elapsed()
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Rate-limited logging macros
// ---------------------------------------------------------------------------

/// Emit a warn-level message with a 1-second per-kind cooldown.
///
/// `$kind` must be a [`crate::log_ratelimit::LogKind`] variant.  If the
/// cooldown has not elapsed since the last emission of this kind, the
/// message is suppressed and the per-kind Prometheus counter is incremented.
/// When the cooldown expires the next message is emitted with an appended
/// "(suppressed N)" note if N > 0.
#[macro_export]
macro_rules! varta_warn_rl {
    ($kind:expr, $($arg:tt)*) => {{
        let _now = $crate::log_ratelimit::rl_now_ns();
        let _drops = $crate::log_ratelimit::LOG_RATE_LIMITER
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .should_emit($kind, _now);
        if let Some(_d) = _drops {
            let mut _buf = $crate::log::StackFmt::<320>::new();
            let _ = ::core::fmt::Write::write_fmt(&mut _buf, ::core::format_args!($($arg)*));
            if _d > 0 {
                let _ = ::core::fmt::Write::write_fmt(
                    &mut _buf,
                    ::core::format_args!(" (suppressed {_d})"),
                );
            }
            $crate::varta_warn!("{}", _buf.as_str());
        }
    }};
}

/// Emit an error-level message with a 1-second per-kind cooldown.
///
/// See [`varta_warn_rl`] for the suppression semantics.
#[macro_export]
macro_rules! varta_error_rl {
    ($kind:expr, $($arg:tt)*) => {{
        let _now = $crate::log_ratelimit::rl_now_ns();
        let _drops = $crate::log_ratelimit::LOG_RATE_LIMITER
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .should_emit($kind, _now);
        if let Some(_d) = _drops {
            let mut _buf = $crate::log::StackFmt::<320>::new();
            let _ = ::core::fmt::Write::write_fmt(&mut _buf, ::core::format_args!($($arg)*));
            if _d > 0 {
                let _ = ::core::fmt::Write::write_fmt(
                    &mut _buf,
                    ::core::format_args!(" (suppressed {_d})"),
                );
            }
            $crate::varta_error!("{}", _buf.as_str());
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_limiter() -> LogRateLimiter {
        LogRateLimiter::new()
    }

    #[test]
    fn first_message_always_emitted() {
        let mut rl = fresh_limiter();
        assert!(rl
            .should_emit(LogKind::FileExportIo, 1_000_000_000)
            .is_some());
    }

    #[test]
    fn second_message_within_cooldown_suppressed() {
        let mut rl = fresh_limiter();
        rl.should_emit(LogKind::FileExportIo, 1_000_000_000);
        // 0.5 s later — still within 1 s cooldown
        assert!(rl
            .should_emit(LogKind::FileExportIo, 1_500_000_000)
            .is_none());
    }

    #[test]
    fn message_allowed_after_cooldown() {
        let mut rl = fresh_limiter();
        rl.should_emit(LogKind::FileExportIo, 1_000_000_000);
        // suppress two
        rl.should_emit(LogKind::FileExportIo, 1_100_000_000);
        rl.should_emit(LogKind::FileExportIo, 1_200_000_000);
        // 1 s+ later — allowed; reported drops == 2
        let result = rl.should_emit(LogKind::FileExportIo, 2_000_000_001);
        assert_eq!(result, Some(2));
    }

    #[test]
    fn total_suppressed_accumulates() {
        let mut rl = fresh_limiter();
        rl.should_emit(LogKind::AuditIo, 1_000_000_000);
        rl.should_emit(LogKind::AuditIo, 1_000_000_100); // suppressed +1
        rl.should_emit(LogKind::AuditIo, 1_000_000_200); // suppressed +1
        let totals = rl.snapshot_totals();
        assert_eq!(totals[LogKind::AuditIo.index()], 2);
    }

    #[test]
    fn kinds_are_independent() {
        let mut rl = fresh_limiter();
        // First emit for both kinds
        assert!(rl.should_emit(LogKind::FileExportIo, 1_000).is_some());
        assert!(rl.should_emit(LogKind::AuditIo, 1_000).is_some());
        // Suppress FileExportIo
        assert!(rl.should_emit(LogKind::FileExportIo, 2_000).is_none());
        // AuditIo second emit is also suppressed
        assert!(rl.should_emit(LogKind::AuditIo, 2_000).is_none());
    }
}
