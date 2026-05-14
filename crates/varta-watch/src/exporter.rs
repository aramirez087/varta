//! Exporters for [`crate::observer::Event`] streams.
//!
//! Two concrete implementations ship with v0.1.0:
//!
//! - [`FileExporter`] — appends one tab-separated line per event to a file
//!   on disk. The schema is documented on [`FileExporter`] and is stable
//!   for the v0.1.0 contract.
//! - [`PromExporter`] — exposes per-pid counters via `GET /metrics` over
//!   HTTP/1.0 in the Prometheus text exposition format. The endpoint is
//!   poll-driven by [`PromExporter::serve_pending`]; no background thread
//!   and no shared state.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "prometheus-exporter")]
use std::collections::HashMap;
#[cfg(feature = "prometheus-exporter")]
use std::fmt::Write as _;
#[cfg(feature = "prometheus-exporter")]
use std::io::{ErrorKind, Read};
#[cfg(feature = "prometheus-exporter")]
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
#[cfg(feature = "prometheus-exporter")]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "prometheus-exporter")]
use varta_vlp::crypto::BearerToken;
#[cfg(feature = "prometheus-exporter")]
use varta_vlp::DecodeError;
use varta_vlp::Status;

#[cfg(feature = "prometheus-exporter")]
use crate::log_ratelimit::{LogKind, LOG_RATE_LIMITER};

use crate::observer::Event;

/// Sink for an [`Event`] stream.
pub trait Exporter {
    /// Record a single observer event. Implementations should never panic
    /// or block the caller for IO; transient failures are returned as
    /// `Err` so the caller can react (log, retry, or fall back).
    fn record(&mut self, ev: &Event) -> io::Result<()>;
    /// Flush any internally buffered output. For network exporters that
    /// hold no per-event buffer this is a no-op that returns `Ok(())`.
    fn flush(&mut self) -> io::Result<()>;
}

/// File-backed exporter. Appends one line per event in the schema:
///
/// ```text
/// <observer_ns>\t<kind>\t<pid>\t<nonce>\t<status>\t<payload>\n
/// ```
///
/// `kind` ∈ `{beat, stall, decode, io, mismatch}`. For `decode`, `io`, and
/// `mismatch` events the pid / nonce / status / payload columns are written
/// as `-` so the line count and column count remain stable.
///
/// `observer_ns` is the observer-local nanosecond timestamp carried by every
/// [`Event`], captured at observer poll time. All exporters sharing an event
/// stream see the same timestamps.
///
/// When `max_bytes` is set, the exporter rotates the file after every write
/// that pushes the size over the limit. Rotation shifts `PATH` → `PATH.1`,
/// `PATH.1` → `PATH.2`, …, up to 5 generations, then re-opens `PATH` in
/// append mode. Without `max_bytes` the file grows unbounded.
pub struct FileExporter {
    sink: BufWriter<File>,
    pending_err: Option<io::Error>,
    path: PathBuf,
    max_bytes: Option<u64>,
    bytes_written: u64,
}

/// Number of rotated file generations kept.
const MAX_ROTATION_GENERATIONS: u32 = 5;

impl FileExporter {
    /// Open `path` in append mode (creating it if necessary) and wrap it
    /// in a [`BufWriter`].
    ///
    /// `max_bytes` is the optional size limit after which the file is
    /// rotated.
    pub fn create(path: impl AsRef<Path>, max_bytes: Option<u64>) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())?;
        let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(FileExporter {
            sink: BufWriter::new(file),
            pending_err: None,
            path: path.as_ref().to_path_buf(),
            max_bytes,
            bytes_written,
        })
    }

    /// Record an evicted pid line into the file export. This is called from
    /// the main loop when a tracker slot is reclaimed, so the operator has
    /// a per-pid trace of eviction events.
    pub fn record_eviction_pid(&mut self, pid: u32, observer_ns: u64) {
        let result = writeln!(self.sink, "{observer_ns}\teviction\t{pid}\t-\t-\t-",);
        if let Err(e) = result {
            self.pending_err = Some(e);
        } else {
            self.pending_err = None;
            let line_len = decimal_digits(observer_ns) as u64
                + 1  // \t
                + 8  // "eviction"
                + 1  // \t
                + decimal_digits(pid as u64) as u64
                + 1  // \t
                + 1  // -
                + 1  // \t
                + 1  // -
                + 1  // \t
                + 1  // -
                + 1; // \n
            self.after_write(line_len);
        }
    }

    /// Called after every successful write. When `max_bytes` is set and
    /// exceeded, rotates the file.
    fn after_write(&mut self, line_len: u64) {
        let Some(max) = self.max_bytes else {
            return;
        };
        self.bytes_written = self.bytes_written.saturating_add(line_len);
        if self.bytes_written < max {
            return;
        }
        // Rotation needed.
        if let Err(e) = self.sink.flush() {
            self.pending_err = Some(e);
            return;
        }
        if let Err(e) = Self::rotate(&self.path) {
            self.pending_err = Some(e);
            return;
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => {
                self.sink = BufWriter::new(file);
                self.bytes_written = 0;
            }
            Err(e) => {
                self.pending_err = Some(e);
            }
        }
    }

    /// Rotate `path`: shift `path` → `path.1`, `path.1` → `path.2`, …
    /// up to [`MAX_ROTATION_GENERATIONS`]. The oldest generation is deleted.
    fn rotate(path: &Path) -> io::Result<()> {
        let path_str = path.to_string_lossy();
        let oldest = format!("{path_str}.{MAX_ROTATION_GENERATIONS}");
        match std::fs::remove_file(&oldest) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        for gen in (1..MAX_ROTATION_GENERATIONS).rev() {
            let src = format!("{path_str}.{gen}");
            let dst = format!("{path_str}.{}", gen + 1);
            match std::fs::rename(&src, &dst) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let first = format!("{path_str}.1");
        // CrossesDevices: stable 1.85, MSRV 1.70; correct on Linux/macOS
        #[allow(clippy::incompatible_msrv)]
        match std::fs::rename(path, &first) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
                std::fs::copy(path, &first)?;
                std::fs::remove_file(path)?;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

impl Exporter for FileExporter {
    fn record(&mut self, ev: &Event) -> io::Result<()> {
        let line_len: u64 = match ev {
            Event::Beat {
                pid,
                status,
                payload,
                nonce,
                observer_ns,
                origin: _,
                pid_ns_inode: _,
            } => {
                let label = status_label(*status);
                decimal_digits(*observer_ns) as u64
                    + 1  // \t
                    + 4  // "beat"
                    + 1  // \t
                    + decimal_digits(*pid as u64) as u64
                    + 1  // \t
                    + decimal_digits(*nonce) as u64
                    + 1  // \t
                    + label.len() as u64
                    + 1  // \t
                    + decimal_digits(*payload as u64) as u64
                    + 1 // \n
            }
            Event::Stall {
                pid,
                last_nonce,
                observer_ns,
                ..
            } => {
                decimal_digits(*observer_ns) as u64
                + 1  // \t
                + 5  // "stall"
                + 1  // \t
                + decimal_digits(*pid as u64) as u64
                + 1  // \t
                + decimal_digits(*last_nonce) as u64
                + 1  // \t
                + 5  // "stall"
                + 1  // \t
                + 1  // "-"
                + 1
            } // \n
            // Error events with variable-length messages: compute exact
            // length after the write below rather than using a fixed
            // estimate (prevents file-rotation timing drift).
            Event::Decode(_, _)
            | Event::Io(_, _)
            | Event::CtrlTruncated(_, _)
            | Event::OriginConflict { .. }
            | Event::NamespaceConflict { .. } => 0,
            Event::AuthFailure {
                claimed_pid,
                observer_ns,
            } => {
                decimal_digits(*observer_ns) as u64
                + 1  // \t
                + 8  // "mismatch"
                + 1  // \t
                + decimal_digits(*claimed_pid as u64) as u64
                + 1  // \t
                + 1  // "-"
                + 1  // \t
                + 1  // "-"
                + 1  // \t
                + 13 // "auth_failure"
                + 1
            } // \n
        };
        let result = match ev {
            Event::Beat {
                pid,
                status,
                payload,
                nonce,
                observer_ns,
                origin: _,
                pid_ns_inode: _,
            } => writeln!(
                self.sink,
                "{observer_ns}\tbeat\t{pid}\t{nonce}\t{}\t{payload}",
                status_label(*status),
            ),
            Event::Stall {
                pid,
                last_nonce,
                last_ns: _,
                observer_ns,
                origin: _,
                pid_ns_inode: _,
            } => writeln!(
                self.sink,
                "{observer_ns}\tstall\t{pid}\t{last_nonce}\tstall\t-",
            ),
            Event::Decode(err, observer_ns) => {
                writeln!(self.sink, "{observer_ns}\tdecode\t-\t-\t-\t{err:?}")
            }
            Event::Io(err, observer_ns) => {
                writeln!(self.sink, "{observer_ns}\tio\t-\t-\t-\t{err}")
            }
            Event::AuthFailure {
                claimed_pid,
                observer_ns,
            } => {
                writeln!(
                    self.sink,
                    "{observer_ns}\tmismatch\t{claimed_pid}\t-\t-\tauth_failure",
                )
            }
            Event::OriginConflict {
                claimed_pid,
                observer_ns,
                ..
            } => {
                writeln!(
                    self.sink,
                    "{observer_ns}\tmismatch\t{claimed_pid}\t-\t-\torigin_conflict",
                )
            }
            Event::NamespaceConflict {
                claimed_pid,
                observer_ns,
                ..
            } => {
                writeln!(
                    self.sink,
                    "{observer_ns}\tmismatch\t{claimed_pid}\t-\t-\tnamespace_conflict",
                )
            }
            Event::CtrlTruncated(err, observer_ns) => {
                writeln!(self.sink, "{observer_ns}\tctrunc\t-\t-\t-\t{err}")
            }
        };
        if let Err(ref e) = result {
            self.pending_err = Some(io::Error::new(e.kind(), e.to_string()));
        }
        match result {
            Err(e) => Err(e),
            Ok(()) => {
                self.pending_err = None;
                let actual_len = if line_len > 0 {
                    line_len
                } else {
                    match ev {
                        Event::Decode(err, observer_ns) => {
                            format!("{observer_ns}\tdecode\t-\t-\t-\t{err:?}\n").len() as u64
                        }
                        Event::Io(err, observer_ns) => {
                            let msg = err.to_string();
                            format!("{observer_ns}\tio\t-\t-\t-\t{msg}\n").len() as u64
                        }
                        Event::CtrlTruncated(err, observer_ns) => {
                            let msg = err.to_string();
                            format!("{observer_ns}\tctrunc\t-\t-\t-\t{msg}\n").len() as u64
                        }
                        Event::OriginConflict {
                            claimed_pid,
                            observer_ns,
                            ..
                        } => format!(
                            "{observer_ns}\tmismatch\t{claimed_pid}\t-\t-\torigin_conflict\n"
                        )
                        .len() as u64,
                        _ => unreachable!(),
                    }
                };
                self.after_write(actual_len);
                Ok(())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let sink_result = self.sink.flush();
        match (self.pending_err.take(), sink_result) {
            (Some(e), _) => Err(e),
            (None, Err(e)) => Err(e),
            (None, Ok(())) => Ok(()),
        }
    }
}

/// Return the number of decimal digits needed to represent `n`.
fn decimal_digits(mut n: u64) -> usize {
    if n == 0 {
        return 1;
    }
    let mut digits = 0;
    while n > 0 {
        n /= 10;
        digits += 1;
    }
    digits
}

fn status_label(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Degraded => "degraded",
        Status::Critical => "critical",
        Status::Stall => "stall",
    }
}

/// Prometheus `kind` label values for `varta_log_suppressed_total`. Indexed
/// by [`LogKind::index`]; the array doubles as the canonical ordering for
/// the exposition output so series remain stable across scrapes.  Must stay
/// in sync with the `LogKind` enum in `log_ratelimit.rs` — same order, same count.
#[cfg(feature = "prometheus-exporter")]
const LOG_KIND_LABELS: [&str; LogKind::COUNT] =
    ["file_export_io", "audit_io", "prom_serve", "heartbeat_io"];

/// Prometheus `kind` label values for `varta_decode_errors_total`. Indexed
/// by [`decode_kind_index`]; the array doubles as the canonical ordering
/// for the exposition output, so series remain stable across scrapes.
#[cfg(feature = "prometheus-exporter")]
const DECODE_KIND_LABELS: [&str; 8] = [
    "bad_magic",
    "bad_version",
    "bad_status",
    "bad_pid",
    "bad_timestamp",
    "bad_nonce",
    "stall_on_wire",
    "bad_crc",
];

#[cfg(feature = "prometheus-exporter")]
fn decode_kind_index(err: &DecodeError) -> usize {
    match err {
        DecodeError::BadMagic => 0,
        DecodeError::BadVersion => 1,
        DecodeError::BadStatus(_) => 2,
        DecodeError::BadPid(_) => 3,
        DecodeError::BadTimestamp(_) => 4,
        DecodeError::BadNonce { .. } => 5,
        DecodeError::StallOnWire => 6,
        DecodeError::BadCrc { .. } => 7,
    }
}

#[cfg(feature = "prometheus-exporter")]
#[derive(Clone, Copy, Debug)]
struct GaugeRow {
    beats_total: u64,
    stalls_total: u64,
    last_status: Option<u8>,
}

#[cfg(feature = "prometheus-exporter")]
impl GaugeRow {
    const fn new() -> Self {
        GaugeRow {
            beats_total: 0,
            stalls_total: 0,
            last_status: None,
        }
    }
}

/// Per-connection read timeout on the [`PromExporter`]'s accepted streams.
/// Capped so a slow or hostile client cannot stall the observer's poll loop.
#[cfg(feature = "prometheus-exporter")]
const PROM_READ_DEADLINE: Duration = Duration::from_millis(10);
/// Per-connection write timeout for the metrics response body.
#[cfg(feature = "prometheus-exporter")]
const PROM_WRITE_TIMEOUT: Duration = Duration::from_millis(50);
/// Maximum connections accepted per [`PromExporter::serve_pending`] call.
/// Caps the amount of work done before returning control to the observer
/// loop so that stall detection, I/O polling, and reaping are not starved
/// under a storm of slow scrapers. The 100 ms serve deadline still applies
/// as an additional guard.
#[cfg(feature = "prometheus-exporter")]
const PROM_MAX_CONNECTIONS_PER_SERVE: usize = 8;
/// After the serve budget is exhausted, the exporter enters drain mode:
/// remaining connections are accepted and immediately closed (without
/// serving) to prevent the kernel's accept queue from building up under a
/// connection flood. A hostile client opening thousands of connections
/// would otherwise fill the backlog and starve legitimate scrapers.
#[cfg(feature = "prometheus-exporter")]
const PROM_MAX_DRAIN_PER_SERVE: usize = 50;

// --- iteration budget histogram (H5) -----------------------------------
//
// Per-iteration wall-time visibility primitive. The observer poll loop is
// single-threaded by design: beat ingestion, stall detection, recovery
// reaping, and Prometheus serving all share one thread. The aggregate
// per-iteration budget is what bounds stall-detection latency under load
// — see `book/src/architecture/observer-liveness.md` for the formal derivation.

/// Cumulative Prometheus histogram cutoffs for observer iteration wall
/// time (seconds). The implicit `+Inf` bucket is rendered last so the
/// total bucket count is `ITERATION_BUCKET_BOUNDS_S.len() + 1`. The 0.25
/// cutoff is aligned to the default `--iteration-budget-ms` so
/// `le="0.25"` directly answers "what fraction of iterations were over
/// budget?".
#[cfg(feature = "prometheus-exporter")]
const ITERATION_BUCKET_BOUNDS_S: [f64; 8] =
    [0.001, 0.005, 0.010, 0.050, 0.100, 0.250, 0.500, 1.000];

/// Default soft budget for a single observer poll iteration. Overruns
/// increment `varta_observer_iteration_budget_exceeded_total`; the budget
/// is advisory — hard wedges remain the responsibility of
/// `--self-watchdog-secs` (see `book/src/architecture/observer-liveness.md`).
pub const DEFAULT_ITERATION_BUDGET: Duration = Duration::from_millis(250);

/// Default soft budget for a single `serve_pending` call. Overruns increment
/// `varta_observer_scrape_budget_exceeded_total`. This is the *scrape-only*
/// component of the total iteration time; separating it from
/// [`DEFAULT_ITERATION_BUDGET`] lets operators alert on scrape-storm
/// pressure independently of beat-path slowness.
///
/// Mirrors [`DEFAULT_ITERATION_BUDGET`] (250 ms) because `serve_pending`'s
/// own structural cap is `100 ms serve + 100 ms drain = 200 ms`; a 250 ms
/// budget gives a small headroom for I/O scheduling jitter before firing.
pub const DEFAULT_SCRAPE_BUDGET: Duration = Duration::from_millis(250);
/// Cap on how many bytes [`PromExporter::serve_pending`] reads from a
/// single request before responding (we discard the request line/headers).
#[cfg(feature = "prometheus-exporter")]
const PROM_REQUEST_CAP: usize = 4096;
/// Minimum interval between accepted scrapes. A scraper hitting faster than
/// once per second cannot starve stall detection in the single-threaded
/// poll loop. Prometheus default scrape intervals are 15–60 s, so this only
/// gates pathological or misconfigured scrapers.
#[cfg(feature = "prometheus-exporter")]
const PROM_MIN_SCRAPE_INTERVAL: Duration = Duration::from_secs(1);

/// Maximum number of unique source IPs tracked in the per-IP token bucket.
/// Bounds memory consumption against a horizontal flood (many distinct IPs,
/// each sending one connection).  When the table is full, stale entries are
/// evicted first; if every entry is still fresh, the oldest is force-evicted
/// and counted as `varta_prom_connections_dropped_total{reason="ip_table_full"}`.
#[cfg(feature = "prometheus-exporter")]
const MAX_PROM_IP_STATES: usize = 1024;

/// How long a source IP's bucket state is retained after its last seen
/// connection. Entries older than this are eligible for stale-eviction.
#[cfg(feature = "prometheus-exporter")]
const PROM_IP_STATE_TTL: Duration = Duration::from_secs(60);

/// How often the stale-IP sweep runs (only triggered when the IP table
/// reaches capacity).
#[cfg(feature = "prometheus-exporter")]
const PROM_IP_STATE_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// Per-source-IP token bucket state for the Prometheus `/metrics` endpoint.
#[cfg(feature = "prometheus-exporter")]
#[derive(Clone, Copy, Debug)]
struct PromIpState {
    /// Tokens available (fractional, scaled by 1000 to avoid floats).
    /// Each accepted connection consumes 1000 milli-tokens.
    tokens_milli: u32,
    /// Wall-clock instant at which `tokens_milli` was last refilled.
    last_refill: Instant,
    /// Most recent connection from this IP — used for stale eviction.
    last_seen: Instant,
}

/// Reasons a `/metrics` connection can be dropped before serving.  Indexed by
/// [`drop_reason_index`]; the array doubles as the canonical ordering for
/// the exposition output, so series remain stable across scrapes.
#[cfg(feature = "prometheus-exporter")]
const DROP_REASON_LABELS: [&str; 3] = ["drain", "rate_limit", "ip_table_full"];

/// Outcome label values for `varta_recovery_outcomes_total`. Indexed by
/// [`recovery_outcome_index`]; emitted unconditionally (every value, even
/// at zero) so `absent()` alert rules stay green.
#[cfg(feature = "prometheus-exporter")]
const RECOVERY_OUTCOME_LABELS: [&str; 9] = [
    "spawned",
    "debounced",
    "reaped_zero",
    "reaped_nonzero",
    "killed",
    "spawn_failed",
    "refused_unauthenticated_transport",
    "refused_cross_namespace",
    "refused_debounce_capacity",
];

/// Reason label values for `varta_recovery_refused_total`. Indexed by
/// [`refused_reason_index`]; emitted unconditionally so `absent()` rules
/// stay green.
#[cfg(feature = "prometheus-exporter")]
const RECOVERY_REFUSED_REASON_LABELS: [&str; 3] = [
    "unauthenticated_transport",
    "cross_namespace_agent",
    "debounce_capacity",
];

/// Map a [`crate::recovery::RecoveryOutcome`] to a stable index for the
/// `varta_recovery_outcomes_total` array.
#[cfg(feature = "prometheus-exporter")]
fn recovery_outcome_index(outcome: &crate::recovery::RecoveryOutcome) -> usize {
    use crate::recovery::RecoveryOutcome;
    match outcome {
        RecoveryOutcome::Spawned { .. } => 0,
        RecoveryOutcome::Debounced => 1,
        RecoveryOutcome::Reaped { status, .. } => {
            if status.success() {
                2
            } else {
                3
            }
        }
        RecoveryOutcome::Killed { .. } => 4,
        RecoveryOutcome::SpawnFailed(_) => 5,
        RecoveryOutcome::RefusedUnauthenticatedSource { .. } => 6,
        RecoveryOutcome::RefusedCrossNamespace { .. } => 7,
        RecoveryOutcome::RefusedDebounceCapacity { .. } => 8,
        // ReapFailed is not user-facing here — treat as a reap-nonzero
        // (it implies the child terminated abnormally from our POV).
        RecoveryOutcome::ReapFailed(_) => 3,
    }
}

/// Refusal reason for the `varta_recovery_refused_total` array. Currently
/// only one reason is defined; the helper is kept to mirror the
/// decode_kind_index / drop_reason_index pattern so adding new reasons is
/// a localized change.
#[cfg(feature = "prometheus-exporter")]
#[derive(Clone, Copy, Debug)]
enum RefusedReason {
    UnauthenticatedTransport,
    CrossNamespaceAgent,
    DebounceCapacity,
}

#[cfg(feature = "prometheus-exporter")]
fn refused_reason_index(r: RefusedReason) -> usize {
    match r {
        RefusedReason::UnauthenticatedTransport => 0,
        RefusedReason::CrossNamespaceAgent => 1,
        RefusedReason::DebounceCapacity => 2,
    }
}

#[cfg(feature = "prometheus-exporter")]
#[derive(Clone, Copy, Debug)]
enum DropReason {
    Drain,
    RateLimit,
    IpTableFull,
}

#[cfg(feature = "prometheus-exporter")]
fn drop_reason_index(r: DropReason) -> usize {
    match r {
        DropReason::Drain => 0,
        DropReason::RateLimit => 1,
        DropReason::IpTableFull => 2,
    }
}

/// Prometheus text-format exporter served over HTTP/1.0.
///
/// The exporter is poll-driven: the daemon main loop calls
/// [`PromExporter::serve_pending`] once per outer tick and the listener
/// is non-blocking, so there is no background thread. Each accepted
/// connection receives a fresh metrics body with `Connection: close`.
#[cfg(feature = "prometheus-exporter")]
pub struct PromExporter {
    listener: TcpListener,
    rows: HashMap<u32, GaugeRow>,
    /// Reused across `/metrics` scrapes to avoid per-scrape allocation.
    body_buf: String,
    /// Timestamp of the most recent scrape served. Enforces
    /// [`PROM_MIN_SCRAPE_INTERVAL`] to protect the single-threaded poll
    /// loop from a fast scraper starving stall detection.
    last_scrape: Option<Instant>,
    evicted_total: u64,
    /// Number of `/metrics` connections rejected because the bearer token
    /// was missing or wrong.  Emitted unconditionally as
    /// `varta_prom_auth_failures_total` (even when zero) so `absent()` alert
    /// rules stay green; see the matching contract on
    /// `varta_decode_errors_total`.
    auth_failures_total: u64,
    /// Pre-shared bearer secret enforced on every scrape via the
    /// `Authorization: Bearer <hex>` request header.  Loaded once at
    /// startup from `--prom-token-file`; the exporter never reads the
    /// file again.  Zeroed on drop.
    token: BearerToken,
    /// Per-kind decode failure counters, indexed by [`decode_kind_index`].
    /// Always emitted in full (even at zero) so `absent()` alert rules and
    /// dashboards stay green-on-green instead of disappearing until the
    /// first incident. Size is derived from [`DECODE_KIND_LABELS`] so
    /// adding a label forces the array to grow.
    decode_errors_total: [u64; DECODE_KIND_LABELS.len()],
    io_errors_total: u64,
    ctrl_truncated_total: u64,
    capacity_exceeded_total: u64,
    decrypt_failures_total: u64,
    truncated_total: u64,
    sender_state_full_total: u64,
    /// Total AEAD decryption attempts across the loaded key set. The
    /// secure-UDP listener trials *every* loaded key (and the master-key
    /// derivation, if configured) on every frame, regardless of which key
    /// succeeds. This removes the linear-in-key-index timing signal that
    /// let a remote attacker fingerprint the primary rotation slot by
    /// measuring RTT. In steady state this equals
    /// `frames_received * (keys.len() + master_key_configured as u64)`.
    secure_aead_attempts_total: u64,
    rate_limited_total: u64,
    nonce_wrap_total: u64,
    /// Count of bounded eviction-scan calls that ran the full
    /// `eviction_scan_window` without finding a victim. Surfaced as
    /// `varta_tracker_eviction_scan_truncated_total`; non-zero values prove
    /// the per-frame work cap engaged under a unique-pid flood.
    eviction_scan_truncated_total: u64,
    /// Configured tracker capacity. Set once at startup via
    /// [`PromExporter::set_tracker_config`]; emitted as
    /// `varta_tracker_capacity` (gauge) so dashboards can derive fill %.
    tracker_capacity_cfg: usize,
    /// Configured eviction scan window. Set once at startup via
    /// [`PromExporter::set_tracker_config`]; emitted as
    /// `varta_tracker_eviction_scan_window_max` (gauge) so operators can
    /// compute the WCET bound: `ceil(capacity / eviction_scan_window_max)` calls.
    eviction_scan_window_max: usize,
    /// Per-outcome recovery counters, indexed by [`recovery_outcome_index`].
    /// Emitted in full at every scrape so dashboards/alerts stay green-on-green.
    recovery_outcomes_total: [u64; RECOVERY_OUTCOME_LABELS.len()],
    /// Per-reason refused-recovery counters, indexed by [`refused_reason_index`].
    /// Surfaced as `varta_recovery_refused_total{reason=...}`. Always emitted
    /// at every scrape (even at zero) per the project's stable-label-set rule.
    recovery_refused_total: [u64; RECOVERY_REFUSED_REASON_LABELS.len()],
    /// Total [`crate::recovery::LastFiredTable`] evictions — stale
    /// entries dropped to make room for a new pid when the table was
    /// at capacity and the evicted entry's debounce window had
    /// elapsed.  Surfaced as `varta_recovery_last_fired_evictions_total`.
    /// Distinct from `recovery_refused_total{reason="debounce_capacity"}`:
    /// an eviction is debounce-respecting churn (operators tune
    /// `MAX_LAST_FIRED_CAPACITY` on this signal); a refusal is
    /// suppression (operators alert on this signal).
    recovery_last_fired_evictions_total: u64,
    /// Total [`crate::recovery::LastFiredTable`] invariant-violation
    /// fall-throughs — defensive `.get()`/`.get_mut()` else-branches
    /// that should be unreachable in correct operation.  Surfaced as
    /// `varta_recovery_invariant_violations_total`; non-zero values
    /// indicate a code bug, not load.
    recovery_invariant_violations_total: u64,
    /// Tracker-level cross-origin conflicts — beats dropped because the
    /// slot's pinned transport origin disagreed with the beat's origin.
    /// Surfaced as `varta_origin_conflict_total`.
    origin_conflict_total: u64,
    /// Frames dropped at receive because the peer's PID-namespace inode
    /// differs from the observer's. Linux-only signal; 0 on other platforms.
    /// Surfaced as `varta_frame_namespace_mismatch_total`.
    frame_namespace_mismatch_total: u64,
    /// Frames dropped at receive because `frame.pid` exceeded the kernel's
    /// configured `pid_max` (Linux: `/proc/sys/kernel/pid_max`). Linux-only
    /// signal; 0 on other platforms where the gate defaults to `u32::MAX`.
    /// Surfaced as `varta_frame_rejected_pid_above_max_total`.
    frame_rejected_pid_above_max_total: u64,
    /// Tracker-level namespace conflicts — beats dropped because the slot's
    /// pinned PID-namespace inode disagreed with the beat's inode
    /// (first-namespace-wins). Surfaced as
    /// `varta_tracker_namespace_conflict_total`.
    tracker_namespace_conflict_total: u64,
    /// Hot-path invariant violations recovered defensively by the tracker.
    /// Surfaced as `varta_tracker_invariant_violations_total`; non-zero
    /// values mean a `.get()` fall-through fired (stale index, OOB slot,
    /// etc.) — the tracker recovered without panicking, but ops should
    /// investigate.
    tracker_invariant_violations_total: u64,
    /// `PidIndex` lookups / inserts that walked the full `MAX_PROBE` budget
    /// without resolving. Surfaced as
    /// `varta_tracker_pid_index_probe_exhausted_total`.
    tracker_pid_index_probe_exhausted_total: u64,
    /// Sum of recovery child wall-clock durations in ns. Used together with
    /// `recovery_duration_count_total` to compute an average runtime.
    recovery_duration_ns_sum: u64,
    /// Count of recovery completions that contributed to
    /// `recovery_duration_ns_sum`. Mirrors a histogram `_count`.
    recovery_duration_count_total: u64,
    /// Number of `/metrics` scrapes served from cache because
    /// [`PROM_MIN_SCRAPE_INTERVAL`] had not elapsed since the last fresh
    /// render.  Operators can alert on this to detect scrape pressure.
    scrape_skipped_total: u64,
    /// Times [`serve_pending`](Self::serve_pending) exhausted its per-tick
    /// budget (connection cap or wall-clock deadline).  Operators can alert
    /// on this to detect when the exporter cannot serve all incoming scrapes
    /// within a single poll tick.
    scrape_budget_exhausted_total: u64,
    /// Per-bucket count of observer poll iterations, indexed by the matching
    /// entry in [`ITERATION_BUCKET_BOUNDS_S`] (with the final slot reserved
    /// for the implicit `+Inf` bucket). Not cumulative: each observation
    /// increments exactly one slot. The exposition layer walks the array
    /// with a running total to emit a Prometheus-compliant cumulative
    /// histogram.
    iteration_buckets: [u64; ITERATION_BUCKET_BOUNDS_S.len() + 1],
    /// Sum of observed iteration durations in nanoseconds. Exposed as
    /// `varta_observer_iteration_seconds_sum` after conversion to seconds.
    iteration_duration_ns_sum: u64,
    /// Total number of iterations contributing to the histogram. Exposed
    /// as `varta_observer_iteration_seconds_count`.
    iteration_count_total: u64,
    /// Times an iteration exceeded [`Self::iteration_budget`]. Exposed as
    /// `varta_observer_iteration_budget_exceeded_total`. Advisory only —
    /// the daemon never aborts on a soft-budget overrun.
    iteration_budget_exceeded_total: u64,
    /// Soft per-iteration budget for the observer poll loop. Configurable
    /// via `--iteration-budget-ms`; defaults to
    /// [`DEFAULT_ITERATION_BUDGET`]. See
    /// `book/src/architecture/observer-liveness.md` for the worst-case
    /// derivation that justifies the default.
    iteration_budget: Duration,
    /// Per-bucket count of `serve_pending` durations, indexed the same way
    /// as [`Self::iteration_buckets`] (same [`ITERATION_BUCKET_BOUNDS_S`]
    /// for cross-histogram coherence). Operators can subtract this
    /// histogram from `iteration_seconds` to isolate beat-path latency
    /// from scrape-induced variance.
    serve_pending_buckets: [u64; ITERATION_BUCKET_BOUNDS_S.len() + 1],
    /// Sum of observed `serve_pending` durations in nanoseconds. Exposed
    /// as `varta_observer_serve_pending_seconds_sum`.
    serve_pending_duration_ns_sum: u64,
    /// Total `serve_pending` calls observed. Exposed as
    /// `varta_observer_serve_pending_seconds_count`.
    serve_pending_count_total: u64,
    /// Times a single `serve_pending` exceeded [`Self::scrape_budget`].
    /// Exposed as `varta_observer_scrape_budget_exceeded_total`. Advisory.
    scrape_budget_exceeded_total: u64,
    /// Soft per-call budget for `serve_pending`. Configurable via
    /// `--scrape-budget-ms`; defaults to [`DEFAULT_SCRAPE_BUDGET`].
    scrape_budget: Duration,
    /// Per-source-IP token bucket state.  Bounded by
    /// [`MAX_PROM_IP_STATES`]; entries older than [`PROM_IP_STATE_TTL`] are
    /// evicted lazily when the table reaches capacity.
    ip_state: HashMap<IpAddr, PromIpState>,
    /// Per-source-IP refill rate (connections per second). Set from
    /// `Config::prom_rate_limit_per_sec` at construction time.
    rate_per_sec: u32,
    /// Per-source-IP burst (token-bucket capacity). Set from
    /// `Config::prom_rate_limit_burst` at construction time.
    rate_burst: u32,
    /// Last instant at which `evict_stale_ip_state` was called.
    last_ip_sweep: Instant,
    /// Connections dropped before serving, broken down by reason.  Always
    /// emitted in full (even at zero) so `absent()` alert rules stay green.
    /// Indexed by [`drop_reason_index`].
    connections_dropped_total: [u64; DROP_REASON_LABELS.len()],
    /// Observer startup instant (monotonic). Used to emit
    /// `varta_watch_uptime_seconds`.
    started_at: Instant,
    /// Wall-clock timestamp of the most recent poll loop tick. Used to emit
    /// `varta_watch_last_poll_loop_timestamp_seconds` so operators can
    /// detect observer stalls.
    last_loop_system: SystemTime,
}

#[cfg(feature = "prometheus-exporter")]
impl PromExporter {
    /// Bind a non-blocking TCP listener on `addr` with default per-IP rate
    /// limits.  Equivalent to
    /// `bind_with_rate_limit(addr, token, DEFAULT_PROM_RATE_LIMIT_PER_SEC, DEFAULT_PROM_RATE_LIMIT_BURST)`.
    ///
    /// `token` is the 32-byte bearer secret enforced on every scrape; see
    /// [`Self::bind_with_rate_limit`].
    pub fn bind(addr: SocketAddr, token: BearerToken) -> io::Result<Self> {
        Self::bind_with_rate_limit(
            addr,
            token,
            crate::config::DEFAULT_PROM_RATE_LIMIT_PER_SEC,
            crate::config::DEFAULT_PROM_RATE_LIMIT_BURST,
        )
    }

    /// Bind a non-blocking TCP listener on `addr` with the supplied per-IP
    /// rate-limit parameters.  `rate_per_sec` is the bucket refill rate
    /// (connections per second) and `rate_burst` is the bucket capacity
    /// (and thus the burst size a single IP can sustain at once).
    ///
    /// `token` is the 32-byte bearer secret enforced on every accepted
    /// connection. Every scrape must include
    /// `Authorization: Bearer <hex>` where `<hex>` is the lowercase 64-byte
    /// hex encoding of this byte array (the same format produced by
    /// `openssl rand -hex 32`). Missing or wrong tokens return
    /// `401 Unauthorized` and bump
    /// `varta_prom_auth_failures_total`.
    pub fn bind_with_rate_limit(
        addr: SocketAddr,
        token: BearerToken,
        rate_per_sec: u32,
        rate_burst: u32,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let now = Instant::now();
        Ok(PromExporter {
            listener,
            rows: HashMap::new(),
            body_buf: String::new(),
            last_scrape: None,
            evicted_total: 0,
            auth_failures_total: 0,
            token,
            decode_errors_total: [0; DECODE_KIND_LABELS.len()],
            io_errors_total: 0,
            ctrl_truncated_total: 0,
            capacity_exceeded_total: 0,
            decrypt_failures_total: 0,
            truncated_total: 0,
            sender_state_full_total: 0,
            secure_aead_attempts_total: 0,
            rate_limited_total: 0,
            nonce_wrap_total: 0,
            eviction_scan_truncated_total: 0,
            tracker_capacity_cfg: 0,
            eviction_scan_window_max: 0,
            recovery_outcomes_total: [0; RECOVERY_OUTCOME_LABELS.len()],
            recovery_refused_total: [0; RECOVERY_REFUSED_REASON_LABELS.len()],
            recovery_last_fired_evictions_total: 0,
            recovery_invariant_violations_total: 0,
            origin_conflict_total: 0,
            frame_namespace_mismatch_total: 0,
            frame_rejected_pid_above_max_total: 0,
            tracker_namespace_conflict_total: 0,
            tracker_invariant_violations_total: 0,
            tracker_pid_index_probe_exhausted_total: 0,
            recovery_duration_ns_sum: 0,
            recovery_duration_count_total: 0,
            scrape_skipped_total: 0,
            scrape_budget_exhausted_total: 0,
            iteration_buckets: [0; ITERATION_BUCKET_BOUNDS_S.len() + 1],
            iteration_duration_ns_sum: 0,
            iteration_count_total: 0,
            iteration_budget_exceeded_total: 0,
            iteration_budget: DEFAULT_ITERATION_BUDGET,
            serve_pending_buckets: [0; ITERATION_BUCKET_BOUNDS_S.len() + 1],
            serve_pending_duration_ns_sum: 0,
            serve_pending_count_total: 0,
            scrape_budget_exceeded_total: 0,
            scrape_budget: DEFAULT_SCRAPE_BUDGET,
            ip_state: HashMap::new(),
            rate_per_sec,
            rate_burst,
            last_ip_sweep: now,
            connections_dropped_total: [0; DROP_REASON_LABELS.len()],
            started_at: now,
            last_loop_system: SystemTime::now(),
        })
    }

    /// Returns `true` and consumes one token if the source IP has tokens
    /// available; otherwise returns `false`.  Capacity-evicts stale or
    /// (as a last resort) the oldest entry when the table is full, and
    /// bumps the corresponding drop counter so operators can observe
    /// rate-limit vs table-full pressure separately.
    fn allow_ip(&mut self, ip: IpAddr, now: Instant) -> bool {
        // Burst of 0 means "no per-IP limit". Skip the bookkeeping entirely.
        if self.rate_burst == 0 {
            return true;
        }
        let cap_milli: u32 = self.rate_burst.saturating_mul(1000);
        let refill_per_ms: u32 = self.rate_per_sec; // 1000 milli-tokens / 1000 ms

        // Periodic stale sweep — cheap when the table is sparse, bounded
        // by MAX_PROM_IP_STATES iterations when it isn't.
        if now.duration_since(self.last_ip_sweep) >= PROM_IP_STATE_SWEEP_INTERVAL {
            self.last_ip_sweep = now;
            self.ip_state
                .retain(|_, st| now.duration_since(st.last_seen) < PROM_IP_STATE_TTL);
        }

        match self.ip_state.get_mut(&ip) {
            Some(st) => {
                let elapsed_ms = now.duration_since(st.last_refill).as_millis() as u64;
                if elapsed_ms > 0 {
                    let add_milli =
                        (elapsed_ms as u128 * refill_per_ms as u128).min(u32::MAX as u128) as u32;
                    st.tokens_milli = st.tokens_milli.saturating_add(add_milli).min(cap_milli);
                    st.last_refill = now;
                }
                st.last_seen = now;
                if st.tokens_milli >= 1000 {
                    st.tokens_milli -= 1000;
                    true
                } else {
                    self.connections_dropped_total[drop_reason_index(DropReason::RateLimit)] = self
                        .connections_dropped_total[drop_reason_index(DropReason::RateLimit)]
                    .saturating_add(1);
                    false
                }
            }
            None => {
                if self.ip_state.len() >= MAX_PROM_IP_STATES {
                    // Try to make room by evicting stale entries first.
                    self.ip_state
                        .retain(|_, st| now.duration_since(st.last_seen) < PROM_IP_STATE_TTL);
                }
                if self.ip_state.len() >= MAX_PROM_IP_STATES {
                    // Still full — force-evict the oldest entry.  Count the
                    // event so a sustained horizontal flood is observable.
                    if let Some(oldest_ip) = self
                        .ip_state
                        .iter()
                        .min_by_key(|(_, s)| s.last_seen)
                        .map(|(k, _)| *k)
                    {
                        self.ip_state.remove(&oldest_ip);
                    }
                    self.connections_dropped_total[drop_reason_index(DropReason::IpTableFull)] =
                        self.connections_dropped_total[drop_reason_index(DropReason::IpTableFull)]
                            .saturating_add(1);
                }
                // New entry starts with a full bucket minus the one token
                // consumed by this connection.
                let tokens_milli = cap_milli.saturating_sub(1000);
                self.ip_state.insert(
                    ip,
                    PromIpState {
                        tokens_milli,
                        last_refill: now,
                        last_seen: now,
                    },
                );
                true
            }
        }
    }

    /// Address the listener is actually bound to. Useful for tests that
    /// bind on port 0 and need to discover the kernel-assigned port.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Record one or more tracker slot evictions.
    pub fn record_eviction(&mut self, count: u64) {
        self.evicted_total = self.evicted_total.saturating_add(count);
    }

    /// Remove the GaugeRow for a pid that was evicted from the tracker.
    /// Prevents unbounded memory growth in the rows HashMap over long-running
    /// deployments with ephemeral processes (CI runners, cron jobs, containers).
    pub fn record_evicted_pid(&mut self, pid: u32) {
        self.rows.remove(&pid);
    }

    /// Record one or more beats dropped due to tracker capacity exceeded.
    pub fn record_capacity_exceeded(&mut self, count: u64) {
        self.capacity_exceeded_total = self.capacity_exceeded_total.saturating_add(count);
    }

    /// Record one or more AEAD decryption (tag verification) failures.
    pub fn record_decrypt_failures(&mut self, count: u64) {
        self.decrypt_failures_total = self.decrypt_failures_total.saturating_add(count);
    }

    /// Record one or more truncated (wrong-size) datagrams received.
    pub fn record_truncated(&mut self, count: u64) {
        self.truncated_total = self.truncated_total.saturating_add(count);
    }

    /// Record one or more times the sender-state map was at capacity,
    /// forcing eviction of the oldest entry.
    pub fn record_sender_state_full(&mut self, count: u64) {
        self.sender_state_full_total = self.sender_state_full_total.saturating_add(count);
    }

    /// Record AEAD decryption attempts since the last drain. The secure-UDP
    /// listener trials every loaded key on every frame, so this counter
    /// grows by `frames_received * (keys.len() + master_key_configured as u64)`
    /// in steady state — the operational signal that the constant-trial-count
    /// timing-leak fix is active.
    pub fn record_secure_aead_attempts(&mut self, count: u64) {
        self.secure_aead_attempts_total = self.secure_aead_attempts_total.saturating_add(count);
    }

    /// Record one or more beats dropped by per-pid rate limiting.
    pub fn record_rate_limited(&mut self, count: u64) {
        self.rate_limited_total = self.rate_limited_total.saturating_add(count);
    }

    /// Record one or more nonce-space wrap events (agent exhausted u64 nonce
    /// space and looped to 0).
    pub fn record_nonce_wraps(&mut self, count: u64) {
        self.nonce_wrap_total = self.nonce_wrap_total.saturating_add(count);
    }

    /// Record one or more bounded eviction-scan calls that exhausted the
    /// `eviction_scan_window` without finding a victim. See
    /// [`crate::tracker::Tracker::take_eviction_scan_truncated`].
    pub fn record_eviction_scan_truncated(&mut self, count: u64) {
        self.eviction_scan_truncated_total =
            self.eviction_scan_truncated_total.saturating_add(count);
    }

    /// Set the tracker capacity and eviction-scan-window config values emitted
    /// as startup gauges. Call once at daemon startup before the first scrape.
    pub fn set_tracker_config(&mut self, capacity: usize, eviction_scan_window: usize) {
        self.tracker_capacity_cfg = capacity;
        self.eviction_scan_window_max = eviction_scan_window;
    }

    /// Record a recovery outcome and optional duration. Increments the
    /// `varta_recovery_outcomes_total{outcome=…}` counter; when
    /// `duration_ns` is provided (typically only for `Reaped` / `Killed`
    /// outcomes), bumps the duration sum + count.
    ///
    /// `RefusedUnauthenticatedSource` outcomes additionally bump
    /// `varta_recovery_refused_total{reason="unauthenticated_transport"}`;
    /// `RefusedCrossNamespace` outcomes bump
    /// `varta_recovery_refused_total{reason="cross_namespace_agent"}`;
    /// `RefusedDebounceCapacity` outcomes bump
    /// `varta_recovery_refused_total{reason="debounce_capacity"}`
    /// (M8 fail-closed guard against stall-burst attacks).
    /// Operators can alert on each refusal independently of the broader
    /// outcome label.
    pub fn record_recovery_outcome(
        &mut self,
        outcome: &crate::recovery::RecoveryOutcome,
        duration_ns: Option<u64>,
    ) {
        let idx = recovery_outcome_index(outcome);
        self.recovery_outcomes_total[idx] = self.recovery_outcomes_total[idx].saturating_add(1);
        match outcome {
            crate::recovery::RecoveryOutcome::RefusedUnauthenticatedSource { .. } => {
                let r_idx = refused_reason_index(RefusedReason::UnauthenticatedTransport);
                self.recovery_refused_total[r_idx] =
                    self.recovery_refused_total[r_idx].saturating_add(1);
            }
            crate::recovery::RecoveryOutcome::RefusedCrossNamespace { .. } => {
                let r_idx = refused_reason_index(RefusedReason::CrossNamespaceAgent);
                self.recovery_refused_total[r_idx] =
                    self.recovery_refused_total[r_idx].saturating_add(1);
            }
            crate::recovery::RecoveryOutcome::RefusedDebounceCapacity { .. } => {
                let r_idx = refused_reason_index(RefusedReason::DebounceCapacity);
                self.recovery_refused_total[r_idx] =
                    self.recovery_refused_total[r_idx].saturating_add(1);
            }
            _ => {}
        }
        if let Some(d) = duration_ns {
            self.recovery_duration_ns_sum = self.recovery_duration_ns_sum.saturating_add(d);
            self.recovery_duration_count_total =
                self.recovery_duration_count_total.saturating_add(1);
        }
    }

    /// Record one or more origin-conflict drops. See
    /// [`crate::tracker::Tracker::take_origin_conflicts`] —
    /// a beat was dropped because its transport origin disagreed with the
    /// slot's pinned origin (first-origin-wins). Surfaced as
    /// `varta_origin_conflict_total`.
    pub fn record_origin_conflicts(&mut self, count: u64) {
        self.origin_conflict_total = self.origin_conflict_total.saturating_add(count);
    }

    /// Record one or more frame-namespace mismatches — kernel-attested
    /// datagrams dropped at receive because the peer's PID-namespace inode
    /// differs from the observer's. See
    /// [`crate::observer::Observer::drain_cross_namespace_drops`]. Surfaced
    /// as `varta_frame_namespace_mismatch_total`.
    pub fn record_frame_namespace_mismatches(&mut self, count: u64) {
        self.frame_namespace_mismatch_total =
            self.frame_namespace_mismatch_total.saturating_add(count);
    }

    /// Record one or more frames rejected because `frame.pid` exceeded the
    /// kernel's configured `pid_max`. See
    /// [`crate::observer::Observer::drain_pid_above_max_drops`]. Surfaced
    /// as `varta_frame_rejected_pid_above_max_total`.
    pub fn record_pid_above_max_drops(&mut self, count: u64) {
        self.frame_rejected_pid_above_max_total = self
            .frame_rejected_pid_above_max_total
            .saturating_add(count);
    }

    /// Record one or more tracker namespace conflicts — beats dropped because
    /// the slot's pinned PID-namespace inode disagreed with the beat's inode
    /// (first-namespace-wins). See
    /// [`crate::tracker::Tracker::take_namespace_conflicts`]. Surfaced as
    /// `varta_tracker_namespace_conflict_total`.
    pub fn record_tracker_namespace_conflicts(&mut self, count: u64) {
        self.tracker_namespace_conflict_total =
            self.tracker_namespace_conflict_total.saturating_add(count);
    }

    /// Record one or more tracker invariant violations recovered by the
    /// defensive `.get()` fall-throughs on the hot path. See
    /// [`crate::tracker::Tracker::take_invariant_violations`].
    pub fn record_tracker_invariant_violations(&mut self, count: u64) {
        self.tracker_invariant_violations_total = self
            .tracker_invariant_violations_total
            .saturating_add(count);
    }

    /// Record one or more [`crate::recovery::LastFiredTable`] evictions
    /// — debounce-respecting churn at table capacity.  Surfaced as
    /// `varta_recovery_last_fired_evictions_total`.
    pub fn record_recovery_last_fired_evictions(&mut self, count: u64) {
        self.recovery_last_fired_evictions_total = self
            .recovery_last_fired_evictions_total
            .saturating_add(count);
    }

    /// Record one or more [`crate::recovery::LastFiredTable`]
    /// invariant-violation fall-throughs.  Surfaced as
    /// `varta_recovery_invariant_violations_total`; non-zero values
    /// indicate a code bug.
    pub fn record_recovery_invariant_violations(&mut self, count: u64) {
        self.recovery_invariant_violations_total = self
            .recovery_invariant_violations_total
            .saturating_add(count);
    }

    /// Record one or more `PidIndex` probe-exhaustion events. See
    /// [`crate::tracker::Tracker::take_probe_exhausted`].
    pub fn record_tracker_pid_index_probe_exhausted(&mut self, count: u64) {
        self.tracker_pid_index_probe_exhausted_total = self
            .tracker_pid_index_probe_exhausted_total
            .saturating_add(count);
    }

    /// Record one or more scrapes served from cache (scrape arrived before
    /// [`PROM_MIN_SCRAPE_INTERVAL`] elapsed since the last fresh render).
    pub fn record_scrape_skipped(&mut self, count: u64) {
        self.scrape_skipped_total = self.scrape_skipped_total.saturating_add(count);
    }

    /// Record that the observer poll loop has completed another tick.
    /// Called once per outer loop iteration so that
    /// `varta_watch_last_poll_loop_timestamp_seconds` stays fresh.
    pub fn record_loop_tick(&mut self) {
        self.last_loop_system = SystemTime::now();
    }

    /// Override the soft per-iteration budget. Builder-style: returns
    /// `self` so the binary can chain `.bind(...).with_iteration_budget(...)`.
    pub fn with_iteration_budget(mut self, budget: Duration) -> Self {
        self.iteration_budget = budget;
        self
    }

    /// Override the soft per-call `serve_pending` budget. Builder-style.
    pub fn with_scrape_budget(mut self, budget: Duration) -> Self {
        self.scrape_budget = budget;
        self
    }

    /// Record the wall-clock duration of one `serve_pending` call.
    /// Updates the `varta_observer_serve_pending_seconds` histogram (same
    /// bucket boundaries as `iteration_seconds` for cross-metric
    /// coherence), the `_sum` / `_count` companions, and increments
    /// `varta_observer_scrape_budget_exceeded_total` when `d` exceeds
    /// [`Self::scrape_budget`]. Operators can subtract this histogram
    /// from `iteration_seconds` to isolate beat-path latency from
    /// scrape-induced variance.
    pub fn record_serve_pending_duration(&mut self, d: Duration) {
        let secs = d.as_secs_f64();
        let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.serve_pending_duration_ns_sum = self.serve_pending_duration_ns_sum.saturating_add(ns);
        self.serve_pending_count_total = self.serve_pending_count_total.saturating_add(1);
        let mut placed = false;
        for (i, &bound) in ITERATION_BUCKET_BOUNDS_S.iter().enumerate() {
            if secs <= bound {
                self.serve_pending_buckets[i] = self.serve_pending_buckets[i].saturating_add(1);
                placed = true;
                break;
            }
        }
        if !placed {
            let inf_idx = ITERATION_BUCKET_BOUNDS_S.len();
            self.serve_pending_buckets[inf_idx] =
                self.serve_pending_buckets[inf_idx].saturating_add(1);
        }
        if d > self.scrape_budget {
            self.scrape_budget_exceeded_total = self.scrape_budget_exceeded_total.saturating_add(1);
        }
    }

    /// Record the wall-clock duration of one observer poll iteration.
    /// Updates the `varta_observer_iteration_seconds` histogram, the
    /// `_sum` / `_count` companions, and increments
    /// `varta_observer_iteration_budget_exceeded_total` when `d` exceeds
    /// [`Self::iteration_budget`]. Buckets are stored non-cumulatively
    /// here and summed at exposition time.
    pub fn record_iteration_duration(&mut self, d: Duration) {
        let secs = d.as_secs_f64();
        let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.iteration_duration_ns_sum = self.iteration_duration_ns_sum.saturating_add(ns);
        self.iteration_count_total = self.iteration_count_total.saturating_add(1);
        let mut placed = false;
        for (i, &bound) in ITERATION_BUCKET_BOUNDS_S.iter().enumerate() {
            if secs <= bound {
                self.iteration_buckets[i] = self.iteration_buckets[i].saturating_add(1);
                placed = true;
                break;
            }
        }
        if !placed {
            let inf_idx = ITERATION_BUCKET_BOUNDS_S.len();
            self.iteration_buckets[inf_idx] = self.iteration_buckets[inf_idx].saturating_add(1);
        }
        if d > self.iteration_budget {
            self.iteration_budget_exceeded_total =
                self.iteration_budget_exceeded_total.saturating_add(1);
        }
    }

    /// Record one or more `MSG_CTRUNC` ancillary-data truncation events.
    /// Indicates the kernel's per-message metadata buffer is too small —
    /// a separate signal from generic I/O errors so operators can size
    /// `ANCILLARY_BUFFER_SIZE` appropriately.
    pub fn record_ctrl_truncated(&mut self, count: u64) {
        self.ctrl_truncated_total = self.ctrl_truncated_total.saturating_add(count);
    }

    /// Accept ready connections on the listener and write a metrics
    /// response back to each. Returns `Ok(())` when the accept queue
    /// drains cleanly; returns the first non-`WouldBlock` error otherwise.
    ///
    /// Service budget per call is bounded by two limits (whichever hits
    /// first): a 100 ms wall-clock deadline and
    /// [`PROM_MAX_CONNECTIONS_PER_SERVE`] accepted connections. Both
    /// exist to prevent a storm of slow scrapers from starving the
    /// observer poll loop (stall detection, I/O polling, reaping).
    ///
    /// After the service budget is exhausted, the exporter enters a
    /// drain phase that accepts and immediately closes up to
    /// [`PROM_MAX_DRAIN_PER_SERVE`] additional connections without
    /// serving them.  This prevents the kernel's accept queue from
    /// building up under a connection flood (hostile client opening
    /// thousands of connections).
    pub fn serve_pending(&mut self) -> io::Result<()> {
        let render_fresh = self
            .last_scrape
            .is_none_or(|last| last.elapsed() >= PROM_MIN_SCRAPE_INTERVAL);
        let serve_deadline = Instant::now() + Duration::from_millis(100);
        let mut served = 0;
        let result = loop {
            if Instant::now() >= serve_deadline {
                self.scrape_budget_exhausted_total =
                    self.scrape_budget_exhausted_total.saturating_add(1);
                break Ok(());
            }
            if served >= PROM_MAX_CONNECTIONS_PER_SERVE {
                self.scrape_budget_exhausted_total =
                    self.scrape_budget_exhausted_total.saturating_add(1);
                break Ok(());
            }
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    // Per-IP rate limit applies even before serve-budget
                    // counting: dropping a rate-limited connection costs
                    // an accept(2) + drop(2) but no body render, and does
                    // not consume the 8-conn budget.  This keeps a single
                    // hostile IP from squeezing out legitimate scrapers.
                    if !self.allow_ip(peer.ip(), Instant::now()) {
                        drop(stream);
                        continue;
                    }
                    self.serve_one(stream, render_fresh)?;
                    served += 1;
                    if !render_fresh {
                        self.scrape_skipped_total = self.scrape_skipped_total.saturating_add(1);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        if served > 0 && render_fresh {
            self.last_scrape = Some(Instant::now());
        }
        let mut drained = 0;
        while drained < PROM_MAX_DRAIN_PER_SERVE {
            if Instant::now() >= serve_deadline + Duration::from_millis(100) {
                break;
            }
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    // Update the IP bucket even on drained connections so a
                    // sustained flooder doesn't get a free pass once the
                    // serve budget is exhausted — its bucket continues to
                    // drain toward 0 and stays there.
                    let _ = self.allow_ip(peer.ip(), Instant::now());
                    drop(stream);
                    drained += 1;
                    self.connections_dropped_total[drop_reason_index(DropReason::Drain)] = self
                        .connections_dropped_total[drop_reason_index(DropReason::Drain)]
                    .saturating_add(1);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        result
    }

    fn serve_one(&mut self, mut stream: TcpStream, render_fresh: bool) -> io::Result<()> {
        // Accepted streams inherit the listener's non-blocking flag on both
        // Linux (via `accept4(SOCK_NONBLOCK)` in libstd) and macOS (libstd
        // calls `fcntl(F_SETFL, O_NONBLOCK)` post-accept). We intentionally
        // do *not* set a blocking read/write timeout here: a blocking socket
        // would let a slow peer hold the observer poll loop hostage for up
        // to the timeout per request. The PROM_READ_DEADLINE /
        // PROM_WRITE_TIMEOUT below are wall-clock budgets enforced by the
        // loops themselves, not socket-level timeouts.
        let deadline = Instant::now() + PROM_READ_DEADLINE;
        // 512 bytes is enough for a request line + Authorization header +
        // typical scrape headers (Prometheus' default request is ~110 bytes
        // including the 64-hex-char token).  We accumulate across reads so
        // that headers split across multiple TCP segments are still
        // contiguous when we scan for `Authorization:`.
        let mut buf = [0u8; 512];
        let mut total = 0;
        loop {
            if Instant::now() >= deadline {
                break;
            }
            if total >= buf.len() {
                break;
            }
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n")
                        || total >= PROM_REQUEST_CAP
                    {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        if total < 4 || buf[..4] != *b"GET " {
            let response = b"HTTP/1.0 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ =
                write_all_nonblocking(&mut stream, response, Instant::now() + PROM_WRITE_TIMEOUT);
            drain_read_to_would_block(&mut stream);
            let _ = stream.shutdown(Shutdown::Write);
            return Ok(());
        }

        // Bearer-token auth.  Header parsing skips the request line and
        // walks CRLF-terminated header fields until either Authorization
        // is found (and its 64-hex Bearer value matches the configured
        // token in constant time) or the headers run out.  All failure
        // paths bump `auth_failures_total` and return 401 without ever
        // touching the response body.
        let authorized = match parse_authorization_bearer(&buf[..total]) {
            Some(presented) => varta_vlp::ct_eq(&presented, self.token.as_bytes()),
            None => false,
        };
        if !authorized {
            self.auth_failures_total = self.auth_failures_total.saturating_add(1);
            let response = b"HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"varta\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ =
                write_all_nonblocking(&mut stream, response, Instant::now() + PROM_WRITE_TIMEOUT);
            drain_read_to_would_block(&mut stream);
            let _ = stream.shutdown(Shutdown::Write);
            return Ok(());
        }

        if render_fresh {
            self.render_body();
        }
        let body_len = self.body_buf.len();
        let write_deadline = Instant::now() + PROM_WRITE_TIMEOUT;
        // Write headers and body in two parts to avoid allocating a
        // combined response String.
        let _ = write_headers_with_len(&mut stream, body_len, write_deadline);
        let _ = write_all_nonblocking(&mut stream, self.body_buf.as_bytes(), write_deadline);
        drain_read_to_would_block(&mut stream);
        let _ = stream.shutdown(Shutdown::Write);
        Ok(())
    }

    fn render_body(&mut self) {
        self.body_buf.clear();
        const BODY_BUF_MAX_CAPACITY: usize = 65_536;
        if self.body_buf.capacity() > BODY_BUF_MAX_CAPACITY {
            self.body_buf = String::with_capacity(BODY_BUF_MAX_CAPACITY);
        }

        let mut pids: Vec<u32> = self.rows.keys().copied().collect();
        pids.sort_unstable();

        self.body_buf
            .push_str("# HELP varta_beats_total Total accepted beats per agent pid.\n");
        self.body_buf.push_str("# TYPE varta_beats_total counter\n");
        for pid in &pids {
            let row = &self.rows[pid];
            let _ = writeln!(
                self.body_buf,
                "varta_beats_total{{pid=\"{pid}\"}} {}",
                row.beats_total
            );
        }
        self.body_buf
            .push_str("# HELP varta_stalls_total Total observer-detected stalls per agent pid.\n");
        self.body_buf
            .push_str("# TYPE varta_stalls_total counter\n");
        for pid in &pids {
            let row = &self.rows[pid];
            let _ = writeln!(
                self.body_buf,
                "varta_stalls_total{{pid=\"{pid}\"}} {}",
                row.stalls_total
            );
        }
        self.body_buf.push_str("# HELP varta_status Last reported status code per agent pid (0=ok,1=degraded,2=critical,3=stall).\n");
        self.body_buf.push_str("# TYPE varta_status gauge\n");
        for pid in &pids {
            let row = &self.rows[pid];
            if let Some(code) = row.last_status {
                let _ = writeln!(self.body_buf, "varta_status{{pid=\"{pid}\"}} {code}");
            }
        }
        self.body_buf.push_str(
            "# HELP varta_tracker_evicted_total Total tracker slots reclaimed from dead agents.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_tracker_evicted_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_evicted_total {}",
            self.evicted_total
        );
        // Security counter — always emitted, even at 0.  Otherwise dashboards
        // and `absent()` alert rules silently produce no series until the
        // first spoof attempt, which defeats the purpose of an alert.
        self.body_buf.push_str(
            "# HELP varta_frame_auth_failures_total Frames rejected due to PID spoofing or authentication failure.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_frame_auth_failures_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_frame_auth_failures_total {}",
            self.auth_failures_total
        );
        // Always emit one series per kind so dashboards and `absent()` rules
        // stay green-on-green instead of disappearing until the first incident.
        self.body_buf
            .push_str("# HELP varta_decode_errors_total Total VLP decode failures by kind.\n");
        self.body_buf
            .push_str("# TYPE varta_decode_errors_total counter\n");
        for (idx, kind) in DECODE_KIND_LABELS.iter().enumerate() {
            let _ = writeln!(
                self.body_buf,
                "varta_decode_errors_total{{kind=\"{kind}\"}} {}",
                self.decode_errors_total[idx]
            );
        }
        self.body_buf
            .push_str("# HELP varta_io_errors_total Total socket receive errors.\n");
        self.body_buf
            .push_str("# TYPE varta_io_errors_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_io_errors_total {}",
            self.io_errors_total
        );
        self.body_buf
            .push_str("# HELP varta_ctrl_truncated_total Total ancillary-data truncation events (MSG_CTRUNC on Linux).\n");
        self.body_buf
            .push_str("# TYPE varta_ctrl_truncated_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_ctrl_truncated_total {}",
            self.ctrl_truncated_total
        );
        self.body_buf.push_str("# HELP varta_tracker_capacity_exceeded_total Total beats dropped because tracker is full.\n");
        self.body_buf
            .push_str("# TYPE varta_tracker_capacity_exceeded_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_capacity_exceeded_total {}",
            self.capacity_exceeded_total
        );
        // Emitted unconditionally (even at zero) so `absent()` alert rules
        // stay green-on-green — see the contract on
        // `varta_decode_errors_total`. Non-zero values prove the bounded
        // eviction-scan window cap engaged under a unique-pid flood.
        self.body_buf.push_str("# HELP varta_tracker_eviction_scan_truncated_total Total bounded eviction scans that exhausted the window without finding a victim.\n");
        self.body_buf
            .push_str("# TYPE varta_tracker_eviction_scan_truncated_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_eviction_scan_truncated_total {}",
            self.eviction_scan_truncated_total
        );
        self.body_buf.push_str("# HELP varta_tracker_capacity Configured tracker capacity (max distinct agent pids).\n");
        self.body_buf
            .push_str("# TYPE varta_tracker_capacity gauge\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_capacity {}",
            self.tracker_capacity_cfg
        );
        self.body_buf.push_str("# HELP varta_tracker_eviction_scan_window_max Configured eviction scan window; per-frame WCET = ceil(capacity / window_max) calls.\n");
        self.body_buf
            .push_str("# TYPE varta_tracker_eviction_scan_window_max gauge\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_eviction_scan_window_max {}",
            self.eviction_scan_window_max
        );
        // Recovery outcome counters — emit every label value at zero from the
        // first scrape so `absent()` rules stay green even before the first
        // recovery fires.
        self.body_buf
            .push_str("# HELP varta_recovery_outcomes_total Total recovery outcomes by kind.\n");
        self.body_buf
            .push_str("# TYPE varta_recovery_outcomes_total counter\n");
        for (idx, outcome) in RECOVERY_OUTCOME_LABELS.iter().enumerate() {
            let _ = writeln!(
                self.body_buf,
                "varta_recovery_outcomes_total{{outcome=\"{outcome}\"}} {}",
                self.recovery_outcomes_total[idx]
            );
        }
        self.body_buf.push_str(
            "# HELP varta_recovery_duration_ns_sum Sum of recovery child wall-clock durations in ns.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_duration_ns_sum counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_recovery_duration_ns_sum {}",
            self.recovery_duration_ns_sum
        );
        self.body_buf.push_str(
            "# HELP varta_recovery_duration_count_total Number of recovery completions contributing to varta_recovery_duration_ns_sum.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_duration_count_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_recovery_duration_count_total {}",
            self.recovery_duration_count_total
        );
        // varta_recovery_refused_total — structural refusals broken down by reason.
        // Always emit every label value (even at zero) so `absent()` alert
        // rules stay green until the first refusal occurs.
        self.body_buf.push_str(
            "# HELP varta_recovery_refused_total Recovery commands NOT spawned because of a structural safety gate, by reason.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_refused_total counter\n");
        for (idx, reason) in RECOVERY_REFUSED_REASON_LABELS.iter().enumerate() {
            let _ = writeln!(
                self.body_buf,
                "varta_recovery_refused_total{{reason=\"{reason}\"}} {}",
                self.recovery_refused_total[idx]
            );
        }
        // varta_recovery_last_fired_evictions_total — table churn at
        // capacity that respected the debounce invariant (the evicted
        // entry's window had elapsed).  Operators tune
        // `MAX_LAST_FIRED_CAPACITY` on this signal.  Always emit so
        // `absent()` alert rules stay green-on-green.
        self.body_buf.push_str(
            "# HELP varta_recovery_last_fired_evictions_total LastFiredTable entries dropped (debounce-respecting) to make room for a new pid at table capacity.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_last_fired_evictions_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_recovery_last_fired_evictions_total {}",
            self.recovery_last_fired_evictions_total
        );
        // varta_recovery_invariant_violations_total — defensive
        // fall-throughs in `LastFiredTable`.  Non-zero values mean a
        // code bug, not load.  Same alerting posture as
        // `varta_tracker_invariant_violations_total`.
        self.body_buf.push_str(
            "# HELP varta_recovery_invariant_violations_total LastFiredTable defensive fall-throughs — should remain at 0 in correct operation.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_invariant_violations_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_recovery_invariant_violations_total {}",
            self.recovery_invariant_violations_total
        );
        // varta_log_suppressed_total — messages suppressed by the per-kind
        // 1-second cooldown rate limiter.  Non-zero values indicate a
        // sustained error flood on that path (e.g. a broken file-export
        // sink).  Always emitted in full so `absent()` alert rules stay
        // green-on-green.
        {
            let suppressed = LOG_RATE_LIMITER
                .lock()
                .map(|g| g.snapshot_totals())
                .unwrap_or([0; LogKind::COUNT]);
            self.body_buf.push_str(
                "# HELP varta_log_suppressed_total Log messages suppressed by the per-kind cooldown rate limiter.\n",
            );
            self.body_buf
                .push_str("# TYPE varta_log_suppressed_total counter\n");
            for (idx, kind) in LOG_KIND_LABELS.iter().enumerate() {
                let _ = writeln!(
                    self.body_buf,
                    "varta_log_suppressed_total{{kind=\"{kind}\"}} {}",
                    suppressed[idx]
                );
            }
        }
        // varta_origin_conflict_total — beats dropped because the slot's
        // pinned transport origin disagreed with the beat's origin
        // (first-origin-wins). Non-zero values indicate either operator
        // misconfiguration (same pid emitted from two transports) or an
        // active spoofing attempt.
        self.body_buf.push_str(
            "# HELP varta_origin_conflict_total Beats dropped because the slot's pinned transport origin disagreed with the beat's origin.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_origin_conflict_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_origin_conflict_total {}",
            self.origin_conflict_total
        );
        // varta_frame_namespace_mismatch_total — kernel-attested frames
        // dropped at receive because the peer's PID-namespace inode differs
        // from the observer's. Linux-only signal; 0 elsewhere. Always emitted
        // so `absent()` rules stay green-on-green.
        self.body_buf.push_str(
            "# HELP varta_frame_namespace_mismatch_total Frames dropped at receive because the peer's PID-namespace inode differs from the observer's.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_frame_namespace_mismatch_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_frame_namespace_mismatch_total {}",
            self.frame_namespace_mismatch_total
        );
        // varta_frame_rejected_pid_above_max_total — frames dropped because
        // `frame.pid` exceeded the kernel's `pid_max`. Always emitted so
        // `absent()` rules stay green-on-green; Linux-only signal.
        self.body_buf.push_str(
            "# HELP varta_frame_rejected_pid_above_max_total Frames dropped at receive because frame.pid exceeded the kernel's configured pid_max.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_frame_rejected_pid_above_max_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_frame_rejected_pid_above_max_total {}",
            self.frame_rejected_pid_above_max_total
        );
        // varta_tracker_namespace_conflict_total — beats dropped because the
        // slot's pinned PID-namespace inode disagreed with the beat's inode
        // (first-namespace-wins). Linux-only signal.
        self.body_buf.push_str(
            "# HELP varta_tracker_namespace_conflict_total Beats dropped because the slot's pinned PID-namespace inode disagreed with the beat's (first-namespace-wins).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_tracker_namespace_conflict_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_namespace_conflict_total {}",
            self.tracker_namespace_conflict_total
        );
        // Tracker hot-path invariant violations recovered without panic.
        // Always emitted (even at zero) so `absent()` alert rules stay
        // green-on-green; any non-zero scrape is a bug worth investigating.
        self.body_buf.push_str(
            "# HELP varta_tracker_invariant_violations_total Tracker hot-path invariant violations recovered by defensive .get() fall-throughs (e.g. stale PidIndex entry pointing at an OOB slot). Non-zero = bug, not a panic.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_tracker_invariant_violations_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_invariant_violations_total {}",
            self.tracker_invariant_violations_total
        );
        // PidIndex probe-exhaustion — pid lookup / insert walked the full
        // MAX_PROBE budget without resolving. At load factor ≤ 0.5 this is
        // effectively unreachable.
        self.body_buf.push_str(
            "# HELP varta_tracker_pid_index_probe_exhausted_total PidIndex lookups/inserts that ran the full MAX_PROBE budget. Should stay at 0 at load factor ≤ 0.5.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_tracker_pid_index_probe_exhausted_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_pid_index_probe_exhausted_total {}",
            self.tracker_pid_index_probe_exhausted_total
        );
        self.body_buf.push_str(
            "# HELP varta_frame_decrypt_failures_total Total AEAD decryption/tag-verification failures.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_frame_decrypt_failures_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_frame_decrypt_failures_total {}",
            self.decrypt_failures_total
        );
        self.body_buf.push_str(
            "# HELP varta_truncated_datagrams_total Total datagrams received with wrong size.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_truncated_datagrams_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_truncated_datagrams_total {}",
            self.truncated_total
        );
        self.body_buf.push_str(
            "# HELP varta_sender_state_full_total Total times the sender-state map was full and an entry was force-evicted.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_sender_state_full_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_sender_state_full_total {}",
            self.sender_state_full_total
        );
        self.body_buf.push_str(
            "# HELP varta_secure_aead_attempts_total Total ChaCha20-Poly1305 decryption attempts across the loaded key set. The listener trials every loaded key (and the master-key derivation, if configured) on every frame, removing the linear-in-key-index timing side-channel. In steady state this equals frames_received * (keys.len() + master_key_configured as u64).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_secure_aead_attempts_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_secure_aead_attempts_total {}",
            self.secure_aead_attempts_total
        );
        self.body_buf.push_str(
            "# HELP varta_rate_limited_total Total beats dropped by per-pid rate limiting.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_rate_limited_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_rate_limited_total {}",
            self.rate_limited_total
        );
        self.body_buf.push_str(
            "# HELP varta_scrape_skipped_total Number of /metrics scrapes served from cache (rate-limited).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_scrape_skipped_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_scrape_skipped_total {}",
            self.scrape_skipped_total
        );
        self.body_buf.push_str(
            "# HELP varta_scrape_budget_exhausted_total Times the serve budget (max connections or deadline) was exhausted during a poll tick.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_scrape_budget_exhausted_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_scrape_budget_exhausted_total {}",
            self.scrape_budget_exhausted_total
        );
        // Observer poll-loop iteration histogram.  Emitted as a Prometheus
        // histogram (cumulative `_bucket{le=...}` series plus `_sum` and
        // `_count`).  Every bucket boundary — including `+Inf` — is rendered
        // on every scrape, even before the first observation, so `absent()`
        // alert rules and `histogram_quantile()` queries stay green from the
        // first scrape (same contract as `varta_decode_errors_total`).
        self.body_buf.push_str(
            "# HELP varta_observer_iteration_seconds Observer poll-loop iteration wall time (excludes idle sleep and test-hooks wedge).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_observer_iteration_seconds histogram\n");
        let mut cum: u64 = 0;
        for (idx, bound) in ITERATION_BUCKET_BOUNDS_S.iter().enumerate() {
            cum = cum.saturating_add(self.iteration_buckets[idx]);
            let _ = writeln!(
                self.body_buf,
                "varta_observer_iteration_seconds_bucket{{le=\"{bound}\"}} {cum}",
            );
        }
        let inf_idx = ITERATION_BUCKET_BOUNDS_S.len();
        cum = cum.saturating_add(self.iteration_buckets[inf_idx]);
        let _ = writeln!(
            self.body_buf,
            "varta_observer_iteration_seconds_bucket{{le=\"+Inf\"}} {cum}"
        );
        let sum_s = (self.iteration_duration_ns_sum as f64) / 1e9;
        let _ = writeln!(
            self.body_buf,
            "varta_observer_iteration_seconds_sum {sum_s:.9}"
        );
        let _ = writeln!(
            self.body_buf,
            "varta_observer_iteration_seconds_count {}",
            self.iteration_count_total
        );
        self.body_buf.push_str(
            "# HELP varta_observer_iteration_budget_exceeded_total Observer poll iterations that exceeded the soft --iteration-budget-ms.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_observer_iteration_budget_exceeded_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_observer_iteration_budget_exceeded_total {}",
            self.iteration_budget_exceeded_total
        );
        // Scrape-only latency histogram — `serve_pending` wall time alone.
        // Same bucket boundaries as `iteration_seconds` so beat-path latency
        // = iteration_seconds - serve_pending_seconds is meaningful in
        // PromQL.  Emit every bucket (including `+Inf`) on every scrape so
        // `absent()` alerts stay green from the first scrape onward.
        // See `book/src/architecture/observer-liveness.md` ("Why /metrics is on
        // the poll thread") for the rationale for measuring this
        // separately rather than moving serving to a thread.
        self.body_buf.push_str(
            "# HELP varta_observer_serve_pending_seconds Wall time spent in PromExporter::serve_pending per poll-loop tick. Subtract from iteration_seconds to derive beat-path latency.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_observer_serve_pending_seconds histogram\n");
        let mut cum_sp: u64 = 0;
        for (idx, bound) in ITERATION_BUCKET_BOUNDS_S.iter().enumerate() {
            cum_sp = cum_sp.saturating_add(self.serve_pending_buckets[idx]);
            let _ = writeln!(
                self.body_buf,
                "varta_observer_serve_pending_seconds_bucket{{le=\"{bound}\"}} {cum_sp}",
            );
        }
        let inf_idx_sp = ITERATION_BUCKET_BOUNDS_S.len();
        cum_sp = cum_sp.saturating_add(self.serve_pending_buckets[inf_idx_sp]);
        let _ = writeln!(
            self.body_buf,
            "varta_observer_serve_pending_seconds_bucket{{le=\"+Inf\"}} {cum_sp}"
        );
        let sum_s_sp = (self.serve_pending_duration_ns_sum as f64) / 1e9;
        let _ = writeln!(
            self.body_buf,
            "varta_observer_serve_pending_seconds_sum {sum_s_sp:.9}"
        );
        let _ = writeln!(
            self.body_buf,
            "varta_observer_serve_pending_seconds_count {}",
            self.serve_pending_count_total
        );
        self.body_buf.push_str(
            "# HELP varta_observer_scrape_budget_exceeded_total serve_pending calls that exceeded the soft --scrape-budget-ms.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_observer_scrape_budget_exceeded_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_observer_scrape_budget_exceeded_total {}",
            self.scrape_budget_exceeded_total
        );
        // Authentication failures on /metrics — emit unconditionally
        // (even at zero) so `absent()` alert rules stay green-on-green
        // until the first incident.  Same contract as
        // `varta_decode_errors_total` and
        // `varta_prom_connections_dropped_total`.
        self.body_buf.push_str(
            "# HELP varta_prom_auth_failures_total Number of /metrics scrapes rejected because the bearer token was missing or wrong.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_prom_auth_failures_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_prom_auth_failures_total {}",
            self.auth_failures_total
        );
        // Per-reason connection drop counter — emit every label value
        // unconditionally so `absent()` alert rules stay green-on-green
        // until the first incident of that kind.  Three reasons today:
        // drain (accept-and-close after serve budget exhausted),
        // rate_limit (per-source-IP token bucket empty), and
        // ip_table_full (per-IP state table at MAX_PROM_IP_STATES and the
        // oldest entry was force-evicted).
        self.body_buf.push_str(
            "# HELP varta_prom_connections_dropped_total Connections accepted on /metrics but closed before serving, by reason.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_prom_connections_dropped_total counter\n");
        for (idx, reason) in DROP_REASON_LABELS.iter().enumerate() {
            let _ = writeln!(
                self.body_buf,
                "varta_prom_connections_dropped_total{{reason=\"{reason}\"}} {}",
                self.connections_dropped_total[idx]
            );
        }
        self.body_buf.push_str(
            "# HELP varta_nonce_wrap_total Total nonce-space wrap events detected (agent exhausted u64 nonces).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_nonce_wrap_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_nonce_wrap_total {}",
            self.nonce_wrap_total
        );
        // --- Observer self-health metrics ---------------------------------
        self.body_buf
            .push_str("# HELP varta_watch_uptime_seconds Observer process uptime in seconds.\n");
        self.body_buf
            .push_str("# TYPE varta_watch_uptime_seconds gauge\n");
        let uptime = self.started_at.elapsed().as_secs_f64();
        let _ = writeln!(self.body_buf, "varta_watch_uptime_seconds {uptime:.3}");
        self.body_buf.push_str(
            "# HELP varta_watch_last_poll_loop_timestamp_seconds Unix timestamp of the most recent poll loop iteration.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_watch_last_poll_loop_timestamp_seconds gauge\n");
        let loop_ts = self
            .last_loop_system
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let _ = writeln!(
            self.body_buf,
            "varta_watch_last_poll_loop_timestamp_seconds {loop_ts:.3}"
        );
        self.body_buf.push_str(
            "# HELP varta_watch_pids_tracked Current number of agent PIDs in the tracker.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_watch_pids_tracked gauge\n");
        let _ = writeln!(
            self.body_buf,
            "varta_watch_pids_tracked {}",
            self.rows.len()
        );
    }
}

#[cfg(feature = "prometheus-exporter")]
impl Exporter for PromExporter {
    fn record(&mut self, ev: &Event) -> io::Result<()> {
        match ev {
            Event::Beat {
                pid,
                status,
                observer_ns: _,
                ..
            } => {
                let row = self.rows.entry(*pid).or_insert_with(GaugeRow::new);
                row.beats_total = row.beats_total.saturating_add(1);
                row.last_status = Some(*status as u8);
            }
            Event::Stall {
                pid,
                observer_ns: _,
                ..
            } => {
                let row = self.rows.entry(*pid).or_insert_with(GaugeRow::new);
                row.stalls_total = row.stalls_total.saturating_add(1);
                row.last_status = Some(Status::Stall as u8);
            }
            Event::AuthFailure { observer_ns: _, .. } => {
                self.auth_failures_total = self.auth_failures_total.saturating_add(1);
            }
            Event::OriginConflict { .. } => {
                // Tallied through `record_origin_conflicts` on the per-tick
                // drain so the counter survives even when no event is
                // surfaced (e.g. another higher-priority event won the poll
                // round). This arm just acknowledges the variant for
                // exhaustiveness.
            }
            Event::NamespaceConflict { .. } => {
                // Counted on the per-tick drain via `record_cross_namespace_drops`
                // and `record_namespace_conflicts`. Acknowledged here for
                // exhaustive matching.
            }
            Event::Decode(err, _) => {
                let idx = decode_kind_index(err);
                self.decode_errors_total[idx] = self.decode_errors_total[idx].saturating_add(1);
            }
            Event::Io(_, _) => {
                self.io_errors_total = self.io_errors_total.saturating_add(1);
            }
            Event::CtrlTruncated(_, _) => {
                self.ctrl_truncated_total = self.ctrl_truncated_total.saturating_add(1);
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Write the HTTP 200 response line and headers (including Content-Length)
/// into `stream` using a stack buffer so no heap allocation occurs on the
/// `/metrics` scrape path.
#[cfg(feature = "prometheus-exporter")]
fn write_headers_with_len(
    stream: &mut TcpStream,
    body_len: usize,
    deadline: Instant,
) -> io::Result<()> {
    let mut buf = [0u8; 128];
    let prefix = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: ";
    let suffix = b"\r\nConnection: close\r\n\r\n";
    let len_str_len = write_usize(&mut buf[prefix.len()..], body_len);
    let total = prefix.len() + len_str_len + suffix.len();
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len() + len_str_len..total].copy_from_slice(suffix);
    write_all_nonblocking(stream, &buf[..total], deadline)
}

/// Write `n` as decimal ASCII into `buf` and return the number of bytes
/// written.
///
/// `usize` on 64-bit can require up to 20 decimal digits.  The caller must
/// ensure `buf` is large enough; the debug assertion catches undersized
/// buffers at test time and has zero overhead in release builds.
#[cfg(feature = "prometheus-exporter")]
fn write_usize(buf: &mut [u8], mut n: usize) -> usize {
    debug_assert!(
        buf.len() >= 20,
        "write_usize: buffer too small ({})",
        buf.len()
    );
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut pos = buf.len();
    while n > 0 {
        pos -= 1;
        buf[pos] = (n % 10) as u8 + b'0';
        n /= 10;
    }
    let len = buf.len() - pos;
    buf.copy_within(pos.., 0);
    len
}

/// Maximum number of `yield_now()` calls per `write_all_nonblocking`
/// invocation.  At ~100 µs per yield (macOS) and 10 yields this bounds
/// scheduler concessions to ~1 ms, well within the 50 ms
/// [`PROM_WRITE_TIMEOUT`].
#[cfg(feature = "prometheus-exporter")]
const MAX_WRITE_YIELDS: usize = 10;

/// Non-blocking `write_all` with a wall-clock deadline. Returns `Ok(())`
/// whether the full buffer was written or the deadline expired; the caller
/// is responsible for deciding whether a short write is an error.
///
/// On `WouldBlock` the loop yields the thread to the OS scheduler rather
/// than busy-spinning.  To prevent a persistently-full TCP send buffer from
/// starving the observer poll loop, the function yields at most
/// [`MAX_WRITE_YIELDS`] times before giving up on the current buffer.
///
/// `yield_now()` can be surprisingly long on macOS (~100 µs).  With the
/// 50 ms [`PROM_WRITE_TIMEOUT`] a 10-yield budget is safe.
#[cfg(feature = "prometheus-exporter")]
fn write_all_nonblocking(stream: &mut TcpStream, buf: &[u8], deadline: Instant) -> io::Result<()> {
    let mut written = 0;
    let mut yields = 0;
    while written < buf.len() {
        if Instant::now() >= deadline {
            break;
        }
        match stream.write(&buf[written..]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if yields >= MAX_WRITE_YIELDS {
                    break;
                }
                yields += 1;
                std::thread::yield_now();
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Parse `Authorization: Bearer <64hex>` out of a buffered HTTP/1.x
/// request without allocating.  Returns the decoded 32-byte token when
/// the header is present, well-formed, and carries exactly 64 hex
/// characters of token material; returns `None` otherwise.  The header
/// field name is matched case-insensitively per RFC 7230 §3.2.
#[cfg(feature = "prometheus-exporter")]
fn parse_authorization_bearer(buf: &[u8]) -> Option<[u8; 32]> {
    // Skip the request line. find_crlf returns the index of '\r'; bump
    // past the '\n' that follows.
    let mut rest = match find_crlf(buf) {
        Some(eol) => &buf[eol + 2..],
        // No CRLF at all — too short to carry a header anyway.
        None => return None,
    };
    while let Some(eol) = find_crlf(rest) {
        let line = &rest[..eol];
        rest = &rest[eol + 2..];
        if line.is_empty() {
            // Empty line == end of headers.
            return None;
        }
        const HDR: &[u8] = b"authorization:";
        if line.len() >= HDR.len() && line[..HDR.len()].eq_ignore_ascii_case(HDR) {
            let mut value = &line[HDR.len()..];
            while let Some(b) = value.first().copied() {
                if b == b' ' || b == b'\t' {
                    value = &value[1..];
                } else {
                    break;
                }
            }
            const BEARER: &[u8] = b"bearer ";
            if value.len() < BEARER.len() {
                return None;
            }
            if !value[..BEARER.len()].eq_ignore_ascii_case(BEARER) {
                return None;
            }
            let mut token_part = &value[BEARER.len()..];
            while let Some(b) = token_part.first().copied() {
                if b == b' ' || b == b'\t' {
                    token_part = &token_part[1..];
                } else {
                    break;
                }
            }
            if token_part.len() < 64 {
                return None;
            }
            return varta_vlp::decode_hex_32(&token_part[..64]).ok();
        }
    }
    None
}

/// Position of the first `\r\n` byte pair in `buf`.
#[cfg(feature = "prometheus-exporter")]
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Drain any unread data from the peer's send buffer so that
/// `shutdown(SHUT_WR)` sends a graceful FIN instead of RST.
///
/// On macOS, calling `shutdown(SHUT_WR)` on a non-blocking socket that has
/// unread data in the receive buffer triggers an RST rather than a TCP FIN.
/// This non-blocking drain empties the receive buffer, letting
/// `shutdown(SHUT_WR)` complete cleanly on all platforms.
#[cfg(feature = "prometheus-exporter")]
fn drain_read_to_would_block(stream: &mut TcpStream) {
    let mut buf = [0u8; 128];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

#[cfg(all(test, feature = "prometheus-exporter"))]
mod tests {
    use super::*;

    /// Shared 32-byte bearer token for unit tests.  The bytes are arbitrary
    /// (chosen so a casual `xxd` of a capture is obviously synthetic) and
    /// the lowercase 64-char hex form is exposed as `TEST_TOKEN_HEX` for
    /// tests that need to inject it into an HTTP request.
    const TEST_TOKEN: [u8; 32] = [0xab; 32];
    const TEST_TOKEN_HEX: &str = "abababababababababababababababababababababababababababababababab";

    fn make_token() -> BearerToken {
        BearerToken::from_bytes(TEST_TOKEN)
    }

    #[test]
    fn render_body_sorts_pids_numerically() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        prom.record(&Event::Beat {
            pid: 30,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 0,
            origin: crate::peer_cred::BeatOrigin::KernelAttested,
            pid_ns_inode: None,
        })
        .unwrap();
        prom.record(&Event::Beat {
            pid: 2,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 0,
            origin: crate::peer_cred::BeatOrigin::KernelAttested,
            pid_ns_inode: None,
        })
        .unwrap();
        prom.record(&Event::Beat {
            pid: 11,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 0,
            origin: crate::peer_cred::BeatOrigin::KernelAttested,
            pid_ns_inode: None,
        })
        .unwrap();
        prom.render_body();
        let body = &prom.body_buf;
        let pos2 = body.find("pid=\"2\"").expect("pid 2");
        let pos11 = body.find("pid=\"11\"").expect("pid 11");
        let pos30 = body.find("pid=\"30\"").expect("pid 30");
        assert!(pos2 < pos11 && pos11 < pos30, "sort order broken:\n{body}");
    }

    #[test]
    fn decode_and_io_events_do_not_create_rows() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        prom.record(&Event::Decode(varta_vlp::DecodeError::BadMagic, 0))
            .unwrap();
        prom.record(&Event::Io(io::Error::other("x"), 0)).unwrap();
        assert!(prom.rows.is_empty());
    }

    #[test]
    fn decode_errors_emit_kind_label_for_every_variant_even_at_zero() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        // Bump bad_magic twice, bad_status once, leave bad_version at zero.
        prom.record(&Event::Decode(DecodeError::BadMagic, 0))
            .unwrap();
        prom.record(&Event::Decode(DecodeError::BadMagic, 0))
            .unwrap();
        prom.record(&Event::Decode(DecodeError::BadStatus(0xff), 0))
            .unwrap();

        prom.render_body();
        let body = &prom.body_buf;
        // All three kind series must be present so `absent()` rules don't
        // silently disappear before the first incident of that kind.
        assert!(
            body.contains("varta_decode_errors_total{kind=\"bad_magic\"} 2"),
            "missing or wrong bad_magic series:\n{body}"
        );
        assert!(
            body.contains("varta_decode_errors_total{kind=\"bad_version\"} 0"),
            "missing zero-valued bad_version series:\n{body}"
        );
        assert!(
            body.contains("varta_decode_errors_total{kind=\"bad_status\"} 1"),
            "missing or wrong bad_status series:\n{body}"
        );
    }

    #[test]
    fn non_get_request_returns_405() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        let addr = prom.local_addr().expect("local_addr");
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        stream
            .write_all(b"POST /metrics HTTP/1.0\r\n\r\n")
            .expect("write");
        // Yield so the kernel can deliver the bytes to the listener's
        // accept queue before serve_pending() runs; under concurrent
        // test load the write→accept race is otherwise observable.
        std::thread::sleep(Duration::from_millis(5));
        prom.serve_pending().expect("serve_pending");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        assert!(
            response.starts_with("HTTP/1.0 405 Method Not Allowed"),
            "expected 405, got: {response}"
        );
        assert!(
            response.contains("Allow: GET"),
            "missing Allow header: {response}"
        );
    }

    /// Drive a single GET against the exporter with optional Authorization
    /// header; returns the raw response so each test can assert on its
    /// status line, headers, and body independently.
    fn one_get(prom: &mut PromExporter, addr: SocketAddr, auth: Option<&str>) -> String {
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let mut req = String::from("GET /metrics HTTP/1.0\r\nHost: localhost\r\n");
        if let Some(a) = auth {
            req.push_str("Authorization: ");
            req.push_str(a);
            req.push_str("\r\n");
        }
        req.push_str("Connection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).expect("write");
        // Yield so the kernel can deliver the bytes to the accept queue
        // before serve_pending reads them.
        std::thread::sleep(Duration::from_millis(5));
        prom.serve_pending().expect("serve_pending");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        response
    }

    #[test]
    fn metrics_requires_bearer_token() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        let addr = prom.local_addr().expect("local_addr");
        let response = one_get(&mut prom, addr, None);
        assert!(
            response.starts_with("HTTP/1.0 401 Unauthorized"),
            "expected 401 on missing auth, got: {response}"
        );
        assert!(
            response.contains("WWW-Authenticate: Bearer"),
            "missing WWW-Authenticate header: {response}"
        );
        assert_eq!(
            prom.auth_failures_total, 1,
            "auth_failures_total must bump on missing auth"
        );
    }

    #[test]
    fn metrics_rejects_wrong_token() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        let addr = prom.local_addr().expect("local_addr");
        let bad = "Bearer 0000000000000000000000000000000000000000000000000000000000000000";
        let response = one_get(&mut prom, addr, Some(bad));
        assert!(
            response.starts_with("HTTP/1.0 401 Unauthorized"),
            "expected 401 on wrong token, got: {response}"
        );
        assert_eq!(
            prom.auth_failures_total, 1,
            "auth_failures_total must bump on wrong token"
        );
    }

    #[test]
    fn metrics_accepts_valid_token() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        let addr = prom.local_addr().expect("local_addr");
        let good = format!("Bearer {TEST_TOKEN_HEX}");
        let response = one_get(&mut prom, addr, Some(&good));
        assert!(
            response.starts_with("HTTP/1.0 200 OK"),
            "expected 200 on valid token, got: {response}"
        );
        assert_eq!(
            prom.auth_failures_total, 0,
            "auth_failures_total must not bump on success"
        );
    }

    #[test]
    fn metrics_authorization_header_is_case_insensitive() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        let addr = prom.local_addr().expect("local_addr");
        // Lowercase `bearer` and uppercase hex must both succeed.
        let token_upper = TEST_TOKEN_HEX.to_uppercase();
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let req = format!(
            "GET /metrics HTTP/1.0\r\nauthorization: bearer {token_upper}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).expect("write");
        std::thread::sleep(Duration::from_millis(5));
        prom.serve_pending().expect("serve_pending");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        assert!(
            response.starts_with("HTTP/1.0 200 OK"),
            "expected 200 with case-insensitive header, got: {response}"
        );
    }

    #[test]
    fn auth_failures_counter_emitted_at_zero_in_body() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        prom.render_body();
        assert!(
            prom.body_buf.contains("varta_prom_auth_failures_total 0"),
            "auth_failures_total must emit at zero; body:\n{}",
            prom.body_buf
        );
    }

    #[test]
    fn parse_authorization_bearer_finds_token_among_many_headers() {
        let req = format!(
            "GET /metrics HTTP/1.0\r\nHost: localhost\r\nX-Foo: bar\r\nAuthorization: Bearer {TEST_TOKEN_HEX}\r\nUser-Agent: prom/2\r\n\r\n"
        );
        let parsed =
            parse_authorization_bearer(req.as_bytes()).expect("token must parse out of headers");
        assert_eq!(parsed, TEST_TOKEN);
    }

    #[test]
    fn parse_authorization_bearer_rejects_non_bearer_scheme() {
        let req = "GET /metrics HTTP/1.0\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n";
        assert!(parse_authorization_bearer(req.as_bytes()).is_none());
    }

    #[test]
    fn parse_authorization_bearer_rejects_short_token() {
        let req = "GET /metrics HTTP/1.0\r\nAuthorization: Bearer abc\r\n\r\n";
        assert!(parse_authorization_bearer(req.as_bytes()).is_none());
    }

    #[test]
    fn record_evicted_pid_removes_row() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        prom.record(&Event::Beat {
            pid: 42,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 0,
            origin: crate::peer_cred::BeatOrigin::KernelAttested,
            pid_ns_inode: None,
        })
        .unwrap();
        assert!(prom.rows.contains_key(&42), "row should exist after beat");
        prom.record_evicted_pid(42);
        assert!(
            !prom.rows.contains_key(&42),
            "row should be removed after eviction"
        );
    }

    #[test]
    fn record_evicted_pid_ignores_unknown_pid() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        // Should not panic when called for a pid that was never tracked.
        prom.record_evicted_pid(99);
        // Verify rows is still empty.
        assert!(prom.rows.is_empty());
    }

    #[test]
    fn self_health_metrics_are_emitted() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        // Add a tracked PID so pids_tracked > 0
        prom.record(&Event::Beat {
            pid: 7,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 1,
            origin: crate::peer_cred::BeatOrigin::KernelAttested,
            pid_ns_inode: None,
        })
        .unwrap();
        prom.record_loop_tick();
        prom.render_body();
        let body = &prom.body_buf;
        assert!(
            body.contains("varta_watch_uptime_seconds"),
            "missing varta_watch_uptime_seconds:\n{body}"
        );
        assert!(
            body.contains("varta_watch_last_poll_loop_timestamp_seconds"),
            "missing varta_watch_last_poll_loop_timestamp_seconds:\n{body}"
        );
        assert!(
            body.contains("varta_watch_pids_tracked 1"),
            "missing/incorrect varta_watch_pids_tracked:\n{body}"
        );
        // Uptime should be small (just created)
        let needle = "varta_watch_uptime_seconds 0.";
        assert!(body.contains(needle), "uptime should start near 0:\n{body}");
        // pids_tracked after eviction
        prom.record_evicted_pid(7);
        prom.render_body();
        let body2 = &prom.body_buf;
        assert!(
            body2.contains("varta_watch_pids_tracked 0"),
            "pids_tracked should be 0 after eviction:\n{body2}"
        );
    }

    /// The dropped-connection metric must emit every label value on every
    /// scrape, even at zero — same contract as `varta_decode_errors_total`.
    /// `absent()` alert rules and dashboards depend on stable series.
    #[test]
    fn connections_dropped_emit_every_reason_label_at_zero() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        prom.render_body();
        let body = &prom.body_buf;
        for reason in DROP_REASON_LABELS {
            let series = format!("varta_prom_connections_dropped_total{{reason=\"{reason}\"}} 0");
            assert!(
                body.contains(&series),
                "missing zero-emission for reason={reason}:\n{body}"
            );
        }
    }

    /// Per-IP token bucket: a single IP exceeding its burst must be denied,
    /// and the denial must bump `varta_prom_connections_dropped_total
    /// {reason="rate_limit"}`.  Unit-tested directly on `allow_ip` to avoid
    /// the flakiness of real TCP-accept loops.
    #[test]
    fn allow_ip_denies_after_burst_and_records_rate_limit() {
        let mut prom = PromExporter::bind_with_rate_limit(
            "127.0.0.1:0".parse().unwrap(),
            make_token(),
            /* rate_per_sec */ 1,
            /* rate_burst   */ 3,
        )
        .expect("bind");

        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let t0 = Instant::now();

        // Burst of 3 consumes all tokens.
        for _ in 0..3 {
            assert!(prom.allow_ip(ip, t0));
        }
        // 4th attempt within the same instant must be denied.
        assert!(!prom.allow_ip(ip, t0));
        let idx = drop_reason_index(DropReason::RateLimit);
        assert_eq!(
            prom.connections_dropped_total[idx], 1,
            "rate_limit drop counter must increment on denial"
        );

        // After enough time, the bucket refills and a new connection passes.
        let t1 = t0 + Duration::from_secs(2);
        assert!(prom.allow_ip(ip, t1));
    }

    /// `allow_ip` with `rate_burst = 0` must always allow — this is the
    /// "no rate limit" escape hatch.  The IP-state map must stay empty.
    #[test]
    fn allow_ip_burst_zero_is_unlimited() {
        let mut prom = PromExporter::bind_with_rate_limit(
            "127.0.0.1:0".parse().unwrap(),
            make_token(),
            /* rate_per_sec */ 5,
            /* rate_burst   */ 0,
        )
        .expect("bind");
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let t = Instant::now();
        for _ in 0..1000 {
            assert!(prom.allow_ip(ip, t));
        }
        assert!(
            prom.ip_state.is_empty(),
            "burst=0 path must not allocate per-IP state"
        );
    }

    /// Filling the per-IP table past `MAX_PROM_IP_STATES` must force-evict
    /// the oldest entry and bump
    /// `varta_prom_connections_dropped_total{reason="ip_table_full"}`.
    #[test]
    fn allow_ip_table_full_force_evicts_and_records() {
        let mut prom = PromExporter::bind_with_rate_limit(
            "127.0.0.1:0".parse().unwrap(),
            make_token(),
            /* rate_per_sec */ 1000,
            /* rate_burst   */ 1000,
        )
        .expect("bind");
        // Insert MAX_PROM_IP_STATES distinct IPs at t0; the (N+1)th must
        // trigger force-eviction.  Use IPv4 within 10.0.0.0/8 to avoid any
        // overlap with the loopback used elsewhere in tests.
        let t0 = Instant::now();
        for i in 0..MAX_PROM_IP_STATES {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            ));
            assert!(prom.allow_ip(ip, t0));
        }
        assert_eq!(prom.ip_state.len(), MAX_PROM_IP_STATES);

        // One more IP at the same instant — sweep can't free anything
        // because everyone is fresh, so the oldest gets force-evicted.
        let new_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(11, 0, 0, 1));
        assert!(prom.allow_ip(new_ip, t0));
        assert_eq!(
            prom.ip_state.len(),
            MAX_PROM_IP_STATES,
            "table size must remain capped"
        );
        let idx = drop_reason_index(DropReason::IpTableFull);
        assert!(
            prom.connections_dropped_total[idx] >= 1,
            "ip_table_full drop counter must increment on force-eviction"
        );
    }

    /// M8: every refusal-reason label must be emitted on the first
    /// scrape (even at zero) so `absent()` alert rules stay green.
    /// Confirms the `debounce_capacity` label joins the
    /// pre-existing `unauthenticated_transport` and `cross_namespace_agent`
    /// labels with no gaps.
    #[test]
    fn recovery_refused_debounce_capacity_label_emitted_at_zero() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        prom.render_body();
        let body = &prom.body_buf;
        for reason in RECOVERY_REFUSED_REASON_LABELS.iter() {
            let needle = format!("varta_recovery_refused_total{{reason=\"{reason}\"}} 0");
            assert!(
                body.contains(&needle),
                "missing first-scrape zero line for reason {reason:?}; body:\n{body}"
            );
        }
        // The new evictions + invariant-violations counters must also
        // emit at zero, mirroring the tracker self-health pattern.
        assert!(
            body.contains("varta_recovery_last_fired_evictions_total 0"),
            "evictions counter missing zero line in first scrape"
        );
        assert!(
            body.contains("varta_recovery_invariant_violations_total 0"),
            "invariant-violations counter missing zero line in first scrape"
        );
    }

    /// M8: bumping the `RefusedDebounceCapacity` outcome counter must
    /// drive both the outcome-label and the refused-reason-label
    /// arrays.  Confirms `record_recovery_outcome` is the single
    /// entry point for the new variant.
    #[test]
    fn recovery_refused_debounce_capacity_outcome_drives_counters() {
        let mut prom =
            PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
        let outcome = crate::recovery::RecoveryOutcome::RefusedDebounceCapacity { pid: 42 };
        prom.record_recovery_outcome(&outcome, None);
        prom.render_body();
        let body = &prom.body_buf;
        assert!(
            body.contains("varta_recovery_outcomes_total{outcome=\"refused_debounce_capacity\"} 1"),
            "outcome counter must increment under refused_debounce_capacity; body:\n{body}"
        );
        assert!(
            body.contains("varta_recovery_refused_total{reason=\"debounce_capacity\"} 1"),
            "refused-reason counter must increment under debounce_capacity; body:\n{body}"
        );
    }
}
