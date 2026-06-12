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

use std::time::Duration;

pub use file::{Exporter, FileExporter};

#[cfg(feature = "prometheus-exporter")]
use std::io;
#[cfg(feature = "prometheus-exporter")]
use std::net::{SocketAddr, TcpListener};
#[cfg(feature = "prometheus-exporter")]
use std::time::{Instant, SystemTime};

#[cfg(feature = "prometheus-exporter")]
use varta_vlp::crypto::BearerToken;
#[cfg(feature = "prometheus-exporter")]
use varta_vlp::DecodeError;
#[cfg(feature = "prometheus-exporter")]
use varta_vlp::Status;

#[cfg(feature = "prometheus-exporter")]
use crate::ip_state_table::{IpStateTable, LastSeen};
#[cfg(feature = "prometheus-exporter")]
use crate::log_ratelimit::LogKind;

#[cfg(feature = "prometheus-exporter")]
use crate::observer::Event;
#[cfg(feature = "prometheus-exporter")]
use crate::probe_table::BoundedIndex;

/// Prometheus `kind` label values for `varta_log_suppressed_total`. Indexed
/// by [`LogKind::index`]; the array doubles as the canonical ordering for
/// the exposition output so series remain stable across scrapes.  Must stay
/// in sync with the `LogKind` enum in `log_ratelimit.rs` — same order, same count.
#[cfg(feature = "prometheus-exporter")]
const LOG_KIND_LABELS: [&str; LogKind::COUNT] = [
    "file_export_io",
    "audit_io",
    "prom_serve",
    "heartbeat_io",
    "audit_ring_warn",
    "audit_ring_critical",
];

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

#[cfg(feature = "prometheus-exporter")]
#[derive(Clone, Copy)]
struct PidRowSlot {
    pid: u32,
    row: GaugeRow,
}

#[cfg(feature = "prometheus-exporter")]
struct PidRowTable {
    slab: Vec<Option<PidRowSlot>>,
    free_list: Vec<u32>,
    pid_to_slot: BoundedIndex<u32>,
}

#[cfg(feature = "prometheus-exporter")]
impl PidRowTable {
    fn with_capacity(capacity: usize) -> Self {
        debug_assert!(capacity > 0, "PidRowTable capacity must be > 0");
        let mut slab = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slab.push(None);
        }
        let mut free_list = Vec::with_capacity(capacity);
        for i in (0..capacity as u32).rev() {
            free_list.push(i);
        }
        Self {
            slab,
            free_list,
            pid_to_slot: BoundedIndex::new(capacity),
        }
    }

    fn len(&self) -> usize {
        self.pid_to_slot.len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.pid_to_slot.len() == 0
    }

    #[cfg(test)]
    fn contains_key(&self, pid: &u32) -> bool {
        self.pid_to_slot.get(*pid).is_some()
    }

    fn get(&self, pid: u32) -> Option<&GaugeRow> {
        let idx = self.pid_to_slot.get(pid)?;
        self.slab.get(idx)?.as_ref().map(|slot| &slot.row)
    }

    fn get_mut_or_insert(&mut self, pid: u32) -> Option<&mut GaugeRow> {
        if let Some(idx) = self.pid_to_slot.get(pid) {
            return self.slab.get_mut(idx)?.as_mut().map(|slot| &mut slot.row);
        }

        let slot_idx = self.free_list.pop()?;
        if self.pid_to_slot.insert(pid, slot_idx as usize).is_err() {
            self.free_list.push(slot_idx);
            return None;
        }
        let Some(cell) = self.slab.get_mut(slot_idx as usize) else {
            self.pid_to_slot.remove(pid);
            self.free_list.push(slot_idx);
            return None;
        };
        *cell = Some(PidRowSlot {
            pid,
            row: GaugeRow::new(),
        });
        cell.as_mut().map(|slot| &mut slot.row)
    }

    fn remove(&mut self, pid: u32) -> Option<GaugeRow> {
        let slot_idx = self.pid_to_slot.remove(pid)?;
        let taken = self.slab.get_mut(slot_idx)?.take();
        if let Some(slot) = taken {
            self.free_list.push(slot_idx as u32);
            Some(slot.row)
        } else {
            None
        }
    }

    fn push_pids(&self, out: &mut Vec<u32>) {
        for slot in self.slab.iter().flatten() {
            out.push(slot.pid);
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
/// Slack above tracker capacity for per-pid metric rows.
///
/// The observer records an accepted beat before the maintenance phase drains
/// tracker removals into [`PromExporter::record_evicted_pid`], so the exporter
/// must be able to hold the just-inserted pid plus rows awaiting cleanup.
#[cfg(feature = "prometheus-exporter")]
const PROM_PID_ROW_SLACK: usize = 64;
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

/// Observer poll-loop stage identifier for per-stage timing attribution.
///
/// Variants are ordered to match the poll-loop execution order in `main.rs`.
/// `STAGE_LABELS[stage as usize]` gives the Prometheus `stage=` label value.
/// Every stage emits on every scrape (including zero-count stages) so
/// `absent()` alert rules and `histogram_quantile()` stay correct from the
/// first scrape.
#[cfg(feature = "prometheus-exporter")]
#[derive(Clone, Copy)]
pub enum IterStage {
    /// Drain queued stall events from the observer stall queue.
    DrainPending = 0,
    /// One non-blocking I/O poll for new beats, decode, and authentication.
    Poll = 1,
    /// Maintenance: eviction drains, capacity counters, and audit-error drain.
    Maintenance = 2,
    /// Recovery reap: non-blocking `waitpid(2)` and optional kill for timed-out children.
    RecoveryReap = 3,
    /// Prometheus `/metrics` serving: `serve_pending` accept + response loop.
    ServePending = 4,
    /// Housekeeping: heartbeat-file write, self-watchdog tick, and hardware watchdog kick.
    Housekeeping = 5,
}

/// Prometheus `stage=` label values for each [`IterStage`] variant, indexed
/// by `stage as usize`. Stable-label-set contract: emit every element on
/// every scrape, even at zero.
#[cfg(feature = "prometheus-exporter")]
pub const STAGE_LABELS: [&str; 6] = [
    "drain_pending",
    "poll",
    "maintenance",
    "recovery_reap",
    "serve_pending",
    "housekeeping",
];

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

/// Outcome of serving a single accepted `/metrics` connection.
///
/// Distinguishes the three states that matter for scrape-cache accounting:
///
/// * [`ServeOutcome::ServedFresh`] — an authorized client received a
///   freshly-rendered body. This is the *only* event that may advance the
///   scrape-freshness window (`last_scrape`).
/// * [`ServeOutcome::ServedCached`] — an authorized client was served the
///   cached body. This is the *only* event that counts as a skipped scrape.
/// * [`ServeOutcome::Rejected`] — the request was refused (401 Unauthorized
///   or 405 Method Not Allowed) without rendering or serving a body. It must
///   touch neither the freshness window nor the skip counter.
#[cfg(feature = "prometheus-exporter")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ServeOutcome {
    ServedFresh,
    ServedCached,
    Rejected,
}

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

#[cfg(feature = "prometheus-exporter")]
impl LastSeen for PromIpState {
    fn last_seen(&self) -> Instant {
        self.last_seen
    }
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
const RECOVERY_OUTCOME_LABELS: [&str; 14] = [
    "spawned",
    "debounced",
    "reaped_zero",
    "reaped_nonzero",
    "killed",
    "spawn_failed",
    "refused_unauthenticated_transport",
    "refused_cross_namespace",
    "refused_debounce_capacity",
    "refused_outstanding_capacity",
    "refused_socket_mode_only",
    "skipped_agent_resumed",
    "skipped_pid_recycled",
    "skipped_stall_unverifiable",
];

/// Reason label values for `varta_recovery_refused_total`. Indexed by
/// [`refused_reason_index`]; emitted unconditionally so `absent()` rules
/// stay green.
#[cfg(feature = "prometheus-exporter")]
const RECOVERY_REFUSED_REASON_LABELS: [&str; 5] = [
    "unauthenticated_transport",
    "cross_namespace_agent",
    "debounce_capacity",
    "outstanding_capacity",
    "socket_mode_only",
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
        RecoveryOutcome::RefusedOutstandingCapacity { .. } => 9,
        RecoveryOutcome::RefusedSocketModeOnly { .. } => 10,
        RecoveryOutcome::SkippedAgentResumed { .. } => 11,
        RecoveryOutcome::SkippedPidRecycled { .. } => 12,
        RecoveryOutcome::SkippedStallUnverifiable { .. } => 13,
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
    OutstandingCapacity,
    SocketModeOnly,
}

#[cfg(feature = "prometheus-exporter")]
fn refused_reason_index(r: RefusedReason) -> usize {
    match r {
        RefusedReason::UnauthenticatedTransport => 0,
        RefusedReason::CrossNamespaceAgent => 1,
        RefusedReason::DebounceCapacity => 2,
        RefusedReason::OutstandingCapacity => 3,
        RefusedReason::SocketModeOnly => 4,
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
    rows: PidRowTable,
    pid_scratch: Vec<u32>,
    /// Reused across `/metrics` scrapes to avoid per-scrape allocation.
    body_buf: String,
    /// Timestamp of the most recent scrape served. Enforces
    /// [`PROM_MIN_SCRAPE_INTERVAL`] to protect the single-threaded poll
    /// loop from a fast scraper starving stall detection.
    last_scrape: Option<Instant>,
    evicted_total: u64,
    /// Number of frames rejected because their kernel-attested PID did not
    /// match the on-wire `frame.pid` (PID spoofing) or otherwise failed
    /// authentication.  Counts `Event::AuthFailure` only — a *frame-ingest*
    /// signal, entirely distinct from `/metrics` bearer-token rejections.
    /// Emitted unconditionally as `varta_frame_auth_failures_total` (even
    /// when zero) so `absent()` alert rules stay green.
    frame_auth_failures_total: u64,
    /// Number of `/metrics` connections rejected because the bearer token
    /// was missing or wrong.  A *scrape-endpoint* signal, entirely distinct
    /// from frame PID-spoofing rejections.  Emitted unconditionally as
    /// `varta_prom_auth_failures_total` (even when zero) so `absent()` alert
    /// rules stay green; see the matching contract on
    /// `varta_decode_errors_total`.
    prom_auth_failures_total: u64,
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
    /// Beats dropped per rate-limit reason since last scrape.
    /// Index 0 = per_pid, 1 = global.
    rate_limited_total: [u64; 2],
    /// Effective SO_RCVBUF size in bytes for the observer UDS, set at startup.
    uds_rcvbuf_bytes: u32,
    /// Observer's currently cached `/proc/sys/kernel/pid_max` value. Seeded at
    /// startup from [`crate::observer::Observer::pid_max`] and refreshed via
    /// `set_pid_max_current` whenever the observer's maintenance-phase
    /// re-read fires. Surfaced as `varta_pid_max_current` (gauge) so
    /// operators can detect runtime `sysctl -w kernel.pid_max=...` changes
    /// (`delta(varta_pid_max_current[5m]) != 0`). On non-Linux this stays
    /// at `u32::MAX` and the gate is effectively disabled.
    pid_max_current: u32,
    /// Times the observer's monotonic clock returned a value strictly less
    /// than the previously observed one and the forward clamp absorbed the
    /// regression. Surfaced as `varta_observer_clock_regression_total`;
    /// non-zero values mean TSC drift, VM live migration, or another
    /// clock anomaly the operator should investigate.
    clock_regressions_total: u64,
    /// Times the observer clock advanced by more than the forward-jump
    /// sentinel between adjacent poll ticks. Surfaced as
    /// `varta_observer_clock_jump_forward_total`.
    clock_jumps_forward_total: u64,
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
    /// Total stale debounce windows dropped because a slot's pinned
    /// generation proved its PID had been recycled to a new process.
    /// Surfaced as `varta_recovery_debounce_recycle_resets_total`; a
    /// non-zero value means recovery was correctly **not** suppressed for
    /// a recycled PID (the genuine new process got its own recovery).
    recovery_debounce_recycle_resets_total: u64,
    /// Total outstanding-child slots reclaimed because a slot's pinned
    /// generation proved its PID had been recycled while the previous
    /// lineage's recovery child was still in flight. Surfaced as
    /// `varta_recovery_outstanding_recycle_resets_total`; a non-zero value
    /// means recovery was correctly **not** suppressed for the new process.
    recovery_outstanding_recycle_resets_total: u64,
    /// Total observer ticks whose [`crate::recovery::RECOVERY_SPAWN_MAX_PER_TICK`]
    /// per-tick recovery-spawn budget engaged, deferring the remaining queued
    /// stalls to a later tick. Surfaced as
    /// `varta_recovery_spawn_budget_exceeded_total`; a non-zero value means a
    /// mass simultaneous stall was staggered rather than fork-bombing the
    /// single-threaded poll loop.
    recovery_spawn_budget_exceeded_total: u64,
    /// Total [`crate::recovery::LastFiredTable`] invariant-violation
    /// fall-throughs — defensive `.get()`/`.get_mut()` else-branches
    /// that should be unreachable in correct operation.  Surfaced as
    /// `varta_recovery_invariant_violations_total`; non-zero values
    /// indicate a code bug, not load.
    recovery_invariant_violations_total: u64,
    /// Tracker-level cross-origin conflicts — beats dropped because the
    /// beat's transport origin was weaker than the slot's pinned origin.
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
    /// Slots reset because a kernel-attested process generation (start-time)
    /// mismatch proved the pid had been recycled to a new process. Surfaced
    /// as `varta_tracker_pid_recycle_total`.
    tracker_pid_recycle_total: u64,
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
    /// `OutstandingTable` pid-index probe-exhaustion events. Surfaced as
    /// `varta_recovery_outstanding_probe_exhausted_total`.  Mirrors the
    /// tracker's counter for the cold recovery path.
    recovery_outstanding_probe_exhausted_total: u64,
    /// Count of [`try_reap`](crate::recovery::Recovery::try_reap) calls
    /// truncated because outstanding children exceeded `REAP_MAX_PER_TICK`.
    /// Surfaced as `varta_recovery_reap_truncated_total`.
    recovery_reap_truncated_total: u64,
    /// `IpStateTable` ip-index probe-exhaustion events. Surfaced as
    /// `varta_prom_ip_state_probe_exhausted_total`.
    prom_ip_state_probe_exhausted_total: u64,
    /// Per-pid metric rows that could not be allocated. Should stay at zero;
    /// non-zero means the bounded row table's slack was exhausted before
    /// tracker eviction cleanup reached the exporter.
    prom_pid_row_refused_total: u64,
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
    /// Per-stage iteration timing histograms. Row index is `IterStage as
    /// usize`; column index is the [`ITERATION_BUCKET_BOUNDS_S`] slot (with
    /// the final column reserved for `+Inf`). Non-cumulative storage; summed
    /// at render time. Every stage emits every bucket on every scrape so
    /// `absent()` alert rules stay correct before the first observation.
    stage_buckets: [[u64; ITERATION_BUCKET_BOUNDS_S.len() + 1]; STAGE_LABELS.len()],
    /// Per-stage sum of observed durations in nanoseconds.
    stage_duration_ns_sum: [u64; STAGE_LABELS.len()],
    /// Per-stage observation count.
    stage_count_total: [u64; STAGE_LABELS.len()],
    /// Lines enqueued by the hot path that were dropped because the audit
    /// ring was at capacity. Surfaced as
    /// `varta_recovery_audit_dropped_total`.
    audit_dropped_total: u64,
    /// Ticks where `flush_pending` ran out of budget before draining the
    /// audit ring. Surfaced as
    /// `varta_recovery_audit_flush_budget_exceeded_total`.
    audit_flush_budget_exceeded_total: u64,
    /// Per-`fdatasync(2)` wall-clock-duration histogram, same bucket
    /// boundaries as [`Self::iteration_buckets`].  Surfaced as
    /// `varta_audit_fsync_seconds`.  Last slot is `+Inf`.
    audit_fsync_buckets: [u64; ITERATION_BUCKET_BOUNDS_S.len() + 1],
    /// Sum (ns) of observed `fdatasync` durations.  Companion to
    /// `varta_audit_fsync_seconds_sum`.
    audit_fsync_duration_ns_sum: u64,
    /// Count of `fdatasync` observations.  Companion to
    /// `varta_audit_fsync_seconds_count`.
    audit_fsync_count_total: u64,
    /// `fsync(2)` calls on the UDS socket's parent directory during bind that
    /// returned an error (soft durability degradation).  Surfaced as
    /// `varta_socket_bind_dir_fsync_failed_total`.
    bind_dir_fsync_failed_total: u64,
    /// `fdatasync(2)` calls on the audit log that exceeded
    /// `--audit-fsync-budget-ms`.  Surfaced as
    /// `varta_audit_fsync_budget_exceeded_total`.
    audit_fsync_budget_exceeded_total: u64,
    /// Rotation state-machine drive calls that exceeded
    /// `--audit-rotation-budget-ms` and had to defer.  Surfaced as
    /// `varta_audit_rotation_budget_exceeded_total`.
    audit_rotation_budget_exceeded_total: u64,
    /// Rising-edge ring-fill watermark counters: `[0]` = warn (≥75%),
    /// `[1]` = critical (≥95%).  Surfaced as
    /// `varta_audit_ring_watermark_total{level=...}`.  Both label
    /// values are emitted unconditionally — even at zero — so
    /// `absent()` alert rules stay green from the first scrape.
    audit_ring_watermark_total: [u64; 2],
    /// Soft per-call budget for `serve_pending`. Configurable via
    /// `--scrape-budget-ms`; defaults to [`DEFAULT_SCRAPE_BUDGET`].
    scrape_budget: Duration,
    /// Per-source-IP token bucket state.  Bounded by
    /// [`MAX_PROM_IP_STATES`]; entries older than [`PROM_IP_STATE_TTL`] are
    /// evicted lazily when the table reaches capacity.
    ip_state: IpStateTable<PromIpState>,
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
    /// Active signal-handler installation mode (`"direct"` or `"libc"`). Set
    /// once at startup via [`PromExporter::set_signal_handler_mode`]; emitted
    /// as `varta_signal_handler_install_total{mode="..."}` so dashboards can
    /// assert the certified path is active.
    signal_handler_mode: &'static str,
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
            rows: PidRowTable::with_capacity(crate::tracker::MAX_CAPACITY + PROM_PID_ROW_SLACK),
            pid_scratch: Vec::with_capacity(crate::tracker::MAX_CAPACITY + PROM_PID_ROW_SLACK),
            body_buf: String::new(),
            last_scrape: None,
            evicted_total: 0,
            frame_auth_failures_total: 0,
            prom_auth_failures_total: 0,
            token,
            decode_errors_total: [0; DECODE_KIND_LABELS.len()],
            io_errors_total: 0,
            ctrl_truncated_total: 0,
            capacity_exceeded_total: 0,
            decrypt_failures_total: 0,
            truncated_total: 0,
            sender_state_full_total: 0,
            secure_aead_attempts_total: 0,
            rate_limited_total: [0; 2],
            uds_rcvbuf_bytes: 0,
            pid_max_current: 0,
            clock_regressions_total: 0,
            clock_jumps_forward_total: 0,
            nonce_wrap_total: 0,
            eviction_scan_truncated_total: 0,
            tracker_capacity_cfg: 0,
            eviction_scan_window_max: 0,
            recovery_outcomes_total: [0; RECOVERY_OUTCOME_LABELS.len()],
            recovery_refused_total: [0; RECOVERY_REFUSED_REASON_LABELS.len()],
            recovery_last_fired_evictions_total: 0,
            recovery_debounce_recycle_resets_total: 0,
            recovery_outstanding_recycle_resets_total: 0,
            recovery_spawn_budget_exceeded_total: 0,
            recovery_invariant_violations_total: 0,
            origin_conflict_total: 0,
            frame_namespace_mismatch_total: 0,
            frame_rejected_pid_above_max_total: 0,
            tracker_namespace_conflict_total: 0,
            tracker_pid_recycle_total: 0,
            tracker_invariant_violations_total: 0,
            tracker_pid_index_probe_exhausted_total: 0,
            recovery_outstanding_probe_exhausted_total: 0,
            recovery_reap_truncated_total: 0,
            prom_ip_state_probe_exhausted_total: 0,
            prom_pid_row_refused_total: 0,
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
            stage_buckets: [[0; ITERATION_BUCKET_BOUNDS_S.len() + 1]; STAGE_LABELS.len()],
            stage_duration_ns_sum: [0; STAGE_LABELS.len()],
            stage_count_total: [0; STAGE_LABELS.len()],
            audit_dropped_total: 0,
            audit_flush_budget_exceeded_total: 0,
            audit_fsync_buckets: [0; ITERATION_BUCKET_BOUNDS_S.len() + 1],
            audit_fsync_duration_ns_sum: 0,
            audit_fsync_count_total: 0,
            bind_dir_fsync_failed_total: 0,
            audit_fsync_budget_exceeded_total: 0,
            audit_rotation_budget_exceeded_total: 0,
            audit_ring_watermark_total: [0; 2],
            scrape_budget: DEFAULT_SCRAPE_BUDGET,
            ip_state: IpStateTable::with_capacity(MAX_PROM_IP_STATES),
            rate_per_sec,
            rate_burst,
            last_ip_sweep: now,
            connections_dropped_total: [0; DROP_REASON_LABELS.len()],
            started_at: now,
            last_loop_system: SystemTime::now(),
            signal_handler_mode: "direct",
        })
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
    /// Keeps the bounded row table aligned with tracker membership in
    /// long-running deployments with ephemeral processes (CI runners, cron
    /// jobs, containers).
    pub fn record_evicted_pid(&mut self, pid: u32) {
        self.rows.remove(pid);
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

    /// Record one or more authenticated secure-UDP frames refused because the
    /// sender-state table was at capacity.
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
    pub fn record_per_pid_rate_limited(&mut self, count: u64) {
        self.rate_limited_total[0] = self.rate_limited_total[0].saturating_add(count);
    }

    /// Record one or more beats dropped by the global rate limiter.
    pub fn record_global_rate_limited(&mut self, count: u64) {
        self.rate_limited_total[1] = self.rate_limited_total[1].saturating_add(count);
    }

    /// Record the effective SO_RCVBUF size granted by the kernel at startup.
    pub fn set_uds_rcvbuf_bytes(&mut self, bytes: u32) {
        self.uds_rcvbuf_bytes = bytes;
    }

    /// Set the observer's currently cached `pid_max`. Called once at startup
    /// (with the value [`crate::observer::Observer::pid_max`] read from
    /// `/proc/sys/kernel/pid_max`) and again from the maintenance phase
    /// whenever [`crate::observer::Observer::maybe_refresh_pid_max`] fires.
    /// Surfaced as the `varta_pid_max_current` gauge.
    pub fn set_pid_max_current(&mut self, value: u32) {
        self.pid_max_current = value;
    }

    /// Record one or more observer clock-regression events drained from
    /// [`crate::observer::Observer::drain_clock_regressions`]. Surfaced as
    /// `varta_observer_clock_regression_total`.
    pub fn record_clock_regressions(&mut self, count: u64) {
        self.clock_regressions_total = self.clock_regressions_total.saturating_add(count);
    }

    /// Record one or more forward-jump events drained from
    /// [`crate::observer::Observer::drain_clock_jumps_forward`]. Surfaced as
    /// `varta_observer_clock_jump_forward_total`.
    pub fn record_clock_jumps_forward(&mut self, count: u64) {
        self.clock_jumps_forward_total = self.clock_jumps_forward_total.saturating_add(count);
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

    /// Set the active signal-handler mode label. Call once at daemon startup,
    /// immediately after [`crate::signal_install::install`] succeeds. The value
    /// is emitted as `varta_signal_handler_install_total{mode="..."}` so
    /// dashboards can assert the certified `direct` path is active.
    pub fn set_signal_handler_mode(&mut self, mode: &'static str) {
        self.signal_handler_mode = mode;
    }

    /// Set the tracker capacity and eviction-scan-window config values emitted
    /// as startup gauges. Call once at daemon startup before the first scrape.
    pub fn set_tracker_config(&mut self, capacity: usize, eviction_scan_window: usize) {
        self.tracker_capacity_cfg = capacity;
        self.eviction_scan_window_max = eviction_scan_window;
    }

    /// Record a recovery outcome and optional duration. Increments the
    /// `varta_recovery_outcomes_total{outcome=…}` counter; when
    /// `duration_ns` is provided (currently `Reaped` outcomes), bumps the
    /// duration sum + count.
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
            crate::recovery::RecoveryOutcome::RefusedOutstandingCapacity { .. } => {
                let r_idx = refused_reason_index(RefusedReason::OutstandingCapacity);
                self.recovery_refused_total[r_idx] =
                    self.recovery_refused_total[r_idx].saturating_add(1);
            }
            crate::recovery::RecoveryOutcome::RefusedSocketModeOnly { .. } => {
                let r_idx = refused_reason_index(RefusedReason::SocketModeOnly);
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
    /// a beat was dropped because its transport origin was weaker than the
    /// slot's pinned origin. Surfaced as
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

    /// Record one or more PID recycles — stale slot identities reset or
    /// retired because a kernel-attested process generation (start-time)
    /// mismatch proved the pid had been reused by a new process. See
    /// [`crate::tracker::Tracker::take_pid_recycles`].
    /// Surfaced as `varta_tracker_pid_recycle_total`.
    pub fn record_tracker_pid_recycles(&mut self, count: u64) {
        self.tracker_pid_recycle_total = self.tracker_pid_recycle_total.saturating_add(count);
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

    /// Record one or more debounce-ledger recycle resets — stale windows
    /// dropped because a slot's pinned generation proved a PID recycle.
    /// Surfaced as `varta_recovery_debounce_recycle_resets_total`.
    pub fn record_recovery_debounce_recycle_resets(&mut self, count: u64) {
        self.recovery_debounce_recycle_resets_total = self
            .recovery_debounce_recycle_resets_total
            .saturating_add(count);
    }

    /// Record one or more outstanding-table recycle resets — stale recovery
    /// children reclaimed because a slot's pinned generation proved a PID
    /// recycle while the previous child was still in flight.
    /// Surfaced as `varta_recovery_outstanding_recycle_resets_total`.
    pub fn record_recovery_outstanding_recycle_resets(&mut self, count: u64) {
        self.recovery_outstanding_recycle_resets_total = self
            .recovery_outstanding_recycle_resets_total
            .saturating_add(count);
    }

    /// Record one or more per-tick recovery-spawn-budget engagements — ticks
    /// where a mass stall exceeded [`crate::recovery::RECOVERY_SPAWN_MAX_PER_TICK`]
    /// and the remainder was deferred to a later tick.
    /// Surfaced as `varta_recovery_spawn_budget_exceeded_total`.
    pub fn record_recovery_spawn_budget_exceeded(&mut self, count: u64) {
        self.recovery_spawn_budget_exceeded_total = self
            .recovery_spawn_budget_exceeded_total
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

    /// Record one or more `OutstandingTable` probe-exhaustion events. See
    /// [`crate::recovery::Recovery::take_outstanding_probe_exhausted`].
    pub fn record_recovery_outstanding_probe_exhausted(&mut self, count: u64) {
        self.recovery_outstanding_probe_exhausted_total = self
            .recovery_outstanding_probe_exhausted_total
            .saturating_add(count);
    }

    /// Record [`try_reap`](crate::recovery::Recovery::try_reap) calls that
    /// were truncated because outstanding children exceeded the per-tick cap.
    /// See [`crate::recovery::Recovery::take_reap_truncated`].
    pub fn record_recovery_reap_truncated(&mut self, count: u64) {
        self.recovery_reap_truncated_total =
            self.recovery_reap_truncated_total.saturating_add(count);
    }

    /// Record audit lines dropped because the ring was at capacity when they
    /// arrived. See [`crate::recovery::Recovery::take_audit_dropped`].
    pub fn record_audit_dropped(&mut self, count: u64) {
        self.audit_dropped_total = self.audit_dropped_total.saturating_add(count);
    }

    /// Record ticks where `flush_pending` ran out of budget before draining
    /// the audit ring. See
    /// [`crate::recovery::Recovery::take_audit_flush_budget_exceeded`].
    pub fn record_audit_flush_budget_exceeded(&mut self, count: u64) {
        self.audit_flush_budget_exceeded_total =
            self.audit_flush_budget_exceeded_total.saturating_add(count);
    }

    /// Record one `fdatasync(2)` observation on the audit log.  Folds
    /// the duration into the `varta_audit_fsync_seconds` histogram
    /// (shares bucket boundaries with `iteration_seconds` so operators
    /// can compare distributions in PromQL) and updates the
    /// `_sum`/`_count` companions.
    pub fn record_audit_fsync_duration(&mut self, d: Duration) {
        let secs = d.as_secs_f64();
        let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.audit_fsync_duration_ns_sum = self.audit_fsync_duration_ns_sum.saturating_add(ns);
        self.audit_fsync_count_total = self.audit_fsync_count_total.saturating_add(1);
        let mut placed = false;
        for (i, &bound) in ITERATION_BUCKET_BOUNDS_S.iter().enumerate() {
            if secs <= bound {
                self.audit_fsync_buckets[i] = self.audit_fsync_buckets[i].saturating_add(1);
                placed = true;
                break;
            }
        }
        if !placed {
            let inf_idx = ITERATION_BUCKET_BOUNDS_S.len();
            self.audit_fsync_buckets[inf_idx] = self.audit_fsync_buckets[inf_idx].saturating_add(1);
        }
    }

    /// Record `fsync(2)` calls on the UDS socket's parent directory that
    /// returned an error during bind.  See
    /// [`crate::listener::drain_bind_dir_fsync_failures`].
    pub fn record_bind_dir_fsync_failed(&mut self, count: u64) {
        self.bind_dir_fsync_failed_total = self.bind_dir_fsync_failed_total.saturating_add(count);
    }

    /// Record `fdatasync(2)` calls that exceeded
    /// `--audit-fsync-budget-ms`.  See
    /// [`crate::recovery::Recovery::take_audit_fsync_budget_exceeded`].
    pub fn record_audit_fsync_budget_exceeded(&mut self, count: u64) {
        self.audit_fsync_budget_exceeded_total =
            self.audit_fsync_budget_exceeded_total.saturating_add(count);
    }

    /// Record rotation state-machine ticks that exceeded
    /// `--audit-rotation-budget-ms` and had to defer.  See
    /// [`crate::recovery::Recovery::take_audit_rotation_budget_exceeded`].
    pub fn record_audit_rotation_budget_exceeded(&mut self, count: u64) {
        self.audit_rotation_budget_exceeded_total = self
            .audit_rotation_budget_exceeded_total
            .saturating_add(count);
    }

    /// Record an audit-ring high-watermark crossing.  `level` must be
    /// `"warn"` (75% fill) or `"critical"` (95% fill); any other value
    /// is silently dropped (stable-label-set discipline applies — only
    /// the two known labels are ever emitted).  Edge-triggered: the
    /// audit sink counts one crossing per excursion above the
    /// threshold, not one per tick.
    pub fn record_audit_ring_watermark(&mut self, level: &str, count: u64) {
        let idx = match level {
            "warn" => 0,
            "critical" => 1,
            _ => return,
        };
        self.audit_ring_watermark_total[idx] =
            self.audit_ring_watermark_total[idx].saturating_add(count);
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

    /// Record the wall-clock duration of one observer poll-loop stage.
    ///
    /// Updates `varta_observer_stage_seconds{stage="..."}` for the given
    /// [`IterStage`] variant. Every stage emits on every scrape (including
    /// zero-count stages) so `absent()` alert rules and
    /// `histogram_quantile()` stay correct from the first scrape.
    ///
    /// Buckets are stored non-cumulatively here and summed at exposition
    /// time — same contract as [`record_iteration_duration`].
    ///
    /// [`record_iteration_duration`]: Self::record_iteration_duration
    pub fn record_stage_duration(&mut self, stage: IterStage, d: Duration) {
        let idx = stage as usize;
        let secs = d.as_secs_f64();
        let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.stage_duration_ns_sum[idx] = self.stage_duration_ns_sum[idx].saturating_add(ns);
        self.stage_count_total[idx] = self.stage_count_total[idx].saturating_add(1);
        let mut placed = false;
        for (i, &bound) in ITERATION_BUCKET_BOUNDS_S.iter().enumerate() {
            if secs <= bound {
                self.stage_buckets[idx][i] = self.stage_buckets[idx][i].saturating_add(1);
                placed = true;
                break;
            }
        }
        if !placed {
            let inf_i = ITERATION_BUCKET_BOUNDS_S.len();
            self.stage_buckets[idx][inf_i] = self.stage_buckets[idx][inf_i].saturating_add(1);
        }
    }

    /// Record one or more `MSG_CTRUNC` ancillary-data truncation events.
    /// Indicates the kernel's per-message metadata buffer is too small —
    /// a separate signal from generic I/O errors so operators can size
    /// `ANCILLARY_BUFFER_SIZE` appropriately.
    pub fn record_ctrl_truncated(&mut self, count: u64) {
        self.ctrl_truncated_total = self.ctrl_truncated_total.saturating_add(count);
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
                if let Some(row) = self.rows.get_mut_or_insert(*pid) {
                    row.beats_total = row.beats_total.saturating_add(1);
                    row.last_status = Some(*status as u8);
                } else {
                    self.prom_pid_row_refused_total =
                        self.prom_pid_row_refused_total.saturating_add(1);
                }
            }
            Event::Stall {
                pid,
                observer_ns: _,
                ..
            } => {
                if let Some(row) = self.rows.get_mut_or_insert(*pid) {
                    row.stalls_total = row.stalls_total.saturating_add(1);
                    row.last_status = Some(Status::Stall as u8);
                } else {
                    self.prom_pid_row_refused_total =
                        self.prom_pid_row_refused_total.saturating_add(1);
                }
            }
            Event::AuthFailure { observer_ns: _, .. } => {
                self.frame_auth_failures_total = self.frame_auth_failures_total.saturating_add(1);
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

#[cfg(feature = "prometheus-exporter")]
mod bearer_token;
mod file;
#[cfg(feature = "prometheus-exporter")]
mod http;
#[cfg(feature = "prometheus-exporter")]
mod prometheus;
#[cfg(all(test, feature = "prometheus-exporter"))]
mod tests;
