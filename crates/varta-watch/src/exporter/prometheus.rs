//! Prometheus text-format body renderer for [`super::PromExporter`].
//!
//! `render_body` serialises all accumulated metric state into `body_buf`
//! in Prometheus text exposition format v0.0.4.  Every counter and
//! histogram emits unconditionally (even at zero) so `absent()` alert
//! rules and `histogram_quantile()` stay correct from the first scrape.

#[cfg(feature = "prometheus-exporter")]
use std::fmt::Write as _;

#[cfg(feature = "prometheus-exporter")]
use crate::log_ratelimit::{LogKind, LOG_RATE_LIMITER};

#[cfg(feature = "prometheus-exporter")]
use super::{
    DECODE_KIND_LABELS, DROP_REASON_LABELS, ITERATION_BUCKET_BOUNDS_S, LOG_KIND_LABELS,
    RECOVERY_OUTCOME_LABELS, RECOVERY_REFUSED_REASON_LABELS, STAGE_LABELS,
};

#[cfg(feature = "prometheus-exporter")]
impl super::PromExporter {
    /// Render the current snapshot of all observer metrics into `body_buf`.
    pub(super) fn render_body(&mut self) {
        self.body_buf.clear();
        const BODY_BUF_MAX_CAPACITY: usize = 65_536;
        if self.body_buf.capacity() > BODY_BUF_MAX_CAPACITY {
            self.body_buf = String::with_capacity(BODY_BUF_MAX_CAPACITY);
        }

        // Drain the IpStateTable probe-exhausted counter into the
        // exporter's own accumulator so exposition has a coherent value
        // to print.  Recovery and Tracker counters are drained in the
        // observer loop via dedicated `record_*` calls; the IP-state
        // table is owned by the exporter, so it drains itself.
        let prom_ip_probes = self.ip_state.take_probe_exhausted();
        if prom_ip_probes > 0 {
            self.prom_ip_state_probe_exhausted_total = self
                .prom_ip_state_probe_exhausted_total
                .saturating_add(prom_ip_probes);
        }

        self.pid_scratch.clear();
        self.rows.push_pids(&mut self.pid_scratch);
        self.pid_scratch.sort_unstable();

        self.body_buf
            .push_str("# HELP varta_beats_total Total accepted beats per agent pid.\n");
        self.body_buf.push_str("# TYPE varta_beats_total counter\n");
        for pid in &self.pid_scratch {
            let Some(row) = self.rows.get(*pid) else {
                continue;
            };
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
        for pid in &self.pid_scratch {
            let Some(row) = self.rows.get(*pid) else {
                continue;
            };
            let _ = writeln!(
                self.body_buf,
                "varta_stalls_total{{pid=\"{pid}\"}} {}",
                row.stalls_total
            );
        }
        self.body_buf.push_str("# HELP varta_status Last reported status code per agent pid (0=ok,1=degraded,2=critical,3=stall).\n");
        self.body_buf.push_str("# TYPE varta_status gauge\n");
        for pid in &self.pid_scratch {
            let Some(row) = self.rows.get(*pid) else {
                continue;
            };
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
            self.frame_auth_failures_total
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
        // varta_recovery_debounce_recycle_resets_total — stale debounce
        // windows dropped because a slot's pinned generation proved its
        // PID had been recycled.  A non-zero value means recovery was
        // correctly NOT suppressed for a genuinely new process that
        // inherited a recently-recovered PID.  Always emit so `absent()`
        // alert rules stay green-on-green.
        self.body_buf.push_str(
            "# HELP varta_recovery_debounce_recycle_resets_total Stale debounce windows dropped because a slot's pinned generation proved a PID recycle; recovery was not suppressed for the new process.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_debounce_recycle_resets_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_recovery_debounce_recycle_resets_total {}",
            self.recovery_debounce_recycle_resets_total
        );
        // varta_recovery_outstanding_recycle_resets_total — stale recovery
        // children reclaimed because a slot's pinned generation proved a PID
        // recycle while the previous lineage's child was still in flight.
        // A non-zero value means recovery was correctly NOT suppressed for the
        // recycled PID's new occupant.  Always emit so `absent()` stays green.
        self.body_buf.push_str(
            "# HELP varta_recovery_outstanding_recycle_resets_total Stale recovery children reclaimed because a slot's pinned generation proved a PID recycle; recovery was not suppressed for the new process.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_outstanding_recycle_resets_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_recovery_outstanding_recycle_resets_total {}",
            self.recovery_outstanding_recycle_resets_total
        );
        // varta_recovery_spawn_budget_exceeded_total — observer ticks whose
        // per-tick recovery-spawn budget engaged, staggering a mass
        // simultaneous stall instead of fork-bombing the single-threaded poll
        // loop (and tripping the self-watchdog).  Always emit.
        self.body_buf.push_str(
            "# HELP varta_recovery_spawn_budget_exceeded_total Observer ticks whose per-tick recovery-spawn budget engaged, deferring remaining stalls to a later tick.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_spawn_budget_exceeded_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_recovery_spawn_budget_exceeded_total {}",
            self.recovery_spawn_budget_exceeded_total
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
        // varta_origin_conflict_total — beats dropped because the beat's
        // transport origin was weaker than the slot's pinned origin. Non-zero
        // values indicate either operator misconfiguration (same pid emitted
        // from two transports) or an active spoofing attempt.
        self.body_buf.push_str(
            "# HELP varta_origin_conflict_total Beats dropped because the beat's transport origin was weaker than the slot's pinned origin.\n",
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
        // varta_pid_max_current — observer's currently cached pid_max value.
        // Seeded at startup and refreshed at most every 60 s from
        // /proc/sys/kernel/pid_max. Operators alert on changes via
        // `delta(varta_pid_max_current[5m]) != 0`. On non-Linux this is
        // `u32::MAX` (gate effectively disabled).
        self.body_buf.push_str(
            "# HELP varta_pid_max_current Observer's cached /proc/sys/kernel/pid_max (refreshed every 60s).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_pid_max_current gauge\n");
        let _ = writeln!(
            self.body_buf,
            "varta_pid_max_current {}",
            self.pid_max_current
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
        // varta_tracker_pid_recycle_total — stale slot identities reset or
        // retired because a kernel-attested process generation (start-time)
        // mismatch proved the pid had been recycled to a new process.
        // Linux-only signal; a non-zero value means PID reuse is happening on
        // this host.
        self.body_buf.push_str(
            "# HELP varta_tracker_pid_recycle_total Stale slot identities reset or retired because a kernel-attested process start-time mismatch proved the pid was recycled to a new process (recycle-safe identity).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_tracker_pid_recycle_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_pid_recycle_total {}",
            self.tracker_pid_recycle_total
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
        // Removed-pid drops — evicted/retired pids that could not be queued
        // for exporter-row cleanup because the bounded queue was full (drain
        // fell behind a sustained eviction burst). Non-zero = stale per-pid
        // rows leaking; scale the tracker capacity / investigate churn.
        self.body_buf.push_str(
            "# HELP varta_tracker_removed_pid_drops_total Evicted/retired pids dropped because the exporter-cleanup queue was full. Non-zero = orphan per-pid metric rows are leaking (load-shed under churn, not a panic).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_tracker_removed_pid_drops_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_removed_pid_drops_total {}",
            self.tracker_removed_pid_drops_total
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
        // OutstandingTable probe-exhaustion — cold recovery path. Mirrors
        // the tracker counter; same load-factor argument applies.
        self.body_buf.push_str(
            "# HELP varta_recovery_outstanding_probe_exhausted_total OutstandingTable pid-index lookups/inserts that ran the full MAX_PROBE budget.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_outstanding_probe_exhausted_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_recovery_outstanding_probe_exhausted_total {}",
            self.recovery_outstanding_probe_exhausted_total
        );
        // Recovery reap-truncated — fires when outstanding fan-out exceeds
        // REAP_MAX_PER_TICK (64). Non-zero sustained rate means children are
        // accumulating faster than they're reaped; check debounce and timeout
        // settings.
        self.body_buf.push_str(
            "# HELP varta_recovery_reap_truncated_total try_reap calls cut short because outstanding children exceeded the per-tick cap (REAP_MAX_PER_TICK=64).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_reap_truncated_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_recovery_reap_truncated_total {}",
            self.recovery_reap_truncated_total
        );
        // Audit ring back-pressure counters.
        self.body_buf.push_str(
            "# HELP varta_recovery_audit_dropped_total Audit lines dropped because the ring was full when they arrived.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_audit_dropped_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_recovery_audit_dropped_total {}",
            self.audit_dropped_total
        );
        self.body_buf.push_str(
            "# HELP varta_recovery_audit_flush_budget_exceeded_total Ticks where flush_pending hit its budget before emptying the audit ring.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_recovery_audit_flush_budget_exceeded_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_recovery_audit_flush_budget_exceeded_total {}",
            self.audit_flush_budget_exceeded_total
        );
        // Per-fdatasync wall-clock histogram on the audit log.  Same
        // bucket boundaries as iteration_seconds for cross-metric
        // coherence; emits every bucket including +Inf on every scrape
        // so absent() alert rules and histogram_quantile() work from
        // the first scrape.
        self.body_buf.push_str(
            "# HELP varta_audit_fsync_seconds Wall time per fdatasync(2) on the recovery audit log. Bounded by --audit-fsync-budget-ms; overruns increment varta_audit_fsync_budget_exceeded_total.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_audit_fsync_seconds histogram\n");
        let mut cum_af: u64 = 0;
        for (idx, bound) in ITERATION_BUCKET_BOUNDS_S.iter().enumerate() {
            cum_af = cum_af.saturating_add(self.audit_fsync_buckets[idx]);
            let _ = writeln!(
                self.body_buf,
                "varta_audit_fsync_seconds_bucket{{le=\"{bound}\"}} {cum_af}",
            );
        }
        let inf_idx_af = ITERATION_BUCKET_BOUNDS_S.len();
        cum_af = cum_af.saturating_add(self.audit_fsync_buckets[inf_idx_af]);
        let _ = writeln!(
            self.body_buf,
            "varta_audit_fsync_seconds_bucket{{le=\"+Inf\"}} {cum_af}"
        );
        let sum_s_af = (self.audit_fsync_duration_ns_sum as f64) / 1e9;
        let _ = writeln!(self.body_buf, "varta_audit_fsync_seconds_sum {sum_s_af:.9}");
        let _ = writeln!(
            self.body_buf,
            "varta_audit_fsync_seconds_count {}",
            self.audit_fsync_count_total
        );
        self.body_buf.push_str(
            "# HELP varta_socket_bind_dir_fsync_failed_total fsync(2) calls on the UDS socket parent directory during observer bind that returned an error. Non-zero indicates a durability degradation — the unlink+bind sequence may not survive a power-loss journal replay.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_socket_bind_dir_fsync_failed_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_socket_bind_dir_fsync_failed_total {}",
            self.bind_dir_fsync_failed_total
        );
        self.body_buf.push_str(
            "# HELP varta_audit_fsync_budget_exceeded_total fdatasync(2) calls on the recovery audit log whose wall time exceeded --audit-fsync-budget-ms. Remaining records in the affected drain are written-to-BufWriter only; the next maintenance tick reattempts the sync.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_audit_fsync_budget_exceeded_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_audit_fsync_budget_exceeded_total {}",
            self.audit_fsync_budget_exceeded_total
        );
        self.body_buf.push_str(
            "# HELP varta_audit_rotation_budget_exceeded_total drive_audit_rotation calls that exceeded --audit-rotation-budget-ms. The state machine preserves progress and the next tick resumes.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_audit_rotation_budget_exceeded_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_audit_rotation_budget_exceeded_total {}",
            self.audit_rotation_budget_exceeded_total
        );
        // Rising-edge ring-fill watermark counters.  Both label values
        // (warn = 75%, critical = 95%) emitted unconditionally so
        // absent() alerts are correct from the first scrape.
        self.body_buf.push_str(
            "# HELP varta_audit_ring_watermark_total Rising-edge transitions of the audit-record ring fill across warning (75%) and critical (95%) thresholds. Increment indicates drain pressure that has not yet caused records to drop.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_audit_ring_watermark_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_audit_ring_watermark_total{{level=\"warn\"}} {}",
            self.audit_ring_watermark_total[0]
        );
        let _ = writeln!(
            self.body_buf,
            "varta_audit_ring_watermark_total{{level=\"critical\"}} {}",
            self.audit_ring_watermark_total[1]
        );
        // IpStateTable probe-exhaustion — /metrics accept path.
        self.body_buf.push_str(
            "# HELP varta_prom_ip_state_probe_exhausted_total IpStateTable lookups/inserts that ran the full MAX_PROBE budget.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_prom_ip_state_probe_exhausted_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_prom_ip_state_probe_exhausted_total {}",
            self.prom_ip_state_probe_exhausted_total
        );
        self.body_buf.push_str(
            "# HELP varta_prom_pid_row_refused_total Per-pid Prometheus metric rows refused by the bounded row table. Should stay at 0.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_prom_pid_row_refused_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_prom_pid_row_refused_total {}",
            self.prom_pid_row_refused_total
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
            "# HELP varta_secure_replay_refused_total Total authenticated secure-UDP frames refused as replays: the AEAD tag verified for a known sender but the inner VLP nonce/timestamp did not advance past the recorded high-water mark. Distinct from varta_frame_decrypt_failures_total (crypto failures).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_secure_replay_refused_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_secure_replay_refused_total {}",
            self.replay_refused_total
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
            "# HELP varta_sender_state_full_total Total authenticated secure-UDP frames refused because the sender-state table was full.\n",
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
        self.body_buf
            .push_str("# HELP varta_rate_limited_total Frames dropped due to rate limiting.\n");
        self.body_buf
            .push_str("# TYPE varta_rate_limited_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_rate_limited_total{{reason=\"per_pid\"}} {}",
            self.rate_limited_total[0]
        );
        let _ = writeln!(
            self.body_buf,
            "varta_rate_limited_total{{reason=\"global\"}} {}",
            self.rate_limited_total[1]
        );
        self.body_buf.push_str(
            "# HELP varta_observer_uds_rcvbuf_bytes Effective SO_RCVBUF size on the observer UDS, in bytes.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_observer_uds_rcvbuf_bytes gauge\n");
        let _ = writeln!(
            self.body_buf,
            "varta_observer_uds_rcvbuf_bytes {}",
            self.uds_rcvbuf_bytes
        );
        self.body_buf.push_str(
            "# HELP varta_observer_clock_regression_total Times the observer monotonic clock returned a value strictly less than the previously observed one and the forward clamp absorbed the regression. Non-zero values indicate TSC drift, VM live migration, or another clock anomaly.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_observer_clock_regression_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_observer_clock_regression_total {}",
            self.clock_regressions_total
        );
        self.body_buf.push_str(
            "# HELP varta_observer_clock_jump_forward_total Times the observer monotonic clock advanced by more than 5 s between adjacent poll ticks. Non-zero values indicate sleep/wake on monotonic-raw/boottime, VM live migration, or a hypervisor pause.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_observer_clock_jump_forward_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_observer_clock_jump_forward_total {}",
            self.clock_jumps_forward_total
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
            "# HELP varta_observer_scrape_budget_exceeded_total serve_pending calls that exceeded --scrape-budget-ms.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_observer_scrape_budget_exceeded_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_observer_scrape_budget_exceeded_total {}",
            self.scrape_budget_exceeded_total
        );
        // Per-stage iteration histogram — one labeled series per IterStage.
        // Same bucket boundaries as iteration_seconds and serve_pending_seconds
        // so operators can decompose per-iteration latency in a single PromQL
        // expression. Emits every stage×bucket combination on every scrape
        // (stable-label-set contract) so absent() alert rules and
        // histogram_quantile() work from the first scrape.
        self.body_buf.push_str(
            "# HELP varta_observer_stage_seconds Per-stage observer poll-loop wall time for latency attribution.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_observer_stage_seconds histogram\n");
        for (stage_idx, stage_label) in STAGE_LABELS.iter().enumerate() {
            let mut cum_st: u64 = 0;
            for (b_idx, bound) in ITERATION_BUCKET_BOUNDS_S.iter().enumerate() {
                cum_st = cum_st.saturating_add(self.stage_buckets[stage_idx][b_idx]);
                let _ = writeln!(
                    self.body_buf,
                    "varta_observer_stage_seconds_bucket{{stage=\"{stage_label}\",le=\"{bound}\"}} {cum_st}",
                );
            }
            let inf_i = ITERATION_BUCKET_BOUNDS_S.len();
            cum_st = cum_st.saturating_add(self.stage_buckets[stage_idx][inf_i]);
            let _ = writeln!(
                self.body_buf,
                "varta_observer_stage_seconds_bucket{{stage=\"{stage_label}\",le=\"+Inf\"}} {cum_st}"
            );
            let sum_s = (self.stage_duration_ns_sum[stage_idx] as f64) / 1e9;
            let _ = writeln!(
                self.body_buf,
                "varta_observer_stage_seconds_sum{{stage=\"{stage_label}\"}} {sum_s:.9}"
            );
            let _ = writeln!(
                self.body_buf,
                "varta_observer_stage_seconds_count{{stage=\"{stage_label}\"}} {}",
                self.stage_count_total[stage_idx]
            );
        }
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
            self.prom_auth_failures_total
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
        self.body_buf.push_str(
            "# HELP varta_signal_handler_install_total Signal-handler installation events since startup, labelled by mode (direct or libc). Always 1 in steady state; 0 means install was skipped or the label was never set.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_signal_handler_install_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_signal_handler_install_total{{mode=\"{}\"}} 1",
            self.signal_handler_mode,
        );
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
            .duration_since(std::time::UNIX_EPOCH)
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
