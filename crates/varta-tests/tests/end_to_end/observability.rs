//! Prometheus endpoint, metrics, file export, and rate-limiting tests — stub. Session 04.
//!
//! Tests to migrate from `end_to_end.rs`:
//! - `iteration_budget_holds_under_slow_scrape_load`
//! - `serve_pending_seconds_separates_scrape_from_beat_path`
//! - `hostile_frame_rejected_at_decode_with_label_emit`
//! - `max_beat_rate_limits_and_reports_metric`
//! - `file_export_writes_tsv`
//! - `file_export_rotation`
//! - `tracker_capacity_exceeded_reports_eviction_metric`
