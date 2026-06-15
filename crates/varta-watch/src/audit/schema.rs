//! TSV record types, field serialization, chain helpers.

/// Outcome category surfaced in the `complete` record.
#[derive(Debug, Clone, Copy)]
pub enum CompleteOutcome {
    /// Child exited and was reaped.
    Reaped,
    /// Child exceeded its timeout and was killed.
    Killed,
    /// `try_wait`/`kill` syscall failed for the outstanding child.
    ReapFailed,
}

impl CompleteOutcome {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Reaped => "reaped",
            Self::Killed => "killed",
            Self::ReapFailed => "reap_failed",
        }
    }
}

/// One spawn-time record. Fields are borrowed so callers can format the
/// line without allocating new strings on the hot path.
#[derive(Debug)]
pub struct SpawnRecord<'a> {
    /// Wall-clock time of the spawn, milliseconds since UNIX epoch.
    pub wallclock_ms: u64,
    /// Observer-local monotonic ns at spawn time (matches event stream).
    pub observer_ns: u64,
    /// Agent pid whose stall triggered the recovery.
    pub agent_pid: u32,
    /// Child pid of the freshly-spawned recovery process.
    pub child_pid: u32,
    /// Always `"exec"` (shell mode was permanently removed).
    pub mode: &'a str,
    /// Program path actually invoked (`argv[0]`).
    pub program: &'a str,
    /// Source of the command: `"inline"` for `--recovery-exec`, or the
    /// path-string for `--recovery-exec-file`.
    pub source: &'a str,
    /// Length in bytes of the full argv.
    pub template_len: u32,
}

/// One completion record (reap, kill, or reap failure).
#[derive(Debug)]
pub struct CompleteRecord {
    /// Wall-clock time of completion, milliseconds since UNIX epoch.
    pub wallclock_ms: u64,
    /// Observer-local monotonic ns at completion (matches event stream).
    pub observer_ns: u64,
    /// Agent pid whose recovery this completion belongs to.
    pub agent_pid: u32,
    /// Child pid of the recovery process.
    pub child_pid: u32,
    /// Outcome category — see [`CompleteOutcome`].
    pub outcome: CompleteOutcome,
    /// Numeric exit code (`Some` only when reaped normally; `-` otherwise).
    pub exit_code: Option<i32>,
    /// Signal number (`Some` only when reaped from a signal; `-` otherwise).
    pub signal: Option<i32>,
    /// Wall-clock duration from spawn to completion in ns.
    pub duration_ns: u64,
    /// Number of bytes captured from child stdout (0 when capture disabled).
    pub stdout_len: u32,
    /// Number of bytes captured from child stderr (0 when capture disabled).
    pub stderr_len: u32,
    /// True iff capture was enabled and either stream hit its byte cap.
    pub truncated: bool,
}

/// One refusal record — recovery was structurally declined for an agent
/// even though the stall threshold was met.
#[derive(Debug)]
pub struct RefusedRecord<'a> {
    /// Wall-clock time of the refusal, milliseconds since UNIX epoch.
    pub wallclock_ms: u64,
    /// Observer-local monotonic ns at refusal time (matches event stream).
    pub observer_ns: u64,
    /// Agent pid whose stall triggered the refused recovery.
    pub agent_pid: u32,
    /// Stable, short token describing why recovery was refused.
    pub reason: &'a str,
}

/// Why a `boot` record was written. Stable tokens for SIEM consumers.
#[derive(Debug, Clone, Copy)]
pub(super) enum BootReason {
    /// Fresh file — no prior audit history.
    Fresh,
    /// Resumed cleanly from a v2 tail.
    Resume,
    /// Opened a legacy v1 file; v2 section starts here.
    LegacyV1,
    /// Opened a v2 file with a torn / unparseable tail; file was truncated.
    CorruptTail,
    /// File header is neither v1 nor v2 — explicit drift evidence.
    SchemaDrift,
    /// Synthesised immediately after rotation rename.
    Rotation,
}

impl BootReason {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Resume => "resume",
            Self::LegacyV1 => "legacy_v1",
            Self::CorruptTail => "corrupt_tail",
            Self::SchemaDrift => "schema_drift",
            Self::Rotation => "rotation",
        }
    }
}

/// Kind label baked into both the TSV `record_kind` column and the chain
/// hash input.
#[derive(Debug, Clone, Copy)]
pub(super) enum AuditKind {
    Boot,
    Spawn,
    Complete,
    Refused,
}

impl AuditKind {
    #[cfg_attr(not(feature = "audit-chain"), allow(dead_code))]
    pub(super) fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Boot => b"boot",
            Self::Spawn => b"spawn",
            Self::Complete => b"complete",
            Self::Refused => b"refused",
        }
    }
}

/// Header line written to a freshly-created v2 audit file.
pub(super) const AUDIT_HEADER_V2: &str = "# varta-watch recovery audit v2\n";

/// Legacy v1 header — used to detect a v1 file on restart.
pub(super) const AUDIT_HEADER_V1_PREFIX: &str = "# varta-watch recovery audit v1";

/// True iff the build includes the `audit-chain` feature.
#[inline]
pub fn chain_enabled() -> bool {
    cfg!(feature = "audit-chain")
}

/// Parse a single TSV record line of v2 format. Returns `(seq, chain_raw)`
/// if both the leading seq column and trailing chain column decode.
pub(super) fn parse_record(line: &[u8]) -> Option<(u64, [u8; 32])> {
    let s = core::str::from_utf8(line).ok()?;
    if s.starts_with('#') {
        return None;
    }
    let mut cols = s.split('\t');
    let seq_str = cols.next()?;
    let seq: u64 = seq_str.parse().ok()?;
    let chain_str = s.rsplit('\t').next()?;
    if chain_str == "-" {
        return Some((seq, [0u8; 32]));
    }
    if chain_str.len() != 64 {
        return None;
    }
    let raw = varta_vlp::util::decode_hex_32(chain_str.as_bytes()).ok()?;
    Some((seq, raw))
}

/// Parse only the leading `seq` column of an audit line as a `u64`, ignoring
/// every later column. Used for a record that [`parse_record`] rejects (a
/// corrupt or newer-schema later column) but that is RETAINED on disk: the
/// resumed `seq` cursor must still step past its sequence number to preserve
/// strict monotonicity. Returns `None` for a comment line or a non-numeric
/// leading column.
pub(super) fn parse_leading_seq(line: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(line).ok()?;
    if s.starts_with('#') {
        return None;
    }
    s.split('\t').next()?.parse::<u64>().ok()
}

/// Replace tab/newline bytes in a free-form audit field with a literal space
/// so a maliciously-chosen file path or argv[0] can never inject a fake column.
pub(super) fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\t' | '\n' | '\r' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}

/// Hex-encode a 32-byte chain hash into a 64-char lowercase string.
pub(super) fn hex_encode_32_string(bytes: &[u8; 32]) -> String {
    let hex = varta_vlp::util::encode_hex_32(bytes);
    String::from_utf8(hex.to_vec()).expect("hex output is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_tabs_and_newlines() {
        assert_eq!(sanitize("a\tb"), "a b");
        assert_eq!(sanitize("a\nb"), "a b");
        assert_eq!(sanitize("/usr/bin/x"), "/usr/bin/x");
    }
}
