//! Structured logging for `varta-watch`.
//!
//! When the `json-log` feature is enabled, diagnostics are emitted as
//! newline-delimited JSON objects on stderr.  Otherwise the default
//! `eprintln!` path is preserved — the macros expand to identical output
//! as pre-0.1.1.
//!
//! # JSON schema (one object per line)
//!
//! ```json
//! {"ts_ns":1720000000000000000,"session_id":"a3b4c5d6e7f80102","level":"info","msg":"observer bound on /tmp/varta.sock"}
//! {"ts_ns":1720000001000000000,"session_id":"a3b4c5d6e7f80102","level":"warn","pid":42,"msg":"agent 42 stalled"}
//! {"ts_ns":1720000002000000000,"session_id":"a3b4c5d6e7f80102","level":"error","pid":42,"child_pid":99,"error":"ECONNREFUSED","msg":"recovery for pid 42 failed"}
//! ```
//!
//! The `session_id` field is a 16-character lowercase hex string seeded from
//! `/dev/urandom` at observer startup.  All log lines from a single process
//! lifetime share the same value, allowing SIEM consumers to correlate entries
//! across restarts without external injection.
//!
//! # JSON string escaping
//!
//! Messages are run through a minimal JSON string escaper that handles
//! `"`, `\`, and ASCII control characters (0x00–0x1F).  No other
//! characters are escaped.  This is safe because the only variable parts
//! of log messages are integer PIDs, `io::Error` Display impls (which
//! Rust guarantees are valid UTF-8), and string constants from the source.
//!
//! There is no `serde` dependency — the JSON is hand-written to satisfy
//! the zero-dependency constraint on production crates.
//!
//! # Allocation policy
//!
//! All `varta_*` macros format into a [`StackFmt`] buffer on the stack.
//! No heap allocation occurs on the log emit path.  The only remaining
//! allocation in the macros is the `eprintln!` / `write_fmt` call itself,
//! which flushes a fixed-size stack buffer to stderr without any
//! intermediate `String`.

#[cfg(feature = "json-log")]
use std::io::{self, Write};
#[cfg(feature = "json-log")]
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-process session identifier seeded from `/dev/urandom` at startup.
/// Included in every JSON log line so all entries from one observer run
/// can be correlated even after a restart.
#[cfg(feature = "json-log")]
static SESSION_ID: AtomicU64 = AtomicU64::new(0);

/// Seed the session identifier. Call once from `main()` before any
/// `varta_*` macro fires. Falls back to a deterministic mix of PID and
/// startup timestamp if `/dev/urandom` is unavailable.
#[cfg(feature = "json-log")]
pub fn init_session_id() {
    let id = (|| -> Option<u64> {
        use std::io::Read;
        let mut buf = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .ok()?;
        Some(u64::from_le_bytes(buf))
    })()
    .unwrap_or_else(|| {
        let pid = std::process::id() as u64;
        pid.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(ts_ns())
    });
    SESSION_ID.store(id, Ordering::Relaxed);
}

/// Wall-clock timestamp for log entries, derived from `UNIX_EPOCH`.
#[cfg(feature = "json-log")]
fn ts_ns() -> u64 {
    std::time::UNIX_EPOCH
        .elapsed()
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// Write `"s"` (with surrounding quotes and proper escaping) to `w`.
#[cfg(feature = "json-log")]
fn write_json_str(w: &mut impl Write, s: &str) -> io::Result<()> {
    w.write_all(b"\"")?;
    for &b in s.as_bytes() {
        match b {
            b'\"' => w.write_all(b"\\\"")?,
            b'\\' => w.write_all(b"\\\\")?,
            b'\n' => w.write_all(b"\\n")?,
            b'\r' => w.write_all(b"\\r")?,
            b'\t' => w.write_all(b"\\t")?,
            0x00..=0x1F => write!(w, "\\u{:04x}", b)?,
            _ => w.write_all(&[b])?,
        }
    }
    w.write_all(b"\"")
}

/// Emit a single JSON log line to stderr.
#[cfg(feature = "json-log")]
pub fn emit_json(
    level: &str,
    msg: &str,
    pid: Option<u32>,
    child_pid: Option<u32>,
    error: Option<&str>,
) {
    let mut stderr = io::stderr().lock();

    let session_id = SESSION_ID.load(Ordering::Relaxed);
    let _ = write!(
        &mut stderr,
        "{{\"ts_ns\":{},\"session_id\":\"{:016x}\"",
        ts_ns(),
        session_id,
    );

    // level
    let _ = stderr.write_all(b",");
    let _ = write!(&mut stderr, "\"level\":");
    let _ = write_json_str(&mut stderr, level);

    // msg
    let _ = stderr.write_all(b",");
    let _ = write!(&mut stderr, "\"msg\":");
    let _ = write_json_str(&mut stderr, msg);

    // pid (optional)
    if let Some(p) = pid {
        let _ = stderr.write_all(b",");
        let _ = write!(&mut stderr, "\"pid\":{p}");
    }

    // child_pid (optional)
    if let Some(cp) = child_pid {
        let _ = stderr.write_all(b",");
        let _ = write!(&mut stderr, "\"child_pid\":{cp}");
    }

    // error (optional)
    if let Some(e) = error {
        let _ = stderr.write_all(b",");
        let _ = write!(&mut stderr, "\"error\":");
        let _ = write_json_str(&mut stderr, e);
    }

    let _ = writeln!(&mut stderr, "}}");
}

// ---------------------------------------------------------------------------
// StackFmt — allocation-free message buffer
// ---------------------------------------------------------------------------

/// Stack-allocated, fixed-capacity formatter for heap-free log message assembly.
///
/// Used internally by the `varta_*` logging macros.  The buffer is sized at
/// compile time; content exceeding `N` bytes is silently truncated at the
/// nearest UTF-8 codepoint boundary so the result is always valid UTF-8.
///
/// This type is an implementation detail.  It is `pub` only because
/// `#[macro_export]` macros expand at the call site and must reference it
/// via `$crate::log::StackFmt`.
#[doc(hidden)]
pub struct StackFmt<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Default for StackFmt<N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> StackFmt<N> {
    /// Create an empty buffer.
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    /// Return the formatted content as a `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        // SAFETY: `write_str` only copies from `&str` slices (which are
        // valid UTF-8) and, when the slice would overflow the buffer, backs
        // off from any partial multibyte codepoint before committing the
        // copy.  Therefore `buf[..len]` is always well-formed UTF-8.
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl<const N: usize> core::fmt::Write for StackFmt<N> {
    #[inline]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let remaining = N.saturating_sub(self.len);
        if remaining == 0 {
            return Ok(());
        }
        let bytes = s.as_bytes();
        if bytes.len() <= remaining {
            self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
        } else {
            // Back off from `remaining` past any UTF-8 continuation bytes
            // (0x80..=0xBF) so we never split a multibyte codepoint.
            let mut cut = remaining;
            while cut > 0 && (bytes[cut] & 0xC0) == 0x80 {
                cut -= 1;
            }
            self.buf[self.len..self.len + cut].copy_from_slice(&bytes[..cut]);
            self.len += cut;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public logging macros
// ---------------------------------------------------------------------------

/// Emit an info-level message.  Produces a JSON line (`json-log`) or a
/// `eprintln!("varta-watch: ...")` call (default).  No heap allocation.
#[macro_export]
macro_rules! varta_info {
    ($($arg:tt)*) => {{
        let mut _buf = $crate::log::StackFmt::<320>::new();
        let _ = ::core::fmt::Write::write_fmt(&mut _buf, ::core::format_args!($($arg)*));
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("info", _buf.as_str(), None, None, None);
        #[cfg(not(feature = "json-log"))]
        {
            let _ = ::std::io::Write::write_fmt(
                &mut ::std::io::stderr().lock(),
                ::core::format_args!("varta-watch: {}\n", _buf.as_str()),
            );
        }
    }};
}

/// Emit a warn-level message.  No heap allocation.
#[macro_export]
macro_rules! varta_warn {
    ($($arg:tt)*) => {{
        let mut _buf = $crate::log::StackFmt::<320>::new();
        let _ = ::core::fmt::Write::write_fmt(&mut _buf, ::core::format_args!($($arg)*));
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("warn", _buf.as_str(), None, None, None);
        #[cfg(not(feature = "json-log"))]
        {
            let _ = ::std::io::Write::write_fmt(
                &mut ::std::io::stderr().lock(),
                ::core::format_args!("varta-watch: {}\n", _buf.as_str()),
            );
        }
    }};
}

/// Emit an error-level message.  No heap allocation.
#[macro_export]
macro_rules! varta_error {
    ($($arg:tt)*) => {{
        let mut _buf = $crate::log::StackFmt::<320>::new();
        let _ = ::core::fmt::Write::write_fmt(&mut _buf, ::core::format_args!($($arg)*));
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("error", _buf.as_str(), None, None, None);
        #[cfg(not(feature = "json-log"))]
        {
            let _ = ::std::io::Write::write_fmt(
                &mut ::std::io::stderr().lock(),
                ::core::format_args!("varta-watch: {}\n", _buf.as_str()),
            );
        }
    }};
}

/// Emit an info-level message with an associated PID in the structured output.
/// No heap allocation.
#[macro_export]
macro_rules! varta_info_pid {
    ($pid:expr, $($arg:tt)*) => {{
        let mut _buf = $crate::log::StackFmt::<320>::new();
        let _ = ::core::fmt::Write::write_fmt(&mut _buf, ::core::format_args!($($arg)*));
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("info", _buf.as_str(), Some($pid), None, None);
        #[cfg(not(feature = "json-log"))]
        {
            let _ = ::std::io::Write::write_fmt(
                &mut ::std::io::stderr().lock(),
                ::core::format_args!("varta-watch: {}\n", _buf.as_str()),
            );
        }
    }};
}

/// Emit an info-level message with an associated PID and child PID.
/// No heap allocation.
#[macro_export]
macro_rules! varta_info_pid_child {
    ($pid:expr, $child_pid:expr, $($arg:tt)*) => {{
        let mut _buf = $crate::log::StackFmt::<320>::new();
        let _ = ::core::fmt::Write::write_fmt(&mut _buf, ::core::format_args!($($arg)*));
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("info", _buf.as_str(), Some($pid), Some($child_pid), None);
        #[cfg(not(feature = "json-log"))]
        {
            let _ = ::std::io::Write::write_fmt(
                &mut ::std::io::stderr().lock(),
                ::core::format_args!("varta-watch: {}\n", _buf.as_str()),
            );
        }
    }};
}

/// Emit a warn-level message with an associated child PID.  No heap allocation.
#[macro_export]
macro_rules! varta_warn_child {
    ($child_pid:expr, $($arg:tt)*) => {{
        let mut _buf = $crate::log::StackFmt::<320>::new();
        let _ = ::core::fmt::Write::write_fmt(&mut _buf, ::core::format_args!($($arg)*));
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("warn", _buf.as_str(), None, Some($child_pid), None);
        #[cfg(not(feature = "json-log"))]
        {
            let _ = ::std::io::Write::write_fmt(
                &mut ::std::io::stderr().lock(),
                ::core::format_args!("varta-watch: {}\n", _buf.as_str()),
            );
        }
    }};
}

/// Emit an error-level message with an associated PID and error Display.
/// No heap allocation.
#[macro_export]
macro_rules! varta_error_pid {
    ($pid:expr, $error:expr, $($arg:tt)*) => {{
        let mut _buf = $crate::log::StackFmt::<320>::new();
        let mut _err = $crate::log::StackFmt::<128>::new();
        let _ = ::core::fmt::Write::write_fmt(&mut _buf, ::core::format_args!($($arg)*));
        let _ = ::core::fmt::Write::write_fmt(&mut _err, ::core::format_args!("{}", $error));
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("error", _buf.as_str(), Some($pid), None, Some(_err.as_str()));
        #[cfg(not(feature = "json-log"))]
        {
            let _ = ::std::io::Write::write_fmt(
                &mut ::std::io::stderr().lock(),
                ::core::format_args!("varta-watch: {}\n", _buf.as_str()),
            );
        }
    }};
}

/// Emit an error-level message with an associated error Display value.
/// No heap allocation.
#[macro_export]
macro_rules! varta_error_err {
    ($error:expr, $($arg:tt)*) => {{
        let mut _buf = $crate::log::StackFmt::<320>::new();
        let mut _err = $crate::log::StackFmt::<128>::new();
        let _ = ::core::fmt::Write::write_fmt(&mut _buf, ::core::format_args!($($arg)*));
        let _ = ::core::fmt::Write::write_fmt(&mut _err, ::core::format_args!("{}", $error));
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("error", _buf.as_str(), None, None, Some(_err.as_str()));
        #[cfg(not(feature = "json-log"))]
        {
            let _ = ::std::io::Write::write_fmt(
                &mut ::std::io::stderr().lock(),
                ::core::format_args!("varta-watch: {}\n", _buf.as_str()),
            );
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::StackFmt;
    use core::fmt::Write as _;

    #[test]
    fn stack_fmt_basic() {
        let mut buf = StackFmt::<64>::new();
        write!(buf, "hello {}", 42).unwrap();
        assert_eq!(buf.as_str(), "hello 42");
    }

    #[test]
    fn stack_fmt_truncates_at_capacity() {
        let mut buf = StackFmt::<8>::new();
        write!(buf, "hello world").unwrap();
        // Truncated at 8 bytes, still valid UTF-8.
        assert_eq!(buf.as_str(), "hello wo");
        assert_eq!(buf.as_str().len(), 8);
    }

    #[test]
    fn stack_fmt_truncates_at_utf8_boundary() {
        // "€" is 3 bytes (0xE2 0x82 0xAC). Buffer of 5 fits "ab" + incomplete
        // "€" — we must not include the partial codepoint.
        let mut buf = StackFmt::<5>::new();
        write!(buf, "ab€").unwrap();
        // "ab" (2 bytes) fits; the 3-byte "€" is too wide for the remaining 3
        // bytes — wait, 2 + 3 = 5 which fits exactly.
        assert_eq!(buf.as_str(), "ab€");

        let mut buf2 = StackFmt::<4>::new();
        write!(buf2, "ab€").unwrap();
        // Only 2 bytes remaining after "ab"; "€" (3 bytes) won't fit without
        // splitting. Should truncate after "ab".
        assert_eq!(buf2.as_str(), "ab");
    }

    #[test]
    fn stack_fmt_overflow_does_not_panic() {
        let mut buf = StackFmt::<4>::new();
        // Writing 100 bytes into a 4-byte buffer must not panic.
        write!(buf, "{:0>100}", 0).unwrap();
        assert_eq!(buf.as_str().len(), 4);
    }

    #[test]
    fn stack_fmt_empty() {
        let buf = StackFmt::<16>::new();
        assert_eq!(buf.as_str(), "");
    }

    #[test]
    fn varta_info_non_json() {
        varta_info!("test {}", 42);
        varta_warn!("test {}", "warn");
        varta_error!("test {}", "err");
        varta_info_pid!(1234, "pid {}", 1234);
        varta_info_pid_child!(1234, 5678, "pid {} child {}", 1234, 5678);
        varta_warn_child!(5678, "child {}", 5678);
        varta_error_pid!(
            1234,
            std::io::Error::from(std::io::ErrorKind::Other),
            "pid {} err {}",
            1234,
            "oops"
        );
        varta_error_err!(
            std::io::Error::from(std::io::ErrorKind::Other),
            "err {}",
            "oops"
        );
    }

    #[cfg(feature = "json-log")]
    mod json_tests {
        use super::super::{write_json_str, SESSION_ID};
        use std::sync::atomic::Ordering;

        #[test]
        fn session_id_initializes_without_panic() {
            super::super::init_session_id();
            let _ = SESSION_ID.load(Ordering::Relaxed);
        }

        #[test]
        fn json_string_escaping() {
            let mut buf = Vec::new();
            write_json_str(&mut buf, "hello world").unwrap();
            assert_eq!(buf, b"\"hello world\"");
        }

        #[test]
        fn json_string_escapes_quotes() {
            let mut buf = Vec::new();
            write_json_str(&mut buf, "say \"hi\"").unwrap();
            assert_eq!(buf, b"\"say \\\"hi\\\"\"");
        }

        #[test]
        fn json_string_escapes_backslash() {
            let mut buf = Vec::new();
            write_json_str(&mut buf, "path\\to").unwrap();
            assert_eq!(buf, b"\"path\\\\to\"");
        }

        #[test]
        fn json_string_escapes_newline() {
            let mut buf = Vec::new();
            write_json_str(&mut buf, "line1\nline2").unwrap();
            assert_eq!(buf, b"\"line1\\nline2\"");
        }

        #[test]
        fn json_string_escapes_control_chars() {
            let mut buf = Vec::new();
            write_json_str(&mut buf, "a\x01b").unwrap();
            assert_eq!(buf, b"\"a\\u0001b\"");
        }
    }
}
