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
//! {"ts_ns":1720000000000000000,"level":"info","msg":"observer bound on /tmp/varta.sock"}
//! {"ts_ns":1720000001000000000,"level":"warn","pid":42,"msg":"agent 42 stalled"}
//! {"ts_ns":1720000002000000000,"level":"error","pid":42,"child_pid":99,"error":"ECONNREFUSED","msg":"recovery for pid 42 failed"}
//! ```
//!
//! # JSON string escaping
//!
//! Messages are run through a minimal JSOn string escaper that handles
//! `"`, `\`, and ASCII control characters (0x00–0x1F).  No other
//! characters are escaped.  This is safe because the only variable parts
//! of log messages are integer PIDs, `io::Error` Display impls (which
//! Rust guarantees are valid UTF-8), and string constants from the source.
//!
//! There is no `serde` dependency — the JSON is hand-written to satisfy
//! the zero-dependency constraint on production crates.

#[cfg(feature = "json-log")]
use std::io::{self, Write};

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

    let _ = write!(&mut stderr, "{{\"ts_ns\":{}", ts_ns());

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
// Public logging macros
// ---------------------------------------------------------------------------

/// Emit an info-level message.  Produces a JSON line (`json-log`) or a
/// `eprintln!("varta-watch: ...")` call (default).
#[macro_export]
macro_rules! varta_info {
    ($($arg:tt)*) => {{
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("info", &::std::format!($($arg)*), None, None, None);
        #[cfg(not(feature = "json-log"))]
        ::std::eprintln!("varta-watch: {}", ::std::format!($($arg)*));
    }};
}

/// Emit a warn-level message.
#[macro_export]
macro_rules! varta_warn {
    ($($arg:tt)*) => {{
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("warn", &::std::format!($($arg)*), None, None, None);
        #[cfg(not(feature = "json-log"))]
        ::std::eprintln!("varta-watch: {}", ::std::format!($($arg)*));
    }};
}

/// Emit an error-level message.
#[macro_export]
macro_rules! varta_error {
    ($($arg:tt)*) => {{
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("error", &::std::format!($($arg)*), None, None, None);
        #[cfg(not(feature = "json-log"))]
        ::std::eprintln!("varta-watch: {}", ::std::format!($($arg)*));
    }};
}

/// Emit an info-level message with an associated PID in the structured output.
#[macro_export]
macro_rules! varta_info_pid {
    ($pid:expr, $($arg:tt)*) => {{
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("info", &::std::format!($($arg)*), Some($pid), None, None);
        #[cfg(not(feature = "json-log"))]
        ::std::eprintln!("varta-watch: {}", ::std::format!($($arg)*));
    }};
}

/// Emit an info-level message with an associated PID and child PID.
#[macro_export]
macro_rules! varta_info_pid_child {
    ($pid:expr, $child_pid:expr, $($arg:tt)*) => {{
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("info", &::std::format!($($arg)*), Some($pid), Some($child_pid), None);
        #[cfg(not(feature = "json-log"))]
        ::std::eprintln!("varta-watch: {}", ::std::format!($($arg)*));
    }};
}

/// Emit a warn-level message with an associated child PID.
#[macro_export]
macro_rules! varta_warn_child {
    ($child_pid:expr, $($arg:tt)*) => {{
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("warn", &::std::format!($($arg)*), None, Some($child_pid), None);
        #[cfg(not(feature = "json-log"))]
        ::std::eprintln!("varta-watch: {}", ::std::format!($($arg)*));
    }};
}

/// Emit an error-level message with an associated PID and error Display.
#[macro_export]
macro_rules! varta_error_pid {
    ($pid:expr, $error:expr, $($arg:tt)*) => {{
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("error", &::std::format!($($arg)*), Some($pid), None, Some(&::std::format!("{}", $error)));
        #[cfg(not(feature = "json-log"))]
        ::std::eprintln!("varta-watch: {}", ::std::format!($($arg)*));
    }};
}

/// Emit an error-level message with an associated error Display value.
#[macro_export]
macro_rules! varta_error_err {
    ($error:expr, $($arg:tt)*) => {{
        #[cfg(feature = "json-log")]
        $crate::log::emit_json("error", &::std::format!($($arg)*), None, None, Some(&::std::format!("{}", $error)));
        #[cfg(not(feature = "json-log"))]
        ::std::eprintln!("varta-watch: {}", ::std::format!($($arg)*));
    }};
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "json-log")]
    mod json_tests {
        use super::super::write_json_str;

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
}
