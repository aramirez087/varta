//! Unit tests for `classify_send_error`.
//!
//! These tests exercise the classifier against synthetic `io::Error` values
//! built from known raw OS codes and ErrorKind variants.

use std::io;

use varta_client::{classify_send_error, BeatError, BeatOutcome, DropReason};

// The errno constants are module-private in client.rs, so they are replicated
// here with identical cfg guards. If the numeric value ever changes it must
// be updated in both places.
#[cfg(target_os = "linux")]
const ENOBUFS_FOR_THIS_OS: i32 = 105;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
const ENOBUFS_FOR_THIS_OS: i32 = 55;

#[cfg(any(target_os = "solaris", target_os = "illumos"))]
const ENOBUFS_FOR_THIS_OS: i32 = 111;

const ENOSPC_FOR_THIS_OS: i32 = 28;

/// Validates that the hardcoded errno constants match the values defined
/// in the system errno header on the current platform.  Reads the canonical
/// header file at test time; if the header is absent (cross-compilation,
/// minimal container), the test is skipped.
///
/// This guards against kernel errno renumbering silently misclassifying send
/// failures as unexpected `Failed` errors.
#[cfg(not(miri))]
#[test]
fn hardcoded_errno_values_match_system_header() {
    #[cfg(target_os = "linux")]
    let header_paths: &[&str] = &[
        "/usr/include/asm-generic/errno-base.h",
        "/usr/include/asm-generic/errno.h",
    ];

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
    ))]
    let header_paths: &[&str] = &[
        "/usr/include/sys/errno.h",
        "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/errno.h",
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/sys/errno.h",
    ];

    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "solaris",
        target_os = "illumos",
    ))]
    let header_paths: &[&str] = &["/usr/include/sys/errno.h"];

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "solaris",
        target_os = "illumos",
    )))]
    let header_paths: &[&str] = &[];

    assert_errno(header_paths, "ENOBUFS", ENOBUFS_FOR_THIS_OS);
    assert_errno(header_paths, "ENOSPC", ENOSPC_FOR_THIS_OS);
}

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos",
))]
#[test]
fn enobufs_classifies_as_dropped() {
    let err = io::Error::from_raw_os_error(ENOBUFS_FOR_THIS_OS);
    assert!(
        matches!(
            classify_send_error(&err),
            BeatOutcome::Dropped(DropReason::KernelQueueFull)
        ),
        "ENOBUFS (code {ENOBUFS_FOR_THIS_OS}) should classify as Dropped(KernelQueueFull)"
    );
}

#[test]
fn enospc_classifies_as_storage_full() {
    let err = io::Error::from_raw_os_error(ENOSPC_FOR_THIS_OS);
    assert!(
        matches!(
            classify_send_error(&err),
            BeatOutcome::Dropped(DropReason::StorageFull)
        ),
        "ENOSPC (code {ENOSPC_FOR_THIS_OS}) should classify as Dropped(StorageFull)"
    );
}

#[test]
fn wouldblock_classifies_as_dropped() {
    let err = io::Error::from(io::ErrorKind::WouldBlock);
    assert!(matches!(
        classify_send_error(&err),
        BeatOutcome::Dropped(DropReason::KernelQueueFull)
    ));
}

#[test]
fn connection_refused_classifies_as_dropped() {
    let err = io::Error::from(io::ErrorKind::ConnectionRefused);
    assert!(matches!(
        classify_send_error(&err),
        BeatOutcome::Dropped(DropReason::NoObserver)
    ));
}

#[test]
fn not_found_classifies_as_no_observer() {
    let err = io::Error::from(io::ErrorKind::NotFound);
    assert!(matches!(
        classify_send_error(&err),
        BeatOutcome::Dropped(DropReason::NoObserver)
    ));
}

#[test]
fn connection_reset_classifies_as_peer_gone() {
    let err = io::Error::from(io::ErrorKind::ConnectionReset);
    assert!(matches!(
        classify_send_error(&err),
        BeatOutcome::Dropped(DropReason::PeerGone)
    ));
}

#[test]
fn not_connected_classifies_as_peer_gone() {
    let err = io::Error::from(io::ErrorKind::NotConnected);
    assert!(matches!(
        classify_send_error(&err),
        BeatOutcome::Dropped(DropReason::PeerGone)
    ));
}

#[test]
fn broken_pipe_classifies_as_peer_gone() {
    let err = io::Error::from(io::ErrorKind::BrokenPipe);
    assert!(matches!(
        classify_send_error(&err),
        BeatOutcome::Dropped(DropReason::PeerGone)
    ));
}

// Structural invariant: DropReason is Copy + Eq and fits in one byte.
const _: () = {
    const fn assert_copy_eq<T: Copy + Eq>() {}
    assert_copy_eq::<DropReason>();
    assert!(core::mem::size_of::<DropReason>() == 1);
};

#[test]
fn permission_denied_classifies_as_failed() {
    // EPERM (1) is not in the Dropped list — must surface as Failed.
    let err = io::Error::from_raw_os_error(1);
    assert!(
        matches!(
            classify_send_error(&err),
            BeatOutcome::Failed(BeatError { errno: 1, .. })
        ),
        "EPERM should classify as Failed(BeatError {{ errno: 1 }}), not Dropped"
    );
}

#[test]
fn beat_error_impl_error() {
    // Compile-time assertion: BeatError satisfies std::error::Error for `?` propagation.
    const _: fn() = || {
        fn req_err<E: std::error::Error>() {}
        req_err::<BeatError>();
    };
}

#[test]
fn beat_error_to_io_error_roundtrip() {
    let be = BeatError {
        errno: 1,
        kind: io::ErrorKind::PermissionDenied,
    };
    let io_err = be.to_io_error();
    assert_eq!(io_err.raw_os_error(), Some(1));
}

#[test]
fn beat_error_unknown_errno_uses_kind() {
    let be = BeatError {
        errno: BeatError::UNKNOWN_ERRNO,
        kind: io::ErrorKind::WouldBlock,
    };
    let io_err = be.to_io_error();
    assert_eq!(io_err.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(io_err.raw_os_error(), None);
}

#[cfg(not(miri))]
fn assert_errno(header_paths: &[&str], symbol: &str, expected: i32) {
    for path in header_paths {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Some(value) = parse_errno_define(&content, symbol) {
            assert_eq!(
                value, expected,
                "{symbol} constant ({expected}) does not match system header \
                 value ({value}) — the hardcoded constant in client.rs is stale for this \
                 kernel / libc version"
            );
            return;
        }
    }

    panic!(
        "{symbol} definition not found in system errno header; \
         check header_paths and the parser"
    );
}

#[cfg(not(miri))]
fn parse_errno_define(content: &str, symbol: &str) -> Option<i32> {
    for line in content.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("#define") else {
            continue;
        };
        let rest = rest.trim_start();
        if !rest.starts_with(symbol) {
            continue;
        }
        let after = &rest[symbol.len()..];
        if !after.is_empty() && !after.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        let value_str = after.split_whitespace().next()?;
        let value = value_str
            .trim_end_matches(|c: char| !c.is_ascii_digit())
            .parse::<i32>()
            .unwrap_or_else(|_| {
                panic!(
                    "failed to parse {symbol} value from line: {line} \
                     (value_str={value_str:?})"
                )
            });
        return Some(value);
    }
    None
}
