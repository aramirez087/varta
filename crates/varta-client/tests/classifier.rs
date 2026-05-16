//! Unit tests for `classify_send_error`.
//!
//! These tests exercise the classifier against synthetic `io::Error` values
//! built from known raw OS codes and ErrorKind variants.

use std::io::{self, Write};

use varta_client::{classify_send_error, BeatError, BeatOutcome, DropReason};

// The ENOBUFS constant is module-private in client.rs, so it is replicated
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

/// Validates that the hardcoded `ENOBUFS` constant matches the value defined
/// in the system errno header on the current platform.  Reads the canonical
/// header file at test time; if the header is absent (cross-compilation,
/// minimal container), the test is skipped.
///
/// This guards against kernel errno renumbering silently misclassifying
/// `ENOBUFS` (transient `Dropped`) as an unexpected `Failed` error.
#[test]
fn enobufs_matches_system_header() {
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

    // Concatenate every header that exists.  On Linux the kernel-headers
    // package splits errnos across `errno-base.h` (1–34) and `errno.h` (35+);
    // ENOBUFS=105 lives in the latter, so reading only the first hit (as the
    // original loop did) caused the test to fail on Ubuntu CI runners that
    // had `errno-base.h` present.  macOS / *BSD bundle every code in one
    // file, so concatenation is a no-op there.
    let mut combined = String::new();
    let mut any_found = false;
    for path in header_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            any_found = true;
            combined.push_str(&content);
            combined.push('\n');
        }
    }

    if !any_found {
        let _ = io::stderr()
            .write_all(b"enobufs_matches_system_header: no errno header found; skipping\n");
        return;
    }
    let content = combined;

    let mut seen_enobufs = false;
    for line in content.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("#define") else {
            continue;
        };
        let rest = rest.trim_start();
        if !rest.starts_with("ENOBUFS") {
            continue;
        }
        // Only match "ENOBUFS" followed by whitespace, not "ENOBUFS_ERROR" etc.
        let after = &rest["ENOBUFS".len()..];
        if !after.is_empty() && !after.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        let value_str = after.split_whitespace().next();
        let value = value_str
            .unwrap_or("")
            .trim_end_matches(|c: char| !c.is_ascii_digit())
            .parse::<i32>()
            .unwrap_or_else(|_| {
                panic!(
                    "failed to parse ENOBUFS value from line: {line} \
                     (value_str={value_str:?})"
                )
            });
        assert_eq!(
            value, ENOBUFS_FOR_THIS_OS,
            "ENOBUFS constant ({ENOBUFS_FOR_THIS_OS}) does not match system header \
             value ({value}) — the hardcoded constant in client.rs is stale for this \
             kernel / libc version"
        );
        seen_enobufs = true;
        break;
    }

    assert!(
        seen_enobufs,
        "ENOBUFS definition not found in system errno header; \
         check header_paths and the parser"
    );
}

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
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

#[test]
fn storage_full_classifies_as_storage_full() {
    let err = io::Error::from(io::ErrorKind::StorageFull);
    assert!(matches!(
        classify_send_error(&err),
        BeatOutcome::Dropped(DropReason::StorageFull)
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
