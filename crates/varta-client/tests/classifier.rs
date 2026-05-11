//! Unit tests for `classify_send_error`.
//!
//! These tests exercise the classifier against synthetic `io::Error` values
//! built from known raw OS codes and ErrorKind variants.

use std::io;

use varta_client::{classify_send_error, BeatOutcome};

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
        matches!(classify_send_error(&err), BeatOutcome::Dropped),
        "ENOBUFS (code {ENOBUFS_FOR_THIS_OS}) should classify as Dropped"
    );
}

#[test]
fn wouldblock_classifies_as_dropped() {
    let err = io::Error::from(io::ErrorKind::WouldBlock);
    assert!(matches!(classify_send_error(&err), BeatOutcome::Dropped));
}

#[test]
fn connection_refused_classifies_as_dropped() {
    let err = io::Error::from(io::ErrorKind::ConnectionRefused);
    assert!(matches!(classify_send_error(&err), BeatOutcome::Dropped));
}

#[test]
fn permission_denied_classifies_as_failed() {
    // EPERM (1) is not in the Dropped list — must surface as Failed.
    let err = io::Error::from_raw_os_error(1);
    assert!(
        matches!(classify_send_error(&err), BeatOutcome::Failed(_)),
        "EPERM should classify as Failed, not Dropped"
    );
}
