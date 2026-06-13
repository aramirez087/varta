#![allow(unsafe_code)]

//! Process-lineage epoch for fork-safe inherited client state.

use std::io;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::Once;

static FORK_EPOCH: AtomicUsize = AtomicUsize::new(0);
static REGISTER_ATFORK: Once = Once::new();
static REGISTER_RESULT: AtomicI32 = AtomicI32::new(i32::MIN);

extern "C" {
    fn pthread_atfork(
        prepare: Option<unsafe extern "C" fn()>,
        parent: Option<unsafe extern "C" fn()>,
        child: Option<unsafe extern "C" fn()>,
    ) -> i32;
}

fn advance(epoch: &AtomicUsize) {
    epoch.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn advance_child_epoch() {
    // AtomicUsize is lock-free on every target where it exists. Keep the
    // child callback to this single atomic operation: no allocation, locks,
    // syscalls, or access to inherited library state.
    advance(&FORK_EPOCH);
}

/// Register the process-wide child callback and return the current epoch.
///
/// Every client constructor calls this before returning an inheritable
/// handle. A registration failure is fatal to construction because silently
/// falling back to PID equality would reintroduce AEAD nonce reuse after PID
/// recycling.
pub(crate) fn register() -> io::Result<usize> {
    REGISTER_ATFORK.call_once(|| {
        // SAFETY: all three callbacks have the ABI required by
        // pthread_atfork. The only installed callback performs one lock-free
        // atomic increment and touches no non-async-signal-safe state.
        let result = unsafe { pthread_atfork(None, None, Some(advance_child_epoch)) };
        REGISTER_RESULT.store(result, Ordering::Release);
    });

    let result = REGISTER_RESULT.load(Ordering::Acquire);
    if result == 0 {
        Ok(current())
    } else {
        // POSIX pthread_atfork returns an error number directly.
        Err(io::Error::from_raw_os_error(result))
    }
}

/// Return the calling process's current lineage epoch.
#[inline]
pub(crate) fn current() -> usize {
    FORK_EPOCH.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_is_idempotent() {
        let first = register().expect("register pthread_atfork");
        let second = register().expect("repeat pthread_atfork registration");
        assert_eq!(first, second);
    }

    #[test]
    fn child_callback_advances_epoch_without_global_test_state() {
        let epoch = AtomicUsize::new(41);
        advance(&epoch);
        assert_eq!(epoch.load(Ordering::Relaxed), 42);
    }
}
