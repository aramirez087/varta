//! Fuzz / test-only entry point that drives the Linux cmsg walker on an
//! arbitrary byte slice.
//!
//! Gated on `#[cfg(any(fuzzing, test))]` so the module does not exist in
//! normal builds — the public API surface of `varta-watch` is unchanged.
//! `cargo fuzz` sets `--cfg fuzzing` automatically.
//!
//! The fuzz target wraps the input bytes in a Linux `Msghdr` whose
//! `msg_control` / `msg_controllen` describe the slice, then calls
//! `find_credential::<LinuxCmsg>`. The contract: never panics, never
//! returns `Some(..)` for a buffer that doesn't actually contain a
//! well-formed `SCM_CREDENTIALS` cmsg.

use super::cmsg::find_credential;
// Access via the `pub(super) use linux::*` re-export in `super::platform`
// rather than `super::platform::linux::*` directly — the inner module is
// private; the re-export is what siblings see.
use super::plat::{LinuxCmsg, Msghdr};

/// Drive the unified Linux cmsg walker on `data`. Returns the
/// `(pid, uid)` extracted from the first `SCM_CREDENTIALS` cmsg in the
/// buffer, or `None` if no such cmsg is present / the buffer is malformed.
///
/// Soundness: `find_credential` treats `data.as_ptr()` /
/// `data.len()` as the kernel-supplied `msg_control` / `msg_controllen`.
/// All bounds checks are inside the walker, so any input slice (including
/// empty, oversize, or adversarial bytes) is processed safely.
pub fn find_credential_linux(data: &[u8]) -> Option<(u32, u32)> {
    let mhdr = Msghdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        _pad1: 0,
        msg_iov: core::ptr::null_mut(),
        msg_iovlen: 0,
        msg_control: data.as_ptr() as *mut core::ffi::c_void,
        msg_controllen: data.len(),
        msg_flags: 0,
        _pad2: 0,
    };
    find_credential::<LinuxCmsg>(&mhdr)
}
