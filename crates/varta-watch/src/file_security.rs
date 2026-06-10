//! Shared hardened file-opening primitives.
//!
//! Secret inputs and integrity-sensitive outputs must reject leaf symlinks
//! atomically at `open(2)` time. A separate `symlink_metadata` check is not
//! sufficient because the path can be replaced between the check and open.

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

// Platform-specific O_NOFOLLOW values (hard-coded for zero-dependency).
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
const O_NOFOLLOW: i32 = 0x0100;

// Linux UAPI O_* values are architecture-specific. Keep this table explicit:
// falling back to a generic value on an unlisted target can silently remove
// the symlink guard.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "m68k",
        target_arch = "powerpc",
        target_arch = "powerpc64",
    )
))]
const O_NOFOLLOW: i32 = 0o100000;

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "csky",
        target_arch = "hexagon",
        target_arch = "loongarch32",
        target_arch = "loongarch64",
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "s390x",
        target_arch = "sparc",
        target_arch = "sparc64",
        target_arch = "x86",
        target_arch = "x86_64",
    )
))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "csky",
        target_arch = "hexagon",
        target_arch = "loongarch32",
        target_arch = "loongarch64",
        target_arch = "m68k",
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "s390x",
        target_arch = "sparc",
        target_arch = "sparc64",
        target_arch = "x86",
        target_arch = "x86_64",
    ))
))]
compile_error!("O_NOFOLLOW value is unknown for this Linux target - add it to the cfg table above");

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
const O_NOFOLLOW: i32 = 0x20000;

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "linux",
    target_os = "illumos",
    target_os = "solaris",
)))]
compile_error!("O_NOFOLLOW value is unknown for this target - add it to the cfg gates above");

#[cfg(target_os = "linux")]
const ELOOP: i32 = 40;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
const ELOOP: i32 = 62;
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
const ELOOP: i32 = 90;

/// Open `path` using the supplied options while atomically rejecting a leaf
/// symlink. Symlink failures are normalized to `InvalidInput` with the path
/// included for operator diagnostics.
pub(crate) fn open_nofollow(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    match options.custom_flags(O_NOFOLLOW).open(path) {
        Ok(file) => Ok(file),
        Err(e) if e.raw_os_error() == Some(ELOOP) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: must not be a symlink", path.display()),
        )),
        Err(e) => Err(e),
    }
}

/// Validate an already-open inode as a regular file owned by the observer
/// UID. The metadata comes from `fstat(2)` on `file`, so a later pathname
/// replacement cannot change the validated object.
pub(crate) fn validate_regular_file(file: &File, path: &Path) -> io::Result<Metadata> {
    use std::os::unix::fs::MetadataExt;

    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: must be a regular file", path.display()),
        ));
    }

    let my_uid = crate::peer_cred::observer_uid();
    let file_uid = meta.uid();
    if file_uid != my_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{}: owned by uid {file_uid}, expected uid {my_uid}",
                path.display()
            ),
        ));
    }

    Ok(meta)
}

/// Validate an already-open inode as a private regular file owned by the
/// observer UID.
pub(crate) fn validate_private_regular_file(file: &File, path: &Path) -> io::Result<Metadata> {
    use std::os::unix::fs::PermissionsExt;

    let meta = validate_regular_file(file, path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{}: insecure permissions {:03o} (must be 0600 or stricter)",
                path.display(),
                mode
            ),
        ));
    }
    Ok(meta)
}
