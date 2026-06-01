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
// the symlink guard from secret-file validation.
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
compile_error!("O_NOFOLLOW value is unknown for this Linux target — add it to the cfg table above");

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
compile_error!("O_NOFOLLOW value is unknown for this target — add it to the cfg gates above");

/// Validate that a secret file (recovery command, key, or token) meets the
/// hardened requirements: regular file, owned by the observer's UID, mode
/// `0o600` or stricter, no symlinks (`O_NOFOLLOW` open).
///
/// The open-and-validate flow is collapsed into a single file descriptor to
/// eliminate the TOCTOU window between metadata check and file read. The
/// sequence is:
///
/// 1. `open(path, O_RDONLY | O_NOFOLLOW)` — atomically rejects a symlink at
///    the leaf component. The kernel returns `ELOOP` if the path resolves
///    to a symlink, so no separate `symlink_metadata` probe is needed.
/// 2. `fstat(fd)` (via `File::metadata`) — operates on the open inode, not
///    the path. An attacker who renames or replaces the file in the parent
///    directory after the open has no effect: the fd still refers to the
///    inode we just authenticated.
/// 3. Mode / UID / file-type checks on the fstat result.
/// 4. `read_to_string` from the same fd.
///
/// Returns the raw file contents on success.
pub(crate) fn validate_secret_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    // ELOOP: 40 on Linux; 62 on BSD family; 90 on illumos/Solaris
    // (sys/errno.h). On platforms outside these lists we fall through with
    // the raw error message.
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

    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            if e.raw_os_error() == Some(ELOOP) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{}: must not be a symlink", path.display()),
                ));
            }
            return Err(e);
        }
    };

    // fstat(fd) — operates on the open inode, immune to path-level races.
    let meta = file.metadata()?;

    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{}: must be a regular file", path.display()),
        ));
    }

    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{}: insecure permissions {:03o} (must be 0600 or stricter)",
                path.display(),
                mode
            ),
        ));
    }

    let my_uid = crate::peer_cred::observer_uid();
    let file_uid = meta.uid();
    if file_uid != my_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{}: owned by uid {file_uid}, expected uid {my_uid}",
                path.display()
            ),
        ));
    }

    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

/// Recovery-command-file wrapper around [`validate_secret_file`] that also
/// trims surrounding whitespace from the contents (recovery templates do not
/// want a trailing newline appended to the command line).
pub(super) fn validate_recovery_file(path: &Path) -> std::io::Result<String> {
    let content = validate_secret_file(path)?;
    Ok(content.trim().to_string())
}

/// Validate and read a secret file (key, accepted-key, master-key, or
/// Prometheus token). Returns the raw bytes; callers are responsible for
/// trimming or splitting line-by-line.
#[cfg(feature = "secure-udp")]
pub(super) fn read_secret_file(path: &Path) -> std::io::Result<String> {
    validate_secret_file(path)
}

/// Parse a recovery command line into (program, args).
///
/// Splits on whitespace. Returns an error if the command line is empty.
pub fn parse_exec_cmd(cmd: &str) -> std::io::Result<(String, Vec<String>)> {
    let mut parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "recovery command must not be empty",
        ));
    }
    let program = parts.remove(0).to_string();
    let args: Vec<String> = parts.into_iter().map(|s| s.to_string()).collect();
    Ok((program, args))
}
