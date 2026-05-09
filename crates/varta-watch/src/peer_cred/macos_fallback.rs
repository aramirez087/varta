//! macOS credential-extraction fallback decision logic.
//!
//! `getsockopt(LOCAL_PEERTOKEN)` is the modern, single-syscall way to obtain
//! both PID and effective UID for the peer of a Unix datagram. On older
//! macOS versions or on unconnected sockets the kernel returns an error and
//! the observer falls back to `getsockopt(LOCAL_PEERPID)` for the PID and
//! `getsockopt(LOCAL_PEERCRED)` (a `struct xucred`) for the UID, taken
//! sequentially.
//!
//! Combining those three syscall outcomes into a `(pid, uid)` pair is pure
//! logic — no FFI — and so it lives in this module. The split lets us
//! exhaustively unit-test the precedence and short-return handling on any
//! CI host (including Linux) without faking syscalls.
//!
//! The result structs are deliberately syscall-flavoured (`ret`, `optlen`)
//! rather than success/failure enums: that matches what `getsockopt(2)`
//! actually returns and keeps the shim functions in `platform/macos.rs`
//! tiny and obviously-correct.

#![cfg(any(target_os = "macos", test))]

/// `getsockopt(LOCAL_PEERTOKEN)` outcome, distilled to the bytes the
/// decision function needs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) struct TokenResult {
    /// Return value from `getsockopt(2)` (0 on success, -1 on error).
    pub ret: i32,
    /// `optlen` after the call — must be ≥ `size_of::<audit_token_t>()`
    /// (32 bytes) for the token to be trusted.
    pub optlen: u32,
    /// `audit_token_t.val[5]` — the peer's PID.
    pub at_pid: u32,
    /// `audit_token_t.val[1]` — the peer's effective UID.
    pub at_euid: u32,
}

/// `getsockopt(LOCAL_PEERPID)` outcome.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) struct PidResult {
    pub ret: i32,
    pub optlen: u32,
    pub pid: i32,
}

/// `getsockopt(LOCAL_PEERCRED)` outcome (we read only `xucred.cr_uid`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) struct CredResult {
    pub ret: i32,
    pub optlen: u32,
    pub cr_uid: u32,
}

const AUDIT_TOKEN_SIZE: u32 = 32;
const I32_SIZE: u32 = 4;
const XUCRED_MIN_RETURN: u32 = 8;

/// Combine the three macOS credential `getsockopt` outcomes into a single
/// `(pid, uid)` pair.
///
/// Precedence is identical to the pre-refactor `peer_pid_after_recv` body:
///
/// 1. If `LOCAL_PEERTOKEN` succeeded with at least an audit-token-sized
///    return, use `at_pid` / `at_euid`.
/// 2. Otherwise fall back to `LOCAL_PEERPID` (positive `pid` with at least
///    `sizeof::<i32>()` returned) and `LOCAL_PEERCRED` (at least 8 bytes
///    returned), taken independently — either can succeed without the other.
/// 3. When everything fails, return `(0, 0)`. The caller treats this as a
///    "kernel attributed the datagram to no recognisable peer" sentinel; on
///    UDS this collapses to relying on socket-file permissions (Layer 1).
pub(super) fn pid_uid_from_results(
    token: TokenResult,
    pid: PidResult,
    cred: CredResult,
) -> (u32, u32) {
    if token.ret == 0 && token.optlen >= AUDIT_TOKEN_SIZE {
        return (token.at_pid, token.at_euid);
    }
    let resolved_pid = if pid.ret == 0 && pid.optlen >= I32_SIZE && pid.pid > 0 {
        pid.pid as u32
    } else {
        0
    };
    let resolved_uid = if cred.ret == 0 && cred.optlen >= XUCRED_MIN_RETURN {
        cred.cr_uid
    } else {
        0
    };
    (resolved_pid, resolved_uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_token(pid: u32, euid: u32) -> TokenResult {
        TokenResult {
            ret: 0,
            optlen: AUDIT_TOKEN_SIZE,
            at_pid: pid,
            at_euid: euid,
        }
    }
    fn fail_token() -> TokenResult {
        TokenResult {
            ret: -1,
            optlen: 0,
            at_pid: 0,
            at_euid: 0,
        }
    }
    fn ok_pid(pid: i32) -> PidResult {
        PidResult {
            ret: 0,
            optlen: I32_SIZE,
            pid,
        }
    }
    fn fail_pid() -> PidResult {
        PidResult {
            ret: -1,
            optlen: 0,
            pid: 0,
        }
    }
    fn ok_cred(uid: u32) -> CredResult {
        CredResult {
            ret: 0,
            optlen: XUCRED_MIN_RETURN,
            cr_uid: uid,
        }
    }
    fn fail_cred() -> CredResult {
        CredResult {
            ret: -1,
            optlen: 0,
            cr_uid: 0,
        }
    }

    #[test]
    fn token_success_wins_over_fallbacks() {
        let result = pid_uid_from_results(ok_token(4321, 1500), ok_pid(9999), ok_cred(9999));
        assert_eq!(result, (4321, 1500), "token success must be returned");
    }

    #[test]
    fn token_short_return_falls_back_to_pid_and_cred() {
        let short_token = TokenResult {
            ret: 0,
            optlen: AUDIT_TOKEN_SIZE - 1,
            at_pid: 9999,
            at_euid: 9999,
        };
        let result = pid_uid_from_results(short_token, ok_pid(4321), ok_cred(1500));
        assert_eq!(result, (4321, 1500));
    }

    #[test]
    fn token_fails_pid_succeeds_cred_succeeds() {
        let result = pid_uid_from_results(fail_token(), ok_pid(4321), ok_cred(1500));
        assert_eq!(result, (4321, 1500));
    }

    #[test]
    fn token_fails_pid_zero_resolves_to_sentinel_pid() {
        let result = pid_uid_from_results(fail_token(), ok_pid(0), ok_cred(1500));
        assert_eq!(result, (0, 1500));
    }

    #[test]
    fn token_fails_pid_negative_resolves_to_sentinel_pid() {
        let result = pid_uid_from_results(fail_token(), ok_pid(-1), ok_cred(1500));
        assert_eq!(result, (0, 1500));
    }

    #[test]
    fn token_fails_pid_fails_cred_succeeds_returns_zero_pid() {
        let result = pid_uid_from_results(fail_token(), fail_pid(), ok_cred(1500));
        assert_eq!(result, (0, 1500));
    }

    #[test]
    fn token_fails_pid_succeeds_cred_fails_returns_zero_uid() {
        let result = pid_uid_from_results(fail_token(), ok_pid(4321), fail_cred());
        assert_eq!(result, (4321, 0));
    }

    #[test]
    fn all_three_fail_returns_zero_zero_sentinel() {
        let result = pid_uid_from_results(fail_token(), fail_pid(), fail_cred());
        assert_eq!(result, (0, 0));
    }
}
