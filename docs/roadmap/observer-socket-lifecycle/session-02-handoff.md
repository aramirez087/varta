# Session 02 — Observer Socket Lifecycle Drop Impl Handoff

**Epic:** `observer-socket-lifecycle`
**Session:** 02 (production impl — M7 Drop + SocketGuard removal)
**Branch:** `epic/observer-socket-lifecycle--s02-drop-impl`
**Date:** 2026-05-10
**Defects closed:** M7 (Drop-leaks-socket-file)

---

## 1. What changed

### `crates/varta-watch/src/observer.rs`

Five categories of edits, all in one file:

**Edit A — import widened (line 12)**

```rust
// Before:
use std::path::Path;

// After:
use std::path::{Path, PathBuf};
```

**Edit B — Observer doc comment updated (lines 67-70)**

```rust
// Before:
/// The observer owns the socket file for its lifetime; dropping it does not
/// remove the file from disk (Session 05 owns the daemon shutdown sequence).

// After:
/// Dropping the observer best-effort unlinks the bound socket file (comparing
/// device + inode to avoid removing a foreign file that won a later race);
/// errors are ignored.
```

**Edit C — Observer struct: three new fields (after `sock`, before `tracker`)**

```rust
    path: PathBuf,
    bound_dev: u64,
    bound_ino: u64,
```

Each carries a doc comment; see the source for the exact text.

**Edit D — `bind()`: capture `owned_path`, thread through both `finish_bind` callsites**

```rust
let owned_path: PathBuf = path.to_path_buf();   // inserted after `let path = path.as_ref();`
// ...
Self::finish_bind(sock, threshold, owned_path)   // Ok arm
// ...
Self::finish_bind(sock, threshold, owned_path)   // stale-recovery arm
```

Both callsites are on disjoint `match` arms; the compiler accepts the move
without a clone.

**Edit E — `finish_bind`: new signature and body**

```rust
fn finish_bind(sock: UnixDatagram, threshold: Duration, path: PathBuf) -> io::Result<Self> {
    use std::os::unix::fs::MetadataExt;

    sock.set_read_timeout(Some(READ_TIMEOUT))?;
    let raw_fd = sock.as_raw_fd();
    peer_cred::enable_credential_passing(raw_fd)?;
    let threshold_ns = threshold.as_nanos().min(u64::MAX as u128) as u64;

    let meta = std::fs::metadata(&path)?;
    let bound_dev = meta.dev();
    let bound_ino = meta.ino();

    Ok(Observer {
        sock,
        path,
        bound_dev,
        bound_ino,
        tracker: Tracker::new(),
        threshold_ns,
        start: Instant::now(),
        stall_queue: Vec::new(),
        stall_pending: Vec::with_capacity(CAPACITY),
        stall_cursor: 0,
    })
}
```

**Edit F — `impl Drop for Observer` (appended after `probe_live`)**

Exact body shipped:

```rust
impl Drop for Observer {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.dev() == self.bound_dev && meta.ino() == self.bound_ino {
                let _ = std::fs::remove_file(&self.path);
            }
        }
        // Missing file or foreign inode → silent no-op.
    }
}
```

Inode-compare strategy chosen per constraint #6 (must not unlink a foreign
inode that won a race).

**Edit G — inline unit test appended at end of file**

```rust
#[cfg(test)]
mod tests {
    // ...
    #[test]
    fn drop_unlinks_bound_socket() { ... }
}
```

Test name: `observer::tests::drop_unlinks_bound_socket`.
Asserts: socket file exists after `bind`; absent after `drop(obs)`.

### `crates/varta-watch/src/main.rs`

**Edit H — `SocketGuard` struct deleted (was lines 32-40)**

The `SocketGuard(PathBuf)` struct and its `Drop` impl were removed entirely.
`Observer::Drop` now owns the unlink; a second cleanup was dead code.

**Edit I — `let _guard = SocketGuard(cfg.socket.clone());` deleted (was line 102)**

**Edit J — `use std::path::PathBuf;` import deleted (was line 17)**

The charter's assessment that `PathBuf` would still be needed by `Config`
was incorrect: `Config` is imported from the library crate via
`varta_watch::Config`; `main.rs` did not need its own `PathBuf` use after
`SocketGuard` was removed. Clippy caught this; import was deleted.

---

## 2. Files touched

| File | Action |
|------|--------|
| `crates/varta-watch/src/observer.rs` | Modified — 7 edits (A–G) |
| `crates/varta-watch/src/main.rs` | Modified — 3 deletions (H–J) |
| `docs/roadmap/observer-socket-lifecycle/session-02-handoff.md` | Created (this file) |

---

## 3. Decisions made

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Inode-compare in Drop (not unconditional `remove_file`) | Hard constraint #6: must not remove a foreign inode. Costs one `stat(2)` at drop time; no new dependency; no `unsafe`. |
| D2 | Single `owned_path` allocation moved into disjoint match arms | Borrow checker accepts moving a value into each arm of a match expression; no clone needed, satisfying constraint #2's spirit (no unnecessary allocations). |
| D3 | `MetadataExt` imported locally inside `finish_bind` and `drop` | Keeps OS-specific trait scoped to the two call sites that need it; cleaner module namespace. |
| D4 | Deleted `SocketGuard` from `main.rs` | Dead code after `Observer::Drop` lands; double-unlink would be harmless but misleading. |
| D5 | Deleted `use std::path::PathBuf;` from `main.rs` | Clippy flagged it as unused after `SocketGuard` was removed. Charter's assumption was wrong; corrected. |
| D6 | No M5 production-code edits | Charter verdict (session-01-handoff §2): M5 is already complete in `observer.rs:100-135`. |

---

## 4. Tests

### Added

| Test | Location | Asserts |
|------|----------|---------|
| `drop_unlinks_bound_socket` | `observer.rs` inline `#[cfg(test)]` | Binds to a unique temp path; asserts file exists; drops observer; asserts file absent |

### Passing (full run)

All 25 unit tests in `varta-watch`, all 5 acceptance tests, all 4 CLI smoke
tests, all 3 exporter endpoint tests, all 6 recovery e2e tests. Zero failures.

---

## 5. Quality gate outputs

```
$ cargo fmt --all -- --check
(no output — clean)

$ cargo clippy --workspace -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.03s
(no warnings)

$ cargo test -p varta-watch
test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
(+ acceptance, cli_smoke, exporter_endpoint, recovery_e2e — all green)

$ cargo build --workspace
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.22s
```

---

## 6. Open issues

None blocking session 03. The following are documented limitations inherited
from session 01 (§2.1), not new:

- TOCTOU between `probe_live` and the second `bind`/`remove_file` on the stale
  path. Accepted for v0.
- No `SO_SNDTIMEO` on the probe socket. Accepted for v0; documented as a
  future hardening point if a regression ever blocks here.

---

## 7. Inputs for session 03

Session 03 creates `crates/varta-watch/tests/observer_lifecycle.rs` with the
six tests specified in `session-01-handoff.md §4.2`.

Key facts session 03 needs:

- **`Observer` struct** now has `path: PathBuf`, `bound_dev: u64`,
  `bound_ino: u64` fields. The `Drop` impl compares `(dev, ino)` before
  calling `remove_file`. Tests `drop_preserves_foreign_inode` (test #6 in
  session 03) relies on this inode-compare behaviour.
- **M5 error message contract** (unchanged): a live-peer second-bind returns
  `ErrorKind::AddrInUse` with message containing the prefix
  `"another varta-watch is already running at "`.
- **`SocketGuard` is gone** from `main.rs`. End-to-end tests that previously
  relied on the daemon binary leaving the socket file around (if any) now get
  cleanup from `Observer::Drop` instead — behaviour is identical but the
  mechanism changed.
- **Isolation idiom for tests**: use `AtomicU64` + `std::env::temp_dir()` +
  a `UdsPath` RAII newtype (see `session-01-handoff.md §4.1`). The inline
  test in `observer.rs` uses a simpler `PathBuf`-returning helper
  (`unique_sock_path`) without the RAII wrapper; session 03 should use the
  full `UdsPath` newtype for belt-and-braces cleanup.
- **No new `[dependencies]`** may be added to any production crate. Test
  files in `crates/varta-watch/tests/` are compiled as part of the
  `varta-watch` crate's dev-deps, which are also currently empty — keep them
  empty.

---

## 8. Decisions log

- **D1.** Inode-compare in Drop — closed symmetric race that M5 closed on bind.
- **D2.** Single `owned_path` allocation, moved into disjoint arms — no clone.
- **D3.** `MetadataExt` scoped locally at call sites.
- **D4.** `SocketGuard` deleted from `main.rs` — dead code.
- **D5.** `use std::path::PathBuf` deleted from `main.rs` — Clippy caught unused import; charter's assessment was incorrect.
- **D6.** No M5 production edits — already complete.

---

*End of session 02 handoff.*
