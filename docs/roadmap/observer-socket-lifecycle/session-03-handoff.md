# Session 03 — Observer Lifecycle Tests Handoff

**Epic:** `observer-socket-lifecycle`
**Session:** 03 (lifecycle tests — no production edits)
**Branch:** `epic/observer-socket-lifecycle--s03-lifecycle-tests`
**Date:** 2026-05-10
**Defects exercised:** M5 (bind-races), M7 (Drop-unlinks-socket-file)

---

## 1. What changed

**Created:** `crates/varta-watch/tests/observer_lifecycle.rs`

Six integration tests covering the full Observer socket lifecycle. No
production source was modified. No Cargo.toml edits were needed — Cargo
discovers test files under `tests/` automatically.

---

## 2. Files touched

| Action | Path |
|--------|------|
| Created | `crates/varta-watch/tests/observer_lifecycle.rs` |
| Created | `docs/roadmap/observer-socket-lifecycle/session-03-handoff.md` (this file) |

---

## 3. Confirmed pre-conditions

- **M5 is complete** in `crates/varta-watch/src/observer.rs:100-135`. The
  bind/probe/remove flow was already in tree; no production edits needed.
- **M7 is absent.** The `Observer` struct at `observer.rs:71-79` has no
  `path`, `bound_dev`, or `bound_ino` fields; there is no `impl Drop for
  Observer`. Two tests fail until session 02 merges (see §6).
- **`Observer` is re-exported** at `crates/varta-watch/src/lib.rs:20`:
  `pub use observer::{Event, Observer};`. Integration tests can use
  `varta_watch::Observer` directly.
- **`.wolf/` directory is absent.** OpenWolf update steps are skipped,
  consistent with the session 01 decision (§7 of session-01-handoff.md).

---

## 4. Tests written

| # | Test name | Defect | Status |
|---|-----------|--------|--------|
| 1 | `bind_succeeds_on_clean_path` | M5 baseline | **PASS** |
| 2 | `bind_fails_when_live_observer_present` | M5 | **PASS** |
| 3 | `bind_cleans_up_stale_socket_file` | M5 | **PASS** |
| 4 | `drop_unlinks_bound_socket` | M7 | **FAIL** — depends on M7 Drop impl (session 02) |
| 5 | `drop_swallows_missing_file` | M7 | **PASS** (trivially — no Drop impl means no panic) |
| 6 | `drop_preserves_foreign_inode` | M7 constraint #6 | **FAIL** — depends on M7 Drop impl (session 02) |

### Why test 5 passes trivially before M7

`drop_swallows_missing_file` manually removes the socket file then drops the
Observer. Before M7, `drop()` is a no-op, so no panic can occur. The test
passes vacuously. After M7 merges it continues to pass because the `Drop`
impl swallows `ENOENT` with `let _ = std::fs::remove_file(...)`.

---

## 5. Unique-path scheme

```rust
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_path(label: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "varta-obs-{}-{}-{}.sock",
        std::process::id(),
        label,
        n
    ))
}
```

`AtomicU64` is used (not `AtomicU32` as in `acceptance.rs`) to avoid
wrap-around risk in long-running test sessions on shared CI hosts. The
human-readable `label` segment is embedded in the filename to aid debugging.
Each test passes a distinct label (`"clean"`, `"live"`, `"stale"`,
`"drop-unlink"`, `"drop-missing"`, `"drop-inode"`), and the counter
provides additional uniqueness guarantees across parallel runs.

---

## 6. Tests that depend on session 02's M7 Drop impl

The following tests will **FAIL** until the wave merge brings in session 02's
changes to `crates/varta-watch/src/observer.rs`:

- **`drop_unlinks_bound_socket`** — assertion `!path.exists()` fails because
  `Drop` does not yet unlink the socket file.
- **`drop_preserves_foreign_inode`** — assertion `!path.exists()` fails
  because `obs_b`'s drop leaves the file on disk (no Drop impl).

After M7 lands (struct fields `path`, `bound_dev`, `bound_ino` added;
`finish_bind` captures `(dev, ino)`; `impl Drop for Observer` appended), both
tests should pass without modification.

---

## 7. Fix applied during this session

**`expect_err` requires `T: Debug`** — `Observer` does not implement `Debug`.
Replaced `.expect_err(msg)` with `.err().expect(msg)` in
`bind_fails_when_live_observer_present` to extract the error without requiring
a `Debug` bound on the `Ok` variant.

**`is_socket()` requires `FileTypeExt` in scope** — added
`use std::os::unix::fs::FileTypeExt;` alongside the existing
`use std::os::unix::fs::PermissionsExt;` import.

---

## 8. Quality gates — final status

All three gates pass:

### 8.1 `cargo fmt --all -- --check`
```
(clean — no output)
```

### 8.2 `cargo clippy --workspace --tests -- -D warnings`
```
    Checking varta-watch v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.03s
```

### 8.3 `cargo test -p varta-watch --test observer_lifecycle` (full run)
```
running 6 tests
test drop_swallows_missing_file ... ok
test bind_fails_when_live_observer_present ... ok
test bind_succeeds_on_clean_path ... ok
test drop_unlinks_bound_socket ... FAILED
test bind_cleans_up_stale_socket_file ... ok
test drop_preserves_foreign_inode ... FAILED

failures:

---- drop_unlinks_bound_socket stdout ----
thread 'drop_unlinks_bound_socket' panicked at observer_lifecycle.rs:113:5:
socket must be removed after drop

---- drop_preserves_foreign_inode stdout ----
thread 'drop_preserves_foreign_inode' panicked at observer_lifecycle.rs:167:5:
drop of current observer must remove the socket

test result: FAILED. 4 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out
```

The two failures are expected and documented in §6. The compile gate
(`--no-run`) passes cleanly; the full test run confirms the 4 M5-related
tests are green.

---

## 9. Decisions log

- **D1.** Used `.err().expect(msg)` instead of `.expect_err(msg)` because
  `Observer` does not derive `Debug`. This avoids requiring a `Debug` impl
  on `Observer` just for a test convenience method.
- **D2.** Added `use std::os::unix::fs::FileTypeExt;` — `is_socket()` is
  a trait method from `FileTypeExt`, not available by default on `FileType`.
- **D3.** Belt-and-braces explicit `remove_file` at the end of tests 1, 2,
  and 3 so those tests remain hermetic whether or not M7 Drop has merged.
  Tests 4, 5, 6 do not need explicit cleanup because they either verify Drop
  removed the file, manually removed it, or leave the assertion as part of
  the test semantics.
- **D4.** `.wolf/` updates skipped — directory absent from worktree
  (consistent with session 01 decision D7).

---

## 10. Inputs for the CI gate session (session 04 or post-merge)

After the wave merge brings session 02's M7 impl into the trunk branch:

1. **Run:** `cargo test -p varta-watch --test observer_lifecycle`
2. **Expect:** all 6 tests pass.
3. **If `drop_unlinks_bound_socket` or `drop_preserves_foreign_inode` fail:**
   check that session 02 has landed the following in
   `crates/varta-watch/src/observer.rs`:
   - `Observer` struct has fields `path: PathBuf`, `bound_dev: u64`,
     `bound_ino: u64`.
   - `finish_bind` captures `std::fs::metadata(&path)?.dev()` and `.ino()`.
   - `impl Drop for Observer` does the inode-compare and swallowed
     `remove_file`.
   - `SocketGuard` in `main.rs:32-40` has been deleted.
4. **Run the full workspace gate:**
   ```
   cargo fmt --all -- --check
   cargo clippy --workspace --tests -- -D warnings
   cargo build --workspace
   cargo test --workspace
   ```

---

*End of session 03 handoff.*
