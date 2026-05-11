# Session 04 — CI Gate Go/No-Go Handoff

**Epic:** `observer-socket-lifecycle`
**Session:** 04 (CI gate — quality bar run + go/no-go report)
**Branch:** `epic/observer-socket-lifecycle--s04-ci-gate`
**Date:** 2026-05-10
**Defects closed:** M5 (bind-races-removing-foreign-socket, confirmed), M7 (Drop-leaks-socket-file, shipped)

---

## Verdict: **GO**

All six quality gates pass. All five verification greps yield the expected result. No new registry
dependencies. Every lifecycle test is green under both serial and 8-thread parallel runs.

---

## 1. Pre-condition verification greps

### 1.1 `impl Drop for Observer` — exactly one match

```
$ grep -n "impl Drop for Observer" crates/varta-watch/src/observer.rs
307:impl Drop for Observer
```

**Result:** 1 match. ✓

### 1.2 `path: PathBuf` field — present inside Observer struct

```
$ grep -n "path: PathBuf" crates/varta-watch/src/observer.rs
77:    path: PathBuf,
112:        let owned_path: PathBuf = path.to_path_buf();
243:    fn finish_bind(sock: UnixDatagram, threshold: Duration, path: PathBuf) -> io::Result<Self> {
```

**Result:** line 77 is the struct field; lines 112 and 243 are usage sites. ✓

### 1.3 Stale doc string — zero matches

```
$ grep -n "dropping it does not remove the file" crates/varta-watch/src/observer.rs
```

**Result:** no output (0 matches). ✓

### 1.4 Zero-dependency invariant

```
$ grep -A20 "\[dependencies\]" crates/varta-vlp/Cargo.toml crates/varta-client/Cargo.toml crates/varta-watch/Cargo.toml

crates/varta-vlp/Cargo.toml:[dependencies]

crates/varta-client/Cargo.toml:[dependencies]
crates/varta-client/Cargo.toml-
crates/varta-client/Cargo.toml-[dependencies.varta-vlp]
crates/varta-client/Cargo.toml-path = "../varta-vlp"

crates/varta-watch/Cargo.toml:[dependencies]
crates/varta-watch/Cargo.toml-
crates/varta-watch/Cargo.toml-[dependencies.varta-vlp]
crates/varta-watch/Cargo.toml-path = "../varta-vlp"
```

**Result:** all three production crates have empty or path-only `[dependencies]`. ✓

### 1.5 Observer lifecycle test list

```
$ cargo test -p varta-watch --test observer_lifecycle -- --list

bind_cleans_up_stale_socket_file: test
bind_fails_when_live_observer_present: test
bind_succeeds_on_clean_path: test
drop_preserves_foreign_inode: test
drop_swallows_missing_file: test
drop_unlinks_bound_socket: test

6 tests, 0 benchmarks
```

**Result:** all 6 tests present. ✓

---

## 2. Quality gate results

### Gate 1 — `cargo fmt --all -- --check`

```
$ cargo fmt --all -- --check
(no output)
```

**Status: PASS** ✓

### Gate 2 — `cargo clippy --workspace --tests -- -D warnings`

```
$ cargo clippy --workspace --tests -- -D warnings
    Checking varta-vlp v0.1.0
    Checking varta-tests v0.1.0
    Checking varta-watch v0.1.0
    Checking varta-client v0.1.0
    Checking varta-bench v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.19s
```

**Status: PASS** — zero warnings. ✓

### Gate 3 — `cargo test --workspace`

```
$ cargo test --workspace
   Compiling ... (all 5 crates)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.59s

varta-bench:            0 tests, ok
varta-client (lib):     0 unit tests
  acceptance:           4/4 passed
  classifier:           4/4 passed
  panic_feature:        3/3 passed
  zero_alloc:           1/1 passed
varta-tests (e2e):      2/2 passed
  client_to_observer_to_recovery_full_loop ... ok
  panic_handler_critical_beat_visible_in_metrics ... ok
varta-vlp:              9/9 passed
varta-watch (lib):      25/25 passed
  observer::tests::drop_unlinks_bound_socket ... ok
  acceptance:           5/5 passed
  cli_smoke:            4/4 passed
  exporter_endpoint:    3/3 passed
  observer_lifecycle:   6/6 passed
  recovery_e2e:         6/6 passed
doc-tests:              1 compile test passed
```

**Status: PASS** — all tests in all crates pass. ✓

### Gate 4 — `cargo build --workspace --release`

```
$ cargo build --workspace --release
   Compiling varta-vlp v0.1.0
   Compiling varta-tests v0.1.0
   Compiling varta-client v0.1.0
   Compiling varta-watch v0.1.0
   Compiling varta-bench v0.1.0
    Finished `release` profile [optimized] target(s) in 0.36s
```

**Status: PASS** ✓

### Gate 5 — `cargo test -p varta-watch --test observer_lifecycle`

```
$ cargo test -p varta-watch --test observer_lifecycle
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.00s
     Running tests/observer_lifecycle.rs

running 6 tests
test bind_succeeds_on_clean_path ... ok
test bind_fails_when_live_observer_present ... ok
test drop_unlinks_bound_socket ... ok
test drop_swallows_missing_file ... ok
test drop_preserves_foreign_inode ... ok
test bind_cleans_up_stale_socket_file ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**Status: PASS** — all 6 tests pass. ✓

Tests 4 (`drop_unlinks_bound_socket`) and 6 (`drop_preserves_foreign_inode`) were reported FAILING
in the session 03 handoff (§8.3) because session 02's M7 Drop impl had not yet merged at test-write
time. After the wave merge both tests pass, confirming the inode-compare `Drop` impl is correct.

### Gate 6 — Stress run `-- --test-threads=8`

```
$ cargo test -p varta-watch --test observer_lifecycle -- --test-threads=8
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.00s
     Running tests/observer_lifecycle.rs

running 6 tests
test bind_fails_when_live_observer_present ... ok
test drop_swallows_missing_file ... ok
test drop_unlinks_bound_socket ... ok
test bind_succeeds_on_clean_path ... ok
test bind_cleans_up_stale_socket_file ... ok
test drop_preserves_foreign_inode ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**Status: PASS** — all 6 tests pass under 8-thread parallel execution. ✓

The `unique_path` scheme (PID + `AtomicU64` counter + human-readable label) is confirmed parallel-safe.
No path collision observed.

### Gate 7 — End-to-end suite (`varta-tests`)

The `varta-tests` crate was included in the `cargo test --workspace` run (Gate 3) and both e2e tests
passed:

```
test client_to_observer_to_recovery_full_loop ... ok
test panic_handler_critical_beat_visible_in_metrics ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

**Status: PASS** — e2e suite green (ran as part of workspace gate). ✓

---

## 3. Epic summary

This epic hardened the `varta-watch` daemon's Unix-domain-socket lifecycle across two defects:

**M5 (bind-races-removing-foreign-socket):** Confirmed already complete in `observer.rs:100-135`
by session 01's audit. The bind/probe/remove flow — try `bind()` first; on `EADDRINUSE` run
`probe_live()` (zero-byte `send` on an unbound probe socket); only `remove_file` when the probe
proves the file is genuinely stale — was in tree before this epic started. Session 03 added
integration coverage (`bind_fails_when_live_observer_present`, `bind_cleans_up_stale_socket_file`,
`bind_succeeds_on_clean_path`) that locks in the contract going forward.

**M7 (Drop-leaks-socket-file):** Session 02 added `path: PathBuf`, `bound_dev: u64`, `bound_ino: u64`
to the `Observer` struct; updated `finish_bind` to capture `(dev, ino)` from `std::fs::metadata` at
bind time; appended `impl Drop for Observer` that does an inode-compare before calling
`remove_file` (ignoring all errors). The `SocketGuard` struct in `main.rs` — the previous
belt-and-braces cleanup that was dead code after the Drop impl — was deleted. Session 03 added
integration coverage (`drop_unlinks_bound_socket`, `drop_swallows_missing_file`,
`drop_preserves_foreign_inode`) that enforces constraint #6 (must not unlink a foreign inode).

Net effect: a clean observer shutdown now leaves no socket file on disk; a second observer launched
against a live first observer is rejected with an informative error; a stale file from a crashed
observer is automatically reaped without operator intervention. Zero new registry dependencies were
introduced across all five production crates.

---

## 4. Residual risks (follow-up candidates)

| Risk | Severity | Notes |
|------|----------|-------|
| SIGTERM drops process before poll loop checks latch | Low | The existing async-signal-safe `AtomicBool` latch and the poll loop's 100 ms read timeout mean the maximum latency before a clean shutdown is ~100 ms. `Observer::Drop` fires on scope exit and unlinks the socket. No additional handling needed unless a SLA tighter than 100 ms is required. |
| TOCTOU between `probe_live` and `remove_file` on the stale path | Low | A third actor can unlink the file between our `probe_live(Ok(false))` and our `remove_file`, causing `remove_file` to fail with `ENOENT` and surface as a non-`AddrInUse` error. Operator-only race; informative error message. Accepted for v0. |
| `probe_live` has no `SO_SNDTIMEO` | Very low | The zero-byte send on a fresh `unbound()` socket cannot block in practice; documented in session 01 §2.1. Set `SO_SNDTIMEO` via `setsockopt(2)` using only `std::os::unix` if a future regression ever blocks here. |
| Inode-compare in `Drop` calls `stat(2)` at drop time | Negligible | One extra syscall at daemon shutdown. Microsecond cost; acceptable given that `bind()` already calls `stat` (via `set_permissions`). |
| `Drop` fires on `Drop` during panic unwinding | Negligible | `Drop` uses `if let Ok(...) = ...` and `let _ = remove_file(...)` — it cannot itself panic. Double-panic risk is zero. |

---

## 5. Files touched this session

| File | Action |
|------|--------|
| `docs/roadmap/observer-socket-lifecycle/session-04-handoff.md` | Created (this file) |
| `.wolf/memory.md` | Created (bootstrapped; gate-run entry appended) |
| `.wolf/cerebrum.md` | Created (bootstrapped; platform learnings + do-not-repeat rules) |

No source files (`crates/**`), no test files, and no existing docs were modified.

---

*End of session 04 handoff.*
