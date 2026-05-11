# Session 01 — Observer Socket Lifecycle Charter Handoff

**Epic:** `observer-socket-lifecycle`
**Session:** 01 (charter — audit + contract; no production edits)
**Branch:** `epic/observer-socket-lifecycle--s01-charter`
**Date:** 2026-05-10
**Defects in scope:** M5 (bind-races-removing-foreign-socket), M7 (Drop-leaks-socket-file)

This handoff is the load-bearing input for sessions 02 (production impl) and
03 (lifecycle tests). It quotes the current code by `file:line`, gives a
verdict on M5, specifies the exact M7 contract, lists every test session 03
must write, records the toolchain, and recommends the SIGTERM posture.

---

## 1. Current-state audit (read-only)

### 1.1 `Observer::bind` — M5 logic is already in tree

Quoting `crates/varta-watch/src/observer.rs:100-135` (verbatim, current
working copy):

```rust
pub fn bind(path: impl AsRef<Path>, threshold: Duration, socket_mode: u32) -> io::Result<Self> {
    let path = path.as_ref();

    match UnixDatagram::bind(path) {
        Ok(sock) => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(socket_mode))?;
            Self::finish_bind(sock, threshold)
        }
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            match probe_live(path) {
                Ok(true) => Err(io::Error::new(
                    ErrorKind::AddrInUse,
                    format!(
                        "another varta-watch is already running at {}",
                        path.display()
                    ),
                )),
                Ok(false) => {
                    // Genuine stale socket — clean up and retry bind.
                    std::fs::remove_file(path)?;
                    let sock = UnixDatagram::bind(path)?;
                    std::fs::set_permissions(
                        path,
                        std::fs::Permissions::from_mode(socket_mode),
                    )?;
                    Self::finish_bind(sock, threshold)
                }
                Err(e) => Err(io::Error::new(
                    e.kind(),
                    format!("cannot probe socket at {}: {e}", path.display()),
                )),
            }
        }
        Err(e) => Err(e),
    }
}
```

And the probe at `crates/varta-watch/src/observer.rs:249-284`:

```rust
fn probe_live(path: &Path) -> io::Result<bool> {
    let sock = UnixDatagram::unbound()?;

    // On macOS, connect() to a dead UDS DGRAM returns ECONNREFUSED immediately.
    // On Linux, it may succeed (sets default peer only), so we must also check send().
    if let Err(e) = sock.connect(path) {
        return match e.kind() {
            ErrorKind::PermissionDenied => Err(e),
            _ => Ok(false), // ECONNREFUSED / ENOENT — no listener.
        };
    }

    // If connect() succeeded, try to send a zero-byte datagram. A live listener
    // will accept it; a stale socket file with no listener will reject it.
    match sock.send(&[]) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Err(e),
        Err(_) => Ok(false), // ECONNREFUSED / ENOTCONN — stale socket.
    }
}
```

**Verdict — M5: complete in production code.** The "try `bind` first; on
`AddrInUse` probe; only `remove_file` when the probe proves the socket is
genuinely stale" flow is in tree at `observer.rs:103-135`. Session 02 does
NOT need to rewrite this. Session 03 must add test coverage (see §4).

### 1.2 `Observer` struct — current shape (no `path` field)

`crates/varta-watch/src/observer.rs:71-79`:

```rust
pub struct Observer {
    sock: UnixDatagram,
    tracker: Tracker,
    threshold_ns: u64,
    start: Instant,
    stall_queue: Vec<Option<Event>>,
    stall_pending: Vec<(u32, u64, u64)>,
    stall_cursor: usize,
}
```

No `path`, no `(dev, ino)`. M7's Drop impl needs all three (see §3).

### 1.3 `finish_bind` constructor

`crates/varta-watch/src/observer.rs:232-247`:

```rust
fn finish_bind(sock: UnixDatagram, threshold: Duration) -> io::Result<Self> {
    sock.set_read_timeout(Some(READ_TIMEOUT))?;
    let raw_fd = sock.as_raw_fd();
    peer_cred::enable_credential_passing(raw_fd)?;
    let threshold_ns = threshold.as_nanos().min(u64::MAX as u128) as u64;
    Ok(Observer {
        sock,
        tracker: Tracker::new(),
        threshold_ns,
        start: Instant::now(),
        stall_queue: Vec::new(),
        stall_pending: Vec::with_capacity(CAPACITY),
        stall_cursor: 0,
    })
}
```

Called from both branches in `bind` (Ok branch at line 106, stale-recovery
branch at line 125). Session 02 threads `PathBuf` through both callsites
plus the signature.

### 1.4 Daemon entrypoint — `SocketGuard` will become redundant

`crates/varta-watch/src/main.rs:32-40`:

```rust
/// RAII guard that removes the socket file on drop so a clean shutdown
/// (signal or `--shutdown-after-secs`) never leaves a stale socket behind.
struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
```

Instantiated at `main.rs:102`:

```rust
let _guard = SocketGuard(cfg.socket.clone());
```

Once `Observer::Drop` lands (M7, session 02) this `SocketGuard` is
double-cleanup. Double-unlink is harmless (the new `Drop` swallows
`ENOENT`), but the dead code should go. Session 02 deletes both the struct
(lines 32-40) and the `let _guard = ...` line (line 102).

### 1.5 SIGTERM / SIGINT handling — already wired

`crates/varta-watch/src/main.rs:42-63` installs an async-signal-safe
handler on SIGINT (2) and SIGTERM (15) via raw `signal(3)`. The handler
flips the `SHUTDOWN: AtomicBool` latch (`main.rs:30`). The poll loop
checks the latch at `main.rs:117-119` and breaks out cleanly. After the
loop, `observer` falls out of scope and is dropped — which after session
02 will trigger our new `Drop` impl and unlink the socket.

**No additional signal handling required in this epic.** See §5 for the
recommendation.

### 1.6 Existing test coverage of the Observer lifecycle

`crates/varta-watch/tests/` files inspected:

- `acceptance.rs` — exercises beat decoding, stall detection, decode
  errors, peer-cred spoof rejection. Uses `unique_uds_path(tag)` /
  `static UDS_COUNTER: AtomicU32` (lines 9, 16, 21). **Does not test
  bind-on-live-peer, bind-on-stale-file, or Drop-unlinks.**
- `cli_smoke.rs` — checks `--help` / argv parsing only.
- `exporter_endpoint.rs` — exercises `/metrics` HTTP.
- `recovery_e2e.rs` — exercises stall→recovery spawn.

**Gap:** no test asserts that `Observer::bind` rejects a live peer with
`AddrInUse`, no test asserts that a stale file is reaped, no test
asserts that the socket file is gone after `drop(observer)`. Session 03
fills this gap.

---

## 2. M5 contract — no production-code delta needed

**Verdict:** M5 is already implemented at
`crates/varta-watch/src/observer.rs:100-135` with the probe at
`crates/varta-watch/src/observer.rs:249-284`. **Session 02 makes no
M5-related production-code edits.** Session 03 inherits the following
contract verbatim:

- A live-peer second-bind returns `io::Error` with
  `e.kind() == ErrorKind::AddrInUse` and the **exact** message
  ```
  another varta-watch is already running at <path>
  ```
  where `<path>` is `path.display()`. The string `"another varta-watch
  is already running at "` is the assertion prefix session 03 uses
  with `e.to_string().contains(...)`.

- A stale regular file at the bind path is removed and bind retried.
  Session 03 asserts both that bind returns `Ok` and that the file is
  subsequently a Unix socket (`metadata.file_type().is_socket()`).

- A path the caller cannot probe (`PermissionDenied` from
  `probe_live`) surfaces with the message
  `cannot probe socket at <path>: <inner>` and the inner error kind
  preserved (`observer.rs:127-130`). Not exercised by v0 tests; recorded
  here for completeness.

### 2.1 Accepted limitations (documented, not in v0 scope)

- **TOCTOU between `probe_live` and the second `bind`/`remove_file`.**
  A third actor could win the path between our `probe_live` returning
  `Ok(false)` and our `remove_file`. Our `remove_file` would then fail
  with `ENOENT` (the third actor already unlinked) and propagate as a
  non-`AddrInUse` error. This is an operator-only race (two misconfigured
  observers) and acceptable for v0. The error message is informative.

- **`probe_live` has no explicit send timeout.** Constraint #4 demands
  the probe must not block. The zero-byte `send(&[])` at line 279 only
  blocks if the peer's receive buffer is full. On a fresh probe socket
  with no prior traffic, the kernel queues the datagram and returns
  immediately. A pathological live peer that has filled its receive
  buffer with prior probes is not reachable from a fresh `unbound()`
  socket. **No `SO_SNDTIMEO` required for v0.** If a future regression
  ever blocks here, set `SO_SNDTIMEO` via `setsockopt(2)` using only
  `std::os::unix` (no new deps).

---

## 3. M7 contract — exact production-code delta for session 02

All edits below are in `crates/varta-watch/src/observer.rs` unless
otherwise stated.

### 3.1 Struct change — add `path`, `bound_dev`, `bound_ino`

Replace the struct at `observer.rs:71-79` with:

```rust
pub struct Observer {
    sock: UnixDatagram,
    /// The on-disk path this Observer bound to. Used by `Drop` to
    /// unlink the socket file at shutdown. Heap-allocated once at
    /// `bind()` time; not touched on the `poll` hot path.
    path: PathBuf,
    /// `st_dev` of the bound socket file, captured immediately after
    /// `bind()`. Compared with the current on-disk file at `Drop` to
    /// avoid unlinking a foreign inode that won a later race.
    bound_dev: u64,
    /// `st_ino` of the bound socket file, captured immediately after
    /// `bind()`. See `bound_dev`.
    bound_ino: u64,
    tracker: Tracker,
    threshold_ns: u64,
    start: Instant,
    stall_queue: Vec<Option<Event>>,
    stall_pending: Vec<(u32, u64, u64)>,
    stall_cursor: usize,
}
```

Add `use std::path::PathBuf;` to the imports at the top of the file
(or expand the existing `use std::path::Path;` to
`use std::path::{Path, PathBuf};`).

**Heap-footprint note.** `PathBuf` allocates once at `bind()`. `bind()`
already allocates for `set_permissions` and for the
`format!("another varta-watch...")` error path. Constraint #2 forbids
heap allocation on the `beat()` hot path — that path lives in
`varta-client::Varta::beat`, not in `varta-watch::Observer::poll`. The
new field has zero effect on it.

### 3.2 `Observer::bind` change — thread `PathBuf` through both branches

At the top of `bind` (just after `let path = path.as_ref();`,
`observer.rs:101`) capture an owned copy:

```rust
let owned_path: PathBuf = path.to_path_buf();
```

Update the two `Self::finish_bind(sock, threshold)` callsites:

- `observer.rs:106` → `Self::finish_bind(sock, threshold, owned_path)`
- `observer.rs:125` → `Self::finish_bind(sock, threshold, owned_path)`

Because both callsites consume `owned_path` and they are on disjoint
match arms, the move is sound; no clone is needed.

### 3.3 `finish_bind` new signature

Replace `observer.rs:232-246` with:

```rust
fn finish_bind(
    sock: UnixDatagram,
    threshold: Duration,
    path: PathBuf,
) -> io::Result<Self> {
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

`MetadataExt::dev` and `MetadataExt::ino` are stable since Rust 1.1.
No new dependency, no `unsafe`.

### 3.4 `Drop` impl — append at end of file

Append to `crates/varta-watch/src/observer.rs` (after the closing brace
of the `probe_live` function, around line 285):

```rust
impl Drop for Observer {
    /// Unlink the socket file iff the on-disk inode still matches the
    /// one we bound to. Errors are swallowed: a `drop` must never panic
    /// (especially during stack unwinding), the file may have been
    /// removed by another process, and library code is forbidden from
    /// emitting diagnostics.
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

### 3.5 Inode-compare vs. unconditional `remove_file` — choice + rationale

**Choice:** inode-compare (the body in §3.4).

**Rationale:**

1. Hard constraint #6 forbids removing a foreign inode that won a race
   between our bind and our drop. Inode-compare is the only mechanical
   way to enforce that without introducing tracking state in a parent
   process.
2. The cost is a single extra `stat(2)` syscall at drop time (and one
   at bind time). On the order of microseconds; `bind()` is already
   doing `set_permissions` (a `chmod(2)`) and a `format!` for the error
   path. Same syscall-budget order of magnitude.
3. It uses only `std::os::unix::fs::MetadataExt` — already used by
   `peer_cred` for fd plumbing — so no new dependency and no new
   `unsafe`.
4. The simpler "unconditional `remove_file`" alternative is only safe
   if we can prove no two processes ever race on the same socket path.
   M5 entered the codebase precisely because that assumption was wrong;
   closing the symmetric end of the loop with the same rigour is the
   consistent posture.

### 3.6 Companion cleanup in `main.rs`

Once §3.1-§3.4 land, the `SocketGuard` in `main.rs:32-40` is dead code.
Session 02 deletes:

- `crates/varta-watch/src/main.rs:32-40` — the `SocketGuard` struct +
  its `Drop` impl.
- `crates/varta-watch/src/main.rs:102` — the
  `let _guard = SocketGuard(cfg.socket.clone());` line.

The remaining cleanup path is: SIGTERM/SIGINT or `--shutdown-after-secs`
flips `SHUTDOWN`; the poll loop breaks; `observer` falls out of scope;
`Observer::Drop` unlinks the socket file iff still ours.

---

## 4. Test contract — what session 03 writes

**New file:** `crates/varta-watch/tests/observer_lifecycle.rs`.

### 4.1 Isolation idiom (no new deps; per session prompt)

```rust
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct UdsPath(PathBuf);

impl UdsPath {
    fn as_path(&self) -> &Path {
        &self.0
    }
}

impl Drop for UdsPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn unique_path() -> UdsPath {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("varta-obs-{}-{}.sock", std::process::id(), n));
    let _ = std::fs::remove_file(&p); // belt-and-braces
    UdsPath(p)
}
```

Note: the prompt specifies `AtomicU64`. The pre-existing
`acceptance.rs:9,16` uses `AtomicU32`; session 03 deliberately uses
`AtomicU64` per the charter to avoid wrap-around risk in long-running
test sessions on shared CI hosts.

### 4.2 Tests session 03 must write

Each test must use an independent `unique_path()` so they can run in
parallel under `cargo test` without interference.

| # | Test name | Setup → Assertion |
|---|-----------|-------------------|
| 1 | `bind_succeeds_on_clean_path` | No prior file at `path`. `Observer::bind(path, threshold, 0o600)` returns `Ok`. `path.exists()` is true. `std::fs::metadata(path).unwrap().file_type().is_socket()` is true. `metadata.permissions().mode() & 0o777 == 0o600`. |
| 2 | `bind_fails_when_live_observer_present` | First `Observer::bind` succeeds and is held in scope. Second `Observer::bind` at the same path returns `Err(e)` where `e.kind() == ErrorKind::AddrInUse` and `e.to_string().contains("another varta-watch is already running at ")`. |
| 3 | `bind_cleans_up_stale_socket_file` | `std::fs::write(path, b"").unwrap()` (a regular file). `Observer::bind(path, threshold, 0o600)` returns `Ok`. `metadata.file_type().is_socket()` is true (the regular file was replaced). |
| 4 | `drop_unlinks_bound_socket` | `Observer::bind` succeeds; assert `path.exists()`; explicit `drop(obs)`; assert `!path.exists()`. |
| 5 | `drop_swallows_missing_file` | `Observer::bind` succeeds. Manually `std::fs::remove_file(path).unwrap()`. `drop(obs)` must complete without panicking (the test merely returns). |
| 6 | `drop_preserves_foreign_inode` | `let a = Observer::bind(path, ...)?;` Capture `a`. Manually `std::fs::remove_file(path).unwrap()`. `let b = Observer::bind(path, ...)?;` (new inode at the same path). `drop(a);` Assert `path.exists()` (a's drop did NOT remove b's inode). `drop(b);` Assert `!path.exists()`. **Locks in constraint #6.** |

`threshold` may be any reasonable value, e.g. `Duration::from_secs(1)`.
`0o600` is the canonical permission tested in the daemon.

### 4.3 What session 03 must NOT do

- Do **not** depend on `tempfile`, `serial_test`, `libc`, `nix`, or any
  registry crate. Use `std::env::temp_dir()` + `std::sync::atomic`.
- Do **not** add tests that rely on signals or `fork(2)` — session 03
  uses in-process `bind`/`drop` only.
- Do **not** change `observer.rs` from a test file. The struct and
  `bind` flow are already test-friendly through the public API.

---

## 5. SIGTERM / SIGINT recommendation

**No epic-scope change.** The current handler at `main.rs:42-63`
flips an `AtomicBool` from an async-signal-safe context (the function
performs only one atomic store, no allocation, no I/O). The poll loop
observes the latch at `main.rs:117-119` and exits cleanly. After
session 02, exiting drops `observer`, which unlinks the socket via
the new `Drop` impl.

If a follow-up epic ever needs to refine the signal posture — e.g.
`sigaction(2)` with `SA_RESTART` cleared, atomic restoration of the
prior handler on shutdown, blocking signals on auxiliary threads — it
can do so without dependencies. None of that is needed to close M5/M7.

**Recommendation:** ship the M7 Drop impl as specified in §3; do not
touch signals.

---

## 6. Toolchain confirmation

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
profile = "minimal"
```

Stable channel; no nightly-only APIs are required by §3 or §4.
`std::os::unix::fs::MetadataExt::{dev, ino}` are stable since Rust 1.1
(file `library/std/src/os/unix/fs.rs`). No toolchain bump in this epic.

---

## 7. OpenWolf state

CLAUDE.md references `.wolf/anatomy.md`, `.wolf/cerebrum.md`,
`.wolf/buglog.json`, and `.wolf/memory.md`. The `.wolf/` directory
**does not exist** in this worktree:

```
$ ls .wolf
ls: .wolf: No such file or directory
```

Per the rule wording in `.claude/rules/openwolf.md` (check / update
files in `.wolf/`), there is nothing to update. This session does not
speculatively create the directory; if a future session reintroduces
the OpenWolf system, this handoff records that no anatomy/memory
entries were owed.

---

## 8. Quality gates run this session

All four pass on the unchanged tree (no production-code edits this
session):

- `cargo fmt --all -- --check` → clean
- `cargo clippy --workspace -- -D warnings` → clean
- `cargo build --workspace` → success
- `cargo test --workspace` → all tests pass

(Re-run by session 02 once production edits land. Run output recorded
in commit message body.)

---

## 9. Files touched by session 01

- `docs/roadmap/observer-socket-lifecycle/session-01-handoff.md` —
  **created** (this document).

No production source modified.

---

## 10. Inputs handed to session 02

Session 02 owns the M7 production change. Inputs:

- **File:** `crates/varta-watch/src/observer.rs`
  - **Imports:** widen `use std::path::Path;` to
    `use std::path::{Path, PathBuf};`.
  - **Struct at lines 71-79:** add `path: PathBuf`, `bound_dev: u64`,
    `bound_ino: u64` (see §3.1 for the exact replacement block).
  - **`bind` at lines 100-135:** capture
    `let owned_path: PathBuf = path.to_path_buf();` and thread it
    into both `finish_bind` callsites at lines 106 and 125 (§3.2).
  - **`finish_bind` at lines 232-246:** new signature
    `fn finish_bind(sock: UnixDatagram, threshold: Duration, path: PathBuf) -> io::Result<Self>`;
    body captures `(dev, ino)` from `std::fs::metadata(&path)` and
    stores them on the struct (§3.3).
  - **Append at end of file:** `impl Drop for Observer { ... }` exactly
    as in §3.4.

- **File:** `crates/varta-watch/src/main.rs`
  - **Delete lines 32-40** (`SocketGuard` struct + `Drop` impl).
  - **Delete line 102** (`let _guard = SocketGuard(cfg.socket.clone());`).
  - The `use std::path::PathBuf;` import at line 17 stays — `PathBuf`
    is still used by `Config`.

- **Quality gates:** `cargo fmt --all -- --check`,
  `cargo clippy --workspace -- -D warnings`,
  `cargo build --workspace`, `cargo test --workspace`. All must pass.

- **Hard constraints reaffirmed:** no new entries in any `[dependencies]`
  section; no new `unsafe`; `Drop` must not panic and must not emit any
  diagnostic; `Drop` must respect inode identity (constraint #6).

---

## 11. Inputs handed to session 03

Session 03 owns the lifecycle test file. Inputs:

- **File to create:** `crates/varta-watch/tests/observer_lifecycle.rs`.

- **Isolation idiom:** verbatim as in §4.1 (uses `AtomicU64`,
  `std::env::temp_dir()`, a `UdsPath` newtype with a `Drop` that
  best-effort removes the file).

- **Six tests** with the exact names and assertions in §4.2.

- **The M5 error-message contract** (§2): a live-peer second-bind
  returns `ErrorKind::AddrInUse` with a message containing the prefix
  `"another varta-watch is already running at "`. Session 03 asserts
  on that prefix, not on the full path suffix.

- **Quality gates:** same four `cargo` commands. All must pass.

- **Hard constraints reaffirmed:** no new dependency (no `tempfile`,
  no `serial_test`); tests must be parallel-safe via unique paths;
  tests must not require root.

---

## 12. Decisions log (one line each)

- **D1.** M5 is complete in production code; session 02 makes no
  M5-related edits. (Rationale: `observer.rs:100-135` already implements
  the bind/probe/remove flow.)
- **D2.** M7 stores `path: PathBuf` on the struct (single source of
  truth) rather than re-deriving it from the fd at drop time.
  (Rationale: `UnixDatagram::local_addr` is not reliable for our
  bound-path use across macOS/Linux edge cases.)
- **D3.** M7 uses inode-compare (`(dev, ino)`) at drop, not
  unconditional `remove_file`. (Rationale: constraint #6; closes the
  symmetric race that M5 closed for the other end.)
- **D4.** Session 02 also deletes the now-redundant `SocketGuard` in
  `main.rs`. (Rationale: avoids dead code; double-unlink would be
  harmless but misleading.)
- **D5.** No signal-handling changes in this epic. (Rationale: the
  existing async-signal-safe latch + clean drop chain is sufficient.)
- **D6.** No `SO_SNDTIMEO` on the probe socket. (Rationale: the
  zero-byte send on a fresh `unbound()` socket cannot block in
  practice; documented as an accepted assumption.)
- **D7.** `.wolf/` updates skipped — directory absent from worktree.

---

*End of session 01 handoff.*
