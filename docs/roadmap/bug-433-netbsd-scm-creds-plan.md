# bug-433 — NetBSD `SCM_CREDS` / `struct sockcred` ABI fix (VERIFIED PLAN — not yet shipped)

**Status:** PLAN ONLY. Do **not** edit the FFI without a way to build/verify NetBSD.
**Severity:** HIGH (total silent denial of stall-detection/recovery on a declared-supported platform).
**Target file:** `crates/varta-watch/src/peer_cred/platform/bsd.rs`
**Confidence basis:** authoritative-source research (NetBSD `src` netbsd-9/10/trunk, FreeBSD `src`, `rust-lang/libc`, `man.netbsd.org`) cross-checked by an adversarial verification pass. Every numeric value below is backed by a fetched header line; offsets not confirmed on a NetBSD host are flagged.

---

## Defect

`bsd.rs` groups FreeBSD / DragonFly / NetBSD and unconditionally hardcodes the **FreeBSD** credential ABI:

| Symbol (current code) | Value | Correct on NetBSD? |
|---|---|---|
| `SCM_CREDS: i32 = 0x03` (bsd.rs:92, unconditional) | `0x03` | ❌ NetBSD is `0x10` |
| `#[cfg(netbsd)] LOCAL_CREDS = 0x0001` (bsd.rs:90) | `0x0001` | ❌ `0x0001` is NetBSD `LOCAL_OCREDS` (deprecated); correct is `0x0004` |
| `struct Cmsgcred` (84 B) used by `BsdCmsg` for all BSD | cmsgcred | ❌ NetBSD delivers `struct sockcred` (28 B) |

Consequence chain on a real NetBSD host:
1. `LOCAL_CREDS = 0x0001` mis-sets the socket option (requests the deprecated `LOCAL_OCREDS` path), so the kernel may not even attach the modern credential cmsg.
2. Even if it did, `BsdCmsg::TARGET_TYPE = SCM_CREDS = 0x03`, but NetBSD stamps the cmsg `cmsg_type = 0x10` → `find_credential::<BsdCmsg>` filters it out → `peer_pid_after_recv` returns `None`.
3. `recv_authenticated` treats no-credential as `IoError` → **every NetBSD beat dropped** → no stall detection, no recovery, on a platform the docs list as supported.
4. CI never catches it: `cross-compile-checks` (ci.yml:320) compiles only illumos + OpenBSD + riscv64 + musl; the sole BSD walker test fabricates a **FreeBSD** `0x03`/`cmsgcred` buffer, baking in the wrong assumption.

This is **two** independent defects: the wrong `LOCAL_CREDS` value, and the wrong `SCM_CREDS`+struct. The `LOCAL_CREDS` value is wrong even for the in-tree NetBSD `cfg` arm that already exists.

---

## (a) Pinned constants & structs (with citations)

### NetBSD — correct values to introduce

| Symbol | Value | Confidence | Source (fetched literal) |
|---|---|---|---|
| `SCM_RIGHTS` | `0x01` | HIGH | NetBSD `sys/sys/socket.h`: `#define SCM_RIGHTS 0x01` |
| `SCM_TIMESTAMP` | `0x08` | HIGH | same: `#define SCM_TIMESTAMP 0x08` |
| `SCM_CREDS` | **`0x10`** | HIGH | same: `#define SCM_CREDS 0x10 /* credentials (struct sockcred) */`; cross-confirmed `rust-libc netbsdlike/netbsd/mod.rs`: `pub const SCM_CREDS: c_int = 0x10;` |
| `LOCAL_CREDS` | **`0x0004`** | HIGH | NetBSD `sys/sys/un.h`: `#define LOCAL_CREDS 0x0004`; cross-confirmed libc: `pub const LOCAL_CREDS: c_int = 0x0004;` |
| `LOCAL_PEEREID` | `0x0003` | HIGH | `sys/sys/un.h`: `#define LOCAL_PEEREID 0x0003` (getsockopt-only connect-time query; informational, not on the per-datagram path) |
| `SOL_SOCKET` | `0xffff` | HIGH | BSD-family convention; identical to the value already used at bsd.rs:83 |

**Contested `0x04` vs `0x10` — RESOLVED in favour of `0x10`.** `0x04` was the pre-NetBSD-8.0 `sockcred70` structure (no `sc_pid`); it now appears only as a *comment* in `socket.h`. The active `#define` across NetBSD 8/9/10/trunk is `0x10`. The constant was bumped `0x04 → 0x10` precisely when `sc_pid` was added, to make the incompatible struct distinguishable on the wire. Adversarial verdict on "SCM_CREDS == 0x04": **false** (corrected to `0x10`).

**`LOCAL_OCREDS = 0x0001`** is what the current code mistakenly uses for NetBSD `LOCAL_CREDS`. Confirmed in NetBSD `un.h`: `#define LOCAL_OCREDS 0x0001`.

### NetBSD `struct sockcred` — correct layout to introduce

Source declaration order (NetBSD `sys/sys/socket.h`), cross-confirmed by `rust-libc` `pub struct sockcred`:

```rust
// NetBSD struct sockcred — SCM_CREDS (0x10) payload. LP64 layout:
//   off  0: sc_pid     (pid_t = i32, 4)
//   off  4: sc_uid     (uid_t = u32, 4)
//   off  8: sc_euid    (uid_t = u32, 4)
//   off 12: sc_gid     (gid_t = u32, 4)
//   off 16: sc_egid    (gid_t = u32, 4)
//   off 20: sc_ngroups (int   = i32, 4)
//   off 24: sc_groups  (gid_t[1] = u32[1], 4)   // flexible array, base len 1
//   total: 28 bytes (all 4-byte fields, no trailing padding)
#[repr(C)]
pub(crate) struct Sockcred {
    pub sc_pid: i32,
    pub sc_uid: u32,
    pub sc_euid: u32,
    pub sc_gid: u32,
    pub sc_egid: u32,
    pub sc_ngroups: i32,
    pub sc_groups: [u32; 1],
}
```

- Field **names/types/order:** HIGH (kernel header + libc agree; adversarial verdict on "sockcred has sc_pid": **true**).
- Exact **byte offsets / total 28 B / no padding:** MEDIUM-HIGH — derived from declaration order under the standard LP64 ABI (all of `pid_t`/`uid_t`/`gid_t`/`int` are 4-byte, 4-aligned on amd64/aarch64/i386 NetBSD). **Not** empirically confirmed on a NetBSD host (see Risks).
- The extractor dereferences **only** `sc_pid@0` and `sc_euid@8` — the two front-most fields, before the variable-length tail, i.e. the most layout-robust offsets.

### FreeBSD / DragonFly — UNCHANGED (pinned for contrast)

| Symbol | Value | Confidence | Source |
|---|---|---|---|
| `SCM_CREDS` | `0x03` | HIGH | FreeBSD `socket.h`: `#define SCM_CREDS 0x03` |
| `LOCAL_CREDS` | `0x0002` | HIGH | FreeBSD `un.h`: `#define LOCAL_CREDS 2` (current bsd.rs:88 already correct) |
| `struct cmsgcred` | 84 B; `cmcred_pid@0, cmcred_uid@4, cmcred_euid@8, cmcred_gid@12, cmcred_ngroups@16(i16), pad@18, cmcred_groups@20([u32;16])` | HIGH | `rust-libc freebsdlike/mod.rs`; matches existing asserts bsd.rs:263-268 |

DragonFly matches FreeBSD exactly (the existing `cfg(any(freebsd, dragonfly))` grouping stays). HIGH.

**Doc fix:** bsd.rs:51 currently labels `cmsgcred` "FreeBSD/NetBSD" — correct to **FreeBSD/DragonFly-only**.

---

## (b) Decision: cfg-split FFI vs route-NetBSD-to-`SocketModeOnly`

**Recommendation: cfg-split FFI per target.** FreeBSD/DragonFly keep `Cmsgcred` + `SCM_CREDS=0x03` + `LOCAL_CREDS=0x0002`; NetBSD gets a new `Sockcred` + `SCM_CREDS=0x10` + `LOCAL_CREDS=0x0004` behind a `NetBsdCmsg` `CmsgPlatform` impl.

**Deciding factor — does NetBSD deliver a per-DATAGRAM PID?** YES (HIGH). The "credentials only on the first read, then the option is cleared" restriction is documented *specifically and only* for `SOCK_STREAM`/`SOCK_SEQPACKET`. Varta's transport is `SOCK_DGRAM`, where NetBSD `unix(4)` says `LOCAL_CREDS` "provides a mechanism for the receiver to receive the credentials of the process as a recvmsg(2) control message" — per datagram. `struct sockcred` carries `sc_pid` as field 0, so the kernel genuinely supplies the per-datagram sender PID the recycle gate needs.

Because per-datagram attestation is genuinely available, routing NetBSD to `SocketModeOnly` would be a **permanent capability downgrade** of a platform the kernel supports — forfeiting `KernelAttested` recovery-eligibility and PID-recycle detection NetBSD can actually provide. That is the wrong long-term posture.

**Honesty caveat that shapes the staging:** the verified evidence safely supports the *constants* and *field order*, but the exact `sockcred` byte layout is **not hardware-validated**, and CI cannot run NetBSD (no runner; cross-compile is type-check-only). A `#[repr(C)]` with wrong offsets would mint `KernelAttested` from garbage and feed a bad PID into the recovery-KILL gate (constraint #8 surface) — worse than dropping the beat. So the cfg-split must ship **with structural guards, not on faith.**

**Staging:**
1. Land the cfg-split FFI (`NetBsdCmsg` + `Sockcred` + correct constants) guarded by:
   - compile-time `assert_field_offset!` + `size_of` asserts for every read field (mirror bsd.rs:238-269) — fail the build if the NetBSD target triple lays the struct out unexpectedly;
   - a Linux-host fabricated-buffer miri test proving the NetBSD walker arm reads `sc_pid@0`/`sc_euid@8` from a NetBSD-shaped buffer.
2. Until a NetBSD host empirically confirms a live beat reaching `/metrics`, mark NetBSD **provisional / not field-validated** in `book/src/architecture/peer-authentication.md` and keep bug-433's "needs build host" item OPEN for the empirical sign-off.

**Not recommended:** `SocketModeOnly` interim — it is a real, permanent regression given per-datagram PID is verified available. It is the correct fallback **only** if a maintainer explicitly vetoes minting `KernelAttested` from a not-yet-hardware-verified struct; in that case `cfg` NetBSD onto the existing OpenBSD plain-recv path with a `// TODO bug-433` marker.

---

## (c) CI

### 1. NetBSD cross-compile job (append to `cross-compile-checks`, ci.yml)

NetBSD is Tier-2 with no pre-built std on the stable channel → follow the **OpenBSD pattern** (nightly + `-Zbuild-std`). The job already switches to nightly + `rust-src` at ci.yml:364-368 for OpenBSD; add the NetBSD step right after the OpenBSD step to reuse that toolchain:

```yaml
      - name: cargo check — x86_64-unknown-netbsd (per-datagram SCM_CREDS attestation)
        # NetBSD uses SCM_CREDS=0x10 + struct sockcred (NOT FreeBSD's 0x03 +
        # cmsgcred) and LOCAL_CREDS=0x0004 (NOT 0x0001 = LOCAL_OCREDS). This
        # check compiles the NetBsdCmsg impl with the real target_os="netbsd"
        # cfg active, so the Sockcred compile-time layout guards run against the
        # actual NetBSD triple ABI. Type-check only — no NetBSD runner exists.
        run: |
          cargo +nightly check --locked -p varta-watch \
            --target x86_64-unknown-netbsd \
            -Zbuild-std=std,panic_abort
```

Also update the job `name:` (ci.yml:321) to include "+ NetBSD".

### 2. NetBSD-shaped fabricated-buffer unit test (mirror the FreeBSD walker test)

`mod bsd` is compiled on Linux (platform/mod.rs:30-36) so `NetBsdCmsg`/`Sockcred` must be Linux-visible (define them unconditionally like `Cmsgcred`; gate only the FFI extern block / `use`). Add alongside the existing BSD walker test, deliberately parallel but with NetBSD's `(SOL_SOCKET, 0x10)` pair and the `sockcred` offsets:

```rust
#[test]
fn netbsd_shape_buffer_returns_pid_euid() {
    // cmsghdr: cmsg_len@0, cmsg_level=SOL_SOCKET(0xffff)@4, cmsg_type=SCM_CREDS(0x10)@8
    // sockcred: sc_pid@0, sc_uid@4, sc_euid@8
    // assert find_credential::<NetBsdCmsg>(&mhdr) == Some((pid, euid))
}
// plus a NEGATIVE test: a buffer tagged cmsg_type=0x03 (FreeBSD's value) is
// REJECTED by NetBsdCmsg — proves the cfg-split actually discriminates on type.
```

Runs in the existing miri job (ci.yml:~310) and the normal Linux test job — gates every PR with no NetBSD runner. (Caveat: the fabricated buffer uses Linux-host struct layout, identical-by-construction on LP64; the NetBSD-triple codegen of the data structs is exercised only by the cross-*check*, which doesn't run tests.)

### 3. Compile-time layout guards (bsd.rs, no runner)

```rust
const _: () = assert!(mem::size_of::<Sockcred>() == 28);
// in layout_tests:
assert_field_offset!(Sockcred, sc_pid, 0);
assert_field_offset!(Sockcred, sc_euid, 8);
assert_field_offset!(Sockcred, sc_ngroups, 20);
assert_field_offset!(Sockcred, sc_groups, 24);
```

`size_of == 28` and `sc_groups@24` are the canaries that fire (inside the NetBSD cross-compile job) if the NetBSD target ABI pads differently than assumed.

---

## (d) Risks / what cannot be verified without a NetBSD build host

1. **Exact `sockcred` byte layout** — source declaration order + LP64 assumption (MEDIUM-HIGH), not a live `recvmsg`. Compile-time guards catch *compiler* layout divergence on the NetBSD triple but not a kernel that lays the struct out differently than the userland header implies (very unlikely for an all-4-byte `#[repr(C)]`, but unprovable here). Mitigated by reading only the front-most `sc_pid@0`/`sc_euid@8`.
2. **Per-datagram delivery on `SOCK_DGRAM`** — HIGH from `unix(4)` (first-read-clears is stream-only) but not observed on a live NetBSD `recvmsg` loop for beat N>1.
3. **`LOCAL_CREDS = 0x0004` actually honoured** on a non-blocking `SOCK_DGRAM` — header/libc-verified (HIGH) but the live `setsockopt` success on NetBSD is unobserved.
4. **CI gap** — no NetBSD GHA runner; the proposed job is type-check-only; no live `varta-watch → /metrics` interop test can run.

**Safest interim posture (recommended):** ship the cfg-split FFI with all compile-time layout guards + the Linux miri fabricated-buffer test + the type-check CI job; mark NetBSD **provisional / not field-validated** in `peer-authentication.md` and keep bug-433 OPEN for a maintainer to run one live beat on a NetBSD host. Do **not** route NetBSD to `SocketModeOnly` (verified capability regression) unless a maintainer vetoes provisional `KernelAttested`.

**Net:** evidence IS sufficient to ship the cfg-split safely behind compile-time + miri guards (constants and front-field offsets are HIGH/MEDIUM-HIGH; the realistic failure mode is statically caught). It is NOT sufficient to declare NetBSD field-validated — that requires a NetBSD host and remains a tracked, open follow-up.

---

## Appendix — research provenance

Authoritative sources fetched and cross-checked (multi-agent research + adversarial verification):
- `github.com/NetBSD/src` netbsd-9 / netbsd-10 / trunk `sys/sys/socket.h`, `sys/sys/un.h`
- `github.com/freebsd/freebsd-src` `sys/sys/socket.h`, `sys/sys/un.h`
- `github.com/rust-lang/libc` `src/unix/bsd/netbsdlike/netbsd/mod.rs`, `src/unix/bsd/freebsdlike/mod.rs`
- `man.netbsd.org/unix.4`, `man.freebsd.org unix(4)`

Adversarial verdicts: "SCM_CREDS == 0x04" → **false** (→ `0x10`); "sockcred has sc_pid" → **true**; "per-datagram delivery" → **true**; "libc defines sockcred/SCM_CREDS for netbsd" → **true** (but Varta is zero-dep and cannot import libc — values must be hardcoded from the headers, which agree with libc).
