# Recovery audit log (schema v2)

The recovery audit log (`varta-watch/src/audit/`) is the canonical
forensic record of every recovery action the daemon took or refused. It
exists to satisfy three operational requirements:

1. **Traceability.** For an IEC 62304 Class C device — or an aviation
   ground-station — every recovery action must be reconstructable after
   the fact: *what* was spawned, *when*, *why*, *with what outcome*.
2. **Survivability.** A power cut on the host must not silently drop the
   most recent audit records.
3. **Tamper-evidence.** A reviewer must be able to detect retroactive
   editing of historical records.

Schema v1 (the pre-2026 format) satisfied only the first of these. Schema
v2 — the current format — satisfies all three when the daemon is built
with the `audit-chain` feature.

## File format

Two file-level header lines, then one record per line. Fields are
tab-separated. Every record kind carries a leading `seq` column and a
trailing `chain` column. Free-form fields (program paths, refusal
reasons) have their `\t`, `\n`, and `\r` bytes replaced with a single
space at write time so a maliciously-chosen `argv[0]` can never inject
columns.

```
# varta-watch recovery audit v2
```

### `boot`

```
seq    wallclock_ms    observer_ns    boot    daemon_pid    prev_chain|-    reason    chain
```

A `boot` record opens every audit-log session and every post-rotation
generation. The `reason` column carries one of six stable tokens:

| reason          | when it fires                                         | `prev_chain` |
| --------------- | ----------------------------------------------------- | ------------ |
| `fresh`         | brand-new file with no prior content                  | `-`          |
| `resume`        | clean v2 tail from a prior session                    | last chain   |
| `legacy_v1`     | existing file uses v1 schema; v2 section starts here  | `-`          |
| `corrupt_tail`  | v2 file with a torn last record (kernel partial write); the file is `ftruncate`'d to the last newline before this record is appended | last good chain if recoverable, else `-` |
| `schema_drift`  | header is neither v1 nor v2                           | `-`          |
| `rotation`      | rotation generation roll                              | last chain of pre-rotation file |

### `spawn`

```
seq    wallclock_ms    observer_ns    spawn    agent_pid    child_pid    mode    program    source    template_len    chain
```

Emitted at the moment a recovery child is `fork(2)` + `execvp(2)`'d.
`mode` is always `"exec"` (shell mode was permanently removed); `program`
is `argv[0]`; `source` is either the literal `"inline"` (for
`--recovery-exec`) or the path-string for `--recovery-exec-file`.
The full argv is **not** logged — it may contain secrets, and the source
path is already auditable.

### `complete`

```
seq    wallclock_ms    observer_ns    complete    agent_pid    child_pid    outcome    exit_code|-    signal|-    duration_ns    stdout_len    stderr_len    truncated    chain
```

Emitted on reap, kill-after-timeout, or reap failure. `outcome` is one of
`reaped`, `killed`, `reap_failed`. `exit_code` and `signal` are mutually
exclusive: at most one is a number, the other is `-`.

### `refused`

```
seq    wallclock_ms    observer_ns    refused    agent_pid    reason    chain
```

Emitted when a stall is detected but recovery is structurally declined
(e.g. unauthenticated transport, cross-namespace agent). `reason` is a
stable short token so SIEM consumers can alert on it without parsing
free text.

## Sequencing

`seq` is a `u64` starting at 1 on the first `boot` record. It is strictly
monotonic *within a daemon lifetime* and *across daemon restarts* (the
new daemon resumes from `last_seq + 1` after parsing the existing tail).
A consumer detects record loss as a gap: `seq[i+1] - seq[i] > 1`.

## Durability cadence

Every `record_*` call is followed by `BufWriter::flush()` and
`File::sync_data()` (= `fdatasync(2)` on Linux) at a configurable cadence
controlled by `--recovery-audit-sync-every <N>`:

- **`N = 1`** (default, IEC 62304 Class C-conforming): one `fdatasync`
  per record.
- **`N > 1`**: one `fdatasync` per `N` records. The daemon emits a
  startup warning and the build is **not** Class C-conforming. Up to
  `N - 1` records can be lost on power cut.
- **`N = 0`**: rejected at parse time.

In addition, the daemon **unconditionally** syncs:

- Before every rotation rename.
- After writing the post-rotation `boot` record.
- In `Drop` (best-effort; not load-bearing for correctness).

## Tamper-evidence: the hash chain

When the daemon is built with `--features audit-chain`, every record's
trailing `chain` column is the lowercase-hex SHA-256 of:

```
DOMAIN || 0x00 || kind || 0x00 || prev_chain_raw || 0x00 || body_with_seq
```

where:

- `DOMAIN = b"VARTA-AUDIT-v2"`. The trailing `v2` is the schema version;
  a future v3 mandatorily bumps this so chains across schemas cannot be
  confused.
- `kind` is the bytes `b"boot"` / `b"spawn"` / `b"complete"` /
  `b"refused"`.
- `prev_chain_raw` is the **raw 32-byte** prior chain hash (not its hex
  form), or `[0u8; 32]` for the very first record in a fresh file.
- `body_with_seq` is the TSV line from the `seq` column up to (but not
  including) the chain column — no trailing `\n`.
- Four `0x00` separators prevent field-boundary confusion: e.g.
  `(kind="ab", body="cd")` and `(kind="abcd", body="")` hash to
  distinct strings.

The construction is implemented once in
`crates/varta-vlp/src/crypto/hash.rs::audit_chain_hash` so callers
cannot accidentally drop the domain separation or transpose the input
order.

### What this detects

- **Any byte edited in any historical record.** The edited record's own
  chain stops matching, and every subsequent chain also stops matching.
- **Any record deleted.** The chain breaks at the deletion point.
- **Any record inserted.** Same — the chain over the synthetic record
  cannot match the next legitimate record.
- **Records reordered.** The chain validates only in original order.

### What this does NOT detect

A pure SHA-256 hash chain — without a secret key — can be **recomputed
end-to-end** by an attacker with write access to the file. Tampering is
only detectable when the *latest chain head* is verified against an
externally trusted source. Operators in safety-critical deployments
should periodically export `tail -1 audit.log | cut -f<last>` to a
sealed log (Tang, AWS S3 with object-lock, a hardware HSM, etc.). The
daemon does not do this — it is an operational policy decision.

A future HMAC-keyed mode is **out of scope** for v2 to avoid forcing a
key-distribution workflow on every Class C deployment.

### When `audit-chain` is disabled

If the daemon is built without `--features audit-chain`:

- The `chain` column is the literal string `-`.
- The daemon emits a startup warning explicitly stating that the build
  is **not** IEC 62304 Class C-conforming.
- `seq` and `fdatasync` cadence still work — record loss is detectable;
  power-cut durability is preserved; **only** tamper-evidence is absent.

The build remains zero-registry-dep (the `audit-chain` feature
propagates the existing optional crypto deps in `varta-vlp/crypto`).

## Rotation

When `--recovery-audit-max-bytes <N>` is set, the file rotates after any
write that pushes it over the threshold: `PATH` → `PATH.1` → … →
`PATH.5`. Five generations are kept; the oldest is unlinked. The same
generation count as the event-stream `FileExporter`.

The chain spans rotation: the first non-header record in the new
generation is a `boot` with `reason=rotation` whose `prev_chain` column
is the final chain of the just-rotated file. A reviewer who pieces
generations together by `seq` order can replay-verify the chain across
the entire history.

## Verification recipe

```bash
# 1. Confirm seq is strictly monotonic across all generations.
cat audit.log.5 audit.log.4 audit.log.3 audit.log.2 audit.log.1 audit.log \
    | grep -v '^#' \
    | awk -F'\t' 'NR==1 { prev = $1; next } $1 != prev+1 { print "GAP at seq", $1; exit 1 } { prev = $1 }'

# 2. Confirm chain validates (requires the daemon's
# audit_chain_hash helper exposed in a verification tool — out of scope
# for the daemon binary itself, see book/src/architecture/peer-authentication.md
# for the pattern).

# 3. Cross-check that the chain head matches the latest sealed-log entry
# the operator exports to their trusted store.
```

## CLI surface

| Flag                                | Required | Default | Meaning |
| ----------------------------------- | -------- | ------- | ------- |
| `--recovery-audit-file <PATH>`      | no       | unset   | Append audit records to PATH. Created mode 0600. |
| `--recovery-audit-max-bytes <N>`    | no       | unbounded | Rotate after a write that pushes the file past N bytes. |
| `--recovery-audit-sync-every <N>`   | no       | 1       | fdatasync cadence. `1` is the only Class C-conforming value. |
| `--audit-fsync-budget-ms <MS>`      | no       | 50      | Soft per-call budget for one `fdatasync(2)`. Overruns defer further fsyncs in the *current* drain to next tick; the poll loop never blocks on more than one slow fsync per tick. |
| `--audit-sync-interval-ms <MS>`     | no       | 0       | Time-based fdatasync cadence. `0` disables; with a non-zero value the drain force-syncs after this many ms have elapsed since the last sync (in addition to `--recovery-audit-sync-every`). |
| `--audit-rotation-budget-ms <MS>`   | no       | 50      | Per-tick budget for the rotation state machine. Overruns preserve progress and resume on the next maintenance tick. |

## Durability vs availability

The default configuration is unchanged from Class C semantics:
`--recovery-audit-sync-every=1` + `--audit-sync-interval-ms=0` means
every record fsyncs before the drain returns, and
`--audit-fsync-budget-ms=50` only ever takes effect when a single
fsync exceeds 50 ms — i.e. when the disk is *already* stalling the
poll loop.  The new flag does not weaken durability for safety-critical
operators; it provides the structural guarantee that the poll loop
itself cannot block indefinitely on a wedged fsync.

Operators who can accept relaxed durability (e.g. cloud SRE
deployments, not safety-critical) set
`--recovery-audit-sync-every=64 --audit-sync-interval-ms=100` to
amortise fsync cost over many records while still pinning a
worst-case sync interval.

See [observer-liveness.md](observer-liveness.md#audit-log-durability-vs-availability)
for the audit-log observability signals and recommended alerts.

## Threat model

| Threat                                          | Detected? | Mechanism |
| ----------------------------------------------- | --------- | --------- |
| Record loss from buffer-only flush + power cut  | yes       | `seq` gap; durability cadence; rotation pre-rename sync |
| Record loss from process kill                   | yes       | `seq` gap; resume `boot` on restart |
| Single record edit (any byte)                   | yes (with chain) | hash chain divergence |
| Bulk re-write by attacker with file-write access AND chain re-computation | no  | requires an external sealed chain-head log |
| Schema downgrade (v2 → v1)                      | yes       | `schema_drift` boot or first-line header check |
| Replay of a captured audit file in a different deployment | yes (with chain) | initial `prev_chain = [0; 32]` differs per host/lifetime |
