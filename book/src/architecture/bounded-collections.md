# Bounded Collections

Varta's observer is a single-threaded poll loop on the hot path, and a
DO-178C-style audit target on the cold paths.  Both contexts require
**every** map-like structure to have a tight worst-case execution time
(WCET) bound.  `std::collections::HashMap` is incompatible with this
posture for two reasons:

1. **SipHash randomisation.**  `HashMap` re-seeds its hasher on every
   process start, so the per-process memory-access pattern is
   non-constant.  Static WCET analysis cannot bound a structure whose
   probe sequence depends on a runtime random value.
2. **Theoretical rehash.**  Even when pre-allocated with
   `HashMap::with_capacity`, growth on collision-driven load is
   reachable in theory — a rehash event would blow the per-tick budget.

`varta-watch` therefore uses a custom, registry-dep-free
**`BoundedIndex<K>`** for every map-like structure, with thin
purpose-built wrappers for each call site.

## `BoundedIndex<K>`

Defined in `crates/varta-watch/src/probe_table.rs`.

* Open-addressed `K → u32` table.
* Hash function: **Murmur3 32-bit finalizer** (`mix32`) — deterministic
  across processes, branchless, good avalanche on 32-bit and IpAddr
  inputs (the only two `Hash32` implementors today).
* Table size: `next_power_of_two(capacity * 2)` — load factor stays
  ≤ 0.5 at peak, so the expected probe distance is ≤ 2
  (Knuth TAOCP 6.4).
* Probe budget: hard cap of **64 steps**
  ([`BoundedIndex::MAX_PROBE`]) — ~32× headroom over the expected
  distance.  Every `get` / `insert` / `remove` walks at most this many
  slots before returning `None` (lookup) or `Err(ProbeExhausted)`
  (insert).
* Tombstone-aware: removal writes a sentinel rather than back-shifting,
  preserving in-flight probe chains.  Inserts reuse the first tombstone
  they encounter so long churn doesn't fill the table with deletion
  markers.
* Entry layout: `slot_idx == u32::MAX` ⇒ empty; `slot_idx == u32::MAX -
  1` ⇒ tombstone; otherwise the slot is occupied and `key` is
  initialised.  This lets `Entry<u32>` stay 8 bytes — same as the
  pre-refactor `PidIndex` — so the tracker hot path has the same
  per-slot cache pressure as before.

`BoundedIndex` is registry-dep-free and inherits the same
zero-registry-dep posture as the rest of `varta-watch`.

## Wrappers

Three thin types compose `BoundedIndex` with a value-bearing slab so the
caller can store more than just an integer index:

| Type | Key | Value | Capacity | Replaces |
|---|---|---|---|---|
| `PidIndex` (newtype) | `u32` | `u32` (slot index) | tracker_capacity | inline PidIndex (legacy `HashMap<u32, usize>`) |
| `OutstandingTable<V>` | `u32` | `V` (e.g. `Outstanding`) | tracker_capacity | `HashMap<u32, Outstanding>` in `Recovery` |
| `IpStateTable<V>` | `IpAddr` | `V` (e.g. `PromIpState`) | `MAX_PROM_IP_STATES = 1024` | `HashMap<IpAddr, PromIpState>` in `PromExporter` |

All three:

* Pre-allocate the slab at construction and never reallocate.
* Maintain a free list of slab indices for O(1) insertion.
* Return `Err(Full)` / `Err(InsertError::Full)` on capacity exhaustion;
  callers surface this as a structured refusal outcome (e.g.
  `RecoveryOutcome::RefusedOutstandingCapacity`) and bump a labelled
  Prometheus counter.

## Probe-exhausted counters

Three counters surface probe-budget exhaustion to operators.  All three
should stay at 0 in correct operation; non-zero values indicate either
a hash-collision pathology or a code bug:

* `varta_tracker_pid_index_probe_exhausted_total` — PidIndex (hot path).
* `varta_recovery_outstanding_probe_exhausted_total` — OutstandingTable
  (cold recovery path).
* `varta_prom_ip_state_probe_exhausted_total` — IpStateTable
  (Prometheus accept path).

## Fuzzing

Every bounded collection has a dedicated `cargo fuzz` target driving
arbitrary op sequences against the public API:

* `fuzz/fuzz_targets/bounded_index_u32.rs`
* `fuzz/fuzz_targets/bounded_index_ip.rs`
* `fuzz/fuzz_targets/outstanding_table.rs`
* `fuzz/fuzz_targets/ip_state_table.rs`

The `bounded_index_*` targets compare against a `HashMap` oracle on
every op to validate set-equality semantics.  The `_table` targets
assert structural invariants (`len <= capacity`, `iter` matches `len`,
post-remove `get` is `None`, etc.).  All four targets are exercised at
30 s per push/PR in the CI `fuzz-smoke` job and at 30 min nightly in
`fuzz-nightly.yml` with corpus persistence.

[`BoundedIndex::MAX_PROBE`]: https://docs.rs/varta-watch/latest/varta_watch/probe_table/struct.BoundedIndex.html
