//! Fixed-capacity debounce ledger for recovery firing.

use std::time::{Duration, Instant};

/// Maximum number of pids tracked in [`LastFiredTable`].
///
/// Each slot is `Option<LastFiredSlot>` ≈ 24 bytes → ~96 KiB total table —
/// within budget for the observer (which already carries
/// `MAX_SENDER_STATES = 1024` rate-limit tables and the `PidIndex`).
///
/// Sized to make the M8 debounce-bypass attack costly: under steady-state
/// 4096 unique pids would have to stall faster than `debounce` cadence
/// before the eviction policy kicks in.  Above that threshold the table
/// fails closed via [`super::RecoveryOutcome::RefusedDebounceCapacity`].
pub(super) const MAX_LAST_FIRED_CAPACITY: usize = 4096;

/// Per-pid entry in [`LastFiredTable`].
#[derive(Clone, Copy)]
pub(super) struct LastFiredSlot {
    pub(super) pid: u32,
    /// Process *generation* token (kernel-attested start-time) pinned by the
    /// stalled slot whose recovery fired. `None` when the origin carried no
    /// kernel attestation (remote `OperatorAttestedTransport`, non-Linux).
    /// Distinguishes a recycled PID from the original process — see
    /// [`same_lineage`].
    pub(super) generation: Option<u64>,
    pub(super) fired_at: Instant,
}

/// Two start-time generation tokens describe the **same** process lineage
/// unless both are `Some(_)` and differ — in which case the OS recycled the
/// PID to a new process. `None` on either side is "generation unknown" and is
/// treated leniently (same lineage, never a recycle signal), mirroring the
/// tracker `Slot` generation semantics in `tracker/mod.rs`.
#[inline]
fn same_lineage(stored: Option<u64>, incoming: Option<u64>) -> bool {
    !matches!((stored, incoming), (Some(a), Some(b)) if a != b)
}

/// Outcome of [`LastFiredTable::try_insert`].
#[derive(Debug, Eq, PartialEq)]
pub(super) enum InsertOutcome {
    /// Slot was newly allocated (either filling an empty slot or
    /// updating an existing one for the same pid).
    Inserted,
    /// Table was at capacity; an entry whose age exceeded `debounce`
    /// was evicted to make room.  Debounce semantics are preserved
    /// because the evicted pid's window had already elapsed.
    EvictedOldest {
        /// Pid whose slot was evicted.
        #[allow(dead_code)]
        evicted_pid: u32,
    },
    /// Table is at capacity AND no entry is older than `debounce`.
    /// The caller MUST treat this as a fail-closed refusal: firing
    /// would either evict a fresh entry (violating its debounce
    /// window) or skip insertion (leaving the new pid unbounded).
    RefusedCapacity,
}

enum ReservationKind {
    Existing,
    Empty,
    EvictOldest { evicted_pid: u32 },
}

pub(super) struct LastFiredReservation {
    idx: usize,
    pid: u32,
    generation: Option<u64>,
    fired_at: Instant,
    kind: ReservationKind,
}

/// Fixed-capacity, array-backed ledger of recent recovery fires.
///
/// Replaces the original `HashMap<u32, Instant>` whose reactive pruning
/// (`prune_threshold = debounce * 10`) created a debounce-bypass window
/// under adversarial load: when the map stayed full of fresh entries,
/// the `at_capacity` branch skipped the debounce check entirely and
/// fired without throttling.
///
/// Design properties:
///
/// * **Bounded WCET.** Every operation is a linear scan over a
///   fixed-size `[Option<LastFiredSlot>; MAX_LAST_FIRED_CAPACITY]`
///   backing store — deterministic, no `HashMap` rehash, no
///   randomised hash function.
/// * **Fail-closed under capacity pressure.** When the table is full
///   and no entry's age exceeds `debounce`, reservation returns `None`;
///   the caller emits a refusal audit row and bumps a Prometheus counter
///   so operators see the condition.
/// * **Clock-regression defense.** All age comparisons use
///   [`Instant::saturating_duration_since`], which returns
///   [`Duration::ZERO`] on regression — preventing a backwards clock
///   blip from auto-evicting the whole table.
/// * **No-panic indexing.** All slot access goes through `.iter()` /
///   `.iter_mut()`; defensive else-branches bump
///   `invariant_violations`, mirroring the DO-178C pattern documented
///   for `PidIndex` in `tracker.rs`.
///
/// See `book/src/architecture/observer-liveness.md` for the operator-facing
/// semantics and alerting recommendation.
pub(super) struct LastFiredTable {
    pub(super) slots: Box<[Option<LastFiredSlot>]>,
    /// Number of slots currently holding `Some`.
    pub(super) occupied: usize,
    /// Monotonic count of evictions.
    pub(super) evictions: u64,
    /// Monotonic count of impossible-by-construction conditions.
    pub(super) invariant_violations: u64,
    /// Monotonic count of stale debounce windows dropped because a slot's
    /// pinned generation proved its PID had been recycled to a new process.
    /// Surfaced as `varta_recovery_debounce_recycle_resets_total`; a non-zero
    /// value means recovery was correctly *not* suppressed for a recycled PID.
    pub(super) recycle_resets: u64,
}

impl LastFiredTable {
    pub(super) fn new() -> Self {
        Self::with_capacity(MAX_LAST_FIRED_CAPACITY)
    }

    pub(super) fn with_capacity(cap: usize) -> Self {
        LastFiredTable {
            slots: vec![None; cap].into_boxed_slice(),
            occupied: 0,
            evictions: 0,
            invariant_violations: 0,
            recycle_resets: 0,
        }
    }

    /// Return the most recent fire time for `pid` **iff** the stored slot
    /// belongs to the same process generation as `generation`.
    ///
    /// When a slot exists for `pid` but its pinned generation proves a PID
    /// recycle (`Some != Some`), the stale debounce window is dropped:
    /// `recycle_resets` is incremented and `None` is returned so the caller
    /// treats the recycled PID as a fresh agent and does **not** suppress its
    /// recovery. `None` generation on either side is lenient (see
    /// [`same_lineage`]) — preserving the pre-generation bare-PID behaviour for
    /// origins without kernel attestation.
    pub(super) fn get(&mut self, pid: u32, generation: Option<u64>) -> Option<Instant> {
        let mut found: Option<(Instant, Option<u64>)> = None;
        for s in self.slots.iter().flatten() {
            if s.pid == pid {
                found = Some((s.fired_at, s.generation));
                break;
            }
        }
        let (fired_at, stored_generation) = found?;
        if same_lineage(stored_generation, generation) {
            Some(fired_at)
        } else {
            self.recycle_resets = self.recycle_resets.saturating_add(1);
            None
        }
    }

    pub(super) fn try_reserve(
        &mut self,
        pid: u32,
        generation: Option<u64>,
        now: Instant,
        debounce: Duration,
    ) -> Option<LastFiredReservation> {
        let mut existing_slot: Option<usize> = None;
        let mut first_empty: Option<usize> = None;
        let mut oldest: Option<(usize, Instant)> = None;

        for (idx, slot) in self.slots.iter().enumerate() {
            match slot {
                Some(s) if s.pid == pid => {
                    existing_slot = Some(idx);
                    break;
                }
                Some(s) => match oldest {
                    Some((_, oldest_at)) if s.fired_at >= oldest_at => {}
                    _ => oldest = Some((idx, s.fired_at)),
                },
                None => {
                    if first_empty.is_none() {
                        first_empty = Some(idx);
                    }
                }
            }
        }

        if let Some(idx) = existing_slot {
            return Some(LastFiredReservation {
                idx,
                pid,
                generation,
                fired_at: now,
                kind: ReservationKind::Existing,
            });
        }

        if let Some(idx) = first_empty {
            return Some(LastFiredReservation {
                idx,
                pid,
                generation,
                fired_at: now,
                kind: ReservationKind::Empty,
            });
        }

        if let Some((idx, oldest_at)) = oldest {
            let age = now.saturating_duration_since(oldest_at);
            if age >= debounce {
                let evicted_pid = match self.slots.get(idx) {
                    Some(Some(s)) => s.pid,
                    _ => {
                        self.invariant_violations = self.invariant_violations.saturating_add(1);
                        return None;
                    }
                };
                return Some(LastFiredReservation {
                    idx,
                    pid,
                    generation,
                    fired_at: now,
                    kind: ReservationKind::EvictOldest { evicted_pid },
                });
            }
            return None;
        }

        self.invariant_violations = self.invariant_violations.saturating_add(1);
        None
    }

    pub(super) fn commit_reserved(&mut self, reservation: LastFiredReservation) -> InsertOutcome {
        let Some(slot) = self.slots.get_mut(reservation.idx) else {
            self.invariant_violations = self.invariant_violations.saturating_add(1);
            return InsertOutcome::RefusedCapacity;
        };

        match reservation.kind {
            ReservationKind::Existing => {
                *slot = Some(LastFiredSlot {
                    pid: reservation.pid,
                    generation: reservation.generation,
                    fired_at: reservation.fired_at,
                });
                InsertOutcome::Inserted
            }
            ReservationKind::Empty => {
                if slot.is_none() {
                    self.occupied = self.occupied.saturating_add(1);
                } else {
                    self.invariant_violations = self.invariant_violations.saturating_add(1);
                }
                *slot = Some(LastFiredSlot {
                    pid: reservation.pid,
                    generation: reservation.generation,
                    fired_at: reservation.fired_at,
                });
                InsertOutcome::Inserted
            }
            ReservationKind::EvictOldest { evicted_pid } => {
                if slot.is_none() {
                    self.invariant_violations = self.invariant_violations.saturating_add(1);
                    self.occupied = self.occupied.saturating_add(1);
                }
                *slot = Some(LastFiredSlot {
                    pid: reservation.pid,
                    generation: reservation.generation,
                    fired_at: reservation.fired_at,
                });
                self.evictions = self.evictions.saturating_add(1);
                InsertOutcome::EvictedOldest { evicted_pid }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn try_insert(
        &mut self,
        pid: u32,
        generation: Option<u64>,
        now: Instant,
        debounce: Duration,
    ) -> InsertOutcome {
        match self.try_reserve(pid, generation, now, debounce) {
            Some(reservation) => self.commit_reserved(reservation),
            None => InsertOutcome::RefusedCapacity,
        }
    }

    pub(super) fn prune_expired(&mut self, now: Instant, threshold: Duration) {
        for slot in self.slots.iter_mut() {
            if let Some(s) = slot {
                if now.saturating_duration_since(s.fired_at) >= threshold {
                    *slot = None;
                    self.occupied = self.occupied.saturating_sub(1);
                }
            }
        }
    }

    #[allow(dead_code)]
    pub(super) fn len(&self) -> usize {
        self.occupied
    }

    pub(super) fn take_evictions(&mut self) -> u64 {
        let n = self.evictions;
        self.evictions = 0;
        n
    }

    pub(super) fn take_invariant_violations(&mut self) -> u64 {
        let n = self.invariant_violations;
        self.invariant_violations = 0;
        n
    }

    pub(super) fn take_recycle_resets(&mut self) -> u64 {
        let n = self.recycle_resets;
        self.recycle_resets = 0;
        n
    }
}
