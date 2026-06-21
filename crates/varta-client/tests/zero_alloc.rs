//! Session 02 zero-allocation guard for `Varta::beat`.
#![allow(unsafe_code)]
//!
//! A `#[global_allocator]` wraps the system allocator with a per-thread
//! "armed" flag. Once armed on the beat thread, allocations on that thread
//! increment an atomic counter. The contract test connects, arms the guard,
//! beats 10 000 times, disarms, then asserts the counter stayed at zero —
//! proving the beat path never touches the heap.
//!
//! Arming is thread-local (not process-global) so unrelated libtest worker
//! threads or glibc malloc background bookkeeping on Linux cannot produce
//! spurious counts while the beat loop runs.
//!
//! See `docs/acceptance/varta-v0-1-0.md` §S02
//! `beat_makes_zero_heap_allocations_after_init`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

mod common;
use common::TempSocket;

use varta_client::{Frame, Status, Varta};

struct GuardAlloc;

thread_local! {
    static ARMED: AtomicBool = const { AtomicBool::new(false) };
}

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
/// Capture the layout size of each allocation while armed so the test can
/// report enough context to diagnose the allocation site.
const DIAG_SLOTS: usize = 8;
static DIAG: [AtomicU64; DIAG_SLOTS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

fn note_allocation_if_armed(layout: Layout) {
    let armed = ARMED.try_with(|flag| flag.load(Ordering::Relaxed));
    if armed == Ok(true) {
        let idx = ALLOC_COUNT.fetch_add(1, Ordering::Relaxed) as usize;
        if idx < DIAG_SLOTS {
            DIAG[idx].store(layout.size() as u64, Ordering::Relaxed);
        }
    }
}

unsafe impl GlobalAlloc for GuardAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_allocation_if_armed(layout);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GUARD: GuardAlloc = GuardAlloc;

#[test]
fn beat_makes_zero_heap_allocations_after_init() {
    let temp = TempSocket::new("zeroalloc");
    let server = UnixDatagram::bind(&temp.path).expect("bind server");
    let mut client = Varta::connect(&temp.path).expect("connect");
    client.set_reconnect_after(0);

    ALLOC_COUNT.store(0, Ordering::Relaxed);
    for slot in &DIAG {
        slot.store(0, Ordering::Relaxed);
    }

    ARMED.with(|armed| armed.store(true, Ordering::Relaxed));
    for _ in 0..10_000 {
        let _ = client.beat(Status::Ok, 0);
    }
    ARMED.with(|armed| armed.store(false, Ordering::Relaxed));

    let n_allocs = ALLOC_COUNT.load(Ordering::Relaxed);
    let diag_sizes: [u64; DIAG_SLOTS] = {
        let mut a = [0u64; DIAG_SLOTS];
        for (i, slot) in DIAG.iter().enumerate() {
            a[i] = slot.load(Ordering::Relaxed);
        }
        a
    };
    assert!(
        n_allocs == 0,
        "beat allocated {} times on the heap (first sizes: {:?}); fork_recoveries={}",
        n_allocs,
        diag_sizes,
        client.fork_recoveries()
    );
    assert_eq!(
        client.fork_recoveries(),
        0,
        "fork recovery must not fire in a single-process beat loop"
    );

    server.set_nonblocking(true).expect("set nonblocking");
    let mut buf = [0u8; 32];
    let mut count: u64 = 0;
    let mut last = [0u8; 32];
    while let Ok(_n) = server.recv(&mut buf) {
        count += 1;
        last = buf;
    }
    assert!(count > 0, "receiver got zero datagrams");
    let frame = Frame::decode(&last).expect("latest decode");
    assert_eq!(frame.status, Status::Ok);
}