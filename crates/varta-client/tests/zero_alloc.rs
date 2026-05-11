//! Session 02 zero-allocation guard for `Varta::beat`.
//!
//! A `#[global_allocator]` wraps the system allocator with an "armed" flag.
//! Once armed, every allocation increments an atomic counter. The contract
//! test connects, arms the guard, beats 10 000 times, disarms, then asserts
//! the counter stayed at zero — proving the beat path never touches the heap.
//!
//! See `docs/acceptance/varta-v0-1-0.md` §S02
//! `beat_makes_zero_heap_allocations_after_init`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use varta_client::{Frame, Status, Varta};

struct GuardAlloc;

static ARMED: AtomicBool = AtomicBool::new(false);
/// Incremented on every allocation while armed. Read after disarm to prove
/// zero allocations. NOT using a panic inside the allocator because the panic
/// machinery itself allocates, causing a double-panic abort that obscures the
/// real failure reason.
static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for GuardAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GUARD: GuardAlloc = GuardAlloc;

struct TempSocket {
    path: PathBuf,
}

impl TempSocket {
    fn new(tag: &str) -> Self {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("varta-{tag}-{pid}-{nanos}-{n}.sock"));
        let _ = std::fs::remove_file(&path);
        TempSocket { path }
    }
}

impl Drop for TempSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn beat_makes_zero_heap_allocations_after_init() {
    let temp = TempSocket::new("zeroalloc");
    let server = UnixDatagram::bind(&temp.path).expect("bind server");
    let mut client = Varta::connect(&temp.path).expect("connect");

    ARMED.store(true, Ordering::Relaxed);
    for _ in 0..10_000 {
        let _ = client.beat(Status::Ok, 0);
    }
    ARMED.store(false, Ordering::Relaxed);

    let n_allocs = ALLOC_COUNT.load(Ordering::Relaxed);
    assert!(
        n_allocs == 0,
        "beat allocated {} times on the heap",
        n_allocs
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
    assert_eq!(frame.status, Status::Ok as u8);
}
