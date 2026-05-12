use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// RAII socket-path holder. `Drop` unlinks the file (best-effort).
pub struct TempSocket {
    pub path: PathBuf,
}

impl TempSocket {
    pub fn new(tag: &str) -> Self {
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
