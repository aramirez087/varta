/// Install SIGINT / SIGTERM handlers on exotic Unix targets whose
/// `sigaction(2)` struct layout is unknown (NetBSD, OpenBSD, illumos, etc.)
/// via the POSIX `signal(2)` API.
///
/// On SysV systems `signal(2)` may reset the handler to `SIG_DFL` after
/// delivery, but the shutdown latch stays set after the first signal — a
/// repeated signal becomes a `SIG_DFL` termination, which is acceptable
/// during the daemon shutdown sequence.
use std::io;

extern "C" {
    // Declared as `*const ()` so we can compare against `SIG_ERR = -1isize`
    // as a raw pointer value without a function-pointer-to-integer cast.
    fn signal(signum: i32, handler: *const ()) -> *const ();
}

pub(super) unsafe fn install(handler: extern "C" fn(i32)) -> io::Result<()> {
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    // `SIG_ERR` is defined as `(void(*)(int))-1` in C99 §7.14.1.1 and POSIX.
    // The all-ones pointer value is portable across exotic-Unix targets.
    let sig_err: *const () = (-1isize) as usize as *const ();

    let prev = unsafe { signal(SIGINT, handler as *const ()) };
    if prev == sig_err {
        return Err(io::Error::last_os_error());
    }
    let prev = unsafe { signal(SIGTERM, handler as *const ()) };
    if prev == sig_err {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
