// Package panic provides the Varta equivalent of Rust's
// install_panic_handler / Python's install_excepthook_*.
//
// Go has no sys.excepthook. Two mechanisms together cover the same
// surface:
//
//   - InstallSignalHandler{UDS,UDP,SecureUDP} — bind a socket at
//     install time, then watch for SIGTERM / SIGINT / SIGQUIT / SIGHUP
//     on a goroutine. On signal, emit one Status=Critical +
//     Nonce=NonceTerminal frame and re-raise the original signal so
//     the process terminates with its normal disposition.
//
//   - Run(fn) — wrap fn in defer/recover. On any Go-runtime panic
//     (nil deref, slice OOB, divide-by-zero, explicit panic) emit a
//     Critical+NonceTerminal frame on the pre-bound socket, then
//     re-panic so the runtime can print the stack trace and exit.
//
// The Go runtime owns SIGSEGV / SIGABRT / SIGBUS; signal.Notify
// cannot intercept those reliably. Run is the only mechanism that
// covers in-process panics.
package panic
