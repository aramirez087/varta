package panic

// Run wraps fn in a deferred recover. If fn panics — for any reason,
// including runtime errors like nil deref or slice OOB — the
// deferred emitter writes one Status=Critical + Nonce=NonceTerminal
// frame to the most-recently-installed socket, then re-panics so the
// Go runtime prints the stack trace and exits with its normal panic
// disposition.
//
// Install one of InstallSignalHandler{UDS,UDP,SecureUDP} before
// calling Run, otherwise the panic propagates without emitting a
// terminal frame (Run becomes a passthrough).
func Run(fn func()) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if e := activeEmitter.Load(); e != nil {
			e.emit()
		}
		panic(r)
	}()
	fn()
}
