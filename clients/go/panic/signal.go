package panic

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aramirez087/Varta/clients/go/internal/vlp"
	"github.com/aramirez087/Varta/clients/go/internal/vlpsecure"
)

// PanicInstallError is the base error returned by every Install
// function on failure.
type PanicInstallError struct {
	Kind string
	Err  error
}

func (e *PanicInstallError) Error() string {
	if e.Err == nil {
		return "varta/panic: " + e.Kind
	}
	return "varta/panic: " + e.Kind + ": " + e.Err.Error()
}
func (e *PanicInstallError) Unwrap() error { return e.Err }

// emitter is the shared closure between the signal goroutine and the
// Run defer/recover wrapper — both write a Critical+NonceTerminal
// frame to a socket that was bound at install time.
type emitter struct {
	emit func()
	desc string
}

// activeEmitter is the most-recently-installed emitter. The Run
// wrapper reads from this on a panic so a single Install* call covers
// both signal-driven and panic-driven termination.
var activeEmitter atomic.Pointer[emitter]

// installSerial guards against concurrent Install* calls clobbering
// each other's signal handlers.
var installSerial sync.Mutex

// installed tracks whether a signal handler is already wired so a
// second Install* call replaces rather than duplicates the handler.
var installed atomic.Bool

func buildCriticalFrame() [vlp.FrameBytes]byte {
	var out [vlp.FrameBytes]byte
	ts := uint64(time.Now().UnixNano())
	// Reject the timestamp sentinel; in practice clamp to MaxUint64-1.
	if ts == 0xFFFFFFFFFFFFFFFF {
		ts = 0xFFFFFFFFFFFFFFFE
	}
	vlp.EncodeInto(&out, vlp.StatusCritical, uint32(os.Getpid()), ts, vlp.NonceTerminal, 0)
	return out
}

// installSignals wires the signal goroutine after the emitter has
// been published. On first signal, emit + re-raise.
func installSignals() {
	installSerial.Lock()
	defer installSerial.Unlock()
	if installed.Load() {
		return
	}
	installed.Store(true)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP)
	go func() {
		sig := <-ch
		if e := activeEmitter.Load(); e != nil {
			e.emit()
		}
		// Re-raise the signal with its default disposition so the
		// process terminates normally.
		signal.Reset(sig)
		_ = syscall.Kill(os.Getpid(), sig.(syscall.Signal))
	}()
}

func dialUDS(path string) (net.Conn, error) {
	addr, err := net.ResolveUnixAddr("unixgram", path)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return nil, err
	}
	if err := setNonblockConn(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func dialUDP(host string, port int) (net.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	if err := setNonblockConn(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func setNonblockConn(conn interface{ SyscallConn() (syscall.RawConn, error) }) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	err = raw.Control(func(fd uintptr) {
		inner = syscall.SetNonblock(int(fd), true)
	})
	if err != nil {
		return err
	}
	return inner
}

// InstallSignalHandlerUDS installs a terminating-signal handler that
// emits a Status=Critical + Nonce=NonceTerminal frame to the UDS at
// path before the process exits. Binds the socket at install time so
// the goroutine itself does only Write + signal.Reset + Kill.
func InstallSignalHandlerUDS(path string) error {
	conn, err := dialUDS(path)
	if err != nil {
		return &PanicInstallError{Kind: "SocketBind", Err: err}
	}
	em := &emitter{
		emit: func() {
			frame := buildCriticalFrame()
			_, _ = conn.Write(frame[:])
		},
		desc: "uds:" + path,
	}
	activeEmitter.Store(em)
	installSignals()
	return nil
}

// InstallSignalHandlerUDP installs the same handler over plaintext UDP.
func InstallSignalHandlerUDP(host string, port int) error {
	conn, err := dialUDP(host, port)
	if err != nil {
		return &PanicInstallError{Kind: "SocketBind", Err: err}
	}
	em := &emitter{
		emit: func() {
			frame := buildCriticalFrame()
			_, _ = conn.Write(frame[:])
		},
		desc: fmt.Sprintf("udp:%s:%d", host, port),
	}
	activeEmitter.Store(em)
	installSignals()
	return nil
}

// InstallSignalHandlerSecureUDP installs the handler over secure UDP
// with a pre-shared 32-byte key. Reads 16 bytes from crypto/rand at
// install time (fail-closed; returns EntropyUnavailable if the read
// fails) and snapshots the install-time PID; if the emit closure
// observes a different PID at signal time, it re-reads entropy before
// re-deriving the IV prefix.
func InstallSignalHandlerSecureUDP(host string, port int, key []byte) error {
	if len(key) != vlpsecure.KeyBytes {
		return &PanicInstallError{Kind: "BadKey", Err: errors.New("key must be 32 bytes")}
	}
	var saltArr [16]byte
	if _, err := rand.Read(saltArr[:]); err != nil {
		return &PanicInstallError{Kind: "EntropyUnavailable", Err: err}
	}
	conn, err := dialUDP(host, port)
	if err != nil {
		return &PanicInstallError{Kind: "SocketBind", Err: err}
	}

	var keyArr [vlpsecure.KeyBytes]byte
	copy(keyArr[:], key)

	state := &secureState{
		salt:    saltArr,
		pid:     os.Getpid(),
		counter: 0,
	}
	em := &emitter{
		emit: func() {
			pid := os.Getpid()
			if pid != state.pid {
				if _, rerr := rand.Read(state.salt[:]); rerr != nil {
					return
				}
				state.pid = pid
				state.counter = 0
			}
			ivPrefix := vlpsecure.DeriveIVPrefix(state.salt, 0)
			plain := buildCriticalFrame()
			wire, sealErr := vlpsecure.EncodeShared(keyArr, ivPrefix, state.counter, plain)
			if sealErr != nil {
				return
			}
			state.counter++
			_, _ = conn.Write(wire[:])
		},
		desc: fmt.Sprintf("secure-udp:%s:%d", host, port),
	}
	activeEmitter.Store(em)
	installSignals()
	return nil
}

// secureState holds the mutable IV state for the secure-UDP emitter.
type secureState struct {
	salt    [16]byte
	pid     int
	counter uint32
}
