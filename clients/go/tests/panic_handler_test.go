package tests

import (
	"os"
	"syscall"
	"testing"
	"time"

	varta "github.com/aramirez087/Varta/clients/go"
	vpanic "github.com/aramirez087/Varta/clients/go/panic"
)

// TestPanicRunEmitsCriticalThenRePanics asserts that vpanic.Run emits
// a Status=Critical + Nonce=NonceTerminal frame on a Go panic, then
// re-panics so the caller can observe the original panic value.
func TestPanicRunEmitsCriticalThenRePanics(t *testing.T) {
	path := tmpUDSPath(t)
	listener := bindUDSListener(t, path)

	if err := vpanic.InstallSignalHandlerUDS(path); err != nil {
		t.Fatalf("InstallSignalHandlerUDS: %v", err)
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected re-panic from vpanic.Run")
		}
		if got, ok := r.(string); !ok || got != "kaboom" {
			t.Fatalf("unexpected re-panic value: %v", r)
		}

		buf := make([]byte, 128)
		_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := listener.ReadFromUnix(buf)
		if err != nil {
			t.Fatalf("ReadFromUnix: %v", err)
		}
		frame, err := varta.DecodeFrame(buf[:n])
		if err != nil {
			t.Fatalf("decode terminal frame: %v", err)
		}
		if frame.Status != varta.StatusCritical {
			t.Errorf("status = %d, want StatusCritical", frame.Status)
		}
		if frame.Nonce != varta.NonceTerminal {
			t.Errorf("nonce = %x, want NonceTerminal", frame.Nonce)
		}
		if frame.PID != uint32(os.Getpid()) {
			t.Errorf("pid = %d, want %d", frame.PID, os.Getpid())
		}
	}()

	vpanic.Run(func() {
		panic("kaboom")
	})
}

// TestPanicSignalHandlerSocketBindError asserts the install function
// surfaces a typed error when the UDS path is missing.
func TestPanicSignalHandlerSocketBindError(t *testing.T) {
	err := vpanic.InstallSignalHandlerUDS("/tmp/varta-does-not-exist-" + itoa(int(time.Now().UnixNano())) + "/sock")
	if err == nil {
		t.Fatal("expected install error for missing socket path")
	}
	pe, ok := err.(*vpanic.PanicInstallError)
	if !ok {
		t.Fatalf("error type = %T, want *PanicInstallError", err)
	}
	if pe.Kind != "SocketBind" {
		t.Errorf("kind = %q, want SocketBind", pe.Kind)
	}
}

// silence unused-import warning when the kill-signal test is not built.
var _ = syscall.SIGTERM
