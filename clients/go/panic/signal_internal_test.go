package panic

import (
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aramirez087/Varta/clients/go/internal/vlp"
)

var panicUDSCounter atomic.Uint64

func TestClaimTerminalTimestampIsStrictAcrossClockResetAndCollision(t *testing.T) {
	var last atomic.Uint64

	first, ok := claimTerminalTimestamp(&last, 100)
	if !ok || first != 100 {
		t.Fatalf("first claim = (%d, %v), want (100, true)", first, ok)
	}
	reset, ok := claimTerminalTimestamp(&last, 5)
	if !ok || reset != 101 {
		t.Fatalf("reset claim = (%d, %v), want (101, true)", reset, ok)
	}
	equal, ok := claimTerminalTimestamp(&last, 101)
	if !ok || equal != 102 {
		t.Fatalf("equal claim = (%d, %v), want (102, true)", equal, ok)
	}

	last.Store(math.MaxUint64 - 1)
	if _, ok := claimTerminalTimestamp(&last, 1); ok {
		t.Fatal("exhausted timestamp space must fail closed")
	}

	firstWire, ok := buildCriticalFrame()
	if !ok {
		t.Fatal("first critical frame unexpectedly dropped")
	}
	secondWire, ok := buildCriticalFrame()
	if !ok {
		t.Fatal("second critical frame unexpectedly dropped")
	}
	firstFrame, err := vlp.Decode(firstWire[:])
	if err != nil {
		t.Fatalf("decode first critical frame: %v", err)
	}
	secondFrame, err := vlp.Decode(secondWire[:])
	if err != nil {
		t.Fatalf("decode second critical frame: %v", err)
	}
	if secondFrame.Timestamp <= firstFrame.Timestamp {
		t.Fatalf(
			"critical frame timestamps = %d then %d, want strictly increasing",
			firstFrame.Timestamp,
			secondFrame.Timestamp,
		)
	}
}

// Regression: the secure-UDP panic emitter is shared between the signal
// goroutine and Run's recover path, which can fire concurrently. Every sealed
// frame must use a unique ChaCha20-Poly1305 nonce — the 12-byte wire prefix
// (ivRandom[8] || ivCounterLE[4]). Pre-fix the unsynchronized iv counter let
// two concurrent emits seal under one nonce (keystream + tag reuse). Run under
// `go test -race`, this also flags the underlying data race on the counter/salt
// when the serializing mutex is removed.
func TestSecureEmitterConcurrentEmitUsesUniqueNonces(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	key := make([]byte, 32) // all-zero test key is a valid 32-byte ChaCha key
	if err := InstallSignalHandlerSecureUDP("127.0.0.1", port, key); err != nil {
		t.Fatalf("install: %v", err)
	}
	em := activeEmitter.Load()
	if em == nil {
		t.Fatal("emitter not published")
	}

	const n = 64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			em.emit()
		}()
	}
	wg.Wait()

	// Every 12-byte nonce must be distinct across the n concurrent emits.
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	seen := make(map[[12]byte]bool, n)
	buf := make([]byte, 128)
	for got := 0; got < n; got++ {
		nbytes, _, rerr := pc.ReadFromUDP(buf)
		if rerr != nil {
			t.Fatalf("read %d/%d: %v", got, n, rerr)
		}
		if nbytes < 12 {
			t.Fatalf("short datagram: %d bytes", nbytes)
		}
		var nonce [12]byte
		copy(nonce[:], buf[0:12])
		if seen[nonce] {
			t.Fatalf("NONCE REUSE: %x seen twice across %d concurrent emits", nonce, n)
		}
		seen[nonce] = true
	}
}

// Regression: repeated InstallSignalHandler* calls replaced activeEmitter but
// left the retired socket open. A stale emitter retained inside an in-flight
// goroutine could still write a terminal frame to the old observer, and long
// running processes that reinstalled the hook leaked one descriptor per
// replacement. Replacement now atomically retires the old emitter and closes
// its socket.
func TestRepeatedInstallClosesRetiredUDSEmitter(t *testing.T) {
	if previous := activeEmitter.Swap(nil); previous != nil && previous.close != nil {
		previous.close()
	}
	t.Cleanup(func() {
		if current := activeEmitter.Swap(nil); current != nil && current.close != nil {
			current.close()
		}
	})

	firstPath := shortUnixgramPath(t, "first")
	secondPath := shortUnixgramPath(t, "second")
	firstListener := listenUnixgram(t, firstPath)
	defer firstListener.Close()
	secondListener := listenUnixgram(t, secondPath)
	defer secondListener.Close()

	if err := InstallSignalHandlerUDS(firstPath); err != nil {
		t.Fatalf("first install: %v", err)
	}
	retired := activeEmitter.Load()
	if retired == nil {
		t.Fatal("first emitter not published")
	}

	if err := InstallSignalHandlerUDS(secondPath); err != nil {
		t.Fatalf("second install: %v", err)
	}
	current := activeEmitter.Load()
	if current == nil {
		t.Fatal("second emitter not published")
	}
	if current == retired {
		t.Fatal("second install reused the retired emitter pointer")
	}

	retired.emit()
	assertNoUnixgram(t, firstListener, "retired emitter wrote to first listener")

	current.emit()
	assertCriticalUnixgram(t, secondListener)
}

func listenUnixgram(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	addr, err := net.ResolveUnixAddr("unixgram", path)
	if err != nil {
		t.Fatalf("resolve unixgram %s: %v", path, err)
	}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("listen unixgram %s: %v", path, err)
	}
	return conn
}

func shortUnixgramPath(t *testing.T, name string) string {
	t.Helper()
	count := panicUDSCounter.Add(1)
	path := filepath.Join(
		"/tmp",
		"varta-go-panic-"+strconv.Itoa(os.Getpid())+"-"+strconv.FormatUint(count, 10)+"-"+name+".sock",
	)
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func assertNoUnixgram(t *testing.T, conn *net.UnixConn, msg string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(75 * time.Millisecond))
	var buf [128]byte
	n, _, err := conn.ReadFromUnix(buf[:])
	if err == nil {
		t.Fatalf("%s: received %d bytes", msg, n)
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("read stale listener: got %v, want timeout", err)
	}
}

func assertCriticalUnixgram(t *testing.T, conn *net.UnixConn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var buf [128]byte
	n, _, err := conn.ReadFromUnix(buf[:])
	if err != nil {
		t.Fatalf("read current listener: %v", err)
	}
	frame, err := vlp.Decode(buf[:n])
	if err != nil {
		t.Fatalf("decode current terminal frame: %v", err)
	}
	if frame.Status != vlp.StatusCritical {
		t.Fatalf("status = %d, want critical", frame.Status)
	}
	if frame.Nonce != vlp.NonceTerminal {
		t.Fatalf("nonce = %x, want terminal", frame.Nonce)
	}
}
