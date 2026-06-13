package panic

import (
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aramirez087/Varta/clients/go/internal/vlp"
)

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
