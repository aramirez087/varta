package panic

import (
	"net"
	"sync"
	"testing"
	"time"
)

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
