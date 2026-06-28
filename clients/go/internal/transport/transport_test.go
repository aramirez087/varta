package transport

import (
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

var udsCounter uint64

func tmpUDSPath(t *testing.T) string {
	t.Helper()
	base := os.Getenv("TMPDIR")
	if base == "" {
		base = "/tmp"
	}
	dir := filepath.Join(base, "varta-tt-"+itoa(int(atomic.AddUint64(&udsCounter, 1)))+"-"+itoa(int(time.Now().UnixNano()&0xFFFFFF)))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "varta.sock")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}

func bindUDSListener(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	addr, err := net.ResolveUnixAddr("unixgram", path)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = os.Remove(path)
	})
	return conn
}

func TestUnitUDSSendReceive(t *testing.T) {
	path := tmpUDSPath(t)
	listener := bindUDSListener(t, path)
	transport, err := NewUDS(path)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	payload := []byte("0123456789abcdefghijklmnopqrstuv") // 32 bytes
	n, err := transport.Send(payload)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if n != 32 {
		t.Fatalf("Send n=%d want 32", n)
	}

	buf := make([]byte, 64)
	_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
	rn, _, err := listener.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("ReadFromUnix: %v", err)
	}
	if rn != 32 || string(buf[:rn]) != string(payload) {
		t.Fatalf("unexpected payload (n=%d): %q", rn, buf[:rn])
	}
}

func TestUnitUDSReconnectRebuildsSocket(t *testing.T) {
	path := tmpUDSPath(t)
	_ = bindUDSListener(t, path)

	transport, err := NewUDS(path)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	if err := transport.Reconnect(); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if _, err := transport.Send(make([]byte, 32)); err != nil {
		t.Fatalf("Send after Reconnect: %v", err)
	}
}

func TestUnitUDSFailedReconnectPreservesSocket(t *testing.T) {
	path := tmpUDSPath(t)
	listener := bindUDSListener(t, path)
	transport, err := NewUDS(path)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	oldConn := transport.conn
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	if err := transport.Reconnect(); err == nil {
		t.Fatal("Reconnect succeeded after the observer path was removed")
	}
	if transport.conn != oldConn {
		t.Fatal("failed Reconnect replaced or cleared the live connection")
	}
	if err := oldConn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("failed Reconnect closed the live connection: %v", err)
	}
}

func TestUnitUDPFailedReconnectPreservesSocket(t *testing.T) {
	transport, err := NewUDP("127.0.0.1", 9)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	oldConn := transport.conn
	transport.host = "["
	if err := transport.Reconnect(); err == nil {
		t.Fatal("Reconnect succeeded with an invalid host")
	}
	if transport.conn != oldConn {
		t.Fatal("failed Reconnect replaced or cleared the live connection")
	}
	if err := oldConn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("failed Reconnect closed the live connection: %v", err)
	}
}

func TestUnitSecureUDPFailedReconnectPreservesSession(t *testing.T) {
	transport, err := NewSecureUDPShared("127.0.0.1", 9, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	transport.SetCounterForTest(17)
	oldConn := transport.conn
	oldSalt := transport.sessionSalt
	oldPrefix := transport.ivPrefix
	oldPrefixIndex := transport.prefixIndex
	oldCounter := transport.counter

	transport.host = "["
	if err := transport.Reconnect(); err == nil {
		t.Fatal("Reconnect succeeded with an invalid host")
	}
	if transport.conn != oldConn {
		t.Fatal("failed Reconnect replaced or cleared the live connection")
	}
	if err := oldConn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("failed Reconnect closed the live connection: %v", err)
	}
	if transport.sessionSalt != oldSalt ||
		transport.ivPrefix != oldPrefix ||
		transport.prefixIndex != oldPrefixIndex ||
		transport.counter != oldCounter {
		t.Fatal("failed Reconnect partially replaced secure session state")
	}
}

func TestUnitSecureUDPFailedSendAtWrapDoesNotRotatePrefix(t *testing.T) {
	// Regression: a Dropped send at the nonce-wrap boundary must NOT rotate the
	// IV prefix or reset the counter. Prefix index, IV prefix, and counter may
	// only advance after a successful Write (commit-on-success); otherwise a
	// failed send burns a prefix index off the wire and runs HKDF on the hot
	// path, violating the cross-client invariant (cf. Rust NonceAdvance, Java
	// bug-478). The prior code called rotatePrefix() eagerly before the Write.
	transport, err := NewSecureUDPShared("127.0.0.1", 9, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	// Park the counter at the wrap boundary and snapshot the pre-send state.
	transport.SetCounterForTest(aeadCounterLimit)
	oldPrefixIndex := transport.prefixIndex
	oldCounter := transport.counter
	oldPrefix := transport.ivPrefix

	// Force the Write to fail deterministically by closing the socket first.
	if err := transport.conn.Close(); err != nil {
		t.Fatalf("closing the conn to force a Write failure: %v", err)
	}

	if _, err := transport.Send(make([]byte, 32)); err == nil {
		t.Fatal("Send on a closed socket must fail")
	}

	if transport.prefixIndex != oldPrefixIndex {
		t.Fatalf("failed wrap-boundary send rotated prefixIndex: got %d, want %d (commit-on-success violated)",
			transport.prefixIndex, oldPrefixIndex)
	}
	if transport.counter != oldCounter {
		t.Fatalf("failed wrap-boundary send advanced counter: got %d, want %d",
			transport.counter, oldCounter)
	}
	if transport.ivPrefix != oldPrefix {
		t.Fatal("failed wrap-boundary send re-derived the IV prefix")
	}
}

func TestUnitSecureUDPDoubleExhaustionReconnectsBeforeNonceReuse(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := listener.LocalAddr().(*net.UDPAddr).Port
	transport, err := NewSecureUDPShared("127.0.0.1", port, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	initialPrefix := transport.ivPrefix
	transport.SetPrefixIndexForTest(aeadCounterLimit)
	transport.SetCounterForTest(aeadCounterLimit)

	if _, err := transport.Send(make([]byte, 32)); err != nil {
		t.Fatalf("Send at double exhaustion: %v", err)
	}
	if got := transport.PrefixIndexForTest(); got != 0 {
		t.Fatalf("double exhaustion should reconnect to prefix index 0, got %d", got)
	}
	if got := transport.CounterForTest(); got != 1 {
		t.Fatalf("first send after reconnect should commit counter 0 -> 1, got %d", got)
	}
	if transport.ivPrefix == initialPrefix {
		t.Fatal("double exhaustion wrapped to the original session prefix instead of reconnecting")
	}
}

func TestUnitSecureUDPDoubleExhaustionFailedReconnectPreservesState(t *testing.T) {
	transport, err := NewSecureUDPShared("127.0.0.1", 9, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	transport.SetPrefixIndexForTest(aeadCounterLimit)
	transport.SetCounterForTest(aeadCounterLimit)
	oldConn := transport.conn
	oldSalt := transport.sessionSalt
	oldPrefix := transport.ivPrefix
	oldPrefixIndex := transport.prefixIndex
	oldCounter := transport.counter

	transport.host = "["
	if _, err := transport.Send(make([]byte, 32)); err == nil {
		t.Fatal("Send at double exhaustion unexpectedly succeeded after failed reconnect")
	}
	if transport.conn != oldConn ||
		transport.sessionSalt != oldSalt ||
		transport.ivPrefix != oldPrefix ||
		transport.prefixIndex != oldPrefixIndex ||
		transport.counter != oldCounter {
		t.Fatal("failed double-exhaustion reconnect partially replaced secure session state")
	}
}
