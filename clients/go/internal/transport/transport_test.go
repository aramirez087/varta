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
