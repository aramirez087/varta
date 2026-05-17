package tests

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

var udsCounter uint64

// tmpUDSPath returns a short UDS path under TMPDIR (or /tmp). Avoids
// the macOS 104-char sun_path limit that testing.T.TempDir routinely
// breaches. Mirrors clients/python/tests/conftest.py:tmp_uds_path.
func tmpUDSPath(t *testing.T) string {
	t.Helper()
	base := os.Getenv("TMPDIR")
	if base == "" {
		base = "/tmp"
	}
	dir := filepath.Join(base, formatTag())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "varta.sock")
}

func formatTag() string {
	pid := os.Getpid()
	clock := time.Now().UnixNano() & 0xFFFFFF
	count := atomic.AddUint64(&udsCounter, 1)
	return "varta-go-" + itoa(pid) + "-" + itohex(int(clock)) + "-" + itoa(int(count))
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

func itohex(i int) string {
	const hex = "0123456789abcdef"
	if i == 0 {
		return "0"
	}
	var b [16]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = hex[i&0xf]
		i >>= 4
	}
	return string(b[n:])
}

// bindUDSListener binds a unixgram socket at path that silently drops
// all datagrams (a test double for the observer).
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

// repoRoot walks up from this test file to the workspace root (four
// levels: tests -> go -> clients -> Varta).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// vectorsPath returns the absolute path to tools/vlp-test-vectors.json.
func vectorsPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "tools", "vlp-test-vectors.json")
}

// locateWatchBinary returns the path to a varta-watch binary. Checks
// VARTA_WATCH_BIN env var first, then target/release/varta-watch and
// target/debug/varta-watch under the repo root. Skips the test if no
// binary is found (matches the Python interop test's behaviour).
func locateWatchBinary(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("VARTA_WATCH_BIN"); env != "" {
		return env
	}
	root := repoRoot(t)
	for _, profile := range []string{"release", "debug"} {
		candidate := filepath.Join(root, "target", profile, "varta-watch")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Skip("varta-watch binary not found; build with `cargo build --release -p varta-watch --features prometheus-exporter` or set VARTA_WATCH_BIN")
	return ""
}
