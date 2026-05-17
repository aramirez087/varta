// Live interop: Go agent ↔ real varta-watch observer.
//
// Spawns the built observer binary, drives beats from the Go client,
// scrapes the Prometheus /metrics endpoint, and asserts the observer
// saw the beats. Mirrors the Python suite at
// clients/python/tests/test_interop_observer.py and the spawn pattern
// at crates/varta-tests/tests/end_to_end.rs::spawn_watch.
//
// Skipped unless VARTA_WATCH_BIN points at a built binary (or
// target/release/varta-watch exists relative to the repo root).
package tests

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	varta "github.com/aramirez087/Varta/clients/go"
)

// promTokenHex must match the constant the Python suite uses, which in
// turn matches crates/varta-tests/tests/end_to_end.rs::PROM_TOKEN_HEX.
const promTokenHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type observerProc struct {
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	promURL string
	udsPath string
}

func spawnObserver(t *testing.T, binary, udsPath string) *observerProc {
	t.Helper()

	tokenPath := filepath.Join(filepath.Dir(udsPath), "prom.token")
	if err := os.WriteFile(tokenPath, []byte(promTokenHex), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	args := []string{
		"--socket", udsPath,
		"--threshold-ms", "10000",
		"--prom-addr", "127.0.0.1:0",
		"--prom-token-file", tokenPath,
		"--prom-rate-limit-burst", "0",
		"--shutdown-after-secs", "60",
	}
	cmd := exec.Command(binary, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = nil // suppress observer chatter

	if err := cmd.Start(); err != nil {
		t.Fatalf("start observer: %v", err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	// First stdout line is the bound prometheus address ("host:port").
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("observer did not print bound prometheus address (scanner err: %v)", scanner.Err())
	}
	line := strings.TrimSpace(scanner.Text())
	if line == "" {
		t.Fatal("empty first line from observer stdout")
	}

	// Strip surrounding brackets for IPv6 if present.
	addr := strings.TrimPrefix(strings.TrimSuffix(line, "]"), "[")
	host, port, ok := splitHostPort(addr)
	if !ok {
		t.Fatalf("unparseable prometheus address %q", line)
	}

	// Wait for the UDS socket file to appear so the agent's Connect
	// does not race the observer's bind.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(udsPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(udsPath); err != nil {
		t.Fatalf("observer never created UDS socket: %v", err)
	}

	return &observerProc{
		cmd:     cmd,
		stdout:  stdout,
		promURL: "http://" + host + ":" + strconv.Itoa(port) + "/metrics",
		udsPath: udsPath,
	}
}

func splitHostPort(s string) (string, int, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 || i == len(s)-1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, false
	}
	return s[:i], port, true
}

func scrapeMetrics(t *testing.T, url string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+promTokenHex)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("/metrics returned HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}
	return string(body)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestInteropGoAgentBeatsVisibleInMetrics(t *testing.T) {
	binary := locateWatchBinary(t)
	udsPath := tmpUDSPath(t)
	obs := spawnObserver(t, binary, udsPath)

	agent, err := varta.Connect(udsPath)
	if err != nil {
		t.Fatalf("varta.Connect: %v", err)
	}
	defer agent.Close()

	sent := 0
	for i := 0; i < 50; i++ {
		outcome := agent.Beat(varta.StatusOK, 0)
		switch {
		case outcome.IsSent():
			sent++
		case outcome.IsDropped() && outcome.Reason() == varta.KernelQueueFull:
			time.Sleep(500 * time.Microsecond)
		case outcome.IsDropped():
			t.Fatalf("unexpected drop reason: %s", outcome.Reason())
		default:
			t.Fatalf("unexpected outcome: %s", outcome)
		}
	}

	if sent < 10 {
		t.Fatalf("expected ≥10 successful beats, sent %d", sent)
	}

	// Give the observer one poll-loop iteration to consume the datagrams.
	time.Sleep(500 * time.Millisecond)

	body := scrapeMetrics(t, obs.promURL)
	if body == "" {
		t.Fatal("empty /metrics body")
	}
	if !strings.Contains(body, "varta_") {
		t.Fatalf("no varta_* metric in body: %s", body[:min(400, len(body))])
	}

	anyNonzero := false
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "varta_") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		val, err := strconv.ParseFloat(parts[len(parts)-1], 64)
		if err == nil && val > 0 {
			anyNonzero = true
			break
		}
	}
	if !anyNonzero {
		t.Fatal("no varta_ metric reached non-zero value")
	}
}
