package tests

import (
	"os"
	"testing"

	varta "github.com/aramirez087/Varta/clients/go"
)

// TestForkAutoRecoveryRebuildsTransport asserts that when the agent
// observes a PID change between Connect and Beat, it transparently
// rebuilds the transport and the next beat reaches the observer.
//
// We cannot fork(2) from a Go test cleanly (Go's runtime is not
// fork-safe under normal exec; spawning a child via exec.Command
// re-imports the world). Instead we drive the SetConnectPIDForTest
// hook — same code path the Python client exercises in
// test_client_unit.py.
func TestForkAutoRecoveryRebuildsTransport(t *testing.T) {
	path := tmpUDSPath(t)
	listener := bindUDSListener(t, path)

	agent, err := varta.Connect(path)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	// Sanity: a beat before the simulated fork lands on the listener.
	if !agent.Beat(varta.StatusOK, 0).IsSent() {
		t.Fatal("pre-fork beat did not Send")
	}
	buf := make([]byte, 64)
	if _, _, err := listener.ReadFromUnix(buf); err != nil {
		t.Fatal(err)
	}

	// Simulate fork: bump the snapshot so the next beat sees a PID
	// mismatch.
	agent.SetConnectPIDForTest(os.Getpid() + 1)
	if !agent.Beat(varta.StatusOK, 1).IsSent() {
		t.Fatal("post-fork beat did not Send (reconnect failed?)")
	}
	if _, _, err := listener.ReadFromUnix(buf); err != nil {
		t.Fatalf("post-fork beat did not reach observer: %v", err)
	}
	if agent.ForkRecoveries() != 1 {
		t.Fatalf("ForkRecoveries = %d, want 1", agent.ForkRecoveries())
	}
}
