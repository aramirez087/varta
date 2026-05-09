package tests

import (
	"os"
	"testing"

	varta "github.com/aramirez087/Varta/clients/go"
	"github.com/aramirez087/Varta/clients/go/internal/vlp"
)

func TestUnitBeatSendsValidFrame(t *testing.T) {
	path := tmpUDSPath(t)
	listener := bindUDSListener(t, path)

	agent, err := varta.Connect(path)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	outcome := agent.Beat(varta.StatusOK, 0xDEADBEEF)
	if !outcome.IsSent() {
		t.Fatalf("expected Sent, got %s", outcome.String())
	}

	buf := make([]byte, 64)
	n, _, err := listener.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("ReadFromUnix: %v", err)
	}
	if n != vlp.FrameBytes {
		t.Fatalf("frame length %d != %d", n, vlp.FrameBytes)
	}
	frame, err := varta.DecodeFrame(buf[:n])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if frame.Status != varta.StatusOK || frame.PID != uint32(os.Getpid()) || frame.Payload != 0xDEADBEEF {
		t.Fatalf("unexpected frame: %+v", frame)
	}
}

func TestUnitConnectMissingObserver(t *testing.T) {
	// Pick a UDS path with no listener bound.
	path := tmpUDSPath(t)
	if _, err := varta.Connect(path); err == nil {
		t.Fatal("expected Connect to fail when no observer is bound")
	}
}

func TestUnitDroppedWhenObserverGone(t *testing.T) {
	path := tmpUDSPath(t)
	listener := bindUDSListener(t, path)

	agent, err := varta.Connect(path)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	// Tear down the listener so the next send hits NoObserver / PeerGone.
	_ = listener.Close()
	_ = os.Remove(path)

	outcome := agent.Beat(varta.StatusOK, 0)
	if outcome.IsSent() {
		t.Fatal("expected non-Sent outcome after observer torn down")
	}
	if !outcome.IsDropped() && !outcome.IsFailed() {
		t.Fatalf("unexpected outcome: %s", outcome.String())
	}
}

func TestUnitForkRecoveryIncrementsCounter(t *testing.T) {
	path := tmpUDSPath(t)
	_ = bindUDSListener(t, path)

	agent, err := varta.Connect(path)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if agent.ForkRecoveries() != 0 {
		t.Fatalf("initial ForkRecoveries = %d, want 0", agent.ForkRecoveries())
	}

	// Simulate a fork by overriding the connect-time PID snapshot.
	agent.SetConnectPIDForTest(os.Getpid() + 100_000_000)

	outcome := agent.Beat(varta.StatusOK, 0)
	if !outcome.IsSent() {
		t.Fatalf("Beat after simulated fork: %s", outcome.String())
	}
	if agent.ForkRecoveries() != 1 {
		t.Fatalf("ForkRecoveries = %d, want 1", agent.ForkRecoveries())
	}
}

func TestUnitDropReasonStringMatchesWireLabel(t *testing.T) {
	cases := map[varta.DropReason]string{
		varta.KernelQueueFull: "kernel queue full",
		varta.NoObserver:      "no observer",
		varta.PeerGone:        "peer gone",
		varta.StorageFull:     "storage full",
	}
	for r, want := range cases {
		if r.String() != want {
			t.Errorf("%d.String() = %q, want %q", r, r.String(), want)
		}
	}
}
