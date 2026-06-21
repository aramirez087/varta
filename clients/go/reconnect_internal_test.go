package varta

import (
	"errors"
	"syscall"
	"testing"
)

// dropAndFailReconnect always reports a Dropped send and a failing
// Reconnect, so the auto-reconnect threshold logic can be exercised
// deterministically without real sockets.
type dropAndFailReconnect struct {
	reconnects int
}

func (t *dropAndFailReconnect) Send(_ []byte) (int, error) { return 0, syscall.EWOULDBLOCK }

func (t *dropAndFailReconnect) Reconnect() error {
	t.reconnects++
	return errors.New("reconnect refused")
}

func (t *dropAndFailReconnect) Close() error { return nil }

// A failed auto-reconnect must re-arm consecutiveDropped. Once the threshold
// is crossed, the next Dropped beat starts a fresh reconnectAfter window
// instead of retrying reconnect immediately.
func TestFailedReconnectRearmsConsecutiveDropped(t *testing.T) {
	tr := &dropAndFailReconnect{}
	v := newVarta(tr)
	v.SetReconnectAfter(2)

	// First drop: 0 -> 1, below threshold, no reconnect attempted.
	if out := v.Beat(StatusOK, 0); !out.IsDropped() {
		t.Fatalf("beat 1: want Dropped, got %s", out.String())
	}
	if tr.reconnects != 0 {
		t.Fatalf("beat 1: reconnects = %d, want 0", tr.reconnects)
	}

	// Second drop: 1 -> 2 crosses the threshold; reconnect is attempted
	// and fails, but the counter is re-armed before the attempt.
	if out := v.Beat(StatusOK, 0); !out.IsDropped() {
		t.Fatalf("beat 2: want Dropped, got %s", out.String())
	}
	if tr.reconnects != 1 {
		t.Fatalf("beat 2: reconnects = %d, want 1 (threshold crossing must attempt reconnect)", tr.reconnects)
	}
	if v.consecutiveDropped != 0 {
		t.Fatalf("beat 2: consecutiveDropped = %d, want 0 (a failed reconnect must re-arm the counter)", v.consecutiveDropped)
	}

	// Third drop starts a fresh window: no immediate reconnect storm.
	if out := v.Beat(StatusOK, 0); !out.IsDropped() {
		t.Fatalf("beat 3: want Dropped, got %s", out.String())
	}
	if v.consecutiveDropped != 1 {
		t.Fatalf("beat 3: consecutiveDropped = %d, want 1", v.consecutiveDropped)
	}
	if tr.reconnects != 1 {
		t.Fatalf("beat 3: reconnects = %d, want 1 (next drop after a failed reconnect must not retry immediately)", tr.reconnects)
	}

	// Only after another full window should reconnect be attempted again.
	if out := v.Beat(StatusOK, 0); !out.IsDropped() {
		t.Fatalf("beat 4: want Dropped, got %s", out.String())
	}
	if v.consecutiveDropped != 0 {
		t.Fatalf("beat 4: consecutiveDropped = %d, want 0", v.consecutiveDropped)
	}
	if tr.reconnects != 2 {
		t.Fatalf("beat 4: reconnects = %d, want 2", tr.reconnects)
	}
}
