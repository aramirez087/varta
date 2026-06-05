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

// A failed auto-reconnect must NOT disarm consecutiveDropped. Once the
// threshold is crossed, every subsequent Dropped beat retries the
// reconnect immediately rather than re-arming a full reconnectAfter-beat
// window. Mirrors the Rust regression
// failed_reconnect_preserves_consecutive_dropped_for_immediate_retry and
// the frozen cross-client contract (reset only on a successful reconnect).
func TestFailedReconnectPreservesConsecutiveDropped(t *testing.T) {
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
	// and FAILS, so the counter must stay saturated at 2.
	if out := v.Beat(StatusOK, 0); !out.IsDropped() {
		t.Fatalf("beat 2: want Dropped, got %s", out.String())
	}
	if tr.reconnects != 1 {
		t.Fatalf("beat 2: reconnects = %d, want 1 (threshold crossing must attempt reconnect)", tr.reconnects)
	}
	if v.consecutiveDropped != 2 {
		t.Fatalf("beat 2: consecutiveDropped = %d, want 2 (a failed reconnect must not disarm the counter)", v.consecutiveDropped)
	}

	// Third drop: threshold still crossed, so reconnect is retried on the
	// very next beat — not after another full window.
	if out := v.Beat(StatusOK, 0); !out.IsDropped() {
		t.Fatalf("beat 3: want Dropped, got %s", out.String())
	}
	if tr.reconnects != 2 {
		t.Fatalf("beat 3: reconnects = %d, want 2 (next drop after a failed reconnect must retry immediately)", tr.reconnects)
	}
}
