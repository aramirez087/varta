package varta

import (
	"syscall"
	"testing"
)

// commit-on-success regressions: a Dropped or Failed send must NOT advance the
// committed nonce/timestamp. Mirrors the Rust regressions in
// crates/varta-client/src/client.rs::tests (dropped_beat_does_not_commit_*,
// failed_beat_does_not_commit_*, reconnect_retry_commits_pending_nonce_only_*)
// and the Python test_client_unit.py equivalents.

// alwaysDrop reports a Dropped send on every call; Reconnect succeeds.
type alwaysDrop struct{ sends int }

func (t *alwaysDrop) Send(_ []byte) (int, error) { t.sends++; return 0, syscall.EWOULDBLOCK }
func (t *alwaysDrop) Reconnect() error           { return nil }
func (t *alwaysDrop) Close() error               { return nil }

// alwaysFail reports a Failed send (non-droppable errno) on every call.
type alwaysFail struct{}

func (t *alwaysFail) Send(_ []byte) (int, error) { return 0, syscall.EACCES }
func (t *alwaysFail) Reconnect() error           { return nil }
func (t *alwaysFail) Close() error               { return nil }

// countingDrop drops the first n sends, then succeeds; Reconnect succeeds.
type countingDrop struct {
	remaining int
	sends     int
}

func (t *countingDrop) Send(buf []byte) (int, error) {
	t.sends++
	if t.remaining > 0 {
		t.remaining--
		return 0, syscall.EWOULDBLOCK
	}
	return len(buf), nil
}
func (t *countingDrop) Reconnect() error { return nil }
func (t *countingDrop) Close() error     { return nil }

func TestDroppedBeatDoesNotCommitNonceOrTimestamp(t *testing.T) {
	v := newVarta(&alwaysDrop{})
	if out := v.Beat(StatusOK, 0); !out.IsDropped() {
		t.Fatalf("want Dropped, got %s", out.String())
	}
	if v.nonce != 0 {
		t.Fatalf("dropped beat committed nonce = %d, want 0", v.nonce)
	}
	if v.lastTimestamp != 0 {
		t.Fatalf("dropped beat committed lastTimestamp = %d, want 0", v.lastTimestamp)
	}
	// The next beat reuses the same candidate (still 1), never 2.
	if out := v.Beat(StatusOK, 0); !out.IsDropped() {
		t.Fatalf("beat 2: want Dropped, got %s", out.String())
	}
	if v.nonce != 0 {
		t.Fatalf("second dropped beat committed nonce = %d, want 0", v.nonce)
	}
}

func TestFailedBeatDoesNotCommitNonceOrTimestamp(t *testing.T) {
	v := newVarta(&alwaysFail{})
	if out := v.Beat(StatusOK, 0); !out.IsFailed() {
		t.Fatalf("want Failed, got %s", out.String())
	}
	if v.nonce != 0 || v.lastTimestamp != 0 {
		t.Fatalf("failed beat committed nonce=%d ts=%d, want 0/0", v.nonce, v.lastTimestamp)
	}
}

func TestFirstSuccessfulBeatAfterDropReusesNonceOne(t *testing.T) {
	v := newVarta(&countingDrop{remaining: 1})
	if out := v.Beat(StatusOK, 0); !out.IsDropped() {
		t.Fatalf("beat 1: want Dropped, got %s", out.String())
	}
	if v.nonce != 0 {
		t.Fatalf("dropped beat burned nonce = %d, want 0", v.nonce)
	}
	if out := v.Beat(StatusOK, 0); !out.IsSent() {
		t.Fatalf("beat 2: want Sent, got %s", out.String())
	}
	if v.nonce != 1 {
		t.Fatalf("first accepted frame committed nonce = %d, want 1", v.nonce)
	}
}

func TestReconnectRetryCommitsNonceOnlyOnSuccessfulRetry(t *testing.T) {
	tr := &countingDrop{remaining: 2}
	v := newVarta(tr)
	v.SetReconnectAfter(2)
	if out := v.Beat(StatusOK, 0); !out.IsDropped() {
		t.Fatalf("beat 1: want Dropped, got %s", out.String())
	}
	if v.nonce != 0 {
		t.Fatalf("beat 1 burned nonce = %d, want 0", v.nonce)
	}
	if out := v.Beat(StatusOK, 0); !out.IsSent() {
		t.Fatalf("beat 2: want Sent (reconnect+retry), got %s", out.String())
	}
	if v.nonce != 1 {
		t.Fatalf("retry committed nonce = %d, want 1", v.nonce)
	}
	if tr.sends != 3 {
		t.Fatalf("sends = %d, want 3 (2 drops + 1 retry)", tr.sends)
	}
}

func TestDroppedWrapAttemptDoesNotCommitNonceWrap(t *testing.T) {
	v := newVarta(&alwaysDrop{})
	v.SetNonceForTest(0xFFFFFFFFFFFFFFFE) // NonceTerminal-1: next candidate wraps to 0
	if out := v.Beat(StatusOK, 0); !out.IsDropped() {
		t.Fatalf("want Dropped, got %s", out.String())
	}
	if v.nonce != 0xFFFFFFFFFFFFFFFE {
		t.Fatalf("dropped wrap attempt committed nonce = %d, want NonceTerminal-1", v.nonce)
	}
}
