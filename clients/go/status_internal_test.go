package varta

import "testing"

type countingTransport struct {
	sends      int
	reconnects int
}

func (t *countingTransport) Send(buf []byte) (int, error) {
	t.sends++
	return len(buf), nil
}

func (t *countingTransport) Reconnect() error {
	t.reconnects++
	return nil
}

func (t *countingTransport) Close() error { return nil }

func TestBeatRejectsObserverOnlyStallWithoutSideEffects(t *testing.T) {
	tr := &countingTransport{}
	v := newVarta(tr)
	v.consecutiveDropped = 7

	out := v.Beat(Status(3), 0)
	if !out.IsFailed() {
		t.Fatalf("Beat(Status(3)) = %s, want Failed", out.String())
	}
	if got := out.Err(); got.Errno != 0 || got.Kind != "InvalidInput" {
		t.Fatalf("Beat(Status(3)) error = %#v, want errno=0 kind=InvalidInput", got)
	}
	if tr.sends != 0 {
		t.Fatalf("sends = %d, want 0", tr.sends)
	}
	if tr.reconnects != 0 {
		t.Fatalf("reconnects = %d, want 0", tr.reconnects)
	}
	if v.nonce != 0 {
		t.Fatalf("nonce = %d, want 0", v.nonce)
	}
	if v.consecutiveDropped != 0 {
		t.Fatalf("consecutiveDropped = %d, want 0", v.consecutiveDropped)
	}
}
