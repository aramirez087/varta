package varta

import (
	"os"
	"testing"
)

type countingTransport struct {
	sends      int
	reconnects int
	closes     int
}

func (t *countingTransport) Send(buf []byte) (int, error) {
	t.sends++
	return len(buf), nil
}

func (t *countingTransport) Reconnect() error {
	t.reconnects++
	return nil
}

func (t *countingTransport) Close() error {
	t.closes++
	return nil
}

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

func TestBeatAfterCloseFailsClosedWithoutTransportSideEffects(t *testing.T) {
	tr := &countingTransport{}
	v := newVarta(tr)
	v.SetReconnectAfter(1)
	v.SetConnectPIDForTest(os.Getpid() + 1)
	v.consecutiveDropped = 7

	if err := v.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err := v.Reconnect(); err == nil {
		t.Fatal("Reconnect() after Close() succeeded, want error")
	}

	out := v.Beat(StatusOK, 0)
	if !out.IsFailed() {
		t.Fatalf("Beat() after Close() = %s, want Failed", out.String())
	}
	if got := out.Err(); got.Errno != 0 || got.Kind != "Closed" {
		t.Fatalf("Beat() after Close() error = %#v, want errno=0 kind=Closed", got)
	}
	if tr.sends != 0 {
		t.Fatalf("sends = %d, want 0", tr.sends)
	}
	if tr.reconnects != 0 {
		t.Fatalf("reconnects = %d, want 0", tr.reconnects)
	}
	if tr.closes != 1 {
		t.Fatalf("closes = %d, want 1", tr.closes)
	}
	if v.nonce != 0 {
		t.Fatalf("nonce = %d, want 0", v.nonce)
	}
	if v.consecutiveDropped != 0 {
		t.Fatalf("consecutiveDropped = %d, want 0", v.consecutiveDropped)
	}
}
