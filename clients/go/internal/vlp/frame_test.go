package vlp

import (
	"encoding/binary"
	"testing"
)

func TestUnitCRC32CGolden(t *testing.T) {
	cases := []struct {
		input []byte
		want  uint32
	}{
		{[]byte{}, 0x00000000},
		{[]byte("a"), 0xc1d04330},
		{[]byte("123456789"), 0xe3069283},
	}
	for _, c := range cases {
		got := CRC32C(c.input)
		if got != c.want {
			t.Fatalf("CRC32C(%q) = %08x, want %08x", c.input, got, c.want)
		}
	}
}

func TestUnitFrameRoundTrip(t *testing.T) {
	wire := Encode(StatusOk, 4242, 1_000_000, 1, 0xDEADBEEF)
	frame, err := Decode(wire[:])
	if err != nil {
		t.Fatalf("Decode err: %v", err)
	}
	if frame.Status != StatusOk || frame.PID != 4242 || frame.Timestamp != 1_000_000 || frame.Nonce != 1 || frame.Payload != 0xDEADBEEF {
		t.Fatalf("decoded fields differ: %+v", frame)
	}
}

func TestUnitDecodeErrors(t *testing.T) {
	good := Encode(StatusOk, 100, 1, 1, 0)
	mut := func(mod func(*[FrameBytes]byte)) []byte {
		out := good
		mod(&out)
		// Recompute CRC for cases that change body bytes but want a
		// non-CRC error to fire first. Callers opt out by passing a
		// mutator that touches buf[28:32] directly.
		return out[:]
	}

	t.Run("BadMagic", func(t *testing.T) {
		w := mut(func(b *[FrameBytes]byte) { b[0] = 0xFF })
		if _, err := Decode(w); err == nil || err.(*DecodeError).Kind != "BadMagic" {
			t.Fatalf("expected BadMagic, got %v", err)
		}
	})
	t.Run("BadVersion", func(t *testing.T) {
		w := mut(func(b *[FrameBytes]byte) { b[2] = 0x99 })
		if _, err := Decode(w); err == nil || err.(*DecodeError).Kind != "BadVersion" {
			t.Fatalf("expected BadVersion, got %v", err)
		}
	})
	t.Run("BadCrc", func(t *testing.T) {
		w := mut(func(b *[FrameBytes]byte) { binary.LittleEndian.PutUint32(b[28:32], 0xDEADBEEF) })
		if _, err := Decode(w); err == nil || err.(*DecodeError).Kind != "BadCrc" {
			t.Fatalf("expected BadCrc, got %v", err)
		}
	})
	t.Run("BadStatus", func(t *testing.T) {
		w := good
		w[3] = 0x09
		binary.LittleEndian.PutUint32(w[28:32], CRC32C(w[0:28]))
		if _, err := Decode(w[:]); err == nil || err.(*DecodeError).Kind != "BadStatus" {
			t.Fatalf("expected BadStatus, got %v", err)
		}
	})
	t.Run("StallOnWire", func(t *testing.T) {
		w := good
		w[3] = byte(StatusStall)
		binary.LittleEndian.PutUint32(w[28:32], CRC32C(w[0:28]))
		if _, err := Decode(w[:]); err == nil || err.(*DecodeError).Kind != "StallOnWire" {
			t.Fatalf("expected StallOnWire, got %v", err)
		}
	})
	t.Run("BadPidZero", func(t *testing.T) {
		w := good
		binary.LittleEndian.PutUint32(w[4:8], 0)
		binary.LittleEndian.PutUint32(w[28:32], CRC32C(w[0:28]))
		if _, err := Decode(w[:]); err == nil || err.(*DecodeError).Kind != "BadPid" {
			t.Fatalf("expected BadPid, got %v", err)
		}
	})
	t.Run("BadPidOne", func(t *testing.T) {
		w := good
		binary.LittleEndian.PutUint32(w[4:8], 1)
		binary.LittleEndian.PutUint32(w[28:32], CRC32C(w[0:28]))
		if _, err := Decode(w[:]); err == nil || err.(*DecodeError).Kind != "BadPid" {
			t.Fatalf("expected BadPid, got %v", err)
		}
	})
	t.Run("BadTimestamp", func(t *testing.T) {
		w := good
		binary.LittleEndian.PutUint64(w[8:16], 0xFFFFFFFFFFFFFFFF)
		binary.LittleEndian.PutUint32(w[28:32], CRC32C(w[0:28]))
		if _, err := Decode(w[:]); err == nil || err.(*DecodeError).Kind != "BadTimestamp" {
			t.Fatalf("expected BadTimestamp, got %v", err)
		}
	})
	t.Run("BadNonce", func(t *testing.T) {
		w := good
		binary.LittleEndian.PutUint64(w[16:24], NonceTerminal)
		binary.LittleEndian.PutUint32(w[28:32], CRC32C(w[0:28]))
		if _, err := Decode(w[:]); err == nil || err.(*DecodeError).Kind != "BadNonce" {
			t.Fatalf("expected BadNonce, got %v", err)
		}
	})
	t.Run("NonceTerminalAllowedWithCritical", func(t *testing.T) {
		w := Encode(StatusCritical, 100, 1, NonceTerminal, 0)
		frame, err := Decode(w[:])
		if err != nil {
			t.Fatalf("expected ok, got %v", err)
		}
		if frame.Nonce != NonceTerminal || frame.Status != StatusCritical {
			t.Fatalf("unexpected frame %+v", frame)
		}
	})
}

func TestUnitStatusFromName(t *testing.T) {
	cases := map[string]Status{"ok": StatusOk, "degraded": StatusDegraded, "critical": StatusCritical, "stall": StatusStall}
	for name, want := range cases {
		got, err := StatusFromName(name)
		if err != nil || got != want {
			t.Fatalf("StatusFromName(%q) = %d,%v; want %d", name, got, err, want)
		}
	}
	if _, err := StatusFromName("bogus"); err == nil {
		t.Fatalf("expected error for bogus status")
	}
}
