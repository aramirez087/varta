package vlpsecure

import (
	"bytes"
	"testing"
)

func TestUnitSharedRoundTrip(t *testing.T) {
	var key [KeyBytes]byte
	for i := range key {
		key[i] = byte(i)
	}
	var iv [IVRandomBytes]byte
	for i := range iv {
		iv[i] = byte(0xA0 + i)
	}
	var pt [32]byte
	for i := range pt {
		pt[i] = byte(i ^ 0x5A)
	}
	wire, err := EncodeShared(key, iv, 7, pt)
	if err != nil {
		t.Fatalf("EncodeShared: %v", err)
	}
	got, err := DecodeShared(key, wire[:])
	if err != nil {
		t.Fatalf("DecodeShared: %v", err)
	}
	if !bytes.Equal(got[:], pt[:]) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestUnitMasterRoundTrip(t *testing.T) {
	var master [KeyBytes]byte
	for i := range master {
		master[i] = byte(0xC0 + i)
	}
	var iv [IVRandomBytes]byte
	for i := range iv {
		iv[i] = byte(0x10 + i)
	}
	var pt [32]byte
	for i := range pt {
		pt[i] = byte(i)
	}
	const pid uint32 = 4242
	wire, _, err := EncodeMaster(master, pid, iv, 3, pt)
	if err != nil {
		t.Fatalf("EncodeMaster: %v", err)
	}
	got, err := DecodeMaster(master, wire[:])
	if err != nil {
		t.Fatalf("DecodeMaster: %v", err)
	}
	if !bytes.Equal(got[:], pt[:]) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestUnitMasterTamperedAADFails(t *testing.T) {
	var master [KeyBytes]byte
	var iv [IVRandomBytes]byte
	var pt [32]byte
	wire, _, err := EncodeMaster(master, 100, iv, 1, pt)
	if err != nil {
		t.Fatalf("EncodeMaster: %v", err)
	}
	// Flip the AAD/PID prefix; AEAD must fail to open.
	wire[0] ^= 0xFF
	if _, err := DecodeMaster(master, wire[:]); err == nil {
		t.Fatalf("expected AEAD failure on tampered AAD")
	}
}

func TestUnitKDFDeterminism(t *testing.T) {
	var master [KeyBytes]byte
	for i := range master {
		master[i] = byte(i)
	}
	a := DeriveAgentKey(master, 99)
	b := DeriveAgentKey(master, 99)
	if a != b {
		t.Fatalf("DeriveAgentKey not deterministic")
	}
	c := DeriveAgentKey(master, 100)
	if a == c {
		t.Fatalf("different agent IDs produced identical keys")
	}
}
