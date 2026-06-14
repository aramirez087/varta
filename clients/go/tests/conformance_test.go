// Conformance: every entry in tools/vlp-test-vectors.json must
// round-trip through the Go client. The same JSON file is consumed by
// the Rust crate and the Python client; wire-format drift between
// languages is impossible without failing three test suites in lockstep.
package tests

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/aramirez087/Varta/clients/go/internal/vlp"
	"github.com/aramirez087/Varta/clients/go/internal/vlpsecure"
)

type vectorDoc struct {
	SpecVersion        string              `json:"spec_version"`
	CRC32CVectors      []crcVector         `json:"crc32c_vectors"`
	FrameVectors       []frameVector       `json:"frame_vectors"`
	SecureFrameVectors []secureFrameVector `json:"secure_frame_vectors"`
}

type crcVector struct {
	ID             string `json:"id"`
	InputHex       string `json:"input_hex"`
	ExpectedCRCHex string `json:"expected_crc_hex"`
}

type frameInputs struct {
	Status    string `json:"status"`
	PID       uint32 `json:"pid"`
	Timestamp uint64 `json:"timestamp"`
	Nonce     uint64 `json:"nonce"`
	Payload   uint32 `json:"payload"`
}

type frameVector struct {
	ID                  string       `json:"id"`
	Kind                string       `json:"kind"`
	Inputs              *frameInputs `json:"inputs,omitempty"`
	ExpectedWireHex     string       `json:"expected_wire_hex"`
	WireHex             string       `json:"wire_hex"`
	ExpectedDecodeError *string      `json:"expected_decode_error"`
}

type secureFrameVector struct {
	ID                  string `json:"id"`
	Kind                string `json:"kind"`
	KeyHex              string `json:"key_hex"`
	MasterKeyHex        string `json:"master_key_hex"`
	AgentKeyHex         string `json:"agent_key_hex"`
	DerivedAgentKeyHex  string `json:"derived_agent_key_hex"`
	AgentID             uint32 `json:"agent_id"`
	AgentPID            uint32 `json:"agent_pid"`
	IVRandomHex         string `json:"iv_random_hex"`
	IVCounter           uint32 `json:"iv_counter"`
	SessionSaltHex      string `json:"session_salt_hex"`
	PrefixIndex         uint32 `json:"prefix_index"`
	Epoch               uint64 `json:"epoch"`
	PlaintextHex        string `json:"plaintext_hex"`
	ExpectedWireHex     string `json:"expected_wire_hex"`
	ExpectedOKMHex      string `json:"expected_okm_hex"`
	ExpectedIVPrefixHex string `json:"expected_iv_prefix_hex"`
}

func loadVectors(t *testing.T) vectorDoc {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath(t))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var d vectorDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return d
}

func mustHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("hex decode %q: %v", h, err)
	}
	return b
}

func TestConformanceCRC32C(t *testing.T) {
	d := loadVectors(t)
	if len(d.CRC32CVectors) == 0 {
		t.Fatal("expected at least one CRC vector")
	}
	for _, v := range d.CRC32CVectors {
		got := vlp.CRC32C(mustHex(t, v.InputHex))
		want, err := strconv.ParseUint(v.ExpectedCRCHex, 16, 32)
		if err != nil {
			t.Fatalf("vector %s: parse expected CRC %q: %v", v.ID, v.ExpectedCRCHex, err)
		}
		if uint64(got) != want {
			t.Errorf("crc/%s: got %08x, want %08x", v.ID, got, want)
		}
	}
}

func TestConformanceFrameVectors(t *testing.T) {
	d := loadVectors(t)
	if len(d.FrameVectors) == 0 {
		t.Fatal("expected at least one frame vector")
	}
	for _, v := range d.FrameVectors {
		switch v.Kind {
		case "encode_decode_roundtrip":
			if v.Inputs == nil {
				t.Errorf("frame/%s: missing inputs", v.ID)
				continue
			}
			status, err := vlp.StatusFromName(v.Inputs.Status)
			if err != nil {
				t.Errorf("frame/%s: %v", v.ID, err)
				continue
			}
			wire := vlp.Encode(status, v.Inputs.PID, v.Inputs.Timestamp, v.Inputs.Nonce, v.Inputs.Payload)
			if hex.EncodeToString(wire[:]) != v.ExpectedWireHex {
				t.Errorf("frame/%s: encode mismatch\n  got  %s\n  want %s",
					v.ID, hex.EncodeToString(wire[:]), v.ExpectedWireHex)
				continue
			}
			frame, err := vlp.Decode(wire[:])
			if err != nil {
				t.Errorf("frame/%s: decode: %v", v.ID, err)
				continue
			}
			if frame.PID != v.Inputs.PID || frame.Timestamp != v.Inputs.Timestamp ||
				frame.Nonce != v.Inputs.Nonce || frame.Payload != v.Inputs.Payload {
				t.Errorf("frame/%s: decoded fields differ: %+v", v.ID, frame)
			}
		case "decode_error":
			wantErr := ""
			if v.ExpectedDecodeError != nil {
				wantErr = *v.ExpectedDecodeError
			}
			wire := mustHex(t, v.WireHex)
			_, err := vlp.Decode(wire)
			if err == nil {
				t.Errorf("frame/%s: expected error %s, got nil", v.ID, wantErr)
				continue
			}
			de, ok := err.(*vlp.DecodeError)
			if !ok || de.Kind != wantErr {
				t.Errorf("frame/%s: expected %s, got %v", v.ID, wantErr, err)
			}
		default:
			t.Errorf("frame/%s: unknown kind %q", v.ID, v.Kind)
		}
	}
}

func TestConformanceKDFVectors(t *testing.T) {
	d := loadVectors(t)
	for _, v := range d.SecureFrameVectors {
		switch v.ID {
		case "kdf-agent-key":
			var master [vlpsecure.KeyBytes]byte
			copy(master[:], mustHex(t, v.MasterKeyHex))
			out := vlpsecure.DeriveAgentKey(master, v.AgentID)
			if hex.EncodeToString(out[:]) != v.ExpectedOKMHex {
				t.Errorf("%s: derived %s want %s", v.ID, hex.EncodeToString(out[:]), v.ExpectedOKMHex)
			}
		case "kdf-iv-prefix":
			var salt [16]byte
			copy(salt[:], mustHex(t, v.SessionSaltHex))
			out := vlpsecure.DeriveIVPrefix(salt, v.PrefixIndex)
			if hex.EncodeToString(out[:]) != v.ExpectedIVPrefixHex {
				t.Errorf("%s: derived %s want %s", v.ID, hex.EncodeToString(out[:]), v.ExpectedIVPrefixHex)
			}
		case "kdf-epoch-key":
			var agent [vlpsecure.KeyBytes]byte
			copy(agent[:], mustHex(t, v.AgentKeyHex))
			out := vlpsecure.DeriveEpochKey(agent, v.Epoch)
			if hex.EncodeToString(out[:]) != v.ExpectedOKMHex {
				t.Errorf("%s: derived %s want %s", v.ID, hex.EncodeToString(out[:]), v.ExpectedOKMHex)
			}
		}
	}
}

// TestPanicIVPrefix locks the Go secure-panic IV-prefix derivation to the
// Rust reference (crates/varta-vlp/src/crypto/kdf.rs) and the Python/Node
// clients via a shared known-answer, and pins the security property that
// replaced the former (unsound) PID-equality fork check.
func TestPanicIVPrefix(t *testing.T) {
	var saltA5 [16]byte
	for i := range saltA5 {
		saltA5[i] = 0xA5
	}
	// Cross-impl known-answer (same KAT pinned in kdf.rs).
	kat := vlpsecure.DerivePanicIVPrefix(saltA5, 42, 1000, 7)
	if got := hex.EncodeToString(kat[:]); got != "e2615ed3e4f44375" {
		t.Fatalf("KAT mismatch: got %s want e2615ed3e4f44375", got)
	}
	// Every input affects the prefix.
	diffPid := vlpsecure.DerivePanicIVPrefix(saltA5, 43, 1000, 7)
	diffTs := vlpsecure.DerivePanicIVPrefix(saltA5, 42, 1001, 7)
	diffCtr := vlpsecure.DerivePanicIVPrefix(saltA5, 42, 1000, 8)
	if kat == diffPid || kat == diffTs || kat == diffCtr {
		t.Fatal("panic IV prefix must vary with pid, timestamp, and counter")
	}
	// Domain separation from the regular session prefix.
	if reg := vlpsecure.DeriveIVPrefix(saltA5, 0); kat == reg {
		t.Fatal("panic IV prefix must differ from derive_iv_prefix(salt, 0)")
	}
	// Security regression: a PID-recycled descendant firing its first panic
	// at counter 0 must not reuse the installer's (pid, counter=0) prefix —
	// the strictly-monotonic timestamp is the only thing keeping them apart.
	var salt5A [16]byte
	for i := range salt5A {
		salt5A[i] = 0x5A
	}
	installer := vlpsecure.DerivePanicIVPrefix(salt5A, 4242, 1000, 0)
	recycled := vlpsecure.DerivePanicIVPrefix(salt5A, 4242, 9_999_000, 0)
	if installer == recycled {
		t.Fatal("recycled-PID descendant must not reuse installer IV prefix at counter 0")
	}
}

func TestConformanceAEADVectors(t *testing.T) {
	d := loadVectors(t)
	for _, v := range d.SecureFrameVectors {
		switch v.ID {
		case "secure-shared-key-seal":
			var key [vlpsecure.KeyBytes]byte
			copy(key[:], mustHex(t, v.KeyHex))
			var iv [vlpsecure.IVRandomBytes]byte
			copy(iv[:], mustHex(t, v.IVRandomHex))
			var pt [32]byte
			copy(pt[:], mustHex(t, v.PlaintextHex))
			wire, err := vlpsecure.EncodeShared(key, iv, v.IVCounter, pt)
			if err != nil {
				t.Errorf("%s: EncodeShared: %v", v.ID, err)
				continue
			}
			if hex.EncodeToString(wire[:]) != v.ExpectedWireHex {
				t.Errorf("%s: wire mismatch\n  got  %s\n  want %s",
					v.ID, hex.EncodeToString(wire[:]), v.ExpectedWireHex)
				continue
			}
			got, err := vlpsecure.DecodeShared(key, wire[:])
			if err != nil {
				t.Errorf("%s: DecodeShared: %v", v.ID, err)
				continue
			}
			if hex.EncodeToString(got[:]) != v.PlaintextHex {
				t.Errorf("%s: round-trip plaintext mismatch", v.ID)
			}
		case "secure-master-key-seal":
			var master [vlpsecure.KeyBytes]byte
			copy(master[:], mustHex(t, v.MasterKeyHex))
			var iv [vlpsecure.IVRandomBytes]byte
			copy(iv[:], mustHex(t, v.IVRandomHex))
			var pt [32]byte
			copy(pt[:], mustHex(t, v.PlaintextHex))
			wire, _, err := vlpsecure.EncodeMaster(master, v.AgentPID, iv, v.IVCounter, pt)
			if err != nil {
				t.Errorf("%s: EncodeMaster: %v", v.ID, err)
				continue
			}
			if hex.EncodeToString(wire[:]) != v.ExpectedWireHex {
				t.Errorf("%s: wire mismatch\n  got  %s\n  want %s",
					v.ID, hex.EncodeToString(wire[:]), v.ExpectedWireHex)
				continue
			}
			got, err := vlpsecure.DecodeMaster(master, wire[:])
			if err != nil {
				t.Errorf("%s: DecodeMaster: %v", v.ID, err)
				continue
			}
			if hex.EncodeToString(got[:]) != v.PlaintextHex {
				t.Errorf("%s: round-trip plaintext mismatch", v.ID)
			}
		}
	}
}
