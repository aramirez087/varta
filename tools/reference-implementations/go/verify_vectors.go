package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

type doc struct {
	SpecVersion       string              `json:"spec_version"`
	CRC32CVectors     []crcVector         `json:"crc32c_vectors"`
	FrameVectors      []frameVector       `json:"frame_vectors"`
	SecureFrameVectors []secureFrameVector `json:"secure_frame_vectors"`
}

type crcVector struct {
	ID              string `json:"id"`
	InputHex        string `json:"input_hex"`
	ExpectedCRCHex  string `json:"expected_crc_hex"`
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
	ID                   string `json:"id"`
	Kind                 string `json:"kind"`
	KeyHex               string `json:"key_hex"`
	MasterKeyHex         string `json:"master_key_hex"`
	AgentKeyHex          string `json:"agent_key_hex"`
	DerivedAgentKeyHex   string `json:"derived_agent_key_hex"`
	AgentID              uint32 `json:"agent_id"`
	AgentPID             uint32 `json:"agent_pid"`
	IVRandomHex          string `json:"iv_random_hex"`
	IVCounter            uint32 `json:"iv_counter"`
	SessionSaltHex       string `json:"session_salt_hex"`
	PrefixIndex          uint32 `json:"prefix_index"`
	Epoch                uint64 `json:"epoch"`
	PlaintextHex         string `json:"plaintext_hex"`
	ExpectedWireHex      string `json:"expected_wire_hex"`
	ExpectedOKMHex       string `json:"expected_okm_hex"`
	ExpectedIVPrefixHex  string `json:"expected_iv_prefix_hex"`
}

func main() {
	defaultPath, _ := filepath.Abs("../../vlp-test-vectors.json")
	path := defaultPath
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		die("read %s: %v", path, err)
	}
	var d doc
	if err := json.Unmarshal(raw, &d); err != nil {
		die("parse %s: %v", path, err)
	}

	var failures []string

	// ----- CRC -----
	for _, v := range d.CRC32CVectors {
		input, _ := hex.DecodeString(v.InputHex)
		got := CRC32C(input)
		want64, _ := strconv.ParseUint(v.ExpectedCRCHex, 16, 32)
		if uint64(got) != want64 {
			failures = append(failures, fmt.Sprintf("crc/%s: got %08x, want %08x", v.ID, got, want64))
		}
	}
	fmt.Printf("crc32c_vectors:        %d OK\n", len(d.CRC32CVectors))

	// ----- Frames -----
	roundtrip := 0
	errs := 0
	for _, v := range d.FrameVectors {
		switch v.Kind {
		case "encode_decode_roundtrip":
			if v.Inputs == nil {
				failures = append(failures, fmt.Sprintf("frame/%s: missing inputs", v.ID))
				continue
			}
			st, err := StatusFromName(v.Inputs.Status)
			if err != nil {
				failures = append(failures, fmt.Sprintf("frame/%s: %v", v.ID, err))
				continue
			}
			wire := Encode(st, v.Inputs.PID, v.Inputs.Timestamp, v.Inputs.Nonce, v.Inputs.Payload)
			if hex.EncodeToString(wire[:]) != v.ExpectedWireHex {
				failures = append(failures, fmt.Sprintf(
					"frame/%s: encode mismatch\n  got  %s\n  want %s",
					v.ID, hex.EncodeToString(wire[:]), v.ExpectedWireHex,
				))
				continue
			}
			rawBytes, _ := hex.DecodeString(v.ExpectedWireHex)
			frame, err := Decode(rawBytes)
			if err != nil {
				failures = append(failures, fmt.Sprintf("frame/%s: decode err %v", v.ID, err))
				continue
			}
			if frame.PID != v.Inputs.PID || frame.Timestamp != v.Inputs.Timestamp ||
				frame.Nonce != v.Inputs.Nonce || frame.Payload != v.Inputs.Payload {
				failures = append(failures, fmt.Sprintf("frame/%s: decoded fields differ", v.ID))
				continue
			}
			roundtrip++
		case "decode_error":
			wantErr := ""
			if v.ExpectedDecodeError != nil {
				wantErr = *v.ExpectedDecodeError
			}
			rawBytes, _ := hex.DecodeString(v.WireHex)
			_, err := Decode(rawBytes)
			if err == nil {
				failures = append(failures, fmt.Sprintf("frame/%s: expected error %s, got OK", v.ID, wantErr))
				continue
			}
			de, ok := err.(*DecodeError)
			if !ok || de.Kind != wantErr {
				failures = append(failures, fmt.Sprintf("frame/%s: expected %s, got %v", v.ID, wantErr, err))
				continue
			}
			errs++
		default:
			failures = append(failures, fmt.Sprintf("frame/%s: unknown kind %q", v.ID, v.Kind))
		}
	}
	fmt.Printf("frame_vectors:         %d round-trips, %d error vectors OK\n", roundtrip, errs)

	// ----- Secure -----
	secureCount := 0
	for _, v := range d.SecureFrameVectors {
		switch v.Kind {
		case "shared_key_seal":
			var key [32]byte
			var ivR [8]byte
			var pt [32]byte
			copyHex(key[:], v.KeyHex)
			copyHex(ivR[:], v.IVRandomHex)
			copyHex(pt[:], v.PlaintextHex)
			wire, err := EncodeShared(key, ivR, v.IVCounter, pt)
			if err != nil {
				failures = append(failures, fmt.Sprintf("secure/%s: %v", v.ID, err))
				continue
			}
			if hex.EncodeToString(wire[:]) != v.ExpectedWireHex {
				failures = append(failures, fmt.Sprintf("secure/%s: wire mismatch", v.ID))
				continue
			}
		case "master_key_seal":
			var master [32]byte
			var ivR [8]byte
			var pt [32]byte
			copyHex(master[:], v.MasterKeyHex)
			copyHex(ivR[:], v.IVRandomHex)
			copyHex(pt[:], v.PlaintextHex)
			wire, derived, err := EncodeMaster(master, v.AgentPID, ivR, v.IVCounter, pt)
			if err != nil {
				failures = append(failures, fmt.Sprintf("secure/%s: %v", v.ID, err))
				continue
			}
			if hex.EncodeToString(derived[:]) != v.DerivedAgentKeyHex {
				failures = append(failures, fmt.Sprintf("secure/%s: agent-key derivation mismatch", v.ID))
				continue
			}
			if hex.EncodeToString(wire[:]) != v.ExpectedWireHex {
				failures = append(failures, fmt.Sprintf("secure/%s: wire mismatch", v.ID))
				continue
			}
		case "kdf_agent_key":
			var master [32]byte
			copyHex(master[:], v.MasterKeyHex)
			key := DeriveAgentKey(master, v.AgentID)
			if hex.EncodeToString(key[:]) != v.ExpectedOKMHex {
				failures = append(failures, fmt.Sprintf("secure/%s: HKDF mismatch", v.ID))
				continue
			}
		case "kdf_iv_prefix":
			var salt [16]byte
			copyHex(salt[:], v.SessionSaltHex)
			iv := DeriveIVPrefix(salt, v.PrefixIndex)
			if hex.EncodeToString(iv[:]) != v.ExpectedIVPrefixHex {
				failures = append(failures, fmt.Sprintf("secure/%s: HKDF mismatch", v.ID))
				continue
			}
		case "kdf_epoch_key":
			var agent [32]byte
			copyHex(agent[:], v.AgentKeyHex)
			key := DeriveEpochKey(agent, v.Epoch)
			if hex.EncodeToString(key[:]) != v.ExpectedOKMHex {
				failures = append(failures, fmt.Sprintf("secure/%s: HKDF mismatch", v.ID))
				continue
			}
		default:
			failures = append(failures, fmt.Sprintf("secure/%s: unknown kind %q", v.ID, v.Kind))
			continue
		}
		secureCount++
	}
	fmt.Printf("secure_frame_vectors:  %d OK\n", secureCount)

	if len(failures) > 0 {
		fmt.Println()
		fmt.Println("FAILED:")
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
	fmt.Println()
	fmt.Println("ALL VECTORS PASSED")
}

func copyHex(dst []byte, src string) {
	b, err := hex.DecodeString(src)
	if err != nil || len(b) != len(dst) {
		die("hex %q: expected %d bytes, got %d (%v)", src, len(dst), len(b), err)
	}
	copy(dst, b)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
