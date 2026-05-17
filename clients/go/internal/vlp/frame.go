package vlp

import (
	"encoding/binary"
	"fmt"
)

// FrameBytes is the fixed wire length of a VLP v0.2 base frame.
const FrameBytes = 32

// MagicHi and MagicLo are the two bytes at offsets 0 and 1 ("VA").
const (
	MagicHi byte = 0x56
	MagicLo byte = 0x41
)

// Version is the protocol version byte at offset 2.
const Version byte = 0x02

// NonceTerminal is the reserved sentinel nonce. It is only valid paired
// with StatusCritical and identifies a panic-emitted terminal frame.
const NonceTerminal uint64 = 0xFFFFFFFFFFFFFFFF

// Status enumerates the agent's reported health.
type Status uint8

const (
	StatusOk       Status = 0
	StatusDegraded Status = 1
	StatusCritical Status = 2
	StatusStall    Status = 3 // observer-synthesized; MUST NOT appear on the wire
)

// StatusFromName accepts the lowercase status names used by the JSON
// conformance vectors ("ok", "degraded", "critical").
func StatusFromName(name string) (Status, error) {
	switch name {
	case "ok":
		return StatusOk, nil
	case "degraded":
		return StatusDegraded, nil
	case "critical":
		return StatusCritical, nil
	case "stall":
		return StatusStall, nil
	default:
		return 0, fmt.Errorf("unknown status name %q", name)
	}
}

// Frame is the decoded form of a 32-byte wire frame.
type Frame struct {
	Status    Status
	PID       uint32
	Timestamp uint64
	Nonce     uint64
	Payload   uint32
}

// DecodeError carries the spec-defined error variant name. Kind matches
// the strings in tools/vlp-test-vectors.json: BadMagic, BadVersion,
// BadCrc, BadStatus, StallOnWire, BadPid, BadTimestamp, BadNonce.
type DecodeError struct {
	Kind   string
	Detail string
}

func (e *DecodeError) Error() string {
	if e.Detail == "" {
		return e.Kind
	}
	return e.Kind + ": " + e.Detail
}

// Encode produces a 32-byte VLP v0.2 frame. Allocates the output array;
// the production agent uses EncodeInto against a reusable buffer.
func Encode(status Status, pid uint32, timestamp, nonce uint64, payload uint32) [FrameBytes]byte {
	var out [FrameBytes]byte
	EncodeInto(&out, status, pid, timestamp, nonce, payload)
	return out
}

// EncodeInto writes the frame into the caller's buffer. Reused on the
// agent's hot path so per-beat allocation stays at zero.
func EncodeInto(out *[FrameBytes]byte, status Status, pid uint32, timestamp, nonce uint64, payload uint32) {
	out[0] = MagicHi
	out[1] = MagicLo
	out[2] = Version
	out[3] = byte(status)
	binary.LittleEndian.PutUint32(out[4:8], pid)
	binary.LittleEndian.PutUint64(out[8:16], timestamp)
	binary.LittleEndian.PutUint64(out[16:24], nonce)
	binary.LittleEndian.PutUint32(out[24:28], payload)
	binary.LittleEndian.PutUint32(out[28:32], CRC32C(out[0:28]))
}

// Decode validates a 32-byte buffer and returns the recovered Frame.
// Validation order is normative — see book/src/spec/vlp.md §5.
func Decode(buf []byte) (Frame, error) {
	if len(buf) != FrameBytes {
		return Frame{}, &DecodeError{Kind: "BadMagic", Detail: fmt.Sprintf("length %d != %d", len(buf), FrameBytes)}
	}
	if buf[0] != MagicHi || buf[1] != MagicLo {
		return Frame{}, &DecodeError{Kind: "BadMagic", Detail: fmt.Sprintf("%02x%02x", buf[0], buf[1])}
	}
	if buf[2] != Version {
		return Frame{}, &DecodeError{Kind: "BadVersion", Detail: fmt.Sprintf("0x%02x", buf[2])}
	}

	storedCRC := binary.LittleEndian.Uint32(buf[28:32])
	computedCRC := CRC32C(buf[0:28])
	if storedCRC != computedCRC {
		return Frame{}, &DecodeError{
			Kind:   "BadCrc",
			Detail: fmt.Sprintf("expected %08x, got %08x", computedCRC, storedCRC),
		}
	}

	statusByte := buf[3]
	if statusByte > 3 {
		return Frame{}, &DecodeError{Kind: "BadStatus", Detail: fmt.Sprintf("0x%02x", statusByte)}
	}
	if statusByte == byte(StatusStall) {
		return Frame{}, &DecodeError{Kind: "StallOnWire"}
	}

	pid := binary.LittleEndian.Uint32(buf[4:8])
	ts := binary.LittleEndian.Uint64(buf[8:16])
	nonce := binary.LittleEndian.Uint64(buf[16:24])
	payload := binary.LittleEndian.Uint32(buf[24:28])

	if pid == 0 || pid == 1 {
		return Frame{}, &DecodeError{Kind: "BadPid", Detail: fmt.Sprintf("%d", pid)}
	}
	if ts == 0xFFFFFFFFFFFFFFFF {
		return Frame{}, &DecodeError{Kind: "BadTimestamp"}
	}
	if nonce == NonceTerminal && statusByte != byte(StatusCritical) {
		return Frame{}, &DecodeError{
			Kind:   "BadNonce",
			Detail: fmt.Sprintf("status 0x%02x with terminal nonce", statusByte),
		}
	}

	return Frame{
		Status:    Status(statusByte),
		PID:       pid,
		Timestamp: ts,
		Nonce:     nonce,
		Payload:   payload,
	}, nil
}
