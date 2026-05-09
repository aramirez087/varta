// Package vlp is a non-normative Go reference for VLP v0.2 base frames.
//
// The authoritative specification lives at book/src/spec/vlp.md. This
// package exists so a Go developer can confirm their understanding of
// the wire format against working code without needing a Rust toolchain.
//
// Standard library only. Requires Go 1.21+.
package main

import (
	"encoding/binary"
	"fmt"
)

// Magic prefix, version byte, and reserved nonce sentinel.
var (
	Magic          = [2]byte{0x56, 0x41} // "VA"
	Version        = byte(0x02)
	NonceTerminal  = uint64(0xFFFFFFFFFFFFFFFF)
)

// Status enumerates the agent's reported health.
type Status uint8

const (
	StatusOk       Status = 0
	StatusDegraded Status = 1
	StatusCritical Status = 2
	StatusStall    Status = 3 // observer-synthesized only — MUST NOT appear on the wire
)

func StatusFromName(name string) (Status, error) {
	switch name {
	case "ok":
		return StatusOk, nil
	case "degraded":
		return StatusDegraded, nil
	case "critical":
		return StatusCritical, nil
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

// DecodeError carries the spec-defined error variant name. The Kind field
// matches the strings in tools/vlp-test-vectors.json.
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

// ----------------------------------------------------------------------------
// CRC-32C (Castagnoli) — byte-at-a-time table lookup. RFC 3720 appendix B.
// ----------------------------------------------------------------------------

const crc32cReflected = uint32(0x82F63B78)

var crc32cTable = buildCRC32CTable()

func buildCRC32CTable() [256]uint32 {
	var t [256]uint32
	for i := uint32(0); i < 256; i++ {
		c := i
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = (c >> 1) ^ crc32cReflected
			} else {
				c = c >> 1
			}
		}
		t[i] = c
	}
	return t
}

// CRC32C computes the Castagnoli CRC-32C of data.
func CRC32C(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc = crc32cTable[(crc^uint32(b))&0xff] ^ (crc >> 8)
	}
	return crc ^ 0xFFFFFFFF
}

// ----------------------------------------------------------------------------
// Encode / Decode
// ----------------------------------------------------------------------------

// Encode produces a 32-byte VLP v0.2 frame.
func Encode(status Status, pid uint32, timestamp, nonce uint64, payload uint32) [32]byte {
	var out [32]byte
	out[0] = Magic[0]
	out[1] = Magic[1]
	out[2] = Version
	out[3] = byte(status)
	binary.LittleEndian.PutUint32(out[4:8], pid)
	binary.LittleEndian.PutUint64(out[8:16], timestamp)
	binary.LittleEndian.PutUint64(out[16:24], nonce)
	binary.LittleEndian.PutUint32(out[24:28], payload)
	binary.LittleEndian.PutUint32(out[28:32], CRC32C(out[0:28]))
	return out
}

// Decode validates a 32-byte buffer and returns the recovered Frame.
// On any validation failure it returns *DecodeError; see
// book/src/spec/vlp.md §5 for the normative decode order.
func Decode(buf []byte) (Frame, error) {
	if len(buf) != 32 {
		return Frame{}, &DecodeError{Kind: "BadMagic", Detail: fmt.Sprintf("length %d != 32", len(buf))}
	}
	if buf[0] != Magic[0] || buf[1] != Magic[1] {
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
