// Package vlpsecure implements HKDF-SHA256 key derivation and the
// ChaCha20-Poly1305 AEAD seal/open construction for the Varta secure
// UDP transport. Normative spec: book/src/spec/vlp-secure.md.
package vlpsecure

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Wire-frame constants.
const (
	KeyBytes          = 32
	IVRandomBytes     = 8
	IVCounterBytes    = 4
	TagBytes          = 16
	SecureSharedBytes = 60
	SecureMasterBytes = 64
)

// HKDF-SHA256 (RFC 5869). Stdlib hash + hmac only.

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	if length > 255*sha256.Size {
		panic(fmt.Sprintf("hkdf: requested length %d too large", length))
	}
	var out, t []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length]
}

// HKDFSha256 runs RFC 5869 extract+expand. Exported so the conformance
// tests can drive raw KDF vectors.
func HKDFSha256(ikm, salt, info []byte, length int) []byte {
	return hkdfExpand(hkdfExtract(salt, ikm), info, length)
}

// Domain-specific derivations — book/src/spec/vlp-secure.md §6.

// DeriveAgentKey returns the 32-byte per-agent key.
func DeriveAgentKey(masterKey [KeyBytes]byte, agentID uint32) [KeyBytes]byte {
	info := make([]byte, 19)
	copy(info[:15], []byte("varta-agent-v1\x00"))
	binary.LittleEndian.PutUint32(info[15:], agentID)
	okm := HKDFSha256(masterKey[:], nil, info, KeyBytes)
	var out [KeyBytes]byte
	copy(out[:], okm)
	return out
}

// DeriveIVPrefix returns the 8-byte per-session IV prefix.
func DeriveIVPrefix(sessionSalt [16]byte, prefixIndex uint32) [IVRandomBytes]byte {
	info := make([]byte, 23)
	copy(info[:19], []byte("varta-iv-prefix-v1\x00"))
	binary.LittleEndian.PutUint32(info[19:], prefixIndex)
	okm := HKDFSha256(sessionSalt[:], nil, info, IVRandomBytes)
	var out [IVRandomBytes]byte
	copy(out[:], okm)
	return out
}

// DeriveEpochKey returns the 32-byte per-epoch key. Reserved for
// forward compatibility; not used on the wire today but covered by the
// conformance vectors.
func DeriveEpochKey(agentKey [KeyBytes]byte, epoch uint64) [KeyBytes]byte {
	info := make([]byte, 23)
	copy(info[:15], []byte("varta-epoch-v1\x00"))
	binary.LittleEndian.PutUint64(info[15:], epoch)
	okm := HKDFSha256(agentKey[:], nil, info, KeyBytes)
	var out [KeyBytes]byte
	copy(out[:], okm)
	return out
}
