package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ----------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869) — small enough to inline; uses stdlib hash + hmac.
// ----------------------------------------------------------------------------

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

func hkdfSha256(ikm, salt, info []byte, length int) []byte {
	return hkdfExpand(hkdfExtract(salt, ikm), info, length)
}

// ----------------------------------------------------------------------------
// Domain-specific derivations (mirror book/src/spec/vlp-secure.md §6).
// ----------------------------------------------------------------------------

// DeriveAgentKey returns the 32-byte per-agent key.
func DeriveAgentKey(masterKey [32]byte, agentID uint32) [32]byte {
	info := make([]byte, 19)
	copy(info[:15], []byte("varta-agent-v1\x00"))
	binary.LittleEndian.PutUint32(info[15:], agentID)
	okm := hkdfSha256(masterKey[:], nil, info, 32)
	var out [32]byte
	copy(out[:], okm)
	return out
}

// DeriveIVPrefix returns the 8-byte per-session IV prefix.
func DeriveIVPrefix(sessionSalt [16]byte, prefixIndex uint32) [8]byte {
	info := make([]byte, 23)
	copy(info[:19], []byte("varta-iv-prefix-v1\x00"))
	binary.LittleEndian.PutUint32(info[19:], prefixIndex)
	okm := hkdfSha256(sessionSalt[:], nil, info, 8)
	var out [8]byte
	copy(out[:], okm)
	return out
}

// DeriveEpochKey returns the 32-byte per-epoch key.
func DeriveEpochKey(agentKey [32]byte, epoch uint64) [32]byte {
	info := make([]byte, 23)
	copy(info[:15], []byte("varta-epoch-v1\x00"))
	binary.LittleEndian.PutUint64(info[15:], epoch)
	okm := hkdfSha256(agentKey[:], nil, info, 32)
	var out [32]byte
	copy(out[:], okm)
	return out
}

// ----------------------------------------------------------------------------
// AEAD wrapping (60-byte shared-key / 64-byte master-key).
// ----------------------------------------------------------------------------

// EncodeShared produces a 60-byte shared-key secure frame.
func EncodeShared(key [32]byte, ivRandom [8]byte, ivCounter uint32, plaintext [32]byte) ([60]byte, error) {
	cipher, err := chacha20poly1305.New(key[:])
	if err != nil {
		var z [60]byte
		return z, err
	}
	nonce := make([]byte, 12)
	copy(nonce[:8], ivRandom[:])
	binary.LittleEndian.PutUint32(nonce[8:], ivCounter)
	ctAndTag := cipher.Seal(nil, nonce, plaintext[:], nil)

	var out [60]byte
	copy(out[0:8], ivRandom[:])
	binary.LittleEndian.PutUint32(out[8:12], ivCounter)
	copy(out[12:60], ctAndTag)
	return out, nil
}

// EncodeMaster produces a 64-byte master-key secure frame.
func EncodeMaster(masterKey [32]byte, agentPID uint32, ivRandom [8]byte, ivCounter uint32, plaintext [32]byte) ([64]byte, [32]byte, error) {
	agentKey := DeriveAgentKey(masterKey, agentPID)
	cipher, err := chacha20poly1305.New(agentKey[:])
	if err != nil {
		var z [64]byte
		return z, agentKey, err
	}
	aad := make([]byte, 4)
	binary.LittleEndian.PutUint32(aad, agentPID)
	nonce := make([]byte, 12)
	copy(nonce[:8], ivRandom[:])
	binary.LittleEndian.PutUint32(nonce[8:], ivCounter)
	ctAndTag := cipher.Seal(nil, nonce, plaintext[:], aad)

	var out [64]byte
	copy(out[0:4], aad)
	copy(out[4:12], ivRandom[:])
	binary.LittleEndian.PutUint32(out[12:16], ivCounter)
	copy(out[16:64], ctAndTag)
	return out, agentKey, nil
}
