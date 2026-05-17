package vlpsecure

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncodeShared produces a 60-byte shared-key secure frame.
// Layout: ivRandom[8] || ivCounterLE[4] || ciphertext+tag[48].
func EncodeShared(key [KeyBytes]byte, ivRandom [IVRandomBytes]byte, ivCounter uint32, plaintext [32]byte) ([SecureSharedBytes]byte, error) {
	var out [SecureSharedBytes]byte
	cipher, err := chacha20poly1305.New(key[:])
	if err != nil {
		return out, err
	}
	nonce := make([]byte, 12)
	copy(nonce[:8], ivRandom[:])
	binary.LittleEndian.PutUint32(nonce[8:], ivCounter)
	ctAndTag := cipher.Seal(nil, nonce, plaintext[:], nil)
	if len(ctAndTag) != 32+TagBytes {
		return out, fmt.Errorf("vlpsecure: unexpected sealed length %d", len(ctAndTag))
	}
	copy(out[0:8], ivRandom[:])
	binary.LittleEndian.PutUint32(out[8:12], ivCounter)
	copy(out[12:SecureSharedBytes], ctAndTag)
	return out, nil
}

// DecodeShared opens a 60-byte shared-key wire frame and returns the
// 32-byte plaintext. Returns an error if authentication fails.
func DecodeShared(key [KeyBytes]byte, wire []byte) ([32]byte, error) {
	var out [32]byte
	if len(wire) != SecureSharedBytes {
		return out, fmt.Errorf("vlpsecure: shared wire must be %d bytes, got %d", SecureSharedBytes, len(wire))
	}
	cipher, err := chacha20poly1305.New(key[:])
	if err != nil {
		return out, err
	}
	nonce := make([]byte, 12)
	copy(nonce, wire[0:12])
	plaintext, err := cipher.Open(nil, nonce, wire[12:SecureSharedBytes], nil)
	if err != nil {
		return out, err
	}
	if len(plaintext) != 32 {
		return out, fmt.Errorf("vlpsecure: opened length %d != 32", len(plaintext))
	}
	copy(out[:], plaintext)
	return out, nil
}

// EncodeMaster produces a 64-byte master-key secure frame.
// Layout: agentPidLE[4] (AAD) || ivRandom[8] || ivCounterLE[4] || ciphertext+tag[48].
func EncodeMaster(masterKey [KeyBytes]byte, agentPID uint32, ivRandom [IVRandomBytes]byte, ivCounter uint32, plaintext [32]byte) ([SecureMasterBytes]byte, [KeyBytes]byte, error) {
	var out [SecureMasterBytes]byte
	agentKey := DeriveAgentKey(masterKey, agentPID)
	cipher, err := chacha20poly1305.New(agentKey[:])
	if err != nil {
		return out, agentKey, err
	}
	aad := make([]byte, 4)
	binary.LittleEndian.PutUint32(aad, agentPID)
	nonce := make([]byte, 12)
	copy(nonce[:8], ivRandom[:])
	binary.LittleEndian.PutUint32(nonce[8:], ivCounter)
	ctAndTag := cipher.Seal(nil, nonce, plaintext[:], aad)
	if len(ctAndTag) != 32+TagBytes {
		return out, agentKey, fmt.Errorf("vlpsecure: unexpected sealed length %d", len(ctAndTag))
	}
	copy(out[0:4], aad)
	copy(out[4:12], ivRandom[:])
	binary.LittleEndian.PutUint32(out[12:16], ivCounter)
	copy(out[16:SecureMasterBytes], ctAndTag)
	return out, agentKey, nil
}

// DecodeMaster opens a 64-byte master-key wire frame.
func DecodeMaster(masterKey [KeyBytes]byte, wire []byte) ([32]byte, error) {
	var out [32]byte
	if len(wire) != SecureMasterBytes {
		return out, fmt.Errorf("vlpsecure: master wire must be %d bytes, got %d", SecureMasterBytes, len(wire))
	}
	agentPID := binary.LittleEndian.Uint32(wire[0:4])
	agentKey := DeriveAgentKey(masterKey, agentPID)
	cipher, err := chacha20poly1305.New(agentKey[:])
	if err != nil {
		return out, err
	}
	nonce := make([]byte, 12)
	copy(nonce, wire[4:16])
	plaintext, err := cipher.Open(nil, nonce, wire[16:SecureMasterBytes], wire[0:4])
	if err != nil {
		return out, err
	}
	if len(plaintext) != 32 {
		return out, fmt.Errorf("vlpsecure: opened length %d != 32", len(plaintext))
	}
	copy(out[:], plaintext)
	return out, nil
}
