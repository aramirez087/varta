package transport

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/aramirez087/Varta/clients/go/internal/vlpsecure"
)

// SecureUDPKind selects between the two on-wire formats.
type SecureUDPKind int

const (
	// SecureUDPKindShared uses a single pre-shared 32-byte key and a
	// 60-byte wire frame.
	SecureUDPKindShared SecureUDPKind = iota + 1

	// SecureUDPKindMaster derives a per-agent key from a master key via
	// HKDF; wire frame is 64 bytes with the agent PID bound as AAD.
	SecureUDPKindMaster
)

// aeadCounterLimit is the wrap-around boundary for the 32-bit IV
// counter. The transport rotates the prefix when the counter is about
// to wrap so a Dropped send never advances past the boundary.
const aeadCounterLimit = uint32(0xFFFFFFFF)

// SecureUDPTransport wraps a connected UDP socket with
// ChaCha20-Poly1305 AEAD. Session salt + IV prefix are read from
// crypto/rand at Open (and again at every Reconnect) so AEAD nonce
// reuse is structurally impossible across fork(2).
type SecureUDPTransport struct {
	kind      SecureUDPKind
	host      string
	port      int
	key       [vlpsecure.KeyBytes]byte
	masterKey [vlpsecure.KeyBytes]byte

	conn        *net.UDPConn
	sessionSalt [16]byte
	ivPrefix    [vlpsecure.IVRandomBytes]byte
	prefixIndex uint32
	counter     uint32
}

// NewSecureUDPShared dials a secure-UDP socket using a pre-shared key.
func NewSecureUDPShared(host string, port int, key []byte) (*SecureUDPTransport, error) {
	if len(key) != vlpsecure.KeyBytes {
		return nil, fmt.Errorf("secure-udp: key must be %d bytes", vlpsecure.KeyBytes)
	}
	t := &SecureUDPTransport{kind: SecureUDPKindShared, host: host, port: port}
	copy(t.key[:], key)
	if err := t.open(); err != nil {
		return nil, err
	}
	return t, nil
}

// NewSecureUDPMaster dials a secure-UDP socket using a master key; the
// agent PID is bound into the AEAD AAD and the per-agent key is
// HKDF-derived.
func NewSecureUDPMaster(host string, port int, masterKey []byte) (*SecureUDPTransport, error) {
	if len(masterKey) != vlpsecure.KeyBytes {
		return nil, fmt.Errorf("secure-udp: master key must be %d bytes", vlpsecure.KeyBytes)
	}
	t := &SecureUDPTransport{kind: SecureUDPKindMaster, host: host, port: port}
	copy(t.masterKey[:], masterKey)
	if err := t.open(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *SecureUDPTransport) open() error {
	conn, sessionSalt, ivPrefix, err := prepareSecureUDPSession(t.host, t.port)
	if err != nil {
		return err
	}
	t.conn = conn
	t.sessionSalt = sessionSalt
	t.ivPrefix = ivPrefix
	t.prefixIndex = 0
	t.counter = 0
	return nil
}

func prepareSecureUDPSession(
	host string,
	port int,
) (*net.UDPConn, [16]byte, [vlpsecure.IVRandomBytes]byte, error) {
	var sessionSalt [16]byte
	var ivPrefix [vlpsecure.IVRandomBytes]byte

	conn, err := dialUDP(host, port)
	if err != nil {
		return nil, sessionSalt, ivPrefix, err
	}
	if _, err := rand.Read(sessionSalt[:]); err != nil {
		_ = conn.Close()
		return nil, sessionSalt, ivPrefix, fmt.Errorf("secure-udp: read crypto/rand: %w", err)
	}
	ivPrefix = vlpsecure.DeriveIVPrefix(sessionSalt, 0)
	return conn, sessionSalt, ivPrefix, nil
}

func (t *SecureUDPTransport) rotatePrefix() {
	t.prefixIndex++
	t.counter = 0
	t.ivPrefix = vlpsecure.DeriveIVPrefix(t.sessionSalt, t.prefixIndex)
}

// Send AEAD-wraps the 32-byte plaintext into a 60- or 64-byte wire
// frame and transmits it. The IV counter advances only after a
// successful Write (commit-on-success), so a Dropped beat does not
// consume a nonce.
func (t *SecureUDPTransport) Send(buf []byte) (int, error) {
	if len(buf) != 32 {
		return 0, errors.New("secure-udp: plaintext must be exactly 32 bytes")
	}
	if t.counter >= aeadCounterLimit {
		t.rotatePrefix()
	}
	var pt [32]byte
	copy(pt[:], buf)
	counter := t.counter

	var (
		wire []byte
		n    int
		err  error
	)
	switch t.kind {
	case SecureUDPKindShared:
		w, sealErr := vlpsecure.EncodeShared(t.key, t.ivPrefix, counter, pt)
		if sealErr != nil {
			return 0, sealErr
		}
		wire = w[:]
	case SecureUDPKindMaster:
		agentPID := uint32(os.Getpid())
		w, _, sealErr := vlpsecure.EncodeMaster(t.masterKey, agentPID, t.ivPrefix, counter, pt)
		if sealErr != nil {
			return 0, sealErr
		}
		wire = w[:]
	default:
		return 0, fmt.Errorf("secure-udp: unknown kind %d", t.kind)
	}
	n, err = t.conn.Write(wire)
	if err != nil {
		// Commit-on-success — leave counter untouched so we never burn
		// a nonce on a Dropped send.
		return n, err
	}
	t.counter = counter + 1
	return n, nil
}

// Reconnect rebuilds the socket and re-reads crypto/rand for a fresh
// session salt. Cold path; allocation is fine.
func (t *SecureUDPTransport) Reconnect() error {
	conn, sessionSalt, ivPrefix, err := prepareSecureUDPSession(t.host, t.port)
	if err != nil {
		return err
	}

	old := t.conn
	t.conn = conn
	t.sessionSalt = sessionSalt
	t.ivPrefix = ivPrefix
	t.prefixIndex = 0
	t.counter = 0
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (t *SecureUDPTransport) Close() error {
	if t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn = nil
	return err
}

// Test hooks — parity with the Python and Rust transports.

func (t *SecureUDPTransport) SetCounterForTest(v uint32) { t.counter = v }
func (t *SecureUDPTransport) CounterForTest() uint32     { return t.counter }
func (t *SecureUDPTransport) PrefixIndexForTest() uint32 { return t.prefixIndex }
func (t *SecureUDPTransport) IVPrefixForTest() [vlpsecure.IVRandomBytes]byte {
	return t.ivPrefix
}
