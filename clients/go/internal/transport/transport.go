// Package transport defines the BeatTransport interface and the three
// concrete implementations used by the Varta agent: UDS, UDP, and
// secure UDP (ChaCha20-Poly1305 AEAD).
//
// Implementations must be non-blocking; the agent layer translates
// syscall errors into the four-way DropReason taxonomy via the
// errnoclass package. Reconnect rebuilds the underlying socket from
// the original parameters — secure UDP additionally re-reads
// crypto/rand for the session salt, the structural guarantee against
// AEAD nonce reuse across fork(2).
package transport

// BeatTransport is the per-transport contract that the Varta agent
// drives. Send accepts a 32-byte plaintext frame (the transport may
// AEAD-wrap before transmission); Reconnect rebuilds session state and
// must leave the current transport usable when replacement setup fails;
// Close releases the socket. All three may allocate freely on the cold
// paths; only Send is on the agent's hot path.
type BeatTransport interface {
	Send(buf []byte) (int, error)
	Reconnect() error
	Close() error
}
