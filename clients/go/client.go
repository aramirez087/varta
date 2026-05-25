package varta

import (
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/aramirez087/Varta/clients/go/internal/transport"
	"github.com/aramirez087/Varta/clients/go/internal/vlp"
)

// Varta is the agent handle. Construct with Connect, ConnectUDP,
// ConnectSecureUDP, or ConnectSecureUDPWithMaster; call Beat in a
// loop; Close when done.
//
// The handle holds a single transport, a reusable 32-byte scratch
// buffer, and the saturating counters surfaced by ClockRegressions
// and ForkRecoveries. All Beat calls are serialised on an internal
// mutex; the type is goroutine-safe but not lock-free.
type Varta struct {
	mu                  sync.Mutex
	transport           transport.BeatTransport
	buf                 [vlp.FrameBytes]byte
	startMono           time.Time
	nonce               uint64
	consecutiveDropped  uint32
	reconnectAfter      uint32
	lastTimestamp       uint64
	clockRegressions    uint64
	connectPID          int
	forkRecoveries      uint64
}

// Connect dials the observer's UDS at path and returns a ready agent.
func Connect(path string) (*Varta, error) {
	t, err := transport.NewUDS(path)
	if err != nil {
		return nil, fmt.Errorf("varta: connect %s: %w", path, err)
	}
	return newVarta(t), nil
}

// ConnectUDP dials the observer over plaintext UDP.
func ConnectUDP(host string, port int) (*Varta, error) {
	t, err := transport.NewUDP(host, port)
	if err != nil {
		return nil, fmt.Errorf("varta: connect udp %s:%d: %w", host, port, err)
	}
	return newVarta(t), nil
}

// ConnectSecureUDP dials the observer over ChaCha20-Poly1305 AEAD UDP
// with a pre-shared 32-byte key.
func ConnectSecureUDP(host string, port int, key []byte) (*Varta, error) {
	t, err := transport.NewSecureUDPShared(host, port, key)
	if err != nil {
		return nil, fmt.Errorf("varta: connect secure-udp %s:%d: %w", host, port, err)
	}
	return newVarta(t), nil
}

// ConnectSecureUDPWithMaster dials the observer over secure UDP using a
// master key; the per-agent key is HKDF-derived from the master key and
// the agent PID.
func ConnectSecureUDPWithMaster(host string, port int, masterKey []byte) (*Varta, error) {
	t, err := transport.NewSecureUDPMaster(host, port, masterKey)
	if err != nil {
		return nil, fmt.Errorf("varta: connect secure-udp/master %s:%d: %w", host, port, err)
	}
	return newVarta(t), nil
}

func newVarta(t transport.BeatTransport) *Varta {
	return &Varta{
		transport:  t,
		startMono:  time.Now(),
		connectPID: os.Getpid(),
	}
}

// Beat emits one VLP frame and returns the outcome. Detects fork(2)
// by comparing the current PID to the connect-time snapshot; on
// mismatch, the transport is rebuilt (secure-UDP re-reads
// crypto/rand) BEFORE the frame is encoded.
//
// Mirrors crates/varta-client/src/client.rs::beat and
// clients/python/src/varta/client.py:272-337.
func (v *Varta) Beat(status Status, payload uint32) BeatOutcome {
	v.mu.Lock()
	defer v.mu.Unlock()

	pid := os.Getpid()
	if pid != v.connectPID {
		if err := v.transport.Reconnect(); err != nil {
			return BeatOutcomeFailed(BeatError{Kind: "ReconnectFailed", Errno: 0})
		}
		v.connectPID = pid
		v.forkRecoveries = saturatingAdd(v.forkRecoveries, 1)
		v.nonce = 0
		v.startMono = time.Now()
		v.lastTimestamp = 0
		v.consecutiveDropped = 0
	}

	if v.nonce < vlp.NonceTerminal-1 {
		v.nonce++
	} else {
		warnNonceWrapOnce()
		v.nonce = 0
	}

	elapsed := time.Since(v.startMono).Nanoseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	rawElapsed := uint64(elapsed)
	if rawElapsed < v.lastTimestamp {
		v.clockRegressions = saturatingAdd(v.clockRegressions, 1)
	} else {
		v.lastTimestamp = rawElapsed
	}
	timestamp := v.lastTimestamp

	vlp.EncodeInto(&v.buf, status, uint32(pid), timestamp, v.nonce, payload)

	outcome := v.sendBuffered()
	if outcome.IsDropped() {
		v.consecutiveDropped = saturatingAdd32(v.consecutiveDropped, 1)
		if v.reconnectAfter > 0 && v.consecutiveDropped >= v.reconnectAfter {
			v.consecutiveDropped = 0
			if err := v.transport.Reconnect(); err != nil {
				return outcome
			}
			return v.sendBuffered()
		}
		return outcome
	}
	v.consecutiveDropped = 0
	return outcome
}

// Reconnect rebuilds the transport. Use after observer restarts.
func (v *Varta) Reconnect() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.transport.Reconnect(); err != nil {
		return err
	}
	v.connectPID = os.Getpid()
	return nil
}

// SetReconnectAfter enables auto-reconnect after n consecutive Dropped
// outcomes. Zero disables the behaviour (the default).
func (v *Varta) SetReconnectAfter(n uint32) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.reconnectAfter = n
	v.consecutiveDropped = 0
}

// ClockRegressions returns the saturating count of platform-clock
// regressions observed. Surface as
// `varta_client_clock_regression_total` in caller-side telemetry.
func (v *Varta) ClockRegressions() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.clockRegressions
}

// ForkRecoveries returns the saturating count of fork auto-recovery
// events. Surface as `varta_client_fork_recoveries_total`.
func (v *Varta) ForkRecoveries() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.forkRecoveries
}

// Close releases the transport.
func (v *Varta) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.transport.Close()
}

// sendBuffered transmits the scratch buffer and translates the
// transport-layer error into a BeatOutcome.
func (v *Varta) sendBuffered() BeatOutcome {
	_, err := v.transport.Send(v.buf[:])
	if err == nil {
		return BeatOutcomeSent()
	}
	return ClassifySendError(err)
}

func saturatingAdd(x, delta uint64) uint64 {
	if x > math.MaxUint64-delta {
		return math.MaxUint64
	}
	return x + delta
}

func saturatingAdd32(x, delta uint32) uint32 {
	if x > math.MaxUint32-delta {
		return math.MaxUint32
	}
	return x + delta
}

var nonceWrapOnce sync.Once

func warnNonceWrapOnce() {
	nonceWrapOnce.Do(func() {
		_, _ = fmt.Fprintln(os.Stderr, "[varta] nonce exhausted; wrapping to 0")
	})
}

// Test hooks — parity with the Python `_set_connect_pid_for_test` etc.

// SetConnectPIDForTest overrides the connect-time PID snapshot. Tests
// only.
func (v *Varta) SetConnectPIDForTest(pid int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.connectPID = pid
}

// SetNonceForTest overrides the running nonce. Tests only.
func (v *Varta) SetNonceForTest(n uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.nonce = n
}

