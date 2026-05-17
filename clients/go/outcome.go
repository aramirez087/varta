package varta

import (
	"fmt"

	"github.com/aramirez087/Varta/clients/go/internal/errnoclass"
)

// DropReason identifies why a Beat returned Dropped. Mirrors the Rust
// enum and the Python StrEnum so the wire-side metrics label matches
// across languages.
type DropReason int

const (
	// KernelQueueFull — WouldBlock or ENOBUFS. Transient burst; the
	// observer is likely alive. Retry or rely on SetReconnectAfter.
	KernelQueueFull DropReason = iota + 1

	// NoObserver — NotFound or ConnectionRefused. The observer has not
	// bound the socket yet; expected during rolling restarts.
	NoObserver

	// PeerGone — ConnectionReset, NotConnected, or BrokenPipe. The
	// channel was live and disappeared (crash or shutdown). Call
	// Reconnect to recover.
	PeerGone

	// StorageFull — ENOSPC. Host filesystem full; operator
	// intervention required.
	StorageFull
)

// String returns the canonical wire-side label for the reason. Matches
// the Rust Display impl and the Python StrEnum values.
func (r DropReason) String() string {
	switch r {
	case KernelQueueFull:
		return "kernel queue full"
	case NoObserver:
		return "no observer"
	case PeerGone:
		return "peer gone"
	case StorageFull:
		return "storage full"
	}
	return "unknown"
}

// BeatError is the payload of BeatOutcome.Failed. Errno is the raw
// syscall errno (0 if not OS-derived); Kind is the symbolic name
// ("ENOENT", "EPERM", "Other", …).
type BeatError struct {
	Errno int
	Kind  string
}

// Error satisfies the error interface so callers can log the value
// directly.
func (e BeatError) Error() string {
	return fmt.Sprintf("varta: beat failed (errno=%d kind=%s)", e.Errno, e.Kind)
}

const (
	outcomeSent    = 1
	outcomeDropped = 2
	outcomeFailed  = 3
)

// BeatOutcome is the result of a single Beat call. Modeled as a tagged
// struct because Go lacks Rust's algebraic enums. Use the boolean
// IsSent/IsDropped/IsFailed predicates and the Reason/Error
// accessors; String renders a human-readable form.
type BeatOutcome struct {
	tag    uint8
	reason DropReason
	err    BeatError
}

// IsSent reports whether the kernel accepted the datagram.
func (o BeatOutcome) IsSent() bool { return o.tag == outcomeSent }

// IsDropped reports whether the datagram was not delivered.
func (o BeatOutcome) IsDropped() bool { return o.tag == outcomeDropped }

// IsFailed reports whether an unexpected I/O error occurred.
func (o BeatOutcome) IsFailed() bool { return o.tag == outcomeFailed }

// Reason returns the DropReason. Only valid when IsDropped is true.
func (o BeatOutcome) Reason() DropReason { return o.reason }

// Err returns the BeatError. Only valid when IsFailed is true.
func (o BeatOutcome) Err() BeatError { return o.err }

// String renders the outcome for logging / debugging.
func (o BeatOutcome) String() string {
	switch o.tag {
	case outcomeSent:
		return "sent"
	case outcomeDropped:
		return "dropped: " + o.reason.String()
	case outcomeFailed:
		return o.err.Error()
	}
	return "uninitialized"
}

// BeatOutcomeSent constructs a Sent outcome.
func BeatOutcomeSent() BeatOutcome { return BeatOutcome{tag: outcomeSent} }

// BeatOutcomeDropped constructs a Dropped outcome with the given reason.
func BeatOutcomeDropped(r DropReason) BeatOutcome {
	return BeatOutcome{tag: outcomeDropped, reason: r}
}

// BeatOutcomeFailed constructs a Failed outcome with the given error.
func BeatOutcomeFailed(e BeatError) BeatOutcome {
	return BeatOutcome{tag: outcomeFailed, err: e}
}

// ClassifySendError translates a transport-layer error (typically a
// *net.OpError wrapping a syscall.Errno) into a BeatOutcome. Exported
// so authors of custom transports can apply the same bucketing.
//
// Mirrors crates/varta-client/src/client.rs::classify_send_error and
// clients/python/src/varta/client.py::classify_send_error.
func ClassifySendError(err error) BeatOutcome {
	if err == nil {
		return BeatOutcomeSent()
	}
	switch errnoclass.Classify(err) {
	case errnoclass.BucketKernelQueueFull:
		return BeatOutcomeDropped(KernelQueueFull)
	case errnoclass.BucketNoObserver:
		return BeatOutcomeDropped(NoObserver)
	case errnoclass.BucketPeerGone:
		return BeatOutcomeDropped(PeerGone)
	case errnoclass.BucketStorageFull:
		return BeatOutcomeDropped(StorageFull)
	}
	return BeatOutcomeFailed(BeatError{
		Errno: int(errnoclass.Errno(err)),
		Kind:  errnoclass.Name(err),
	})
}
