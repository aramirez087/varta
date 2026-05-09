package errnoclass

import (
	"errors"
	"syscall"
)

// Bucket enumerates the four-way drop taxonomy. The root varta package
// re-exports these as DropReason constants.
type Bucket int

const (
	BucketNone Bucket = iota
	BucketKernelQueueFull
	BucketNoObserver
	BucketPeerGone
	BucketStorageFull
)

// Errno extracts a syscall.Errno from a wrapped net.OpError /
// os.PathError / etc. Returns 0 if no errno can be recovered.
func Errno(err error) syscall.Errno {
	var e syscall.Errno
	if errors.As(err, &e) {
		return e
	}
	return 0
}

// Classify maps a syscall errno to a Bucket. Anything unrecognised
// returns BucketNone — the caller surfaces those as BeatOutcome.Failed.
//
// Mirrors crates/varta-client/src/client.rs::classify_send_error and
// clients/python/src/varta/client.py::classify_send_error.
//
// EAGAIN and EWOULDBLOCK share a value on most Unixes, so an if/else
// chain (not a switch) is used to dodge the duplicate-case compile
// error.
func Classify(err error) Bucket {
	e := Errno(err)
	if e == 0 {
		return BucketNone
	}
	if e == ENOBUFS || e == syscall.EAGAIN || e == syscall.EWOULDBLOCK {
		return BucketKernelQueueFull
	}
	if e == syscall.ECONNREFUSED || e == syscall.ENOENT {
		return BucketNoObserver
	}
	if e == syscall.ECONNRESET || e == syscall.ENOTCONN || e == syscall.EPIPE {
		return BucketPeerGone
	}
	if e == syscall.ENOSPC {
		return BucketStorageFull
	}
	return BucketNone
}

// Name returns the symbolic errno name (e.g. "ENOENT", "EPERM") or
// "Other" if unknown. Used to populate BeatError.Kind for the failed
// outcome variant.
func Name(err error) string {
	e := Errno(err)
	if e == 0 {
		return "Other"
	}
	if e == syscall.EAGAIN {
		return "EAGAIN"
	}
	if e == syscall.EWOULDBLOCK {
		return "EWOULDBLOCK"
	}
	if e == ENOBUFS {
		return "ENOBUFS"
	}
	if e == syscall.ECONNREFUSED {
		return "ECONNREFUSED"
	}
	if e == syscall.ECONNRESET {
		return "ECONNRESET"
	}
	if e == syscall.ENOTCONN {
		return "ENOTCONN"
	}
	if e == syscall.EPIPE {
		return "EPIPE"
	}
	if e == syscall.ENOENT {
		return "ENOENT"
	}
	if e == syscall.ENOSPC {
		return "ENOSPC"
	}
	if e == syscall.EPERM {
		return "EPERM"
	}
	if e == syscall.EACCES {
		return "EACCES"
	}
	if e == syscall.EINVAL {
		return "EINVAL"
	}
	return e.Error()
}
