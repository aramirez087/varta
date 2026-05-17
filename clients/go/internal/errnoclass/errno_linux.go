//go:build linux

// Package errnoclass holds the platform-specific errno constants and a
// classifier that buckets transport errors into the four-way DropReason
// taxonomy used by the public BeatOutcome.
package errnoclass

import "syscall"

// Linux ENOBUFS = 105 (asm-generic/errno.h).
const ENOBUFS = syscall.ENOBUFS
