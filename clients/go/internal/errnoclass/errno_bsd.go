//go:build darwin || freebsd || netbsd || openbsd || dragonfly || ios

package errnoclass

import "syscall"

// BSD-family ENOBUFS = 55 (sys/errno.h on macOS / FreeBSD / NetBSD /
// OpenBSD / DragonFly / iOS).
const ENOBUFS = syscall.ENOBUFS
