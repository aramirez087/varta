//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !ios

package errnoclass

import "syscall"

// Other Unix-likes: defer to syscall.ENOBUFS if defined, else fall back
// to the Linux value. The client compiles on any Unix that satisfies
// the build tags above; this branch is a structural fallback.
const ENOBUFS = syscall.ENOBUFS
