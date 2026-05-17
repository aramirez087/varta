// Platform-specific errno constants for parity with the Rust
// `varta-client::classify_send_error`. Mirrors Python's `_errno.py`.
//
// Node exposes runtime errno values via `os.constants.errno`, but the
// `ENOBUFS` symbol is not present on every platform's constant table
// (Linux=105, BSD/macOS=55, illumos/Solaris=132). We hard-code per
// `process.platform` to match the Rust constants exactly.

import { constants as osConstants } from "node:os";

const LINUX_ENOBUFS = 105;
const BSD_ENOBUFS = 55; // macOS / iOS / FreeBSD / NetBSD / OpenBSD / DragonFly
const SOLARIS_ENOBUFS = 132;

function selectEnobufs(): number {
  const p = process.platform;
  if (p === "linux") return LINUX_ENOBUFS;
  if (p === "darwin" || p === "freebsd" || p === "openbsd") {
    return BSD_ENOBUFS;
  }
  if (p === "sunos") return SOLARIS_ENOBUFS;
  // Fall back to whatever the running platform exposes — better than
  // silently using the Linux value on an unknown OS.
  const fromOs = osConstants.errno as Record<string, number>;
  return fromOs.ENOBUFS ?? LINUX_ENOBUFS;
}

const errno = osConstants.errno as Record<string, number>;

export const ENOBUFS = selectEnobufs();
export const ENOSPC = errno.ENOSPC;
export const EAGAIN = errno.EAGAIN;
export const EWOULDBLOCK = errno.EWOULDBLOCK ?? errno.EAGAIN;
export const ECONNREFUSED = errno.ECONNREFUSED;
export const ECONNRESET = errno.ECONNRESET;
export const ENOTCONN = errno.ENOTCONN;
export const EPIPE = errno.EPIPE;
export const ENOENT = errno.ENOENT;

// Reverse-lookup table for symbolic errno names. Used when surfacing
// unexpected `BeatOutcome.failed` results so the caller's log line has
// "ENOENT" instead of just "errno=2".
const NAME_BY_CODE: Map<number, string> = (() => {
  const m = new Map<number, string>();
  for (const [name, code] of Object.entries(errno)) {
    if (!m.has(code as number)) m.set(code as number, name);
  }
  return m;
})();

export function errnoName(code: number | null | undefined): string {
  if (code === null || code === undefined || code === 0) return "Unknown";
  return NAME_BY_CODE.get(code) ?? `errno_${code}`;
}
