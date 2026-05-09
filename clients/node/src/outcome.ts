// BeatOutcome tagged union, DropReason enum, BeatError, and the
// `classifySendError` function — mirrors Rust `BeatOutcome`,
// Python `BeatOutcome`/`DropReason`, and Go `BeatOutcome`/`DropReason`.

import {
  EAGAIN,
  ECONNREFUSED,
  ECONNRESET,
  ENOBUFS,
  ENOENT,
  ENOSPC,
  ENOTCONN,
  EPIPE,
  EWOULDBLOCK,
  errnoName,
} from "./errno.js";

// String-valued enum so the wire-side metrics label matches the Rust
// `Display` impl directly. The string values MUST stay byte-equal to
// the labels Prometheus sees from the observer (`varta_*_total{reason=…}`).
export enum DropReason {
  KernelQueueFull = "kernel queue full",
  NoObserver = "no observer",
  PeerGone = "peer gone",
  StorageFull = "storage full",
}

// Payload of `{ kind: "failed" }`. Extends `Error` so it can be thrown
// or logged like any other Node error, but carries structured `errno`
// and `kind` fields so callers don't have to parse `.message`.
export class BeatError extends Error {
  readonly errno: number;
  readonly kind: string;
  constructor(errno: number, kind: string, message?: string) {
    super(message ?? `${kind} (errno=${errno})`);
    this.name = "BeatError";
    this.errno = errno;
    this.kind = kind;
  }

  static fromNodeError(err: NodeJS.ErrnoException): BeatError {
    const code = typeof err.errno === "number" ? err.errno : 0;
    return new BeatError(code, code ? errnoName(code) : err.name || "Other", err.message);
  }
}

// Discriminated-union shape for results of `Varta.beat`. Mirrors the
// Rust algebraic enum and Python frozen dataclass.
export type BeatOutcome =
  | { readonly kind: "sent" }
  | { readonly kind: "dropped"; readonly reason: DropReason }
  | { readonly kind: "failed"; readonly error: BeatError };

export const BeatOutcomes = Object.freeze({
  sent(): BeatOutcome {
    return { kind: "sent" };
  },
  dropped(reason: DropReason): BeatOutcome {
    return { kind: "dropped", reason };
  },
  failed(error: BeatError): BeatOutcome {
    return { kind: "failed", error };
  },
});

export function isSent(o: BeatOutcome): boolean {
  return o.kind === "sent";
}
export function isDropped(o: BeatOutcome): boolean {
  return o.kind === "dropped";
}
export function isFailed(o: BeatOutcome): boolean {
  return o.kind === "failed";
}

// Translate a Node `send`-time error into a `BeatOutcome`.
//
// Mirrors `crates/varta-client/src/client.rs::classify_send_error` and
// the Python and Go equivalents. Exported because authors of custom
// `BeatTransport` implementations are likely to want the same bucketing.
export function classifySendError(err: NodeJS.ErrnoException): BeatOutcome {
  // Node's `ErrnoException.errno` is the negative POSIX value on some
  // calls (libuv convention) and the positive value on others. Take
  // the absolute value so the comparisons below work uniformly.
  const rawErrno = typeof err.errno === "number" ? err.errno : 0;
  const code = rawErrno < 0 ? -rawErrno : rawErrno;
  const sym = err.code ?? "";

  if (code === ENOBUFS || sym === "ENOBUFS") {
    return BeatOutcomes.dropped(DropReason.KernelQueueFull);
  }
  if (
    code === EAGAIN ||
    code === EWOULDBLOCK ||
    sym === "EAGAIN" ||
    sym === "EWOULDBLOCK"
  ) {
    return BeatOutcomes.dropped(DropReason.KernelQueueFull);
  }
  if (
    code === ECONNREFUSED ||
    code === ENOENT ||
    sym === "ECONNREFUSED" ||
    sym === "ENOENT"
  ) {
    return BeatOutcomes.dropped(DropReason.NoObserver);
  }
  if (
    code === ECONNRESET ||
    code === ENOTCONN ||
    code === EPIPE ||
    sym === "ECONNRESET" ||
    sym === "ENOTCONN" ||
    sym === "EPIPE"
  ) {
    return BeatOutcomes.dropped(DropReason.PeerGone);
  }
  if (code === ENOSPC || sym === "ENOSPC") {
    return BeatOutcomes.dropped(DropReason.StorageFull);
  }
  return BeatOutcomes.failed(BeatError.fromNodeError(err));
}
