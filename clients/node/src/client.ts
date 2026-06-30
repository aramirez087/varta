// Agent surface — `Varta` connects to the observer and emits
// fire-and-forget 32-byte VLP frames.
//
// Mirrors the Rust reference at `crates/varta-client/src/client.rs`
// and the Python/Go ports under `clients/{python,go}/`. Hot-path
// invariants preserved:
//
//   * Non-blocking I/O. Node's libuv enqueues to the kernel; any
//     `ENOBUFS` / `EAGAIN` surfaces on the next beat through the
//     transport's `pendingError` slot.
//   * Per-emission `process.pid`. No PID caching — forked children
//     report their own identity on the next beat.
//   * Fork auto-detection. On PID mismatch we call
//     `transport.reconnect()` BEFORE encoding the frame; for
//     secure-UDP that re-reads `crypto.randomBytes` so IV state is
//     rotated before any frame leaves the child.
//   * Clock-regression detection runs BEFORE the monotonic clamp so
//     wire-format monotonicity is preserved while the underlying
//     event is observable.
//   * Nonce wraps with a single-shot stderr warning, never silently.

import {
  BeatError,
  BeatOutcomes,
  classifySendError,
  DropReason,
  type BeatOutcome,
} from "./outcome.js";
import {
  type BeatTransport,
  SecureUdpTransport,
  UdpTransport,
  UdsTransport,
} from "./transport.js";
import {
  encodeInto,
  FRAME_BYTES,
  NONCE_TERMINAL,
  Status,
  type StatusLike,
} from "./vlp.js";

const U64_MAX: bigint = 0xffffffffffffffffn;

function satAddBig(value: bigint, delta: bigint): bigint {
  const next = value + delta;
  return next > U64_MAX ? U64_MAX : next;
}

let nonceWrapWarned = false;
function warnNonceWrapping(): void {
  if (nonceWrapWarned) return;
  nonceWrapWarned = true;
  try {
    process.stderr.write("[varta] nonce exhausted; wrapping to 0\n");
  } catch {
    // stderr unavailable — give up silently.
  }
}

// `process.hrtime.bigint()` is monotonic and unaffected by NTP slew.
// We expose this through a tiny indirection so unit tests can clamp the
// clock without touching the global.
let monotonicNs: () => bigint = () => process.hrtime.bigint();

export function __setMonotonicForTest(fn: (() => bigint) | null): void {
  monotonicNs = fn ?? (() => process.hrtime.bigint());
}

function coerceBeatStatus(status: StatusLike): Status | null {
  if (typeof status === "string") {
    switch (status.toLowerCase()) {
      case "ok":
        return Status.Ok;
      case "degraded":
        return Status.Degraded;
      case "critical":
        return Status.Critical;
      case "stall":
        return Status.Stall;
      default:
        return null;
    }
  }
  if (
    status === Status.Ok ||
    status === Status.Degraded ||
    status === Status.Critical ||
    status === Status.Stall
  ) {
    return status as Status;
  }
  return null;
}

export class Varta {
  private transport: BeatTransport;
  private readonly buf: Buffer;
  private startNs: bigint;
  private nonce: bigint;
  private consecutiveDropped: number;
  private reconnectAfter: number;
  private lastTimestamp: bigint;
  private clockRegressionsCount: bigint;
  private connectPid: number;
  private forkRecoveriesCount: bigint;
  private closed: boolean;

  private constructor(transport: BeatTransport) {
    this.transport = transport;
    this.buf = Buffer.alloc(FRAME_BYTES);
    this.startNs = monotonicNs();
    this.nonce = 0n;
    this.consecutiveDropped = 0;
    this.reconnectAfter = 0;
    this.lastTimestamp = 0n;
    this.clockRegressionsCount = 0n;
    this.connectPid = process.pid;
    this.forkRecoveriesCount = 0n;
    this.closed = false;
  }

  // ─── constructors ─────────────────────────────────────────────

  // Connect to a `varta-watch` observer over a Unix domain datagram
  // socket. Requires the optional `node-unix-socket` addon; raises
  // `UdsUnavailableError` if it could not be loaded (missing prebuild,
  // Windows, etc.). Preferred same-host transport: gives the observer
  // kernel-attested `BeatOrigin` and unlocks recovery eligibility.
  static connectUds(path: string): Varta {
    return new Varta(new UdsTransport(path));
  }

  static connectUdp(host: string, port: number): Varta {
    return new Varta(new UdpTransport(host, port));
  }

  static connectSecureUdp(host: string, port: number, key: Buffer): Varta {
    return new Varta(SecureUdpTransport.shared(host, port, key));
  }

  static connectSecureUdpWithMaster(
    host: string,
    port: number,
    masterKey: Buffer,
  ): Varta {
    return new Varta(SecureUdpTransport.master(host, port, masterKey));
  }

  // Lower-level escape hatch for users with a custom `BeatTransport`.
  // Stays unstable in 0.x.
  static fromTransport(transport: BeatTransport): Varta {
    return new Varta(transport);
  }

  // ─── public API ───────────────────────────────────────────────

  beat(status: StatusLike, payload: number = 0): BeatOutcome {
    const statusValue = coerceBeatStatus(status);
    if (statusValue === null || statusValue === Status.Stall) {
      this.consecutiveDropped = 0;
      return BeatOutcomes.failed(new BeatError(0, "InvalidInput"));
    }
    if (this.closed) {
      this.consecutiveDropped = 0;
      return BeatOutcomes.failed(new BeatError(0, "Closed"));
    }

    const pid = process.pid;
    if (pid !== this.connectPid) {
      try {
        this.transport.reconnect();
      } catch (err) {
        return BeatOutcomes.failed(BeatError.fromNodeError(err as NodeJS.ErrnoException));
      }
      this.connectPid = pid;
      this.forkRecoveriesCount = satAddBig(this.forkRecoveriesCount, 1n);
      this.nonce = 0n;
      this.startNs = monotonicNs();
      this.lastTimestamp = 0n;
      this.consecutiveDropped = 0;
    }

    // Compute the nonce and timestamp CANDIDATES without mutating the
    // committed counters; they advance only when send accepts the datagram
    // (commit-on-success). A Dropped or Failed attempt leaves the same
    // candidate available for the next beat, so no invisible nonce/timestamp
    // is burned on the wire. Mirrors crates/varta-client/src/client.rs
    // (next_regular_nonce / commit_sent_frame).
    let candidateNonce: bigint;
    let wrappedNonce = false;
    if (this.nonce < NONCE_TERMINAL - 1n) {
      candidateNonce = this.nonce + 1n;
    } else {
      candidateNonce = 0n;
      wrappedNonce = true;
    }

    let rawElapsed = monotonicNs() - this.startNs;
    if (rawElapsed < 0n) rawElapsed = 0n;
    if (rawElapsed > U64_MAX) rawElapsed = U64_MAX;
    if (rawElapsed < this.lastTimestamp) {
      this.clockRegressionsCount = satAddBig(this.clockRegressionsCount, 1n);
    }
    const candidateTimestamp =
      rawElapsed > this.lastTimestamp ? rawElapsed : this.lastTimestamp;

    encodeInto(this.buf, statusValue, pid, candidateTimestamp, candidateNonce, payload);

    const outcome = this.sendFrame();
    if (outcome.kind === "sent") {
      this.commitSentFrame(candidateNonce, candidateTimestamp, wrappedNonce);
      this.consecutiveDropped = 0;
      return outcome;
    }
    if (outcome.kind === "dropped") {
      this.consecutiveDropped = Math.min(
        this.consecutiveDropped + 1,
        Number.MAX_SAFE_INTEGER,
      );
      if (
        this.reconnectAfter > 0 &&
        this.consecutiveDropped >= this.reconnectAfter
      ) {
        this.consecutiveDropped = 0;
        try {
          this.transport.reconnect();
        } catch {
          return outcome;
        }
        const retry = this.sendFrame();
        if (retry.kind === "sent") {
          this.commitSentFrame(candidateNonce, candidateTimestamp, wrappedNonce);
        }
        return retry;
      }
      return outcome;
    }

    // Failed: leave nonce/timestamp uncommitted; reset the dropped run
    // (matches the Rust BeatOutcome::Failed arm).
    this.consecutiveDropped = 0;
    return outcome;
  }

  reconnect(): void {
    this.transport.reconnect();
    this.connectPid = process.pid;
  }

  setReconnectAfter(n: number | null): void {
    this.reconnectAfter = n && n > 0 ? Math.trunc(n) : 0;
    this.consecutiveDropped = 0;
  }

  // Saturating count of platform-clock regressions observed.
  // Suggested Prometheus label: `varta_client_clock_regression_total`.
  clockRegressions(): bigint {
    return this.clockRegressionsCount;
  }

  // Saturating count of fork auto-recovery events.
  // Suggested Prometheus label: `varta_client_fork_recoveries_total`.
  forkRecoveries(): bigint {
    return this.forkRecoveriesCount;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.transport.close();
  }

  // ─── internal ─────────────────────────────────────────────────

  private sendFrame(): BeatOutcome {
    try {
      this.transport.send(this.buf);
      return BeatOutcomes.sent();
    } catch (err) {
      return classifySendError(err as NodeJS.ErrnoException);
    }
  }

  // Advance the committed nonce/timestamp only after the kernel accepted the
  // datagram. The one-shot wrap warning fires here so it is emitted only for a
  // frame that actually reached the wire.
  private commitSentFrame(
    nonce: bigint,
    timestamp: bigint,
    wrapped: boolean,
  ): void {
    this.nonce = nonce;
    this.lastTimestamp = timestamp;
    if (wrapped) warnNonceWrapping();
  }

  // ─── test hooks (underscore-prefixed; not part of the public surface) ─

  __setConnectPidForTest(pid: number): void {
    this.connectPid = pid >>> 0;
  }

  __setNonceForTest(value: bigint): void {
    this.nonce = value;
  }
}

// Re-export Status for ergonomic call sites: `agent.beat(Status.Ok)`.
export { Status, DropReason };
