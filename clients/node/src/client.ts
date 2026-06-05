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

    if (this.nonce < NONCE_TERMINAL - 1n) {
      this.nonce = this.nonce + 1n;
    } else {
      warnNonceWrapping();
      this.nonce = 0n;
    }

    let rawElapsed = monotonicNs() - this.startNs;
    if (rawElapsed < 0n) rawElapsed = 0n;
    if (rawElapsed > U64_MAX) rawElapsed = U64_MAX;
    if (rawElapsed < this.lastTimestamp) {
      this.clockRegressionsCount = satAddBig(this.clockRegressionsCount, 1n);
    }
    const ts = rawElapsed > this.lastTimestamp ? rawElapsed : this.lastTimestamp;
    this.lastTimestamp = ts;

    encodeInto(this.buf, status, pid, ts, this.nonce, payload);

    const outcome = this.sendFrame();
    if (outcome.kind === "dropped") {
      this.consecutiveDropped = Math.min(
        this.consecutiveDropped + 1,
        Number.MAX_SAFE_INTEGER,
      );
      if (
        this.reconnectAfter > 0 &&
        this.consecutiveDropped >= this.reconnectAfter
      ) {
        try {
          this.transport.reconnect();
        } catch {
          // Failed reconnect leaves the counter saturated so the next
          // Dropped beat re-crosses the threshold and retries immediately,
          // rather than re-arming a full reconnectAfter-beat window.
          return outcome;
        }
        // Reset only on a successful reconnect.
        this.consecutiveDropped = 0;
        return this.sendFrame();
      }
      return outcome;
    }

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
