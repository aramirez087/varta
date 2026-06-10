// Unit tests for the `Varta` agent — bucketing, fork detection,
// clock-regression accounting, nonce wrap. Mirrors the Python
// `test_client_unit.py` and Go `client_unit_test.go` contracts.

import { test } from "node:test";
import assert from "node:assert/strict";

import { Varta, __setMonotonicForTest } from "../src/client.js";
import {
  BeatError,
  BeatOutcomes,
  classifySendError,
  DropReason,
} from "../src/outcome.js";
import type { BeatTransport } from "../src/transport.js";
import { decode, NONCE_TERMINAL, Status } from "../src/vlp.js";
import { bindUdpRecorder } from "./helpers.js";

// Always drops on send; reconnect always throws. Drives the
// auto-reconnect threshold logic deterministically without sockets.
class DropAndFailReconnect implements BeatTransport {
  reconnects = 0;
  send(_buf: Buffer): void {
    const e = new Error("mock EAGAIN") as NodeJS.ErrnoException;
    e.code = "EAGAIN";
    e.errno = 11;
    throw e;
  }
  reconnect(): void {
    this.reconnects += 1;
    const e = new Error("mock ECONNREFUSED") as NodeJS.ErrnoException;
    e.code = "ECONNREFUSED";
    e.errno = 111;
    throw e;
  }
  close(): void {}
}

class CountingTransport implements BeatTransport {
  sends = 0;
  reconnects = 0;
  send(_buf: Buffer): void {
    this.sends += 1;
  }
  reconnect(): void {
    this.reconnects += 1;
  }
  close(): void {}
}

function errnoErr(code: string, errno: number): NodeJS.ErrnoException {
  const e = new Error(`mock ${code}`) as NodeJS.ErrnoException;
  e.code = code;
  e.errno = errno;
  return e;
}

test("classifySendError buckets each errno class", () => {
  // EAGAIN / EWOULDBLOCK → KernelQueueFull
  const eagain = classifySendError(errnoErr("EAGAIN", 11));
  assert.equal(eagain.kind, "dropped");
  if (eagain.kind === "dropped") {
    assert.equal(eagain.reason, DropReason.KernelQueueFull);
  }

  // ENOBUFS → KernelQueueFull
  const enobufs = classifySendError(errnoErr("ENOBUFS", 105));
  assert.equal(enobufs.kind, "dropped");
  if (enobufs.kind === "dropped") {
    assert.equal(enobufs.reason, DropReason.KernelQueueFull);
  }

  // ECONNREFUSED → NoObserver
  const refused = classifySendError(errnoErr("ECONNREFUSED", 111));
  assert.equal(refused.kind, "dropped");
  if (refused.kind === "dropped") {
    assert.equal(refused.reason, DropReason.NoObserver);
  }

  // ENOENT → NoObserver
  const enoent = classifySendError(errnoErr("ENOENT", 2));
  assert.equal(enoent.kind, "dropped");
  if (enoent.kind === "dropped") {
    assert.equal(enoent.reason, DropReason.NoObserver);
  }

  // ECONNRESET → PeerGone
  const reset = classifySendError(errnoErr("ECONNRESET", 104));
  assert.equal(reset.kind, "dropped");
  if (reset.kind === "dropped") {
    assert.equal(reset.reason, DropReason.PeerGone);
  }

  // ENOSPC → StorageFull
  const enospc = classifySendError(errnoErr("ENOSPC", 28));
  assert.equal(enospc.kind, "dropped");
  if (enospc.kind === "dropped") {
    assert.equal(enospc.reason, DropReason.StorageFull);
  }

  // Unknown errno → failed
  const weird = classifySendError(errnoErr("EWHATEVER", 9999));
  assert.equal(weird.kind, "failed");
  if (weird.kind === "failed") {
    assert.ok(weird.error instanceof BeatError);
  }
});

test("BeatOutcomes constructors produce the expected discriminants", () => {
  const s = BeatOutcomes.sent();
  assert.equal(s.kind, "sent");

  const d = BeatOutcomes.dropped(DropReason.NoObserver);
  assert.equal(d.kind, "dropped");
  if (d.kind === "dropped") assert.equal(d.reason, DropReason.NoObserver);

  const f = BeatOutcomes.failed(new BeatError(1, "EPERM", "perm"));
  assert.equal(f.kind, "failed");
});

test("beat sends a valid VLP frame to the bound listener", async () => {
  const listener = await bindUdpRecorder();
  try {
    const agent = Varta.connectUdp(listener.host, listener.port);
    const outcome = agent.beat(Status.Ok);
    assert.equal(outcome.kind, "sent");
    await listener.wait(1);
    const frame = decode(listener.received[0]!);
    assert.equal(frame.status, Status.Ok);
    assert.equal(frame.pid, process.pid);
    assert.equal(frame.nonce, 1n);
    assert.equal(frame.payload, 0);
    agent.close();
  } finally {
    await listener.close();
  }
});

test("beat rejects observer-only Stall without side effects", () => {
  for (const status of [Status.Stall, "stall", 3] as const) {
    const transport = new CountingTransport();
    const agent = Varta.fromTransport(transport);

    const outcome = agent.beat(status);

    assert.equal(outcome.kind, "failed");
    if (outcome.kind === "failed") {
      assert.equal(outcome.error.errno, 0);
      assert.equal(outcome.error.kind, "InvalidInput");
    }
    assert.equal(transport.sends, 0);
    assert.equal(transport.reconnects, 0);
    agent.close();
  }
});

test("beat against a closed listener does not throw", async () => {
  // The connected-mode UDP transport may surface ICMP `port unreachable`
  // as `DropReason.NoObserver` (Linux) or stay silent (macOS, where
  // ICMP propagation is racy). Either way, beats must keep returning a
  // structured `BeatOutcome` without crashing the agent.
  const listener = await bindUdpRecorder();
  const { host, port } = listener;
  await listener.close();

  const agent = Varta.connectUdp(host, port);
  for (let i = 0; i < 5; i++) {
    const outcome = agent.beat(Status.Ok);
    assert.ok(
      outcome.kind === "sent" ||
        outcome.kind === "dropped" ||
        outcome.kind === "failed",
      "outcome must be a known discriminant",
    );
  }
  agent.close();
});

test("clock-regression counter increments when monotonic clock goes backwards", async () => {
  const listener = await bindUdpRecorder();
  try {
    let fakeTime = 1_000_000n;
    __setMonotonicForTest(() => fakeTime);
    const agent = Varta.connectUdp(listener.host, listener.port);
    // Advance forward, then jump backward.
    fakeTime = 2_000_000n;
    agent.beat(Status.Ok);
    fakeTime = 1_500_000n; // regression
    agent.beat(Status.Ok);
    assert.equal(agent.clockRegressions(), 1n);
    agent.close();
  } finally {
    __setMonotonicForTest(null);
    await listener.close();
  }
});

test("nonce sequence is monotonic and starts at 1", async () => {
  const listener = await bindUdpRecorder();
  try {
    const agent = Varta.connectUdp(listener.host, listener.port);
    agent.beat(Status.Ok);
    agent.beat(Status.Ok);
    agent.beat(Status.Degraded);
    await listener.wait(3);
    const f1 = decode(listener.received[0]!);
    const f2 = decode(listener.received[1]!);
    const f3 = decode(listener.received[2]!);
    assert.equal(f1.nonce, 1n);
    assert.equal(f2.nonce, 2n);
    assert.equal(f3.nonce, 3n);
    agent.close();
  } finally {
    await listener.close();
  }
});

test("failed reconnect preserves consecutiveDropped for immediate retry", () => {
  // A failed auto-reconnect must NOT disarm the counter: once the
  // threshold is crossed, every subsequent Dropped beat retries the
  // reconnect immediately rather than re-arming a full window. Mirrors
  // the Rust regression and the frozen cross-client contract (reset only
  // on a successful reconnect).
  const transport = new DropAndFailReconnect();
  const agent = Varta.fromTransport(transport);
  agent.setReconnectAfter(2);

  // First drop: 0 -> 1, below threshold, no reconnect attempted.
  assert.equal(agent.beat(Status.Ok).kind, "dropped");
  assert.equal(transport.reconnects, 0);

  // Second drop: crosses the threshold; reconnect attempted and FAILS,
  // so the counter must stay saturated at 2.
  assert.equal(agent.beat(Status.Ok).kind, "dropped");
  assert.equal(transport.reconnects, 1);

  // Third drop: threshold still crossed → reconnect retried immediately.
  assert.equal(agent.beat(Status.Ok).kind, "dropped");
  assert.equal(transport.reconnects, 2);
});

test("__setNonceForTest at NONCE_TERMINAL - 1 triggers wrap to 0", async () => {
  const listener = await bindUdpRecorder();
  try {
    const agent = Varta.connectUdp(listener.host, listener.port);
    agent.__setNonceForTest(NONCE_TERMINAL - 1n);
    agent.beat(Status.Ok); // should wrap
    await listener.wait(1);
    const f = decode(listener.received[0]!);
    assert.equal(f.nonce, 0n, "nonce wrapped to 0 after exhausting space");
    agent.close();
  } finally {
    await listener.close();
  }
});

// ---------------------------------------------------------------------------
// Commit-on-success: a Dropped or Failed send must NOT advance the committed
// nonce/timestamp. Mirrors the Rust regressions in
// crates/varta-client/src/client.rs::tests and the Python / Go equivalents.
// The accepted frame's wire nonce is the observable proof.
// ---------------------------------------------------------------------------

// Drops the first `drops` sends (EAGAIN), then captures the accepted buffer.
class DropThenCapture implements BeatTransport {
  remaining: number;
  last?: Buffer;
  constructor(drops: number) {
    this.remaining = drops;
  }
  send(buf: Buffer): void {
    if (this.remaining > 0) {
      this.remaining -= 1;
      throw errnoErr("EAGAIN", 11);
    }
    this.last = Buffer.from(buf);
  }
  reconnect(): void {}
  close(): void {}
}

// Fails the first send (EACCES → failed), then captures the accepted buffer.
class FailOnceThenCapture implements BeatTransport {
  failed = false;
  last?: Buffer;
  send(buf: Buffer): void {
    if (!this.failed) {
      this.failed = true;
      throw errnoErr("EACCES", 13);
    }
    this.last = Buffer.from(buf);
  }
  reconnect(): void {}
  close(): void {}
}

test("dropped beats do not burn the nonce; first accepted frame carries nonce 1", () => {
  const tr = new DropThenCapture(2);
  const agent = Varta.fromTransport(tr);
  assert.equal(agent.beat(Status.Ok).kind, "dropped");
  assert.equal(agent.beat(Status.Ok).kind, "dropped");
  assert.equal(agent.beat(Status.Ok).kind, "sent");
  assert.ok(tr.last, "a frame was accepted");
  assert.equal(decode(tr.last!).nonce, 1n);
});

test("failed beat does not burn the nonce", () => {
  const tr = new FailOnceThenCapture();
  const agent = Varta.fromTransport(tr);
  assert.equal(agent.beat(Status.Ok).kind, "failed");
  assert.equal(agent.beat(Status.Ok).kind, "sent");
  assert.equal(decode(tr.last!).nonce, 1n);
});

test("reconnect retry commits nonce only on a successful retry", () => {
  const tr = new DropThenCapture(2);
  const agent = Varta.fromTransport(tr);
  agent.setReconnectAfter(2);
  assert.equal(agent.beat(Status.Ok).kind, "dropped");
  // Second drop crosses the threshold; reconnect (no-op success) → retry sends.
  assert.equal(agent.beat(Status.Ok).kind, "sent");
  assert.equal(decode(tr.last!).nonce, 1n);
});

test("dropped wrap attempt does not commit the wrap", () => {
  const tr = new DropThenCapture(1);
  const agent = Varta.fromTransport(tr);
  agent.__setNonceForTest(NONCE_TERMINAL - 1n);
  // Wrap candidate is 0 but the send drops → wrap not committed.
  assert.equal(agent.beat(Status.Ok).kind, "dropped");
  // Next beat wraps for real and is accepted → wire nonce 0 (not 1).
  assert.equal(agent.beat(Status.Ok).kind, "sent");
  assert.equal(decode(tr.last!).nonce, 0n);
});
