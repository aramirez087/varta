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
import { decode, NONCE_TERMINAL, Status } from "../src/vlp.js";
import { bindUdpRecorder } from "./helpers.js";

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
