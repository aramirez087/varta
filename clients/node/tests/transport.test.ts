// Unit tests for the UDP / SecureUDP transports.

import { test, after } from "node:test";

// node-unix-socket's DgramSocket has no unref() — the native handle is
// always referenced. One setImmediate after all tests complete lets
// libuv drain every pending uv_close() callback so the subprocess can
// exit cleanly without the test runner's timeout killing it.
after(() => new Promise<void>((r) => setImmediate(r)));
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import {
  SecureUdpTransport,
  UdpTransport,
  UdsTransport,
  UdsUnavailableError,
} from "../src/transport.js";
import { decode, encodeInto, FRAME_BYTES, Status } from "../src/vlp.js";
import { decodeShared, decodeMaster } from "../src/vlp_secure.js";
import { bindUdpRecorder, bindUdsRecorder, makeUdsPath } from "./helpers.js";

test("UdpTransport.send delivers a 32-byte frame to a UDP listener", async () => {
  const listener = await bindUdpRecorder();
  try {
    const t = new UdpTransport(listener.host, listener.port);
    const buf = Buffer.alloc(FRAME_BYTES);
    encodeInto(buf, Status.Ok, 12345, 1n, 1n, 0xdeadbeef);
    t.send(buf);
    await listener.wait(1);
    const frame = decode(listener.received[0]!);
    assert.equal(frame.status, Status.Ok);
    assert.equal(frame.pid, 12345);
    assert.equal(frame.payload, 0xdeadbeef);
    t.close();
  } finally {
    await listener.close();
  }
});

test("UdpTransport.reconnect rebuilds the socket and continues to send", async () => {
  const listener = await bindUdpRecorder();
  try {
    const t = new UdpTransport(listener.host, listener.port);
    const buf = Buffer.alloc(FRAME_BYTES);
    encodeInto(buf, Status.Ok, 12345, 1n, 1n, 1);
    t.send(buf);
    await listener.wait(1);
    t.reconnect();
    // Give libuv a tick to bind the new socket's source port.
    await new Promise((r) => setImmediate(r));
    encodeInto(buf, Status.Ok, 12345, 2n, 2n, 2);
    t.send(buf);
    await listener.wait(2);
    const f1 = decode(listener.received[0]!);
    const f2 = decode(listener.received[1]!);
    assert.equal(f1.payload, 1);
    assert.equal(f2.payload, 2);
    t.close();
  } finally {
    await listener.close();
  }
});

test("SecureUdpTransport (shared) wraps a frame and opens with same key", async () => {
  const listener = await bindUdpRecorder();
  try {
    const key = randomBytes(32);
    const t = SecureUdpTransport.shared(listener.host, listener.port, key);
    const buf = Buffer.alloc(FRAME_BYTES);
    encodeInto(buf, Status.Ok, 9999, 1n, 1n, 0xcafe);
    t.send(buf);
    await listener.wait(1);
    assert.equal(listener.received[0]!.length, 60, "secure-shared wire is 60 bytes");
    const plaintext = decodeShared(key, listener.received[0]!);
    const frame = decode(plaintext);
    assert.equal(frame.pid, 9999);
    assert.equal(frame.payload, 0xcafe);
    t.close();
  } finally {
    await listener.close();
  }
});

test("SecureUdpTransport (master) embeds agent PID as AAD", async () => {
  const listener = await bindUdpRecorder();
  try {
    const masterKey = randomBytes(32);
    const t = SecureUdpTransport.master(listener.host, listener.port, masterKey);
    const buf = Buffer.alloc(FRAME_BYTES);
    encodeInto(buf, Status.Ok, process.pid, 1n, 1n, 1);
    t.send(buf);
    await listener.wait(1);
    assert.equal(listener.received[0]!.length, 64, "secure-master wire is 64 bytes");
    const plaintext = decodeMaster(masterKey, listener.received[0]!);
    const frame = decode(plaintext);
    assert.equal(frame.pid, process.pid);
    t.close();
  } finally {
    await listener.close();
  }
});

test("SecureUdpTransport counter advances commit-on-success", async () => {
  const listener = await bindUdpRecorder();
  try {
    const key = randomBytes(32);
    const t = SecureUdpTransport.shared(listener.host, listener.port, key);
    const buf = Buffer.alloc(FRAME_BYTES);
    encodeInto(buf, Status.Ok, 12345, 1n, 1n, 0);
    const c0 = t.__getCounterForTest();
    t.send(buf);
    t.send(buf);
    t.send(buf);
    await listener.wait(3);
    // The counter advances asynchronously inside the libuv callback,
    // but by the time we observe three delivered frames, all three
    // commits must have run.
    const c1 = t.__getCounterForTest();
    assert.equal(c0, 0, "starts at 0");
    assert.equal(c1, 3, "advances exactly once per successful send");
    t.close();
  } finally {
    await listener.close();
  }
});

test("UdsTransport.send delivers a 32-byte frame to a UDS recorder", async (t) => {
  const listener = await bindUdsRecorder();
  if (listener === null) {
    t.skip("node-unix-socket addon not installed; skipping UDS transport test");
    return;
  }
  try {
    const tx = new UdsTransport(listener.path);
    const buf = Buffer.alloc(FRAME_BYTES);
    encodeInto(buf, Status.Ok, 12345, 1n, 1n, 0xabcd);
    tx.send(buf);
    await listener.wait(1);
    const frame = decode(listener.received[0]!);
    assert.equal(frame.status, Status.Ok);
    assert.equal(frame.pid, 12345);
    assert.equal(frame.payload, 0xabcd);
    tx.close();
  } finally {
    await listener.close();
  }
});

test("UdsTransport.reconnect rebuilds the socket", async (t) => {
  const listener = await bindUdsRecorder();
  if (listener === null) {
    t.skip("node-unix-socket addon not installed; skipping UDS transport test");
    return;
  }
  try {
    const tx = new UdsTransport(listener.path);
    const buf = Buffer.alloc(FRAME_BYTES);
    encodeInto(buf, Status.Ok, 12345, 1n, 1n, 1);
    tx.send(buf);
    await listener.wait(1);
    tx.reconnect();
    encodeInto(buf, Status.Ok, 12345, 2n, 2n, 2);
    tx.send(buf);
    await listener.wait(2);
    assert.equal(decode(listener.received[0]!).payload, 1);
    assert.equal(decode(listener.received[1]!).payload, 2);
    tx.close();
  } finally {
    await listener.close();
  }
});

test("UdsTransport surfaces ENOENT when the observer path does not exist", async (t) => {
  let installed = false;
  try {
    await import("node-unix-socket");
    installed = true;
  } catch {
    // Fall through to skip.
  }
  if (!installed) {
    t.skip("node-unix-socket addon not installed; skipping UDS transport test");
    return;
  }
  const { path, cleanup } = makeUdsPath();
  try {
    const tx = new UdsTransport(path);
    const buf = Buffer.alloc(FRAME_BYTES);
    encodeInto(buf, Status.Ok, 1, 1n, 1n, 0);
    // First send queues the error onto pendingError via the
    // sendTo callback (no peer on `path`).
    tx.send(buf);
    // Give libuv a tick to deliver the sendTo callback.
    await new Promise((r) => setTimeout(r, 20));
    let threw: NodeJS.ErrnoException | null = null;
    try {
      tx.send(buf);
    } catch (e) {
      threw = e as NodeJS.ErrnoException;
    }
    assert.ok(threw, "second send must throw the queued ENOENT");
    assert.equal(threw!.code, "ENOENT");
    tx.close();
  } finally {
    cleanup();
  }
});

test("UdsTransport raises UdsUnavailableError when the addon is missing", () => {
  // Smoke-test: we can't truly remove the addon at runtime, but the
  // error class must at least be constructible from outside.
  const err = new UdsUnavailableError(new Error("simulated"));
  assert.equal(err.name, "UdsUnavailableError");
  assert.match(err.message, /node-unix-socket/);
});

test("SecureUdpTransport.reconnect rotates session salt + resets counter", async () => {
  const listener = await bindUdpRecorder();
  try {
    const key = randomBytes(32);
    const t = SecureUdpTransport.shared(listener.host, listener.port, key);
    const beforePrefix = t.__getIvPrefixForTest();
    const buf = Buffer.alloc(FRAME_BYTES);
    encodeInto(buf, Status.Ok, 12345, 1n, 1n, 0);
    t.send(buf);
    t.send(buf);
    await listener.wait(2);
    t.reconnect();
    const afterPrefix = t.__getIvPrefixForTest();
    assert.equal(t.__getCounterForTest(), 0, "counter reset to 0");
    assert.equal(t.__getPrefixIndexForTest(), 0, "prefix index reset to 0");
    assert.notEqual(
      beforePrefix.toString("hex"),
      afterPrefix.toString("hex"),
      "session salt rotated → IV prefix differs",
    );
    t.close();
  } finally {
    await listener.close();
  }
});
