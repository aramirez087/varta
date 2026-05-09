// Tests for `panic.installSignalHandler*`.
//
// We exercise the installer error paths and the wire-format of the
// pre-built critical frame; running the full uncaughtException → emit
// pathway requires spawning a child process (similar to the Python
// `test_panic_hook.py` strategy), which we do at the end.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { join } from "node:path";

import {
  PanicInstallError,
  installSignalHandlerSecureUdp,
  installSignalHandlerUds,
} from "../src/panic.js";
import { decode, NONCE_TERMINAL, Status } from "../src/vlp.js";
import { decodeShared } from "../src/vlp_secure.js";
import { bindUdpRecorder, bindUdsRecorder, repoRoot } from "./helpers.js";

test("installSignalHandlerSecureUdp rejects wrong-length keys", () => {
  try {
    installSignalHandlerSecureUdp("127.0.0.1", 5876, Buffer.alloc(31));
    assert.fail("expected RangeError");
  } catch (err) {
    assert.ok(err instanceof RangeError, `got ${err}`);
  }
});

test("PanicInstallError is shaped like the Python/Go panic install errors", () => {
  const e = new PanicInstallError("SocketBind", "boom");
  assert.equal(e.kind, "SocketBind");
  assert.match(e.message, /SocketBind/);
  assert.ok(e instanceof Error);
});

test("uncaughtException triggers critical+NONCE_TERMINAL beat (via child process)", async () => {
  const listener = await bindUdpRecorder();
  try {
    const script = `
      import("${join(repoRoot(), "clients", "node", "src", "panic.ts").replace(/\\\\/g, "\\\\\\\\")}")
        .then(({ installSignalHandlerUdp }) => {
          installSignalHandlerUdp("${listener.host}", ${listener.port});
          setTimeout(() => { throw new Error("intentional"); }, 50);
        });
    `;
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "-e", script],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    // Drain stderr so the child doesn't block on its crash output.
    child.stderr.resume();
    child.stdout.resume();

    await listener.wait(1, 5000);
    try {
      child.kill("SIGKILL");
    } catch {
      // Already dead.
    }

    const frame = decode(listener.received[0]!);
    assert.equal(frame.status, Status.Critical, "panic beat is Critical");
    assert.equal(frame.nonce, NONCE_TERMINAL, "panic beat carries NONCE_TERMINAL");
  } finally {
    await listener.close();
  }
});

test("installSignalHandlerUds throws PanicInstallError when the addon is missing", async (t) => {
  // If the addon is installed, the runtime exercise is covered by the
  // subsequent UDS panic test; here we only assert the addon-missing
  // surface signature.
  let installed = false;
  try {
    await import("node-unix-socket");
    installed = true;
  } catch {
    // Not installed — exercise the error path.
  }
  if (installed) {
    t.skip("addon installed; runtime exercise covered by next test");
    return;
  }
  try {
    installSignalHandlerUds("/nonexistent/varta.sock");
    assert.fail("expected PanicInstallError when addon is missing");
  } catch (err) {
    assert.ok(err instanceof PanicInstallError, `got ${err}`);
    assert.equal((err as PanicInstallError).kind, "UdsUnavailable");
  }
});

test("uncaughtException over UDS triggers a critical+NONCE_TERMINAL beat", async (t) => {
  const listener = await bindUdsRecorder();
  if (listener === null) {
    t.skip("node-unix-socket addon not installed; skipping UDS panic test");
    return;
  }
  try {
    const script = `
      import("${join(repoRoot(), "clients", "node", "src", "panic.ts").replace(/\\\\/g, "\\\\\\\\")}")
        .then(({ installSignalHandlerUds }) => {
          installSignalHandlerUds(${JSON.stringify(listener.path)});
          setTimeout(() => { throw new Error("intentional uds"); }, 50);
        });
    `;
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "-e", script],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    child.stderr.resume();
    child.stdout.resume();

    await listener.wait(1, 5000);
    try {
      child.kill("SIGKILL");
    } catch {
      // Already dead.
    }

    const frame = decode(listener.received[0]!);
    assert.equal(frame.status, Status.Critical, "panic beat is Critical");
    assert.equal(frame.nonce, NONCE_TERMINAL, "panic beat carries NONCE_TERMINAL");
  } finally {
    await listener.close();
  }
});

test("uncaughtException over secure UDP wraps a NONCE_TERMINAL critical beat", async () => {
  const listener = await bindUdpRecorder();
  try {
    const keyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const script = `
      import("${join(repoRoot(), "clients", "node", "src", "panic.ts").replace(/\\\\/g, "\\\\\\\\")}")
        .then(({ installSignalHandlerSecureUdp }) => {
          installSignalHandlerSecureUdp("${listener.host}", ${listener.port}, Buffer.from("${keyHex}", "hex"));
          setTimeout(() => { throw new Error("intentional secure"); }, 50);
        });
    `;
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "-e", script],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    child.stderr.resume();
    child.stdout.resume();

    await listener.wait(1, 5000);
    try {
      child.kill("SIGKILL");
    } catch {
      // Already dead.
    }

    const wire = listener.received[0]!;
    assert.equal(wire.length, 60, "secure-shared wire is 60 bytes");
    const plaintext = decodeShared(Buffer.from(keyHex, "hex"), wire);
    const frame = decode(plaintext);
    assert.equal(frame.status, Status.Critical);
    assert.equal(frame.nonce, NONCE_TERMINAL);
  } finally {
    await listener.close();
  }
});
