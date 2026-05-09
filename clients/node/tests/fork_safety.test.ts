// Fork-safety test. Node provides no `fork(2)` primitive at the JS
// level — `child_process.fork` spawns a new V8 process. The Python and
// Go ports drive their fork-recovery counter via a test hook
// (`_set_connect_pid_for_test` / `SetConnectPIDForTest`) and we do the
// same here.

import { test } from "node:test";
import assert from "node:assert/strict";

import { Varta } from "../src/client.js";
import { decode, Status } from "../src/vlp.js";
import { bindUdpRecorder } from "./helpers.js";

test("__setConnectPidForTest triggers a transport rebuild + fork recovery counter", async () => {
  const listener = await bindUdpRecorder();
  try {
    const agent = Varta.connectUdp(listener.host, listener.port);
    agent.beat(Status.Ok);
    assert.equal(agent.forkRecoveries(), 0n);
    await listener.wait(1);

    // Pretend the agent was constructed in a different process and we
    // are now executing in a forked child whose PID does not match.
    agent.__setConnectPidForTest(process.pid + 1);
    // The beat() call triggers transport.reconnect(); give libuv a
    // tick to bind the new ephemeral source port before the next send.
    agent.beat(Status.Ok);
    assert.equal(agent.forkRecoveries(), 1n);
    await new Promise((r) => setImmediate(r));

    // After fork recovery, the nonce is reset and the next beat carries nonce=1.
    await listener.wait(2);
    const second = decode(listener.received[1]!);
    assert.equal(second.nonce, 1n, "fork recovery resets nonce to 0 → first beat after is 1");
    agent.close();
  } finally {
    await listener.close();
  }
});
