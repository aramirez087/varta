package health.varta;

import health.varta.transport.BeatTransport;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

class ForkSafetyTest {

    /**
     * Transport whose {@code reconnect()} always fails with an exception whose
     * message would otherwise be classified as a transient drop.
     */
    private static final class ReconnectRefused implements BeatTransport {
        @Override
        public int send(ByteBuffer frame) {
            return Varta.FRAME_BYTES;
        }

        @Override
        public void reconnect() throws IOException {
            // "connection refused" maps to Dropped(NO_OBSERVER) in
            // ErrnoClassifier — the exact misclassification this test guards.
            throw new IOException("Connection refused");
        }

        @Override
        public void close() {
        }
    }

    @Test
    void fork_reconnect_failure_returns_failed_not_dropped() {
        // Regression (bug-480 sibling): a fork-recovery reconnect failure is a
        // terminal error and must surface as Failed, matching the Rust
        // reference and every other client (Go/Python/Node/.NET). Java alone
        // routed it through ErrnoClassifier, so a "connection refused" reconnect
        // exception was misclassified as Dropped(NO_OBSERVER) — telling the
        // caller the beat path was still operational when fork recovery had
        // failed.
        Varta agent = Varta.__forTest(new ReconnectRefused());
        agent.__setConnectPidForTest(31337); // force the fork-recovery branch

        BeatOutcome o = agent.beat(Status.OK);

        assertThat(o.isFailed())
            .as("a failed fork-recovery reconnect must surface as Failed, not Dropped")
            .isTrue();
        assertThat(o).isNotInstanceOf(BeatOutcome.Dropped.class);
    }

    @Test
    void changing_connect_pid_triggers_reconnect_and_resets_nonce() throws Exception {
        try (DatagramSocket rec = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
             Varta agent = Varta.connectUdp(
                 new InetSocketAddress(InetAddress.getLoopbackAddress(), rec.getLocalPort()))) {

            agent.beat(Status.OK);
            agent.beat(Status.OK);
            assertThat(agent.__getNonceForTest()).isEqualTo(3L); // 1, 2 consumed → next is 3

            // Simulate fork(2) by spoofing the cached connect PID.
            agent.__setConnectPidForTest(31337);
            long forkCountBefore = agent.forkRecoveries();

            BeatOutcome o = agent.beat(Status.OK);
            assertThat(o.isFailed()).isFalse(); // reconnect succeeded
            assertThat(agent.forkRecoveries()).isEqualTo(forkCountBefore + 1);
            // After fork-recovery the nonce resets to NONCE_MIN and the next beat used it.
            assertThat(agent.__getNonceForTest()).isEqualTo(2L);
        }
    }
}
