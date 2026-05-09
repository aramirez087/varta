package health.varta;

import org.junit.jupiter.api.Test;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;

class ForkSafetyTest {

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
