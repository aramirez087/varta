package health.varta;

import org.junit.jupiter.api.Test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;

class VartaAgentTest {

    @Test
    void beat_over_udp_round_trips_to_recorder() throws Exception {
        try (DatagramSocket recorder = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0))) {
            int port = recorder.getLocalPort();
            try (Varta agent = Varta.connectUdp(
                    new InetSocketAddress(InetAddress.getLoopbackAddress(), port))) {

                BeatOutcome outcome = agent.beat(Status.OK, 0xCAFEBABE);
                assertThat(outcome).isInstanceOf(BeatOutcome.Sent.class);

                recorder.setSoTimeout(2000);
                DatagramPacket pkt = new DatagramPacket(new byte[64], 64);
                recorder.receive(pkt);
                assertThat(pkt.getLength()).isEqualTo(Varta.FRAME_BYTES);
                // Decode and assert structural fields.
                Frame frame = Frame.decode(java.util.Arrays.copyOf(pkt.getData(), pkt.getLength()));
                assertThat(frame.status()).isEqualTo(Status.OK);
                assertThat(frame.payload()).isEqualTo(0xCAFEBABE);
                assertThat(frame.nonce()).isEqualTo(1L);
            }
        }
    }

    @Test
    void beat_without_observer_surfaces_dropped_no_observer() throws Exception {
        // Pick an ephemeral port, then close the recorder. Subsequent beats
        // see ICMP unreachable (Linux) or ECONNREFUSED (macOS) → NO_OBSERVER.
        DatagramSocket rec = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
        int port = rec.getLocalPort();
        rec.close();

        try (Varta agent = Varta.connectUdp(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), port))) {
            // First beat goes through; ICMP unreachable arrives async.
            agent.beat(Status.OK);
            Thread.sleep(50);
            // Second beat should observe the unreachable signal.
            BeatOutcome second = agent.beat(Status.OK);
            // Either NO_OBSERVER (preferred) or a sent (kernel never delivered the ICMP).
            // The contract: it must not throw or return Failed.
            assertThat(second.isFailed()).isFalse();
        }
    }

    @Test
    void clock_regressions_and_fork_recoveries_start_at_zero() throws Exception {
        try (DatagramSocket rec = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
             Varta agent = Varta.connectUdp(
                 new InetSocketAddress(InetAddress.getLoopbackAddress(), rec.getLocalPort()))) {
            assertThat(agent.clockRegressions()).isZero();
            assertThat(agent.forkRecoveries()).isZero();
        }
    }

    @Test
    void close_is_idempotent() throws Exception {
        try (DatagramSocket rec = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0))) {
            Varta agent = Varta.connectUdp(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), rec.getLocalPort()));
            agent.close();
            agent.close();
            // Beat after close returns Failed, never throws.
            assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Failed.class);
        }
    }
}
