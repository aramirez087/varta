package health.varta.transport;

import org.junit.jupiter.api.Test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class UdpTransportTest {

    @Test
    void send_delivers_one_frame_to_loopback_recorder() throws Exception {
        try (DatagramSocket recorder = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
             UdpTransport tx = UdpTransport.create(
                 new InetSocketAddress(InetAddress.getLoopbackAddress(), recorder.getLocalPort()))) {

            byte[] payload = new byte[32];
            for (int i = 0; i < 32; i++) payload[i] = (byte) i;
            int sent = tx.send(ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN));
            assertThat(sent).isEqualTo(32);

            recorder.setSoTimeout(2000);
            DatagramPacket pkt = new DatagramPacket(new byte[64], 64);
            recorder.receive(pkt);
            assertThat(Arrays.copyOf(pkt.getData(), pkt.getLength())).isEqualTo(payload);
        }
    }

    @Test
    void reconnect_replaces_channel_without_throwing() throws Exception {
        try (DatagramSocket recorder = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
             UdpTransport tx = UdpTransport.create(
                 new InetSocketAddress(InetAddress.getLoopbackAddress(), recorder.getLocalPort()))) {
            assertThatNoException().isThrownBy(tx::reconnect);
            // Send still works after reconnect.
            byte[] payload = new byte[32];
            assertThat(tx.send(ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN))).isEqualTo(32);
        }
    }
}
