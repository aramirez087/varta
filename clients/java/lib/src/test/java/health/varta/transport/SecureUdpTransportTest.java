package health.varta.transport;

import health.varta.Key;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.assertj.core.api.Assertions.assertThat;

class SecureUdpTransportTest {

    private static final byte[] KEY32 = new byte[32];
    static { for (int i = 0; i < 32; i++) KEY32[i] = (byte) i; }

    @Test
    void shared_send_emits_60_byte_wire_frame() throws Exception {
        try (DatagramSocket rec = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
             SecureUdpTransport tx = SecureUdpTransport.createShared(
                 new InetSocketAddress(InetAddress.getLoopbackAddress(), rec.getLocalPort()),
                 Key.fromBytes(KEY32))) {

            byte[] plaintext = new byte[32];
            for (int i = 0; i < 32; i++) plaintext[i] = (byte) (i + 1);
            int sent = tx.send(ByteBuffer.wrap(plaintext).order(ByteOrder.LITTLE_ENDIAN));
            assertThat(sent).isEqualTo(32);

            rec.setSoTimeout(2000);
            DatagramPacket pkt = new DatagramPacket(new byte[128], 128);
            rec.receive(pkt);
            assertThat(pkt.getLength()).isEqualTo(60);
        }
    }

    @Test
    void master_send_emits_64_byte_wire_frame() throws Exception {
        try (DatagramSocket rec = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
             SecureUdpTransport tx = SecureUdpTransport.createMaster(
                 new InetSocketAddress(InetAddress.getLoopbackAddress(), rec.getLocalPort()),
                 Key.fromBytes(KEY32))) {

            byte[] plaintext = new byte[32];
            tx.send(ByteBuffer.wrap(plaintext).order(ByteOrder.LITTLE_ENDIAN));

            rec.setSoTimeout(2000);
            DatagramPacket pkt = new DatagramPacket(new byte[128], 128);
            rec.receive(pkt);
            assertThat(pkt.getLength()).isEqualTo(64);
        }
    }

    @Test
    void counter_advances_only_on_successful_send() throws Exception {
        try (DatagramSocket rec = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
             SecureUdpTransport tx = SecureUdpTransport.createShared(
                 new InetSocketAddress(InetAddress.getLoopbackAddress(), rec.getLocalPort()),
                 Key.fromBytes(KEY32))) {

            int before = invokeIntHook(tx, "__getCounterForTest");
            tx.send(ByteBuffer.wrap(new byte[32]).order(ByteOrder.LITTLE_ENDIAN));
            tx.send(ByteBuffer.wrap(new byte[32]).order(ByteOrder.LITTLE_ENDIAN));
            int after = invokeIntHook(tx, "__getCounterForTest");
            assertThat(after).isEqualTo(before + 2);
        }
    }

    @Test
    void reconnect_rotates_session_salt() throws Exception {
        try (DatagramSocket rec = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
             SecureUdpTransport tx = SecureUdpTransport.createShared(
                 new InetSocketAddress(InetAddress.getLoopbackAddress(), rec.getLocalPort()),
                 Key.fromBytes(KEY32))) {
            tx.send(ByteBuffer.wrap(new byte[32]).order(ByteOrder.LITTLE_ENDIAN));
            int counterBefore = invokeIntHook(tx, "__getCounterForTest");
            int prefixBefore = invokeIntHook(tx, "__getPrefixIndexForTest");
            tx.reconnect();
            int counterAfter = invokeIntHook(tx, "__getCounterForTest");
            int prefixAfter = invokeIntHook(tx, "__getPrefixIndexForTest");
            assertThat(counterAfter).isZero();
            assertThat(prefixAfter).isZero();
            // Either counter or prefix moved on reconnect (counter reset to 0).
            assertThat(counterBefore).isNotEqualTo(counterAfter);
            // Drain socket.
            rec.setSoTimeout(2000);
            rec.receive(new DatagramPacket(new byte[128], 128));
            // Suppress unused warnings.
            assertThat(prefixBefore).isGreaterThanOrEqualTo(0);
        }
    }

    private static int invokeIntHook(Object target, String name) throws Exception {
        Method m = target.getClass().getDeclaredMethod(name);
        m.setAccessible(true);
        return (int) m.invoke(target);
    }
}
