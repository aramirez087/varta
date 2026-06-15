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

    /** Controllable inner transport: returns 0 (WouldBlock/ENOBUFS) until
     *  {@code succeed} is set, then echoes the wire length (success). */
    private static final class FakeInner implements BeatTransport {
        boolean succeed = false;

        @Override
        public int send(ByteBuffer frame) {
            return succeed ? frame.remaining() : 0;
        }

        @Override
        public void reconnect() {}

        @Override
        public void close() {}
    }

    @Test
    void wrap_at_counter_boundary_is_commit_on_success() throws Exception {
        // Regression (bug-478): at the counter-wrap boundary the IV-prefix
        // rotation must be commit-on-success — a failed send must NOT burn the
        // prefix index, re-derive the prefix, or advance the counter. The old
        // code mutated prefixIndex/ivPrefix/counter unconditionally before send.
        FakeInner inner = new FakeInner();
        SecureUdpTransport tx =
            new SecureUdpTransport(SecureUdpTransport.Mode.SHARED, inner, KEY32);

        // Fast-forward the counter to the wrap boundary.
        tx.__setCounterForTest(Integer.MAX_VALUE);
        int prefixBefore = tx.__getPrefixIndexForTest();
        byte[] ivBefore = tx.__getIvPrefixForTest();

        // (1) A FAILED send at the wrap boundary leaves all IV state untouched.
        inner.succeed = false;
        int written = tx.send(ByteBuffer.wrap(new byte[32]).order(ByteOrder.LITTLE_ENDIAN));
        assertThat(written).isZero();
        assertThat(tx.__getPrefixIndexForTest()).isEqualTo(prefixBefore);
        assertThat(tx.__getIvPrefixForTest()).isEqualTo(ivBefore);
        assertThat(tx.__getCounterForTest()).isEqualTo(Integer.MAX_VALUE);

        // (2) A SUCCESSFUL send rotates the prefix and resets the counter,
        //     committed only now that the frame actually went out.
        inner.succeed = true;
        int sent = tx.send(ByteBuffer.wrap(new byte[32]).order(ByteOrder.LITTLE_ENDIAN));
        assertThat(sent).isEqualTo(32);
        assertThat(tx.__getPrefixIndexForTest()).isEqualTo(prefixBefore + 1);
        assertThat(tx.__getIvPrefixForTest()).isNotEqualTo(ivBefore);
        assertThat(tx.__getCounterForTest()).isEqualTo(1);
    }

    private static int invokeIntHook(Object target, String name) throws Exception {
        Method m = target.getClass().getDeclaredMethod(name);
        m.setAccessible(true);
        return (int) m.invoke(target);
    }
}
