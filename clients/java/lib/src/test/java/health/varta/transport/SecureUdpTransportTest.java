package health.varta.transport;

import health.varta.Key;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

    private static final class ShortInner implements BeatTransport {
        @Override
        public int send(ByteBuffer frame) {
            return frame.remaining() - 1;
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

    @Test
    void double_exhaustion_reconnects_before_nonce_reuse() throws Exception {
        RecordingInner inner = new RecordingInner();
        SecureUdpTransport tx =
            new SecureUdpTransport(SecureUdpTransport.Mode.SHARED, inner, KEY32);

        byte[] initialPrefix = tx.__getIvPrefixForTest();
        tx.__setPrefixIndexForTest(Integer.MAX_VALUE);
        tx.__setCounterForTest(Integer.MAX_VALUE);

        int sent = tx.send(ByteBuffer.wrap(new byte[32]).order(ByteOrder.LITTLE_ENDIAN));

        assertThat(sent).isEqualTo(32);
        assertThat(inner.reconnects).isEqualTo(1);
        assertThat(tx.__getPrefixIndexForTest()).isZero();
        assertThat(tx.__getCounterForTest()).isEqualTo(1);
        assertThat(tx.__getIvPrefixForTest()).isNotEqualTo(initialPrefix);
    }

    @Test
    void short_secure_send_does_not_commit_nonce_state() {
        SecureUdpTransport tx =
            new SecureUdpTransport(SecureUdpTransport.Mode.SHARED, new ShortInner(), KEY32);

        tx.__setCounterForTest(17);
        int prefixBefore = tx.__getPrefixIndexForTest();
        byte[] ivBefore = tx.__getIvPrefixForTest();

        assertThatThrownBy(() -> tx.send(ByteBuffer.wrap(new byte[32]).order(ByteOrder.LITTLE_ENDIAN)))
            .isInstanceOf(IOException.class)
            .hasMessage("WriteZero");

        assertThat(tx.__getPrefixIndexForTest()).isEqualTo(prefixBefore);
        assertThat(tx.__getIvPrefixForTest()).isEqualTo(ivBefore);
        assertThat(tx.__getCounterForTest()).isEqualTo(17);
    }

    /** Inner transport that records how many times reconnect() was called. */
    private static final class RecordingInner implements BeatTransport {
        int reconnects = 0;

        @Override
        public int send(ByteBuffer frame) {
            return frame.remaining();
        }

        @Override
        public void reconnect() {
            reconnects++;
        }

        @Override
        public void close() {
        }
    }

    @Test
    void reconnect_entropy_failure_surfaces_ioexception_and_is_transactional() {
        // Regression: a session-prep (entropy/KDF) failure during reconnect()
        // must surface as a checked IOException — so beat()'s fork-recovery
        // catch (IOException) returns Failed instead of an unchecked exception
        // escaping and crashing the caller's beat loop — AND must leave the
        // transport entirely unchanged: the inner socket is NOT reconnected
        // until the fresh session material is in hand. The prior code ran
        // inner.reconnect() first and then threw IllegalStateException from
        // rotateSession() on entropy failure, leaving a new socket with stale IV.
        RecordingInner inner = new RecordingInner();
        SecureUdpTransport tx =
            new SecureUdpTransport(SecureUdpTransport.Mode.SHARED, inner, KEY32);

        int prefixBefore = tx.__getPrefixIndexForTest();
        byte[] ivBefore = tx.__getIvPrefixForTest();

        tx.__setSessionMaterialSourceForTest(() -> {
            throw new IOException("simulated entropy failure");
        });

        assertThatThrownBy(tx::reconnect)
            .as("a session-prep failure must surface as IOException, not an unchecked exception")
            .isInstanceOf(IOException.class);

        // Transactional: the inner socket was never reconnected (prepare failed
        // first), and the IV state is unchanged.
        assertThat(inner.reconnects).isZero();
        assertThat(tx.__getPrefixIndexForTest()).isEqualTo(prefixBefore);
        assertThat(tx.__getIvPrefixForTest()).isEqualTo(ivBefore);
    }

    private static int invokeIntHook(Object target, String name) throws Exception {
        Method m = target.getClass().getDeclaredMethod(name);
        m.setAccessible(true);
        return (int) m.invoke(target);
    }
}
