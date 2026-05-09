package health.varta.vlp;

import health.varta.DecodeError;
import health.varta.DecodeErrorKind;
import health.varta.Frame;
import health.varta.Status;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.CRC32C;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VlpCodecUnitTest {

    @Test
    void roundtrip_all_status_values() {
        for (Status s : Status.values()) {
            ByteBuffer buf = ByteBuffer.allocate(Codec.FRAME_BYTES).order(ByteOrder.LITTLE_ENDIAN);
            Codec.encodeInto(buf, s, 4242, 123_456_789L, 7L, 0xCAFEBABE, new CRC32C());
            byte[] wire = new byte[Codec.FRAME_BYTES];
            buf.get(wire);

            Frame frame = Frame.decode(wire);
            assertThat(frame.status()).isEqualTo(s);
            assertThat(frame.pid()).isEqualTo(4242);
            assertThat(frame.timestamp()).isEqualTo(123_456_789L);
            assertThat(frame.nonce()).isEqualTo(7L);
            assertThat(frame.payload()).isEqualTo(0xCAFEBABE);
        }
    }

    @Test
    void encode_reuses_crc_instance_without_alloc_growth() {
        // Smoke: identical input → identical output, no state bleed across calls.
        ByteBuffer buf = ByteBuffer.allocate(Codec.FRAME_BYTES).order(ByteOrder.LITTLE_ENDIAN);
        CRC32C crc = new CRC32C();
        Codec.encodeInto(buf, Status.OK, 99, 1L, 1L, 0, crc);
        byte[] first = new byte[Codec.FRAME_BYTES];
        buf.get(first);

        Codec.encodeInto(buf, Status.OK, 99, 1L, 1L, 0, crc);
        byte[] second = new byte[Codec.FRAME_BYTES];
        buf.get(second);

        assertThat(second).isEqualTo(first);
    }

    @Test
    void decode_rejects_short_buffer() {
        assertThatThrownBy(() -> Frame.decode(new byte[31]))
            .isInstanceOf(DecodeError.class)
            .matches(t -> ((DecodeError) t).kind() == DecodeErrorKind.BAD_MAGIC);
    }

    @Test
    void terminal_nonce_with_critical_is_allowed() {
        ByteBuffer buf = ByteBuffer.allocate(Codec.FRAME_BYTES).order(ByteOrder.LITTLE_ENDIAN);
        Codec.encodeInto(buf, Status.CRITICAL, 99, 0L, Codec.NONCE_TERMINAL, 0, new CRC32C());
        byte[] wire = new byte[Codec.FRAME_BYTES];
        buf.get(wire);
        Frame frame = Frame.decode(wire);
        assertThat(frame.status()).isEqualTo(Status.CRITICAL);
        assertThat(frame.nonce()).isEqualTo(Codec.NONCE_TERMINAL);
    }

    @Test
    void encodeInto_rejects_big_endian_buffer() {
        ByteBuffer buf = ByteBuffer.allocate(Codec.FRAME_BYTES); // default BIG_ENDIAN
        assertThatThrownBy(() ->
            Codec.encodeInto(buf, Status.OK, 2, 0L, 1L, 0, new CRC32C()))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("LITTLE_ENDIAN");
    }
}
