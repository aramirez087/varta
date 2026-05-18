package health.varta.vlp;

import health.varta.DecodeError;
import health.varta.DecodeErrorKind;
import health.varta.Frame;
import health.varta.Status;
import health.varta.helpers.VectorsLoader;
import health.varta.helpers.VectorsLoader.FrameVector;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Locale;
import java.util.stream.Stream;
import java.util.zip.CRC32C;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ConformanceFrameTest {

    @ParameterizedTest(name = "{0}")
    @MethodSource("roundtripVectors")
    void encode_matches_expected_wire(FrameVector v) {
        ByteBuffer buf = ByteBuffer.allocate(Codec.FRAME_BYTES).order(ByteOrder.LITTLE_ENDIAN);
        Codec.encodeInto(buf, statusFromName(v.status()), v.pid(), v.timestamp(),
            v.nonce(), v.payload(), new CRC32C());
        byte[] got = new byte[Codec.FRAME_BYTES];
        buf.get(got);
        assertThat(got)
            .as("vector %s", v.id())
            .isEqualTo(v.expectedWire());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("roundtripVectors")
    void decode_roundtrips(FrameVector v) {
        Frame frame = Frame.decode(v.expectedWire());
        assertThat(frame.status()).isEqualTo(statusFromName(v.status()));
        assertThat(frame.pid()).isEqualTo(v.pid());
        assertThat(frame.timestamp()).isEqualTo(v.timestamp());
        assertThat(frame.nonce()).isEqualTo(v.nonce());
        assertThat(frame.payload()).isEqualTo(v.payload());
    }

    @ParameterizedTest(name = "{0} → {1}")
    @MethodSource("errorVectors")
    void decode_rejects(String id, String errorName, byte[] wire) {
        assertThatThrownBy(() -> Frame.decode(wire))
            .as("vector %s", id)
            .isInstanceOf(DecodeError.class)
            .matches(t -> ((DecodeError) t).kind() == kindFromSpec(errorName),
                "expected " + errorName);
    }

    static Stream<FrameVector> roundtripVectors() {
        return VectorsLoader.load().frameVectors().stream()
            .filter(v -> "encode_decode_roundtrip".equals(v.kind()));
    }

    static Stream<Arguments> errorVectors() {
        return VectorsLoader.load().frameVectors().stream()
            .filter(v -> "decode_error".equals(v.kind()))
            .map(v -> Arguments.of(v.id(), v.expectedDecodeError(), v.decodeErrorWire()));
    }

    private static Status statusFromName(String name) {
        return Status.valueOf(name.toUpperCase(Locale.ROOT));
    }

    private static DecodeErrorKind kindFromSpec(String specName) {
        // Spec uses PascalCase ("BadMagic"); enum is SCREAMING_SNAKE_CASE ("BAD_MAGIC").
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < specName.length(); i++) {
            char c = specName.charAt(i);
            if (Character.isUpperCase(c) && i > 0) sb.append('_');
            sb.append(Character.toUpperCase(c));
        }
        return DecodeErrorKind.valueOf(sb.toString());
    }
}
