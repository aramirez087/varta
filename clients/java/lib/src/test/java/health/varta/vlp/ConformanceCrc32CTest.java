package health.varta.vlp;

import health.varta.helpers.VectorsLoader;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.HexFormat;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class ConformanceCrc32CTest {
    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void crc_vector_matches(String id, byte[] input, long expected) {
        long actual = Crc32C.compute(input);
        assertThat(actual)
            .as("vector %s — input=%s", id, HexFormat.of().formatHex(input))
            .isEqualTo(expected);
    }

    static Stream<org.junit.jupiter.params.provider.Arguments> vectors() {
        return VectorsLoader.load().crc32cVectors().stream()
            .map(v -> org.junit.jupiter.params.provider.Arguments.of(v.id(), v.input(), v.expectedCrc()));
    }
}
