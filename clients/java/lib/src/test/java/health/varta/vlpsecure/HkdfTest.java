package health.varta.vlpsecure;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spot-checks the three KDFs against the spec §6.4 reference vectors.
 * Full coverage is in {@link ConformanceSecureFrameTest}; this guards
 * against ConformanceSecureFrameTest accidentally being skipped or
 * silently breaking with a meaningless message.
 */
class HkdfTest {
    private static final HexFormat HEX = HexFormat.of();

    private static final byte[] MASTER_KEY = HEX.parseHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] SESSION_SALT = HEX.parseHex("0102030405060708090a0b0c0d0e0f10");

    @Test
    void agent_key_for_pid_42_matches_spec() {
        byte[] okm = Hkdf.deriveAgentKey(MASTER_KEY, 42);
        assertThat(HEX.formatHex(okm))
            .isEqualTo("61f5951b2bf1905d5053df0abb027002cba62da1f16d93c6552ff61cb65f2599");
    }

    @Test
    void iv_prefix_for_index_7_matches_spec() {
        byte[] okm = Hkdf.deriveIvPrefix(SESSION_SALT, 7);
        assertThat(HEX.formatHex(okm)).isEqualTo("9fee777f36be69ce");
    }

    @Test
    void epoch_key_for_epoch_100_matches_spec() {
        byte[] okm = Hkdf.deriveEpochKey(MASTER_KEY, 100L);
        assertThat(HEX.formatHex(okm))
            .isEqualTo("cb9fe8cb3db0d8d667b7dd9e72adce07c669d3b27bc68ea69e3cc3c129d601ab");
    }

    @Test
    void requires_correct_input_lengths() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
            Hkdf.deriveAgentKey(new byte[31], 1))
            .isInstanceOf(IllegalArgumentException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
            Hkdf.deriveIvPrefix(new byte[15], 0))
            .isInstanceOf(IllegalArgumentException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
            Hkdf.deriveEpochKey(new byte[33], 0L))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
