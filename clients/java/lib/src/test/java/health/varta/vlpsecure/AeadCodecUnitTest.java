package health.varta.vlpsecure;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AeadCodecUnitTest {

    private static final byte[] KEY32 = new byte[32];
    static {
        for (int i = 0; i < 32; i++) KEY32[i] = (byte) i;
    }

    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }

    @Test
    void shared_roundtrip() {
        byte[] iv = randomBytes(8);
        byte[] plaintext = randomBytes(32);
        byte[] wire = AeadCodec.encodeShared(KEY32, iv, 0, plaintext);
        assertThat(wire).hasSize(Hkdf.SECURE_SHARED_BYTES);
        byte[] decoded = AeadCodec.decodeShared(KEY32, wire);
        assertThat(decoded).isEqualTo(plaintext);
    }

    @Test
    void master_roundtrip() {
        byte[] iv = randomBytes(8);
        byte[] plaintext = randomBytes(32);
        int agentPid = 31337;
        byte[] wire = AeadCodec.encodeMaster(KEY32, agentPid, iv, 1, plaintext);
        assertThat(wire).hasSize(Hkdf.SECURE_MASTER_BYTES);
        byte[] decoded = AeadCodec.decodeMaster(KEY32, wire);
        assertThat(decoded).isEqualTo(plaintext);
    }

    @Test
    void shared_tamper_tag_is_rejected() {
        byte[] wire = AeadCodec.encodeShared(KEY32, randomBytes(8), 0, randomBytes(32));
        wire[wire.length - 1] ^= (byte) 0xFF; // flip last tag byte
        assertThatThrownBy(() -> AeadCodec.decodeShared(KEY32, wire))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("tag mismatch");
    }

    @Test
    void master_tamper_aad_is_rejected() {
        byte[] wire = AeadCodec.encodeMaster(KEY32, 42, randomBytes(8), 0, randomBytes(32));
        wire[0] ^= (byte) 0xFF; // mutate agent_pid byte (= AAD)
        assertThatThrownBy(() -> AeadCodec.decodeMaster(KEY32, wire))
            .isInstanceOf(SecurityException.class);
    }

    @Test
    void shared_rejects_wrong_key_length() {
        assertThatThrownBy(() -> AeadCodec.encodeShared(new byte[31], new byte[8], 0, new byte[32]))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("sharedKey32");
    }
}
