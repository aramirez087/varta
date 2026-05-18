package health.varta.vlpsecure;

import health.varta.helpers.VectorsLoader;
import health.varta.helpers.VectorsLoader.SecureVector;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ConformanceSecureFrameTest {

    @TestFactory
    List<DynamicTest> vectors() {
        List<DynamicTest> tests = new ArrayList<>();
        for (SecureVector v : VectorsLoader.load().secureFrameVectors()) {
            tests.add(DynamicTest.dynamicTest(v.id() + " (" + v.kind() + ")", () -> run(v)));
        }
        return tests;
    }

    private void run(SecureVector v) {
        switch (v.kind()) {
            case "shared_key_seal" -> {
                byte[] wire = AeadCodec.encodeShared(v.key(), v.ivRandom(), v.ivCounter(), v.plaintext());
                assertThat(wire).isEqualTo(v.expectedWire());
                byte[] decoded = AeadCodec.decodeShared(v.key(), wire);
                assertThat(decoded).isEqualTo(v.plaintext());
            }
            case "master_key_seal" -> {
                byte[] derived = Hkdf.deriveAgentKey(v.masterKey(), v.agentPid());
                assertThat(derived)
                    .as("derived per-agent key for pid=%d", v.agentPid())
                    .isEqualTo(v.derivedAgentKey());
                byte[] wire = AeadCodec.encodeMaster(v.masterKey(), v.agentPid(),
                    v.ivRandom(), v.ivCounter(), v.plaintext());
                assertThat(wire).isEqualTo(v.expectedWire());
                byte[] decoded = AeadCodec.decodeMaster(v.masterKey(), wire);
                assertThat(decoded).isEqualTo(v.plaintext());
            }
            case "kdf_agent_key" -> {
                byte[] okm = Hkdf.deriveAgentKey(v.masterKey(), v.agentId());
                assertThat(okm).isEqualTo(v.expectedOkm());
            }
            case "kdf_iv_prefix" -> {
                byte[] okm = Hkdf.deriveIvPrefix(v.sessionSalt(), v.prefixIndex());
                assertThat(okm).isEqualTo(v.expectedIvPrefix());
            }
            case "kdf_epoch_key" -> {
                byte[] okm = Hkdf.deriveEpochKey(v.agentKey(), v.epoch());
                assertThat(okm).isEqualTo(v.expectedOkm());
            }
            default -> throw new AssertionError("unknown kind " + v.kind());
        }
    }
}
