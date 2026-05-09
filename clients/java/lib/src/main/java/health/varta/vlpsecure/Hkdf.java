package health.varta.vlpsecure;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * HKDF-SHA256 (RFC 5869) and the three VLP-Secure domain-specific
 * derivations. Pure JCE — uses {@code Mac.HmacSHA256}, no third-party crypto.
 *
 * <p>Spec: {@code book/src/spec/vlp-secure.md} §6.</p>
 */
public final class Hkdf {
    public static final int KEY_BYTES = 32;
    public static final int IV_RANDOM_BYTES = 8;
    public static final int IV_COUNTER_BYTES = 4;
    public static final int NONCE_BYTES = IV_RANDOM_BYTES + IV_COUNTER_BYTES; // 12
    public static final int TAG_BYTES = 16;
    public static final int SESSION_SALT_BYTES = 16;
    public static final int SECURE_SHARED_BYTES = 60; // iv_random[8] || iv_counter[4] || ct[32] || tag[16]
    public static final int SECURE_MASTER_BYTES = 64; // agent_pid[4] || iv_random[8] || iv_counter[4] || ct[32] || tag[16]

    private static final byte[] EMPTY = new byte[0];
    private static final int HMAC_OUT = 32;

    private static final byte[] INFO_PREFIX_AGENT     = bytesAscii("varta-agent-v1\0");      // 15
    private static final byte[] INFO_PREFIX_IV_PREFIX = bytesAscii("varta-iv-prefix-v1\0");  // 19
    private static final byte[] INFO_PREFIX_EPOCH     = bytesAscii("varta-epoch-v1\0");      // 15

    private Hkdf() {}

    private static byte[] bytesAscii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * RFC 5869 HKDF-SHA256. {@code salt} may be empty (treated as 32 zero bytes
     * per §2.2).
     */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        Objects.requireNonNull(ikm);
        Objects.requireNonNull(info);
        if (length < 1 || length > 255 * HMAC_OUT) {
            throw new IllegalArgumentException("length out of range: " + length);
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[HMAC_OUT] : salt;

            // Extract
            mac.init(new SecretKeySpec(effectiveSalt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);

            // Expand
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] okm = new byte[length];
            byte[] t = EMPTY;
            int written = 0;
            int counter = 1;
            while (written < length) {
                mac.update(t);
                mac.update(info);
                mac.update((byte) counter);
                t = mac.doFinal();
                int take = Math.min(t.length, length - written);
                System.arraycopy(t, 0, okm, written, take);
                written += take;
                counter++;
            }
            return okm;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HKDF-SHA256 unavailable; JDK is broken", e);
        }
    }

    /**
     * Derive a 32-byte per-agent key from a 32-byte master key.
     *
     * <p>info = {@code "varta-agent-v1\0" || u32_LE(agentId)} (19 bytes). salt = empty.</p>
     */
    public static byte[] deriveAgentKey(byte[] masterKey32, int agentId) {
        requireLen("masterKey32", masterKey32, KEY_BYTES);
        byte[] info = new byte[INFO_PREFIX_AGENT.length + Integer.BYTES];
        System.arraycopy(INFO_PREFIX_AGENT, 0, info, 0, INFO_PREFIX_AGENT.length);
        ByteBuffer.wrap(info, INFO_PREFIX_AGENT.length, Integer.BYTES)
            .order(ByteOrder.LITTLE_ENDIAN).putInt(agentId);
        return hkdfSha256(masterKey32, EMPTY, info, KEY_BYTES);
    }

    /**
     * Derive an 8-byte IV prefix from a 16-byte session salt + counter.
     *
     * <p>info = {@code "varta-iv-prefix-v1\0" || u32_LE(prefixIndex)} (23 bytes).
     * IKM = sessionSalt, salt = empty (matches Rust / Go / .NET reference impls).</p>
     */
    public static byte[] deriveIvPrefix(byte[] sessionSalt16, int prefixIndex) {
        requireLen("sessionSalt16", sessionSalt16, SESSION_SALT_BYTES);
        byte[] info = new byte[INFO_PREFIX_IV_PREFIX.length + Integer.BYTES];
        System.arraycopy(INFO_PREFIX_IV_PREFIX, 0, info, 0, INFO_PREFIX_IV_PREFIX.length);
        ByteBuffer.wrap(info, INFO_PREFIX_IV_PREFIX.length, Integer.BYTES)
            .order(ByteOrder.LITTLE_ENDIAN).putInt(prefixIndex);
        return hkdfSha256(sessionSalt16, EMPTY, info, IV_RANDOM_BYTES);
    }

    /**
     * Derive a 32-byte epoch key from a 32-byte agent key. Reserved for
     * forward compatibility; covered by conformance vectors but not used
     * on the wire today.
     *
     * <p>info = {@code "varta-epoch-v1\0" || u64_LE(epoch)} (23 bytes). salt = empty.</p>
     */
    public static byte[] deriveEpochKey(byte[] agentKey32, long epoch) {
        requireLen("agentKey32", agentKey32, KEY_BYTES);
        byte[] info = new byte[INFO_PREFIX_EPOCH.length + Long.BYTES];
        System.arraycopy(INFO_PREFIX_EPOCH, 0, info, 0, INFO_PREFIX_EPOCH.length);
        ByteBuffer.wrap(info, INFO_PREFIX_EPOCH.length, Long.BYTES)
            .order(ByteOrder.LITTLE_ENDIAN).putLong(epoch);
        return hkdfSha256(agentKey32, EMPTY, info, KEY_BYTES);
    }

    private static void requireLen(String name, byte[] b, int expected) {
        if (b == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        if (b.length != expected) {
            throw new IllegalArgumentException(name + " must be " + expected + " bytes, got " + b.length);
        }
    }
}
