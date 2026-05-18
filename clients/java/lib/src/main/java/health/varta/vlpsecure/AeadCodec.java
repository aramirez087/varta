package health.varta.vlpsecure;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * ChaCha20-Poly1305 AEAD seal/open for VLP-Secure frames.
 *
 * <p>Two modes:
 * <ul>
 *   <li><b>Shared</b> — 60-byte wire: {@code iv_random[8] || iv_counter[4] || ct[32] || tag[16]}.
 *       AAD = empty.</li>
 *   <li><b>Master</b> — 64-byte wire: {@code agent_pid[4] || iv_random[8] || iv_counter[4] || ct[32] || tag[16]}.
 *       AAD = {@code agent_pid} LE bytes (bound by Poly1305). Per-agent key derived via
 *       {@link Hkdf#deriveAgentKey(byte[], int)}.</li>
 * </ul>
 *
 * <p>Spec: {@code book/src/spec/vlp-secure.md} §3–§5.</p>
 */
public final class AeadCodec {
    private AeadCodec() {}

    /** Algorithm string for {@link Cipher#getInstance(String)}. */
    public static final String CIPHER_NAME = "ChaCha20-Poly1305";
    /** JCE key algorithm name for {@link SecretKeySpec}. */
    public static final String KEY_ALG = "ChaCha20";

    /**
     * Seal a 32-byte plaintext under a shared key. Output is exactly 60 bytes
     * laid out as {@code iv_random || iv_counter || ciphertext || tag}.
     */
    public static byte[] encodeShared(byte[] sharedKey32, byte[] ivRandom8, int ivCounter, byte[] plaintext32) {
        requireLen("sharedKey32", sharedKey32, Hkdf.KEY_BYTES);
        requireLen("ivRandom8", ivRandom8, Hkdf.IV_RANDOM_BYTES);
        requireLen("plaintext32", plaintext32, 32);

        byte[] nonce = buildNonce(ivRandom8, ivCounter);
        byte[] sealed = aeadSeal(sharedKey32, nonce, plaintext32, /* aad */ null);

        byte[] wire = new byte[Hkdf.SECURE_SHARED_BYTES];
        System.arraycopy(ivRandom8, 0, wire, 0, Hkdf.IV_RANDOM_BYTES);
        ByteBuffer.wrap(wire, Hkdf.IV_RANDOM_BYTES, Hkdf.IV_COUNTER_BYTES)
            .order(ByteOrder.LITTLE_ENDIAN).putInt(ivCounter);
        System.arraycopy(sealed, 0, wire, Hkdf.IV_RANDOM_BYTES + Hkdf.IV_COUNTER_BYTES, sealed.length);
        return wire;
    }

    /**
     * Open a 60-byte shared-key wire frame. Throws {@link AEADBadTagException}
     * (rethrown as {@link SecurityException}) on tag mismatch.
     */
    public static byte[] decodeShared(byte[] sharedKey32, byte[] wire60) {
        requireLen("sharedKey32", sharedKey32, Hkdf.KEY_BYTES);
        requireLen("wire60", wire60, Hkdf.SECURE_SHARED_BYTES);

        byte[] ivRandom = new byte[Hkdf.IV_RANDOM_BYTES];
        System.arraycopy(wire60, 0, ivRandom, 0, Hkdf.IV_RANDOM_BYTES);
        int ivCounter = ByteBuffer.wrap(wire60, Hkdf.IV_RANDOM_BYTES, Hkdf.IV_COUNTER_BYTES)
            .order(ByteOrder.LITTLE_ENDIAN).getInt();
        byte[] ctTag = new byte[32 + Hkdf.TAG_BYTES];
        System.arraycopy(wire60, Hkdf.IV_RANDOM_BYTES + Hkdf.IV_COUNTER_BYTES, ctTag, 0, ctTag.length);

        byte[] nonce = buildNonce(ivRandom, ivCounter);
        return aeadOpen(sharedKey32, nonce, ctTag, /* aad */ null);
    }

    /**
     * Seal a 32-byte plaintext under a master key for {@code agentPid}.
     * Output is exactly 64 bytes laid out as
     * {@code agent_pid || iv_random || iv_counter || ciphertext || tag}.
     * AAD = {@code u32_LE(agent_pid)} (4 bytes).
     */
    public static byte[] encodeMaster(byte[] masterKey32, int agentPid, byte[] ivRandom8, int ivCounter,
                                      byte[] plaintext32) {
        requireLen("masterKey32", masterKey32, Hkdf.KEY_BYTES);
        requireLen("ivRandom8", ivRandom8, Hkdf.IV_RANDOM_BYTES);
        requireLen("plaintext32", plaintext32, 32);

        byte[] agentKey = Hkdf.deriveAgentKey(masterKey32, agentPid);
        byte[] aad = new byte[Integer.BYTES];
        ByteBuffer.wrap(aad).order(ByteOrder.LITTLE_ENDIAN).putInt(agentPid);

        byte[] nonce = buildNonce(ivRandom8, ivCounter);
        byte[] sealed = aeadSeal(agentKey, nonce, plaintext32, aad);

        byte[] wire = new byte[Hkdf.SECURE_MASTER_BYTES];
        System.arraycopy(aad, 0, wire, 0, Integer.BYTES);
        System.arraycopy(ivRandom8, 0, wire, Integer.BYTES, Hkdf.IV_RANDOM_BYTES);
        ByteBuffer.wrap(wire, Integer.BYTES + Hkdf.IV_RANDOM_BYTES, Hkdf.IV_COUNTER_BYTES)
            .order(ByteOrder.LITTLE_ENDIAN).putInt(ivCounter);
        System.arraycopy(sealed, 0, wire,
            Integer.BYTES + Hkdf.IV_RANDOM_BYTES + Hkdf.IV_COUNTER_BYTES, sealed.length);

        java.util.Arrays.fill(agentKey, (byte) 0);
        return wire;
    }

    /**
     * Open a 64-byte master-key wire frame. Re-derives the per-agent key from
     * {@code agent_pid} on the wire.
     */
    public static byte[] decodeMaster(byte[] masterKey32, byte[] wire64) {
        requireLen("masterKey32", masterKey32, Hkdf.KEY_BYTES);
        requireLen("wire64", wire64, Hkdf.SECURE_MASTER_BYTES);

        int agentPid = ByteBuffer.wrap(wire64, 0, Integer.BYTES)
            .order(ByteOrder.LITTLE_ENDIAN).getInt();
        byte[] ivRandom = new byte[Hkdf.IV_RANDOM_BYTES];
        System.arraycopy(wire64, Integer.BYTES, ivRandom, 0, Hkdf.IV_RANDOM_BYTES);
        int ivCounter = ByteBuffer.wrap(wire64, Integer.BYTES + Hkdf.IV_RANDOM_BYTES, Hkdf.IV_COUNTER_BYTES)
            .order(ByteOrder.LITTLE_ENDIAN).getInt();
        byte[] ctTag = new byte[32 + Hkdf.TAG_BYTES];
        System.arraycopy(wire64, Integer.BYTES + Hkdf.IV_RANDOM_BYTES + Hkdf.IV_COUNTER_BYTES,
            ctTag, 0, ctTag.length);

        byte[] agentKey = Hkdf.deriveAgentKey(masterKey32, agentPid);
        byte[] aad = new byte[Integer.BYTES];
        ByteBuffer.wrap(aad).order(ByteOrder.LITTLE_ENDIAN).putInt(agentPid);
        byte[] nonce = buildNonce(ivRandom, ivCounter);
        try {
            return aeadOpen(agentKey, nonce, ctTag, aad);
        } finally {
            java.util.Arrays.fill(agentKey, (byte) 0);
        }
    }

    static byte[] buildNonce(byte[] ivRandom8, int ivCounter) {
        byte[] nonce = new byte[Hkdf.NONCE_BYTES];
        System.arraycopy(ivRandom8, 0, nonce, 0, Hkdf.IV_RANDOM_BYTES);
        ByteBuffer.wrap(nonce, Hkdf.IV_RANDOM_BYTES, Hkdf.IV_COUNTER_BYTES)
            .order(ByteOrder.LITTLE_ENDIAN).putInt(ivCounter);
        return nonce;
    }

    private static byte[] aeadSeal(byte[] key32, byte[] nonce12, byte[] plaintext, byte[] aadOrNull) {
        try {
            Cipher c = Cipher.getInstance(CIPHER_NAME);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key32, KEY_ALG), new IvParameterSpec(nonce12));
            if (aadOrNull != null) {
                c.updateAAD(aadOrNull);
            }
            return c.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ChaCha20-Poly1305 unavailable", e);
        }
    }

    private static byte[] aeadOpen(byte[] key32, byte[] nonce12, byte[] ciphertextAndTag, byte[] aadOrNull) {
        try {
            Cipher c = Cipher.getInstance(CIPHER_NAME);
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key32, KEY_ALG), new IvParameterSpec(nonce12));
            if (aadOrNull != null) {
                c.updateAAD(aadOrNull);
            }
            return c.doFinal(ciphertextAndTag);
        } catch (AEADBadTagException e) {
            throw new SecurityException("AEAD tag mismatch", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ChaCha20-Poly1305 unavailable", e);
        }
    }

    private static void requireLen(String name, byte[] b, int expected) {
        Objects.requireNonNull(b, name);
        if (b.length != expected) {
            throw new IllegalArgumentException(name + " must be " + expected + " bytes, got " + b.length);
        }
    }
}
