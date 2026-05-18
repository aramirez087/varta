package health.varta.transport;

import health.varta.Key;
import health.varta.vlpsecure.AeadCodec;
import health.varta.vlpsecure.Hkdf;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Secure UDP transport — wraps {@link UdpTransport} with ChaCha20-Poly1305
 * AEAD seal. Two modes: shared-key (60-byte wire, AAD empty) and master-key
 * (64-byte wire, AAD = {@code u32_LE(agent_pid)}, per-agent key derived via
 * {@link Hkdf#deriveAgentKey(byte[], int)}).
 *
 * <p>Session salt is read from {@link SecureRandom} at construct and at every
 * {@link #reconnect()}. The IV prefix is derived via
 * {@link Hkdf#deriveIvPrefix(byte[], int)} and rotated locally at
 * {@code counter == Integer.MAX_VALUE} — zero syscalls, zero blocking.</p>
 *
 * <p>Counter is commit-on-success: incremented only after the UDP send
 * returns success. A {@code WouldBlock} retry safely reuses the same nonce.</p>
 */
public final class SecureUdpTransport implements BeatTransport {
    public enum Mode { SHARED, MASTER }

    private final Mode mode;
    private final InetSocketAddress addr;
    private final byte[] key32; // shared or master, retained for reconnect

    private UdpTransport inner;
    private final byte[] sessionSalt = new byte[Hkdf.SESSION_SALT_BYTES];
    private byte[] ivPrefix = new byte[Hkdf.IV_RANDOM_BYTES];
    private int prefixIndex = 0;
    private int counter = 0;
    private int agentPid = (int) ProcessHandle.current().pid();

    private SecureUdpTransport(Mode mode, InetSocketAddress addr, byte[] key32) throws IOException {
        this.mode = mode;
        this.addr = addr;
        this.key32 = key32.clone();
        this.inner = UdpTransport.create(addr);
        rotateSession();
    }

    public static SecureUdpTransport createShared(InetSocketAddress addr, Key sharedKey) throws IOException {
        Objects.requireNonNull(addr, "addr");
        Objects.requireNonNull(sharedKey, "sharedKey");
        if (sharedKey.bytes().length != Hkdf.KEY_BYTES) {
            throw new IllegalArgumentException("sharedKey must be 32 bytes");
        }
        return new SecureUdpTransport(Mode.SHARED, addr, sharedKey.bytes());
    }

    public static SecureUdpTransport createMaster(InetSocketAddress addr, Key masterKey) throws IOException {
        Objects.requireNonNull(addr, "addr");
        Objects.requireNonNull(masterKey, "masterKey");
        if (masterKey.bytes().length != Hkdf.KEY_BYTES) {
            throw new IllegalArgumentException("masterKey must be 32 bytes");
        }
        return new SecureUdpTransport(Mode.MASTER, addr, masterKey.bytes());
    }

    private void rotateSession() {
        try {
            // NativePRNGNonBlocking on Linux maps to getrandom(2) without
            // blocking on first-boot pool init. Falls back to the default
            // strong instance on other platforms.
            SecureRandom rng;
            try {
                rng = SecureRandom.getInstance("NativePRNGNonBlocking");
            } catch (NoSuchAlgorithmException ignored) {
                rng = new SecureRandom();
            }
            rng.nextBytes(sessionSalt);
            prefixIndex = 0;
            counter = 0;
            ivPrefix = Hkdf.deriveIvPrefix(sessionSalt, prefixIndex);
        } catch (Exception e) {
            throw new IllegalStateException("could not initialise secure session", e);
        }
    }

    @Override
    public int send(ByteBuffer plaintextFrame) throws IOException {
        if (plaintextFrame.remaining() != 32) {
            throw new IllegalArgumentException("VLP plaintext must be 32 bytes");
        }

        // Snapshot plaintext into a heap byte[] for the JCE Cipher API.
        byte[] plaintext = new byte[32];
        int basePos = plaintextFrame.position();
        plaintextFrame.duplicate().get(plaintext);
        plaintextFrame.position(basePos);

        // Rotate IV prefix when counter wraps.
        if (counter == Integer.MAX_VALUE) {
            prefixIndex++;
            counter = 0;
            ivPrefix = Hkdf.deriveIvPrefix(sessionSalt, prefixIndex);
        }

        byte[] wire = (mode == Mode.SHARED)
            ? AeadCodec.encodeShared(key32, ivPrefix, counter, plaintext)
            : AeadCodec.encodeMaster(key32, agentPid, ivPrefix, counter, plaintext);

        ByteBuffer wireBuf = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        int written = inner.send(wireBuf);
        if (written > 0) {
            counter++; // commit-on-success
        }
        return written == wire.length ? 32 /* report logical plaintext bytes */ : written;
    }

    @Override
    public void reconnect() throws IOException {
        inner.reconnect();
        // Re-read entropy; this guards against fork() reusing parent's IV.
        agentPid = (int) ProcessHandle.current().pid();
        rotateSession();
    }

    @Override
    public void close() {
        try { java.util.Arrays.fill(key32, (byte) 0); } catch (Exception ignored) {}
        inner.close();
    }

    // Test hooks
    int __getCounterForTest() { return counter; }
    int __getPrefixIndexForTest() { return prefixIndex; }
}
