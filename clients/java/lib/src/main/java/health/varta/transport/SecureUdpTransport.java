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

    private BeatTransport inner;
    private final byte[] sessionSalt = new byte[Hkdf.SESSION_SALT_BYTES];
    private byte[] ivPrefix = new byte[Hkdf.IV_RANDOM_BYTES];
    private int prefixIndex = 0;
    private int counter = 0;
    private int agentPid = (int) ProcessHandle.current().pid();

    /** The fallible entropy + IV-derivation step of a session rotation,
     *  isolated so a failure can be (a) surfaced as a checked {@link IOException}
     *  rather than an unchecked exception that would escape {@code beat()}'s
     *  fork-recovery {@code catch (IOException)}, and (b) injected in tests. */
    @FunctionalInterface
    interface SessionMaterialSource {
        /** @return {@code {sessionSalt, ivPrefix}} for a fresh session. */
        byte[][] get() throws IOException;
    }

    private SessionMaterialSource sessionMaterialSource =
        SecureUdpTransport::readFreshSessionMaterial;

    /** Package-private: tests override the entropy/KDF source to force a
     *  session-prep failure during {@link #reconnect()}. */
    void __setSessionMaterialSourceForTest(SessionMaterialSource source) {
        this.sessionMaterialSource = source;
    }

    private static byte[][] readFreshSessionMaterial() throws IOException {
        try {
            // NativePRNGNonBlocking maps to getrandom(2) on Linux without
            // blocking on first-boot pool init; falls back elsewhere.
            SecureRandom rng;
            try {
                rng = SecureRandom.getInstance("NativePRNGNonBlocking");
            } catch (NoSuchAlgorithmException ignored) {
                rng = new SecureRandom();
            }
            byte[] salt = new byte[Hkdf.SESSION_SALT_BYTES];
            rng.nextBytes(salt);
            byte[] prefix = Hkdf.deriveIvPrefix(salt, 0);
            return new byte[][] {salt, prefix};
        } catch (Exception e) {
            throw new IOException("could not read secure-session entropy", e);
        }
    }

    private SecureUdpTransport(Mode mode, InetSocketAddress addr, byte[] key32) throws IOException {
        this.mode = mode;
        this.addr = addr;
        this.key32 = key32.clone();
        this.inner = UdpTransport.create(addr);
        rotateSession();
    }

    /** Package-private test constructor: inject a controllable inner transport
     *  (e.g. one that returns 0 to simulate a WouldBlock/ENOBUFS failed send)
     *  so the commit-on-success behaviour at the counter-wrap boundary can be
     *  exercised without a real socket. */
    SecureUdpTransport(Mode mode, BeatTransport inner, byte[] key32) {
        this.mode = mode;
        this.addr = null;
        this.key32 = key32.clone();
        this.inner = inner;
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
        // Construction-time rotation: an entropy/KDF failure here is a fatal
        // startup error, so it is fine to surface it as an unchecked exception
        // (the factory methods already declare {@code throws IOException} for
        // the socket bind). {@link #reconnect()} must NOT use this path — there
        // a failure must stay an IOException so {@code beat()} can return Failed.
        try {
            byte[][] material = sessionMaterialSource.get();
            System.arraycopy(material[0], 0, sessionSalt, 0, sessionSalt.length);
            ivPrefix = material[1];
            prefixIndex = 0;
            counter = 0;
        } catch (IOException e) {
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

        // Compute the IV state for THIS send into locals, mutating no committed
        // field until the datagram actually escapes the process (commit-on-
        // success). At the counter-wrap boundary this rotates the prefix into
        // locals only: a failed send (WouldBlock / ENOBUFS) must NOT burn the
        // prefix index, re-derive the prefix (an HKDF on the hot beat path), or
        // advance the counter — a retry must re-send the SAME (prefix, counter).
        // Mirrors the Rust reference (secure_transport: NonceAdvance computed
        // into locals, committed only inside `if result.is_ok()`).
        int sendPrefixIndex = prefixIndex;
        int sendCounter = counter;
        byte[] sendPrefix = ivPrefix;
        if (sendCounter == Integer.MAX_VALUE) {
            sendPrefixIndex = prefixIndex + 1;
            sendCounter = 0;
            sendPrefix = Hkdf.deriveIvPrefix(sessionSalt, sendPrefixIndex);
        }

        byte[] wire = (mode == Mode.SHARED)
            ? AeadCodec.encodeShared(key32, sendPrefix, sendCounter, plaintext)
            : AeadCodec.encodeMaster(key32, agentPid, sendPrefix, sendCounter, plaintext);

        ByteBuffer wireBuf = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        int written = inner.send(wireBuf);
        if (written == 0) {
            return 0;
        }
        if (written != wire.length) {
            throw new IOException("WriteZero");
        }
        // commit-on-success: the wrap rotation and the counter advance land
        // only now that the full encrypted frame was actually transmitted.
        prefixIndex = sendPrefixIndex;
        ivPrefix = sendPrefix;
        counter = sendCounter + 1;
        return 32; // report logical plaintext bytes
    }

    @Override
    public void reconnect() throws IOException {
        // Prepare ALL fallible session material (entropy + KDF) into locals
        // FIRST, surfacing any failure as the declared, caught IOException — so
        // beat()'s fork-recovery path returns Failed instead of letting an
        // unchecked exception escape (the never-throws contract), and so a
        // failure leaves the transport entirely unchanged. Only after the
        // material is in hand do we reconnect the socket and commit; the commit
        // cannot fail. Mirrors the Rust/.NET prepare-then-commit reconnect.
        //
        // The prior order (inner.reconnect() then rotateSession()) both threw an
        // unchecked IllegalStateException on entropy failure — which escaped the
        // fork-recovery catch and crashed the caller's beat loop — AND left a
        // freshly-reconnected socket paired with stale IV state when entropy
        // failed after the socket was already swapped.
        int newAgentPid = (int) ProcessHandle.current().pid();
        byte[][] material = sessionMaterialSource.get();
        inner.reconnect();
        System.arraycopy(material[0], 0, sessionSalt, 0, sessionSalt.length);
        ivPrefix = material[1];
        prefixIndex = 0;
        counter = 0;
        agentPid = newAgentPid;
    }

    @Override
    public void close() {
        try { java.util.Arrays.fill(key32, (byte) 0); } catch (Exception ignored) {}
        inner.close();
    }

    // Test hooks
    int __getCounterForTest() { return counter; }
    int __getPrefixIndexForTest() { return prefixIndex; }
    void __setCounterForTest(int c) { this.counter = c; }
    byte[] __getIvPrefixForTest() { return ivPrefix.clone(); }
}
