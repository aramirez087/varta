package health.varta;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * 32-byte symmetric key material for Secure UDP transports.
 *
 * <p>Stores the raw bytes directly (no defensive clone on
 * {@link #bytes()}; callers MUST NOT mutate the returned array). Use
 * {@link #fromBytes(byte[])} when accepting external input — it
 * defensive-copies. Call {@link #zeroize()} when done; the JVM does not
 * scrub freed buffers and GC can leave key material in old-generation
 * memory for minutes.</p>
 */
public final class Key {
    public static final int BYTES = 32;

    private final byte[] bytes;

    private Key(byte[] bytes) {
        this.bytes = bytes;
    }

    /** Defensive-copy a 32-byte array. */
    public static Key fromBytes(byte[] bytes32) {
        Objects.requireNonNull(bytes32, "bytes32");
        if (bytes32.length != BYTES) {
            throw new IllegalArgumentException("key must be " + BYTES + " bytes, got " + bytes32.length);
        }
        return new Key(bytes32.clone());
    }

    /**
     * Load a key from a file. The file may contain either exactly 32 raw
     * bytes or exactly 64 hex characters (with optional trailing
     * whitespace, matching the Rust / Go / .NET clients).
     */
    public static Key fromFile(Path keyFile) throws IOException {
        Objects.requireNonNull(keyFile, "keyFile");
        byte[] raw = Files.readAllBytes(keyFile);
        if (raw.length == BYTES) {
            return new Key(raw);
        }
        String text = new String(raw, java.nio.charset.StandardCharsets.US_ASCII).trim();
        if (text.length() == BYTES * 2) {
            try {
                return new Key(HexFormat.of().parseHex(text));
            } catch (IllegalArgumentException e) {
                throw new IOException("key file is not valid hex: " + keyFile, e);
            }
        }
        throw new IOException("key file " + keyFile + " must be 32 raw bytes or 64 hex chars, got "
            + raw.length + " bytes (" + text.length() + " trimmed chars)");
    }

    /** Direct access to internal buffer; do not mutate. Use {@link #fromBytes} on external input. */
    public byte[] bytes() {
        return bytes;
    }

    /** Best-effort scrub. JVM GC may have already copied the array elsewhere. */
    public void zeroize() {
        Arrays.fill(bytes, (byte) 0);
    }
}
