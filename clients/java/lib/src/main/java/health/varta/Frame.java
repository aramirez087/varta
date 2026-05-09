package health.varta;

import health.varta.vlp.Codec;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

/**
 * Decoded VLP v0.2 frame. All numeric fields are wire-order independent
 * (decoder normalises little-endian → host).
 *
 * <p>{@code pid} is the emitter's u32 PID; display via
 * {@link Integer#toUnsignedString(int)} if you need numeric formatting.
 * {@code timestamp} and {@code nonce} are u64; use
 * {@link Long#toUnsignedString(long)} for display.</p>
 */
public final class Frame {
    private final Status status;
    private final int pid;
    private final long timestamp;
    private final long nonce;
    private final int payload;

    public Frame(Status status, int pid, long timestamp, long nonce, int payload) {
        this.status = Objects.requireNonNull(status);
        this.pid = pid;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.payload = payload;
    }

    public Status status()      { return status; }
    public int pid()            { return pid; }
    public long timestamp()     { return timestamp; }
    public long nonce()         { return nonce; }
    public int payload()        { return payload; }

    /** Decode a 32-byte little-endian wire frame. */
    public static Frame decode(byte[] wire32) {
        Objects.requireNonNull(wire32);
        if (wire32.length != Codec.FRAME_BYTES) {
            throw new DecodeError(DecodeErrorKind.BAD_MAGIC,
                "frame must be exactly 32 bytes, got " + wire32.length);
        }
        return Codec.decode(ByteBuffer.wrap(wire32).order(ByteOrder.LITTLE_ENDIAN));
    }

    /** Decode from a ByteBuffer; the buffer's byte order is forced to little-endian. */
    public static Frame decode(ByteBuffer wire32) {
        Objects.requireNonNull(wire32);
        if (wire32.remaining() != Codec.FRAME_BYTES) {
            throw new DecodeError(DecodeErrorKind.BAD_MAGIC,
                "frame must be exactly 32 bytes, got " + wire32.remaining());
        }
        ByteBuffer dup = wire32.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        return Codec.decode(dup);
    }

    @Override
    public String toString() {
        return "Frame{status=" + status
            + ", pid=" + Integer.toUnsignedString(pid)
            + ", timestamp=" + Long.toUnsignedString(timestamp)
            + ", nonce=" + Long.toUnsignedString(nonce)
            + ", payload=" + Integer.toUnsignedString(payload) + "}";
    }
}
