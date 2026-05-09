package health.varta.vlp;

import health.varta.DecodeError;
import health.varta.DecodeErrorKind;
import health.varta.Frame;
import health.varta.Status;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.CRC32C;

/**
 * VLP v0.2 wire codec — see {@code book/src/spec/vlp.md}.
 *
 * <p>Frame layout (all little-endian):</p>
 * <pre>
 * offset │ size │ field
 *  0     │  2   │ magic     = 0x56 0x41  ("VA")
 *  2     │  1   │ version   = 0x02
 *  3     │  1   │ status    = OK(0)/DEGRADED(1)/CRITICAL(2)
 *  4     │  4   │ pid       (u32)
 *  8     │  8   │ timestamp (u64, monotonic ns since connect)
 * 16     │  8   │ nonce     (u64, strictly increasing per session)
 * 24     │  4   │ payload   (u32)
 * 28     │  4   │ crc32c    (u32, Castagnoli of bytes 0..28)
 * </pre>
 */
public final class Codec {
    public static final int FRAME_BYTES = 32;
    public static final int MAGIC_0 = 0x56;
    public static final int MAGIC_1 = 0x41;
    public static final byte VERSION = 0x02;
    public static final long NONCE_TERMINAL = 0xFFFF_FFFF_FFFF_FFFFL;
    public static final long NONCE_MIN = 1L;

    private Codec() {}

    /**
     * Encode a frame into the supplied 32-byte buffer (which must be
     * {@link ByteOrder#LITTLE_ENDIAN}). The CRC instance is reset and
     * reused — caller owns its lifecycle so the hot path stays alloc-free.
     */
    public static void encodeInto(ByteBuffer dest, Status status, int pid, long timestamp,
                                  long nonce, int payload, CRC32C crc) {
        if (dest.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("buffer must be LITTLE_ENDIAN");
        }
        if (dest.capacity() < FRAME_BYTES) {
            throw new IllegalArgumentException("buffer too small: " + dest.capacity());
        }
        dest.clear();
        dest.put((byte) MAGIC_0);
        dest.put((byte) MAGIC_1);
        dest.put(VERSION);
        dest.put(status.wireByte());
        dest.putInt(pid);
        dest.putLong(timestamp);
        dest.putLong(nonce);
        dest.putInt(payload);

        crc.reset();
        crc.update(dest.array(), dest.arrayOffset(), 28);
        dest.putInt((int) crc.getValue());
        dest.flip();
    }

    /**
     * Decode a 32-byte frame. Validates in spec-defined order: magic,
     * version, CRC, status, pid, timestamp, nonce. First failure wins.
     */
    public static Frame decode(ByteBuffer src) {
        if (src.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("buffer must be LITTLE_ENDIAN");
        }
        if (src.remaining() < FRAME_BYTES) {
            throw new DecodeError(DecodeErrorKind.BAD_MAGIC,
                "need 32 bytes, got " + src.remaining());
        }

        int basePos = src.position();
        byte[] backing;
        int backingOff;
        if (src.hasArray()) {
            backing = src.array();
            backingOff = src.arrayOffset() + basePos;
        } else {
            backing = new byte[FRAME_BYTES];
            src.duplicate().get(backing);
            backingOff = 0;
        }

        int m0 = backing[backingOff] & 0xFF;
        int m1 = backing[backingOff + 1] & 0xFF;
        if (m0 != MAGIC_0 || m1 != MAGIC_1) {
            throw new DecodeError(DecodeErrorKind.BAD_MAGIC,
                String.format("got 0x%02x 0x%02x", m0, m1));
        }

        int ver = backing[backingOff + 2] & 0xFF;
        if (ver != (VERSION & 0xFF)) {
            throw new DecodeError(DecodeErrorKind.BAD_VERSION, "got 0x" + Integer.toHexString(ver));
        }

        long expectedCrc = ((long) ByteBuffer.wrap(backing, backingOff + 28, 4)
            .order(ByteOrder.LITTLE_ENDIAN).getInt()) & 0xFFFF_FFFFL;
        CRC32C crc = new CRC32C();
        crc.update(backing, backingOff, 28);
        long actualCrc = crc.getValue() & 0xFFFF_FFFFL;
        if (expectedCrc != actualCrc) {
            throw new DecodeError(DecodeErrorKind.BAD_CRC,
                String.format("expected 0x%08x got 0x%08x", expectedCrc, actualCrc));
        }

        byte statusByte = backing[backingOff + 3];
        if (statusByte == Status.STALL_WIRE_BYTE) {
            throw new DecodeError(DecodeErrorKind.STALL_ON_WIRE,
                "Status::STALL is observer-synthesized; never appears on the wire");
        }
        Status status = Status.fromWireByte(statusByte);
        if (status == null) {
            throw new DecodeError(DecodeErrorKind.BAD_STATUS,
                "unknown status byte 0x" + Integer.toHexString(statusByte & 0xFF));
        }

        ByteBuffer view = ByteBuffer.wrap(backing, backingOff, FRAME_BYTES).order(ByteOrder.LITTLE_ENDIAN);
        int pid = view.getInt(backingOff + 4);
        long timestamp = view.getLong(backingOff + 8);
        long nonce = view.getLong(backingOff + 16);
        int payload = view.getInt(backingOff + 24);

        int pidUnsigned = pid; // semantic clarity — pid is treated as u32
        if (pidUnsigned == 0 || pidUnsigned == 1) {
            throw new DecodeError(DecodeErrorKind.BAD_PID,
                "pid=" + Integer.toUnsignedString(pidUnsigned)
                    + " is reserved (0 = kernel, 1 = init/systemd)");
        }
        if (timestamp == 0xFFFF_FFFF_FFFF_FFFFL) {
            throw new DecodeError(DecodeErrorKind.BAD_TIMESTAMP,
                "timestamp = u64::MAX is the reserved saturation sentinel");
        }
        if (nonce == NONCE_TERMINAL && status != Status.CRITICAL) {
            throw new DecodeError(DecodeErrorKind.BAD_NONCE,
                "nonce = NONCE_TERMINAL is permitted only with Status::CRITICAL");
        }

        // Advance the source buffer past the consumed frame.
        src.position(basePos + FRAME_BYTES);

        return new Frame(status, pid, timestamp, nonce, payload);
    }
}
