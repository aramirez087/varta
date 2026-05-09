package health.varta.vlp;

import java.util.zip.CRC32C;

/**
 * Thin wrapper around {@link java.util.zip.CRC32C} (JDK 9+; hardware-accelerated
 * via SSE4.2 / ARMv8 CRC intrinsics on supported CPUs).
 *
 * <p>The VLP frame trailer is the CRC-32C of the first 28 bytes, written
 * little-endian at offset 28..32.</p>
 */
public final class Crc32C {
    private Crc32C() {}

    /** One-shot CRC-32C for arbitrary input. Allocates a fresh instance — for tests only. */
    public static long compute(byte[] input) {
        CRC32C crc = new CRC32C();
        crc.update(input, 0, input.length);
        return crc.getValue() & 0xFFFF_FFFFL;
    }

    /** One-shot CRC-32C for a slice. */
    public static long compute(byte[] input, int offset, int length) {
        CRC32C crc = new CRC32C();
        crc.update(input, offset, length);
        return crc.getValue() & 0xFFFF_FFFFL;
    }
}
