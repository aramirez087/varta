package health.varta;

/**
 * Agent-emitted health status carried on byte offset 3 of every VLP frame.
 *
 * <p>{@code STALL} is observer-synthesized and never appears on the wire;
 * the decoder rejects it as {@link DecodeErrorKind#STALL_ON_WIRE}.</p>
 */
public enum Status {
    /** Wire byte {@code 0x00}. */
    OK((byte) 0x00),
    /** Wire byte {@code 0x01}. */
    DEGRADED((byte) 0x01),
    /** Wire byte {@code 0x02}. */
    CRITICAL((byte) 0x02);

    private final byte wireByte;

    Status(byte wireByte) {
        this.wireByte = wireByte;
    }

    public byte wireByte() {
        return wireByte;
    }

    /** Wire byte 0x03, reserved for observer-synthesized STALL. Never agent-emitted. */
    public static final byte STALL_WIRE_BYTE = (byte) 0x03;

    public static Status fromWireByte(byte b) {
        return switch (b) {
            case 0x00 -> OK;
            case 0x01 -> DEGRADED;
            case 0x02 -> CRITICAL;
            default -> null;
        };
    }
}
