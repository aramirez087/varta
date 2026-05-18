package health.varta;

/**
 * Thrown by {@link Frame#decode(byte[])} / {@link Frame#decode(java.nio.ByteBuffer)}
 * when a VLP frame fails validation. Inspect {@link #kind()} for the
 * structured rejection reason.
 */
public final class DecodeError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final DecodeErrorKind kind;

    public DecodeError(DecodeErrorKind kind, String detail) {
        super(kind.name() + ": " + detail);
        this.kind = kind;
    }

    public DecodeErrorKind kind() {
        return kind;
    }
}
