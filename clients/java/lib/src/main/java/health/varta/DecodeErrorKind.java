package health.varta;

/**
 * Reason a VLP frame failed to decode. Matches the {@code expected_decode_error}
 * values in {@code tools/vlp-test-vectors.json}.
 */
public enum DecodeErrorKind {
    BAD_MAGIC,
    BAD_VERSION,
    BAD_CRC,
    BAD_STATUS,
    STALL_ON_WIRE,
    BAD_PID,
    BAD_TIMESTAMP,
    BAD_NONCE;
}
