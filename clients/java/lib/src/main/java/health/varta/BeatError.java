package health.varta;

/**
 * Unexpected failure from {@link Varta#beat(Status, int)}. {@code errno} is
 * the platform errno when extractable (currently only from junixsocket's
 * {@code AFSocketException}); otherwise 0. {@code kind} carries the
 * exception class + message for diagnostics.
 */
public record BeatError(int errno, String kind) {}
