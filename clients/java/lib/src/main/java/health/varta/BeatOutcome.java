package health.varta;

import java.util.Objects;

/**
 * Result of {@link Varta#beat(Status, int)}. Modelled as a sealed interface so
 * downstream callers can pattern-match exhaustively. Three variants:
 * <ul>
 *   <li>{@link Sent} — frame handed to the kernel.</li>
 *   <li>{@link Dropped} — frame not sent (back-pressure or observer absent).
 *       Carries a {@link DropReason} for diagnostics.</li>
 *   <li>{@link Failed} — unexpected error. Carries a {@link BeatError}.</li>
 * </ul>
 */
public sealed interface BeatOutcome
    permits BeatOutcome.Sent, BeatOutcome.Dropped, BeatOutcome.Failed {

    record Sent() implements BeatOutcome {
        public static final Sent INSTANCE = new Sent();
    }

    record Dropped(DropReason reason) implements BeatOutcome {
        public Dropped { Objects.requireNonNull(reason, "reason"); }
    }

    record Failed(BeatError error) implements BeatOutcome {
        public Failed { Objects.requireNonNull(error, "error"); }
    }

    /** Cached singleton — keeps the happy path allocation-free. */
    static BeatOutcome sent() { return Sent.INSTANCE; }

    static BeatOutcome dropped(DropReason reason) { return new Dropped(reason); }

    static BeatOutcome failed(BeatError error) { return new Failed(error); }

    default boolean isSent()    { return this instanceof Sent; }
    default boolean isDropped() { return this instanceof Dropped; }
    default boolean isFailed()  { return this instanceof Failed; }
}
