/**
 * Best-effort classification of {@link java.io.IOException} into
 * {@link health.varta.DropReason} variants.
 *
 * <p>Java does not expose {@code errno} directly. The classifier combines
 * (a) typed exception class checks, (b) junixsocket's numeric errno when
 * present, and (c) message-string heuristics across HotSpot, Temurin,
 * Zulu, and Corretto. Unrecognised exceptions surface as
 * {@code BeatOutcome.Failed} — never silently as {@code Dropped}.</p>
 */
package health.varta.errno;
