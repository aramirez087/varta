package health.varta;

/** Why a {@link BeatOutcome.Dropped} happened. Maps to errno classes / typed I/O exceptions. */
public enum DropReason {
    /** {@code EAGAIN} / {@code EWOULDBLOCK} / {@code ENOBUFS}. Kernel send-queue at high-water. */
    KERNEL_QUEUE_FULL,
    /** {@code ECONNREFUSED} / {@code ENOENT}. Observer is not bound to the configured socket. */
    NO_OBSERVER,
    /** {@code ECONNRESET} / {@code ENOTCONN} / {@code EPIPE}. Observer went away mid-session. */
    PEER_GONE,
    /** {@code ENOSPC}. Disk-backed transport (filesystem socket path) ran out of space. */
    STORAGE_FULL;
}
