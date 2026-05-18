package health.varta.transport;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Non-blocking, datagram-oriented send interface used by {@link health.varta.Varta}.
 * Implementations: {@code UdpTransport}, {@code UdsTransport} (via
 * provider-specific impl), {@code SecureUdpTransport}.
 *
 * <p>Implementations MUST be non-blocking. {@link #send(ByteBuffer)} returns
 * the number of bytes written; a return of {@code 0} indicates kernel-queue
 * backpressure (the agent maps that to {@code Dropped(KERNEL_QUEUE_FULL)}).
 * Throwing means a typed I/O failure to be classified by
 * {@code ErrnoClassifier}.</p>
 */
public interface BeatTransport extends AutoCloseable {
    /** Send one frame. Returns bytes written (0 on WouldBlock). */
    int send(ByteBuffer frame) throws IOException;

    /** Reopen the underlying socket. Used after fork(2) or operator-requested reconnect. */
    void reconnect() throws IOException;

    /** Best-effort close; never throws. */
    @Override
    void close();
}
