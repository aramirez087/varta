package health.varta.panic;

import health.varta.Status;
import health.varta.transport.BeatTransport;
import health.varta.vlp.Codec;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.CRC32C;

/**
 * Pre-bound transport + pre-encoded Critical+NONCE_TERMINAL frame. The
 * {@link #emitBestEffort()} call performs exactly one non-blocking
 * {@code send(2)} and swallows any failure — same posture as Go's
 * {@code panic/signal.go} and the .NET {@code SignalHandler}.
 */
final class Emitter {
    private final BeatTransport transport;
    private final ByteBuffer frameBuf;
    private final byte[] frameBytes = new byte[Codec.FRAME_BYTES];

    Emitter(BeatTransport transport) {
        this.transport = transport;
        this.frameBuf = ByteBuffer.wrap(frameBytes).order(ByteOrder.LITTLE_ENDIAN);
        // Pre-encode a Critical + NONCE_TERMINAL frame. timestamp=0 because
        // we don't have a coherent monotonic baseline at install time; the
        // observer ignores timestamp on Critical+Terminal beats.
        int pid = (int) ProcessHandle.current().pid();
        Codec.encodeInto(frameBuf, Status.CRITICAL, pid, 0L, Codec.NONCE_TERMINAL, 0, new CRC32C());
    }

    void emitBestEffort() {
        try {
            frameBuf.rewind();
            transport.send(frameBuf);
        } catch (Throwable ignored) {
            // Best-effort by design — never throw from a signal/shutdown path.
        }
    }

    void close() {
        try { transport.close(); } catch (Throwable ignored) {}
    }
}
