package health.varta.panic;

import health.varta.Status;
import health.varta.transport.BeatTransport;
import health.varta.vlp.Codec;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.CRC32C;

/**
 * Pre-bound transport + preallocated Critical+NONCE_TERMINAL frame. The
 * {@link #emitBestEffort()} call stamps a process-monotonic terminal timestamp,
 * performs exactly one non-blocking {@code send(2)}, and swallows any failure
 * — same posture as Go's {@code panic/signal.go} and the .NET
 * {@code SignalHandler}.
 */
final class Emitter {
    private static final long CLOCK_EPOCH_NANOS = System.nanoTime();
    private static final AtomicLong LAST_TERMINAL_TIMESTAMP = new AtomicLong();

    private final BeatTransport transport;
    private final ByteBuffer frameBuf;
    private final byte[] frameBytes = new byte[Codec.FRAME_BYTES];
    private final CRC32C crc = new CRC32C();
    private final AtomicBoolean emitting = new AtomicBoolean();
    private final int pid;

    Emitter(BeatTransport transport) {
        this.transport = transport;
        this.frameBuf = ByteBuffer.wrap(frameBytes).order(ByteOrder.LITTLE_ENDIAN);
        this.pid = (int) ProcessHandle.current().pid();
    }

    void emitBestEffort() {
        // Signal, shutdown-hook, and run() paths may race. Never block in this
        // path and never let two callers mutate the shared frame/transport
        // state concurrently; a concurrent duplicate is best-effort dropped.
        if (!emitting.compareAndSet(false, true)) return;
        try {
            Codec.encodeInto(
                frameBuf,
                Status.CRITICAL,
                pid,
                nextTerminalTimestamp(),
                Codec.NONCE_TERMINAL,
                0,
                crc);
            transport.send(frameBuf);
        } catch (Throwable ignored) {
            // Best-effort by design — never throw from a signal/shutdown path.
        } finally {
            emitting.set(false);
        }
    }

    private static long nextTerminalTimestamp() {
        // A process-wide epoch survives handler reinstallation. The CAS clamp
        // also makes successive terminal frames strictly ordered when
        // System.nanoTime() has coarse resolution.
        long elapsed = Math.max(1L, System.nanoTime() - CLOCK_EPOCH_NANOS);
        while (true) {
            long previous = LAST_TERMINAL_TIMESTAMP.get();
            long candidate = Math.max(elapsed, previous + 1L);
            if (LAST_TERMINAL_TIMESTAMP.compareAndSet(previous, candidate)) {
                return candidate;
            }
        }
    }

    void close() {
        try { transport.close(); } catch (Throwable ignored) {}
    }
}
