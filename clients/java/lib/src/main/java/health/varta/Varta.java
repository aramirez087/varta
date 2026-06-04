package health.varta;

import health.varta.errno.ErrnoClassifier;
import health.varta.transport.BeatTransport;
import health.varta.transport.UdpTransport;
import health.varta.transport.UdsTransport;
import health.varta.vlp.Codec;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.util.Objects;
import java.util.zip.CRC32C;

/**
 * Varta agent — emit 32-byte VLP heartbeats to a local observer.
 *
 * <p>Use the static factories to connect ({@link #connect(Path)},
 * {@link #connectUdp(InetSocketAddress)},
 * {@link #connectSecureUdp(InetSocketAddress, Key)},
 * {@link #connectSecureUdpWithMaster(InetSocketAddress, Key)}), then call
 * {@link #beat(Status, int)} on a fixed cadence (typically every 500 ms).</p>
 *
 * <p>{@code beat()} is non-blocking and never throws. A return of
 * {@link BeatOutcome.Dropped} indicates either kernel backpressure or
 * observer-absent — both are recoverable conditions the application can
 * log or ignore. {@link BeatOutcome.Failed} signals an unexpected error.</p>
 *
 * <p>The class is thread-safe: a single intrinsic monitor serialises all
 * {@code beat()} calls. Concurrent emit from many threads is supported
 * but the call rate is bounded by the cost of one
 * {@code System.nanoTime} + one non-blocking {@code send(2)}.</p>
 */
public final class Varta implements AutoCloseable {
    public static final int FRAME_BYTES = Codec.FRAME_BYTES;
    public static final long NONCE_TERMINAL = Codec.NONCE_TERMINAL;
    public static final long NONCE_MIN = Codec.NONCE_MIN;

    private final Object lock = new Object();
    private final BeatTransport transport;
    private final byte[] scratch = new byte[FRAME_BYTES];
    private final ByteBuffer scratchBuf = ByteBuffer.wrap(scratch).order(ByteOrder.LITTLE_ENDIAN);
    private final CRC32C crc = new CRC32C();
    private final long startNanos = System.nanoTime();

    private int connectPid;
    private long nonce = NONCE_MIN;
    private long lastTimestamp = 0L;
    private long clockRegressions = 0L;
    private long forkRecoveries = 0L;
    private int reconnectAfter = 0;
    private int consecutiveDropped = 0;
    private boolean closed = false;

    private Varta(BeatTransport transport) {
        this.transport = transport;
        this.connectPid = currentPid();
    }

    /** Connect over UDS (AF_UNIX SOCK_DGRAM). Requires a UDS provider on the classpath. */
    public static Varta connect(Path socketPath) {
        Objects.requireNonNull(socketPath, "socketPath");
        try {
            return new Varta(UdsTransport.create(socketPath));
        } catch (IOException e) {
            throw new IllegalStateException("Varta.connect: " + e.getMessage(), e);
        }
    }

    /** Connect over plaintext UDP. Recovery commands are refused by the observer. */
    public static Varta connectUdp(InetSocketAddress addr) {
        Objects.requireNonNull(addr, "addr");
        try {
            return new Varta(UdpTransport.create(addr));
        } catch (IOException e) {
            throw new IllegalStateException("Varta.connectUdp: " + e.getMessage(), e);
        }
    }

    /**
     * Connect over ChaCha20-Poly1305 AEAD UDP using a 32-byte shared key.
     * The wire frame is 60 bytes; AAD is empty. Recovery is refused.
     * <p>Implementation lives in {@code health.varta.transport.SecureUdpTransport}
     * — wired in Phase 3.</p>
     */
    public static Varta connectSecureUdp(InetSocketAddress addr, Key key) {
        Objects.requireNonNull(addr, "addr");
        Objects.requireNonNull(key, "key");
        try {
            return new Varta(health.varta.transport.SecureUdpTransport.createShared(addr, key));
        } catch (IOException e) {
            throw new IllegalStateException("Varta.connectSecureUdp: " + e.getMessage(), e);
        }
    }

    /**
     * Connect over ChaCha20-Poly1305 AEAD UDP using a 32-byte master key.
     * The wire frame is 64 bytes; AAD = {@code u32_LE(agentPid)}. Recovery is refused.
     */
    public static Varta connectSecureUdpWithMaster(InetSocketAddress addr, Key masterKey) {
        Objects.requireNonNull(addr, "addr");
        Objects.requireNonNull(masterKey, "masterKey");
        try {
            return new Varta(health.varta.transport.SecureUdpTransport.createMaster(addr, masterKey));
        } catch (IOException e) {
            throw new IllegalStateException("Varta.connectSecureUdpWithMaster: " + e.getMessage(), e);
        }
    }

    /** Emit one beat with payload = 0. Convenience for the common case. */
    public BeatOutcome beat(Status status) {
        return beat(status, 0);
    }

    /** Emit one beat with the supplied 32-bit payload. Non-blocking; never throws. */
    public BeatOutcome beat(Status status, int payload) {
        Objects.requireNonNull(status, "status");
        synchronized (lock) {
            if (closed) {
                return BeatOutcome.failed(new BeatError(0, "Varta agent is closed"));
            }

            // 1) Fork-safety: PID changed → reconnect, reset session state.
            int currentPid = currentPid();
            if (currentPid != connectPid) {
                try {
                    transport.reconnect();
                    connectPid = currentPid;
                    nonce = NONCE_MIN;
                    lastTimestamp = 0L;
                    consecutiveDropped = 0;
                    forkRecoveries = saturatingInc(forkRecoveries);
                } catch (IOException e) {
                    return ErrnoClassifier.classify(e);
                }
            }

            // 2) Monotonic timestamp + regression clamp.
            long nowNs = System.nanoTime() - startNanos;
            if (nowNs < lastTimestamp) {
                clockRegressions = saturatingInc(clockRegressions);
                nowNs = lastTimestamp;
            }
            lastTimestamp = nowNs;

            // 3) Sentinel reservation: u64::MAX is reserved.
            if (nowNs == 0xFFFF_FFFF_FFFF_FFFFL) {
                nowNs = 0xFFFF_FFFF_FFFF_FFFEL;
            }

            // 4) Nonce sequencing.
            long n = nonce;
            if (n == NONCE_TERMINAL) {
                System.err.println("[varta] nonce wrapped past terminal; recycling from " + NONCE_MIN);
                n = NONCE_MIN;
                nonce = NONCE_MIN;
            } else {
                nonce = n + 1;
                if (nonce == NONCE_TERMINAL && status != Status.CRITICAL) {
                    // Avoid emitting terminal nonce on a non-Critical beat next call.
                    nonce = NONCE_MIN;
                }
            }

            // 5) Encode + send. On a Dropped outcome, mirror the cross-client
            // contract: after `reconnectAfter` consecutive drops, reconnect and
            // retry once (recovery from an observer restart). The counter resets
            // on any Sent or Failed outcome.
            Codec.encodeInto(scratchBuf, status, currentPid, nowNs, n, payload, crc);
            BeatOutcome outcome = sendScratch();
            if (outcome instanceof BeatOutcome.Sent) {
                consecutiveDropped = 0;
                return outcome;
            }
            if (outcome instanceof BeatOutcome.Dropped) {
                consecutiveDropped = saturatingIncInt(consecutiveDropped);
                if (reconnectAfter > 0 && consecutiveDropped >= reconnectAfter) {
                    boolean reconnected;
                    try {
                        transport.reconnect();
                        reconnected = true;
                    } catch (IOException e) {
                        reconnected = false;
                    }
                    if (reconnected) {
                        // Reset only on a *successful* reconnect. A failed
                        // reconnect leaves the counter saturated so the next
                        // Dropped beat re-crosses the threshold and retries
                        // immediately, rather than re-arming a full
                        // reconnectAfter-beat window.
                        consecutiveDropped = 0;
                        return sendScratch();
                    }
                }
                return outcome;
            }
            // Failed: reset like a Sent so a transient error does not arm a
            // spurious reconnect on the next drop.
            consecutiveDropped = 0;
            return outcome;
        }
    }

    /** Send the already-encoded scratch buffer once and classify the result. */
    private BeatOutcome sendScratch() {
        scratchBuf.rewind();
        try {
            int written = transport.send(scratchBuf);
            if (written == 0) {
                return BeatOutcome.dropped(DropReason.KERNEL_QUEUE_FULL);
            }
            return BeatOutcome.sent();
        } catch (IOException e) {
            return ErrnoClassifier.classify(e);
        }
    }

    /** Reopen the underlying transport. Throws {@link IllegalStateException} on I/O failure. */
    public void reconnect() {
        synchronized (lock) {
            try {
                transport.reconnect();
                connectPid = currentPid();
                nonce = NONCE_MIN;
                lastTimestamp = 0L;
                consecutiveDropped = 0;
            } catch (IOException e) {
                throw new IllegalStateException("Varta.reconnect: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Auto-reconnect after {@code n} consecutive {@link BeatOutcome.Dropped}
     * outcomes — recovery from an observer restart. The internal counter
     * increments on each Dropped beat and resets to zero on any Sent or Failed
     * outcome; once it reaches {@code n} the next beat reconnects and retries
     * once. {@code 0} (default) disables auto-reconnect. Mirrors Rust's
     * {@code Varta::set_reconnect_after}.
     */
    public void setReconnectAfter(int n) {
        if (n < 0) throw new IllegalArgumentException("n must be >= 0");
        synchronized (lock) {
            this.reconnectAfter = n;
            this.consecutiveDropped = 0;
        }
    }

    /** Saturating counter of detected clock regressions. */
    public long clockRegressions() {
        synchronized (lock) {
            return clockRegressions;
        }
    }

    /** Saturating counter of fork-driven reconnects. */
    public long forkRecoveries() {
        synchronized (lock) {
            return forkRecoveries;
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            if (closed) return;
            closed = true;
            transport.close();
        }
    }

    private static long saturatingInc(long v) {
        return v == Long.MAX_VALUE ? v : v + 1;
    }

    private static int saturatingIncInt(int v) {
        return v == Integer.MAX_VALUE ? v : v + 1;
    }

    private static int currentPid() {
        return (int) ProcessHandle.current().pid();
    }

    // Test hooks — package-private, no public stability contract.

    static Varta __forTest(BeatTransport transport) {
        return new Varta(transport);
    }

    void __setConnectPidForTest(int pid) {
        synchronized (lock) { this.connectPid = pid; }
    }

    void __setNonceForTest(long n) {
        synchronized (lock) { this.nonce = n; }
    }

    long __getNonceForTest() {
        synchronized (lock) { return nonce; }
    }
}
