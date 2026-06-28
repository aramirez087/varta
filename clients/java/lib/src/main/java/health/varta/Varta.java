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
import java.util.concurrent.atomic.AtomicBoolean;
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
    private static final AtomicBoolean NONCE_WRAP_WARNED = new AtomicBoolean(false);

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
        if (status == null) {
            return BeatOutcome.failed(new BeatError(0, "InvalidInput"));
        }
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
                    // Fork-recovery reconnect failed: the fork invalidated the
                    // old socket and a new one could not be established, so the
                    // beat path is broken. This is a terminal error, NOT a
                    // transient drop — return Failed unconditionally, matching
                    // the Rust reference (BeatOutcome::Failed(BeatError::from_io))
                    // and every other client (Go "ReconnectFailed", Python/Node
                    // from_oserror/fromNodeError, .NET). Routing it through
                    // ErrnoClassifier would misclassify e.g. "connection refused"
                    // as Dropped(NO_OBSERVER), telling the caller the beat path
                    // is still operational when fork recovery has actually
                    // failed — so it would keep retrying a dead beat loop instead
                    // of surfacing the hard failure.
                    return BeatOutcome.failed(new BeatError(0, "ReconnectFailed"));
                }
            }

            // 2) Monotonic timestamp + regression clamp. Compute the candidate
            // high-water WITHOUT committing it; commit-on-success advances it
            // only when send accepts the datagram.
            long nowNs = System.nanoTime() - startNanos;
            if (nowNs < lastTimestamp) {
                clockRegressions = saturatingInc(clockRegressions);
                nowNs = lastTimestamp;
            }
            long candidateTimestamp = nowNs;

            // 3) Sentinel reservation: u64::MAX is reserved on the wire.
            long wireTimestamp = nowNs;
            if (wireTimestamp == 0xFFFF_FFFF_FFFF_FFFFL) {
                wireTimestamp = 0xFFFF_FFFF_FFFF_FFFEL;
            }

            // 4) Nonce sequencing — compute the wire nonce and the value the
            // counter advances to WITHOUT committing either until send succeeds
            // (commit-on-success). A Dropped or Failed attempt leaves the same
            // candidate for the next beat, so no invisible nonce/timestamp is
            // burned on the wire. Mirrors crates/varta-client/src/client.rs
            // (next_regular_nonce / commit_sent_frame).
            long candidateNonce = nonce;
            long nextNonce;
            boolean wrappedNonce = false;
            if (candidateNonce == NONCE_TERMINAL) {
                // NONCE_TERMINAL is reserved for panic-hook Critical frames.
                // The regular stream wraps to wire nonce 0 and only commits
                // to nonce 1 after the send succeeds.
                candidateNonce = 0L;
                nextNonce = NONCE_MIN;
                wrappedNonce = true;
            } else {
                nextNonce = candidateNonce + 1;
            }

            // 5) Encode + send. On a Dropped outcome, mirror the cross-client
            // contract: after `reconnectAfter` consecutive drops, reconnect and
            // retry once (recovery from an observer restart). The counter resets
            // on any Sent or Failed outcome. Nonce/timestamp commit only for a
            // frame the kernel actually accepted.
            Codec.encodeInto(scratchBuf, status, currentPid, wireTimestamp, candidateNonce, payload, crc);
            BeatOutcome outcome = sendScratch();
            if (outcome instanceof BeatOutcome.Sent) {
                commitSentFrame(nextNonce, candidateTimestamp, wrappedNonce);
                consecutiveDropped = 0;
                return outcome;
            }
            if (outcome instanceof BeatOutcome.Dropped) {
                consecutiveDropped = saturatingIncInt(consecutiveDropped);
                if (reconnectAfter > 0 && consecutiveDropped >= reconnectAfter) {
                    consecutiveDropped = 0;
                    boolean reconnected;
                    try {
                        transport.reconnect();
                        reconnected = true;
                    } catch (IOException e) {
                        reconnected = false;
                    }
                    if (reconnected) {
                        BeatOutcome retry = sendScratch();
                        if (retry instanceof BeatOutcome.Sent) {
                            commitSentFrame(nextNonce, candidateTimestamp, wrappedNonce);
                        }
                        return retry;
                    }
                }
                return outcome;
            }
            // Failed: reset like a Sent so a transient error does not arm a
            // spurious reconnect on the next drop. Nonce/timestamp stay
            // uncommitted for the next beat.
            consecutiveDropped = 0;
            return outcome;
        }
    }

    /**
     * Advance the committed nonce/timestamp after the kernel accepted the
     * datagram (commit-on-success).
     */
    private void commitSentFrame(long nextNonce, long timestamp, boolean wrappedNonce) {
        nonce = nextNonce;
        lastTimestamp = timestamp;
        if (wrappedNonce) {
            warnNonceWrapping();
        }
    }

    private static void warnNonceWrapping() {
        if (NONCE_WRAP_WARNED.compareAndSet(false, true)) {
            System.err.println("[varta] nonce exhausted; wrapping to 0");
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
            if (written != FRAME_BYTES) {
                return BeatOutcome.failed(new BeatError(0, "WriteZero"));
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
