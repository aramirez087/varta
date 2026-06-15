package health.varta.panic;

import health.varta.Key;
import health.varta.PanicInstallException;
import health.varta.transport.BeatTransport;
import health.varta.transport.SecureUdpTransport;
import health.varta.transport.UdpTransport;
import health.varta.transport.UdsTransport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Install a panic-equivalent handler that emits a {@code CRITICAL} +
 * {@link health.varta.vlp.Codec#NONCE_TERMINAL} beat on JVM shutdown
 * (or, optionally, on POSIX SIGTERM/SIGINT/SIGQUIT/SIGHUP).
 *
 * <p>The transport is pre-bound at install time so the shutdown / signal
 * path makes exactly one non-blocking {@code send(2)} — no allocation, no
 * blocking I/O, no exceptions.</p>
 */
public final class SignalHandler {
    private static final List<String> POSIX_SIGNALS = List.of("TERM", "INT", "HUP", "QUIT");
    private static final AtomicReference<Emitter> ACTIVE = new AtomicReference<>();

    private SignalHandler() {}

    // -------- Shutdown-hook installers (universal, all OSes) --------

    public static AutoCloseable installShutdownHookUds(Path socketPath) {
        return installShutdownHook(() -> openUds(socketPath));
    }

    public static AutoCloseable installShutdownHookUdp(InetSocketAddress addr) {
        return installShutdownHook(() -> openUdp(addr));
    }

    public static AutoCloseable installShutdownHookSecureUdp(InetSocketAddress addr, Key sharedKey) {
        prefetchEntropyOrFail();
        return installShutdownHook(() -> openSecureUdp(addr, sharedKey));
    }

    // -------- sun.misc.Signal-based installers (POSIX only) --------

    public static AutoCloseable installSignalHandlerUds(Path socketPath) {
        return installSignalHandler(() -> openUds(socketPath));
    }

    public static AutoCloseable installSignalHandlerUdp(InetSocketAddress addr) {
        return installSignalHandler(() -> openUdp(addr));
    }

    public static AutoCloseable installSignalHandlerSecureUdp(InetSocketAddress addr, Key sharedKey) {
        prefetchEntropyOrFail();
        return installSignalHandler(() -> openSecureUdp(addr, sharedKey));
    }

    // -------- Wrap a runnable so any thrown Throwable emits Critical+Terminal --------

    public static <X extends Throwable> void run(ThrowingRunnable<X> action) throws X {
        Objects.requireNonNull(action, "action");
        try {
            action.run();
        } catch (Throwable t) {
            Emitter active = ACTIVE.get();
            if (active != null) active.emitBestEffort();
            throw t;
        }
    }

    // -------- internals --------

    private static AutoCloseable installShutdownHook(TransportOpener opener) {
        BeatTransport tx = openOrFail(opener);
        Emitter emitter = new Emitter(tx);
        ACTIVE.compareAndSet(null, emitter);
        Thread hook = new Thread(emitter::emitBestEffort, "varta-shutdown-hook");
        Runtime.getRuntime().addShutdownHook(hook);
        return () -> {
            try { Runtime.getRuntime().removeShutdownHook(hook); } catch (IllegalStateException ignored) {}
            ACTIVE.compareAndSet(emitter, null);
            emitter.close();
        };
    }

    private static AutoCloseable installSignalHandler(TransportOpener opener) {
        if (isWindows()) {
            throw new UnsupportedOperationException(
                "sun.misc.Signal-based handlers are POSIX-only; use installShutdownHook* on Windows");
        }
        BeatTransport tx = openOrFail(opener);
        Emitter emitter = new Emitter(tx);
        ACTIVE.compareAndSet(null, emitter);

        Map<String, sun.misc.SignalHandler> previous = new HashMap<>();
        for (String name : POSIX_SIGNALS) {
            try {
                sun.misc.Signal sig = new sun.misc.Signal(name);
                // The lambda looks up `previous.get(name)` at FIRE time (by then
                // the map is fully populated), so it can chain to the handler
                // that was installed before ours.
                sun.misc.SignalHandler prev = sun.misc.Signal.handle(sig, signal ->
                    onTerminatingSignal(signal, previous.get(name), emitter, SignalHandler::reRaiseSignal));
                previous.put(name, prev);
            } catch (IllegalArgumentException ignored) {
                // signal not supported on this OS — skip silently
            }
        }
        return () -> {
            for (var e : previous.entrySet()) {
                try {
                    sun.misc.Signal.handle(new sun.misc.Signal(e.getKey()), e.getValue());
                } catch (Throwable ignored) {}
            }
            ACTIVE.compareAndSet(emitter, null);
            emitter.close();
        };
    }

    /**
     * Signal-fire action: emit the terminal beat, then restore the handler that
     * was installed before ours and re-raise the signal so it — the host's
     * graceful-shutdown handler, or the JVM default that runs shutdown hooks —
     * still runs. A plain {@code System.exit(128 + sig)} here (the prior
     * behaviour) skipped the previously-installed {@code sun.misc.Signal}
     * handler entirely, silently clobbering host teardown. Mirrors the
     * cross-client contract: Node removes its own listener and re-raises
     * (bug-481), Go uses {@code signal.Reset} + re-raise, and the Rust/Python
     * hooks chain to the previous hook. Re-raising the signal also yields the
     * conventional {@code 128 + signum} exit status without hard-coding it.
     *
     * <p>The re-raise is injected so the restore-and-chain can be unit-tested
     * without delivering a real signal to the test JVM.</p>
     */
    static void onTerminatingSignal(
            sun.misc.Signal sig,
            sun.misc.SignalHandler previousHandler,
            Emitter emitter,
            Consumer<sun.misc.Signal> reRaise) {
        emitter.emitBestEffort();
        // Restore the prior handler (or the default disposition if somehow
        // none) BEFORE re-raising, so the re-raised signal runs that handler
        // rather than re-entering THIS one in an infinite loop.
        sun.misc.SignalHandler prev =
            previousHandler != null ? previousHandler : sun.misc.SignalHandler.SIG_DFL;
        sun.misc.Signal.handle(sig, prev);
        reRaise.accept(sig);
    }

    private static void reRaiseSignal(sun.misc.Signal sig) {
        sun.misc.Signal.raise(sig);
    }

    private static BeatTransport openOrFail(TransportOpener opener) {
        try {
            return opener.open();
        } catch (IOException e) {
            throw new PanicInstallException(
                "could not pre-bind transport for panic handler: " + e.getMessage(), e);
        }
    }

    private static BeatTransport openUds(Path socketPath) throws IOException {
        return UdsTransport.create(socketPath);
    }

    private static BeatTransport openUdp(InetSocketAddress addr) throws IOException {
        return UdpTransport.create(addr);
    }

    private static BeatTransport openSecureUdp(InetSocketAddress addr, Key sharedKey) throws IOException {
        return SecureUdpTransport.createShared(addr, sharedKey);
    }

    private static void prefetchEntropyOrFail() {
        try {
            SecureRandom rng;
            try {
                rng = SecureRandom.getInstance("NativePRNGNonBlocking");
            } catch (NoSuchAlgorithmException ignored) {
                rng = SecureRandom.getInstanceStrong();
            }
            byte[] probe = new byte[16];
            rng.nextBytes(probe);
        } catch (Exception e) {
            throw new PanicInstallException(
                "OS RNG unavailable for Secure UDP panic handler", e);
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    @FunctionalInterface
    private interface TransportOpener {
        BeatTransport open() throws IOException;
    }
}
