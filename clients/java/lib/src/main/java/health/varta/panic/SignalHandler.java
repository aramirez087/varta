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
                sun.misc.SignalHandler prev = sun.misc.Signal.handle(sig, signal -> {
                    emitter.emitBestEffort();
                    System.exit(128 + signalNumber(name));
                });
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

    private static int signalNumber(String name) {
        return switch (name) {
            case "HUP" -> 1;
            case "INT" -> 2;
            case "QUIT" -> 3;
            case "TERM" -> 15;
            default -> 1;
        };
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
