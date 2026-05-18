package health.varta.errno;

import health.varta.BeatError;
import health.varta.BeatOutcome;
import health.varta.DropReason;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.PortUnreachableException;
import java.net.SocketException;
import java.nio.channels.ClosedChannelException;
import java.util.Locale;

/**
 * Classify a thrown {@link IOException} into a {@link BeatOutcome.Dropped}
 * (when the failure is a recognised backpressure / observer-absent / peer-gone /
 * storage-full condition) or a {@link BeatOutcome.Failed} (otherwise).
 */
public final class ErrnoClassifier {
    private ErrnoClassifier() {}

    public static BeatOutcome classify(IOException e) {
        // 1) Typed exceptions — covered by JDK regardless of locale.
        if (e instanceof PortUnreachableException) {
            return BeatOutcome.dropped(DropReason.NO_OBSERVER);
        }
        if (e instanceof ClosedChannelException) {
            return BeatOutcome.dropped(DropReason.PEER_GONE);
        }

        // 2) junixsocket numeric errno (when available).
        int junixErrno = tryExtractJunixsocketErrno(e);
        if (junixErrno > 0) {
            DropReason mapped = mapErrno(junixErrno);
            if (mapped != null) return BeatOutcome.dropped(mapped);
        }

        // 3) Message-string heuristics. The JDK's IOException messages are
        // English and largely stable across HotSpot vendors.
        String msg = (e.getMessage() == null ? "" : e.getMessage()).toLowerCase(Locale.ROOT);

        if (e instanceof SocketException) {
            if (matchesKernelQueueFull(msg)) return BeatOutcome.dropped(DropReason.KERNEL_QUEUE_FULL);
            if (matchesNoObserver(msg))      return BeatOutcome.dropped(DropReason.NO_OBSERVER);
            if (matchesPeerGone(msg))        return BeatOutcome.dropped(DropReason.PEER_GONE);
            if (matchesStorageFull(msg))     return BeatOutcome.dropped(DropReason.STORAGE_FULL);
        }
        if (matchesKernelQueueFull(msg)) return BeatOutcome.dropped(DropReason.KERNEL_QUEUE_FULL);
        if (matchesNoObserver(msg))      return BeatOutcome.dropped(DropReason.NO_OBSERVER);
        if (matchesPeerGone(msg))        return BeatOutcome.dropped(DropReason.PEER_GONE);
        if (matchesStorageFull(msg))     return BeatOutcome.dropped(DropReason.STORAGE_FULL);

        return BeatOutcome.failed(new BeatError(
            junixErrno, e.getClass().getSimpleName() + ": " + (e.getMessage() == null ? "" : e.getMessage())));
    }

    private static boolean matchesKernelQueueFull(String m) {
        return m.contains("no buffer space")
            || m.contains("would block")
            || m.contains("resource temporarily unavailable")
            || m.contains("operation would block");
    }

    private static boolean matchesNoObserver(String m) {
        return m.contains("connection refused")
            || m.contains("no such file")
            || m.contains("no such file or directory");
    }

    private static boolean matchesPeerGone(String m) {
        return m.contains("connection reset")
            || m.contains("broken pipe")
            || m.contains("not connected")
            || m.contains("socket is not connected");
    }

    private static boolean matchesStorageFull(String m) {
        return m.contains("no space left");
    }

    /** Best-effort errno extraction from junixsocket's AFSocketException via reflection. */
    static int tryExtractJunixsocketErrno(Throwable t) {
        while (t != null) {
            String name = t.getClass().getName();
            if (name.startsWith("org.newsclub.net.unix.")) {
                // AFSocketException doesn't expose errno publicly across versions;
                // try `getErrno()` reflectively, then fall back to the cause chain.
                try {
                    Method m = t.getClass().getMethod("getErrno");
                    Object v = m.invoke(t);
                    if (v instanceof Number n) return n.intValue();
                } catch (ReflectiveOperationException ignored) {
                    // fall through
                }
            }
            t = t.getCause();
        }
        return 0;
    }

    /** POSIX errno → DropReason. Linux/macOS values where they agree. */
    private static DropReason mapErrno(int errno) {
        // EAGAIN/EWOULDBLOCK = 11 (Linux) / 35 (macOS); ENOBUFS = 105 (Linux) / 55 (macOS).
        if (errno == 11 || errno == 35 || errno == 105 || errno == 55) return DropReason.KERNEL_QUEUE_FULL;
        // ECONNREFUSED = 111 (Linux) / 61 (macOS); ENOENT = 2.
        if (errno == 111 || errno == 61 || errno == 2) return DropReason.NO_OBSERVER;
        // ECONNRESET = 104/54; EPIPE = 32; ENOTCONN = 107/57.
        if (errno == 104 || errno == 54 || errno == 32 || errno == 107 || errno == 57) return DropReason.PEER_GONE;
        // ENOSPC = 28.
        if (errno == 28) return DropReason.STORAGE_FULL;
        return null;
    }
}
