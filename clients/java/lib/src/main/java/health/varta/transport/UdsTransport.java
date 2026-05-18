package health.varta.transport;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.Objects;

/**
 * UDS (AF_UNIX SOCK_DGRAM) provider dispatcher.
 *
 * <p>No shipping JDK (through 22+) exposes {@code SOCK_DGRAM} AF_UNIX via
 * standard NIO. This dispatcher probes the classpath at runtime:</p>
 *
 * <ol>
 *   <li><b>FFM provider</b> ({@code health.varta.transport.UdsTransportFfm},
 *       requires JDK 22+ and the future {@code varta-client-ffm} module)</li>
 *   <li><b>junixsocket</b> ({@code org.newsclub.net.unix.AFUNIXDatagramChannel})</li>
 * </ol>
 *
 * <p>Throws {@link NoUdsTransportException} if neither is present with a
 * message naming both remediation paths.</p>
 */
public final class UdsTransport {
    private UdsTransport() {}

    public static BeatTransport create(Path socketPath) throws IOException {
        Objects.requireNonNull(socketPath, "socketPath");

        // Strategy 1: FFM provider (JDK 22+).
        try {
            Class<?> ffm = Class.forName("health.varta.transport.UdsTransportFfm");
            Method create = ffm.getMethod("create", Path.class);
            return (BeatTransport) create.invoke(null, socketPath);
        } catch (ClassNotFoundException ignored) {
            // not on classpath — fall through
        } catch (NoSuchMethodException | IllegalAccessException e) {
            throw new IOException("FFM provider present but has invalid signature", e);
        } catch (InvocationTargetException e) {
            // FFM provider threw; surface the cause.
            Throwable cause = e.getCause();
            if (cause instanceof IOException io) throw io;
            if (cause instanceof RuntimeException re) throw re;
            throw new IOException("FFM provider failed", cause);
        }

        // Strategy 2: junixsocket.
        try {
            Class.forName("org.newsclub.net.unix.AFUNIXSocketAddress");
            return UdsTransportJunixsocket.create(socketPath);
        } catch (ClassNotFoundException ignored) {
            throw new NoUdsTransportException(
                "No AF_UNIX SOCK_DGRAM provider found on the classpath.\n" +
                "Add one of the following to your build:\n" +
                "  - com.kohlschutter.junixsocket:junixsocket-core:2.10.1 (recommended for JDK 17+)\n" +
                "  - health.varta:varta-client-ffm (zero-dep, JDK 22+, requires --enable-native-access)");
        }
    }
}
