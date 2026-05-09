package health.varta.transport;

import java.io.IOException;

/**
 * Thrown by {@link UdsTransport#create(java.nio.file.Path)} when no
 * AF_UNIX SOCK_DGRAM provider is on the classpath.
 */
public final class NoUdsTransportException extends IOException {
    private static final long serialVersionUID = 1L;

    public NoUdsTransportException(String message) {
        super(message);
    }
}
