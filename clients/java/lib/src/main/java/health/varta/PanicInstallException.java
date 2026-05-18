package health.varta;

/**
 * Thrown by {@code health.varta.panic.SignalHandler.install*} when the
 * handler cannot be set up — typically because the underlying transport
 * could not connect, or the OS RNG is unavailable for Secure UDP.
 *
 * <p>Fails closed: callers MUST NOT proceed assuming the handler is
 * installed.</p>
 */
public final class PanicInstallException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public PanicInstallException(String message) {
        super(message);
    }

    public PanicInstallException(String message, Throwable cause) {
        super(message, cause);
    }
}
