package health.varta.panic;

/** Functional interface for {@link SignalHandler#run}. */
@FunctionalInterface
public interface ThrowingRunnable<X extends Throwable> {
    void run() throws X;
}
