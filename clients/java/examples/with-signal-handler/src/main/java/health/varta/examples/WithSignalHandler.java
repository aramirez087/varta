package health.varta.examples;

import health.varta.Status;
import health.varta.Varta;
import health.varta.panic.SignalHandler;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Install a shutdown-hook panic handler, then beat in a loop. Any
 * terminating signal (SIGTERM/SIGINT/SIGHUP/SIGQUIT) or normal exit
 * emits a Critical + NONCE_TERMINAL beat before the JVM dies.
 */
public final class WithSignalHandler {
    private WithSignalHandler() {}

    public static void main(String[] args) throws Exception {
        Path socket = Paths.get(args.length > 0 ? args[0] : "/run/varta/observer.sock");

        try (AutoCloseable hook = SignalHandler.installShutdownHookUds(socket);
             Varta agent = Varta.connect(socket)) {
            System.out.println("[with-signal-handler] connected; press Ctrl-C to test.");
            while (!Thread.currentThread().isInterrupted()) {
                agent.beat(Status.OK);
                Thread.sleep(500);
            }
        }
    }
}
