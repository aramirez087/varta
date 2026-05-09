package health.varta.examples;

import health.varta.Status;
import health.varta.Varta;

import java.nio.file.Path;
import java.nio.file.Paths;

/** Pack two metrics into the payload field. */
public final class WithPayload {
    private WithPayload() {}

    public static void main(String[] args) throws InterruptedException {
        Path socket = Paths.get(args.length > 0 ? args[0] : "/run/varta/observer.sock");
        try (Varta agent = Varta.connect(socket)) {
            int queueDepth = 0;
            int lastError = 0;
            while (!Thread.currentThread().isInterrupted()) {
                // High 16 bits = queue depth, low 16 bits = last error code.
                int payload = ((queueDepth & 0xFFFF) << 16) | (lastError & 0xFFFF);
                Status status = lastError > 0 ? Status.DEGRADED : Status.OK;
                agent.beat(status, payload);
                queueDepth = (queueDepth + 1) & 0xFFFF;
                Thread.sleep(500);
            }
        }
    }
}
